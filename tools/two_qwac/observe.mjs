// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Uses Node's built-in WebSocket; no npm dependencies are required.
// Run from src: node tools/two_qwac/observe.mjs https://your-qwac-site.example
// CHROMIUM_BINARY selects a different locally built Chrome executable.

import {spawn} from 'node:child_process';
import {mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';

const url = process.argv[2];
if (!url || url === '--help') {
  console.log('Usage: node tools/two_qwac/observe.mjs URL');
  console.log(
      'Optional: CHROMIUM_BINARY, QWAC_WAIT_MS (30000), ' +
      'QWAC_TIMEOUT_MS (10000, per setup step/command).');
  process.exit(url === '--help' ? 0 : 1);
}

function duration(name, fallback) {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(value) || value <= 0 || value > 2147483647)
    throw new Error(
        `${name} must be a positive 32-bit integer in milliseconds`);
  return value;
}

const waitMs = duration('QWAC_WAIT_MS', 30000);
const timeoutMs = duration('QWAC_TIMEOUT_MS', 10000);
const shutdownMs = Math.min(timeoutMs, 2000);

async function bounded(promise, description, milliseconds = timeoutMs) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
            () => reject(new Error(`${description} timed out`)), milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

const binary = process.env.CHROMIUM_BINARY ||
    resolve(import.meta.dirname,
            '../../out/Qwac/Chromium.app/Contents/MacOS/Chromium');
const profile = await mkdtemp(resolve(tmpdir(), 'chromium-two-qwac-'));
const browser = spawn(
    binary,
    [
      '--headless',
      '--remote-debugging-port=0',
      `--user-data-dir=${profile}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--use-mock-keychain',
    ],
    {stdio: ['ignore', 'ignore', 'pipe']});
const closed =
    new Promise(resolveClosed => browser.once('close', resolveClosed));

let socket;
let nextId = 0;
let deadline;
let connectionError;
let browserStderr = '';
let rejectDisconnected;
const pending = new Map();
const disconnected = new Promise((_, reject) => rejectDisconnected = reject);
// Disconnect can happen before a stage starts awaiting it. Keep the rejection
// handled here; races below still receive and propagate the original error.
disconnected.catch(() => {});

function disconnect(error) {
  if (connectionError)
    return;
  connectionError = error;
  for (const callbacks of pending.values())
    callbacks.reject(error);
  pending.clear();
  rejectDisconnected(error);
}

browser.once('error', disconnect);
browser.once(
    'exit',
    (code, signal) => disconnect(
        new Error(`Browser exited (${signal || code}): ${browserStderr}`)));

try {
  const advertisedEndpoint = new Promise(resolveEndpoint => {
    browser.stderr.on('data', chunk => {
      browserStderr = (browserStderr + chunk.toString()).slice(-8192);
      const match = browserStderr.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match)
        resolveEndpoint(match[1]);
    });
  });
  const endpoint = await bounded(
      Promise.race([advertisedEndpoint, disconnected]), 'Browser startup');

  socket = new WebSocket(endpoint);
  socket.addEventListener(
      'close', () => disconnect(new Error('DevTools WebSocket closed')));
  socket.addEventListener(
      'error', () => disconnect(new Error('DevTools WebSocket failed')));
  await bounded(
      Promise.race([
        new Promise(
            resolveOpen =>
                socket.addEventListener('open', resolveOpen, {once: true})),
        disconnected,
      ]),
      'DevTools connection');

  let sessionId;
  let receivedChain;
  const verified =
      new Promise(resolveVerified => receivedChain = resolveVerified);
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.id) {
      const callbacks = pending.get(message.id);
      pending.delete(message.id);
      if (message.error)
        callbacks?.reject(new Error(JSON.stringify(message.error)));
      else
        callbacks?.resolve(message.result);
      return;
    }
    if (message.sessionId !== sessionId ||
        message.method !== 'Security.visibleSecurityStateChanged') {
      return;
    }
    const state = message.params.visibleSecurityState;
    console.log(JSON.stringify(
        {
          tlsCertificateChain: state.certificateSecurityState?.certificate,
          twoQwacCertificateChain: state.twoQwacCertificateChain,
        },
        null, 2));
    if (state.twoQwacCertificateChain)
      receivedChain();
  });

  async function send(method, params = {}, targetSessionId) {
    if (connectionError)
      throw connectionError;
    const id = ++nextId;
    const response =
        new Promise((resolve, reject) => pending.set(id, {resolve, reject}));
    try {
      socket.send(
          JSON.stringify({id, method, params, sessionId: targetSessionId}));
      return await bounded(response, `${method} command`);
    } finally {
      pending.delete(id);
    }
  }

  const {targetId} = await send('Target.createTarget', {url: 'about:blank'});
  ({sessionId} =
       await send('Target.attachToTarget', {targetId, flatten: true}));
  // The listener above is installed before enable, which sends an initial
  // snapshot. A later event carries the chain if verification completes.
  await send('Security.enable', {}, sessionId);
  await send('Page.navigate', {url}, sessionId);

  const result = await Promise.race([
    verified.then(() => 'verified'),
    disconnected,
    new Promise(resolveDeadline => {
      deadline = setTimeout(() => resolveDeadline('timeout'), waitMs);
    }),
  ]);
  clearTimeout(deadline);
  if (result === 'timeout') {
    console.log(
        'No verified 2-QWAC result arrived during the observation window.');
    console.log(
        'Omission does not distinguish pending, absent, disabled, ' +
        'or failed processing.');
  }
  if (connectionError)
    throw connectionError;
  try {
    await send('Browser.close');
  } catch (error) {
    // Closing Chrome may close the connection before its reply is delivered.
    if (!connectionError)
      throw error;
  }
} finally {
  clearTimeout(deadline);
  socket?.close();
  browser.kill('SIGTERM');
  try {
    await bounded(closed, 'Browser shutdown', shutdownMs);
  } catch {
    browser.kill('SIGKILL');
    try {
      await bounded(closed, 'Browser forced shutdown', shutdownMs);
    } finally {
      // Inherited pipes must not keep Node alive if a descendant retains them.
      browser.stderr.destroy();
      browser.unref();
    }
  } finally {
    await rm(profile, {recursive: true, force: true});
  }
}
