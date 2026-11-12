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
  console.log('Optional: CHROMIUM_BINARY and QWAC_WAIT_MS (default 30000).');
  process.exit(url === '--help' ? 0 : 1);
}

const binary = process.env.CHROMIUM_BINARY || resolve(
    import.meta.dirname, '../../out/Qwac/Chromium.app/Contents/MacOS/Chromium');
const profile = await mkdtemp(resolve(tmpdir(), 'chromium-two-qwac-'));
const browser = spawn(binary, [
  '--headless', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--use-mock-keychain',
], {stdio: ['ignore', 'ignore', 'pipe']});
const closed = new Promise(resolveClosed => browser.once('close', resolveClosed));

let socket;
let nextId = 0;
let deadline;
let startupDeadline;
const pending = new Map();

try {
  const endpoint = await new Promise((resolveEndpoint, reject) => {
    let stderr = '';
    startupDeadline = setTimeout(
        () => reject(new Error('Browser startup timed out')), 30000);
    browser.once('error', reject);
    browser.once('exit', code => reject(new Error(`Browser exited (${code}): ${stderr}`)));
    browser.stderr.on('data', chunk => {
      stderr = (stderr + chunk.toString()).slice(-8192);
      const match = stderr.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) {
        clearTimeout(startupDeadline);
        resolveEndpoint(match[1]);
      }
    });
  });

  socket = new WebSocket(endpoint);
  await new Promise((resolveOpen, reject) => {
    socket.addEventListener('open', resolveOpen, {once: true});
    socket.addEventListener('error', reject, {once: true});
  });

  let sessionId;
  let receivedChain;
  const verified = new Promise(resolveVerified => receivedChain = resolveVerified);
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
    console.log(JSON.stringify({
      tlsCertificateChain: state.certificateSecurityState?.certificate,
      twoQwacCertificateChain: state.twoQwacCertificateChain,
    }, null, 2));
    if (state.twoQwacCertificateChain)
      receivedChain();
  });

  function send(method, params = {}, targetSessionId) {
    return new Promise((resolveResponse, reject) => {
      const id = ++nextId;
      pending.set(id, {resolve: resolveResponse, reject});
      socket.send(JSON.stringify({id, method, params, sessionId: targetSessionId}));
    });
  }

  const {targetId} = await send('Target.createTarget', {url: 'about:blank'});
  ({sessionId} = await send('Target.attachToTarget', {targetId, flatten: true}));
  // The listener above is installed before enable, which sends an initial
  // snapshot. A later event carries the chain if verification completes.
  await send('Security.enable', {}, sessionId);
  await send('Page.navigate', {url}, sessionId);

  const waitMs = Number(process.env.QWAC_WAIT_MS || 30000);
  const result = await Promise.race([
    verified.then(() => 'verified'),
    new Promise(resolveDeadline => {
      deadline = setTimeout(() => resolveDeadline('timeout'), waitMs);
    }),
  ]);
  if (result === 'timeout') {
    console.log('No verified 2-QWAC result arrived during the observation window.');
    console.log('Omission does not distinguish pending, absent, disabled, or failed processing.');
  }
  await send('Browser.close');
} finally {
  clearTimeout(deadline);
  clearTimeout(startupDeadline);
  socket?.close();
  browser.kill('SIGTERM');
  await closed;
  await rm(profile, {recursive: true, force: true});
}
