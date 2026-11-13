// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {access, mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {delimiter, dirname, join} from 'node:path';
import {test} from 'node:test';

const cases = [
  ['disconnect', /WebSocket closed/, false],
  ['exit', /Browser exited|WebSocket (closed|failed)/, false],
  ['startup-silent', /Browser startup timed out/, false],
  ['handshake-silent', /DevTools connection timed out/, false],
  ['command-silent', /Target.createTarget command timed out/, false],
  ['observation-disconnect', /WebSocket (closed|failed)/, false],
  ['close-command-silent', /Browser.close command timed out/, false],
  ['shutdown-stuck', /No verified 2-QWAC result arrived/, true],
  ['success', /"twoQwacCertificateChain": \[\s*"qualified"/, true],
];

for (const [mode, expected, succeeds] of cases) {
  test(mode, {timeout: 10000}, async t => {
    const directory = await mkdtemp(join(tmpdir(), 'qwac-client-test-'));
    const log = join(directory, 'browser.json');
    let browser;
    let child;
    t.after(async () => {
      child?.kill('SIGKILL');
      if (browser) {
        try {
          process.kill(browser.pid, 'SIGKILL');
        } catch (error) {
          assert.equal(error.code, 'ESRCH');
        }
        await rm(browser.profile, {recursive: true, force: true});
      }
      await rm(directory, {recursive: true, force: true});
    });
    child = spawn(
        process.execPath,
        [
          join(import.meta.dirname, 'observe.mjs'),
          'data:text/html,<title>QWAC client test</title>',
        ],
        {
          env: {
            ...process.env,
            PATH: dirname(process.execPath) + delimiter + process.env.PATH,
            CHROMIUM_BINARY: join(import.meta.dirname, 'test/fake_browser.mjs'),
            QWAC_FAKE_MODE: mode,
            QWAC_FAKE_LOG: log,
            QWAC_WAIT_MS: '100',
            QWAC_TIMEOUT_MS: '1000',
          },
          stdio: ['ignore', 'pipe', 'pipe'],
          timeout: 7000,
          killSignal: 'SIGKILL',
        });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', chunk => stdout += chunk);
    child.stderr.on('data', chunk => stderr += chunk);
    const [code, signal] = await new Promise((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (...args) => resolve(args));
    });
    browser = JSON.parse(await readFile(log, 'utf8'));
    assert.equal(signal, null, `example exceeded its deadline: ${stderr}`);
    if (succeeds)
      assert.equal(code, 0, stderr);
    else
      assert.notEqual(code, 0, stdout);
    assert.match(stdout + stderr, expected);
    assert.throws(
        () => process.kill(browser.pid, 0), {code: 'ESRCH'},
        'the example must reap its browser');
    await assert.rejects(
        access(browser.profile), {code: 'ENOENT'},
        'the example must remove its temporary profile');
    if (mode === 'success')
      assert.match(stdout, /"tlsCertificateChain": \[\s*"tls"/);
  });
}
