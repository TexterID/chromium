// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

(async function(/** @type {import('test_runner').TestRunner} */ testRunner) {
  const origin = testRunner.params('httpsOrigin');
  const expected = testRunner.params('expectedChain');
  const expectedTls = testRunner.params('expectedTlsChain');
  const field = 'twoQwacCertificateChain';
  const {page, session, dp} = await testRunner.startBlank(
      'Verified 2-QWAC chains in modern headless Chrome.');

  function check(condition, description) {
    if (!condition)
      testRunner.die('Assertion failed', new Error(description));
    testRunner.log('PASS: ' + description);
  }

  function state(event) {
    return event.params.visibleSecurityState;
  }

  function hasChain(event) {
    return field in state(event);
  }

  function checkChain(event, description) {
    check(
        JSON.stringify(state(event)[field]) === JSON.stringify(expected),
        description);
  }

  // This fixture-only HTTP endpoint coordinates actual binding requests and
  // verifier completion on the browser UI thread. No timers or trust bypasses.
  async function control(command, id, target = page.targetId()) {
    const query = new URLSearchParams({command, id, target});
    const response = await fetch('/qwac-control?' + query);
    return response.json();
  }

  async function snapshot(protocol) {
    await protocol.Security.disable();
    const event = protocol.Security.onceVisibleSecurityStateChanged();
    await protocol.Security.enable();
    return event;
  }

  async function barrier(protocol) {
    // A round trip on this session also drains earlier security events.
    await protocol.Runtime.evaluate({expression: '0'});
  }

  await testRunner.runTestSuite([
    async function enabledBeforeCompletion() {
      await dp.Security.enable();
      await session.navigate(origin + 'page/before');
      await control('wait-request', 'before');
      check(!hasChain(await snapshot(dp)), 'pending binding is not verified');
      const completion = dp.Security.onceVisibleSecurityStateChanged(hasChain);
      const result = await control('release', 'before');
      check(result.verified, 'fixture used successful Chromium verification');
      const event = await completion;
      checkChain(
          event, 'completion event contains the leaf-first verified chain');
      check(
          expected.length === 3,
          'the complete three-certificate chain is tested');
      const tls = state(event).certificateSecurityState.certificate;
      check(
          tls[0] === expectedTls[0] && tls[0] !== expected[0],
          'TLS certificate remains separate from the qualified certificate');
    },

    async function navigationWithoutBinding() {
      const noChain = dp.Security.onceVisibleSecurityStateChanged(
          event => !hasChain(event));
      await session.navigate(origin + 'plain');
      await noChain;
      check(
          !hasChain(await snapshot(dp)),
          'a page without a binding does not inherit the previous chain');
    },

    async function enabledAfterCompletion() {
      await dp.Security.disable();
      await session.navigate(origin + 'page/after');
      await control('wait-request', 'after');
      const result = await control('release', 'after');
      check(
          result.verified, 'verification finishes while Security is disabled');
      const event = dp.Security.onceVisibleSecurityStateChanged();
      await dp.Security.enable();
      checkChain(
          await event, 'enabling Security returns the already verified chain');
    },

    async function invalidBinding() {
      await session.navigate(origin + 'page/invalid');
      const result = await control('wait-finished', 'invalid');
      check(!result.verified, 'Chromium rejects the invalid binding signature');
      check(
          !hasChain(await snapshot(dp)),
          'invalid binding exposes no verified chain');
    },

    async function bindingDownloadFailure() {
      await session.navigate(origin + 'page/download-failure');
      await control('wait-request', 'download-failure');
      await snapshot(dp);
      const completion = dp.Security.onceVisibleSecurityStateChanged();
      const result = await control('fail-download', 'download-failure');
      check(
          result.finished && !result.verified,
          'HTTP failure finishes binding processing without a verified chain');
      check(
          !hasChain(await completion),
          'binding download failure emits a completion event without a chain');
      check(
          !hasChain(await snapshot(dp)),
          'enabling Security after download failure still omits the chain');
    },

    async function sameDocumentReloadAndHistory() {
      await session.navigate(origin + 'page/valid');
      check(
          (await control('wait-finished', 'valid')).verified,
          'valid page verifies before lifecycle checks');
      await dp.Page.enable();
      const withinDocument = dp.Page.onceNavigatedWithinDocument();
      await session.evaluate('location.hash = "same-document"');
      await withinDocument;
      checkChain(
          await snapshot(dp), 'same-document navigation retains the chain');

      const loaded = dp.Page.onceLoadEventFired();
      await dp.Page.reload();
      await loaded;
      await control('wait-finished', 'reload');
      checkChain(
          await snapshot(dp),
          'reload exposes only the current verified result');

      const history = (await dp.Page.getNavigationHistory()).result;
      const entry = history.entries[history.currentIndex].id;
      await session.navigate(origin + 'plain');
      const restored = dp.Security.onceVisibleSecurityStateChanged(hasChain);
      await dp.Page.navigateToHistoryEntry({entryId: entry});
      checkChain(
          await restored, 'back navigation restores the page-specific chain');
    },

    async function lateCompletionOnCachedPage() {
      await session.navigate(origin + 'page/late');
      await control('wait-request', 'late');
      const history = (await dp.Page.getNavigationHistory()).result;
      const entry = history.entries[history.currentIndex].id;
      await session.navigate(origin + 'plain');
      await barrier(dp);
      const events = [];
      const listener = event => events.push(event);
      dp.Security.onVisibleSecurityStateChanged(listener);
      const result = await control('release', 'late');
      await barrier(dp);
      dp.Security.offVisibleSecurityStateChanged(listener);
      check(
          result.alive && !result.primary && result.verified,
          'the previous page stays alive and verifies ' +
              'in the back/forward cache');
      check(
          events.length === 0,
          'late completion on a non-primary page emits no security event');
      check(
          !hasChain(await snapshot(dp)),
          'the current page still has no qualified chain');
      const restored = dp.Security.onceVisibleSecurityStateChanged(hasChain);
      await dp.Page.navigateToHistoryEntry({entryId: entry});
      checkChain(
          await restored,
          'restoring the late-verified page exposes its own chain');
    },

    async function destroyedPageDuringPendingWork() {
      const survivor = await page.createSession();
      await survivor.protocol.Security.enable();
      const doomed = await testRunner.createPage({url: 'about:blank'});
      const doomedSession = await doomed.createSession();
      await doomedSession.protocol.Security.enable();
      await doomedSession.navigate(origin + 'page/destroyed');
      await control('wait-request', 'destroyed', doomed.targetId());

      const bp = testRunner.browserP();
      await bp.Target.setDiscoverTargets({discover: true});
      const destroyed = bp.Target.onceTargetDestroyed(
          event => event.params.targetId === doomed.targetId());
      await bp.Target.closeTarget({targetId: doomed.targetId()});
      await destroyed;
      await barrier(dp);
      await barrier(survivor.protocol);

      const events = [];
      const listener = event => events.push(event);
      dp.Security.onVisibleSecurityStateChanged(listener);
      survivor.protocol.Security.onVisibleSecurityStateChanged(listener);
      const result = await control('release', 'destroyed');
      await barrier(dp);
      await barrier(survivor.protocol);
      dp.Security.offVisibleSecurityStateChanged(listener);
      survivor.protocol.Security.offVisibleSecurityStateChanged(listener);
      check(!result.alive, 'closing the target destroys the pending QWAC page');
      check(
          events.length === 0,
          'releasing a destroyed page emits no event to surviving sessions');
      checkChain(
          await snapshot(dp), 'the original session retains its own chain');
      checkChain(
          await snapshot(survivor.protocol),
          'the second surviving session retains its own chain');
      await survivor.disconnect();
      await bp.Target.setDiscoverTargets({discover: false});
    },

    async function disabledDuringPendingWork() {
      await session.navigate(origin + 'page/disabled');
      await control('wait-request', 'disabled');
      await dp.Security.disable();
      const events = [];
      const listener = event => events.push(event);
      dp.Security.onVisibleSecurityStateChanged(listener);
      await control('release', 'disabled');
      await barrier(dp);
      dp.Security.offVisibleSecurityStateChanged(listener);
      check(
          events.length === 0, 'disabled Security emits no completion events');
      checkChain(
          await snapshot(dp),
          're-enabling Security observes the stored result');
    },

    async function multipleSessions() {
      await session.navigate(origin + 'page/multiple');
      await control('wait-request', 'multiple');
      const second = await page.createSession();
      await second.protocol.Security.enable();
      const firstEvent = dp.Security.onceVisibleSecurityStateChanged(hasChain);
      const secondEvent =
          second.protocol.Security.onceVisibleSecurityStateChanged(hasChain);
      await control('release', 'multiple');
      checkChain(await firstEvent, 'the first session receives the completion');
      checkChain(
          await secondEvent,
          'the second session independently receives the completion');
      await second.disconnect();
    },

    async function detachedDuringPendingWork() {
      await session.navigate(origin + 'page/detached');
      await control('wait-request', 'detached');
      const departing = await page.createSession();
      await departing.protocol.Security.enable();
      await departing.disconnect();
      const completion = dp.Security.onceVisibleSecurityStateChanged(hasChain);
      await control('release', 'detached');
      checkChain(
          await completion,
          'destroying another session does not cancel verification ' +
              'or surviving sessions');
    },
  ]);
});
