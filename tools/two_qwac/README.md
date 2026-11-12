# Verified 2-QWAC DevTools draft

This draft exposes Chrome's successfully verified 2-QWAC certificate chain to
trusted DevTools clients, including clients driving modern `--headless` Chrome.
It reuses the existing verifier and page-owned result. It does not change trust
policy or add an API accessible to website JavaScript. The separate
`chrome-headless-shell` executable is outside this draft.

The starting Chromium revision is
`8d01b13862ccf1e61b32f27028505acaedbeb9c2`. The local build uses arm64,
`is_debug=false`, `is_component_build=true`, `symbol_level=0`,
`blink_symbol_level=0`, `v8_symbol_level=0`, and `use_remoteexec=false`.

## Protocol payload

After `Security.enable`, the existing experimental
`Security.visibleSecurityStateChanged` event can contain:

```json
{
  "visibleSecurityState": {
    "securityState": "secure",
    "certificateSecurityState": {
      "certificate": ["BASE64_DER_TLS_LEAF", "BASE64_DER_TLS_ISSUER"]
    },
    "twoQwacCertificateChain": [
      "BASE64_DER_QUALIFIED_LEAF",
      "BASE64_DER_QUALIFIED_INTERMEDIATE",
      "BASE64_DER_QUALIFIED_ROOT"
    ]
  }
}
```

The TLS certificate fields above are abbreviated. Each qualified certificate is
base64-encoded DER, in the order of Chromium's verified chain, leaf first. This
is a separate chain from the certificate authenticating the TLS connection.

Omission means no verified 2-QWAC result is currently available. It does not
distinguish processing that is pending, disabled, unsuccessful, or never started.
A client must subscribe before enabling Security: enabling sends an immediate
snapshot, and later verification can send another event. A page's load event
does not mean that its qualified certificate has finished verification.

## Data flow and lifetime

`QwacWebContentsObserver::DidFinishNavigation` discovers the binding link on a
committed primary-frame navigation. Its `QwacStatus` fetches the binding using
the existing same-origin restrictions, size limit, and timeout. The network
service verifies the binding and the qualified certificate under the existing
rules. Only the successful verifier result becomes `verified_2qwac_`.

`content::Page` owns `QwacStatus` through `PageUserData`. The status owns its URL
loader and verifier callback weak-pointer factory. Destroying the status cancels
the loader's callback and invalidates the verifier callback's weak pointer.

The new `OnProcessingFinished` helper sets the finished flag, then notifies the
existing completion callbacks. It saves a local weak pointer before notification
because a callback can destroy the status. It checks that weak pointer before
accessing members again. This guards access to destroyed objects.

A still-live old page is a separate problem: back/forward cache can retain both
the page and its status after navigation. The helper checks `page().IsPrimary()`
before sending `WebContents::DidChangeVisibleSecurityState()`. This guards stale
completion notifications from surviving objects. It does not cancel verification
for cached pages; their results remain available if the page is restored.

`chrome_security_state::GetVisibleSecurityState` obtains the verified result for
the committed primary page. `SecurityHandler` serializes that result into the
new optional field. The handler remains owned by its Chrome DevTools session and
continues to observe the existing WebContents notification. No per-session QWAC
subscription is added. Its existing enabled flag suppresses events after disable;
destruction unregisters its WebContents observation. Multiple sessions therefore
observe the same page independently.

Serialization creates a `unique_ptr` to the protocol array and moves it into the
event object. It does not add a certificate cache or a new long-lived owner.
In the test fixture, callback maps own the held server replies and completion
subscriptions until fixture teardown. Page and server-delegate references are
weak; they do not keep a document or connection alive. Replies are posted back
to the server thread before its delegate is accessed.

Reload, same-document navigation, and history restoration retain or recreate
status according to the existing QWAC observer. This draft does not introduce a
second page cache or copy certificates between pages. No generic `//content`
implementation depends on the Chrome-specific QWAC classes.

## Build and verify

Run these commands from the Chromium `src` directory:

```sh
autoninja -C out/Qwac -j 4 browser_tests chrome net_unittests

out/Qwac/browser_tests \
  --gtest_filter='HeadlessModeQwacProtocolTest*' \
  --disable-features=InitialWebUI \
  --test-launcher-jobs=1 --test-launcher-retry-limit=0

out/Qwac/browser_tests \
  --gtest_filter='QwacWebContentsObserver*:DevToolsProtocolTest.VisibleSecurityState*' \
  --disable-features=InitialWebUI \
  --test-launcher-jobs=1 --test-launcher-retry-limit=0

out/Qwac/net_unittests --gtest_filter='*Qwac*' \
  --test-launcher-jobs=1 --test-launcher-retry-limit=0

third_party/cpython3/host/bin/python3 \
  third_party/inspector_protocol/check_protocol_compatibility.py \
  third_party/blink/public/devtools_protocol/browser_protocol.pdl \
  v8/include/js_protocol.pdl
```

The local baseline timed out before test bodies while waiting for the initial
WebUI toolbar paint. Disabling `InitialWebUI` bypasses that unrelated startup
wait. It does not bypass TLS or QWAC certificate checks.

The new test runs JavaScript protocol assertions in the existing modern headless
harness. Its C++ fixture supplies an embedded HTTPS server, a generated
three-certificate qualified chain, a signed binding to the server's actual TLS
certificate, and test EUTL trust. A fixture-only HTTP control endpoint releases
held binding responses and waits for verifier completion; tests do not use
arbitrary sleeps. The expected output identifies nine lifecycle scenarios and
23 assertions, including invalid signatures, independent sessions, disable,
reload, same-document navigation, and completion on a still-live cached page.

Local verification on macOS arm64 with Xcode 27.2:

| Check | Result |
| --- | --- |
| `browser_tests`, `chrome`, and `net_unittests` build | Passed |
| New modern headless protocol test | 1 test passed; all 9 scenarios and 23 assertions matched |
| Existing QWAC and visible-security-state browser tests | 14 passed |
| Existing `*Qwac*` net tests | 43 passed |
| Protocol compatibility, C++/GN formatting, and include dependencies | Passed |
| Node example against a data URL | Passed; omitted qualified chain and exited normally |

For the local-only presubmit, run:

```sh
PRESUBMIT_SKIP_NETWORK=1 git cl presubmit --upload origin/main
```

The configured contributor email is not yet in Chromium's `AUTHORS` file.
The contributor check therefore reports that registration is needed; the
network-enabled run also encountered HTTP 401 looking up Gerrit ownership.
These are unresolved upstream-contribution prerequisites. Do not describe the
draft as having a clean upstream presubmit or as ready for Gerrit submission.
Protocol sources are regenerated by the normal build via the DevTools
`concatenate_protocols` and `protocol_generated_sources` targets; generated
files are not hand-edited or committed.

## Automation example

Node 24 is already bundled in this checkout. No npm installation is needed:

```sh
third_party/node/mac_arm64/node-darwin-arm64/bin/node \
  tools/two_qwac/observe.mjs https://YOUR_QWAC_SITE
```

`CHROMIUM_BINARY` overrides the default `out/Qwac` browser path. The script
launches modern headless Chrome in a temporary profile, connects through CDP,
subscribes before enabling Security, and prints the TLS and qualified chains as
separate fields. `QWAC_WAIT_MS` sets its observation window (default 30000 ms).
A timeout is not a claim that the site has no QWAC. The fixture-backed protocol
test above provides the deterministic demonstration without a public site or a
purchased certificate.

For a local smoke test of the client with no external site:

```sh
QWAC_WAIT_MS=1000 third_party/node/mac_arm64/node-darwin-arm64/bin/node \
  tools/two_qwac/observe.mjs 'data:text/html,<title>QWAC smoke</title>'
```

This checks launch, CDP subscription, navigation, omission handling, and shutdown.
The HTTPS protocol fixture proves the positive verified-chain result.

## Questions for the next revision

The optional field is deliberately narrower than a processing-state API. A
future design could distinguish pending, absent, disabled, download failure,
and verification failure. Upstream CDP owners still need to review the field
name, placement, and product justification. Parsed organization attributes and
additional diagnostics are separate API decisions.

The existing event has no new document identifier. Clients must coordinate with
their Page navigation events, discard state from previous navigations, and treat
the payload as the current visible security snapshot. This draft prevents an old
page's completion notification from being emitted for the new page; it does not
make unrelated Page and Security events an atomic transaction.

The completion notification also reaches non-DevTools observers of visible
security state. This reuses the existing notification rather than introducing a
separate QWAC observer API, but that notification scope is an upstream review
question. The verification result and restrictions remain unchanged.

## Reading order

1. `third_party/blink/public/devtools_protocol/domains/Security.pdl`: what does
   omission mean, and why is the qualified chain outside the TLS certificate?
2. `chrome/browser/net/qwac_web_contents_observer.h` and `.cc`: who owns the
   status, what cancels each callback, and why are both a weak pointer and a
   primary-page check necessary?
3. `chrome/browser/ssl/chrome_security_state_util.cc`: why can only the committed
   primary page supply the chain?
4. `chrome/browser/devtools/protocol/security_handler.cc` and
   `chrome/browser/devtools/chrome_devtools_session.cc`: who owns the handler,
   how does enable replay current state, and why does disable still work?
5. `chrome/browser/headless/test/headless_mode_qwac_browsertest.cc` and
   `chrome/browser/headless/test/data/protocol/security/verified-two-qwac.js`:
   where is trust installed, how do responses coordinate the tests, and which
   assertion proves that a still-live old page cannot report stale completion?
