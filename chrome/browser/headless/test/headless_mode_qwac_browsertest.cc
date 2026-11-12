// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "base/base64.h"
#include "base/functional/bind.h"
#include "base/json/json_writer.h"
#include "base/memory/weak_ptr.h"
#include "base/run_loop.h"
#include "base/strings/strcat.h"
#include "base/strings/string_view_util.h"
#include "base/task/bind_post_task.h"
#include "base/task/sequenced_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "chrome/browser/headless/test/headless_mode_protocol_browsertest.h"
#include "chrome/browser/net/qwac_web_contents_observer.h"
#include "chrome/browser/net/system_network_context_manager.h"
#include "content/public/browser/devtools_agent_host.h"
#include "content/public/browser/network_service_instance.h"
#include "content/public/browser/page.h"
#include "content/public/browser/web_contents.h"
#include "content/public/common/content_features.h"
#include "mojo/public/cpp/base/proto_wrapper.h"
#include "net/base/features.h"
#include "net/base/url_util.h"
#include "net/cert/internal/trust_store_chrome.h"
#include "net/cert/root_store_proto_lite/root_store.pb.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "net/dns/mock_host_resolver.h"
#include "net/test/embedded_test_server/embedded_test_server.h"
#include "net/test/two_qwac_cert_binding_builder.h"
#include "services/cert_verifier/public/mojom/cert_verifier_service_factory.mojom.h"

namespace headless {
namespace {

using ControlReply = base::OnceCallback<void(base::DictValue)>;
using ResponseReply = base::OnceCallback<void(std::string, std::string)>;
using RequestCallback =
    base::RepeatingCallback<void(const GURL&, ResponseReply)>;

// The HTTP server runs on its own thread. Test controls run on the UI thread;
// their replies return to the server thread before touching its delegate.
class QwacTestResponse : public net::test_server::HttpResponse {
 public:
  QwacTestResponse(scoped_refptr<base::SequencedTaskRunner> ui_runner,
                   RequestCallback callback,
                   GURL url)
      : ui_runner_(std::move(ui_runner)),
        callback_(std::move(callback)),
        url_(std::move(url)) {}

  void SendResponse(
      base::WeakPtr<net::test_server::HttpResponseDelegate> delegate) override {
    auto reply = base::BindPostTaskToCurrentDefault(base::BindOnce(
        [](base::WeakPtr<net::test_server::HttpResponseDelegate> delegate,
           std::string content_type, std::string body) {
          if (delegate) {
            delegate->SendHeadersContentAndFinish(
                net::HTTP_OK, "OK", {{"Content-Type", content_type}}, body);
          }
        },
        delegate));
    ui_runner_->PostTask(FROM_HERE,
                         base::BindOnce(callback_, url_, std::move(reply)));
  }

 private:
  scoped_refptr<base::SequencedTaskRunner> ui_runner_;
  RequestCallback callback_;
  GURL url_;
};

base::ListValue CertificateChain(net::X509Certificate* certificate) {
  base::ListValue chain;
  for (const auto& cert : certificate->cert_buffers()) {
    chain.Append(base::Base64Encode(
        net::x509_util::CryptoBufferAsStringPiece(cert.get())));
  }
  return chain;
}

// Supplies real TLS, binding signatures and test EUTL trust. All protocol
// assertions live in JavaScript, running against Chrome's --headless path.
class HeadlessModeQwacProtocolTest : public HeadlessModeProtocolBrowserTest {
 public:
  HeadlessModeQwacProtocolTest() {
    feature_list_.InitWithFeatures(
        {net::features::kVerifyQWACs, features::kBackForwardCache}, {});
  }

  void SetUpInProcessBrowserTestFixture() override {
    SystemNetworkContextManager::SetEnableCertificateTransparencyForTesting(
        false);
    HeadlessModeProtocolBrowserTest::SetUpInProcessBrowserTestFixture();
  }

  void SetUpOnMainThread() override {
    HeadlessModeProtocolBrowserTest::SetUpOnMainThread();
    host_resolver()->AddRule("*", "127.0.0.1");
    https_server_.SetCertHostnames({"www.example.com"});
    ASSERT_TRUE(https_server_.InitializeAndListen());
    binding_builder_.GetIntermediateBuilder()->SetCertificatePolicies(
        {"2.5.29.32.0"});  // anyPolicy
    binding_builder_.SetBoundCerts({std::string(
        base::as_string_view(https_server_.GetCertificate()->cert_span()))});
    binding_ = binding_builder_.GetJWS();
    invalid_binding_ = binding_builder_.GetJWSWithInvalidSignature();

    auto ui_runner = base::SequencedTaskRunner::GetCurrentDefault();
    https_server_.RegisterRequestHandler(base::BindRepeating(
        [](scoped_refptr<base::SequencedTaskRunner> ui_runner,
           RequestCallback callback,
           const net::test_server::HttpRequest& request)
            -> std::unique_ptr<net::test_server::HttpResponse> {
          const std::string path = request.GetURL().GetPath();
          if (!path.starts_with("/binding/") || path == "/binding/valid" ||
              path == "/binding/invalid") {
            return nullptr;
          }
          return std::make_unique<QwacTestResponse>(ui_runner, callback,
                                                    request.GetURL());
        },
        ui_runner,
        base::BindRepeating(&HeadlessModeQwacProtocolTest::OnBindingRequest,
                            weak_factory_.GetWeakPtr())));
    https_server_.RegisterRequestHandler(
        base::BindRepeating(&HeadlessModeQwacProtocolTest::HandleHttpsRequest,
                            base::Unretained(this)));
    https_server_.StartAcceptingConnections();

    auto control = base::BindRepeating(
        [](base::WeakPtr<HeadlessModeQwacProtocolTest> fixture, const GURL& url,
           ResponseReply reply) {
          if (fixture) {
            fixture->Control(
                url, base::BindOnce(
                         [](ResponseReply reply, base::DictValue result) {
                           std::move(reply).Run(
                               "application/json",
                               base::WriteJson(result).value());
                         },
                         std::move(reply)));
          }
        },
        weak_factory_.GetWeakPtr());
    embedded_test_server()->RegisterRequestHandler(base::BindRepeating(
        [](scoped_refptr<base::SequencedTaskRunner> ui_runner,
           RequestCallback callback,
           const net::test_server::HttpRequest& request)
            -> std::unique_ptr<net::test_server::HttpResponse> {
          if (request.GetURL().GetPath() != "/qwac-control") {
            return nullptr;
          }
          return std::make_unique<QwacTestResponse>(ui_runner, callback,
                                                    request.GetURL());
        },
        ui_runner, std::move(control)));

    // The ordinary embedded-server TLS root is trusted by the test harness.
    // QWAC validation additionally requires an explicitly trusted EUTL issuer.
    chrome_root_store::RootStore store;
    store.set_version_major(net::CompiledChromeRootStoreVersion() + 1);
    store.add_trust_anchors()->set_der(
        base::as_string_view(https_server_.GetRoot()->cert_span()));
    auto* eutl = store.add_additional_certs();
    eutl->set_der(base::as_string_view(
        binding_builder_.GetRootBuilder()->GetX509Certificate()->cert_span()));
    eutl->set_eutl(true);
    auto update = cert_verifier::mojom::PKIMetadataUpdate::New();
    update->chrome_root_store =
        cert_verifier::mojom::ChromeRootStoreUpdate::New(
            mojo_base::ProtoWrapper(store), std::nullopt);
    base::RunLoop loop;
    content::GetCertVerifierServiceFactory()->UpdatePKIMetadata(
        std::move(update), loop.QuitClosure());
    loop.Run();
  }

  void TearDownOnMainThread() override {
    EXPECT_TRUE(https_server_.ShutdownAndWaitUntilComplete());
    HeadlessModeProtocolBrowserTest::TearDownOnMainThread();
  }

 protected:
  base::DictValue GetPageUrlExtraParams() override {
    return base::DictValue()
        .Set("httpsOrigin", https_server_.GetURL("www.example.com", "/").spec())
        .Set("expectedChain",
             CertificateChain(binding_builder_.GetLeafBuilder()
                                  ->GetX509CertificateFullChain()
                                  .get()))
        .Set("expectedTlsChain",
             CertificateChain(https_server_.GetCertificate().get()));
  }

 private:
  std::unique_ptr<net::test_server::HttpResponse> HandleHttpsRequest(
      const net::test_server::HttpRequest& request) {
    const std::string path = request.GetURL().GetPath();
    auto response = std::make_unique<net::test_server::BasicHttpResponse>();
    if (path == "/binding/valid" || path == "/binding/invalid") {
      response->set_content_type("application/jose");
      response->set_content(path == "/binding/valid" ? binding_
                                                     : invalid_binding_);
    } else {
      response->set_content_type("text/html");
      response->set_content("<!doctype html><title>QWAC protocol test</title>");
      if (path.starts_with("/page/")) {
        response->AddCustomHeader(
            "Link", base::StrCat({"</binding/", path.substr(6),
                                  ">;rel=\"tls-certificate-binding\""}));
      }
    }
    return response;
  }

  void OnBindingRequest(const GURL& url, ResponseReply reply) {
    const std::string id = url.GetPath().substr(9);
    CHECK(!binding_replies_.contains(id));
    binding_replies_.emplace(id, std::move(reply));
    if (request_waiters_.contains(id)) {
      std::move(request_waiters_.at(id)).Run(base::DictValue());
      request_waiters_.erase(id);
    }
  }

  void Control(const GURL& url, ControlReply reply) {
    std::string command;
    std::string id;
    std::string target;
    net::GetValueForKeyInQuery(url, "command", &command);
    net::GetValueForKeyInQuery(url, "id", &id);
    net::GetValueForKeyInQuery(url, "target", &target);
    if (command == "wait-request") {
      auto host = content::DevToolsAgentHost::GetForId(target);
      CHECK(host && host->GetWebContents());
      pages_[id] = host->GetWebContents()->GetPrimaryPage().GetWeakPtr();
      if (binding_replies_.contains(id)) {
        std::move(reply).Run(base::DictValue());
      } else {
        request_waiters_.emplace(id, std::move(reply));
      }
      return;
    }

    base::WeakPtr<content::Page> page;
    if (command == "release") {
      page = pages_.at(id);
      std::move(binding_replies_.at(id)).Run("application/jose", binding_);
    } else {
      CHECK_EQ(command, "wait-finished");
      auto host = content::DevToolsAgentHost::GetForId(target);
      CHECK(host && host->GetWebContents());
      page = host->GetWebContents()->GetPrimaryPage().GetWeakPtr();
    }

    auto finished = base::BindOnce(
        [](base::WeakPtr<content::Page> page, ControlReply reply) {
          auto* status =
              page ? QwacWebContentsObserver::QwacStatus::GetForPage(*page)
                   : nullptr;
          std::move(reply).Run(
              base::DictValue()
                  .Set("alive", !!page)
                  .Set("primary", page && page->IsPrimary())
                  .Set("verified", status && status->is_finished() &&
                                       status->verified_2qwac_cert()));
        },
        page, std::move(reply));
    auto* status =
        page ? QwacWebContentsObserver::QwacStatus::GetForPage(*page) : nullptr;
    if (status && !status->is_finished()) {
      subscriptions_.insert_or_assign(
          id, status->RegisterCallback(std::move(finished)));
    } else {
      std::move(finished).Run();
    }
  }

  base::test::ScopedFeatureList feature_list_;
  net::TwoQwacCertBindingBuilder binding_builder_{3};
  std::string binding_;
  std::string invalid_binding_;
  std::map<std::string, ResponseReply> binding_replies_;
  std::map<std::string, ControlReply> request_waiters_;
  std::map<std::string, base::WeakPtr<content::Page>> pages_;
  std::map<std::string, base::CallbackListSubscription> subscriptions_;
  net::EmbeddedTestServer https_server_{net::EmbeddedTestServer::TYPE_HTTPS};
  base::WeakPtrFactory<HeadlessModeQwacProtocolTest> weak_factory_{this};
};

HEADLESS_MODE_PROTOCOL_TEST_F(HeadlessModeQwacProtocolTest,
                              VerifiedTwoQwac,
                              "security/verified-two-qwac.js")

}  // namespace
}  // namespace headless
