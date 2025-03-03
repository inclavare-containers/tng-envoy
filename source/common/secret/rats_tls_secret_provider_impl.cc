#include "source/common/secret/rats_tls_secret_provider_impl.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <chrono>

#include "envoy/extensions/transport_sockets/tls/v3/cert.pb.h"

#include "source/common/common/assert.h"
#include "source/common/common/hex.h"
#include "source/common/ssl/certificate_validation_context_config_impl.h"
#include "source/common/ssl/tls_certificate_config_impl.h"

#include "openssl/x509.h"
#include "openssl/bio.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/err.h"
#include "rats-rs/rats-rs.h"

constexpr int kMaxNumsOfPolicyIds = 16;
constexpr int kCertUpdateIntervalSecond = 60 * 60; // 1 hour
constexpr int kRatsRsCreateCertTimeoutSecond = 120; // 2 min

namespace Envoy {
namespace Secret {

RatsTlsCertificateConfigProviderImpl::RatsTlsCertificateConfigProviderImpl(
    Api::Api& api, Event::Dispatcher& main_thread_dispatcher,
    const envoy::extensions::transport_sockets::tls::v3::RatsTlsCertGeneratorConfig&
        rats_tls_cert_generator_config)
    : cert_updater_(std::make_shared<RatsTlsCertificateUpdater>(api, main_thread_dispatcher,
                                                                rats_tls_cert_generator_config)) {

  // Generate cert once
  this->cert_updater_->tls_certificate_ = this->cert_updater_->generateCertOnceBlocking();
  this->cert_updater_->enableUpdater();
}

RatsTlsCertificateUpdater::RatsTlsCertificateUpdater(
    Api::Api& api, Event::Dispatcher& main_thread_dispatcher,
    const envoy::extensions::transport_sockets::tls::v3::RatsTlsCertGeneratorConfig&
        rats_tls_cert_generator_config)
    : rats_tls_cert_generator_config_(
          std::make_unique<
              envoy::extensions::transport_sockets::tls::v3::RatsTlsCertGeneratorConfig>(
              rats_tls_cert_generator_config)),
      api_(api), main_thread_dispatcher_(main_thread_dispatcher),
      rats_tls_worker_(Envoy::Common::RatsTls::allocateRatsTlsWorker(api_)),
      rats_tls_worker_dispatcher_(rats_tls_worker_->dispatcher()),
      update_callback_manager_(Common::ThreadSafeCallbackManager::create()),
      tls_certificate_(nullptr), cert_update_timer_(nullptr) {}

void RatsTlsCertificateUpdater::enableUpdater() {
  // Create a Timer for updating certs
  auto weak_self = weak_from_this();

  rats_tls_worker_dispatcher_.post([weak_self]() -> void {
    if (auto self = weak_self.lock()) {
      ENVOY_LOG(info, "Setting up rats-tls cert update task");
      self->cert_update_timer_ = self->rats_tls_worker_dispatcher_.createTimer([weak_self]()
                                                                                   -> void {
        ENVOY_LOG(info, "Running rats-tls cert update task (interval: {} seconds)",
                  kCertUpdateIntervalSecond);
        if (auto self = weak_self.lock()) {
          try {
            self->tls_certificate_ = self->generateCertOnceBlocking();
            self->update_callback_manager_->runCallbacks();
          } catch (const EnvoyException& e) {
            ENVOY_LOG(warn, "Updating rats-tls cert failed, old cert will be used: {}", e.what());
          }
          self->cert_update_timer_->enableTimer(std::chrono::seconds(kCertUpdateIntervalSecond));
        } else {
          ENVOY_LOG(info, "The std::weak_ptr<RatsTlsCertificateUpdater> is empty and maybe "
                          "released, pausing rats-tls update task now");
        }
      });
      // Enable the timer
      self->cert_update_timer_->enableTimer(std::chrono::seconds(kCertUpdateIntervalSecond));
    }
  });
}

std::unique_ptr<envoy::extensions::transport_sockets::tls::v3::TlsCertificate>
RatsTlsCertificateUpdater::generateCertOnceBlocking() const {
  ENVOY_LOG(info, "Generating rats-tls X509 cert");

  // TODO: align rats-rs log level with envoy
  if (this->rats_tls_cert_generator_config_->has_coco_attester()) {
    auto& coco_attester = this->rats_tls_cert_generator_config_->coco_attester();
    const char* tmp_policy_ids[kMaxNumsOfPolicyIds] = {nullptr};

    rats_rs_coco_attest_mode_t attest_mode;
    if (coco_attester.has_evidence_mode()) {
      attest_mode.tag = RATS_RS_COCO_ATTEST_MODE_EVIDENCE;
    } else if (coco_attester.has_token_mode()) {
      auto& token_mode = coco_attester.token_mode();

      if (token_mode.policy_ids_size() < 1 || token_mode.policy_ids_size() > kMaxNumsOfPolicyIds) {
        throw EnvoyException(fmt::format(
            "The num of `policy_ids` should be greater equal than 1 and no more than {}",
            kMaxNumsOfPolicyIds));
      }
      for (int i = 0; i < token_mode.policy_ids_size(); ++i) {
        tmp_policy_ids[i] = token_mode.policy_ids(i).c_str();
      }

      attest_mode.tag = RATS_RS_COCO_ATTEST_MODE_TOKEN;
      attest_mode.TOKEN.as_addr = token_mode.as_addr().c_str();
      attest_mode.TOKEN.as_is_grpc = token_mode.as_is_grpc();
      attest_mode.TOKEN.policy_ids = tmp_policy_ids;
      attest_mode.TOKEN.policy_ids_len = token_mode.policy_ids_size();
    } else {
      throw EnvoyException("One of the field `evidence_mode` and `token_mode` must be set");
    }

    rats_rs_attester_type_t attester_type;
    attester_type.tag = RATS_RS_ATTESTER_TYPE_COCO;
    attester_type.COCO.attest_mode = attest_mode;
    attester_type.COCO.aa_addr = coco_attester.aa_addr().c_str();
    attester_type.COCO.timeout_nano = (kRatsRsCreateCertTimeoutSecond) * 1000ll * 1000 * 1000;

    rats_rs_error_obj_t* rats_rs_error_obj = nullptr;
    uint8_t* privkey_out = nullptr;
    size_t privkey_len_out = 0;
    uint8_t* certificate_out = nullptr;
    size_t certificate_len_out = 0;

    rats_rs_error_obj =
        rats_rs_create_cert("CN=TNG,O=Inclavare Containers", RATS_RS_HASH_ALGO_SHA256,
                            RATS_RS_ASYMMETRIC_ALGO_P256, attester_type, nullptr, 0, &privkey_out,
                            &privkey_len_out, &certificate_out, &certificate_len_out);

    if (rats_rs_error_obj != nullptr) {
      rats_rs_error_msg_t rats_rs_error_msg = rats_rs_err_get_msg_ref(rats_rs_error_obj);
      auto exception_msg = fmt::format(
          "Failed to generate rats-tls certificate with rats-rs: Error kind: {:#x}, msg: {:.{}s}",
          rats_rs_err_get_kind(rats_rs_error_obj), rats_rs_error_msg.msg,
          rats_rs_error_msg.msg_len);
      rats_rs_err_free(rats_rs_error_obj);
      rats_rs_error_obj = nullptr;
      throw EnvoyException(exception_msg);
    }
    // The private key in PEM format
    std::string private_key(reinterpret_cast<const char*>(privkey_out), privkey_len_out);
    rats_rs_rust_free(privkey_out, privkey_len_out);
    std::string certificate(reinterpret_cast<const char*>(certificate_out), certificate_len_out);
    rats_rs_rust_free(certificate_out, certificate_len_out);

    ENVOY_LOG(debug, "The rats-tls X509 cert is generated successfully: {}", certificate);

    // Create DataSource
    envoy::config::core::v3::DataSource* ds_cert_chain = new envoy::config::core::v3::DataSource();
    envoy::config::core::v3::DataSource* ds_private_key = new envoy::config::core::v3::DataSource();
    ds_cert_chain->set_inline_bytes(std::move(certificate));
    ds_private_key->set_inline_bytes(std::move(private_key));

    auto tls_certificate =
        std::make_unique<envoy::extensions::transport_sockets::tls::v3::TlsCertificate>();
    tls_certificate->set_allocated_certificate_chain(ds_cert_chain);
    tls_certificate->set_allocated_private_key(ds_private_key);

    return tls_certificate;
  } else {
    throw EnvoyException("The field `coco_attester` must be set");
  }
}

const envoy::extensions::transport_sockets::tls::v3::TlsCertificate*
RatsTlsCertificateConfigProviderImpl::secret() const {
  return this->cert_updater_->tls_certificate_.get();
}

} // namespace Secret
} // namespace Envoy
