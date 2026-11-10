#include "ExternalCryptoPlugin.h"

#include <cstdlib>

#include "../wifibroadcast_spdlog.h"

#ifdef __linux__
#include <dlfcn.h>
#endif

namespace {
constexpr const char* kExternalCryptoEnvVar = "OPENHD_VIDEO_CRYPTO_SO";
constexpr const char* kDefaultExternalCryptoPath =
    "/usr/local/lib/openhd/plugins/libopenhd_video_crypto.so";
constexpr const char* kLegacyExternalCryptoPath =
    "/usr/local/lib/openhd/libohd_video_crypto.so";
}

wb::ExternalCryptoPlugin::~ExternalCryptoPlugin() {
#ifdef __linux__
  if (m_provider && m_provider->shutdown) {
    m_provider->shutdown();
  } else if (m_legacy_shutdown) {
    m_legacy_shutdown();
  }
  if (m_handle) {
    dlclose(m_handle);
  }
#endif
}

bool wb::ExternalCryptoPlugin::load(const std::string& path, bool is_air) {
#ifdef __linux__
  if (m_handle != nullptr) {
    return true;
  }

  std::string resolved_path = path;
  if (resolved_path.empty()) {
    const char* env_path = std::getenv(kExternalCryptoEnvVar);
    resolved_path = (env_path && env_path[0] != '\0')
                        ? env_path
                        : kDefaultExternalCryptoPath;
  }

  m_handle = dlopen(resolved_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  if (!m_handle && path.empty() &&
      resolved_path == kDefaultExternalCryptoPath) {
    resolved_path = kLegacyExternalCryptoPath;
    m_handle = dlopen(resolved_path.c_str(), RTLD_NOW | RTLD_LOCAL);
  }
  if (!m_handle) {
    const char* load_error = dlerror();
    wifibroadcast::log::get_default()->debug(
        "External crypto plugin not loaded from {}: {}", resolved_path,
        load_error ? load_error : "unknown error");
    return false;
  }

  auto get_provider = reinterpret_cast<openhd_crypto_get_provider_fn>(
      dlsym(m_handle, OPENHD_CRYPTO_ENTRYPOINT));
  m_provider = get_provider ? get_provider() : nullptr;
  const bool provider_compatible = m_provider &&
      m_provider->struct_size >= sizeof(openhd_crypto_provider) &&
      m_provider->abi_version == OPENHD_CRYPTO_ABI_VERSION &&
      m_provider->wire_format_id != 0U && m_provider->init &&
      m_provider->shutdown && m_provider->encrypt && m_provider->decrypt;
  legacy_init_fn legacy_init = nullptr;
  if (!provider_compatible) {
    m_provider = nullptr;
    legacy_init = reinterpret_cast<legacy_init_fn>(
        dlsym(m_handle, "openhd_video_crypto_init"));
    m_legacy_shutdown = reinterpret_cast<legacy_shutdown_fn>(
        dlsym(m_handle, "openhd_video_crypto_shutdown"));
    m_legacy_encrypt = reinterpret_cast<legacy_encrypt_fn>(
        dlsym(m_handle, "openhd_video_crypto_encrypt"));
    m_legacy_decrypt = reinterpret_cast<legacy_decrypt_fn>(
        dlsym(m_handle, "openhd_video_crypto_decrypt"));
  }
  if (!provider_compatible &&
      (!legacy_init || !m_legacy_shutdown || !m_legacy_encrypt ||
       !m_legacy_decrypt)) {
    wifibroadcast::log::get_default()->warn(
        "External crypto plugin {} is missing required symbols",
        resolved_path);
    dlclose(m_handle);
    m_handle = nullptr;
    m_provider = nullptr;
    m_legacy_shutdown = nullptr;
    m_legacy_encrypt = nullptr;
    m_legacy_decrypt = nullptr;
    return false;
  }

  const int rc = provider_compatible ? m_provider->init(is_air ? 1 : 0)
                                     : legacy_init(is_air ? 1 : 0);
  if (rc != 0) {
    wifibroadcast::log::get_default()->warn(
        "External crypto plugin init failed with code {}", rc);
    dlclose(m_handle);
    m_handle = nullptr;
    m_provider = nullptr;
    m_legacy_shutdown = nullptr;
    m_legacy_encrypt = nullptr;
    m_legacy_decrypt = nullptr;
    return false;
  }

  if (wire_format_id() == 2U) {
    m_session = reinterpret_cast<session_fn>(
        dlsym(m_handle, "openhd_video_crypto_session"));
    m_encrypt_stream = reinterpret_cast<encrypt_stream_fn>(
        dlsym(m_handle, "openhd_video_crypto_encrypt_stream"));
    m_decrypt_stream = reinterpret_cast<decrypt_stream_fn>(
        dlsym(m_handle, "openhd_video_crypto_decrypt_stream"));
  }
  m_loaded_path = resolved_path;
  wifibroadcast::log::get_default()->info("Loaded external crypto plugin {}",
                                          m_loaded_path);
  return true;
#else
  (void)path;
  (void)is_air;
  return false;
#endif
}

bool wb::ExternalCryptoPlugin::session(const uint8_t* input, size_t size,
                                   uint8_t* output, size_t capacity,
                                   size_t& output_size) const {
  output_size = 0;
  return m_session &&
         m_session(input, size, output, capacity, &output_size) == 1;
}

bool wb::ExternalCryptoPlugin::encrypt(const uint8_t* in, size_t in_len,
                                       uint8_t* out, size_t* out_len,
                                       uint64_t* key_id, uint8_t stream) const {
  if (wire_format_id() == 2U) {
    return supports_sessions() &&
           m_encrypt_stream(stream, in, in_len, out, out_len, key_id) == 0;
  }
  if ((!m_provider || !m_provider->encrypt) && !m_legacy_encrypt) {
    return false;
  }
  if (m_provider) {
    const size_t capacity = *out_len;
    return m_provider->encrypt(in, in_len, out, capacity, out_len, key_id) == 0;
  }
  return m_legacy_encrypt(in, in_len, out, out_len, key_id) == 0;
}

bool wb::ExternalCryptoPlugin::decrypt(const uint8_t* in, size_t in_len,
                                       uint8_t* out, size_t* out_len,
                                       uint64_t key_id, uint8_t stream) const {
  if (wire_format_id() == 2U) {
    return supports_sessions() &&
           m_decrypt_stream(stream, in, in_len, out, out_len, key_id) == 0;
  }
  if ((!m_provider || !m_provider->decrypt) && !m_legacy_decrypt) {
    return false;
  }
  if (m_provider) {
    const size_t capacity = *out_len;
    return m_provider->decrypt(in, in_len, out, capacity, out_len, key_id) == 0;
  }
  return m_legacy_decrypt(in, in_len, out, out_len, key_id) == 0;
}
