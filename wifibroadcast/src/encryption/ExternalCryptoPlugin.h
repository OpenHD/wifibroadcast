#ifndef WIFIBROADCAST_EXTERNAL_CRYPTO_PLUGIN_H
#define WIFIBROADCAST_EXTERNAL_CRYPTO_PLUGIN_H

#include <cstddef>
#include <cstdint>
#include <string>

#include "openhd_crypto_plugin.h"

namespace wb {

class ExternalCryptoPlugin {
 public:
  ExternalCryptoPlugin() = default;
  ExternalCryptoPlugin(const ExternalCryptoPlugin&) = delete;
  ExternalCryptoPlugin& operator=(const ExternalCryptoPlugin&) = delete;
  ~ExternalCryptoPlugin();

  bool load(const std::string& path, bool is_air);
  bool is_loaded() const { return m_handle != nullptr; }
  uint32_t wire_format_id() const {
    return m_provider ? m_provider->wire_format_id : (m_legacy_encrypt ? 1U : 0U);
  }
  bool supports_sessions() const {
    return m_session && m_encrypt_stream && m_decrypt_stream;
  }
  bool session(const uint8_t* input, size_t size, uint8_t* output,
               size_t capacity, size_t& output_size) const;
  const std::string& loaded_path() const { return m_loaded_path; }

  bool encrypt(const uint8_t* in, size_t in_len, uint8_t* out,
               size_t* out_len, uint64_t* key_id, uint8_t stream = 0) const;
  bool decrypt(const uint8_t* in, size_t in_len, uint8_t* out,
               size_t* out_len, uint64_t key_id, uint8_t stream = 0) const;

 private:
  using legacy_init_fn = int (*)(int);
  using legacy_shutdown_fn = void (*)();
  using legacy_encrypt_fn = int (*)(const uint8_t*, size_t, uint8_t*, size_t*,
                                    uint64_t*);
  using legacy_decrypt_fn = int (*)(const uint8_t*, size_t, uint8_t*, size_t*,
                                    uint64_t);

  using session_fn = int32_t (*)(const uint8_t*, size_t, uint8_t*, size_t,
                                 size_t*);
  session_fn m_session = nullptr;
  using encrypt_stream_fn = int (*)(uint8_t, const uint8_t*, size_t, uint8_t*,
                                    size_t*, uint64_t*);
  using decrypt_stream_fn = int (*)(uint8_t, const uint8_t*, size_t, uint8_t*,
                                    size_t*, uint64_t);
  encrypt_stream_fn m_encrypt_stream = nullptr;
  decrypt_stream_fn m_decrypt_stream = nullptr;
  void* m_handle = nullptr;
  std::string m_loaded_path;
  const openhd_crypto_provider* m_provider = nullptr;
  legacy_shutdown_fn m_legacy_shutdown = nullptr;
  legacy_encrypt_fn m_legacy_encrypt = nullptr;
  legacy_decrypt_fn m_legacy_decrypt = nullptr;
};

}  // namespace wb

#endif  // WIFIBROADCAST_EXTERNAL_CRYPTO_PLUGIN_H
