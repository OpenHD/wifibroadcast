
#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include "HelperSources/Helper.hpp"
#include <cstdio>
#include <stdexcept>
#include <vector>
#include <optional>
#include <iostream>
#include <array>
#include <sodium.h>
#include "wifibroadcast-spdlog.h"

// Single Header file that can be used to add encryption+packet validation
// (Or packet validation only to save CPU resources)
// to a lossy unidirectional link
// Packet validation is quite important, to make sure only openhd packets (and not standard wifi packets) are used in OpenHD
// The Encryption / Decryption name(s) are legacy -
// The more difficult part is dealing with the session key stuff, and this class makes it a bit easier to use

// For developing or when encryption is not important, you can use this default seed to
// create deterministic rx and tx keys
static const std::array<unsigned char, crypto_box_SEEDBYTES> DEFAULT_ENCRYPTION_SEED = {0};

static_assert(crypto_onetimeauth_BYTES==crypto_aead_chacha20poly1305_ABYTES);
// Encryption (or packet validation) adds this many bytes to the end of the message
static constexpr auto ENCRYPTION_ADDITIONAL_VALIDATION_DATA=crypto_aead_chacha20poly1305_ABYTES;

// https://libsodium.gitbook.io/doc/key_derivation
// Helper since we both support encryption and one time validation to save cpu performance
static std::array<uint8_t,32> create_onetimeauth_subkey(const uint64_t nonce,const std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key){
  // sub-key for this packet
  std::array<uint8_t, 32> subkey{};
  // We only have an 8 byte nonce, this should be enough entropy
  std::array<uint8_t,16> nonce_buf{0};
  memcpy(nonce_buf.data(),(uint8_t*)&nonce,8);
  crypto_core_hchacha20(subkey.data(),nonce_buf.data(),session_key.data(), nullptr);
  return subkey;
}

class Encryptor {
 public:
  /**
   *
   * @param keypair encryption key, otherwise enable a default deterministic encryption key by using std::nullopt
   * @param DISABLE_ENCRYPTION_FOR_PERFORMANCE only validate, do not encrypt (less CPU usage)
   */
  explicit Encryptor(std::optional<std::string> keypair, const bool DISABLE_ENCRYPTION_FOR_PERFORMANCE = false)
      : DISABLE_ENCRYPTION_FOR_PERFORMANCE(DISABLE_ENCRYPTION_FOR_PERFORMANCE) {
    if (keypair == std::nullopt) {
      // use default encryption keys
      crypto_box_seed_keypair(rx_publickey.data(), tx_secretkey.data(), DEFAULT_ENCRYPTION_SEED.data());
      wifibroadcast::log::get_default()->debug("Using default keys");
    } else {
      FILE *fp;
      if ((fp = fopen(keypair->c_str(), "r")) == nullptr) {
        throw std::runtime_error(fmt::format("Unable to open {}: {}", keypair->c_str(), strerror(errno)));
      }
      if (fread(tx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1) {
        fclose(fp);
        throw std::runtime_error(fmt::format("Unable to read tx secret key: {}", strerror(errno)));
      }
      if (fread(rx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1) {
        fclose(fp);
        throw std::runtime_error(fmt::format("Unable to read rx public key: {}", strerror(errno)));
      }
      fclose(fp);
    }
  }
  /**
   * Creates a new session key, simply put, the data we can send publicly
   * @param sessionKeyNonce filled with public nonce
   * @param sessionKeyData filled with public data
   */
  void makeNewSessionKey(std::array<uint8_t, crypto_box_NONCEBYTES> &sessionKeyNonce,
                         std::array<uint8_t,
                                    crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES> &sessionKeyData) {
    randombytes_buf(session_key.data(), sizeof(session_key));
    randombytes_buf(sessionKeyNonce.data(), sizeof(sessionKeyNonce));
    if (crypto_box_easy(sessionKeyData.data(), session_key.data(), sizeof(session_key),
                        sessionKeyNonce.data(), rx_publickey.data(), tx_secretkey.data()) != 0) {
      throw std::runtime_error("Unable to make session key!");
    }
  }
  /**
   * Encrypt the given message of size @param src_len
   * (Or if encryption is disabled, only calculate the message sign)
   * and write the (encrypted) data appended by the validation data into dest
   * @param nonce: needs to be different for every packet
   * @param authenticate_only: if
   * @param dest needs to point to a memory region at least @param src_len + 16 bytes big
   * Returns written data size (msg payload plus sign data)
   */
  int authenticate_and_encrypt(const uint64_t nonce,const uint8_t *src,std::size_t src_len,uint8_t* dest){
    if(DISABLE_ENCRYPTION_FOR_PERFORMANCE){
      memcpy(dest,src, src_len);
      uint8_t* sign=dest+src_len;
      const auto sub_key=create_onetimeauth_subkey(nonce,session_key);
      crypto_onetimeauth(sign,src,src_len,sub_key.data());
      return src_len+crypto_onetimeauth_BYTES;
    }
    long long unsigned int ciphertext_len;
    crypto_aead_chacha20poly1305_encrypt(dest, &ciphertext_len,
                                         src, src_len,
                                         (uint8_t *)nullptr, 0,
                                         nullptr,
                                         (uint8_t *) &nonce, session_key.data());
    return (int)ciphertext_len;
  }
  // For easy use - returns a buffer including (encrypted) payload plus validation data
  std::shared_ptr<std::vector<uint8_t>> authenticate_and_encrypt_buff(const uint64_t nonce,const uint8_t *src,std::size_t src_len){
    auto ret=std::make_shared<std::vector<uint8_t>>(src_len + ENCRYPTION_ADDITIONAL_VALIDATION_DATA);
    const auto size=authenticate_and_encrypt(nonce, src, src_len, ret->data());
    assert(size==ret->size());
    return ret;
  }
  /**
   * Disables encryption (to save cpu performance) but keeps packet validation functionality
   * @param encryption_enabled
   */
  void set_encryption_enabled(bool encryption_enabled){
    DISABLE_ENCRYPTION_FOR_PERFORMANCE=!encryption_enabled;
  }
 private:
  // tx->rx keypair
  std::array<uint8_t, crypto_box_SECRETKEYBYTES> tx_secretkey{};
  std::array<uint8_t, crypto_box_PUBLICKEYBYTES> rx_publickey{};
  std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
  // use this one if you are worried about CPU usage when using encryption
  bool DISABLE_ENCRYPTION_FOR_PERFORMANCE;
  //static_assert(crypto_onetimeauth_BYTES);
};

class Decryptor {
 public:
  // enable a default deterministic encryption key by using std::nullopt
  // else, pass path to file with encryption keys
  explicit Decryptor(std::optional<std::string> keypair, const bool DISABLE_ENCRYPTION_FOR_PERFORMANCE = false)
      : DISABLE_ENCRYPTION_FOR_PERFORMANCE(DISABLE_ENCRYPTION_FOR_PERFORMANCE) {
    if (keypair == std::nullopt) {
      crypto_box_seed_keypair(tx_publickey.data(), rx_secretkey.data(), DEFAULT_ENCRYPTION_SEED.data());
      wifibroadcast::log::get_default()->debug("Using default keys");
    } else {
      FILE *fp;
      if ((fp = fopen(keypair->c_str(), "r")) == nullptr) {
        throw std::runtime_error(fmt::format("Unable to open {}: {}", keypair->c_str(), strerror(errno)));
      }
      if (fread(rx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1) {
        fclose(fp);
        throw std::runtime_error(fmt::format("Unable to read rx secret key: {}", strerror(errno)));
      }
      if (fread(tx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1) {
        fclose(fp);
        throw std::runtime_error(fmt::format("Unable to read tx public key: {}", strerror(errno)));
      }
      fclose(fp);
    }
    memset(session_key.data(), 0, sizeof(session_key));
  }
 private:
  // use this one if you are worried about CPU usage when using encryption
  bool DISABLE_ENCRYPTION_FOR_PERFORMANCE;
 public:
  std::array<uint8_t, crypto_box_SECRETKEYBYTES> rx_secretkey{};
 public:
  std::array<uint8_t, crypto_box_PUBLICKEYBYTES> tx_publickey{};
  std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
 public:
  static constexpr auto SESSION_VALID_NEW=0;
  static constexpr auto SESSION_VALID_NOT_NEW=1;
  static constexpr auto SESSION_NOT_VALID=-1;
  /**
   * Returns 0 if the session is a valid session in regards to the key-pairs AND the session is a new session
   * Returns 1 if the session is a valid session in regards to the key-pairs but it is not a new session
   * Returns -1 if the session is not a valid session in regards to the key-pairs
   *
   */
  int onNewPacketSessionKeyData(const std::array<uint8_t, crypto_box_NONCEBYTES> &sessionKeyNonce,
                                 const std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES+ crypto_box_MACBYTES> &sessionKeyData) {
    std::array<uint8_t, sizeof(session_key)> new_session_key{};
    if (crypto_box_open_easy(new_session_key.data(),
                             sessionKeyData.data(), sessionKeyData.size(),
                             sessionKeyNonce.data(),
                             tx_publickey.data(), rx_secretkey.data()) != 0) {
      // this basically should just never happen, and is an error
      wifibroadcast::log::get_default()->warn("unable to decrypt session key");
      return SESSION_NOT_VALID;
    }
    if (memcmp(session_key.data(), new_session_key.data(), sizeof(session_key)) != 0) {
      // this is NOT an error, the same session key is sent multiple times !
      wifibroadcast::log::get_default()->info("Decryptor-New session detected");
      session_key = new_session_key;
      return SESSION_VALID_NEW;
    }
    return SESSION_VALID_NOT_NEW;
  }
  /**
   * Decrypt (or validate only if encryption is disabled) the given message
   * and writes the original message content into dest.
   * Returns true on success, false otherwise (false== the message is not a valid message)
   * @param dest needs to be at least @param encrypted - 16 bytes big.
   */
  bool authenticate_and_decrypt(const uint64_t& nonce,const uint8_t* encrypted,int encrypted_size,uint8_t* dest){
    if(DISABLE_ENCRYPTION_FOR_PERFORMANCE){
      const auto payload_size=encrypted_size-crypto_onetimeauth_BYTES;
      assert(payload_size>0);
      const uint8_t* sign=encrypted+payload_size;
      //const int res=crypto_auth_hmacsha256_verify(sign,msg,payload_size,session_key.data());
      const auto sub_key=create_onetimeauth_subkey(nonce,session_key);
      const int res=crypto_onetimeauth_verify(sign,encrypted,payload_size,sub_key.data());
      if(res!=-1){
        memcpy(dest,encrypted,payload_size);
        return true;
      }
      return false;
    }
    unsigned long long mlen;
    int res=crypto_aead_chacha20poly1305_decrypt(dest, &mlen,
                                                   nullptr,
                                                   encrypted, encrypted_size,
                                                   nullptr,0,
                                                   (uint8_t *) (&nonce), session_key.data());
    return res!=-1;
  }
  std::shared_ptr<std::vector<uint8_t>> authenticate_and_decrypt_buff(const uint64_t& nonce,const uint8_t* encrypted,int encrypted_size){
    auto ret=std::make_shared<std::vector<uint8_t>>(encrypted_size - get_additional_payload_size());
    const auto res=
        authenticate_and_decrypt(nonce, encrypted, encrypted_size, ret->data());
    if(res){
      return ret;
    }
    return nullptr;
  }
  int get_additional_payload_size() const{
    if(DISABLE_ENCRYPTION_FOR_PERFORMANCE){
      return crypto_onetimeauth_BYTES;
    }
    return crypto_aead_chacha20poly1305_ABYTES;
  }
  /**
   * Disables encryption (to save cpu performance) but keeps packet validation functionality
   * @param encryption_enabled
   */
  void set_encryption_enabled(bool encryption_enabled){
    DISABLE_ENCRYPTION_FOR_PERFORMANCE=!encryption_enabled;
  }
};

namespace wbencryption{

struct KeypairData{
  unsigned char drone_publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char drone_secretkey[crypto_box_SECRETKEYBYTES];
  unsigned char gs_publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char gs_secretkey[crypto_box_SECRETKEYBYTES];
};

static KeypairData generate_keypair(){
  KeypairData ret{};
  crypto_box_keypair(ret.drone_publickey, ret.drone_secretkey);
  crypto_box_keypair(ret.gs_publickey, ret.gs_secretkey);
  return ret;
}

static int write_to_file(const KeypairData& data){
  FILE *fp;
  if ((fp = fopen("drone.key", "w")) == NULL) {
    perror("Unable to save drone.key");
    return 1;
  }
  fwrite(data.drone_secretkey, crypto_box_SECRETKEYBYTES, 1, fp);
  fwrite(data.gs_publickey, crypto_box_PUBLICKEYBYTES, 1, fp);
  fclose(fp);

  fprintf(stderr, "Drone keypair (drone sec + gs pub) saved to drone.key\n");

  if ((fp = fopen("gs.key", "w")) == NULL) {
    perror("Unable to save gs.key");
    return 1;
  }

  fwrite(data.gs_secretkey, crypto_box_SECRETKEYBYTES, 1, fp);
  fwrite(data.drone_publickey, crypto_box_PUBLICKEYBYTES, 1, fp);
  fclose(fp);
  fprintf(stderr, "GS keypair (gs sec + drone pub) saved to gs.key\n");
  return 0;
}

}

#endif //ENCRYPTION_HPP