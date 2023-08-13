
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

// one time authentication and encryption nicely are really similar
static_assert(crypto_onetimeauth_BYTES==crypto_aead_chacha20poly1305_ABYTES);
// Encryption (or packet validation) adds this many bytes to the end of the message
static constexpr auto ENCRYPTION_ADDITIONAL_VALIDATION_DATA=crypto_aead_chacha20poly1305_ABYTES;

namespace wb{

// A wb key consists of a public and secret key
struct Key {
  std::array<uint8_t,crypto_box_PUBLICKEYBYTES> public_key;
  std::array<uint8_t,crypto_box_SECRETKEYBYTES> secret_key;
};

// A wb keypair are 2 keys, one for transmitting, one for receiving
// (Since both ground and air unit talk bidirectional)
// We use a different key for the down-link / uplink, respective
struct KeyPairTxRx {
  Key key_1;
  Key key_2;
  Key get_tx_key(bool is_air){
      return is_air ? key_1 : key_2;
  }
  Key get_rx_key(bool is_air){
      return is_air ? key_2 : key_1;
  }
};

// Generates a new keypair. Non-deterministic, 100% secure.
static KeyPairTxRx generate_keypair_random(){
  KeyPairTxRx ret{};
  crypto_box_keypair(ret.key_1.public_key.data(), ret.key_1.secret_key.data());
  crypto_box_keypair(ret.key_2.public_key.data(), ret.key_2.secret_key.data());
  return ret;
}

// Obsolete
static Key generate_keypair_deterministic(bool is_air){
  Key ret{};
  std::array<uint8_t , crypto_box_SEEDBYTES> seed1{0};
  std::array<uint8_t , crypto_box_SEEDBYTES> seed2{1};
  crypto_box_seed_keypair(ret.public_key.data(), ret.secret_key.data(),is_air ? seed1.data(): seed2.data());
  return ret;
}

// Salts generated once using https://www.random.org/cgi-bin/randbyte?nbytes=16&format=d
// We want deterministic seed from a pw, and are only interested in making it impossible to reverse the process (even though the salt is plain text)
static constexpr std::array<uint8_t,crypto_pwhash_SALTBYTES> OHD_SALT_AIR{192,189,216,102,56,153,154,92,228,26,49,209,157,7,128,207};
static constexpr std::array<uint8_t,crypto_pwhash_SALTBYTES> OHD_SALT_GND{179,30,150,20,17,200,225,82,48,64,18,130,89,62,83,234};
static constexpr auto OHD_DEFAULT_TX_RX_KEY_FILENAME="txrx.key";

// See https://libsodium.gitbook.io/doc/password_hashing
static  std::array<uint8_t , crypto_box_SEEDBYTES> create_seed_from_password(const std::string& pw,bool use_salt_air){
  const auto salt = use_salt_air ? OHD_SALT_AIR : OHD_SALT_GND;
  std::array<uint8_t , crypto_box_SEEDBYTES> key{};
  if (crypto_pwhash(key.data(), key.size(), pw.c_str(), pw.length(), salt.data(),
       crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
       crypto_pwhash_ALG_DEFAULT) != 0) {
    std::cerr<<"ERROR: cannot create_seed_from_password"<<std::endl;
    assert(false);
    // out of memory
  }
  return key;
}

// We always use the same bind phrase by default
static constexpr auto DEFAULT_BIND_PHRASE="openhd";
static KeyPairTxRx generate_keypair_from_bind_phrase(const std::string& bind_phrase=DEFAULT_BIND_PHRASE){
  const auto seed_air= create_seed_from_password(bind_phrase, true);
  const auto seed_gnd= create_seed_from_password(bind_phrase, false);
  KeyPairTxRx ret{};
  crypto_box_seed_keypair(ret.key_1.public_key.data(), ret.key_1.secret_key.data(),seed_air.data());
  crypto_box_seed_keypair(ret.key_2.public_key.data(), ret.key_2.secret_key.data(),seed_gnd.data());
  return ret;
}

static int write_keypair_to_file(const KeyPairTxRx& keypair_txrx,const std::string& filename){
  FILE *fp;
  if ((fp = fopen(filename.c_str(), "w")) == nullptr) {
    std::cerr<<"Unable to save "<<filename<<std::endl;
    assert(false);
    return 1;
  }
  assert(fwrite(keypair_txrx.key_1.secret_key.data(), crypto_box_SECRETKEYBYTES, 1, fp)==1);
  assert(fwrite(keypair_txrx.key_1.public_key.data(), crypto_box_PUBLICKEYBYTES, 1, fp)==1);
  assert(fwrite(keypair_txrx.key_2.secret_key.data(), crypto_box_SECRETKEYBYTES, 1, fp)==1);
  assert(fwrite(keypair_txrx.key_2.public_key.data(), crypto_box_PUBLICKEYBYTES, 1, fp)==1);
  fclose(fp);
  return 0;
}

static KeyPairTxRx read_keypair_from_file(const std::string& filename){
  KeyPairTxRx ret{};
  FILE *fp;
  if ((fp = fopen(filename.c_str(), "r")) == nullptr) {
    std::cerr<<fmt::format("Unable to open {}: {}", filename.c_str(), strerror(errno))<<std::endl;
    assert(false);
  }
  assert(fread(ret.key_1.secret_key.data(), crypto_box_SECRETKEYBYTES, 1, fp)==1);
  assert(fread(ret.key_1.public_key.data(), crypto_box_PUBLICKEYBYTES, 1, fp)==1);
  assert(fread(ret.key_2.secret_key.data(), crypto_box_SECRETKEYBYTES, 1, fp)==1);
  assert(fread(ret.key_2.public_key.data(), crypto_box_PUBLICKEYBYTES, 1, fp)==1);
  fclose(fp);
  return ret;
}


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
   * @param key1 encryption key, otherwise enable a default deterministic encryption key by using std::nullopt
   * @param DISABLE_ENCRYPTION_FOR_PERFORMANCE only validate, do not encrypt (less CPU usage)
   */
  explicit Encryptor(wb::Key key1)
      : tx_secretkey(key1.secret_key),
        rx_publickey(key1.public_key){
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
   * @param src @param src_len message to encrypt
   * @param dest needs to point to a memory region at least @param src_len + 16 bytes big
   * Returns written data size (msg payload plus sign data)
   */
  int authenticate_and_encrypt(const uint64_t nonce,const uint8_t *src,int src_len,uint8_t* dest){
    if(!m_encrypt_data){ // Only sign message
      memcpy(dest,src, src_len);
      uint8_t* sign=dest+src_len;
      const auto sub_key=wb::create_onetimeauth_subkey(nonce,session_key);
      crypto_onetimeauth(sign,src,src_len,sub_key.data());
      return src_len+crypto_onetimeauth_BYTES;
    }
    // sign and encrypt all together
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
    m_encrypt_data =encryption_enabled;
  }
 private:
  // tx->rx keypair
  const std::array<uint8_t, crypto_box_SECRETKEYBYTES> tx_secretkey{};
  const std::array<uint8_t, crypto_box_PUBLICKEYBYTES> rx_publickey{};
  std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
  // use this one if you are worried about CPU usage when using encryption
  bool m_encrypt_data= true;
};

class Decryptor {
 public:
  // enable a default deterministic encryption key by using std::nullopt
  // else, pass path to file with encryption keys
  explicit Decryptor(wb::Key key1)
      :rx_secretkey(key1.secret_key),tx_publickey(key1.public_key){
    memset(session_key.data(), 0, sizeof(session_key));
  }
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
      wifibroadcast::log::get_default()->info("Decryptor-New session detected");
      session_key = new_session_key;
      m_has_valid_session= true;
      return SESSION_VALID_NEW;
    }
    // this is NOT an error, the same session key is sent multiple times !
    return SESSION_VALID_NOT_NEW;
  }
  /**
   * Decrypt (or validate only if encryption is disabled) the given message
   * and writes the original message content into dest.
   * Returns true on success, false otherwise (false== the message is not a valid message)
   * @param dest needs to be at least @param encrypted - 16 bytes big.
   */
  bool authenticate_and_decrypt(const uint64_t& nonce,const uint8_t* encrypted,int encrypted_size,uint8_t* dest){
    if(!m_encrypt_data){
      const auto payload_size=encrypted_size-crypto_onetimeauth_BYTES;
      assert(payload_size>0);
      const uint8_t* sign=encrypted+payload_size;
      //const int res=crypto_auth_hmacsha256_verify(sign,msg,payload_size,session_key.data());
      const auto sub_key=wb::create_onetimeauth_subkey(nonce,session_key);
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
    if(m_encrypt_data){
      return crypto_onetimeauth_BYTES;
    }
    return crypto_aead_chacha20poly1305_ABYTES;
  }
  /**
   * Disables encryption (to save cpu performance) but keeps packet validation functionality
   * @param encryption_enabled
   */
  void set_encryption_enabled(bool encryption_enabled){
    m_encrypt_data =encryption_enabled;
  }
  // Set to true as soon as a valid session has been detected
  bool has_valid_session(){
    return m_has_valid_session;
  }
 private:
  // use this one if you are worried about CPU usage when using encryption
  bool m_encrypt_data= true;
  const std::array<uint8_t, crypto_box_SECRETKEYBYTES> rx_secretkey{};
  const std::array<uint8_t, crypto_box_PUBLICKEYBYTES> tx_publickey{};
  std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
  bool m_has_valid_session= false;
};

} // namespace wb end


#endif //ENCRYPTION_HPP