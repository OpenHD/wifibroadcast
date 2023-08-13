
#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include <vector>
#include <array>
#include <string>
#include <memory>

#include <sodium.h>

// Namespace that can be used to add encryption+packet validation
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

/**
 * Generates a new keypair. Non-deterministic, 100% secure.
 */
KeyPairTxRx generate_keypair_random();

/**
 * See https://libsodium.gitbook.io/doc/password_hashing
 * Deterministic seed from password, but hides password itself (non-reversible)
 * Uses a pre-defined salt to be deterministic
 */
std::array<uint8_t , crypto_box_SEEDBYTES>
create_seed_from_password_openhd_salt(const std::string& pw,bool use_salt_air);

// We always use the same bind phrase by default
static constexpr auto DEFAULT_BIND_PHRASE="openhd";
/**
 * Generates 2 new (deterministic) tx rx keys, using the seed created from the pw.
 * @param bind_phrase the password / bind phrase
 */
KeyPairTxRx generate_keypair_from_bind_phrase(const std::string& bind_phrase=DEFAULT_BIND_PHRASE);

/**
 * Saves the KeyPairTxRx as a raw file
 */
int write_keypair_to_file(const KeyPairTxRx& keypair_txrx,const std::string& filename);

/**
 * Reads a raw KeyPairTxRx from a raw file previusly generated.
 */
KeyPairTxRx read_keypair_from_file(const std::string& filename);


/**
 * https://libsodium.gitbook.io/doc/key_derivation
 * UINT16SeqNrHelper since we both support encryption and one time validation to save cpu performance
 */
std::array<uint8_t,32> create_onetimeauth_subkey(const uint64_t& nonce,const std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES>& session_key);

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
                         std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES> &sessionKeyData);
  /**
   * Encrypt the given message of size @param src_len
   * (Or if encryption is disabled, only calculate the message sign)
   * and write the (encrypted) data appended by the validation data into dest
   * @param nonce: needs to be different for every packet
   * @param src @param src_len message to encrypt
   * @param dest needs to point to a memory region at least @param src_len + 16 bytes big
   * Returns written data size (msg payload plus sign data)
   */
  int authenticate_and_encrypt(const uint64_t& nonce,const uint8_t *src,int src_len,uint8_t* dest);

  /**
   *  For easy use - returns a buffer including (encrypted) payload plus validation data
   */
  std::shared_ptr<std::vector<uint8_t>> authenticate_and_encrypt_buff(const uint64_t& nonce,const uint8_t *src,std::size_t src_len);
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
  explicit Decryptor(wb::Key key1);
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
                                const std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES+ crypto_box_MACBYTES> &sessionKeyData);
  /**
   * Decrypt (or validate only if encryption is disabled) the given message
   * and writes the original message content into dest.
   * Returns true on success, false otherwise (false== the message is not a valid message)
   * @param dest needs to be at least @param encrypted - 16 bytes big.
   */
  bool authenticate_and_decrypt(const uint64_t& nonce,const uint8_t* encrypted,int encrypted_size,uint8_t* dest);

  /**
   * Easier to use, but usage might require memcpy
   */
  std::shared_ptr<std::vector<uint8_t>> authenticate_and_decrypt_buff(const uint64_t& nonce,const uint8_t* encrypted,int encrypted_size);
  /**
   * Disables encryption (to save cpu performance) but keeps packet validation functionality
   * @param encryption_enabled
   */
  void set_encryption_enabled(bool encryption_enabled){
    m_encrypt_data =encryption_enabled;
  }
  // Set to true as soon as a valid session has been detected
  bool has_valid_session() const{
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