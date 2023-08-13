//
// Created by consti10 on 13.08.23.
//

#include "Encryption.h"

#include <cassert>
#include <cstring>
#include <iostream>

#include <spdlog/spdlog.h>
#include "wifibroadcast_spdlog.h"

wb::KeyPairTxRx wb::generate_keypair_random() {
  KeyPairTxRx ret{};
  crypto_box_keypair(ret.key_1.public_key.data(), ret.key_1.secret_key.data());
  crypto_box_keypair(ret.key_2.public_key.data(), ret.key_2.secret_key.data());
  return ret;
}

// Salts generated once using https://www.random.org/cgi-bin/randbyte?nbytes=16&format=d
// We want deterministic seed from a pw, and are only interested in making it impossible to reverse the process (even though the salt is plain text)
static constexpr std::array<uint8_t,crypto_pwhash_SALTBYTES> OHD_SALT_AIR{192,189,216,102,56,153,154,92,228,26,49,209,157,7,128,207};
static constexpr std::array<uint8_t,crypto_pwhash_SALTBYTES> OHD_SALT_GND{179,30,150,20,17,200,225,82,48,64,18,130,89,62,83,234};

std::array<uint8_t, crypto_box_SEEDBYTES>
wb::create_seed_from_password_openhd_salt(const std::string& pw,
                                          bool use_salt_air) {
  const auto salt = use_salt_air ? OHD_SALT_AIR : OHD_SALT_GND;
  std::array<uint8_t , crypto_box_SEEDBYTES> key{};
  if (crypto_pwhash(key.data(), key.size(), pw.c_str(), pw.length(), salt.data(),
                    crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                    crypto_pwhash_ALG_DEFAULT) != 0) {
    std::cerr<<"ERROR: cannot create_seed_from_password_openhd_salt"<<std::endl;
    assert(false);
    // out of memory
  }
  return key;
}

wb::KeyPairTxRx wb::generate_keypair_from_bind_phrase(
    const std::string& bind_phrase) {
  const auto seed_air=
      create_seed_from_password_openhd_salt(bind_phrase, true);
  const auto seed_gnd=
      create_seed_from_password_openhd_salt(bind_phrase, false);
  KeyPairTxRx ret{};
  crypto_box_seed_keypair(ret.key_1.public_key.data(), ret.key_1.secret_key.data(),seed_air.data());
  crypto_box_seed_keypair(ret.key_2.public_key.data(), ret.key_2.secret_key.data(),seed_gnd.data());
  return ret;
}

int wb::write_keypair_to_file(const wb::KeyPairTxRx& keypair_txrx,
                              const std::string& filename) {
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

wb::KeyPairTxRx wb::read_keypair_from_file(const std::string& filename) {
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

std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> wb::create_onetimeauth_subkey(
    const uint64_t& nonce, const std::array<uint8_t, 32U>& session_key) {
  // sub-key for this packet
  std::array<uint8_t, 32> subkey{};
  // We only have an 8 byte nonce, this should be enough entropy
  std::array<uint8_t,16> nonce_buf{0};
  memcpy(nonce_buf.data(),(uint8_t*)&nonce,8);
  crypto_core_hchacha20(subkey.data(),nonce_buf.data(),session_key.data(), nullptr);
  return subkey;
}

void wb::Encryptor::makeNewSessionKey(
    std::array<uint8_t, 24U>& sessionKeyNonce,
    std::array<uint8_t, 32U + 16U>& sessionKeyData) {
  randombytes_buf(session_key.data(), sizeof(session_key));
  randombytes_buf(sessionKeyNonce.data(), sizeof(sessionKeyNonce));
  if (crypto_box_easy(sessionKeyData.data(), session_key.data(), sizeof(session_key),
                      sessionKeyNonce.data(), rx_publickey.data(), tx_secretkey.data()) != 0) {
    throw std::runtime_error("Unable to make session key!");
  }
}

int wb::Encryptor::authenticate_and_encrypt(const uint64_t& nonce,
                                            const uint8_t* src, int src_len,
                                            uint8_t* dest) {
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

std::shared_ptr<std::vector<uint8_t>>
wb::Encryptor::authenticate_and_encrypt_buff(const uint64_t& nonce,
                                             const uint8_t* src,
                                             std::size_t src_len) {
  auto ret=std::make_shared<std::vector<uint8_t>>(src_len + ENCRYPTION_ADDITIONAL_VALIDATION_DATA);
  const auto size=authenticate_and_encrypt(nonce, src, src_len, ret->data());
  assert(size==ret->size());
  return ret;
}

wb::Decryptor::Decryptor(wb::Key key1)
    :rx_secretkey(key1.secret_key),tx_publickey(key1.public_key){
  memset(session_key.data(), 0, sizeof(session_key));
}


int wb::Decryptor::onNewPacketSessionKeyData(
    const std::array<uint8_t, 24U>& sessionKeyNonce,
    const std::array<uint8_t, 32U + 16U>& sessionKeyData) {
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

bool wb::Decryptor::authenticate_and_decrypt(const uint64_t& nonce,
                                             const uint8_t* encrypted,
                                             int encrypted_size,
                                             uint8_t* dest) {
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

std::shared_ptr<std::vector<uint8_t>>
wb::Decryptor::authenticate_and_decrypt_buff(const uint64_t& nonce,
                                             const uint8_t* encrypted,
                                             int encrypted_size) {
  auto ret=std::make_shared<std::vector<uint8_t>>(encrypted_size - crypto_aead_chacha20poly1305_ABYTES);
  const auto res=authenticate_and_decrypt(nonce, encrypted, encrypted_size, ret->data());
  if(res){
    return ret;
  }
  return nullptr;
}
