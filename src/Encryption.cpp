//
// Created by consti10 on 13.08.23.
//

#include "Encryption.h"

wb::KeyPairTxRx wb::generate_keypair_random() {
  KeyPairTxRx ret{};
  crypto_box_keypair(ret.key_1.public_key.data(), ret.key_1.secret_key.data());
  crypto_box_keypair(ret.key_2.public_key.data(), ret.key_2.secret_key.data());
  return ret;
}

std::array<uint8_t, crypto_box_SEEDBYTES> wb::create_seed_from_password(
    const std::string& pw, bool use_salt_air) {
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

wb::KeyPairTxRx wb::generate_keypair_from_bind_phrase(
    const std::string& bind_phrase) {
  const auto seed_air= create_seed_from_password(bind_phrase, true);
  const auto seed_gnd= create_seed_from_password(bind_phrase, false);
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
