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
