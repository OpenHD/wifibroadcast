//
// Created by consti10 on 05.01.24.
//
#include "KeyPair.h"
#include <memory>

std::array<uint8_t, KEYPAIR_RAW_SIZE> wb::KeyPairTxRx::as_raw(
    const KeyPairTxRx& keypair) {
  std::array<uint8_t, 32 * 4> ret{};
  memcpy(ret.data(), &keypair,KEYPAIR_RAW_SIZE);
  return ret;
}

wb::KeyPairTxRx wb::KeyPairTxRx::from_raw(
    const std::array<uint8_t, KEYPAIR_RAW_SIZE>& raw) {
  wb::KeyPairTxRx ret{};
  memcpy(&ret,raw.data(),KEYPAIR_RAW_SIZE);
  return ret;
}
