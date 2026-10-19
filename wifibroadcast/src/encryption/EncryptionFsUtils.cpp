//
// Created by consti10 on 13.08.23.
//

#include "EncryptionFsUtils.h"

#include <sodium/crypto_box.h>
#include <spdlog/spdlog.h>

#include <cassert>
#include <cstring>
#include <iostream>

#include "../wifibroadcast_spdlog.h"

bool wb::write_keypair_to_file(const wb::KeyPairTxRx& keypair_txrx,
                               const std::string& filename) {
  FILE* fp;
  if ((fp = fopen(filename.c_str(), "wb")) == nullptr) {
    std::cerr << "Unable to save " << filename << std::endl;
    return false;
  }
  const auto raw = KeyPairTxRx::as_raw(keypair_txrx);
  auto res = fwrite(raw.data(), raw.size(), 1, fp);
  if (res != 1) {
    std::cerr << "Cannot write to file" << std::endl;
    fclose(fp);
    return false;
  }
  fclose(fp);
  return true;
}

std::optional<wb::KeyPairTxRx> wb::read_keypair_from_file(
    const std::string& filename) {
  KeyPairTxRx ret{};
  FILE* fp;
  if ((fp = fopen(filename.c_str(), "rb")) == nullptr) {
    std::cerr << fmt::format("Unable to open {}: {}", filename.c_str(),
                             strerror(errno))
              << std::endl;
    return std::nullopt;
  }
  std::array<uint8_t, KEYPAIR_RAW_SIZE> raw{};
  auto res = fread(raw.data(), raw.size(), 1, fp);
  if (res != 1) {
    std::cerr << "Cannot read keypair data" << std::endl;
    fclose(fp);
    return std::nullopt;
  }
  fclose(fp);
  return KeyPairTxRx::from_raw(raw);
}
