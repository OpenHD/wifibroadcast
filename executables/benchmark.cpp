
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>
// 2020 Constantin Geier

/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "../src/HelperSources/SchedulingHelper.hpp"
#include "../src/FECEnabled.h"
#include "../src/Encryption.hpp"
#include "../src/HelperSources/RandomBufferPot.hpp"
#include "../src/HelperSources/Benchmark.hpp"
#include <cassert>
#include <cstdio>
#include <cinttypes>
#include <unistd.h>
#include <poll.h>
#include <memory>
#include <string>
#include <chrono>
#include <sstream>
#include <list>

// Test the FEC encoding / decoding and Encryption / Decryption performance (throughput) of this system
// Gives a hint on max possible FEC K target(s) for this platform
// NOTE: Does not take WIFI card throughput into account

static constexpr auto BENCHMARK_FEC_ENCODE=0;
static constexpr auto BENCHMARK_FEC_DECODE=1;
static constexpr auto BENCHMARK_ENCRYPT=2;
static constexpr auto BENCHMARK_DECRYPT=3;
static std::string benchmarkTypeReadable(const int value) {
  switch (value) {
	case BENCHMARK_FEC_ENCODE:return "FEC_ENCODE";
	case BENCHMARK_FEC_DECODE:return "FEC_DECODE";
        case BENCHMARK_ENCRYPT:return "ENCRYPT";
	case BENCHMARK_DECRYPT:return "DECRYPT";
	default:
          assert(false);
          return "ERROR";
  }
}

struct Options {
  // size of each packet
  int PACKET_SIZE = FEC_PACKET_MAX_PAYLOAD_SIZE;
  int FEC_K = 12; // not used when testing encryption / decryption
  int FEC_PERCENTAGE = 20; // not used when testing encryption / decryption
  int benchmarkType = BENCHMARK_FEC_ENCODE;
  // How long the benchmark will run
  int benchmarkTimeSeconds = 10;
};

void benchmark_fec_encode(const Options &options, bool printBlockTime = false) {
  assert(options.benchmarkType == BENCHMARK_FEC_ENCODE);

  std::vector<std::vector<std::shared_ptr<std::vector<uint8_t>>>> fragments_list_in;
  for(int i=0;i<100;i++){
      auto fragments=GenericHelper::createRandomDataBuffers_shared(options.FEC_K,options.PACKET_SIZE,options.PACKET_SIZE);
      fragments_list_in.push_back(fragments);
  }
  FECEncoder encoder{};
  PacketizedBenchmark packetizedBenchmark("FEC_ENCODE", (100 + options.FEC_PERCENTAGE) / 100.0f);
  DurationBenchmark durationBenchmark("FEC_BLOCK_ENCODE", options.PACKET_SIZE * options.FEC_K);
  const auto cb = [&packetizedBenchmark](const uint8_t* packet,int packet_len)mutable {
    // called each time we got a new 'packet'
    packetizedBenchmark.doneWithPacket(packet_len);
  };
  encoder.outputDataCallback = cb;
  const auto testBegin = std::chrono::steady_clock::now();
  packetizedBenchmark.begin();
  // run the test for X seconds
  while ((std::chrono::steady_clock::now() - testBegin) < std::chrono::seconds(options.benchmarkTimeSeconds)) {
      for (const auto &fragments: fragments_list_in) {
          durationBenchmark.start();
          const auto n_secondary= calculate_n_secondary_fragments(fragments.size(),options.FEC_PERCENTAGE);
          encoder.encode_block(fragments,n_secondary);
          durationBenchmark.stop();
      }
  }
  packetizedBenchmark.end();
  durationBenchmark.print();
}


// Simple benchmark for encryption / decryption performance
void benchmark_crypt(const Options &options,const bool packet_validation_only) {
  assert(options.benchmarkType == BENCHMARK_ENCRYPT || options.benchmarkType == BENCHMARK_DECRYPT);
  const bool encrypt=options.benchmarkType==BENCHMARK_ENCRYPT;
  wb::Encryptor encryptor{wb::generate_keypair_deterministic(true)};
  encryptor.set_encryption_enabled(!packet_validation_only);
  wb::Decryptor decryptor{wb::generate_keypair_deterministic(true)};
  decryptor.set_encryption_enabled(!packet_validation_only);
  std::array<uint8_t, crypto_box_NONCEBYTES> sessionKeyNonce{};
  std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES> sessionKeyData{};
  encryptor.makeNewSessionKey(sessionKeyNonce, sessionKeyData);
  decryptor.onNewPacketSessionKeyData(sessionKeyNonce,sessionKeyData);

  constexpr auto N_BUFFERS = 1000;
  RandomBufferPot randomBufferPot{N_BUFFERS, (std::size_t)options.PACKET_SIZE};

  struct EncryptedPacket{
      uint64_t nonce;
      std::shared_ptr<std::vector<uint8_t>> data;
  };
  std::vector<EncryptedPacket> encrypted_packets_buff;
  if(!encrypt){
      // encrypt the packets and store them for later use, me measure decryption throughput
      for(int i=0;i<N_BUFFERS;i++){
          auto buf=randomBufferPot.getBuffer(i);
          auto encrypted= encryptor.authenticate_and_encrypt_buff(
              i, buf->data(), buf->size());
          EncryptedPacket encryptedPacket{(uint64_t)i,encrypted};
          encrypted_packets_buff.push_back(encryptedPacket);
      }
  }
  std::string tag;
  if(encrypt){
      if(packet_validation_only){
          tag="Calc Validation";
      }else{
          tag="Encrypt";
      }
  }else{
      if(packet_validation_only){
          tag="Validate";
      }else{
          tag="Decrypt";
      }
  }
  std::cout<<"Benchmarking "<<tag<<std::endl;
  PacketizedBenchmark packetizedBenchmark(tag, 1.0); // roughly 1:1
  DurationBenchmark durationBenchmark(tag, options.PACKET_SIZE);

  const auto testBegin = std::chrono::steady_clock::now();
  packetizedBenchmark.begin();

  uint64_t nonce=0;
  while ((std::chrono::steady_clock::now() - testBegin) < std::chrono::seconds(options.benchmarkTimeSeconds)) {
      for (int i = 0; i < N_BUFFERS; i++) {
          if(encrypt){
            const auto buffer = randomBufferPot.getBuffer(i);
            durationBenchmark.start();
            const auto encrypted = encryptor.authenticate_and_encrypt_buff(
                nonce, buffer->data(), buffer->size());
            durationBenchmark.stop();
            assert(!encrypted->empty());
            nonce++;
            packetizedBenchmark.doneWithPacket(buffer->size());
          }else{
            const auto& encrypted=encrypted_packets_buff.at(i);
            durationBenchmark.start();
            auto decrypted= decryptor.authenticate_and_decrypt_buff(
                encrypted.nonce, encrypted.data->data(),
                encrypted.data->size());
            assert(!decrypted->empty());
            durationBenchmark.stop();
            packetizedBenchmark.doneWithPacket(decrypted->size());
          }
      }
  }
  packetizedBenchmark.end();
  durationBenchmark.print();
}

int main(int argc, char *const *argv) {
  int opt;
  Options options{};
  print_optimization_method();
  SchedulingHelper::setThreadParamsMaxRealtime();
  SchedulingHelper::printCurrentThreadPriority("TEST_MAIN");
  SchedulingHelper::printCurrentThreadSchedulingPolicy("TEST_MAIN");

  while ((opt = getopt(argc, argv, "s:k:p:x:t:")) != -1) {
	switch (opt) {
	  case 's':options.PACKET_SIZE = atoi(optarg);
		break;
	  case 'k':options.FEC_K = atoi(optarg);
		break;
	  case 'p':options.FEC_PERCENTAGE = atoi(optarg);
		break;
	  case 'x': options.benchmarkType = atoi(optarg);
		break;
	  case 't':options.benchmarkTimeSeconds = atoi(optarg);
		break;
	  default: /* '?' */
	  show_usage:
		std::cout
			<< "Usage: [-s=packet size in bytes] [-k=FEC_K] [-p=FEC_P] [-x Benchmark type. 0=FEC_ENCODE 1=FEC_DECODE 2=ENCRYPT 3=DECRYPT ] [-t benchmark time in seconds]\n";
		return 1;
	}
  }

  std::cout << "Benchmark type: " << options.benchmarkType << "(" << benchmarkTypeReadable(options.benchmarkType)
			<< ")\n";
  std::cout << "PacketSize: " << options.PACKET_SIZE << " B\n";
  if(options.benchmarkType==BENCHMARK_FEC_ENCODE || options.benchmarkType==BENCHMARK_FEC_DECODE){
        std::cout << "FEC_K: " << options.FEC_K << "\n";
        std::cout << "FEC_PERCENTAGE: " << options.FEC_PERCENTAGE << "\n";
  }
  std::cout << "Benchmark time: " << options.benchmarkTimeSeconds << " s\n";
  switch (options.benchmarkType) {
	case BENCHMARK_FEC_ENCODE:
          benchmark_fec_encode(options);
	  break;
	case BENCHMARK_FEC_DECODE:
	  std::cout << "Unimplemented"<<std::endl;
	  break;
	case BENCHMARK_ENCRYPT:
        case BENCHMARK_DECRYPT:
          benchmark_crypt(options, false);
          benchmark_crypt(options, true);
	  break;
  }
  return 0;
}

// Quick math:
// With a 20Mbit/s @ 60 fps one frame is on average 20*1024*1024 / 8 / 60 = 43690 bytes.
// With a max usable MTU of 1446 Bytes this means one block ideally consists of up to 443690/1446=306 packets
// if you analyze the dji link (Bitrate and resolution unknown though) you get:
// For an IDR frame: 72674 bytes, for a non-idr frame: 34648, 43647
