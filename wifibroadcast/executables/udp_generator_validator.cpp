//
// Created by consti10 on 30.12.21.
//

// testing utility
// when run as creator, creates deterministic packets and forwards them as udp
// packets when run as validator, receives UDP packets (from a creator instance)
// and validates these (deterministic) packets This way one can (for example)
// run a wfb_tx instance and the creator on one pc, and run a wfb_rx instance
// and a validator on another pc and measure packet loss as well as validate the
// content of the packets.

#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <cassert>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <memory>
#include <sstream>
#include <string>
#include <thread>

#include "../src/HelperSources/Helper.hpp"
#include "../src/HelperSources/RandomBufferPot.hpp"
#include "../src/HelperSources/SequenceNumberDebugger.hpp"
#include "../src/HelperSources/SocketHelper.hpp"

struct Options {
  // size of each packet
  int PACKET_SIZE = 1446;
  // wanted bitrate (MBit/s)
  int wanted_packets_per_second = 1;
  bool generator = true;  // else validator
  int udp_port =
      5600;  // port to send data to (generator) or listen on (validator)
  std::string udp_host = SocketHelper::ADDRESS_LOCALHOST;
  // How long you want this program to run, it will terminate after the
  // specified time. You can also always manually terminate with crt+x
  std::chrono::seconds runTimeSeconds = std::chrono::seconds(10);
};

using SEQUENCE_NUMBER = uint32_t;
using TIMESTAMP = uint64_t;

// the content of each packet is simple -
// the sequence number appended by some random data depending on the sequence
// number
namespace TestPacket {
// each test packet has the following layout:
// 4 bytes (uint32_t) sequence number
// 8 bytes (uint64_t) timestamp, nanoseconds
// rest is semi-random data (RandomBufferPot)
struct TestPacketHeader {
  SEQUENCE_NUMBER seqNr;
  TIMESTAMP ts;
} __attribute__((packed));
//
static void writeTestPacketHeader(std::vector<uint8_t> &data,
                                  TestPacketHeader header) {
  assert(data.size() >= sizeof(TestPacketHeader));
  // convert to network byte order
  header.seqNr = htonl(header.seqNr);
  header.ts = htole64(header.ts);
  std::memcpy(data.data(), &header.seqNr, sizeof(header.seqNr));
  // std::memcpy(data.data()+sizeof(header.seqNr),&header.ts,sizeof(header.ts));
}
//
static TestPacketHeader getTestPacketHeader(const std::vector<uint8_t> &data) {
  assert(data.size() >= sizeof(TestPacketHeader));
  TestPacketHeader ret{};
  std::memcpy(&ret.seqNr, data.data(), sizeof(ret.seqNr));
  // std::memcpy(&ret.ts,data.data()+sizeof(ret.seqNr),sizeof(ret.ts));
  ret.seqNr = ntohl(ret.seqNr);
  // ret.ts= ntohll(ret.ts); //TODO
  return ret;
}
// Returns true if everything except the first couple of bytes
// (TestPacketHeader) match. The first couple of bytes are the TestPacketHeader
// (which is written after creating the packet)
bool checkPayloadMatches(const std::vector<uint8_t> &sb,
                         const std::vector<uint8_t> &rb) {
  if (sb.size() != rb.size()) {
    return false;
  }
  const int result = memcmp(&sb.data()[sizeof(TestPacketHeader)],
                            &rb.data()[sizeof(TestPacketHeader)],
                            sb.size() - sizeof(TestPacketHeader));
  return result == 0;
}
};  // namespace TestPacket

static void loopUntilDone(const Options &options) {
  const float wantedBitRate_MBits =
      (float)(options.PACKET_SIZE * options.wanted_packets_per_second * 8.0f /
              1024.0f / 1024.0f);
  std::cout << "PACKET_SIZE: " << options.PACKET_SIZE << "\n";
  std::cout << "wanted_packets_per_second: "
            << options.wanted_packets_per_second << "\n";
  std::cout << "wanted Bitrate: " << wantedBitRate_MBits << "MBit/s" << "\n";
  std::cout << "Generator: " << (options.generator ? "yes" : "no") << "\n";
  std::cout << "UDP port: " << options.udp_port << "\n";
  std::cout << "UDP host: " << options.udp_host << "\n";
  std::cout << "Run time (s): " << options.runTimeSeconds.count() << "\n";

  const auto randomBufferPot =
      std::make_unique<RandomBufferPot>(1000, options.PACKET_SIZE);

  const auto deltaBetweenPackets = std::chrono::nanoseconds(
      (1000 * 1000 * 1000) / options.wanted_packets_per_second);
  auto lastLog = std::chrono::steady_clock::now();

  if (options.generator) {
    static bool quit = false;
    const auto startTime = std::chrono::steady_clock::now();
    signal(SIGTERM, [](int sig) { quit = true; });
    uint32_t seqNr = 0;
    SocketHelper::UDPForwarder forwarder(options.udp_host, options.udp_port);
    auto before = std::chrono::steady_clock::now();
    while (!quit) {
      const auto packet = randomBufferPot->getBuffer(seqNr);
      TestPacket::writeTestPacketHeader(*packet.get(), {seqNr, 0});

      forwarder.forwardPacketViaUDP(packet->data(), packet->size());
      // keep logging to a minimum for fast testing
      if (options.wanted_packets_per_second < 10) {
        std::cout << "Sent packet:" << seqNr << "\n";
      } else {
        if (std::chrono::steady_clock::now() - lastLog >
            std::chrono::seconds(1)) {
          std::cout << "Sent packets:" << seqNr << "\n";
          lastLog = std::chrono::steady_clock::now();
        }
      }
      seqNr++;
      // std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      while (std::chrono::steady_clock::now() - before < deltaBetweenPackets) {
        // busy wait
      }
      before = std::chrono::steady_clock::now();
      if ((std::chrono::steady_clock::now() - startTime) >
          options.runTimeSeconds) {
        quit = true;
      }
    }
  } else {
    static int nValidPackets = 0;
    static int nInvalidPackets = 0;
    static auto lastLog = std::chrono::steady_clock::now();
    static SequenceNumberDebugger sequenceNumberDebugger{};

    const auto cb = [&randomBufferPot](const uint8_t *payload,
                                       const std::size_t payloadSize) mutable {
      const auto receivedPacket =
          std::vector<uint8_t>(payload, payload + payloadSize);

      const auto info = TestPacket::getTestPacketHeader(receivedPacket);
      sequenceNumberDebugger.sequenceNumber(info.seqNr);

      auto validPacket = randomBufferPot->getBuffer(info.seqNr);
      TestPacket::writeTestPacketHeader(*validPacket, {info.seqNr, 0});

      bool valid =
          TestPacket::checkPayloadMatches(receivedPacket, *validPacket);

      if (valid) {
        nValidPackets++;
      } else {
        nInvalidPackets++;
        std::cout << "Packet nr:" << info.seqNr << "is invalid."
                  << " N packets V,INV:" << nValidPackets << ","
                  << nInvalidPackets << "\n";
      }
      auto delta = std::chrono::steady_clock::now() - lastLog;
      if (delta > std::chrono::milliseconds(500)) {
        // std::cout<<"Packet nr:"<< info.seqNr<<"Valid:"<<(valid ? "y":"n")<<"
        // N packets V,INV:"<<nValidPackets<<","<<nInvalidPackets<<"\n";
        sequenceNumberDebugger.debug(true);
        lastLog = std::chrono::steady_clock::now();
      }
    };

    static SocketHelper::UDPReceiver receiver{SocketHelper::ADDRESS_LOCALHOST,
                                              options.udp_port, cb};
    static bool quit = false;
    signal(SIGTERM, [](int sig) { quit = true; });
    const auto startTime = std::chrono::steady_clock::now();
    // run until ctr+x or time has elapsed
    receiver.runInBackground();
    // keep the thread alive until either ctr+x is pressed or we run out of
    // time.
    while (!quit) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      if ((std::chrono::steady_clock::now() - startTime) >
          options.runTimeSeconds) {
        quit = true;
      }
    }
    receiver.stopBackground();
  }
}

int main(int argc, char *const *argv) {
  int opt;
  Options options;
  while ((opt = getopt(argc, argv, "s:vu:b:h:p:t:")) != -1) {
    switch (opt) {
      case 's':
        options.PACKET_SIZE = atoi(optarg);
        break;
      case 'v':
        options.generator = false;
        break;
      case 'u':
        options.udp_port = std::stoi(optarg);
        break;
      case 'p':
        options.wanted_packets_per_second = std::atoi(optarg);
        break;
      case 'h':
        options.udp_host = std::string(optarg);
        break;
      case 't':
        options.runTimeSeconds = std::chrono::seconds(std::atoi(optarg));
        break;
      default: /* '?' */
      show_usage:
        std::cout << "Usage: [-s=packet size in bytes,default:"
                  << options.PACKET_SIZE
                  << "] [-v validate packets (else generate packets)] [-u udp "
                     "port,default:"
                  << options.udp_port
                  << "] [-h udp host default:" << options.udp_host << "]"
                  << "[-p wanted packets per second, default:"
                  << options.wanted_packets_per_second << "]" << "\n";
        return 1;
    }
  }
  if (options.PACKET_SIZE < sizeof(SEQUENCE_NUMBER)) {
    std::cout << "Error min packet size is " << sizeof(SEQUENCE_NUMBER)
              << " bytes\n";
    return 0;
  }
  loopUntilDone(options);
  return 0;
}
