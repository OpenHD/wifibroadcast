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

#include <cassert>
#include <chrono>
#include <cinttypes>
#include <climits>
#include <cstdio>
#include <ctime>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "../src//encryption/EncryptionFsUtils.h"
#include "../src/HelperSources/Helper.hpp"
#include "../src/Ieee80211Header.hpp"
#include "../src/WBPacketHeader.h"
#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/WBTxRx.h"
#include "../src/encryption/Decryptor.h"
#include "../src/encryption/Encryption.h"
#include "../src/encryption/Encryptor.h"
#include "../src/fec/FEC.h"
#include "../src/fec/FECDecoder.h"
#include "../src/fec/FECEncoder.h"
#include "../src/wifibroadcast_spdlog.h"

// Simple unit testing for the FEC lib that doesn't require wifi cards

namespace TestFEC {

// randomly select a possible combination of received indices (either primary or
// secondary).
static void testFecCPlusPlusWrapperY(const int nPrimaryFragments,
                                     const int nSecondaryFragments) {
  srand(time(NULL));
  constexpr auto FRAGMENT_SIZE = 1446;

  auto txBlockBuffer = GenericHelper::createRandomDataBuffers<FRAGMENT_SIZE>(
      nPrimaryFragments + nSecondaryFragments);
  std::cout << "XSelected nPrimaryFragments:" << nPrimaryFragments
            << " nSecondaryFragments:" << nSecondaryFragments << "\n";

  fecEncode(FRAGMENT_SIZE, txBlockBuffer, nPrimaryFragments,
            nSecondaryFragments);
  std::cout << "Encode done\n";

  for (int test = 0; test < 100; test++) {
    // takes nPrimaryFragments random (possible) indices without duplicates
    // NOTE: Perhaps you could calculate all possible permutations, but these
    // would be quite a lot. Therefore, I just use n random selections of
    // received indices
    auto receivedFragmentIndices = GenericHelper::takeNRandomElements(
        GenericHelper::createIndices(nPrimaryFragments + nSecondaryFragments),
        nPrimaryFragments);
    assert(receivedFragmentIndices.size() == nPrimaryFragments);
    std::cout << "(Emulated) receivedFragmentIndices"
              << StringHelper::vectorAsString(receivedFragmentIndices) << "\n";

    auto rxBlockBuffer = std::vector<std::array<uint8_t, FRAGMENT_SIZE>>(
        nPrimaryFragments + nSecondaryFragments);
    std::vector<bool> fragmentMap(nPrimaryFragments + nSecondaryFragments,
                                  FRAGMENT_STATUS_UNAVAILABLE);
    for (const auto idx : receivedFragmentIndices) {
      rxBlockBuffer[idx] = txBlockBuffer[idx];
      fragmentMap[idx] = FRAGMENT_STATUS_AVAILABLE;
    }

    fecDecode(FRAGMENT_SIZE, rxBlockBuffer, nPrimaryFragments, fragmentMap);

    for (unsigned int i = 0; i < nPrimaryFragments; i++) {
      // std::cout<<"Comparing fragment:"<<i<<"\n";
      GenericHelper::assertArraysEqual(txBlockBuffer[i], rxBlockBuffer[i]);
    }
  }
}

// Note: This test will take quite a long time ! (or rather ages :) when trying
// to do all possible combinations. )
static void testFecCPlusPlusWrapperX() {
  std::cout << "testFecCPlusPlusWrapper Begin\n";
  // constexpr auto MAX_N_P_F=128;
  // constexpr auto MAX_N_S_F=128;
  //  else it really takes ages
  constexpr auto MAX_N_P_F = 32;
  constexpr auto MAX_N_S_F = 32;
  for (int nPrimaryFragments = 1; nPrimaryFragments < MAX_N_P_F;
       nPrimaryFragments++) {
    for (int nSecondaryFragments = 0; nSecondaryFragments < MAX_N_S_F;
         nSecondaryFragments++) {
      testFecCPlusPlusWrapperY(nPrimaryFragments, nSecondaryFragments);
    }
  }
  std::cout << "testFecCPlusPlusWrapper End\n";
}

// Chooses randomly
// 1) block size (n fragments in block)
// 2) size of data in each fragment in a block
// 3) a fec overhead value (k)
// 4) a specific amount of dropped packets, but keeping enough packets to be
// fully recoverable
static void test_fec_stream_random_bs_fs_overhead_dropped() {
  wifibroadcast::log::get_default()->debug(
      "test_random_bs_fs_overhead_dropped begin");
  std::vector<std::vector<std::vector<uint8_t>>> fragmented_frames_in;
  std::vector<std::vector<uint8_t>> fragmented_frames_sequential_in;
  for (int i = 0; i < 1000 * 2; i++) {
    std::vector<std::vector<uint8_t>> fragmented_frame;
    const auto n_fragments = GenericHelper::create_random_number_between(
        1, MAX_N_P_FRAGMENTS_PER_BLOCK);
    for (int j = 0; j < n_fragments; j++) {
      const auto buff_size = GenericHelper::create_random_number_between(
          1, FEC_PACKET_MAX_PAYLOAD_SIZE);
      // const auto
      // buff_size=GenericHelper::create_random_number_between(12,12);
      auto buff = GenericHelper::createRandomDataBuffer(buff_size);
      fragmented_frame.push_back(buff);
      fragmented_frames_sequential_in.push_back(buff);
    }
    // wifibroadcast::log::get_default()->debug("test_random_bs_fs_overhead_dropped
    // with {} fragments",fragmented_frame.size());
    fragmented_frames_in.push_back(fragmented_frame);
  }
  FECEncoder encoder{};
  FECDecoder decoder{10};
  std::vector<std::vector<uint8_t>> testOut;
  // The indices of packets we shall drop
  std::vector<unsigned int> curr_indices_of_packets_to_drop{};

  const auto cb1 = [&decoder, &curr_indices_of_packets_to_drop,
                    &fragmented_frames_sequential_in](
                       const uint8_t *payload,
                       const std::size_t payloadSize) mutable {
    auto *hdr = (FECPayloadHdr *)payload;
    if (GenericHelper::vec_contains(curr_indices_of_packets_to_drop,
                                    hdr->fragment_idx)) {
      // wifibroadcast::log::get_default()->debug("Dropping packet {} in
      // {}",(int)hdr->fragment_idx,(int)hdr->n_primary_fragments);
    } else {
      decoder.process_valid_packet(payload, payloadSize);
    }
    /*if(hdr->fragment_idx<hdr->n_primary_fragments){
      auto
    lol=std::vector<uint8_t>(payload+sizeof(FECPayloadHdr),payload+payloadSize);
      auto original=fragmented_frames_sequential_in[hdr->fragment_idx];
      GenericHelper::assertVectorsEqual(original,lol);
    }*/
  };
  int out_index = 0;
  const auto cb2 = [&testOut, &fragmented_frames_sequential_in, &out_index](
                       const uint8_t *payload,
                       std::size_t payloadSize) mutable {
    auto buff = std::vector<uint8_t>(payload, payload + payloadSize);
    testOut.emplace_back(buff);
    // wifibroadcast::log::get_default()->debug("Out:{}",payloadSize);
    GenericHelper::assertVectorsEqual(
        fragmented_frames_sequential_in[out_index], buff);
    out_index++;
  };
  encoder.m_out_cb = cb1;
  decoder.mSendDecodedPayloadCallback = cb2;
  for (int i = 0; i < fragmented_frames_in.size(); i++) {
    auto fragmented_frame = fragmented_frames_in[i];
    const auto n_secondary_fragments =
        GenericHelper::create_random_number_between(
            0, MAX_N_S_FRAGMENTS_PER_BLOCK);
    // const auto n_secondary_fragments=0;
    //  We'l drop a random amount of fragments - but only up to as many
    //  fragments such that we can still recover the block
    const auto n_fragments_to_drop =
        GenericHelper::create_random_number_between(0, n_secondary_fragments);
    // const auto n_fragments_to_drop=1;
    auto indices = GenericHelper::createIndices(fragmented_frame.size() +
                                                n_secondary_fragments);
    auto indices_packets_to_drop =
        GenericHelper::takeNRandomElements(indices, n_fragments_to_drop);
    wifibroadcast::log::get_default()->debug(
        "Feeding block of {} fragments with {} secondary fragments and "
        "dropping {}",
        fragmented_frame.size(), n_secondary_fragments, n_fragments_to_drop);
    curr_indices_of_packets_to_drop = indices_packets_to_drop;
    encoder.encode_block(
        GenericHelper::convert_vec_of_vec_to_shared(fragmented_frame),
        n_secondary_fragments);
  }
  GenericHelper::assertVectorsOfVectorsEqual(fragmented_frames_sequential_in,
                                             testOut);
  wifibroadcast::log::get_default()->debug(
      "test_random_bs_fs_overhead_dropped end");
}

}  // namespace TestFEC

// Test encryption+packet validation and packet validation only
static void test_encrypt_decrypt_validate(const bool use_key_from_file,
                                          bool message_signing_only) {
  const std::string TEST_TYPE = message_signing_only ? "Sign" : "Encrypt&Sign";
  const std::string TEST_KEY_TYPE =
      use_key_from_file ? "key from file" : "default key";
  fmt::print("Testing {} with {}\n", TEST_TYPE, TEST_KEY_TYPE);
  const std::string KEY_FILENAME = "../example_key/txrx.key";
  wb::KeyPairTxRx keyPairTxRx{};
  if (use_key_from_file) {
    auto tmp = wb::read_keypair_from_file(KEY_FILENAME);
    assert(tmp.has_value());
    keyPairTxRx = tmp.value();
  } else {
    const auto before = std::chrono::steady_clock::now();
    keyPairTxRx = wb::generate_keypair_from_bind_phrase("openhd");
    std::cout << "Generating keypair from bind phrase took:"
              << MyTimeHelper::R(std::chrono::steady_clock::now() - before)
              << std::endl;
  }

  wb::Encryptor encryptor{
      keyPairTxRx.get_tx_key(true)};  // We send from air unit
  encryptor.set_encryption_enabled(!message_signing_only);
  wb::Decryptor decryptor{keyPairTxRx.get_rx_key(false)};  // To the ground unit
  auto decryptor_encryption_enabled = !message_signing_only;
  struct SessionStuff {
    std::array<uint8_t, crypto_box_NONCEBYTES>
        sessionKeyNonce{};  // filled with random data
    std::array<uint8_t,
               crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES>
        sessionKeyData{};
  };
  SessionStuff sessionKeyPacket;
  // make session key (tx)
  encryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce,
                              sessionKeyPacket.sessionKeyData);
  // and "receive" session key (rx)
  assert(decryptor.onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce,
                                             sessionKeyPacket.sessionKeyData) ==
         wb::Decryptor::SESSION_VALID_NEW);
  // now encrypt a couple of packets and decrypt them again afterwards
  for (uint64_t nonce = 0; nonce < 200; nonce++) {
    const auto data =
        GenericHelper::createRandomDataBuffer(FEC_PACKET_MAX_PAYLOAD_SIZE);
    const auto encrypted = encryptor.authenticate_and_encrypt_buff(
        nonce, data.data(), data.size());
    {
      // Correct usage - let packets through and get the original data back
      const auto decrypted = decryptor.authenticate_and_decrypt_buff(
          nonce, encrypted->data(), encrypted->size(),
          decryptor_encryption_enabled);
      assert(GenericHelper::compareVectors(data, *decrypted) == true);
    }
    {
      // tamper with the nonce - shouldn't let packets through
      const auto decrypted = decryptor.authenticate_and_decrypt_buff(
          nonce + 1, encrypted->data(), encrypted->size(),
          decryptor_encryption_enabled);
      assert(decrypted == nullptr);
    }
    {
      // tamper with the encryption suffix -  shouldn't let data through
      auto encrypted_wrong_sing = encrypted;
      encrypted_wrong_sing->at(encrypted_wrong_sing->size() - 1) = 0;
      encrypted_wrong_sing->at(encrypted_wrong_sing->size() - 2) = 0;
      const auto decrypted = decryptor.authenticate_and_decrypt_buff(
          nonce, encrypted_wrong_sing->data(), encrypted_wrong_sing->size(),
          decryptor_encryption_enabled);
      assert(decrypted == nullptr);
    }
  }
  // and make sure we don't let packets with an invalid signing suffix through
  for (uint64_t nonce = 0; nonce < 200; nonce++) {
    const auto data =
        GenericHelper::createRandomDataBuffer(FEC_PACKET_MAX_PAYLOAD_SIZE);
    const auto enrypted_wrong_sign = std::make_shared<std::vector<uint8_t>>();
    enrypted_wrong_sign->resize(data.size() +
                                ENCRYPTION_ADDITIONAL_VALIDATION_DATA);
    memcpy(enrypted_wrong_sign->data(), data.data(), data.size());
    const auto decrypted = decryptor.authenticate_and_decrypt_buff(
        nonce, enrypted_wrong_sign->data(), enrypted_wrong_sign->size(),
        decryptor_encryption_enabled);
    assert(decrypted == nullptr);
  }
  fmt::print("Test {} with {} passed\n", TEST_TYPE, TEST_KEY_TYPE);
}
static void test_encryption_serialize() {
  auto keypair1 = wb::generate_keypair_from_bind_phrase("openhd");
  auto raw = wb::KeyPairTxRx::as_raw(keypair1);
  auto serialized_deserialized = wb::KeyPairTxRx::from_raw(raw);
  assert(keypair1 == serialized_deserialized);
  fmt::print("Serialize / Deserialize test passed\n");
}

static void test_manual_retransmission() {
  std::cout << "Testing Manual Retransmission" << std::endl;

  // Create a dummy card
  auto card = wifibroadcast::create_card_emulate(true);
  std::vector<wifibroadcast::WifiCard> cards;
  cards.push_back(card);

  // Create WBTxRx with dummy link
  WBTxRx::Options options_txrx{};
  options_txrx.tx_without_pcap = true;  // Avoid real pcap
  auto radiotap_header_holder_tx = std::make_shared<RadiotapHeaderTxHolder>();
  std::shared_ptr<WBTxRx> txrx =
      std::make_shared<WBTxRx>(cards, options_txrx, radiotap_header_holder_tx);

  // Enable dummy link interception
  auto dummy_link = txrx->get_dummy_link();
  assert(dummy_link);

  // Create WBStreamTx with retransmission enabled
  WBStreamTx::Options options_stream{};
  options_stream.enable_fec =
      false;  // Easier to test with telemetry/plain packets
  options_stream.enable_retransmission = true;
  options_stream.radio_port = 5;  // Arbitrary

  WBStreamTx stream_tx(txrx, options_stream, radiotap_header_holder_tx);
  stream_tx.set_encryption(false);

  // Create the receiver dummy link BEFORE sending, to avoid race conditions
  // (packet lost if sent before receiver binds)
  auto dummy_link_rx = std::make_shared<DummyLink>(false);  // Ground unit

  // Create a dummy packet
  std::string payload_str = "Hello Retransmission";
  auto payload = std::make_shared<std::vector<uint8_t>>(payload_str.begin(),
                                                        payload_str.end());

  // Send packet
  bool queued = stream_tx.try_enqueue_packet(payload);
  assert(queued);

  // Wait for the packet to be "sent" (processed by the thread)
  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Let's read packets until we find ours (ignore session key packets)
  std::shared_ptr<std::vector<uint8_t>> sent_packet = nullptr;
  WBPacketHeader *header = nullptr;

  for (int i = 0; i < 10; i++) {
    sent_packet = dummy_link_rx->rx_radiotap();
    if (sent_packet == nullptr) {
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
      continue;
    }
    std::cout << "Received packet of size " << sent_packet->size() << std::endl;

    std::string received_str(sent_packet->begin(), sent_packet->end());
    size_t pos = received_str.find(payload_str);
    if (pos != std::string::npos) {
      // Found it
      // Check WBPacketHeader
      // The structure is WBPacketHeader + FECDisabledHeader + Payload
      // WBPacketHeader size is sizeof(WBPacketHeader).
      // FECDisabledHeader size is 8 bytes.
      size_t header_pos = pos - sizeof(WBPacketHeader) - 8;
      header = (WBPacketHeader *)(sent_packet->data() + header_pos);
      break;
    }
  }

  assert(sent_packet != nullptr);
  assert(header != nullptr);

  std::cout << "Packet Type: " << (int)header->packet_type << std::endl;
  std::cout << "Packet Flags: " << (int)header->packet_flags << std::endl;
  std::cout << "Sequence: " << header->stream_packet_idx << std::endl;

  assert(header->packet_type == WB_PACKET_TYPE_TELEMETRY);
  assert(header->packet_flags == 0);
  uint32_t seq_num = header->stream_packet_idx;

  // Request retransmission
  std::cout << "Requesting retransmission of seq " << seq_num << std::endl;
  stream_tx.process_retransmission_request(header->packet_type, seq_num, 0);

  std::this_thread::sleep_for(std::chrono::milliseconds(200));

  // Read the retransmitted packet
  auto retransmitted_packet = dummy_link_rx->rx_radiotap();
  assert(retransmitted_packet != nullptr);

  // Validate retransmitted packet
  std::string re_received_str(retransmitted_packet->begin(),
                              retransmitted_packet->end());
  size_t re_pos = re_received_str.find(payload_str);
  assert(re_pos != std::string::npos);

  // Adjust header position (account for FECDisabledHeader)
  size_t re_header_pos = re_pos - sizeof(WBPacketHeader) - 8;
  WBPacketHeader *re_header =
      (WBPacketHeader *)(retransmitted_packet->data() + re_header_pos);

  std::cout << "Retransmitted Packet Type: " << (int)re_header->packet_type
            << std::endl;
  std::cout << "Retransmitted Packet Flags: " << (int)re_header->packet_flags
            << std::endl;

  assert(re_header->packet_type == WB_PACKET_TYPE_TELEMETRY);
  assert((re_header->packet_flags & WB_PACKET_FLAG_RETRANSMITTED) != 0);
  assert(re_header->stream_packet_idx == seq_num);

  std::cout << "Retransmission Test Passed" << std::endl;
}

static void test_auto_retransmission() {
  std::cout << "Testing Auto Retransmission" << std::endl;

  // Setup Tx side (Air)
  auto card_air = wifibroadcast::create_card_emulate(true);
  std::vector<wifibroadcast::WifiCard> cards_air;
  cards_air.push_back(card_air);

  WBTxRx::Options options_txrx_air{};
  options_txrx_air.tx_without_pcap = true;
  options_txrx_air.use_gnd_identifier = false;  // Air unit
  auto radiotap_header_holder = std::make_shared<RadiotapHeaderTxHolder>();
  std::shared_ptr<WBTxRx> txrx_air = std::make_shared<WBTxRx>(
      cards_air, options_txrx_air, radiotap_header_holder);
  txrx_air->start_receiving();  // Listen for retransmission requests

  // Setup Rx side (Gnd)
  auto card_gnd = wifibroadcast::create_card_emulate(false);
  std::vector<wifibroadcast::WifiCard> cards_gnd;
  cards_gnd.push_back(card_gnd);

  WBTxRx::Options options_txrx_gnd{};
  options_txrx_gnd.tx_without_pcap = true;
  options_txrx_gnd.use_gnd_identifier = true;  // Ground unit
  std::shared_ptr<WBTxRx> txrx_gnd = std::make_shared<WBTxRx>(
      cards_gnd, options_txrx_gnd, radiotap_header_holder);
  txrx_gnd->start_receiving();  // Listen for video/telemetry

  // Setup WBStreamTx on Air
  WBStreamTx::Options options_stream_tx{};
  options_stream_tx.enable_fec = false;
  options_stream_tx.enable_retransmission = true;
  options_stream_tx.radio_port = 5;

  WBStreamTx stream_tx(txrx_air, options_stream_tx, radiotap_header_holder);
  stream_tx.set_encryption(false);

  // Setup WBStreamRx on Gnd
  WBStreamRx::Options options_stream_rx{};
  options_stream_rx.enable_fec = false;
  options_stream_rx.radio_port = 5;
  options_stream_rx.enable_threading = true;  // Use threading to process queue
  options_stream_rx.enable_retransmission = true;

  WBStreamRx stream_rx(txrx_gnd, options_stream_rx);

  std::atomic<int> received_packet_count = 0;
  std::vector<std::string> received_payloads;

  stream_rx.set_callback([&](const uint8_t *payload, size_t size) {
    std::string s(payload, payload + size);
    std::cout << "Callback received: " << s << std::endl;
    received_payloads.push_back(s);
    received_packet_count++;
  });

  // Send 3 packets: 0, 1, 2
  // We want to drop 1 to trigger retransmission
  // How to drop 1?
  // We can't easily intercept DummyLink with WBTxRx running.
  // Hack: Send 0. Wait. Send 2. Wait.
  // Packet 1 is skipped on TX side?
  // If I just skip calling try_enqueue_packet for payload 1, then sequence
  // number will increment? No, WBStreamTx assigns sequence number. So if I
  // enqueue P0, it gets Seq 0. If I enqueue P2, it gets Seq 1. Rx sees Seq 0
  // then Seq 1. No gap.

  // I need to produce Seq 0, Seq 1, Seq 2.
  // And ensure Rx sees Seq 0, then Seq 2.

  // I can modify `DummyLink` to drop packet based on pattern?
  // `DummyLink` is shared via `m_optional_dummy_link`.
  // I can access it from `txrx_air`.
  auto dummy_air = txrx_air->get_dummy_link();
  // I need to set it to drop the 2nd packet sent.
  // `DummyLink` has `set_drop_mode(int prob)`.
  // I need deterministic drop.
  // I can't easily do it with current `DummyLink`.

  // ALTERNATIVE:
  // Don't use `DummyLink` logic for dropping.
  // Stop `txrx_gnd`.
  // Send P0, P1, P2.
  // Manually read from `txrx_gnd`'s dummy link.
  // Inject P0, P2 into `WBStreamRx` via manual injection?
  // `WBStreamRx` doesn't have public inject.
  // But `WBStreamRx` listens to `txrx_gnd`.
  // `txrx_gnd` reads from `DummyLink`.

  // `DummyLink` is a pair of sockets.
  // If I read from the socket that `txrx_gnd` reads from, I steal the packet.
  // `DummyLink(false)` (Gnd) reads from "air" socket.
  // `DummyLink(true)` (Air) writes to "air" socket.

  // So:
  // 1. Pause `txrx_gnd`? `stop_receiving()`.
  txrx_gnd->stop_receiving();

  // 2. Send P0, P1, P2 from Air.
  auto p0 = std::make_shared<std::vector<uint8_t>>(10, 'A');
  auto p1 = std::make_shared<std::vector<uint8_t>>(10, 'B');
  auto p2 = std::make_shared<std::vector<uint8_t>>(10, 'C');

  stream_tx.try_enqueue_packet(p0);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  stream_tx.try_enqueue_packet(p1);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  stream_tx.try_enqueue_packet(p2);
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // 3. Steal packets from "air" socket (which Gnd reads from).
  // I need a separate `DummyLink` instance to steal?
  // `DummyLink(false)` binds to "air".
  // If I create another `DummyLink(false)`, it will try to bind to "air".
  // Address already in use? Unix sockets... bind might fail or steal.

  // But `txrx_gnd` has `m_optional_dummy_link`.
  // I can use THAT one.
  // But `WBTxRx` has it in `private`.
  // But I added `get_dummy_link()` public method!

  auto dummy_gnd_link = txrx_gnd->get_dummy_link();
  // `txrx_gnd` is stopped (thread joined).
  // So I can safely use `dummy_gnd_link->rx_radiotap()`.

  // Read all packets
  std::vector<std::shared_ptr<std::vector<uint8_t>>> packets;
  while (true) {
    auto pkt = dummy_gnd_link->rx_radiotap();
    if (!pkt) break;
    packets.push_back(pkt);
    // std::cout << "Stole packet size " << pkt->size() << std::endl;
  }

  // We should have at least 3 data packets + session keys.
  // We need to inject ALL packets back, EXCEPT P1 (which we drop).
  // And we must inject them in order.

  // Start `txrx_gnd`.
  txrx_gnd->start_receiving();
  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Inject packets via `dummy_air` (which sends to "air", where Gnd listens).
  // Filter out P1 ("BBBBBBBBBB").

  int injected_count = 0;
  for (auto pkt : packets) {
    std::string s(pkt->begin(), pkt->end());
    if (s.find("BBBBBBBBBB") != std::string::npos) {
      std::cout << "Dropping P1" << std::endl;
      continue;
    }

    // Inject (Session keys, P0, P2)
    dummy_air->tx_radiotap(pkt->data(), pkt->size());
    injected_count++;
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  std::cout << "Injected " << injected_count << " packets." << std::endl;

  // Wait for gap detection and retransmission
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  // `txrx_gnd` should receive P2.
  // Detect Gap. Send Req.
  // `txrx_air` receives Req. Resends P1.
  // `txrx_gnd` receives P1.

  // Total received should be 3.
  std::cout << "Received count: " << received_packet_count << std::endl;

  // Stop everything
  txrx_air->stop_receiving();
  txrx_gnd->stop_receiving();

  assert(
      received_packet_count >=
      3);  // Might receive duplicates or session keys if not filtered properly
  // Filter received payloads
  bool foundA = false, foundB = false, foundC = false;
  for (const auto &s : received_payloads) {
    if (s.find("AAAAAAAAAA") != std::string::npos) foundA = true;
    if (s.find("BBBBBBBBBB") != std::string::npos) foundB = true;
    if (s.find("CCCCCCCCCC") != std::string::npos) foundC = true;
  }

  assert(foundA);
  assert(foundC);
  assert(foundB);  // Retransmitted

  std::cout << "Auto Retransmission Test Passed" << std::endl;
}

int main(int argc, char *argv[]) {
  std::cout << "Tests for Wifibroadcast\n";
  srand(time(NULL));
  int opt;
  int test_mode = 0;

  while ((opt = getopt(argc, argv, "m:")) != -1) {
    switch (opt) {
      case 'm':
        test_mode = atoi(optarg);
        break;
      default: /* '?' */
      show_usage:
        std::cout << "Usage: Unit tests for FEC and encryption. -m 0,1,2 test "
                     "mode: 0==ALL, 1==FEC only 2==Encryption only "
                     "3==ManualRetransmission 4==AutoRetransmission\n";
        return 1;
    }
  }
  print_optimization_method();
  test::test_nonce();

  try {
    if (test_mode == 3) {
      test_manual_retransmission();
      return 0;
    }
    if (test_mode == 4) {
      test_auto_retransmission();
      return 0;
    }
    if (test_mode == 0 || test_mode == 1) {
      std::cout << "Testing FEC" << std::endl;
      // First test FEC itself
      test_gf();
      test_fec();
      TestFEC::testFecCPlusPlusWrapperX();
      // and then the FEC streaming implementation
      TestFEC::test_fec_stream_random_bs_fs_overhead_dropped();
    }
    if (test_mode == 0 || test_mode == 2) {
      std::cout << "Testing Encryption" << std::endl;
      test_encryption_serialize();
      test_encrypt_decrypt_validate(false, false);
      test_encrypt_decrypt_validate(false, true);
      test_encrypt_decrypt_validate(true, false);
    }
    if (test_mode == 0) {
      test_manual_retransmission();
      test_auto_retransmission();
    }
  } catch (std::runtime_error &e) {
    std::cerr << "Error: " << std::string(e.what());
    exit(1);
  }
  std::cout << "All Tests Passing\n";
  return 0;
}
