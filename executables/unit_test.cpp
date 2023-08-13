
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

#include "../src/FECStream.h"
#include "../src/FEC.hpp"

#include "../src/Encryption.h"
#include "../src/HelperSources/Helper.hpp"
#include "../src/Ieee80211Header.hpp"
#include "../src/wifibroadcast_spdlog.h"

// Simple unit testing for the FEC lib that doesn't require wifi cards

namespace TestFEC {

// Chooses randomly
// 1) block size (n fragments in block)
// 2) size of data in each fragment in a block
// 3) a fec overhead value (k)
// 4) a specific amount of dropped packets, but keeping enough packets to be fully recoverable
static void test_fec_stream_random_bs_fs_overhead_dropped(){
  wifibroadcast::log::get_default()->debug("test_random_bs_fs_overhead_dropped begin");
  std::vector<std::vector<std::vector<uint8_t>>> fragmented_frames_in;
  std::vector<std::vector<uint8_t>> fragmented_frames_sequential_in;
  for(int i=0;i<1000*2;i++){
    std::vector<std::vector<uint8_t>> fragmented_frame;
    const auto n_fragments=GenericHelper::create_random_number_between(1,MAX_N_P_FRAGMENTS_PER_BLOCK);
    for(int j=0;j<n_fragments;j++){
      const auto buff_size=GenericHelper::create_random_number_between(1,FEC_PACKET_MAX_PAYLOAD_SIZE);
      //const auto buff_size=GenericHelper::create_random_number_between(12,12);
      auto buff=GenericHelper::createRandomDataBuffer(buff_size);
      fragmented_frame.push_back(buff);
      fragmented_frames_sequential_in.push_back(buff);
    }
    //wifibroadcast::log::get_default()->debug("test_random_bs_fs_overhead_dropped with {} fragments",fragmented_frame.size());
    fragmented_frames_in.push_back(fragmented_frame);
  }
  FECEncoder encoder{};
  FECDecoder decoder{10};
  std::vector<std::vector<uint8_t>> testOut;
  // The indices of packets we shall drop
  std::vector<unsigned int> curr_indices_of_packets_to_drop{};

  const auto cb1 = [&decoder,&curr_indices_of_packets_to_drop,&fragmented_frames_sequential_in](const uint8_t *payload, const std::size_t payloadSize)mutable {
    auto* hdr=(FECPayloadHdr*)payload;
    if(GenericHelper::vec_contains(curr_indices_of_packets_to_drop,hdr->fragment_idx)){
      //wifibroadcast::log::get_default()->debug("Dropping packet {} in {}",(int)hdr->fragment_idx,(int)hdr->n_primary_fragments);
    }else{
      decoder.process_valid_packet(payload,payloadSize);
    }
    /*if(hdr->fragment_idx<hdr->n_primary_fragments){
      auto lol=std::vector<uint8_t>(payload+sizeof(FECPayloadHdr),payload+payloadSize);
      auto original=fragmented_frames_sequential_in[hdr->fragment_idx];
      GenericHelper::assertVectorsEqual(original,lol);
    }*/
  };
  int out_index=0;
  const auto cb2 = [&testOut,&fragmented_frames_sequential_in,&out_index](const uint8_t *payload, std::size_t payloadSize)mutable {
    auto buff=std::vector<uint8_t>(payload,payload+payloadSize);
    testOut.emplace_back(buff);
    //wifibroadcast::log::get_default()->debug("Out:{}",payloadSize);
    GenericHelper::assertVectorsEqual(fragmented_frames_sequential_in[out_index],buff);
    out_index++;
  };
  encoder.outputDataCallback = cb1;
  decoder.mSendDecodedPayloadCallback = cb2;
  for(int i=0;i<fragmented_frames_in.size();i++){
    auto fragmented_frame=fragmented_frames_in[i];
    const auto n_secondary_fragments=GenericHelper::create_random_number_between(0,MAX_N_S_FRAGMENTS_PER_BLOCK);
    //const auto n_secondary_fragments=0;
    // We'l drop a random amount of fragments - but only up to as many fragments such that we can still recover the block
    const auto n_fragments_to_drop=GenericHelper::create_random_number_between(0,n_secondary_fragments);
    //const auto n_fragments_to_drop=1;
    auto indices=GenericHelper::createIndices(fragmented_frame.size()+n_secondary_fragments);
    auto indices_packets_to_drop=GenericHelper::takeNRandomElements(indices,n_fragments_to_drop);
    wifibroadcast::log::get_default()->debug("Feeding block of {} fragments with {} secondary fragments and dropping {}",
                                             fragmented_frame.size(),n_secondary_fragments,n_fragments_to_drop);
    curr_indices_of_packets_to_drop=indices_packets_to_drop;
    encoder.encode_block(GenericHelper::convert_vec_of_vec_to_shared(fragmented_frame),n_secondary_fragments);
  }
  GenericHelper::assertVectorsOfVectorsEqual(fragmented_frames_sequential_in,testOut);
  wifibroadcast::log::get_default()->debug("test_random_bs_fs_overhead_dropped end");
}

}

// Test encryption+packet validation and packet validation only
static void test_encrypt_decrypt_validate(const bool use_key_from_file,bool message_signing_only) {
  const std::string TEST_TYPE=message_signing_only ?  "Sign" : "Encrypt&Sign";
  const std::string TEST_KEY_TYPE=use_key_from_file ? "key from file" : "default key";
  fmt::print("Testing {} with {}\n",TEST_TYPE,TEST_KEY_TYPE);
  const std::string KEY_FILENAME="../example_key/txrx.key";
  wb::KeyPairTxRx keyPairTxRx{};
  if(use_key_from_file){
    keyPairTxRx=wb::read_keypair_from_file(KEY_FILENAME);
  }else{
    const auto before=std::chrono::steady_clock::now();
    keyPairTxRx=wb::generate_keypair_from_bind_phrase("openhd");
    std::cout<<"Generating keypair from bind phrase took:"<<MyTimeHelper::R(std::chrono::steady_clock::now()-before)<<std::endl;
  }

  wb::Encryptor encryptor{keyPairTxRx.get_tx_key(true)};// We send from air unit
  encryptor.set_encryption_enabled(!message_signing_only);
  wb::Decryptor decryptor{keyPairTxRx.get_rx_key(false)}; // To the ground unit
  decryptor.set_encryption_enabled(!message_signing_only);
  struct SessionStuff{
    std::array<uint8_t, crypto_box_NONCEBYTES> sessionKeyNonce{};  // filled with random data
    std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES> sessionKeyData{};
  };
  SessionStuff sessionKeyPacket;
  // make session key (tx)
  encryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
  // and "receive" session key (rx)
  assert(decryptor.onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData)
         == wb::Decryptor::SESSION_VALID_NEW);
  // now encrypt a couple of packets and decrypt them again afterwards
  for (uint64_t nonce = 0; nonce < 200; nonce++) {
	const auto data = GenericHelper::createRandomDataBuffer(FEC_PACKET_MAX_PAYLOAD_SIZE);
        const auto encrypted= encryptor.authenticate_and_encrypt_buff(
            nonce, data.data(), data.size());
        {
            // Correct usage - let packets through and get the original data back
            const auto decrypted = decryptor.authenticate_and_decrypt_buff(
          nonce, encrypted->data(), encrypted->size());
            assert(GenericHelper::compareVectors(data, *decrypted) == true);
        }
        {
            // tamper with the nonce - shouldn't let packets through
            const auto decrypted = decryptor.authenticate_and_decrypt_buff(
                nonce + 1, encrypted->data(), encrypted->size());
            assert(decrypted== nullptr);
        }
        {
            // tamper with the encryption suffix -  shouldn't let data through
            auto encrypted_wrong_sing=encrypted;
            encrypted_wrong_sing->at(encrypted_wrong_sing->size()-1)=0;
            encrypted_wrong_sing->at(encrypted_wrong_sing->size()-2)=0;
            const auto decrypted = decryptor.authenticate_and_decrypt_buff(
                nonce, encrypted_wrong_sing->data(),
                encrypted_wrong_sing->size());
            assert(decrypted== nullptr);
        }
  }
  // and make sure we don't let packets with an invalid signing suffix through
  for (uint64_t nonce = 0; nonce < 200; nonce++) {
        const auto data = GenericHelper::createRandomDataBuffer(FEC_PACKET_MAX_PAYLOAD_SIZE);
        const auto enrypted_wrong_sign=std::make_shared<std::vector<uint8_t>>();
        enrypted_wrong_sign->resize(data.size()+ENCRYPTION_ADDITIONAL_VALIDATION_DATA);
        memcpy(enrypted_wrong_sign->data(),data.data(),data.size());
        const auto decrypted = decryptor.authenticate_and_decrypt_buff(
            nonce, enrypted_wrong_sign->data(), enrypted_wrong_sign->size());
        assert(decrypted== nullptr);
  }
  fmt::print("Test {} with {} passed\n",TEST_TYPE,TEST_KEY_TYPE);
}


int main(int argc, char *argv[]) {
  std::cout << "Tests for Wifibroadcast\n";
  srand(time(NULL));
  int opt;
  int test_mode = 0;

  while ((opt = getopt(argc, argv, "m:")) != -1) {
	switch (opt) {
	  case 'm':test_mode = atoi(optarg);
		break;
	  default: /* '?' */
	  show_usage:
		std::cout
			<< "Usage: Unit tests for FEC and encryption. -m 0,1,2 test mode: 0==ALL, 1==FEC only 2==Encryption only\n";
		return 1;
	}
  }
  print_optimization_method();
  test::test_nonce();

  try {
	if (test_mode == 0 || test_mode == 1) {
	  std::cout << "Testing FEC"<<std::endl;
          // First test FEC itself
	  test_gf();
	  test_fec();
	  testFecCPlusPlusWrapperX();
          // and then the FEC streaming implementation
          TestFEC::test_fec_stream_random_bs_fs_overhead_dropped();
	}
	if (test_mode == 0 || test_mode == 2) {
	  std::cout << "Testing Encryption"<<std::endl;
          test_encrypt_decrypt_validate(false, false);
          test_encrypt_decrypt_validate(false, true);
          test_encrypt_decrypt_validate(true, false);
	}
  } catch (std::runtime_error &e) {
	std::cerr << "Error: " << std::string(e.what());
	exit(1);
  }
  std::cout << "All Tests Passing\n";
  return 0;
}