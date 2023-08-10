//
// Created by consti10 on 28.06.23.
//

#ifndef WIFIBROADCAST_FECENABLED_H
#define WIFIBROADCAST_FECENABLED_H

#include <array>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "FEC.hpp"
#include "HelperSources/TimeHelper.hpp"

/**
 * Encoder and Decoder pair for FEC protected block / packet based data streaming.
 * adds sizeof(FECPayloadHdr) to each fec primary or secondary packet.
 */

static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "This code is written for little endian only !");

struct FECPayloadHdr{
  // Most often each frame is encoded as one fec block
  // rolling
  uint32_t block_idx;
  // each fragment inside a block has a fragment index
  // uint8_t is enough, since we are limited to 128+128=256 fragments anyway by the FEC impl.
  uint8_t fragment_idx;
  // how many fragments make up the primary fragments part, the rest is secondary fragments
  // note that we do not need to know how many secondary fragments have been created - as soon as we
  // 'have enough', we can perform the FEC correction step if necessary
  uint8_t n_primary_fragments;
  // For FEC all data fragments have to be the same size. We pad the rest during encoding / decoding with 0,
  // and do this when encoding / decoding such that the 0 bytes don't have to be transmitted.
  // This needs to be included during the fec encode / decode step !
  uint16_t data_size;
}__attribute__ ((packed));
static_assert(sizeof(FECPayloadHdr)==8);

// See WBTxRx
static constexpr const auto MAX_PAYLOAD_BEFORE_FEC=1449;
// The FEC stream encode adds an overhead, leaving X bytes to the application
static constexpr const auto FEC_PACKET_MAX_PAYLOAD_SIZE=MAX_PAYLOAD_BEFORE_FEC-sizeof(FECPayloadHdr);
static_assert(FEC_PACKET_MAX_PAYLOAD_SIZE==1441);

// max 255 primary and secondary fragments together for now. Theoretically, this implementation has enough bytes in the header for
// up to 15 bit fragment indices, 2^15=32768
// Note: currently limited by the fec c implementation
static constexpr const uint16_t MAX_N_P_FRAGMENTS_PER_BLOCK = 128;
static constexpr const uint16_t MAX_N_S_FRAGMENTS_PER_BLOCK = 128;
static constexpr const uint16_t
    MAX_TOTAL_FRAGMENTS_PER_BLOCK = MAX_N_P_FRAGMENTS_PER_BLOCK + MAX_N_S_FRAGMENTS_PER_BLOCK;

// For dynamic block sizes, we switched to a FEC overhead "percentage" value.
// e.g. the final data throughput ~= original data throughput * fec overhead percentage
static uint32_t calculate_n_secondary_fragments(uint32_t n_primary_fragments,uint32_t fec_overhead_perc){
  if(fec_overhead_perc<=0)return 0;
  const float n_secondary=static_cast<float>(n_primary_fragments) * static_cast<float>(fec_overhead_perc) / 100.0f;
  if(n_secondary<=1.0){
    // Always calculate at least one FEC packet
    return 1;
  }
  return std::lroundf(n_secondary);
}
// calculate n from k and percentage as used in FEC terms
// (k: number of primary fragments, n: primary + secondary fragments)
static unsigned int calculateN(const unsigned int k, const unsigned int percentage) {
  return k + calculate_n_secondary_fragments(k,percentage);
}

class FECEncoder {
 public:
  typedef std::function<void(const uint8_t* packet,int packet_len)>
      OUTPUT_DATA_CALLBACK;
  OUTPUT_DATA_CALLBACK outputDataCallback;
  explicit FECEncoder()=default;
  FECEncoder(const FECEncoder &other) = delete;
 public:
  /**
   * Encodes a new block and forwards the packets for this block
   * forwards data packets first, then generated fec packets
   * (if needed) and forwards them after.
   * @param data_packets the packets for this block
   * @param n_secondary_fragments how many secondary fragments (FEC packets) should be created
   */
  void encode_block(std::vector<std::shared_ptr<std::vector<uint8_t>>> data_packets,int n_secondary_fragments);
  // Pre-allocated to have space for storing primary fragments (they are needed once the fec step needs to be performed)
  // and creating the wanted amount of secondary packets
  std::array<std::array<uint8_t, MAX_PAYLOAD_BEFORE_FEC>,MAX_TOTAL_FRAGMENTS_PER_BLOCK> m_block_buffer{};
  uint32_t m_curr_block_idx=0;
  static_assert(sizeof(m_curr_block_idx)==sizeof(FECPayloadHdr::block_idx));
  AvgCalculator m_fec_block_encode_time;
  MinMaxAvg<std::chrono::nanoseconds> m_curr_fec_block_encode_time{};
  BaseAvgCalculator<uint16_t> m_block_sizes{};
  MinMaxAvg<uint16_t> m_curr_fec_block_sizes{};
};

// This encapsulates everything you need when working on a single FEC block on the receiver
// for example, addFragment() or pullAvailablePrimaryFragments()
// it also provides convenient methods to query if the block is fully forwarded
// or if it is ready for the FEC reconstruction step.
class RxBlock {
 public:
  // @param maxNFragmentsPerBlock max number of primary and secondary fragments for this block.
  // you could just use MAX_TOTAL_FRAGMENTS_PER_BLOCK for that, but if your tx then uses (4:8) for example, you'd
  // allocate much more memory every time for a new RX block than needed.
  explicit RxBlock(const unsigned int maxNFragmentsPerBlock, const uint64_t blockIdx1)
      :blockIdx(blockIdx1),
        fragment_map(maxNFragmentsPerBlock,FragmentStatus::UNAVAILABLE), //after creation of the RxBlock every f. is marked as unavailable
        blockBuffer(maxNFragmentsPerBlock) {
    assert(fragment_map.size() == blockBuffer.size());
  }
  // No copy constructor for safety
  RxBlock(const RxBlock &) = delete;
  // two blocks are the same if they refer to the same block idx:
  constexpr bool operator==(const RxBlock &other) const {
    return blockIdx == other.blockIdx;
  }
  // same for not equal operator
  constexpr bool operator!=(const RxBlock &other) const {
    return !(*this == other);
  }
  ~RxBlock() = default;
 public:
  // returns true if this fragment has been already received
  bool hasFragment(int fragment_idx);
  // returns true if we are "done with this block" aka all data has been already forwarded
  bool allPrimaryFragmentsHaveBeenForwarded() const;
  // returns true if enough FEC secondary fragments are available to replace all missing primary fragments
  bool allPrimaryFragmentsCanBeRecovered() const;
  // returns true as soon as all primary fragments are available
  bool allPrimaryFragmentsAreAvailable() const;
  // copy the fragment data and mark it as available
  // you should check if it is already available with hasFragment() to avoid copying the same fragment multiple times
  // when using multiple RX cards
  void addFragment(const uint8_t *data, const std::size_t dataLen);
  // util to copy the packet size and payload (and not more)
  void fragment_copy_payload(const int fragment_idx,const uint8_t *data, const std::size_t dataLen);
  /**
   * @returns the indices for all primary fragments that have not yet been forwarded and are available (already received or reconstructed).
   * Once an index is returned here, it won't be returned again
   * (Therefore, as long as you immediately forward all primary fragments returned here,everything happens in order)
   * @param discardMissingPackets : if true, gaps are ignored and fragments are forwarded even though this means the missing ones are irreversible lost
   * Be carefully with this param, use it only before you need to get rid of a block */
  std::vector<uint16_t> pullAvailablePrimaryFragments(const bool discardMissingPackets = false);
  const uint8_t *get_primary_fragment_data_p(const int fragment_index);
  const int get_primary_fragment_data_size(const int fragment_index);

  // returns the n of primary and secondary fragments for this block
  int getNAvailableFragments() const {
    return m_n_available_primary_fragments + m_n_available_secondary_fragments;
  }
  /**
   * Reconstruct all missing primary fragments (data packets) by using the received secondary (FEC) packets
   * NOTE: reconstructing only part of the missing data is not supported ! (That's a non-fixable technical detail of FEC)
   * NOTE: Do not call this method unless it is needed
   * @return the n of reconstructed packets
   */
  int reconstructAllMissingData();
  [[nodiscard]] uint64_t getBlockIdx() const {
    return blockIdx;
  }
  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point> getFirstFragmentTimePoint() const {
    return firstFragmentTimePoint;
  }
  // Returns the number of missing primary packets (e.g. the n of actual data packets that are missing)
  // This only works if we know the "fec_k" parameter
  std::optional<int> get_missing_primary_packets() const;
  std::string get_missing_primary_packets_readable() const;
  int get_n_primary_fragments()const;
 private:
  // the block idx marks which block this element refers to
  const uint64_t blockIdx = 0;
  // n of primary fragments that are already pulled out
  int nAlreadyForwardedPrimaryFragments = 0;
  // for each fragment (via fragment_idx) store if it has been received yet
  std::vector<FragmentStatus> fragment_map;
  // holds all the data for all received fragments (if fragment_map says UNAVALIABLE at this position, content is undefined)
  std::vector<std::array<uint8_t, MAX_PAYLOAD_BEFORE_FEC>> blockBuffer;
  // time point when the first fragment for this block was received (via addFragment() )
  std::optional<std::chrono::steady_clock::time_point> firstFragmentTimePoint = std::nullopt;
  // as soon as we know any of the fragments for this block, we know how many primary fragments this block contains
  // (and therefore, how many primary or secondary fragments we need to fully reconstruct)
  int m_n_primary_fragments_in_block =-1;
  // for the fec step, we need the size of the fec secondary fragments, which should be equal for all secondary fragments
  int m_size_of_secondary_fragments =-1;
  int m_n_available_primary_fragments =0;
  int m_n_available_secondary_fragments =0;
};

// Takes a continuous stream of packets (data and fec correction packets) and
// processes them such that the output is exactly (or as close as possible) to the
// Input stream fed to FECEncoder.
// Most importantly, it also handles re-ordering of packets and packet duplicates due to multiple rx cards
class FECDecoder {
 public:
  /**
   * @param rx_queue_max_depth max size of rx queue - since in case of openhd, one frame is either one or two FEC blocks
   *        we don't need that big of an rx queue
   * @param maxNFragmentsPerBlock memory per block is pre-allocated, reduce this value if you know the encoder doesn't ever exceed a given
   *        n of fragments per block
   * @param enable_log_debug
   */
  explicit FECDecoder(const unsigned int rx_queue_max_depth,const unsigned int maxNFragmentsPerBlock = MAX_TOTAL_FRAGMENTS_PER_BLOCK,
                      bool enable_log_debug=false) :
                                                       RX_QUEUE_MAX_SIZE(rx_queue_max_depth),
                                                       maxNFragmentsPerBlock(maxNFragmentsPerBlock),
                                                       m_enable_log_debug(enable_log_debug){
    assert(rx_queue_max_depth<20);
    assert(rx_queue_max_depth>=1);
  }
  FECDecoder(const FECDecoder &other) = delete;
  ~FECDecoder() = default;
  // data forwarded on this callback is always in-order but possibly with gaps
  typedef std::function<void(const uint8_t *payload, std::size_t payloadSize)> SEND_DECODED_PACKET;
  // WARNING: Don't forget to register this callback !
  SEND_DECODED_PACKET mSendDecodedPayloadCallback;
  // A value too high doesn't really give much benefit and increases memory usage
  const unsigned int RX_QUEUE_MAX_SIZE;
  const unsigned int maxNFragmentsPerBlock;
  const bool m_enable_log_debug;
  AvgCalculator m_fec_decode_time{};
 public:
  static bool validate_packet_size(int data_len);
  // process a valid packet
  bool process_valid_packet(const uint8_t* data,int data_len);
 private:
  // since we also need to search this data structure, a std::queue is not enough.
  // since we have an upper limit on the size of this dequeue, it is basically a searchable ring buffer
  std::deque<std::unique_ptr<RxBlock>> rx_queue;
  uint64_t last_known_block = ((uint64_t) -1);  //id of last known block
  /**
   * For this Block,
   * starting at the primary fragment we stopped on last time,
   * forward as many primary fragments as they are available until there is a gap
   * @param discardMissingPackets : if true, gaps are ignored and fragments are forwarded even though this means the missing ones are irreversible lost
   * Be carefully with this param, use it only before you need to get rid of a block
   */
  void forwardMissingPrimaryFragmentsIfAvailable(RxBlock &block, const bool discardMissingPackets = false);
  // also increase lost block count if block is not fully recovered
  void rxQueuePopFront();
  // create a new RxBlock for the specified block_idx and push it into the queue
  // NOTE: Checks first if this operation would increase the size of the queue over its max capacity
  // In this case, the only solution is to remove the oldest block before adding the new one
  void rxRingCreateNewSafe(const uint64_t blockIdx);

  // If block is already known and not in the queue anymore return nullptr
  // else if block is inside the ring return pointer to it
  // and if it is not inside the ring add as many blocks as needed, then return pointer to it
  RxBlock *rxRingFindCreateBlockByIdx(const uint64_t blockIdx);
  void process_with_rx_queue(const FECPayloadHdr& header,const uint8_t* data,int data_size);
 public:
  // matches FECDecoder
  struct FECRxStats {
    // total block count
    uint64_t count_blocks_total = 0;
    // a block counts as "lost" if it was removed before being fully received or recovered
    uint64_t count_blocks_lost = 0;
    // a block counts as "recovered" if it was recovered using FEC packets
    uint64_t count_blocks_recovered = 0;
    // n of primary fragments that were reconstructed during the recovery process of a block
    uint64_t count_fragments_recovered = 0;
    // n of forwarded bytes
    uint64_t count_bytes_forwarded=0;
    MinMaxAvg<std::chrono::nanoseconds> curr_fec_decode_time{};
  };
  FECRxStats stats{};
  void reset_rx_queue();
};

// quick math regarding sequence numbers:
//uint32_t holds max 4294967295 . At 10 000 pps (packets per seconds) (which is already completely out of reach) this allows the tx to run for 429496.7295 seconds
// 429496.7295 / 60 / 60 = 119.304647083 hours which is also completely overkill for OpenHD (and after this time span, a "reset" of the sequence number happens anyways)
// unsigned 24 bits holds 16777215 . At 1000 blocks per second this allows the tx to create blocks for 16777.215 seconds or 4.6 hours. That should cover a flight (and after 4.6h a reset happens,
// which means you might lose a couple of blocks once every 4.6 h )
// and 8 bits holds max 255.

#endif  // WIFIBROADCAST_FECENABLED_H
