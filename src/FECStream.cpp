//
// Created by consti10 on 30.06.23.
//

#include "FECStream.h"

#include <cmath>

#include "FEC.hpp"
#include "wifibroadcast_spdlog.h"
#include <spdlog/spdlog.h>

void FECEncoder::encode_block(
    std::vector<std::shared_ptr<std::vector<uint8_t>>> data_packets,
    int n_secondary_fragments) {
  assert(data_packets.size()<=MAX_N_P_FRAGMENTS_PER_BLOCK);
  assert(n_secondary_fragments<=MAX_N_S_FRAGMENTS_PER_BLOCK);
  const auto n_primary_fragments=data_packets.size();
  // nice to have statistic
  m_block_sizes.add(n_primary_fragments);
  if(m_block_sizes.get_delta_since_last_reset()>=std::chrono::seconds(1)){
    //wifibroadcast::log::get_default()->debug("Block sizes: {}",m_block_sizes.getAvgReadable());
    m_curr_fec_block_sizes=m_block_sizes.getMinMaxAvg();
    m_block_sizes.reset();
  }
  FECPayloadHdr header{};
  header.block_idx=m_curr_block_idx;
  m_curr_block_idx++;
  header.n_primary_fragments=n_primary_fragments;
  // write and forward all the data packets first
  // also calculate the size of the biggest data packet
  size_t max_packet_size=0;
  // Store a pointer where the FEC data begins for performing the FEC step later on
  std::vector<const uint8_t *> primary_fragments_data_p;
  for(int i=0;i<data_packets.size();i++){
    const auto& data_fragment=data_packets[i];
    //wifibroadcast::log::get_default()->debug("In:{}",(int)data_fragment->size());
    assert(!data_fragment->empty());
    assert(data_fragment->size()<=FEC_PACKET_MAX_PAYLOAD_SIZE);
    header.fragment_idx=i;
    header.data_size=data_fragment->size();
    auto buffer_p=m_block_buffer[i].data();
    // copy over the header
    memcpy(buffer_p,(uint8_t*)&header,sizeof(FECPayloadHdr));
    // write the actual data
    memcpy(buffer_p + sizeof(FECPayloadHdr), data_fragment->data(),data_fragment->size());
    // zero out the remaining bytes such that FEC always sees zeroes
    // same is done on the rx. These zero bytes are never transmitted via wifi
    const auto writtenDataSize = sizeof(FECPayloadHdr) + data_fragment->size();
    memset(buffer_p + writtenDataSize, 0, MAX_PAYLOAD_BEFORE_FEC - writtenDataSize);
    max_packet_size = std::max(max_packet_size, data_fragment->size());
    // we can forward the data packet immediately via the callback
    if(outputDataCallback){
      outputDataCallback(buffer_p,writtenDataSize);
    }
    // NOTE: FECPayloadHdr::data_size needs to be included during the fec encode step
    primary_fragments_data_p.push_back(buffer_p+sizeof(FECPayloadHdr)-sizeof(uint16_t));
  }
  // then we create as many FEC packets as needed
  if(n_secondary_fragments==0){
    //wifibroadcast::log::get_default()->debug("No FEC step performed");
    // no FEC step is actually performed, usefully for debugging / performance evaluation
    return ;
  }
  const auto before=std::chrono::steady_clock::now();
  // Now we perform the actual FEC encode step
  std::vector<uint8_t*> secondary_fragments_data_p;
  for(int i=0;i<n_secondary_fragments;i++){
    auto fragment_index=i+n_primary_fragments;
    auto buffer_p=m_block_buffer[fragment_index].data();
    header.fragment_idx=fragment_index;
    // copy over the header
    memcpy(buffer_p,(uint8_t*)&header,sizeof(FECPayloadHdr));
    // where the FEC packet correction data is written to
    secondary_fragments_data_p.push_back(buffer_p+sizeof(FECPayloadHdr)-sizeof(uint16_t));
  }
  fec_encode2(max_packet_size+sizeof(uint16_t),primary_fragments_data_p,secondary_fragments_data_p);
  m_fec_block_encode_time.add(std::chrono::steady_clock::now()-before);
  if(m_fec_block_encode_time.get_delta_since_last_reset()>=std::chrono::seconds(1)){
    //wifibroadcast::log::get_default()->debug("FEC encode time:{}",m_fec_block_encode_time.getAvgReadable());
    m_curr_fec_block_encode_time=m_fec_block_encode_time.getMinMaxAvg();
    m_fec_block_encode_time.reset();
  }
  // and forward all the FEC correction packets
  for(int i=0;i<n_secondary_fragments;i++){
    auto fragment_index=i+n_primary_fragments;
    if(outputDataCallback){
      outputDataCallback(m_block_buffer[fragment_index].data(),sizeof(FECPayloadHdr)+max_packet_size);
    }
  }
}

RxBlock::RxBlock(const unsigned int maxNFragmentsPerBlock,
                 const uint64_t blockIdx1)
    :blockIdx(blockIdx1),
      fragment_map(maxNFragmentsPerBlock,FRAGMENT_STATUS_UNAVAILABLE), //after creation of the RxBlock every f. is marked as unavailable
      blockBuffer(maxNFragmentsPerBlock) {
  assert(fragment_map.size() == blockBuffer.size());
}

bool RxBlock::hasFragment(const int fragment_idx) {
  assert(fragment_idx<fragment_map.size());
  return fragment_map[fragment_idx] == FRAGMENT_STATUS_AVAILABLE;
}

bool RxBlock::allPrimaryFragmentsHaveBeenForwarded() const {
  if (m_n_primary_fragments_in_block == -1)return false;
  return nAlreadyForwardedPrimaryFragments == m_n_primary_fragments_in_block;
}

bool RxBlock::allPrimaryFragmentsCanBeRecovered() const {
  // return false if k is not known for this block yet (which means we didn't get a secondary fragment yet,
  // since each secondary fragment contains k)
  if (m_n_primary_fragments_in_block == -1)return false;
  // ready for FEC step if we have as many secondary fragments as we are missing on primary fragments
  if (m_n_available_primary_fragments + m_n_available_secondary_fragments >=
      m_n_primary_fragments_in_block)return true;
  return false;
}

bool RxBlock::allPrimaryFragmentsAreAvailable() const {
  if (m_n_primary_fragments_in_block == -1)return false;
  return m_n_available_primary_fragments == m_n_primary_fragments_in_block;
}

void RxBlock::addFragment(const uint8_t* data, const std::size_t dataLen) {
  auto* hdr_p=(FECPayloadHdr*) data;
  FECPayloadHdr& header=*hdr_p;
  assert(!hasFragment(header.fragment_idx));
  assert(header.block_idx == blockIdx);
  assert(fragment_map[header.fragment_idx] == FRAGMENT_STATUS_UNAVAILABLE);
  assert(header.fragment_idx < blockBuffer.size());
  fragment_copy_payload(header.fragment_idx,data,dataLen);
  // mark it as available
  fragment_map[header.fragment_idx] = FRAGMENT_STATUS_AVAILABLE;

  // each fragment inside a block should report the same n of primary fragments
  if(m_n_primary_fragments_in_block ==-1){
    m_n_primary_fragments_in_block =header.n_primary_fragments;
  }else{
    assert(m_n_primary_fragments_in_block ==header.n_primary_fragments);
  }
  const bool is_primary_fragment=header.fragment_idx<header.n_primary_fragments;
  if(is_primary_fragment){
    m_n_available_primary_fragments++;
  }else{
    m_n_available_secondary_fragments++;
    const auto payload_len_including_size=dataLen-sizeof(FECPayloadHdr)+sizeof(uint16_t);
    // all secondary fragments shall have the same size
    if(m_size_of_secondary_fragments ==-1){
      m_size_of_secondary_fragments =payload_len_including_size;
    }else{
      assert(m_size_of_secondary_fragments ==payload_len_including_size);
    }
  }
  if(firstFragmentTimePoint==std::nullopt){
    firstFragmentTimePoint=std::chrono::steady_clock::now();
  }
}

void RxBlock::fragment_copy_payload(const int fragment_idx, const uint8_t* data,
                                    const std::size_t dataLen) {
  uint8_t* buff=blockBuffer[fragment_idx].data();
  // NOTE: FECPayloadHdr::data_size needs to be included during the fec decode step
  const uint8_t* payload_p=data+sizeof(FECPayloadHdr)-sizeof(uint16_t);
  auto payload_s=dataLen-sizeof(FECPayloadHdr)+sizeof(uint16_t);
  // write the data (doesn't matter if FEC data or correction packet)
  memcpy(buff, payload_p,payload_s);
  // set the rest to zero such that FEC works
  memset(buff+payload_s, 0, MAX_PAYLOAD_BEFORE_FEC - payload_s);
}

std::vector<uint16_t> RxBlock::pullAvailablePrimaryFragments(
    const bool discardMissingPackets) {
  // note: when pulling the available fragments, we do not need to know how many primary fragments this block actually contains
  std::vector<uint16_t> ret;
  for (int i = nAlreadyForwardedPrimaryFragments; i < m_n_available_primary_fragments; i++) {
    if (fragment_map[i] == FRAGMENT_STATUS_UNAVAILABLE) {
      if (discardMissingPackets) {
        continue;
      } else {
        break;
      }
    }
    ret.push_back(i);
  }
  // make sure these indices won't be returned again
  nAlreadyForwardedPrimaryFragments += (int) ret.size();
  return ret;
}

const uint8_t* RxBlock::get_primary_fragment_data_p(const int fragment_index) {
  assert(fragment_map[fragment_index] == FRAGMENT_STATUS_AVAILABLE);
  assert(m_n_primary_fragments_in_block !=-1);
  assert(fragment_index< m_n_primary_fragments_in_block);
  //return blockBuffer[fragment_index].data()+sizeof(FECPayloadHdr);
  return blockBuffer[fragment_index].data()+sizeof(uint16_t);
}

const int RxBlock::get_primary_fragment_data_size(const int fragment_index) {
  assert(fragment_map[fragment_index] == FRAGMENT_STATUS_AVAILABLE);
  assert(m_n_primary_fragments_in_block !=-1);
  assert(fragment_index< m_n_primary_fragments_in_block);
  uint16_t* len_p=(uint16_t*)blockBuffer[fragment_index].data();
  return *len_p;
}

int RxBlock::reconstructAllMissingData() {
  //wifibroadcast::log::get_default()->debug("reconstructAllMissingData"<<nAvailablePrimaryFragments<<" "<<nAvailableSecondaryFragments<<" "<<fec.FEC_K<<"\n";
  // NOTE: FEC does only work if nPrimaryFragments+nSecondaryFragments>=FEC_K
  assert(m_n_primary_fragments_in_block != -1);
  assert(m_size_of_secondary_fragments != -1);
  // do not reconstruct if reconstruction is impossible
  assert(getNAvailableFragments() >= m_n_primary_fragments_in_block);
  // also do not reconstruct if reconstruction is not needed
  // const int nMissingPrimaryFragments = m_n_primary_fragments_in_block- m_n_available_primary_fragments;
  auto recoveredFragmentIndices = fecDecode(m_size_of_secondary_fragments, blockBuffer,
                                            m_n_primary_fragments_in_block, fragment_map);
  // now mark them as available
  for (const auto idx: recoveredFragmentIndices) {
    fragment_map[idx] = FRAGMENT_STATUS_AVAILABLE;
  }
  m_n_available_primary_fragments += recoveredFragmentIndices.size();
  // n of reconstructed packets
  return recoveredFragmentIndices.size();
}

std::optional<int> RxBlock::get_missing_primary_packets() const {
  if(m_n_primary_fragments_in_block<=0)return std::nullopt;
  return m_n_primary_fragments_in_block-getNAvailableFragments();
}

std::string RxBlock::get_missing_primary_packets_readable() const {
  const auto tmp=get_missing_primary_packets();
  if(tmp==std::nullopt)return "?";
  return std::to_string(tmp.value());
}
int RxBlock::get_n_primary_fragments() const {
  return m_n_primary_fragments_in_block;
}

bool FECDecoder::validate_packet_size(const int data_len) {
  if(data_len<sizeof(FECPayloadHdr)){
    // packet is too small
    return false;
  }
  if(data_len>MAX_PAYLOAD_BEFORE_FEC){
    // packet is too big
    return false;
  }
  return true;
}

bool FECDecoder::process_valid_packet(const uint8_t* data,
                                             int data_len) {
  assert(validate_packet_size(data_len));
  // reconstruct the data layout
  const FECPayloadHdr* header_p=(FECPayloadHdr*)data;
  /* const uint8_t* payload_p=data+sizeof(FECPayloadHdr);
   const int payload_size=data_len-sizeof(FECPayloadHdr);*/
  if (header_p->fragment_idx >= maxNFragmentsPerBlock) {
    wifibroadcast::log::get_default()->warn("invalid fragment_idx: {}",header_p->fragment_idx);
    return false;
  }
  process_with_rx_queue(*header_p,data,data_len);
  return true;
}

void FECDecoder::forwardMissingPrimaryFragmentsIfAvailable(
    RxBlock& block, const bool discardMissingPackets) {
  assert(mSendDecodedPayloadCallback);
  // TODO remove me
  if(discardMissingPackets){
    if(m_enable_log_debug){
      wifibroadcast::log::get_default()->warn("Forwarding block that is not yet fully finished: {} total: {} available: {} missing: {}",
                                              block.getBlockIdx(),block.get_n_primary_fragments(),block.getNAvailableFragments(),block.get_missing_primary_packets_readable());
    }
  }
  const auto indices = block.pullAvailablePrimaryFragments(discardMissingPackets);
  for (auto primaryFragmentIndex: indices) {
    const uint8_t* data=block.get_primary_fragment_data_p(primaryFragmentIndex);
    const int data_size=block.get_primary_fragment_data_size(primaryFragmentIndex);
    if (data_size > FEC_PACKET_MAX_PAYLOAD_SIZE || data_size <= 0) {
      wifibroadcast::log::get_default()->warn("corrupted packet on FECDecoder out ({}:{}) : {}B",block.getBlockIdx(),primaryFragmentIndex,data_size);
    } else {
      mSendDecodedPayloadCallback(data, data_size);
      stats.count_bytes_forwarded+=data_size;
    }
  }
}

void FECDecoder::rxQueuePopFront() {
  assert(rx_queue.front() != nullptr);
  if (!rx_queue.front()->allPrimaryFragmentsHaveBeenForwarded()) {
    stats.count_blocks_lost++;
    if(m_enable_log_debug){
      auto& block=*rx_queue.front();
      wifibroadcast::log::get_default()->debug("Removing block {} {}",block.getBlockIdx(),block.get_missing_primary_packets_readable());
    }
  }
  rx_queue.pop_front();
}

void FECDecoder::rxRingCreateNewSafe(const uint64_t blockIdx) {
  // check: make sure to always put blocks into the queue in order !
  if (!rx_queue.empty()) {
    // the newest block in the queue should be equal to block_idx -1
    // but it must not ?!
    if (rx_queue.back()->getBlockIdx() != (blockIdx - 1)) {
      // If we land here, one or more full blocks are missing, which can happen on bad rx links
      //wifibroadcast::log::get_default()->debug("In queue: {} But new: {}",rx_queue.back()->getBlockIdx(),blockIdx);
    }
    //assert(rx_queue.back()->getBlockIdx() == (blockIdx - 1));
  }
  // we can return early if this operation doesn't exceed the size limit
  if (rx_queue.size() < RX_QUEUE_MAX_SIZE) {
    rx_queue.push_back(std::make_unique<RxBlock>(maxNFragmentsPerBlock, blockIdx));
    stats.count_blocks_total++;
    return;
  }
  //Ring overflow. This means that there are more unfinished blocks than ring size
  //Possible solutions:
  //1. Increase ring size. Do this if you have large variance of packet travel time throught WiFi card or network stack.
  //   Some cards can do this due to packet reordering inside, diffent chipset and/or firmware or your RX hosts have different CPU power.
  //2. Reduce packet injection speed or try to unify RX hardware.

  // forward remaining data for the (oldest) block, since we need to get rid of it
  auto &oldestBlock = rx_queue.front();
  forwardMissingPrimaryFragmentsIfAvailable(*oldestBlock, true);
  // and remove the block once done with it
  rxQueuePopFront();

  // now we are guaranteed to have space for one new block
  rx_queue.push_back(std::make_unique<RxBlock>(maxNFragmentsPerBlock, blockIdx));
  stats.count_blocks_total++;
}

RxBlock* FECDecoder::rxRingFindCreateBlockByIdx(const uint64_t blockIdx) {
  // check if block is already in the ring
  auto found = std::find_if(rx_queue.begin(), rx_queue.end(),
                            [&blockIdx](const std::unique_ptr<RxBlock> &block) {
                              return block->getBlockIdx() == blockIdx;
                            });
  if (found != rx_queue.end()) {
    return found->get();
  }
  // check if block is already known and not in the ring then it is already processed
  if (last_known_block != (uint64_t) -1 && blockIdx <= last_known_block) {
    return nullptr;
  }

  // don't forget to increase the lost blocks counter if we do not add blocks here due to no space in the rx queue
  // (can happen easily if the rx queue has a size of 1)
  const auto n_needed_new_blocks = last_known_block != (uint64_t) -1 ? blockIdx - last_known_block : 1;
  if(n_needed_new_blocks>RX_QUEUE_MAX_SIZE){
    if(m_enable_log_debug){
      wifibroadcast::log::get_default()->debug("Need {} blocks, exceeds {}",n_needed_new_blocks,RX_QUEUE_MAX_SIZE);
    }
    stats.count_blocks_lost+=n_needed_new_blocks-RX_QUEUE_MAX_SIZE;
  }
  // add as many blocks as we need ( the rx ring mustn't have any gaps between the block indices).
  // but there is no point in adding more blocks than RX_RING_SIZE
  const int new_blocks = (int) std::min(n_needed_new_blocks,
                                        (uint64_t) FECDecoder::RX_QUEUE_MAX_SIZE);
  last_known_block = blockIdx;

  for (int i = 0; i < new_blocks; i++) {
    rxRingCreateNewSafe(blockIdx + i + 1 - new_blocks);
  }
  // the new block we've added is now the most recently added element (and since we always push to the back, the "back()" element)
  assert(rx_queue.back()->getBlockIdx() == blockIdx);
  return rx_queue.back().get();
}

void FECDecoder::process_with_rx_queue(const FECPayloadHdr& header,
                                       const uint8_t* data, int data_size) {
  auto blockP = rxRingFindCreateBlockByIdx(header.block_idx);
  //ignore already processed blocks
  if (blockP == nullptr) return;
  // cannot be nullptr
  RxBlock &block = *blockP;
  // ignore already processed fragments
  if (block.hasFragment(header.fragment_idx)) {
    return;
  }
  block.addFragment(data,data_size);
  if (block == *rx_queue.front()) {
    //wifibroadcast::log::get_default()->debug("In front\n";
    // we are in the front of the queue (e.g. at the oldest block)
    // forward packets until the first gap
    forwardMissingPrimaryFragmentsIfAvailable(block);
    // We are done with this block if either all fragments have been forwarded or it can be recovered
    if (block.allPrimaryFragmentsHaveBeenForwarded()) {
      // remove block when done with it
      rxQueuePopFront();
      return;
    }
    if (block.allPrimaryFragmentsCanBeRecovered()) {
      // apply fec for this block
      const auto before_encode=std::chrono::steady_clock::now();
      stats.count_fragments_recovered += block.reconstructAllMissingData();
      stats.count_blocks_recovered++;
      m_fec_decode_time.add(std::chrono::steady_clock::now()-before_encode);
      if(m_fec_decode_time.get_delta_since_last_reset()>std::chrono::seconds(1)){
        //wifibroadcast::log::get_default()->debug("FEC decode took {}",m_fec_decode_time.getAvgReadable());
        stats.curr_fec_decode_time=m_fec_decode_time.getMinMaxAvg();
        m_fec_decode_time.reset();
      }
      forwardMissingPrimaryFragmentsIfAvailable(block);
      assert(block.allPrimaryFragmentsHaveBeenForwarded());
      // remove block when done with it
      rxQueuePopFront();
      return;
    }
    return;
  } else {
    //wifibroadcast::log::get_default()->debug("Not in front\n";
    // we are not in the front of the queue but somewhere else
    // If this block can be fully recovered or all primary fragments are available this triggers a flush
    if (block.allPrimaryFragmentsAreAvailable() || block.allPrimaryFragmentsCanBeRecovered()) {
      // send all queued packets in all unfinished blocks before and remove them
      if(m_enable_log_debug){
        wifibroadcast::log::get_default()->debug("Block {} triggered a flush",block.getBlockIdx());
      }
      while (block != *rx_queue.front()) {
        forwardMissingPrimaryFragmentsIfAvailable(*rx_queue.front(), true);
        rxQueuePopFront();
      }
      // then process the block who is fully recoverable or has no gaps in the primary fragments
      if (block.allPrimaryFragmentsAreAvailable()) {
        forwardMissingPrimaryFragmentsIfAvailable(block);
        assert(block.allPrimaryFragmentsHaveBeenForwarded());
      } else {
        // apply fec for this block
        stats.count_fragments_recovered += block.reconstructAllMissingData();
        stats.count_blocks_recovered++;
        forwardMissingPrimaryFragmentsIfAvailable(block);
        assert(block.allPrimaryFragmentsHaveBeenForwarded());
      }
      // remove block
      rxQueuePopFront();
    }
  }
}

void FECDecoder::reset_rx_queue() {
  /*while (auto el=rx_queue.front() != nullptr){
    rxQueuePopFront();
  }*/
  rx_queue.resize(0);
  last_known_block=((uint64_t) -1);
}

uint32_t calculate_n_secondary_fragments(uint32_t n_primary_fragments,
                                         uint32_t fec_overhead_perc) {
  if(fec_overhead_perc<=0)return 0;
  const float n_secondary=static_cast<float>(n_primary_fragments) * static_cast<float>(fec_overhead_perc) / 100.0f;
  if(n_secondary<=1.0){
    // Always calculate at least one FEC packet
    return 1;
  }
  return std::lroundf(n_secondary);
}

unsigned int calculateN(const unsigned int k, const unsigned int percentage) {
  return k + calculate_n_secondary_fragments(k,percentage);
}
