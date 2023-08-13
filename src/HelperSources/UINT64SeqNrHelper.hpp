//
// Created by consti10 on 08.08.23.
//

#ifndef WIFIBROADCAST_UINT64SEQNRHELPER_HPP
#define WIFIBROADCAST_UINT64SEQNRHELPER_HPP

#include <atomic>
#include <cmath>
#include <memory>

#include "../wifibroadcast_spdlog.h"
#include <spdlog/spdlog.h>
#include "StringHelper.hpp"

// UINT16SeqNrHelper for dealing with sequence number
// (calculate packet loss and more)
// Using a unique uint64_t nonce
class UINT64SeqNrHelper {
 public:
  int16_t get_current_loss_percent(){
    return m_curr_loss_perc.load();
  }
  int16_t get_current_gaps_counter(){
    return m_curr_gaps_counter;
  }
  // NOTE: Does no packet re-ordering, therefore can only be used per card !
  void on_new_sequence_number(uint64_t seq_nr){
    if(m_last_seq_nr==UINT64_MAX){
      m_last_seq_nr=seq_nr;
      return ;
    }
    if(m_last_seq_nr>=seq_nr){
      // Nonce must be strictly increasing, otherwise driver is bugged and reorders packets
      // Or - more likely - a tx was restarted - which is so rare that it is okay to log a warning here and just accept the new value
      wifibroadcast::log::get_default()->warn("Invalid sequence number last:{} new:{}",m_last_seq_nr,seq_nr);
      m_last_seq_nr=seq_nr;
      return ;
    }
    const auto diff=seq_nr-m_last_seq_nr;
    if(diff>10000){
      wifibroadcast::log::get_default()->warn("Unlikely high gap, diff {} last:{} new:{}",diff,m_last_seq_nr,seq_nr);
      m_last_seq_nr=seq_nr;
      return ;
    }
    if(diff>1){
      // There is a gap of X packets
      const auto gap_size=diff-1;
      // as an example, a diff of 2 means one packet is missing.
      m_n_missing_packets+=gap_size;
      m_n_received_packets++;
      if(m_store_and_debug_gaps && gap_size>1){
        store_debug_gap(static_cast<int>(gap_size));
      }
      set_and_recalculate_big_gap_counter(static_cast<int>(gap_size));
    }else{
      // There is no gap between last and current packet
      m_n_received_packets++;
    }
    recalculate_loss_if_needed();
    m_last_seq_nr=seq_nr;
  }
  void reset(){
    m_last_seq_nr=UINT64_MAX;
    m_curr_loss_perc=-1;
    m_curr_gaps_counter=-1;
  }
  void set_store_and_debug_gaps(int card_idx,bool enable){
    m_store_and_debug_gaps=enable;
    m_card_index=card_idx;
  }
 private:
  // recalculate the loss in percentage in fixed intervals
  // resets the received and missing packet count
  void recalculate_loss_if_needed(){
    const auto elapsed=std::chrono::steady_clock::now()-m_last_loss_perc_recalculation;
    if(elapsed>=std::chrono::seconds(2) || m_n_received_packets>500){
      m_last_loss_perc_recalculation=std::chrono::steady_clock::now();
      const auto n_total_packets=m_n_received_packets+m_n_missing_packets;
      //m_console->debug("x_n_missing_packets:{} x_n_received_packets:{} n_total_packets:{}",x_n_missing_packets,x_n_received_packets,n_total_packets);
      if(n_total_packets>=1){
        const double loss_perc=static_cast<double>(m_n_missing_packets)/static_cast<double>(n_total_packets)*100.0;
        //m_curr_packet_loss=static_cast<int16_t>(std::lround(loss_perc));
        // we always round up the packet loss
        m_curr_loss_perc=static_cast<int16_t>(std::ceil(loss_perc));
        //wifibroadcast::log::get_default()->debug("Packet loss:{} % {} %",m_curr_packet_loss,loss_perc);
      }else{
        // We did not get any packets in the last x seconds
        m_curr_loss_perc=-1;
      }
      m_n_received_packets=0;
      m_n_missing_packets=0;
    }
  }
  void store_debug_gap(int gap_size){
    m_gaps.push_back(gap_size);
    const auto elasped=std::chrono::steady_clock::now()-m_last_gap_log;
    if(elasped>std::chrono::seconds(1) || m_gaps.size()>=MAX_N_STORED_GAPS){
      wifibroadcast::log::get_default()->debug("Card{} Gaps: {}",m_card_index,StringHelper::vectorAsString(m_gaps));
      m_gaps.resize(0);
      m_last_gap_log=std::chrono::steady_clock::now();
    }
  }
  void set_and_recalculate_big_gap_counter(int gap_size){
    if(gap_size>=GAP_SIZE_COUNTS_AS_BIG_GAP){
      m_n_big_gaps++;
    }
    const auto elapsed=std::chrono::steady_clock::now()-m_last_big_gaps_counter_recalculation;
    if(elapsed>=std::chrono::seconds(1)){
      m_curr_gaps_counter=(int16_t)m_n_big_gaps;
      m_n_big_gaps=0;
      m_last_big_gaps_counter_recalculation=std::chrono::steady_clock::now();
    }
  }
 private:
  std::chrono::steady_clock::time_point m_last_loss_perc_recalculation=std::chrono::steady_clock::now();
  std::chrono::steady_clock::time_point m_last_gap_log=std::chrono::steady_clock::now();
  std::chrono::steady_clock::time_point m_last_big_gaps_counter_recalculation=std::chrono::steady_clock::now();
  uint64_t m_last_seq_nr=UINT64_MAX;
  std::atomic<int16_t> m_curr_loss_perc=-1;
  std::atomic<int16_t> m_curr_gaps_counter{};
  int m_n_received_packets=0;
  int m_n_missing_packets=0;
  int m_n_big_gaps=0;
  static constexpr int MAX_N_STORED_GAPS=1000;
  std::vector<int> m_gaps;
  static constexpr int GAP_SIZE_COUNTS_AS_BIG_GAP=10;
  bool m_store_and_debug_gaps= false;
  int m_card_index=0;
};

#endif  // WIFIBROADCAST_UINT64SEQNRHELPER_HPP
