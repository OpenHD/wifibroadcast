//
// Created by consti10 on 18.05.22.
//

#ifndef WIFIBROADCAST_SRC_HELPERSOURCES_SEQUENCENUMBERDEBUGGER_H_
#define WIFIBROADCAST_SRC_HELPERSOURCES_SEQUENCENUMBERDEBUGGER_H_

#include <chrono>
#include <cstdint>
#include <iostream>
#include <vector>

#include "../wifibroadcast_spdlog.h"
#include <spdlog/spdlog.h>
#include "StringHelper.hpp"

/**
 * Debug the n lost packets and the n of packet gaps by for a continuous stream of packets with increasing sequence number.
 */
class SequenceNumberDebugger {
 public:
  SequenceNumberDebugger() {
    gapsBetweenLostPackets.reserve(1000);
  }
  /**
   * Call when a new squence number is received
   * @param seqNr the received sequence number.
   */
  void sequenceNumber(const int64_t seqNr) {
    nReceivedPackets++;
    auto delta = seqNr - lastReceivedSequenceNr;
    if (delta <= 0) {
      wifibroadcast::log::get_default()->debug("got packet nr: {} after packet nr: {}",seqNr,lastReceivedSequenceNr);
      return;
    }
    if (delta > 1) {
      nLostPackets += delta - 1;
      gapsBetweenLostPackets.push_back(delta);
    }
    if(gapsBetweenLostPackets.size()>=1000){
      gapsBetweenLostPackets.resize(0);
    }
    lastReceivedSequenceNr = seqNr;
  }
  /**
   * Log information about the lost packets and gaps between them.
   * @param clear clear the already accumulated data.
   */
  void debug(bool clear) {
    std::stringstream ss;
    ss<< "N packets received:" << nReceivedPackets << "\tlost:" << nLostPackets << "\n";
    ss<< "Packet gaps:" << StringHelper::vectorAsString(gapsBetweenLostPackets);
    wifibroadcast::log::get_default()->debug(ss.str());
    if (clear) {
      gapsBetweenLostPackets.resize(0);
    }
  }
  void debug_in_intervals(){
    const auto elapsed=std::chrono::steady_clock::now()-m_last_log;
    if(elapsed<std::chrono::seconds(1)){
      return;
    }
    debug(true);
    m_last_log=std::chrono::steady_clock::now();
  }
 private:
  std::int64_t lastReceivedSequenceNr = -1;
  std::int64_t nReceivedPackets = 0;
  std::int64_t nLostPackets = 0;
  std::vector<int64_t> gapsBetweenLostPackets;
  std::chrono::steady_clock::time_point m_last_log=std::chrono::steady_clock::now();
};

#endif //WIFIBROADCAST_SRC_HELPERSOURCES_SEQUENCENUMBERDEBUGGER_H_
