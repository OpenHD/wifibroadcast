//
// Created by consti10 on 09.08.23.
//

#ifndef WIFIBROADCAST_SIGNALQUALITYACCUMULATOR_HPP
#define WIFIBROADCAST_SIGNALQUALITYACCUMULATOR_HPP

#include <optional>

#include "HelperSources/TimeHelper.hpp"
#include "wifibroadcast_spdlog.h"

/**
 * UINT16SeqNrHelper to accumulate (rtl8812au) signal quality values
 */
class SignalQualityAccumulator{
 public:
  void add_signal_quality(int signal_quality_perc){
    if(signal_quality_perc>100 || signal_quality_perc<0){
      if(m_debug_invalid_signal_quality){
        wifibroadcast::log::get_default()->debug("Invalid signal quality {}",signal_quality_perc);
      }
      return ;
    }
    m_acc.add(signal_quality_perc);
    if(m_acc.getNSamples()>10 || m_acc.get_delta_since_last_reset()>std::chrono::milliseconds(500)){
      const auto tmp=m_acc.getMinMaxAvg();
      const auto avg=tmp.avg;
      if(avg>=0 && avg<=100){
        m_curr_signal_quality=avg;
      }
      m_acc.reset();
    }
  }
  void reset(){
    m_acc.reset();
    m_curr_signal_quality=-1;
  }
  int8_t get_current_signal_quality()const{
    return m_curr_signal_quality;
  }
  void set_debug_invalid_signal_quality(bool enable){
    m_debug_invalid_signal_quality=enable;
  }
 private:
  BaseAvgCalculator<int> m_acc;
  // -1 if invalid, [0,100] otherwise
  int8_t m_curr_signal_quality=-1;
  bool m_debug_invalid_signal_quality= false;
};

#endif  // WIFIBROADCAST_SIGNALQUALITYACCUMULATOR_HPP
