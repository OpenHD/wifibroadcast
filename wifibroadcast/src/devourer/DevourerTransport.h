#pragma once

#ifdef WIFIBROADCAST_WITH_DEVOURER

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "FhssSession.h"
#include "ThermalStatus.h"
#include "RxQuality.h"

struct Packet;

namespace wifibroadcast::devourer_transport {

struct Channel {
  int frequency_mhz = 0;
  int width_mhz = 20;
};

struct FhssConfig {
  devourer::FhssSession::Role role = devourer::FhssSession::Role::Follower;
  std::vector<int> frequencies_mhz;
  int width_mhz = 20;
  uint32_t slot_ms = 50;
  devourer::HopSchedule::Key key{};
};

class Transport {
 public:
  using RxCallback = std::function<void(int, const Packet&)>;
  using FatalCallback = std::function<void(int)>;

  Transport(std::vector<std::string> interface_names, Channel channel);
  ~Transport();
  Transport(const Transport&) = delete;
  Transport& operator=(const Transport&) = delete;

  bool open();
  void close();
  bool send(int card_index, const uint8_t* data, int length);
  bool set_channel(Channel channel);
  bool set_card_channel(int card_index, Channel channel);
  void set_tx_power_index_override(int card_index, int index);
  int set_tx_power_offset_qdb(int card_index, int offset_qdb);
  int set_tx_power_level(int card_index, int level, int normal_offset_qdb);
  std::optional<devourer::ThermalStatus> get_thermal_status(int card_index);
  struct QualitySnapshot {
    devourer::RxQuality quality;
    devourer::ActiveRxPaths paths;
  };
  std::optional<QualitySnapshot> get_quality_snapshot(int card_index);
  void start_rx(RxCallback callback, FatalCallback fatal_callback);
  void stop_rx();
  bool start_fhss(const FhssConfig& config);
  void stop_fhss();
  std::optional<devourer::FhssSession::Status> get_fhss_status() const;

 private:
  struct Card;
  std::vector<std::string> m_interface_names;
  std::vector<std::unique_ptr<Card>> m_cards;
  Channel m_channel;
  mutable std::mutex m_fhss_mutex;
  std::shared_ptr<devourer::FhssSession> m_fhss;
};

}  // namespace wifibroadcast::devourer_transport

#endif
