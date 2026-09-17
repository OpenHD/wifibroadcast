#include "DevourerTransport.h"

#ifdef WIFIBROADCAST_WITH_DEVOURER

#include <libusb-1.0/libusb.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <utility>

#include "DeviceConfig.h"
#include "IRtlDevice.h"
#include "RadiotapBuilder.h"
#include "RxPacket.h"
#include "SelectedChannel.h"
#include "UsbDeviceLock.h"
#include "UsbOpen.h"
#include "WiFiDriver.h"
#include "logger.h"

namespace wifibroadcast::devourer_transport {
namespace {

struct UsbAddress {
  uint8_t bus = 0;
  uint8_t device = 0;
};

std::optional<int> read_int(const std::filesystem::path& path) {
  std::ifstream input(path);
  int value = 0;
  if (!(input >> value)) return std::nullopt;
  return value;
}

std::optional<UsbAddress> usb_address_for_interface(const std::string& name) {
  static constexpr const char* prefix = "devourer-usb-";
  if (name.rfind(prefix, 0) == 0) {
    const auto separator = name.find('-', std::char_traits<char>::length(prefix));
    if (separator != std::string::npos) {
      try {
        const int bus = std::stoi(
            name.substr(std::char_traits<char>::length(prefix),
                        separator - std::char_traits<char>::length(prefix)));
        const int device = std::stoi(name.substr(separator + 1));
        if (bus > 0 && bus <= 255 && device > 0 && device <= 255) {
          return UsbAddress{static_cast<uint8_t>(bus),
                            static_cast<uint8_t>(device)};
        }
      } catch (...) {
      }
    }
    return std::nullopt;
  }
  std::error_code ec;
  auto path = std::filesystem::canonical(
      std::filesystem::path("/sys/class/net") / name / "device", ec);
  if (ec) return std::nullopt;
  for (int depth = 0; depth < 12 && !path.empty(); ++depth) {
    const auto bus = read_int(path / "busnum");
    const auto device = read_int(path / "devnum");
    if (bus && device && *bus > 0 && *bus <= 255 && *device > 0 &&
        *device <= 255) {
      return UsbAddress{static_cast<uint8_t>(*bus),
                        static_cast<uint8_t>(*device)};
    }
    const auto parent = path.parent_path();
    if (parent == path) break;
    path = parent;
  }
  return std::nullopt;
}

libusb_device_handle* open_address(libusb_context* context,
                                   const UsbAddress& address) {
  libusb_device** devices = nullptr;
  const auto count = libusb_get_device_list(context, &devices);
  if (count < 0) return nullptr;
  libusb_device_handle* handle = nullptr;
  for (ssize_t i = 0; i < count; ++i) {
    auto* device = devices[i];
    if (libusb_get_bus_number(device) != address.bus ||
        libusb_get_device_address(device) != address.device) {
      continue;
    }
    if (libusb_open(device, &handle) != 0) handle = nullptr;
    break;
  }
  libusb_free_device_list(devices, 1);
  return handle;
}

std::optional<SelectedChannel> selected_channel(Channel channel) {
  int number = -1;
  if (channel.frequency_mhz == 2484) {
    number = 14;
  } else if (channel.frequency_mhz >= 2412 &&
             channel.frequency_mhz <= 2472 &&
             (channel.frequency_mhz - 2407) % 5 == 0) {
    number = (channel.frequency_mhz - 2407) / 5;
  } else if (channel.frequency_mhz >= 5000 &&
             (channel.frequency_mhz - 5000) % 5 == 0) {
    number = (channel.frequency_mhz - 5000) / 5;
  }
  ChannelWidth_t width;
  uint8_t channel_offset = 0;
  switch (channel.width_mhz) {
    case 5:
      width = CHANNEL_WIDTH_5;
      break;
    case 10:
      width = CHANNEL_WIDTH_10;
      break;
    case 20:
      width = CHANNEL_WIDTH_20;
      break;
    case 40:
      width = CHANNEL_WIDTH_40;
      // Devourer needs the primary-20 position to tune the RF center for
      // HT40. OpenHD's supported channel list alternates HT40+ and HT40-
      // within each standard four-channel block. ChannelOffset follows the
      // HAL convention: 1 = HT40+ (secondary above), 2 = HT40- (below).
      if (number <= 14) {
        channel_offset = ((number - 1) / 4) % 2 == 0 ? 1 : 2;
      } else if (number <= 36 || number >= 181) {
        channel_offset = 1;
      } else if (number >= 149) {
        channel_offset = ((number - 1) / 4) % 2 == 1 ? 1 : 2;
      } else {
        channel_offset = (number / 4) % 2 == 1 ? 1 : 2;
      }
      break;
    case 80:
      width = CHANNEL_WIDTH_80;
      break;
    default:
      return std::nullopt;
  }
  if (number < 0 || number > 255) return std::nullopt;
  return SelectedChannel{static_cast<uint8_t>(number), channel_offset, width};
}

constexpr int scale_overdrive_qdb(int full_headroom_qdb, int level) {
  const int overdrive = level <= 100 ? 0 : (level >= 150 ? 50 : level - 100);
  return (full_headroom_qdb * overdrive + 25) / 50;
}

static_assert(scale_overdrive_qdb(56, 100) == 0);
static_assert(scale_overdrive_qdb(56, 125) == 28);
static_assert(scale_overdrive_qdb(56, 150) == 56);

}  // namespace

struct Transport::Card {
  std::string interface_name;
  std::shared_ptr<Logger> logger = std::make_shared<Logger>();
  libusb_context* context = nullptr;
  libusb_device_handle* handle = nullptr;
  int interface_number = -1;
  std::shared_ptr<devourer::UsbDeviceLock> lock;
  std::unique_ptr<IRtlDevice> device;
  std::thread rx_thread;
  std::mutex control_mutex;

  ~Card() { close(); }

  bool open(Channel channel) {
    const auto address = usb_address_for_interface(interface_name);
    if (!address) {
      logger->error("Cannot resolve {} to a USB device", interface_name);
      return false;
    }
    if (libusb_init(&context) != 0) return false;
    libusb_set_option(context, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_WARNING);
    handle = open_address(context, *address);
    if (!handle) {
      logger->error("Cannot open USB device for {}", interface_name);
      close();
      return false;
    }
    interface_number = devourer::find_wifi_interface(handle);
    const int rc = devourer::claim_interface_reset_reopen(
        context, handle, logger, true, lock);
    if (rc != 0) {
      logger->error("Cannot claim {} (libusb rc={})", interface_name, rc);
      close();
      return false;
    }
    interface_number = devourer::find_wifi_interface(handle);
    devourer::DeviceConfig config;
    config.rx.enable_with_tx = true;
    WiFiDriver factory(logger);
    device = factory.CreateRtlDevice(handle, context, lock, config);
    const auto selected = selected_channel(channel);
    if (!device || !selected) {
      logger->error("Unsupported adapter or channel for {}", interface_name);
      close();
      return false;
    }
    try {
      device->InitWrite(*selected);
      const auto caps = device->GetAdapterCaps();
      if (!caps.supported) {
        logger->error("Refusing {} for broadcast: Devourer capabilities "
                      "are unavailable", interface_name);
        close();
        return false;
      }
      // The shared RTL8812A/RTL8811A chip ID alone is not a reason to deny
      // a card. The initialized RF capabilities are decisive: STBC cannot be
      // kept active on a physical 1T1R cut.
      if (caps.tx_chains < 2 || caps.rx_chains < 2 ||
          !caps.tx.stbc_ok || !caps.tx.ldpc_ok) {
        logger->error(
            "Refusing {} for broadcast: {} TX / {} RX chains, "
            "STBC={}, LDPC={}", interface_name, caps.tx_chains,
            caps.rx_chains, caps.tx.stbc_ok, caps.tx.ldpc_ok);
        close();
        return false;
      }
    } catch (const std::exception& ex) {
      logger->error("Devourer bring-up failed for {}: {}", interface_name,
                    ex.what());
      close();
      return false;
    }
    return true;
  }

  void close() {
    stop_rx();
    if (device) {
      try {
        device->Stop();
      } catch (...) {
      }
      device.reset();
    }
    if (handle) {
      if (interface_number >= 0) {
        libusb_release_interface(handle, interface_number);
      }
      libusb_close(handle);
      handle = nullptr;
    }
    lock.reset();
    if (context) {
      libusb_exit(context);
      context = nullptr;
    }
  }

  void stop_rx() {
    if (device) device->StopRxLoop();
    if (rx_thread.joinable()) rx_thread.join();
  }
};

Transport::Transport(std::vector<std::string> interface_names, Channel channel)
    : m_interface_names(std::move(interface_names)), m_channel(channel) {}

Transport::~Transport() { close(); }

bool Transport::open() {
  close();
  for (const auto& name : m_interface_names) {
    auto card = std::make_unique<Card>();
    card->interface_name = name;
    card->logger->set_level(Logger::Level::Info);
    if (!card->open(m_channel)) {
      close();
      return false;
    }
    m_cards.push_back(std::move(card));
  }
  return !m_cards.empty();
}

void Transport::close() {
  stop_fhss();
  stop_rx();
  m_cards.clear();
}

bool Transport::send(int card_index, const uint8_t* data, int length) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size()) ||
      !data || length <= 0) {
    return false;
  }
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  return card->device->send_packet(
      data, static_cast<size_t>(length));
}

bool Transport::set_channel(Channel channel) {
  {
    std::lock_guard<std::mutex> lock(m_fhss_mutex);
    if (m_fhss && m_fhss->running()) return false;
  }
  const auto selected = selected_channel(channel);
  if (!selected) return false;
  try {
    for (auto& card : m_cards) {
      std::lock_guard<std::mutex> guard(card->control_mutex);
      card->device->SetMonitorChannel(*selected);
    }
  } catch (const std::exception&) {
    return false;
  }
  m_channel = channel;
  return true;
}

bool Transport::set_card_channel(const int card_index, Channel channel) {
  {
    std::lock_guard<std::mutex> lock(m_fhss_mutex);
    if (m_fhss && m_fhss->running()) return false;
  }
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size())) {
    return false;
  }
  const auto selected = selected_channel(channel);
  if (!selected) return false;
  try {
    auto& card = m_cards[card_index];
    std::lock_guard<std::mutex> guard(card->control_mutex);
    if (!card->device) return false;
    card->device->SetMonitorChannel(*selected);
  } catch (const std::exception&) {
    return false;
  }
  return true;
}

void Transport::set_tx_power_index_override(const int card_index,
                                            const int index) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size())) return;
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  card->device->SetTxPowerIndexOverride(index);
}

int Transport::set_tx_power_offset_qdb(const int card_index,
                                       const int offset_qdb) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size())) {
    return 0;
  }
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  // A flat override discards the EFUSE per-rate/per-path shape. Always restore
  // that calibrated baseline before applying the relative control.
  card->device->SetTxPowerIndexOverride(-1);
  return card->device->SetTxPowerOffsetQdb(offset_qdb);
}

int Transport::set_tx_power_level(const int card_index, const int level,
                                  const int normal_offset_qdb) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size())) {
    return 0;
  }
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  if (!card->device) return 0;

  // Always stay on the calibrated relative-power path. In particular, do not
  // revive the old flat max-index override, which discards the per-rate and
  // per-path EFUSE shape.
  card->device->SetTxPowerIndexOverride(-1);
  if (level <= 100) {
    return card->device->SetTxPowerOffsetQdb(normal_offset_qdb);
  }

  // Measure headroom from a clean 100% baseline. The representative MCS7
  // index is the anchor used by Devourer's calibrated tables. Families with a
  // fixed-dBm/TSSI model expose their headroom directly as offset_max_qdb.
  card->device->SetTxPowerOffsetQdb(0);
  const auto caps = card->device->GetTxPowerCaps();
  const auto state = card->device->GetTxPowerState();
  if (!caps.supported || caps.step_qdb == 0) return 0;

  int full_headroom_qdb = caps.offset_max_qdb;
  if (caps.index_max > 0 && state.valid && state.mcs7_index >= 0) {
    const int headroom_steps =
        std::max(0, static_cast<int>(caps.index_max) - state.mcs7_index);
    full_headroom_qdb = headroom_steps * caps.step_qdb;
  }
  const int max_supported_qdb =
      std::max(0, static_cast<int>(caps.offset_max_qdb));
  full_headroom_qdb =
      std::clamp(full_headroom_qdb, 0, max_supported_qdb);

  const int requested_qdb = scale_overdrive_qdb(full_headroom_qdb, level);
  card->logger->warn(
      "TX-power OVERDRIVE {}%: using {} of {} qdB calibrated headroom",
      level, requested_qdb, full_headroom_qdb);
  return card->device->SetTxPowerOffsetQdb(requested_qdb);
}

std::optional<devourer::ThermalStatus> Transport::get_thermal_status(
    const int card_index) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size())) {
    return std::nullopt;
  }
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  if (!card->device) return std::nullopt;
  return card->device->GetThermalStatus();
}

std::optional<Transport::QualitySnapshot> Transport::get_quality_snapshot(
    const int card_index) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size())) {
    return std::nullopt;
  }
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  if (!card->device) return std::nullopt;
  return QualitySnapshot{card->device->GetRxQuality(),
                         card->device->GetActiveRxPaths()};
}

void Transport::start_rx(RxCallback callback, FatalCallback fatal_callback) {
  for (int i = 0; i < static_cast<int>(m_cards.size()); ++i) {
    auto* card = m_cards[i].get();
    if (card->rx_thread.joinable()) continue;
    card->rx_thread = std::thread([this, card, i, callback, fatal_callback]() {
      try {
        card->device->StartRxLoop(
            [this, i, callback](const Packet& packet) {
              // Devourer's sync/control frame is consumed by the backend.  It
              // is never OpenHD telemetry and must not enter wifibroadcast's
              if (packet.Data.size() >= 24 && !packet.RxAtrib.crc_err &&
                  !packet.RxAtrib.icv_err) {
                std::shared_ptr<devourer::FhssSession> session;
                {
                  std::lock_guard<std::mutex> lock(m_fhss_mutex);
                  session = m_fhss;
                }
                if (session && session->on_sync_marker(
                                   packet.Data.data(), packet.Data.size()))
                  return;
              }
              callback(i, packet);
            });
      } catch (const std::exception& ex) {
        card->logger->error("RX loop failed for {}: {}", card->interface_name,
                            ex.what());
        if (fatal_callback) fatal_callback(ENODEV);
      }
    });
  }
}

bool Transport::start_fhss(const FhssConfig& config) {
  if (config.frequencies_mhz.empty() || m_cards.empty()) return false;
  std::vector<uint8_t> channels;
  channels.reserve(config.frequencies_mhz.size());
  std::optional<uint8_t> required_offset;
  for (const int frequency : config.frequencies_mhz) {
    const auto selected = selected_channel({frequency, config.width_mhz});
    if (!selected) return false;
    // FastRetune keeps the configured bandwidth/primary position.  At HT40
    // every member of one hopset must therefore use the same +/- orientation.
    if (!required_offset) required_offset = selected->ChannelOffset;
    if (selected->ChannelOffset != *required_offset) return false;
    channels.push_back(selected->Channel);
  }

  devourer::FhssSession::Config session_config;
  session_config.role = config.role;
  session_config.channels = std::move(channels);
  session_config.slot_ms = config.slot_ms;
  session_config.key = config.key;

  auto retune = [this](const uint8_t channel, const bool cache_rf) {
    try {
      for (auto& card : m_cards) {
        std::lock_guard<std::mutex> guard(card->control_mutex);
        if (!card->device) return false;
        card->device->FastRetune(channel, cache_rf);
      }
      return true;
    } catch (const std::exception&) {
      return false;
    }
  };
  auto marker_tx = [this](const uint8_t* marker, const size_t marker_size) {
    if (m_cards.empty() || !marker || !marker_size) return false;
    auto frame = devourer::build_stream_radiotap(
        devourer::parse_tx_mode_str("6M"));
    static constexpr uint8_t kProbeHeader[24] = {
        0x40, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x57, 0x42, 0x75, 0x05, 0xd6, 0x00,
        0x57, 0x42, 0x75, 0x05, 0xd6, 0x00,
        0x80, 0x00};
    frame.insert(frame.end(), std::begin(kProbeHeader), std::end(kProbeHeader));
    frame.insert(frame.end(), marker, marker + marker_size);
    auto& card = m_cards.front();
    std::lock_guard<std::mutex> guard(card->control_mutex);
    return card->device && card->device->send_packet(frame.data(), frame.size());
  };

  try {
    auto next = std::make_shared<devourer::FhssSession>(
        std::move(session_config), std::move(retune), std::move(marker_tx));
    next->start();
    std::shared_ptr<devourer::FhssSession> old;
    {
      std::lock_guard<std::mutex> lock(m_fhss_mutex);
      old = std::move(m_fhss);
      m_fhss = std::move(next);
    }
    if (old) old->stop();
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

void Transport::stop_fhss() {
  std::shared_ptr<devourer::FhssSession> session;
  {
    std::lock_guard<std::mutex> lock(m_fhss_mutex);
    session = std::move(m_fhss);
  }
  if (session) session->stop();
}

std::optional<devourer::FhssSession::Status> Transport::get_fhss_status() const {
  std::lock_guard<std::mutex> lock(m_fhss_mutex);
  if (!m_fhss) return std::nullopt;
  return m_fhss->status();
}

void Transport::stop_rx() {
  for (auto& card : m_cards) {
    if (card->device) card->device->StopRxLoop();
  }
  for (auto& card : m_cards) {
    if (card->rx_thread.joinable()) card->rx_thread.join();
  }
}

}  // namespace wifibroadcast::devourer_transport

#endif
