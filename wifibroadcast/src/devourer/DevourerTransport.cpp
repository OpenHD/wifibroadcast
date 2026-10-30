#include "DevourerTransport.h"
#include "RxLoopWorker.h"

#ifdef WIFIBROADCAST_WITH_DEVOURER

#include <libusb-1.0/libusb.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <iomanip>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <sstream>
#include <thread>
#include <utility>

#include "DeviceConfig.h"
#include "sensing/SenseWindow.h"
#if defined(__has_include) && __has_include("IRadio.h")
#include "IRadio.h"
using DevourerRadioInterface = IRadio;
#define DEVOURER_CREATE_RADIO(factory, handle, ctx, lock, cfg) \
  (factory).CreateRadio((handle), (ctx), (lock), (cfg))
#else
#include "IRtlDevice.h"
using DevourerRadioInterface = IRtlDevice;
#define DEVOURER_CREATE_RADIO(factory, handle, ctx, lock, cfg) \
  (factory).CreateRtlDevice((handle), (ctx), (lock), (cfg))
#endif
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
  uint16_t vendor = 0;
  uint16_t product = 0;
};

std::optional<int> read_int(const std::filesystem::path& path) {
  std::ifstream input(path);
  int value = 0;
  if (!(input >> value)) return std::nullopt;
  return value;
}

std::optional<UsbAddress> usb_address_for_interface(const std::string& name) {
  // Windows bus numbering can change between libusb contexts. Resolve stable
  // VID/PID selectors in the same context that will open the device.
  const std::string id_prefix = "devourer-id-";
  if (name.rfind(id_prefix, 0) == 0) {
    const auto separator = name.find('-', id_prefix.size());
    if (separator == std::string::npos) return std::nullopt;
    try {
      const auto vendor_text = name.substr(id_prefix.size(), separator - id_prefix.size());
      const auto product_text = name.substr(separator + 1);
      std::size_t vendor_used = 0, product_used = 0;
      const auto vendor = std::stoul(vendor_text, &vendor_used, 16);
      const auto product = std::stoul(product_text, &product_used, 16);
      if (vendor_used == vendor_text.size() && product_used == product_text.size() &&
          vendor > 0 && vendor <= 65535 && product > 0 && product <= 65535)
        return UsbAddress{0, 0, static_cast<uint16_t>(vendor), static_cast<uint16_t>(product)};
    } catch (...) {}
    return std::nullopt;
  }
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
  libusb_device* selected = nullptr;
  for (ssize_t i = 0; i < count; ++i) {
    auto* device = devices[i];
    if (address.vendor != 0) {
      libusb_device_descriptor descriptor{};
      if (libusb_get_device_descriptor(device, &descriptor) != 0 ||
          descriptor.idVendor != address.vendor || descriptor.idProduct != address.product)
        continue;
      if (selected) {  // Refuse ambiguity without opening/resetting either radio.
        libusb_free_device_list(devices, 1);
        return nullptr;
      }
    } else {
      if (libusb_get_bus_number(device) != address.bus ||
          libusb_get_device_address(device) != address.device) continue;
    }
    selected = device;
    if (address.vendor == 0) break;
  }
  if (selected && libusb_open(selected, &handle) != 0) handle = nullptr;
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
        channel_offset = number <= 9 && ((number - 1) / 4) % 2 == 0 ? 1 : 2;
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
  std::FILE* log_file = nullptr;
  libusb_context* context = nullptr;
  libusb_device_handle* handle = nullptr;
  int interface_number = -1;
  std::shared_ptr<devourer::UsbDeviceLock> lock;
  std::unique_ptr<DevourerRadioInterface> device;
  RxLoopWorker rx_worker;
  std::mutex control_mutex;
  std::optional<std::chrono::steady_clock::time_point> tx_timeout_since;

  ~Card() { close(); }

  bool open(Channel channel, bool reset_usb_on_open) {
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
        context, handle, logger, reset_usb_on_open, lock);
    if (rc != 0) {
      logger->error("Cannot claim {} (libusb rc={})", interface_name, rc);
      close();
      return false;
    }
    interface_number = devourer::find_wifi_interface(handle);
    devourer::DeviceConfig config;
    config.rx.enable_with_tx = true;
    WiFiDriver factory(logger);
    device = DEVOURER_CREATE_RADIO(factory, handle, context, lock, config);
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
    logger->set_diag_stream(nullptr);
    if (log_file) { std::fclose(log_file); log_file = nullptr; }
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
    rx_worker.stop_and_join([this] {
      if (device) device->StopRxLoop();
    });
  }
};

Transport::Transport(std::vector<std::string> interface_names, Channel channel,
                     std::string log_path, bool reset_usb_on_open)
    : m_interface_names(std::move(interface_names)), m_channel(channel),
      m_log_path(std::move(log_path)), m_reset_usb_on_open(reset_usb_on_open) {}

Transport::~Transport() { close(); }

bool Transport::open() {
  close();
  for (const auto& name : m_interface_names) {
    auto card = std::make_unique<Card>();
    card->interface_name = name;
    card->logger->set_level(Logger::Level::Info);
    if (!m_log_path.empty()) {
      card->log_file = std::fopen(m_log_path.c_str(), "a");
      if (card->log_file) {
        card->logger->set_diag_stream(card->log_file);
      }
    }
    if (!card->open(m_channel, m_reset_usb_on_open)) {
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

bool Transport::send(int card_index, const uint8_t* data, int length,
                     bool* fatal_error, std::string* failure_reason) {
  if (fatal_error) *fatal_error = false;
  if (failure_reason) failure_reason->clear();
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size()) ||
      !data || length <= 0) {
    if (failure_reason) *failure_reason = "invalid card or packet";
    return false;
  }
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
#if defined(__has_include) && __has_include("IRadio.h")
  const auto previous_stats = card->device->GetTxStats();
#endif
  const bool sent = card->device->send_packet(
      data, static_cast<size_t>(length));
#if defined(__has_include) && __has_include("IRadio.h")
  if (!sent) {
    const auto stats = card->device->GetTxStats();
    const bool new_failure = stats.failed > previous_stats.failed;
    if (failure_reason) {
      if (new_failure) {
        *failure_reason = "USB TX rc=" + std::to_string(stats.last_error_rc) +
                          " timeout=" +
                          (stats.last_was_timeout ? "yes" : "no");
        if (stats.last_error_rc == devourer::kTxShortWriteRc) {
          *failure_reason += " (partial USB write)";
        }
      } else {
        *failure_reason = "send rejected without a new USB TX failure";
      }
    }
    const auto now = std::chrono::steady_clock::now();
    if (new_failure && stats.last_was_timeout) {
      if (!card->tx_timeout_since) card->tx_timeout_since = now;
    } else {
      card->tx_timeout_since.reset();
    }
    // Isolated FIFO back-pressure drops a packet. A cancelled prefix or a
    // sustained stall needs reinitialization before another frame is sent.
    const bool stalled = card->tx_timeout_since &&
        now - *card->tx_timeout_since >= std::chrono::seconds(2);
    if (fatal_error) {
      *fatal_error = stalled || (new_failure && !stats.last_was_timeout &&
          (stats.last_error_rc == LIBUSB_ERROR_NO_DEVICE ||
           stats.last_error_rc == LIBUSB_ERROR_PIPE ||
           stats.last_error_rc == LIBUSB_ERROR_IO ||
           stats.last_error_rc == devourer::kTxShortWriteRc));
    }
  }
#else
  // Older Devourer interfaces expose no failure classification.
  if (!sent && fatal_error) *fatal_error = true;
  if (!sent && failure_reason) {
    *failure_reason = "legacy Devourer backend: USB TX status unavailable";
  }
#endif
  if (sent) card->tx_timeout_since.reset();
  return sent;
}

bool Transport::set_log_path(std::string log_path) {
  bool success = true;
  for (auto& card : m_cards) {
    std::lock_guard<std::mutex> guard(card->control_mutex);
    card->logger->set_diag_stream(nullptr);
    if (card->log_file) {
      std::fclose(card->log_file);
      card->log_file = nullptr;
    }
    if (!log_path.empty()) {
      card->log_file = std::fopen(log_path.c_str(), "a");
      if (card->log_file) {
        card->logger->set_diag_stream(card->log_file);
      } else {
        success = false;
      }
    }
  }
  m_log_path = std::move(log_path);
  return success;
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

std::optional<devourer::AdapterCaps> Transport::get_adapter_caps(int card_index) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size())) return std::nullopt;
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  if (!card->device) return std::nullopt;
  return card->device->GetAdapterCaps();
}

std::string Transport::get_tx_power_diagnostics(const int card_index) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size()))
    return "unavailable: invalid card index";
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  if (!card->device) return "unavailable: no device";
  try {
    const auto caps = card->device->GetTxPowerCaps();
    const auto s = card->device->GetTxPowerDiagnosticState();
    std::ostringstream text;
    text << std::boolalpha << "valid=" << s.valid
         << " hw_readback=" << s.hw_readback << " flat_index=" << s.flat_index
         << " offset_qdb=" << s.offset_qdb << " offset_steps=" << s.offset_steps
         << " step_qdb=" << int(caps.step_qdb) << " index_max=" << int(caps.index_max)
         << " saturated_low=" << s.saturated_low << " saturated_high=" << s.saturated_high
         << " cck=" << s.cck_index << " ofdm=" << s.ofdm_index
         << " mcs7=" << s.mcs7_index << " custom_rate_diffs=" << s.rate_diffs_custom;
    text << " write_status_valid=" << s.tx_write_status_valid
         << " txagc_attempted=" << s.txagc_writes_attempted
         << " txagc_failed=" << s.txagc_writes_failed;
    bool txagc_matches = true;
    for (uint8_t p = 0; p < s.jaguar1_paths; ++p) {
      const auto actual0 = s.jaguar1_mcs03[p] & 0xff;
      const auto actual7 = (s.jaguar1_mcs47[p] >> 24) & 0xff;
      txagc_matches = txagc_matches &&
          actual0 == s.jaguar1_expected_mcs0[p] &&
          actual7 == s.jaguar1_expected_mcs7[p];
      text << " path" << int(p) << "[mcs03=0x" << std::hex << std::setfill('0')
           << std::setw(8) << s.jaguar1_mcs03[p]
           << " mcs47=0x" << std::setw(8) << s.jaguar1_mcs47[p]
           << " training=0x" << std::setw(8) << s.jaguar1_training[p]
           << " swing=0x" << std::setw(8) << s.jaguar1_swing[p] << std::dec
           << " mcs0=" << actual0 << "/expected:" << int(s.jaguar1_expected_mcs0[p])
           << " mcs7=" << actual7 << "/expected:" << int(s.jaguar1_expected_mcs7[p])
           << " match=" << (actual0 == s.jaguar1_expected_mcs0[p] &&
                              actual7 == s.jaguar1_expected_mcs7[p]) << "]";
    }
    // This string is forwarded to the persistent power logger. Distinguish
    // transfer completion from the sampled hardware state; neither measures RF.
    const char* result = "unavailable";
    if (s.tx_write_status_valid) {
      if (s.txagc_writes_failed > 0)
        result = "write_failed";
      else if (s.txagc_writes_attempted == 0)
        result = "no_writes_attempted";
      else if (s.hw_readback && s.jaguar1_paths > 0)
        result = txagc_matches ? "sampled_readback_matches" : "readback_mismatch";
      else
        result = "writes_completed_readback_unavailable";
    }
    text << " txagc_result=" << result;
    return text.str();
  } catch (const std::exception& ex) {
    return std::string("readback failed: ") + ex.what();
  }
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
  try {
    return card->device->GetThermalStatus();
  } catch (const std::exception& ex) {
    // Statistics must survive a failed USB read while the radio recovers.
    card->logger->warn("Thermal read failed for {}: {}", card->interface_name,
                       ex.what());
    return std::nullopt;
  }
}

std::optional<Transport::QualitySnapshot> Transport::get_quality_snapshot(
    const int card_index) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size())) {
    return std::nullopt;
  }
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  if (!card->device) return std::nullopt;
  try {
    return QualitySnapshot{card->device->GetRxQuality(),
                           card->device->GetActiveRxPaths()};
  } catch (const std::exception& ex) {
    // GetRxQuality also reads hardware counters/NHM over USB. A disconnect
    // must not escape the OpenHD statistics thread and terminate the process.
    card->logger->warn("Quality read failed for {}: {}", card->interface_name,
                       ex.what());
    return std::nullopt;
  }
}

std::optional<Transport::SurveySample> Transport::measure_survey(int card_index, int sample_count) {
  if (card_index < 0 || card_index >= static_cast<int>(m_cards.size()))
    return std::nullopt;
  auto& card = m_cards[card_index];
  std::lock_guard<std::mutex> guard(card->control_mutex);
  if (!card->device) return std::nullopt;
  try {
    devourer::sensing::SenseWindow window(
        card->device.get(), dynamic_cast<IRtlRadio*>(card->device.get()));
    devourer::sensing::SenseOptions options;
    window.barrier(options);
    uint64_t nhm_sum = 0, nhm_weight = 0;
    uint64_t busy_sum = 0, busy_weight = 0;
    // Spread short CCX samples across the dwell instead of judging a channel
    // by a single ~2 ms snapshot that can miss intermittent transmitters.
    // Bound caller-supplied counts; Quick uses 10; Medium/Detailed use 20 per visit.
    for (int i = 0; i < std::clamp(sample_count, 1, 20); ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
      const auto sample = window.read(options);
      // FA/CCA event counters and CCX histograms have independent validity.
      // A wrapped event counter must not discard a valid NHM/CLM reading.
      if (sample.nhm.valid) {
        nhm_sum += static_cast<uint64_t>(sample.nhm.env_pct) * sample.nhm.total;
        nhm_weight += sample.nhm.total;
      }
      if (sample.busy.valid_busy && sample.busy.window_us > 0) {
        busy_sum += static_cast<uint64_t>(sample.busy.busy_pct) * sample.busy.window_us;
        busy_weight += sample.busy.window_us;
      }
    }
    SurveySample result;
    result.nhm_valid = nhm_weight != 0;
    result.busy_valid = busy_weight != 0;
    if (result.nhm_valid) result.nhm_env_percent = (nhm_sum + nhm_weight / 2) / nhm_weight;
    if (result.busy_valid) result.busy_percent = (busy_sum + busy_weight / 2) / busy_weight;
    return result;
  } catch (const std::exception& ex) {
    card->logger->warn("Channel survey failed for {}: {}", card->interface_name, ex.what());
    return std::nullopt;
  }
}

void Transport::start_rx(RxCallback callback, FatalCallback fatal_callback) {
  for (int i = 0; i < static_cast<int>(m_cards.size()); ++i) {
    auto* card = m_cards[i].get();
    if (card->rx_worker.joinable()) continue;
    card->rx_worker.start([this, card, i, callback, fatal_callback]() {
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
        // A USB disconnect can end Devourer's RX loop without throwing.
        // Notify the supervisor unless we deliberately stopped reception.
        if (!card->rx_worker.stop_requested()) {
          card->logger->error("RX loop exited unexpectedly for {}",
                              card->interface_name);
          if (fatal_callback) fatal_callback(ENODEV);
        }
      } catch (const std::exception& ex) {
        card->logger->error("RX loop failed for {}: {}", card->interface_name,
                            ex.what());
        if (!card->rx_worker.stop_requested() && fatal_callback)
          fatal_callback(ENODEV);
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
    card->rx_worker.request_stop();
  }
  for (auto& card : m_cards) {
    card->stop_rx();
  }
}

}  // namespace wifibroadcast::devourer_transport

#endif
