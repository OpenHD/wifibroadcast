//
// Created by consti10 on 27.06.23.
//

#include "WBTxRx.h"

#include <utility>

#include "../radiotap/RadiotapHeaderRx.hpp"
#include "../radiotap/radiotap_util.hpp"
#include "SchedulingHelper.hpp"
#include "pcap_helper.hpp"
#include "raw_socket_helper.hpp"

WBTxRx::WBTxRx(
    std::vector<wifibroadcast::WifiCard> wifi_cards1, Options options1,
    std::shared_ptr<RadiotapHeaderTxHolder> session_key_radiotap_header)
    : m_options(options1),
      m_wifi_cards(std::move(wifi_cards1)),
      m_session_key_radiotap_header(std::move(session_key_radiotap_header)) {
  assert(!m_wifi_cards.empty());
  m_console = wifibroadcast::log::create_or_get("WBTxRx");
  m_console->debug(
      "[{}]", options_to_string(
                  wifibroadcast::get_wifi_card_names(m_wifi_cards), m_options));
  // Common error - not run as root
  if (!SchedulingHelper::check_root()) {
    std::cerr << "wifibroadcast needs root" << std::endl;
    m_console->warn("wifibroadcast needs root");
    assert(false);
  }
  m_receive_pollfds.resize(m_wifi_cards.size());
  m_active_tx_card_data.resize(m_wifi_cards.size());
  for (int i = 0; i < m_wifi_cards.size(); i++) {
    RxStatsPerCard tmp{};
    tmp.card_index = i;
    m_rx_stats_per_card.push_back(tmp);
  }
  m_card_is_disconnected.resize(m_wifi_cards.size());
  for (int i = 0; i < m_wifi_cards.size(); i++) {
    auto tmp = std::make_shared<PerCardCalculators>();
    tmp->seq_nr.set_store_and_debug_gaps(i, m_options.debug_packet_gaps);
    tmp->rf_aggregator.set_debug_invalid_values(m_options.debug_rssi >= 1);
    m_per_card_calc.push_back(tmp);
    m_card_is_disconnected[i] = false;
  }
  for (int i = 0; i < m_wifi_cards.size(); i++) {
    auto wifi_card = m_wifi_cards[i];
    if (wifi_card.type == wifibroadcast::WIFI_CARD_TYPE_EMULATE_GND) {
      m_optional_dummy_link = std::make_unique<DummyLink>(false);
    } else if (wifi_card.type == wifibroadcast::WIFI_CARD_TYPE_EMULATE_AIR) {
      m_optional_dummy_link = std::make_unique<DummyLink>(true);
    } else {
      PcapTxRx pcapTxRx{};
      // RX part - using pcap
      pcapTxRx.rx = wifibroadcast::pcap_helper::open_pcap_rx(wifi_card.name);
      if (m_options.pcap_rx_set_direction) {
        const auto ret = pcap_setdirection(pcapTxRx.rx, PCAP_D_IN);
        if (ret != 0) {
          m_console->debug("pcap_setdirection() returned {}", ret);
        }
      }
      auto rx_pollfd = pcap_get_selectable_fd(pcapTxRx.rx);
      m_receive_pollfds[i].fd = rx_pollfd;
      m_receive_pollfds[i].events = POLLIN;
      // TX part - using raw socket or pcap
      if (m_options.tx_without_pcap) {
        pcapTxRx.tx_sockfd = open_wifi_interface_as_raw_socket(wifi_card.name);
        if (m_options.set_tx_sock_qdisc_bypass) {
          wifibroadcast::pcap_helper::set_tx_sock_qdisc_bypass(
              pcapTxRx.tx_sockfd);
        }
      } else {
        pcapTxRx.tx = wifibroadcast::pcap_helper::open_pcap_tx(wifi_card.name);
        if (m_options.set_tx_sock_qdisc_bypass) {
          wifibroadcast::pcap_helper::pcap_set_tx_sock_qdisc_bypass(
              pcapTxRx.tx);
        }
      }
      m_pcap_handles.push_back(pcapTxRx);
    }
  }
  wb::KeyPairTxRx keypair{};
  if (m_options.secure_keypair.has_value()) {
    keypair = m_options.secure_keypair.value();
  } else {
    keypair = wb::generate_keypair_from_bind_phrase();
  }
  m_encryptor = std::make_unique<wb::Encryptor>(
      keypair.get_tx_key(!m_options.use_gnd_identifier));
  m_decryptor = std::make_unique<wb::Decryptor>(
      keypair.get_rx_key(!m_options.use_gnd_identifier));
  m_encryptor->makeNewSessionKey(m_tx_sess_key_packet.sessionKeyNonce,
                                 m_tx_sess_key_packet.sessionKeyData);
  // next session key in delta ms if packets are being fed
  m_session_key_next_announce_ts = std::chrono::steady_clock::now();
  // Per libsodium documentation, the first nonce should be chosen randomly
  // This selects a random nonce in 32-bit range - we therefore have still
  // 32-bit increasing indexes left, which means tx can run indefinitely
  m_nonce = randombytes_random();
}

WBTxRx::~WBTxRx() {
  stop_receiving();
  for (auto& fd : m_receive_pollfds) {
    close(fd.fd);
  }
  for (auto& pcapTxRx : m_pcap_handles) {
    if (pcapTxRx.rx == pcapTxRx.tx) {
      pcap_close(pcapTxRx.rx);
      pcapTxRx.rx = nullptr;
      pcapTxRx.tx = nullptr;
    } else {
      if (pcapTxRx.rx != nullptr) {
        pcap_close(pcapTxRx.rx);
      }
      if (pcapTxRx.tx != nullptr) {
        pcap_close(pcapTxRx.tx);
      }
      if (pcapTxRx.tx_sockfd != -1) {
        close(pcapTxRx.tx_sockfd);
      }
    }
    // pcap_close(pcapTxRx.rx);
    // pcap_close(pcapTxRx.tx);
  }
}

void WBTxRx::tx_inject_packet(const uint8_t stream_index, const uint8_t* data,
                              int data_len,
                              const RadiotapHeaderTx& tx_radiotap_header,
                              bool encrypt) {
  assert(data_len <= MAX_PACKET_PAYLOAD_SIZE);
  assert(stream_index >= STREAM_INDEX_MIN && stream_index <= STREAM_INDEX_MAX);
  std::lock_guard<std::mutex> guard(m_tx_mutex);
  // for openhd ground station functionality
  if (m_disable_all_transmissions) {
    return;
  }
  announce_session_key_if_needed();
  // new wifi packet
  const auto packet_size =
      // Radiotap header comes first
      RadiotapHeaderTx::SIZE_BYTES +
      // Then the Ieee80211 header
      Ieee80211HeaderRaw::SIZE_BYTES +
      // actual data
      data_len +
      // encryption suffix
      crypto_aead_chacha20poly1305_ABYTES;
  uint8_t* packet_buff = m_tx_packet_buff.data();
  // radiotap header comes first
  memcpy(packet_buff, tx_radiotap_header.getData(),
         RadiotapHeaderTx::SIZE_BYTES);
  // Iee80211 header comes next
  // Will most likely be overridden by the driver
  const auto this_packet_ieee80211_seq = m_ieee80211_seq++;
  m_tx_ieee80211_hdr_openhd.write_ieee80211_seq_nr(this_packet_ieee80211_seq);
  // create a new nonce for this packet
  const uint64_t this_packet_nonce = m_nonce++;
  RadioPort this_packet_radio_port{encrypt, stream_index};
  m_tx_ieee80211_hdr_openhd.write_radio_port_src_dst(
      radio_port_to_uint8_t(this_packet_radio_port));
  const auto unique_tx_id = m_options.use_gnd_identifier
                                ? OPENHD_IEEE80211_HEADER_UNIQUE_ID_GND
                                : OPENHD_IEEE80211_HEADER_UNIQUE_ID_AIR;
  m_tx_ieee80211_hdr_openhd.write_unique_id_src_dst(unique_tx_id);
  m_tx_ieee80211_hdr_openhd.write_nonce(this_packet_nonce);
  if (m_options.enable_non_openhd_mode) {
    // dirty, just overwrite the mac and inject
    m_tx_ieee80211_hdr_openhd.dirty_write_dummy_fixed_src_dest_mac();
  }
  // m_console->debug("Test Nonce:{}/{} {} {}
  // {}",this_packet_nonce,m_tx_ieee80211_hdr_openhd.get_nonce(),m_tx_ieee80211_hdr_openhd.has_valid_air_gnd_id(),m_tx_ieee80211_hdr_openhd.has_valid_radio_port(),
  //                  m_tx_ieee80211_hdr_openhd.is_data_frame());
  memcpy(packet_buff + RadiotapHeaderTx::SIZE_BYTES,
         (uint8_t*)&m_tx_ieee80211_hdr_openhd, Ieee80211HeaderRaw::SIZE_BYTES);
  // Then the encrypted / validated data (including encryption / validation
  // suffix)
  uint8_t* encrypted_data_p = packet_buff + RadiotapHeaderTx::SIZE_BYTES +
                              Ieee80211HeaderRaw::SIZE_BYTES;
  m_encryptor->set_encryption_enabled(encrypt);
  const auto before_encrypt = std::chrono::steady_clock::now();
  const auto ciphertext_len = m_encryptor->authenticate_and_encrypt(
      this_packet_nonce, data, data_len, encrypted_data_p);
  if (m_options.debug_encrypt_time) {
    m_packet_encrypt_time.add(std::chrono::steady_clock::now() -
                              before_encrypt);
    if (m_packet_encrypt_time.get_delta_since_last_reset() >
        std::chrono::seconds(2)) {
      m_console->debug("Encrypt/validate: {}",
                       m_packet_encrypt_time.getAvgReadable());
      m_packet_encrypt_time.reset();
    }
  }
  // we allocate the right size in the beginning, but check if ciphertext_len is
  // actually matching what we calculated (the documentation says 'write up to n
  // bytes' but they probably mean (write exactly n bytes unless an error
  // occurs)
  assert(data_len + crypto_aead_chacha20poly1305_ABYTES == ciphertext_len);
  // we inject the packet on whatever card has the highest rx rssi right now
  const bool success =
      inject_radiotap_packet(m_curr_tx_card.load(), packet_buff, packet_size);
  if (success) {
    m_tx_stats.n_injected_bytes_excluding_overhead += data_len;
    m_tx_stats.n_injected_bytes_including_overhead += packet_size;
    m_tx_stats.n_injected_packets++;
  } else {
    m_console->debug("inject error, sleeping ...");
    // m_tx_mutex.unlock(); for now, don't unlock ... therefore we block all
    // threads calling inject
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
}

bool WBTxRx::inject_radiotap_packet(int card_index, const uint8_t* packet_buff,
                                    int packet_size) {
  // inject via pcap
  int len_injected = 0;
  // we inject the packet on whatever card has the highest rx rssi right now
  const auto before_inject = std::chrono::steady_clock::now();
  if (m_optional_dummy_link) {
    m_optional_dummy_link->tx_radiotap(packet_buff, packet_size);
    len_injected = packet_size;
  } else if (m_options.tx_without_pcap) {
    len_injected = (int)write(m_pcap_handles[card_index].tx_sockfd, packet_buff,
                              packet_size);
  } else {
    len_injected =
        pcap_inject(m_pcap_handles[card_index].tx, packet_buff, packet_size);
    // const auto
    // len_injected=write(m_receive_pollfds[card_index].fd,packet_buff,packet_size);
  }
  const auto delta_inject = std::chrono::steady_clock::now() - before_inject;
  if (delta_inject >= m_options.max_sane_injection_time) {
    m_tx_stats.count_tx_injections_error_hint++;
  }
  if (m_options.debug_tx_injection_time) {
    m_tx_inject_time.add(delta_inject);
    if (m_tx_inject_time.get_delta_since_last_reset() >
        std::chrono::seconds(2)) {
      m_console->debug("packet injection time: {}",
                       m_tx_inject_time.getAvgReadable());
      m_tx_inject_time.reset();
    }
    if (delta_inject > m_options.max_sane_injection_time) {
      m_console->debug("Injected packet ret:{} took:{}", len_injected,
                       MyTimeHelper::R(delta_inject));
    }
  }
  if (len_injected != (int)packet_size) {
    // This basically should never fail - if the tx queue is full, pcap seems to
    // wait ?!
    bool has_fatal_error = false;
    if (m_options.tx_without_pcap) {
      m_console->warn(
          "raw sock - unable to inject packet size:{} ret:{} err:[{}]",
          packet_size, len_injected, strerror(errno));
      if (errno == ENXIO) {
        // See https://man7.org/linux/man-pages/man3/errno.3.html
        m_console->warn("Fatal error, no device");
        has_fatal_error = true;
      }
    } else {
      m_console->warn("pcap -unable to inject packet size:{} ret:{} err:[{}]",
                      packet_size, len_injected,
                      pcap_geterr(m_pcap_handles[card_index].tx));
    }
    m_tx_stats.count_tx_dropped_packets++;
    if (has_fatal_error) {
      if (m_fatal_error_cb != nullptr) {
        m_fatal_error_cb(errno);
      }
    }
    return false;
  }
  return true;
}

void WBTxRx::rx_register_callback(WBTxRx::OUTPUT_DATA_CALLBACK cb) {
  m_output_cb = std::move(cb);
}

void WBTxRx::rx_register_stream_handler(
    std::shared_ptr<StreamRxHandler> handler) {
  assert(handler);
  m_rx_handlers[handler->radio_port] = handler;
}

void WBTxRx::rx_unregister_stream_handler(uint8_t radio_port) {
  m_rx_handlers.erase(radio_port);
}

void WBTxRx::loop_receive_packets() {
  if (m_options.receive_thread_max_realtime) {
    SchedulingHelper::set_thread_params_max_realtime(
        "WBTxRx::loop_receive_packets");
  }
  std::vector<int> packets_per_card{};
  packets_per_card.resize(m_wifi_cards.size());
  while (keep_receiving) {
    if (m_optional_dummy_link) {
      auto packet = m_optional_dummy_link->rx_radiotap();
      if (packet) {
        on_new_packet(0, packet->data(), packet->size());
      }
      continue;
    }
    const int timeoutMS =
        (int)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::seconds(1))
            .count();
    int rc =
        poll(m_receive_pollfds.data(), m_receive_pollfds.size(), timeoutMS);

    if (rc < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      m_console->warn("Poll error: {}", strerror(errno));
    }

    if (rc == 0) {
      // timeout expired
      if (m_options.advanced_debugging_rx) {
        m_console->debug("Timeout - no packet after 1 second");
      }
      recalculate_pollution_perc();
      continue;
    }
    // TODO Optimization: If rc>1 we have data on more than one wifi card. It
    // would be better to alternating process a couple of packets from card 1,
    // then card 2 or similar
    for (int i = 0; rc > 0 && i < m_receive_pollfds.size(); i++) {
      // m_console->debug("Got data on {}",i);
      if (m_receive_pollfds[i].revents & (POLLERR | POLLNVAL)) {
        if (keep_receiving) {
          // we should only get errors here if the card is disconnected
          m_n_receiver_errors++;
          m_card_is_disconnected[i] = true;
          // limit logging here
          const auto elapsed =
              std::chrono::steady_clock::now() - m_last_receiver_error_log;
          if (elapsed > std::chrono::seconds(1)) {
            m_console->warn("{} receiver errors on pcap fd {} (wlan {})",
                            m_n_receiver_errors, i, m_wifi_cards[i].name);
            m_last_receiver_error_log = std::chrono::steady_clock::now();
          }
        } else {
          return;
        }
      }
      if (m_receive_pollfds[i].revents & POLLIN) {
        const auto n_packets = loop_iter_pcap(i);
        packets_per_card[i] = n_packets;
        rc -= 1;
      } else {
        packets_per_card[i] = 0;
      }
    }
    if (m_options.debug_multi_rx_packets_variance) {
      std::stringstream ss;
      ss << "Packets";
      for (int i = 0; i < packets_per_card.size(); i++) {
        ss << fmt::format(" Card{}:{}", i, packets_per_card[i]);
      }
      m_console->debug("{}", ss.str());
    }
    recalculate_pollution_perc();
  }
}

int WBTxRx::loop_iter_pcap(const int rx_index) {
  pcap_t* ppcap = m_pcap_handles[rx_index].rx;
  // loop while incoming queue is not empty
  int nPacketsPolledUntilQueueWasEmpty = 0;
  for (;;) {
    struct pcap_pkthdr hdr {};
    const uint8_t* pkt = pcap_next(ppcap, &hdr);
    if (pkt == nullptr) {
      if (m_options.advanced_latency_debugging_rx) {
        m_n_packets_polled_pcap.add(nPacketsPolledUntilQueueWasEmpty);
        if (m_n_packets_polled_pcap.get_delta_since_last_reset() >
            std::chrono::seconds(1)) {
          m_console->debug("m_n_packets_polled_pcap: {}",
                           m_n_packets_polled_pcap.getAvgReadable());
          m_n_packets_polled_pcap.reset();
        }
      }
      break;
    }
    if (m_options.advanced_latency_debugging_rx) {
      const auto delta = std::chrono::system_clock::now() -
                         MyTimeHelper::to_time_point_system_clock(hdr.ts);
      m_packet_host_latency.add(delta);
      if (m_packet_host_latency.get_delta_since_last_reset() >
          std::chrono::seconds(1)) {
        m_console->debug("packet latency {}",
                         m_packet_host_latency.getAvgReadable());
        m_packet_host_latency.reset();
      }
    }
    on_new_packet(rx_index, pkt, hdr.len);
    nPacketsPolledUntilQueueWasEmpty++;
  }
  return nPacketsPolledUntilQueueWasEmpty;
}

int WBTxRx::loop_iter_raw(const int rx_index) {
  // loop while incoming queue is not empty
  int nPacketsPolledUntilQueueWasEmpty = 0;
  for (;;) {
    auto buff = std::vector<uint8_t>(PCAP_MAX_PACKET_SIZE);
    // const int ret= read(0,buff.data(),buff.size());
    const int ret = recv(m_receive_pollfds[rx_index].fd, buff.data(),
                         buff.size(), MSG_DONTWAIT);
    if (ret <= 0) {
      if (m_options.advanced_latency_debugging_rx) {
        m_n_packets_polled_pcap.add(nPacketsPolledUntilQueueWasEmpty);
        if (m_n_packets_polled_pcap.get_delta_since_last_reset() >
            std::chrono::seconds(1)) {
          m_console->debug("m_n_packets_polled_pcap: {}",
                           m_n_packets_polled_pcap.getAvgReadable());
          m_n_packets_polled_pcap.reset();
        }
      }
      break;
    }
    on_new_packet(rx_index, buff.data(), ret);
    nPacketsPolledUntilQueueWasEmpty++;
  }
  return nPacketsPolledUntilQueueWasEmpty;
}

void WBTxRx::on_new_packet(const uint8_t wlan_idx, const uint8_t* pkt,
                           const int pkt_len) {
  if (m_options.log_all_received_packets) {
    m_console->debug("Got packet {} {}", wlan_idx, pkt_len);
  }
  const auto parsedPacket =
      radiotap::rx::process_received_radiotap_packet(pkt, pkt_len);
  if (parsedPacket == std::nullopt) {
    // Radiotap header malformed - should never happen
    if (m_options.advanced_debugging_rx) {
      m_console->warn("Discarding packet due to radiotap parsing error!");
    }
    return;
  }
  if (parsedPacket->radiotap_f_bad_fcs) {
    // Bad FCS - treat as not a usable packet
    if (m_options.advanced_debugging_rx) {
      m_console->debug("Discarding packet due to bad FCS!");
    }
    return;
  }
  // m_console->debug("{}",radiotap::util::radiotap_header_to_string(pkt,pkt_len));
  // m_console->debug("{}",radiotap::rx::parsed_radiotap_to_string(parsedPacket.value()));
  // m_per_card_calc[wlan_idx]->rf_aggregator.on_valid_openhd_packet(parsedPacket.value());
  const uint8_t* pkt_payload = parsedPacket->payload;
  const size_t pkt_payload_size = parsedPacket->payloadSize;
  m_rx_stats.count_p_any++;
  m_rx_stats.count_bytes_any += pkt_payload_size;
  m_rx_stats_per_card[wlan_idx].count_p_any++;
  if (wlan_idx == 0) {
    m_pollution_total_rx_packets++;
  }
  const auto& rx_iee80211_hdr_openhd =
      *((Ieee80211HeaderOpenHD*)parsedPacket->ieee80211Header);
  // m_console->debug(parsedPacket->ieee80211Header->header_as_string());
  if (!rx_iee80211_hdr_openhd.is_data_frame()) {
    if (m_options.advanced_debugging_rx) {
      // we only process data frames
      m_console->debug("Got packet that is not a data packet {}",
                       rx_iee80211_hdr_openhd.debug_control_field());
    }
    return;
  }
  // All these edge cases should NEVER happen if using a proper tx/rx setup and
  // the wifi driver isn't complete crap
  if (parsedPacket->payloadSize <= 0 ||
      parsedPacket->payloadSize > RAW_WIFI_FRAME_MAX_PAYLOAD_SIZE) {
    m_console->warn("Discarding packet due to no actual payload !");
    return;
  }
  // Generic packet validation end - now to the openhd specific validation(s)
  if (parsedPacket->payloadSize > RAW_WIFI_FRAME_MAX_PAYLOAD_SIZE) {
    m_console->warn("Discarding packet due to payload exceeding max {}",
                    (int)parsedPacket->payloadSize);
    return;
  }
  if (!rx_iee80211_hdr_openhd.has_valid_air_gnd_id()) {
    if (m_options.advanced_debugging_rx) {
      m_console->debug("Got packet that has not a valid unique id {}",
                       rx_iee80211_hdr_openhd.debug_unique_ids());
    }
    return;
  }
  const auto unique_air_gnd_id = rx_iee80211_hdr_openhd.get_valid_air_gnd_id();
  const auto unique_tx_id = m_options.use_gnd_identifier
                                ? OPENHD_IEEE80211_HEADER_UNIQUE_ID_GND
                                : OPENHD_IEEE80211_HEADER_UNIQUE_ID_AIR;
  const auto unique_rx_id = m_options.use_gnd_identifier
                                ? OPENHD_IEEE80211_HEADER_UNIQUE_ID_AIR
                                : OPENHD_IEEE80211_HEADER_UNIQUE_ID_GND;
  if (unique_air_gnd_id != unique_rx_id) {
    // Rare case - when multiple RX-es are used, we might get a packet we sent
    // on this air / gnd unit And on AR9271, there is a bug where the card
    // itself gives injected packets back to us
    if (unique_air_gnd_id == unique_tx_id) {
      // Packet (most likely) originated from this unit
      if (m_options.advanced_debugging_rx) {
        m_console->debug(
            "Got packet back on rx {} that was injected (bug or multi rx) {}",
            wlan_idx, rx_iee80211_hdr_openhd.debug_unique_ids());
      }
      if (wlan_idx == 0) {
        m_pollution_total_rx_packets--;
      }
    } else {
      if (m_options.advanced_debugging_rx) {
        m_console->debug("Got packet with invalid unique air gnd id {}",
                         rx_iee80211_hdr_openhd.debug_unique_ids());
      }
    }
    return;
  }
  if (!rx_iee80211_hdr_openhd.has_valid_radio_port()) {
    if (m_options.advanced_debugging_rx) {
      m_console->debug("Got packet that has not a valid radio port{}",
                       rx_iee80211_hdr_openhd.debug_radio_ports());
    }
    return;
  }
  const auto radio_port_raw = rx_iee80211_hdr_openhd.get_valid_radio_port();
  const RadioPort& radio_port = *(RadioPort*)&radio_port_raw;

  // m_console->debug("Packet enc:{} stream_idx:{}
  // nonce:{}",radio_port.encrypted,radio_port.multiplex_index,nonce);
  //  Quite likely an openhd packet (I'd say pretty much 100%) but not validated
  //  yet
  m_rx_stats.curr_n_likely_openhd_packets++;
  const auto nonce = rx_iee80211_hdr_openhd.get_nonce();
  if (radio_port.multiplex_index == STREAM_INDEX_SESSION_KEY_PACKETS) {
    process_session_stream_packet(wlan_idx, radio_port, parsedPacket,
                                  pkt_payload_size, nonce);
  } else {
    process_common_stream_packet(wlan_idx, radio_port, pkt, pkt_len,
                                 parsedPacket, pkt_payload, pkt_payload_size,
                                 nonce);
  }
}

void WBTxRx::process_session_stream_packet(
    const uint8_t wlan_idx, const RadioPort& radio_port,
    const std::optional<radiotap::rx::ParsedRxRadiotapPacket>& parsedPacket,
    const size_t pkt_payload_size, uint64_t nonce) {
  // encryption bit must always be set to off on session key packets, since
  // encryption serves no purpose here
  if (radio_port.encrypted) {
    if (m_options.advanced_debugging_rx) {
      m_console->warn(
          "Cannot be session key packet - encryption flag set to true");
    }
    return;
  }

  if (pkt_payload_size != sizeof(SessionKeyPacket)) {
    if (m_options.advanced_debugging_rx) {
      m_console->warn("Cannot be session key packet - size mismatch {}",
                      pkt_payload_size);
    }
    return;
  }
  const SessionKeyPacket& sessionKeyPacket =
      *((SessionKeyPacket*)parsedPacket->payload);
  const auto decrypt_res = m_decryptor->onNewPacketSessionKeyData(
      sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
  if (decrypt_res == wb::Decryptor::SESSION_VALID_NEW ||
      decrypt_res == wb::Decryptor::SESSION_VALID_NOT_NEW) {
    if (wlan_idx == 0) {  // Pollution is calculated only on card0
      m_pollution_openhd_rx_packets++;
    }
    m_likely_wrong_encryption_valid_session_keys++;
    auto& seq_nr_for_card = m_per_card_calc.at(wlan_idx)->seq_nr;
    seq_nr_for_card.on_new_sequence_number(nonce);
    m_rx_stats_per_card.at(wlan_idx).curr_packet_loss =
        seq_nr_for_card.get_current_loss_percent();
  } else {
    m_likely_wrong_encryption_invalid_session_keys++;
  }

  // A lot of invalid session keys and no valid session keys hint at a bind
  // phrase mismatch
  const auto elapsed_likely_wrong_key =
      std::chrono::steady_clock::now() - m_likely_wrong_encryption_last_check;
  if (elapsed_likely_wrong_key > std::chrono::seconds(5)) {
    // No valid session key(s) and at least one invalid session key
    if (m_likely_wrong_encryption_valid_session_keys == 0 &&
        m_likely_wrong_encryption_invalid_session_keys >= 1) {
      m_rx_stats.likely_mismatching_encryption_key = true;
    } else {
      m_rx_stats.likely_mismatching_encryption_key = false;
    }
    m_likely_wrong_encryption_last_check = std::chrono::steady_clock::now();
    m_likely_wrong_encryption_valid_session_keys = 0;
    m_likely_wrong_encryption_invalid_session_keys = 0;
  }

  if (decrypt_res == wb::Decryptor::SESSION_VALID_NEW) {
    m_console->debug("Initializing new session.");
    m_rx_stats.n_received_valid_session_key_packets++;
    for (const auto& handler : m_rx_handlers) {
      if (auto opt_cb_session = handler.second->cb_session) {
        opt_cb_session();
      }
    }
  }
}

void WBTxRx::process_common_stream_packet(
    const uint8_t wlan_idx, const WBTxRx::RadioPort& radio_port,
    const uint8_t* pkt, const int pkt_len,
    const std::optional<radiotap::rx::ParsedRxRadiotapPacket> parsedPacket,
    const uint8_t* pkt_payload, const size_t pkt_payload_size,
    const uint64_t nonce) {
  // the payload needs to include at least one byte of actual payload and the
  // encryption suffix
  static constexpr auto MIN_PACKET_PAYLOAD_SIZE =
      1 + crypto_aead_chacha20poly1305_ABYTES;
  if (pkt_payload_size < MIN_PACKET_PAYLOAD_SIZE) {
    if (m_options.advanced_debugging_rx) {
      m_console->debug("Got packet with payload of {} (min:{})",
                       pkt_payload_size, MIN_PACKET_PAYLOAD_SIZE);
    }
    return;
  }

  const bool valid = process_received_data_packet(
      wlan_idx, radio_port.multiplex_index, radio_port.encrypted, nonce,
      pkt_payload, pkt_payload_size);
  if (valid) {
    if (m_options.rx_radiotap_debug_level == 1 ||
        m_options.rx_radiotap_debug_level == 4) {
      m_console->debug("{}",
                       radiotap::util::radiotap_header_to_string(pkt, pkt_len));
    }

    if (m_options.rx_radiotap_debug_level == 2 ||
        m_options.rx_radiotap_debug_level == 4) {
      m_console->debug(
          "{}", radiotap::rx::parsed_radiotap_to_string(parsedPacket.value()));
    }

    m_rx_stats.count_p_valid++;
    m_rx_stats.count_bytes_valid += pkt_payload_size;

    // We only use known "good" packets for those stats.
    auto& this_wifi_card_stats = m_rx_stats_per_card.at(wlan_idx);
    PerCardCalculators& this_wifi_card_calc = *m_per_card_calc.at(wlan_idx);
    if (m_options.debug_rssi >= 2) {
      m_console->debug(
          "{}", radiotap::rx::all_rf_path_to_string(parsedPacket->rf_paths));
    }

    this_wifi_card_calc.rf_aggregator.on_valid_openhd_packet(
        parsedPacket.value());
    const auto& rf_indicators =
        this_wifi_card_calc.rf_aggregator.get_current().adapter;
    this_wifi_card_stats.curr_rssi_dbm = rf_indicators.rssi_dbm;
    this_wifi_card_stats.curr_noise_dbm = rf_indicators.noise_dbm;
    this_wifi_card_stats.curr_signal_quality_perc =
        rf_indicators.card_signal_quality_perc;
    if (m_options.rx_radiotap_debug_level == 3 ||
        m_options.rx_radiotap_debug_level == 4) {
      this_wifi_card_calc.rf_aggregator.debug_every_one_second();
    }

    this_wifi_card_stats.count_p_valid++;
    if (wlan_idx == 0) {
      m_pollution_openhd_rx_packets++;
    }
    {
      // Same for iee80211 seq nr
      // uint16_t iee_seq_nr=parsedPacket->ieee80211Header->getSequenceNumber();
      // m_seq_nr_helper_iee80211.on_new_sequence_number(iee_seq_nr);
      // m_console->debug("IEE SEQ NR PACKET LOSS
      // {}",m_seq_nr_helper_iee80211.get_current_loss_percent());
    }
    switch_tx_card_if_needed();
  }
}

void WBTxRx::switch_tx_card_if_needed() {
  if (m_wifi_cards.size() > 1 && m_options.enable_auto_switch_tx_card) {
    const auto elapsed =
        std::chrono::steady_clock::now() - m_last_highest_rssi_adjustment_tp;
    if (elapsed >= HIGHEST_RSSI_ADJUSTMENT_INTERVAL) {
      m_last_highest_rssi_adjustment_tp = std::chrono::steady_clock::now();
      // NEW: Instead of dealing with RSSI issues, we just take whatever card
      // received the most amount of packets
      std::vector<int64_t> per_card_packet_delta;
      per_card_packet_delta.reserve(m_wifi_cards.size());
      for (int i = 0; i < m_wifi_cards.size(); i++) {
        RxStatsPerCard& this_card_stats = m_rx_stats_per_card.at(i);
        // Check if this card is behaving "okay", aka receiving packets at the
        // time
        const auto delta_valid_packets =
            this_card_stats.count_p_valid -
            m_active_tx_card_data[i].last_received_n_valid_packets;
        m_active_tx_card_data[i].last_received_n_valid_packets =
            this_card_stats.count_p_valid;
        per_card_packet_delta.push_back(delta_valid_packets);
      }
      int64_t best_packet_delta = per_card_packet_delta[m_curr_tx_card];
      int idx_card_highest_packet_delta = m_curr_tx_card;
      for (int i = 0; i < m_wifi_cards.size(); i++) {
        // Switch card if there is a difference of more than X packets
        if (per_card_packet_delta[i] > best_packet_delta + 50) {
          best_packet_delta = per_card_packet_delta[i];
          idx_card_highest_packet_delta = i;
        }
      }
      if (m_curr_tx_card != idx_card_highest_packet_delta) {
        m_console->debug("Switching to card {}", idx_card_highest_packet_delta);
        m_curr_tx_card = idx_card_highest_packet_delta;
      }
    }
  }
}

bool WBTxRx::process_received_data_packet(int wlan_idx, uint8_t stream_index,
                                          bool encrypted, const uint64_t nonce,
                                          const uint8_t* payload_and_enc_suffix,
                                          int payload_and_enc_suffix_size) {
  std::shared_ptr<std::vector<uint8_t>> decrypted =
      std::make_shared<std::vector<uint8_t>>(
          payload_and_enc_suffix_size - crypto_aead_chacha20poly1305_ABYTES);
  // after that, we have the encrypted data (and the encryption suffix)
  const uint8_t* encrypted_data_with_suffix = payload_and_enc_suffix;
  const auto encrypted_data_with_suffix_len = payload_and_enc_suffix_size;

  const auto before_decrypt = std::chrono::steady_clock::now();
  bool res;
  if (encrypted) {
    res =
        m_decryptor->decrypt(nonce, encrypted_data_with_suffix,
                             encrypted_data_with_suffix_len, decrypted->data());
  } else {
    res = m_decryptor->authenticate(nonce, encrypted_data_with_suffix,
                                    encrypted_data_with_suffix_len,
                                    decrypted->data());
  }

  if (res) {
    if (m_options.log_all_received_validated_packets) {
      m_console->debug(
          "Got valid packet nonce:{} wlan_idx:{} encrypted:{} stream_index:{} "
          "size:{}",
          nonce, wlan_idx, encrypted, stream_index,
          payload_and_enc_suffix_size);
    }
    if (m_options.debug_decrypt_time) {
      m_packet_decrypt_time.add(std::chrono::steady_clock::now() -
                                before_decrypt);
      if (m_packet_decrypt_time.get_delta_since_last_reset() >
          std::chrono::seconds(2)) {
        m_console->debug("Decrypt/Validate: {}",
                         m_packet_decrypt_time.getAvgReadable());
        m_packet_decrypt_time.reset();
      }
    }
    on_valid_data_packet(nonce, wlan_idx, stream_index, decrypted->data(),
                         decrypted->size());
    // Calculate sequence number stats per card
    auto& seq_nr_for_card = m_per_card_calc.at(wlan_idx)->seq_nr;
    seq_nr_for_card.on_new_sequence_number(nonce);
    m_rx_stats_per_card.at(wlan_idx).curr_packet_loss =
        seq_nr_for_card.get_current_loss_percent();
    // Update the main loss to whichever card reports the lowest loss
    int lowest_loss = INT32_MAX;
    for (auto& per_card_calc : m_per_card_calc) {
      auto& card_loss = per_card_calc->seq_nr;
      const auto loss = card_loss.get_current_loss_percent();
      if (loss < 0) {
        continue;
      }
      if (loss < lowest_loss) {
        lowest_loss = loss;
      }
    }
    if (lowest_loss == INT32_MAX) {
      lowest_loss = -1;
    }
    m_rx_stats.curr_lowest_packet_loss = lowest_loss;
    return true;
  }
  // m_console->debug("Got non-wb packet {}",radio_port);
  return false;
}

void WBTxRx::on_valid_data_packet(uint64_t nonce, int wlan_index,
                                  const uint8_t stream_index,
                                  const uint8_t* data, const int data_len) {
  if (m_output_cb != nullptr) {
    m_output_cb(nonce, wlan_index, stream_index, data, data_len);
  }
  // find a consumer for data of this radio port
  auto handler = m_rx_handlers.find(stream_index);
  if (handler != m_rx_handlers.end()) {
    StreamRxHandler& rxHandler = *handler->second;
    rxHandler.cb_packet(nonce, wlan_index, data, data_len);
  }
}

void WBTxRx::start_receiving() {
  keep_receiving = true;
  m_receive_thread =
      std::make_unique<std::thread>(&WBTxRx::loop_receive_packets, this);
}

void WBTxRx::stop_receiving() {
  keep_receiving = false;
  if (m_receive_thread != nullptr) {
    if (m_receive_thread->joinable()) {
      m_receive_thread->join();
    }
    m_receive_thread = nullptr;
  }
}

void WBTxRx::announce_session_key_if_needed() {
  const auto cur_ts = std::chrono::steady_clock::now();
  if (cur_ts >= m_session_key_next_announce_ts) {
    // Announce session key
    send_session_key();
    m_session_key_next_announce_ts =
        cur_ts + m_options.session_key_packet_interval;
  }
}

void WBTxRx::send_session_key() {
  RadiotapHeaderTx tmp_radiotap_header =
      m_session_key_radiotap_header->thread_safe_get();
  Ieee80211HeaderOpenHD tmp_tx_hdr{};
  const auto unique_tx_id = m_options.use_gnd_identifier
                                ? OPENHD_IEEE80211_HEADER_UNIQUE_ID_GND
                                : OPENHD_IEEE80211_HEADER_UNIQUE_ID_AIR;
  tmp_tx_hdr.write_unique_id_src_dst(unique_tx_id);
  RadioPort radioPort{false, STREAM_INDEX_SESSION_KEY_PACKETS};
  tmp_tx_hdr.write_radio_port_src_dst(radio_port_to_uint8_t(radioPort));
  tmp_tx_hdr.write_ieee80211_seq_nr(m_ieee80211_seq++);
  tmp_tx_hdr.write_nonce(m_nonce++);
  auto packet = RadiotapHelper::create_radiotap_wifi_packet(
      tmp_radiotap_header, *(Ieee80211HeaderRaw*)&tmp_tx_hdr,
      (uint8_t*)&m_tx_sess_key_packet, sizeof(SessionKeyPacket));
  const int packet_size = (int)packet.size();
  // NOTE: Session key is always sent via card 0 since otherwise we might pick
  // up the session key intended for the ground unit from the air unit !
  const bool success = inject_radiotap_packet(0, packet.data(), packet_size);
  if (success) {
    // These bytes only count as "including overhead"
    m_tx_stats.n_injected_bytes_including_overhead += packet_size;
    m_tx_stats.n_injected_packets++;
  }
}

WBTxRx::TxStats WBTxRx::get_tx_stats() {
  m_tx_stats.curr_bits_per_second_excluding_overhead =
      m_tx_bitrate_calculator_excluding_overhead.get_last_or_recalculate(
          m_tx_stats.n_injected_bytes_excluding_overhead);
  m_tx_stats.curr_bits_per_second_including_overhead =
      m_tx_bitrate_calculator_including_overhead.get_last_or_recalculate(
          m_tx_stats.n_injected_bytes_including_overhead);
  m_tx_stats.curr_packets_per_second =
      m_tx_packets_per_second_calculator.get_last_or_recalculate(
          m_tx_stats.n_injected_packets);
  return m_tx_stats;
}

WBTxRx::RxStats WBTxRx::get_rx_stats() {
  WBTxRx::RxStats ret = m_rx_stats;
  ret.curr_bits_per_second =
      m_rx_bitrate_calculator.get_last_or_recalculate(ret.count_bytes_valid);
  ret.curr_packets_per_second =
      m_rx_packets_per_second_calculator.get_last_or_recalculate(
          ret.count_p_valid);
  return ret;
}

WBTxRx::RxStatsPerCard WBTxRx::get_rx_stats_for_card(int card_index) {
  return m_rx_stats_per_card.at(card_index);
}

void WBTxRx::rx_reset_stats() {
  m_rx_stats = RxStats{};
  m_rx_bitrate_calculator.reset();
  m_rx_packets_per_second_calculator.reset();
  for (int i = 0; i < m_wifi_cards.size(); i++) {
    RxStatsPerCard card_stats{};
    card_stats.card_index = i;
    m_rx_stats_per_card[i] = card_stats;
    m_per_card_calc.at(i)->reset_all();
  }
}

int WBTxRx::get_curr_active_tx_card_idx() { return m_curr_tx_card; }

void WBTxRx::set_passive_mode(bool passive) {
  m_disable_all_transmissions = passive;
}

bool WBTxRx::get_card_has_disconnected(int card_idx) {
  if (card_idx >= m_wifi_cards.size()) {
    return true;
  }
  return m_card_is_disconnected[card_idx];
}

void WBTxRx::tx_reset_stats() {
  m_tx_stats = TxStats{};
  m_tx_packets_per_second_calculator.reset();
  m_tx_bitrate_calculator_excluding_overhead.reset();
  m_tx_bitrate_calculator_including_overhead.reset();
}

void WBTxRx::recalculate_pollution_perc() {
  const auto elapsed =
      std::chrono::steady_clock::now() - m_last_pollution_calculation;
  if (elapsed <= std::chrono::seconds(1)) {
    return;
  }
  m_last_pollution_calculation = std::chrono::steady_clock::now();
  const auto non_openhd_packets =
      m_pollution_total_rx_packets - m_pollution_openhd_rx_packets;
  if (m_pollution_total_rx_packets > 0) {
    double perc_non_openhd_packets = (double)non_openhd_packets /
                                     (double)m_pollution_total_rx_packets *
                                     100.0;
    // m_console->debug("Link pollution: {}%
    // [{}:{}]",perc_non_openhd_packets,non_openhd_packets,m_pollution_total_rx_packets);
    m_rx_stats.curr_link_pollution_perc = std::ceil(perc_non_openhd_packets);
    // curr_link_pollution_perc=std::ceil();
  } else {
    m_rx_stats.curr_link_pollution_perc = 0;
  }
  const int elapsed_ms = static_cast<int>(
      std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count());
  m_rx_stats.curr_n_foreign_packets_pps =
      (int)non_openhd_packets * 1000 / elapsed_ms;
  m_pollution_total_rx_packets = 0;
  m_pollution_openhd_rx_packets = 0;
}

std::string WBTxRx::tx_stats_to_string(const WBTxRx::TxStats& data) {
  return fmt::format(
      "TxStats[injected packets:{} bytes:{} tx error hint/dropped:{}:{} pps:{} "
      "bps:{}:{}]",
      data.n_injected_packets, data.n_injected_bytes_including_overhead,
      data.count_tx_injections_error_hint, data.count_tx_dropped_packets,
      data.curr_packets_per_second,
      StringHelper::bitrate_readable(
          data.curr_bits_per_second_excluding_overhead),
      StringHelper::bitrate_readable(
          data.curr_bits_per_second_including_overhead));
}
std::string WBTxRx::rx_stats_to_string(const WBTxRx::RxStats& data) {
  return fmt::format(
      "RxStats[packets any:{} session:{} valid:{} Loss:{}% pps:{} bps:{} "
      "foreign:{}%/{}pps likely_key_mismatch:{}]",
      data.count_p_any, data.n_received_valid_session_key_packets,
      data.count_p_valid, data.curr_lowest_packet_loss,
      data.curr_packets_per_second, data.curr_bits_per_second,
      data.curr_link_pollution_perc, data.curr_n_foreign_packets_pps,
      data.likely_mismatching_encryption_key);
}
std::string WBTxRx::rx_stats_per_card_to_string(
    const WBTxRx::RxStatsPerCard& data) {
  return fmt::format(
      "RxStatsCard{}[packets total:{} valid:{}, loss:{}% rssi:{}dBm noise:{}dBm "
      "quality:{}%]",
      data.card_index, data.count_p_any, data.count_p_valid, data.curr_packet_loss,
      static_cast<int>(data.curr_rssi_dbm), static_cast<int>(data.curr_noise_dbm),
      static_cast<int>(data.curr_signal_quality_perc));
}
std::string WBTxRx::options_to_string(
    const std::vector<std::string>& wifi_cards,
    const WBTxRx::Options& options) {
  return fmt::format(
      "Id:{} Cards:{} Key:{} ", options.use_gnd_identifier ? "Ground" : "Air",
      StringHelper::string_vec_as_string(wifi_cards),
      options.secure_keypair.has_value() ? "Custom" : "Default(openhd)");
}

RadiotapRxRfAggregator::CardKeyRfIndicators WBTxRx::get_rx_rf_stats_for_card(
    int card_index) {
  return m_per_card_calc.at(card_index)->rf_aggregator.get_current();
}

std::shared_ptr<DummyLink> WBTxRx::get_dummy_link() {
  return m_optional_dummy_link;
}

void WBTxRx::PerCardCalculators::reset_all() {
  seq_nr.reset();
  rf_aggregator.reset();
}
