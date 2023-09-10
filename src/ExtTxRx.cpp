//
// Created by consti10 on 27.06.23.
//

#include "ExtTxRx.h"

#include <string>
#include <utility>

#include "SchedulingHelper.hpp"
#include "pcap_helper.hpp"
#include "raw_socket_helper.hpp"

int ExtTxRx::open_udp_rx(const int port)
{
  int sockfd;
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  sockaddr_in servaddr, cliaddr;
  memset(&servaddr, 0, sizeof(servaddr));

  servaddr.sin_family = AF_INET;  // IPv4
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(port);

  if (bind(sockfd, reinterpret_cast<const sockaddr*>(&servaddr), sizeof(servaddr)) < 0)
  {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  return sockfd;
}


ExtTxRx::ExtTxRx(std::vector<UdpWifiCard> wifi_cards1, Options options1)
    : m_options(options1),
      m_wifi_cards(std::move(wifi_cards1)),
      m_tx_radiotap_header(RadiotapHeader::UserSelectableParams{})
{
  assert(!m_wifi_cards.empty());
  m_console=wifibroadcast::log::create_or_get("ExtTxRx");
  m_console->debug("{}", options_to_string(get_wifi_card_names(),m_options));
  // Common error - not run as root
  if(!SchedulingHelper::check_root()){
    std::cerr<<"wifibroadcast needs root"<<std::endl;
    m_console->warn("wifibroadcast needs root");
    assert(false);
  }
  m_receive_pollfds.resize(m_wifi_cards.size());
  m_active_tx_card_data.resize(m_wifi_cards.size());
  for(int i=0;i<m_wifi_cards.size();i++){
    RxStatsPerCard tmp{};
    tmp.card_index=i;
    m_rx_stats_per_card.push_back(tmp);
  }
  m_card_is_disconnected.resize(m_wifi_cards.size());

  for(int i=0;i<m_wifi_cards.size();i++){
    auto tmp=std::make_shared<PerCardCalculators>();
    tmp->seq_nr.set_store_and_debug_gaps(i,m_options.debug_packet_gaps);
    tmp->card_rssi.set_debug_invalid_rssi(m_options.debug_rssi>=1,0);
    tmp->antenna1_rssi.set_debug_invalid_rssi(m_options.debug_rssi>=1,1);
    tmp->antenna2_rssi.set_debug_invalid_rssi(m_options.debug_rssi>=1,2);
    tmp->signal_quality.set_debug_invalid_signal_quality(m_options.debug_rssi>=1);
    m_per_card_calc.push_back(tmp);
    m_card_is_disconnected[i]=false;
  }

  for(int i=0;i<m_wifi_cards.size();i++){
    auto wifi_card=m_wifi_cards[i];
    UdpTxRx pcapTxRx{};
    // RX part - using pcap
    pcapTxRx.sockfd = open_udp_rx(wifi_card.port);
    auto rx_pollfd = pcapTxRx.sockfd;
    m_receive_pollfds[i].fd = rx_pollfd;
    m_receive_pollfds[i].events = POLLIN;

    m_pcap_handles.push_back(pcapTxRx);
  }

  wb::KeyPairTxRx keypair{};
  if(m_options.secure_keypair.has_value()){
    keypair= m_options.secure_keypair.value();
  }else{
    keypair=wb::generate_keypair_from_bind_phrase();
  }
  m_encryptor=std::make_unique<wb::Encryptor>(keypair.get_tx_key(!m_options.use_gnd_identifier));
  m_decryptor=std::make_unique<wb::Decryptor>(keypair.get_rx_key(!m_options.use_gnd_identifier));
  m_encryptor->makeNewSessionKey(m_tx_sess_key_packet.sessionKeyNonce,m_tx_sess_key_packet.sessionKeyData);
  // next session key in delta ms if packets are being fed
  m_session_key_next_announce_ts = std::chrono::steady_clock::now();
  // Per libsodium documentation, the first nonce should be chosen randomly
  // This selects a random nonce in 32-bit range - we therefore have still 32-bit increasing indexes left, which means tx can run indefinitely
  m_nonce=randombytes_random();
}

ExtTxRx::~ExtTxRx() {
  stop_receiving();
  for(auto& fd: m_receive_pollfds){
    close(fd.fd);
  }
  //for(auto& pcapTxRx:m_pcap_handles){
  //  if(pcapTxRx.rx==pcapTxRx.tx){
  //    pcap_close(pcapTxRx.rx);
  //    pcapTxRx.rx= nullptr;
  //    pcapTxRx.tx= nullptr;
  //  }else{
  //    if(pcapTxRx.rx!= nullptr){
  //      pcap_close(pcapTxRx.rx);
  //    }
  //    if(pcapTxRx.tx!= nullptr){
  //      pcap_close(pcapTxRx.tx);
  //    }
  //    if(pcapTxRx.tx_sockfd!=-1){
  //      close(pcapTxRx.tx_sockfd);
  //    }
  //  }
  //  //pcap_close(pcapTxRx.rx);
  //  //pcap_close(pcapTxRx.tx);
  //}
}

void ExtTxRx::tx_inject_packet(const uint8_t stream_index,const uint8_t* data, int data_len,bool encrypt) { }

void ExtTxRx::rx_register_callback(ExtTxRx::OUTPUT_DATA_CALLBACK cb) {
  m_output_cb=std::move(cb);
}

void ExtTxRx::rx_register_stream_handler(std::shared_ptr<StreamRxHandler> handler) {
  assert(handler);
  m_rx_handlers[handler->radio_port]=handler;
}

void ExtTxRx::rx_unregister_stream_handler(uint8_t radio_port) {
  m_rx_handlers.erase(radio_port);
}

void ExtTxRx::loop_receive_packets() {
  if(m_options.receive_thread_max_realtime){
    SchedulingHelper::setThreadParamsMaxRealtime();
  }
  std::vector<int> packets_per_card{};
  packets_per_card.resize(m_wifi_cards.size());
  while (keep_receiving){
    const int timeoutMS = (int) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(1)).count();
    int rc = poll(m_receive_pollfds.data(), m_receive_pollfds.size(), timeoutMS);

    if (rc < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      m_console->warn("Poll error: {}", strerror(errno));
    }

    if (rc == 0) {
      // timeout expired
      if(m_options.advanced_debugging_rx){
        m_console->debug("Timeout - no packet after 1 second");
      }
      continue;
    }
    // TODO Optimization: If rc>1 we have data on more than one wifi card. It would be better to alternating process a couple of packets from card 1, then card 2 or similar
    for (int i = 0; rc > 0 && i < m_receive_pollfds.size(); i++) {
      //m_console->debug("Got data on {}",i);
      if (m_receive_pollfds[i].revents & (POLLERR | POLLNVAL)) {
        if(keep_receiving){
          // we should only get errors here if the card is disconnected
          m_n_receiver_errors++;
          m_card_is_disconnected[i]=true;
          // limit logging here
          const auto elapsed=std::chrono::steady_clock::now()-m_last_receiver_error_log;
          if(elapsed>std::chrono::seconds(1)){
            m_console->warn("{} receiver errors on pcap fd {} (wlan {})",m_n_receiver_errors,i,std::to_string(m_wifi_cards[i].port));
            m_last_receiver_error_log=std::chrono::steady_clock::now();
          }
        }else{
          return;
        }
      }
      if (m_receive_pollfds[i].revents & POLLIN) {
        const auto n_packets = loop_iter_raw(i);
        packets_per_card[i]=n_packets;
        rc -= 1;
      }else{
        packets_per_card[i]=0;
      }
    }
    if(m_options.debug_multi_rx_packets_variance){
      std::stringstream ss;
      ss<<"Packets";
      for(int i=0;i<packets_per_card.size();i++){
        ss<<fmt::format(" Card{}:{}",i,packets_per_card[i]);
      }
      m_console->debug("{}",ss.str());
    }
  }
}

int ExtTxRx::loop_iter_raw(const int rx_index) {
  // loop while incoming queue is not empty
  int nPacketsPolledUntilQueueWasEmpty = 0;
  for (;;) {
    auto buff=std::vector<uint8_t>(PCAP_MAX_PACKET_SIZE);
    //const int ret= read(0,buff.data(),buff.size());
    const int ret= recv(m_receive_pollfds[rx_index].fd,buff.data(),buff.size(),MSG_DONTWAIT);
    if (ret<=0) {
      if(m_options.advanced_latency_debugging_rx){
        m_n_packets_polled_pcap.add(nPacketsPolledUntilQueueWasEmpty);
        if(m_n_packets_polled_pcap.get_delta_since_last_reset()>std::chrono::seconds(1)){
          m_console->debug("m_n_packets_polled_pcap: {}",m_n_packets_polled_pcap.getAvgReadable());
          m_n_packets_polled_pcap.reset();
        }
      }
      break;
    }
    on_new_packet(rx_index,buff.data(),ret);
    nPacketsPolledUntilQueueWasEmpty++;
  }
  return nPacketsPolledUntilQueueWasEmpty;
}

void ExtTxRx::on_new_packet(const uint8_t wlan_idx,const uint8_t *pkt,const int pkt_len)
{
  if(m_options.log_all_received_packets)
  {
    m_console->debug("Got packet {} {}",wlan_idx,pkt_len);
  }

  const auto& rx_iee80211_hdr_openhd = *((Ieee80211HeaderOpenHD*)pkt);

  const uint8_t *pkt_payload = pkt+24;
  const size_t pkt_payload_size = pkt_len-28;

  m_rx_stats.count_p_any++;
  m_rx_stats.count_bytes_any+=pkt_payload_size;
  m_rx_stats_per_card[wlan_idx].count_p_any++;

  if(wlan_idx==0)
  {
    m_pollution_total_rx_packets++;
  }

  //m_console->debug(parsedPacket->ieee80211Header->header_as_string());
  if (!rx_iee80211_hdr_openhd.is_data_frame())
  {
    if(m_options.advanced_debugging_rx)
    {
      // we only process data frames
      m_console->debug("Got packet that is not a data packet {}",rx_iee80211_hdr_openhd.debug_control_field());
    }
    return;
  }

  // All these edge cases should NEVER happen if using a proper tx/rx setup and the wifi driver isn't complete crap
  if (pkt_payload_size <= 0)
  {
    m_console->warn("Discarding packet due to no actual payload !");
    return;
  }

  // Generic packet validation end - now to the openhd specific validation(s)
  if (pkt_payload_size > RAW_WIFI_FRAME_MAX_PAYLOAD_SIZE)
  {
    m_console->warn("Discarding packet due to payload exceeding max {}",
                    (int)pkt_payload_size);
    return;
  }

  if(!rx_iee80211_hdr_openhd.has_valid_air_gnd_id())
  {
    if(m_options.advanced_debugging_rx)
    {
      m_console->debug("Got packet that has not a valid unique id {}",rx_iee80211_hdr_openhd.debug_unique_ids());
    }
    return;
  }

  const auto unique_air_gnd_id=rx_iee80211_hdr_openhd.get_valid_air_gnd_id();
  const auto unique_tx_id= m_options.use_gnd_identifier ? OPENHD_IEEE80211_HEADER_UNIQUE_ID_GND : OPENHD_IEEE80211_HEADER_UNIQUE_ID_AIR;
  const auto unique_rx_id= m_options.use_gnd_identifier ? OPENHD_IEEE80211_HEADER_UNIQUE_ID_AIR : OPENHD_IEEE80211_HEADER_UNIQUE_ID_GND;

  if(unique_air_gnd_id!=unique_rx_id)
  {
    // Rare case - when multiple RX-es are used, we might get a packet we sent on this air / gnd unit
    // And on AR9271, there is a bug where the card itself gives injected packets back to us
    if(unique_air_gnd_id==unique_tx_id)
    {
      // Packet (most likely) originated from this unit
      if(m_options.advanced_debugging_rx)
      {
        m_console->debug("Got packet back on rx {} that was injected (bug or multi rx) {}",wlan_idx,rx_iee80211_hdr_openhd.debug_unique_ids());
      }

      if(wlan_idx==0)
      {
        m_pollution_total_rx_packets--;
      }
    }
    else
    {
      if(m_options.advanced_debugging_rx)
      {
        m_console->debug("Got packet with invalid unique air gnd id {}",rx_iee80211_hdr_openhd.debug_unique_ids());
      }
    }

    return ;
  }

  if(!rx_iee80211_hdr_openhd.has_valid_radio_port())
  {
    if(m_options.advanced_debugging_rx)
    {
      m_console->debug("Got packet that has not a valid radio port{}",rx_iee80211_hdr_openhd.debug_radio_ports());
    }

    return;
  }

  const auto radio_port_raw=rx_iee80211_hdr_openhd.get_valid_radio_port();
  const RadioPort& radio_port=*(RadioPort*)&radio_port_raw;
  const auto nonce=rx_iee80211_hdr_openhd.get_nonce();

  //m_console->debug("Packet enc:{} stream_idx:{} nonce:{}",radio_port.encrypted,radio_port.multiplex_index,nonce);
  // Quite likely an openhd packet (I'd say pretty much 100%) but not validated yet
  m_rx_stats.curr_n_likely_openhd_packets++;

  if(radio_port.multiplex_index== STREAM_INDEX_SESSION_KEY_PACKETS)
  {
    // encryption bit must always be set to off on session key packets, since encryption serves no purpose here
    if(radio_port.encrypted)
    {
      if(m_options.advanced_debugging_rx)
      {
        m_console->warn("Cannot be session key packet - encryption flag set to true");
      }

      return;
    }

    int sesPktSize = sizeof(SessionKeyPacket);

    if (pkt_payload_size != sesPktSize)
    {
      if(m_options.advanced_debugging_rx)
      {
        m_console->warn("Cannot be session key packet - size mismatch {}",pkt_payload_size);
      }

      return;
    }
    // Issue when using multiple wifi card(s) on ground - by example:
    // When we inject data on card 1, it is intended for the "air unit" - however,
    // card 2 on the ground likely picks up such a packet and if we were not to ignore it, we'd get the session key
    // TODO make it better -
    // for now, ignore session key packets not from card 0
    // Not needed anymore, due to unique air / ground id's
    /*if(wlan_idx!=0){
      return ;
    }*/
    SessionKeyPacket& sessionKeyPacket = *((SessionKeyPacket*)pkt_payload);
    const auto decrypt_res=m_decryptor->onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);

    if(decrypt_res==wb::Decryptor::SESSION_VALID_NEW || decrypt_res==wb::Decryptor::SESSION_VALID_NOT_NEW)
    {
      if(wlan_idx==0)
      { // Pollution is calculated only on card0
        m_pollution_openhd_rx_packets++;
        recalculate_pollution_perc();
      }

      m_likely_wrong_encryption_valid_session_keys++;
    }
    else
    {
      m_likely_wrong_encryption_invalid_session_keys++;
    }
    // A lot of invalid session keys and no valid session keys hint at a bind phrase mismatch
    const auto elapsed_likely_wrong_key=std::chrono::steady_clock::now()-m_likely_wrong_encryption_last_check;
    if(elapsed_likely_wrong_key>std::chrono::seconds(5))
    {
      // No valid session key(s) and at least one invalid session key
      if( m_likely_wrong_encryption_valid_session_keys==0 &&
          m_likely_wrong_encryption_invalid_session_keys>=1)
      {
        m_rx_stats.likely_mismatching_encryption_key= true;
      }
      else
      {
        m_rx_stats.likely_mismatching_encryption_key= false;
      }

      m_likely_wrong_encryption_last_check=std::chrono::steady_clock::now();
      m_likely_wrong_encryption_valid_session_keys=0;
      m_likely_wrong_encryption_invalid_session_keys=0;
    }

    if (decrypt_res==wb::Decryptor::SESSION_VALID_NEW)
    {
      m_console->debug("Initializing new session.");
      m_rx_stats.n_received_valid_session_key_packets++;
      for(auto& handler:m_rx_handlers)
      {
        auto opt_cb_session=handler.second->cb_session;
        if(opt_cb_session)
        {
          opt_cb_session();
        }
      }
    }
  }
  else
  {
    // the payload needs to include at least one byte of actual payload and the encryption suffix
    static constexpr auto MIN_PACKET_PAYLOAD_SIZE=1+crypto_aead_chacha20poly1305_ABYTES;
    if(pkt_payload_size<MIN_PACKET_PAYLOAD_SIZE)
    {
      if(m_options.advanced_debugging_rx)
      {
        m_console->debug("Got packet with payload of {} (min:{})",pkt_payload_size,MIN_PACKET_PAYLOAD_SIZE);
      }
      return ;
    }

    const bool valid=process_received_data_packet(wlan_idx,radio_port.multiplex_index,radio_port.encrypted,nonce,pkt_payload,pkt_payload_size);

    if(valid)
    {
      m_rx_stats.count_p_valid++;
      m_rx_stats.count_bytes_valid+=pkt_payload_size;
      // We only use known "good" packets for those stats.
      auto &this_wifi_card_stats = m_rx_stats_per_card.at(wlan_idx);
      PerCardCalculators& this_wifi_card_calc= *m_per_card_calc.at(wlan_idx);
      if(m_options.debug_rssi>=2)
      {
        //m_console->debug("{}",all_rssi_to_string(parsedPacket->allAntennaValues));
      }

      // assumes driver gives 1st and 2nd antenna as 2nd and 3rd value
      //if(parsedPacket->allAntennaValues.size()>=1)
      //{
      //  const auto rssi=parsedPacket->allAntennaValues[0].rssi;
      //  auto opt_minmaxavg= this_wifi_card_calc.card_rssi.add_and_recalculate_if_needed(rssi);
      //  if(opt_minmaxavg.has_value())
      //  {
      //    if(m_options.debug_rssi>=1)
      //    {
      //      m_console->debug("Card{}:{}",wlan_idx, RSSIAccumulator::min_max_avg_to_string(opt_minmaxavg.value(), false));
      //    }
      //  }
      //}

      //if(parsedPacket->allAntennaValues.size()>=2)
      //{
      //  const auto rssi=parsedPacket->allAntennaValues[1].rssi;
      //  auto opt_minmaxavg= this_wifi_card_calc.antenna1_rssi.add_and_recalculate_if_needed(rssi);
      //  if(opt_minmaxavg.has_value()){
      //    this_wifi_card_stats.antenna1_dbm=opt_minmaxavg.value().avg;
      //    if(m_options.debug_rssi>=1){
      //      m_console->debug("Card{} Antenna{}:{}",wlan_idx,0, RSSIAccumulator::min_max_avg_to_string(opt_minmaxavg.value(), false));
      //    }
      //  }
      //}

      //if(parsedPacket->allAntennaValues.size()>=3)
      //{
      //  const auto rssi=parsedPacket->allAntennaValues[2].rssi;
      //  auto opt_minmaxavg= this_wifi_card_calc.antenna2_rssi.add_and_recalculate_if_needed(rssi);
      //  if(opt_minmaxavg.has_value()){
      //    this_wifi_card_stats.antenna2_dbm=opt_minmaxavg.value().avg;
      //    if(m_options.debug_rssi>=1){
      //      m_console->debug("Card{} Antenna{}:{}",wlan_idx,1, RSSIAccumulator::min_max_avg_to_string(opt_minmaxavg.value(), false));
      //    }
      //  }
      //}

      this_wifi_card_stats.count_p_valid++;

      //if(parsedPacket->mcs_index.has_value())
      //{
      //  m_rx_stats.last_received_packet_mcs_index=parsedPacket->mcs_index.value();
      //}

      //if(parsedPacket->channel_width.has_value())
      //{
      //  m_rx_stats.last_received_packet_channel_width=parsedPacket->channel_width.value();
      //}

      //if(parsedPacket->signal_quality.has_value())
      //{
      //  this_wifi_card_calc.signal_quality.add_signal_quality(parsedPacket->signal_quality.value());
      //  this_wifi_card_stats.signal_quality=this_wifi_card_calc.signal_quality.get_current_signal_quality();
      //}

      if(wlan_idx==0)
      {
        m_pollution_openhd_rx_packets++;
        recalculate_pollution_perc();
      }
    }
  }
}

bool ExtTxRx::process_received_data_packet(int wlan_idx,uint8_t stream_index,bool encrypted,const uint64_t nonce,const uint8_t *payload_and_enc_suffix,int payload_and_enc_suffix_size) {
  std::shared_ptr<std::vector<uint8_t>> decrypted=std::make_shared<std::vector<uint8_t>>(payload_and_enc_suffix_size-crypto_aead_chacha20poly1305_ABYTES);
  // after that, we have the encrypted data (and the encryption suffix)
  const uint8_t* encrypted_data_with_suffix=payload_and_enc_suffix;
  const auto encrypted_data_with_suffix_len = payload_and_enc_suffix_size;
  m_decryptor->set_encryption_enabled(encrypted);
  const auto before_decrypt=std::chrono::steady_clock::now();
  const auto res= m_decryptor->authenticate_and_decrypt(nonce, encrypted_data_with_suffix, encrypted_data_with_suffix_len,decrypted->data());
  if(res){
    if(m_options.log_all_received_validated_packets){
      m_console->debug("Got valid packet nonce:{} wlan_idx:{} encrypted:{} stream_index:{} size:{}",nonce,wlan_idx,encrypted,stream_index,payload_and_enc_suffix_size);
    }
    if(m_options.debug_decrypt_time){
      m_packet_decrypt_time.add(std::chrono::steady_clock::now()-before_decrypt);
      if(m_packet_decrypt_time.get_delta_since_last_reset()>std::chrono::seconds(2)){
        m_console->debug("Decrypt/Validate: {}",m_packet_decrypt_time.getAvgReadable());
        m_packet_decrypt_time.reset();
      }
    }
    on_valid_packet(nonce,wlan_idx,stream_index,decrypted->data(),decrypted->size());
    // Calculate sequence number stats per card
    auto& seq_nr_for_card=m_per_card_calc.at(wlan_idx)->seq_nr;
    seq_nr_for_card.on_new_sequence_number(nonce);
    m_rx_stats_per_card.at(wlan_idx).curr_packet_loss=seq_nr_for_card.get_current_loss_percent();
    // Update the main loss to whichever card reports the lowest loss
    int lowest_loss=INT32_MAX;
    for(auto& per_card_calc: m_per_card_calc){
      auto& card_loss=per_card_calc->seq_nr;
      const auto loss=card_loss.get_current_loss_percent();
      if(loss<0){
        continue ;
      }
      if(loss<lowest_loss){
        lowest_loss=loss;
      }
    }
    if(lowest_loss==INT32_MAX){
      lowest_loss=-1;
    }
    m_rx_stats.curr_lowest_packet_loss=lowest_loss;
    return true;
  }
  //m_console->debug("Got non-wb packet {}",radio_port);
  return false;
}

void ExtTxRx::on_valid_packet(uint64_t nonce,int wlan_index,const uint8_t stream_index,const uint8_t *data, const int data_len) {
  if(m_output_cb!= nullptr){
    m_output_cb(nonce,wlan_index,stream_index,data,data_len);
  }
  // find a consumer for data of this radio port
  auto handler=m_rx_handlers.find(stream_index);
  if(handler!=m_rx_handlers.end()){
    StreamRxHandler& rxHandler=*handler->second;
    rxHandler.cb_packet(nonce,wlan_index,data,data_len);
  }
}

void ExtTxRx::start_receiving() {
  keep_receiving= true;
  m_receive_thread=std::make_unique<std::thread>([this](){
    loop_receive_packets();
  });
}

void ExtTxRx::stop_receiving() {
  keep_receiving= false;
  if(m_receive_thread!= nullptr){
    if(m_receive_thread->joinable()){
      m_receive_thread->join();
    }
    m_receive_thread= nullptr;
  }
}

void ExtTxRx::tx_update_mcs_index(uint8_t mcs_index) { }
void ExtTxRx::tx_update_channel_width(int width_mhz) { }
void ExtTxRx::tx_update_stbc(int stbc) { }
void ExtTxRx::tx_update_guard_interval(bool short_gi) { }
void ExtTxRx::tx_update_ldpc(bool ldpc) { }
void ExtTxRx::tx_update_set_flag_tx_no_ack(bool enable) { }
void ExtTxRx::tx_threadsafe_update_radiotap_header(const RadiotapHeader::UserSelectableParams &params) { }

ExtTxRx::TxStats ExtTxRx::get_tx_stats() {
    m_tx_stats.curr_bits_per_second_excluding_overhead=
      m_tx_bitrate_calculator_excluding_overhead.get_last_or_recalculate(m_tx_stats.n_injected_bytes_excluding_overhead);
    m_tx_stats.curr_bits_per_second_including_overhead=
        m_tx_bitrate_calculator_including_overhead.get_last_or_recalculate(m_tx_stats.n_injected_bytes_including_overhead);
    m_tx_stats.curr_packets_per_second=m_tx_packets_per_second_calculator.get_last_or_recalculate(m_tx_stats.n_injected_packets);
    return m_tx_stats;
}

ExtTxRx::RxStats ExtTxRx::get_rx_stats() {
  ExtTxRx::RxStats ret=m_rx_stats;
  ret.curr_big_gaps_counter=0;
  ret.curr_bits_per_second=m_rx_bitrate_calculator.get_last_or_recalculate(ret.count_bytes_valid);
  ret.curr_packets_per_second=m_rx_packets_per_second_calculator.get_last_or_recalculate(ret.count_p_valid);
  return ret;
}

ExtTxRx::RxStatsPerCard ExtTxRx::get_rx_stats_for_card(int card_index) {
  return m_rx_stats_per_card.at(card_index);
}

void ExtTxRx::rx_reset_stats() {
  m_rx_stats=RxStats{};
  m_rx_bitrate_calculator.reset();
  m_rx_packets_per_second_calculator.reset();
  for(int i=0;i<m_wifi_cards.size();i++){
    RxStatsPerCard card_stats{};
    card_stats.card_index=i;
    m_rx_stats_per_card[i]=card_stats;
    m_per_card_calc.at(i)->reset_all();
  }
}

int ExtTxRx::get_curr_active_tx_card_idx() {
  return m_curr_tx_card;
}

void ExtTxRx::set_passive_mode(bool passive) {
  m_disable_all_transmissions=passive;
}

bool ExtTxRx::get_card_has_disconnected(int card_idx) {
  if(card_idx>=m_wifi_cards.size()){
    return true;
  }
  return m_card_is_disconnected[card_idx];
}

void ExtTxRx::tx_reset_stats() {
  m_tx_stats=TxStats{};
  m_tx_packets_per_second_calculator.reset();
  m_tx_bitrate_calculator_excluding_overhead.reset();
  m_tx_bitrate_calculator_including_overhead.reset();
}

void ExtTxRx::recalculate_pollution_perc() {
  const auto elapsed=std::chrono::steady_clock::now()-m_last_pollution_calculation;
  if(elapsed<=std::chrono::seconds(1)){
    return ;
  }
  if(m_pollution_total_rx_packets<=0 || m_pollution_openhd_rx_packets<=0 ){
    return ;
  }
  m_last_pollution_calculation=std::chrono::steady_clock::now();
  const auto non_openhd_packets=m_pollution_total_rx_packets-m_pollution_openhd_rx_packets;
  if(m_pollution_total_rx_packets>0){
    double perc_non_openhd_packets=(double)non_openhd_packets/(double)m_pollution_total_rx_packets*100.0;
    //m_console->debug("Link pollution: {}% [{}:{}]",perc_non_openhd_packets,non_openhd_packets,m_pollution_total_rx_packets);
    m_rx_stats.curr_link_pollution_perc=std::ceil(perc_non_openhd_packets);
    //curr_link_pollution_perc=std::ceil()
  }
  m_pollution_total_rx_packets=0;
  m_pollution_openhd_rx_packets=0;
}

std::string ExtTxRx::tx_stats_to_string(const ExtTxRx::TxStats& data) {
  return fmt::format("TxStats[injected packets:{} bytes:{} tx error hint/dropped:{}:{} pps:{} bps:{}:{}]",
                     data.n_injected_packets,data.n_injected_bytes_including_overhead,
                     data.count_tx_injections_error_hint,data.count_tx_dropped_packets,
                     data.curr_packets_per_second,
                     StringHelper::bitrate_readable(data.curr_bits_per_second_excluding_overhead),
                     StringHelper::bitrate_readable(data.curr_bits_per_second_including_overhead));
}
std::string ExtTxRx::rx_stats_to_string(const ExtTxRx::RxStats& data) {
  return fmt::format("RxStats[packets any:{} session:{} valid:{} Loss:{}% pps:{} bps:{} foreign:{}% likely_key_mismatch:{}]",
                     data.count_p_any,data.n_received_valid_session_key_packets,data.count_p_valid,
                     data.curr_lowest_packet_loss,data.curr_packets_per_second,data.curr_bits_per_second,
                     data.curr_link_pollution_perc,data.likely_mismatching_encryption_key);
}
std::string ExtTxRx::rx_stats_per_card_to_string(
    const ExtTxRx::RxStatsPerCard& data) {
  return fmt::format("Card{}[packets total:{} valid:{}, loss:{}% RSSI:{}/{},{}]",data.card_index,
                     data.count_p_any,data.count_p_valid,data.curr_packet_loss,
                     (int)data.card_dbm,data.antenna1_dbm,data.antenna2_dbm);
}
std::string ExtTxRx::options_to_string(const std::vector<std::string>& wifi_cards,const ExtTxRx::Options& options) {
  return fmt::format("Id:{} Cards:{} Key:{} ",options.use_gnd_identifier ? "Ground":"Air",StringHelper::string_vec_as_string(wifi_cards),
                     options.secure_keypair.has_value() ? "Custom" : "Default(openhd)");
}

void ExtTxRx::PerCardCalculators::reset_all() {
    seq_nr.reset();
    card_rssi.reset();
    antenna1_rssi.reset();
    antenna2_rssi.reset();
    signal_quality.reset();
}
