//
// Created by consti10 on 27.06.23.
//

#ifndef WIFIBROADCAST_TXRXINSTANCE_H
#define WIFIBROADCAST_TXRXINSTANCE_H

#include "RadiotapHeader.hpp"
#include "RawTransmitter.hpp"
#include <atomic>
#include "Encryption.hpp"

class TxRxInstance {
 public:
  explicit TxRxInstance(std::vector<std::string> wifi_cards);
  /**
   * Creates a valid injection packet which has the layout:
   * radiotap_header,ieee_80211_header,nonce (64 bit), encrypted data, encryption prefix
   * A increasing nonce is used for each packet, and is used for packet validation
   * on the receiving side.
   * @param radioPort used to multiplex more than one data stream
   * @param data the packet payload
   * @param data_len the packet payload length
   */
  void tx_inject_packet(uint8_t radioPort,const uint8_t* data,int data_len);

  // register a callback that is called every time a valid packet (for the given radio port) is received
  void rx_register_callback(const uint8_t radioPort,void* data){

  }

 private:
  void loop_receive_packets();
  int loop_iter(int rx_index);

  void on_new_packet(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt);
  void process_received_data_packet(uint8_t wlan_idx,const uint8_t *pkt_payload,size_t pkt_payload_size);

  void on_valid_packet(int wlan_index,uint8_t radio_port,std::shared_ptr<std::vector<uint8_t>> data);
 private:
  std::vector<std::string> m_wifi_cards;
  RadiotapHeader m_radiotap_header;
  Ieee80211Header mIeee80211Header;
  uint16_t m_ieee80211_seq = 0;
  uint64_t m_nonce=0;
  int m_highest_rssi_index=0;
 private:
  std::unique_ptr<Encryptor> m_encryptor;
  std::unique_ptr<Decryptor> m_decryptor;
 private:
  struct PcapTxRx{
    pcap_t *tx= nullptr;
    pcap_t *rx= nullptr;
  };
  std::vector<PcapTxRx> m_pcap_handles;
 private:
  bool keep_running= true;
  int m_n_receiver_errors=0;
  std::unique_ptr<std::thread> m_receive_thread;
  std::vector<pollfd> mReceiverFDs;
  std::chrono::steady_clock::time_point m_last_receiver_error_log=std::chrono::steady_clock::now();
};

#endif  // WIFIBROADCAST_TXRXINSTANCE_H
