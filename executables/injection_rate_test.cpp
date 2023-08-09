//
// Created by consti10 on 25.07.23.
//

#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/WBTxRx.h"
#include "../src/wifibroadcast-spdlog.h"
#include "DummyStreamGenerator.hpp"
#include "RandomBufferPot.hpp"
#include "Rates.hpp"

// Utility / benchmark executable to find the maximum injection rate possible for the card given a MCS index
// It works by increasing the injection rate (injected bitrate / packets per second) until there are so called
// "TX ERRORS", aka the driver tx packet queue is running full


//static constexpr auto TEST_PACKETS_SIZE=1024;
// Video in openhd is fragmented into packets of this size - and in general, is by far the biggest bitrate producer
// Therefore, we use this packet size during testing - Note that a smaller packet size reduces bitrate due to more overhead.
static constexpr auto TEST_PACKETS_SIZE=1440;

struct TestResult {
  int mcs_index;
  int pass_pps_set;
  int pass_pps_measured;
  int pass_bps_measured;
  int fail_pps_set;
  int fail_pps_measured;
  int fail_bps_measured;
};

static TestResult increase_pps_until_fail(std::shared_ptr<WBTxRx> txrx,const int mcs,const int pps_start,const int pps_increment){
  auto m_console=wifibroadcast::log::create_or_get("main");
  m_console->info("Testing MCS {}", mcs);
  txrx->tx_update_mcs_index(mcs);

  int last_passed_pps_set=0;
  int last_passed_pps_measured=0;
  int last_passed_bps_measured=0;
  // 7*1000 packets per second are a lot (way over 50MBit/s) but we can reach it in ideal scenarios
  // have a limit here though to not run infinitely
  for(int pps=pps_start;pps<7*1000;pps+=pps_increment) {
    auto tx_cb=[&txrx](const uint8_t* data,int data_len){
      txrx->tx_inject_packet(10,data,data_len);
    };
    auto stream_generator=std::make_unique<DummyStreamGenerator>(tx_cb,TEST_PACKETS_SIZE);
    stream_generator->set_target_pps(pps);
    std::this_thread::sleep_for(std::chrono::seconds(1));  // give driver time to empty queue
    txrx->tx_reset_stats();
    stream_generator->start();
    m_console->info("Testing MCS {} with {} pps", mcs, pps);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    const auto txstats = txrx->get_tx_stats();
    if (txstats.count_tx_injections_error_hint > 0 || stream_generator->n_times_cannot_keep_up_wanted_pps>10 ) {
      m_console->info("TX errors {} n_times_cannot_keep_up_wanted_pps {}",txstats.count_tx_injections_error_hint,stream_generator->n_times_cannot_keep_up_wanted_pps);
      // TX errors
      m_console->info("Got TX errors at set:{} actual: {} pps {} pps", pps,txstats.curr_packets_per_second,txstats.curr_packets_per_second);
      TestResult result{};
      result.mcs_index=mcs;
      result.pass_pps_set=last_passed_pps_set;
      result.pass_pps_measured=last_passed_pps_measured;
      result.pass_bps_measured=last_passed_bps_measured;
      result.fail_pps_set=pps;
      result.fail_pps_measured=txstats.curr_packets_per_second;
      result.fail_bps_measured=txstats.curr_bits_per_second_excluding_overhead;
      return result;
    }else{
      m_console->info("MCS {} passed {} - measured {} {}", mcs,pps,txstats.curr_packets_per_second,StringHelper::bitrate_readable(txstats.curr_bits_per_second_excluding_overhead));
      m_console->info("{}",WBTxRx::tx_stats_to_string(txstats));
      last_passed_pps_set=pps;
      last_passed_pps_measured=txstats.curr_packets_per_second;
      last_passed_bps_measured=txstats.curr_bits_per_second_excluding_overhead;
    }
  }
  //assert(false);
  return {mcs,0,0,0,0,0};
}

static void calculate_max_possible_pps_quick(std::shared_ptr<WBTxRx> txrx,const int mcs){
  auto m_console=wifibroadcast::log::create_or_get("main");
  m_console->info("Testing MCS {}", mcs);
  txrx->tx_update_mcs_index(mcs);
  auto tx_cb=[&txrx](const uint8_t* data,int data_len){
    txrx->tx_inject_packet(10,data,data_len);
  };
  auto stream_generator=std::make_unique<DummyStreamGenerator>(tx_cb,TEST_PACKETS_SIZE);
  stream_generator->set_target_pps(10*1000);
  std::this_thread::sleep_for(std::chrono::seconds(1));  // give driver time to empty queue
  txrx->tx_reset_stats();
  stream_generator->start();
  std::this_thread::sleep_for(std::chrono::seconds(4));
  auto stats=txrx->get_tx_stats();
  m_console->info("MCS {} max {} {}",mcs,stats.curr_packets_per_second,StringHelper::bitrate_readable(stats.curr_bits_per_second_excluding_overhead));
}

static std::string validate_specific_rate(std::shared_ptr<WBTxRx> txrx,const int mcs,const int rate_kbits){
  auto m_console=wifibroadcast::log::create_or_get("main");
  const auto rate_bps=(rate_kbits*1000)+10; // add a bit more to actually hit the target
  const auto pps=rate_bps / (TEST_PACKETS_SIZE*8);
  m_console->info("Validating {} - {}", mcs,pps);
  txrx->tx_update_mcs_index(mcs);
  auto tx_cb=[&txrx](const uint8_t* data,int data_len){
    txrx->tx_inject_packet(10,data,data_len);
  };
  auto stream_generator=std::make_unique<DummyStreamGenerator>(tx_cb,TEST_PACKETS_SIZE);
  stream_generator->set_target_pps(pps);
  std::this_thread::sleep_for(std::chrono::seconds(1));  // give driver time to empty queue
  txrx->tx_reset_stats();
  stream_generator->start();
  std::this_thread::sleep_for(std::chrono::seconds(10));
  const auto txstats = txrx->get_tx_stats();
  std::stringstream ss;
  if(txstats.count_tx_injections_error_hint>0 || stream_generator->n_times_cannot_keep_up_wanted_pps>10){
    ss<<fmt::format("MCS {} didn't pass {}/{} measured {}-{}\n",mcs,
                      pps,StringHelper::bitrate_readable(rate_bps),
                    txstats.curr_packets_per_second,StringHelper::bitrate_readable(txstats.curr_bits_per_second_excluding_overhead));
    ss<<fmt::format("{}",WBTxRx::tx_stats_to_string(txstats));
  }else{
    ss<<fmt::format("MCS {} passed {}/{} measured {}-{}\n",mcs,
                      pps,StringHelper::bitrate_readable(rate_bps),
                    txstats.curr_packets_per_second,StringHelper::bitrate_readable(txstats.curr_bits_per_second_excluding_overhead));
    //ss<<fmt::format("{}",WBTxRx::tx_stats_to_string(txstats));
  }
  m_console->info(ss.str());
  return ss.str();
}
static void validate_rtl8812au_rates(std::shared_ptr<WBTxRx> txrx,const bool is_40mhz){
  txrx->tx_update_channel_width(is_40mhz ? 40 : 20);
  std::stringstream log;
  for(int mcs=0;mcs<12;mcs++){
    const auto rate=wifibroadcast::get_practical_rate_5G(mcs);
    const auto rate_kbits=(is_40mhz ? rate.rate_40mhz_kbits : rate.rate_20mhz_kbits);
    const auto res=validate_specific_rate(txrx,mcs,rate_kbits);
    log<<res<<"\n";
  }
  wifibroadcast::log::get_default()->debug("\n{}",log.str());
}


static void print_test_results_rough(const std::vector<TestResult>& test_results){
  auto m_console=wifibroadcast::log::create_or_get("main");
  for(const auto& result: test_results){
    m_console->debug("MCS {} PASSED: {}-{}-{} FAILED {}-{}-{}",
                     result.mcs_index,
                     result.pass_pps_set,result.pass_pps_measured,StringHelper::bitrate_readable(result.pass_bps_measured),
                     result.fail_pps_set,result.fail_pps_measured,StringHelper::bitrate_readable(result.fail_bps_measured));
  }
}
static void print_test_results_and_theoretical(const std::vector<TestResult>& test_results,bool is_40mhz){
  auto m_console=wifibroadcast::log::create_or_get("main");
  for(const auto& result: test_results){
    const auto theoretical=wifibroadcast::get_theoretical_rate_5G(result.mcs_index);
    const int rate_kbits=is_40mhz ? theoretical.rate_40mhz_kbits : theoretical.rate_20mhz_kbits;
    m_console->debug("MCS {} PASSED {}--{}",result.mcs_index,
                     StringHelper::bitrate_readable(result.pass_bps_measured),
                     StringHelper::bitrate_readable(rate_kbits*1000));
  }
}

static std::vector<TestResult> all_mcs_increase_pps_until_fail(std::shared_ptr<WBTxRx> txrx,const int pps_increment,const int max_mcs=12){
  assert(max_mcs>=0);
  assert(max_mcs<=32);
  std::vector<TestResult> ret;
  auto m_console=wifibroadcast::log::create_or_get("main");
  // Since we use increasing MCS, start where the last measurement failed to speed up testing
  int pps_start=500;
  for(int mcs=0;mcs< max_mcs;mcs++) {
    // at MCS8 we loop around regarding rate
    if(mcs % 8 ==0){
      pps_start=500;
    }
    if(pps_start<=0){
      m_console->warn("Didn't pass a prev. rate");
      pps_start=500;
    }
    auto res = increase_pps_until_fail(txrx,mcs, pps_start, pps_increment);
    print_test_results_rough({res});
    // start where the last mcs successfully passed
    pps_start = res.pass_pps_set;
    ret.push_back(res);
    /*auto res_rough_fine= increase_pps_until_fail_fine_adjust(txrx,mcs,pps_start,400);
    auto rough=res_rough_fine.rough;
    auto fine=res_rough_fine.fine;
    pps_start=rough.pass_pps_set;
    ret.push_back(fine);*/
  }
  return ret;
}

void long_test(std::shared_ptr<WBTxRx> txrx,bool use_40mhz){
  auto m_console=wifibroadcast::log::create_or_get("main");
  const int freq_w=use_40mhz ? 40 : 20;
  m_console->info("Long test {}",freq_w);
  txrx->tx_update_channel_width(freq_w);
  const int mcs_max=12;
  const auto res_first= all_mcs_increase_pps_until_fail(txrx, 50,mcs_max);
  const auto res_second= all_mcs_increase_pps_until_fail(txrx, 50,mcs_max);
  const auto res_third= all_mcs_increase_pps_until_fail(txrx, 50,mcs_max);
  m_console->info("First run:");
  print_test_results_rough(res_first);
  m_console->info("Second run:");
  print_test_results_rough(res_second);
  m_console->info("Third run:");
  print_test_results_rough(res_third);
  m_console->info("---------------------------");
  m_console->info("First run:");
  print_test_results_and_theoretical(res_first, use_40mhz);
  m_console->info("Second run:");
  print_test_results_and_theoretical(res_second, use_40mhz);
  m_console->info("Third run:");
  print_test_results_and_theoretical(res_third, use_40mhz);
  for(int i=0;i<res_first.size();i++){
    m_console->info("MCS {} possible {}--{}--{}",res_first.at(i).mcs_index,
                    StringHelper::bitrate_readable(res_first.at(i).pass_bps_measured),
                    StringHelper::bitrate_readable(res_second.at(i).pass_bps_measured),
                    StringHelper::bitrate_readable(res_third.at(i).pass_bps_measured));
  }
}

void test_rates_and_print_results(std::shared_ptr<WBTxRx> txrx,bool use_40mhz){
  const int freq_w=use_40mhz ? 40 : 20;
  txrx->tx_update_channel_width(freq_w);
  const auto res_20mhz= all_mcs_increase_pps_until_fail(txrx, 20);
  print_test_results_rough(res_20mhz);
  print_test_results_and_theoretical(res_20mhz, false);
}

int main(int argc, char *const *argv) {
  std::string card="wlxac9e17596103";
  int opt;
  while ((opt = getopt(argc, argv, "w:agd")) != -1) {
    switch (opt) {
      case 'w':
        card = optarg;
        break;
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "injection rate test %s [-w wifi card to use]\n",
                argv[0]);
        exit(1);
    }
  }
  std::cout<<"Running on card "<<card<<"\n";

  // Create the Tx-RX
  std::vector<WBTxRx::WifiCard> cards;
  WBTxRx::WifiCard tmp_card{card,1};
  cards.push_back(tmp_card);
  WBTxRx::Options options_txrx{};
  options_txrx.rtl8812au_rssi_fixup= true;
  //options_txrx.set_direction= false;
  options_txrx.log_all_received_validated_packets= false;

  std::shared_ptr<WBTxRx> txrx=std::make_shared<WBTxRx>(cards,options_txrx);
  // No idea if and what effect stbc and ldpc have on the rate, but openhd enables them if possible by default
  // since they greatly increase range / resiliency
  txrx->tx_update_stbc(true);
  txrx->tx_update_ldpc(true);
  // short GI interval gives slightly higher rates, but also decreases resiliency
  txrx->tx_update_guard_interval(false);

  txrx->start_receiving();

  auto m_console=wifibroadcast::log::create_or_get("main");
  std::vector<TestResult> m_test_results;

  WBTxRx::OUTPUT_DATA_CALLBACK cb=[](uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len){
    //std::string message((const char*)data,data_len);
    //fmt::print("Got packet[{}]\n",message);
  };
  txrx->rx_register_callback(cb);

  //long_test(txrx, false);

  //test_rates_and_print_results(txrx, false);
  //test_rates_and_print_results(txrx, true);

  validate_rtl8812au_rates(txrx, false);

  /*const auto res_40mhz= all_mcs_increase_pps_until_fail(txrx);
  print_test_results_rough(res_40mhz);
  m_console->info("20Mhz:");
  print_test_results_rough(res_20mhz);
  m_console->info("40Mhz:");
  print_test_results_rough(res_40mhz);*/
}