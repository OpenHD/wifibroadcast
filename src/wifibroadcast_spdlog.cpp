//
// Created by consti10 on 13.08.23.
//

#include "wifibroadcast_spdlog.h"
#include <spdlog/spdlog.h>

std::shared_ptr<spdlog::logger> wifibroadcast::log::create_or_get(
    const std::string& logger_name) {
  static std::mutex logger_mutex2{};
  std::lock_guard<std::mutex> guard(logger_mutex2);
  auto ret = spdlog::get(logger_name);
  if (ret == nullptr) {
    auto created = spdlog::stdout_color_mt(logger_name);
    created->set_level(spdlog::level::debug);
    assert(created);
    return created;
  }
  return ret;
}

std::shared_ptr<spdlog::logger> wifibroadcast::log::get_default() {
  return create_or_get("wifibroadcast");
}
