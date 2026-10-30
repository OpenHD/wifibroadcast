#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>

#include "devourer/RxLoopWorker.h"

using wifibroadcast::devourer_transport::RxLoopWorker;
using namespace std::chrono_literals;

void require(bool ok, const char* message) {
  if (!ok) throw std::runtime_error(message);
}

int main() {
  RxLoopWorker worker;
  // Reproduce a driver that clears a stale stop when its RX entry is delayed.
  // The first StopRxLoop happens before that clear; the second must stop it.
  std::promise<void> entering_driver;
  auto entering = entering_driver.get_future();
  std::atomic_bool stopped{false};
  std::atomic_int stops{0};
  worker.start([&] {
    entering_driver.set_value();
    while (stops.load() == 0) std::this_thread::yield();
    stopped = false;  // IRadio clears the stale stop on StartRxLoop entry.
    while (stops.load() < 2 || !stopped.load()) std::this_thread::yield();
  });
  require(entering.wait_for(2s) == std::future_status::ready, "worker did not start");
  worker.stop_and_join([&] {
    stopped = true;
    ++stops;
  });
  require(stops >= 2, "lost stop was not reasserted");
  require(!worker.joinable(), "worker was not joined");

  // A fresh start must accept reception after a previous stop.
  for (int i = 0; i < 20; ++i) {
    std::promise<void> running;
    auto ready = running.get_future();
    stopped = false;
    worker.start([&] {
      running.set_value();
      while (!stopped.load()) std::this_thread::yield();
    });
    require(ready.wait_for(2s) == std::future_status::ready, "restart failed");
    worker.stop_and_join([&] { stopped = true; });
  }
  // Joining an already exited worker must not touch the device.
  std::promise<void> returned;
  auto done = returned.get_future();
  worker.start([&] { returned.set_value(); });
  require(done.wait_for(2s) == std::future_status::ready, "normal exit failed");
  worker.stop_and_join([] {});
  worker.stop_and_join([] { throw std::runtime_error("stopped twice"); });
  std::cout << "Devourer delayed RX entry, restart and shutdown passed\n";
}
