#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <utility>

namespace wifibroadcast::devourer_transport {

// Start/stop are called by one control thread. IRadio::StartRxLoop clears a
// stale StopRxLoop request on entry, so a single stop before join is insufficient
// when the worker is still entering the driver.
class RxLoopWorker {
 public:
  bool joinable() const { return m_thread.joinable(); }
  bool stop_requested() const { return m_stop_requested.load(); }
  void request_stop() { m_stop_requested = true; }

  template <typename Loop>
  void start(Loop loop) {
    if (joinable()) return;
    m_stop_requested = false;
    m_exited = false;
    m_thread = std::thread([this, loop = std::move(loop)] {
      struct ExitSignal {
        RxLoopWorker& worker;
        ~ExitSignal() {
          std::lock_guard<std::mutex> lock(worker.m_mutex);
          worker.m_exited = true;
          worker.m_exited_cv.notify_all();
        }
      } exit{*this};
      if (!stop_requested()) loop();
    });
  }

  template <typename Stop>
  void stop_and_join(Stop stop) {
    request_stop();
    if (!joinable()) return;
    std::unique_lock<std::mutex> lock(m_mutex);
    while (!m_exited) {
      lock.unlock();
      stop();
      lock.lock();
      // Reassert cancellation if StartRxLoop cleared our first request.
      m_exited_cv.wait_for(lock, std::chrono::milliseconds(10),
                          [this] { return m_exited; });
    }
    lock.unlock();
    m_thread.join();
  }

 private:
  std::thread m_thread;
  std::atomic_bool m_stop_requested{true};
  std::mutex m_mutex;
  std::condition_variable m_exited_cv;
  bool m_exited = true;
};

}  // namespace wifibroadcast::devourer_transport
