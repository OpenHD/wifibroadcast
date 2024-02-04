//
// Created by consti10 on 04.02.24.
//

#include <cassert>
#include <iostream>
#include <memory>
#include <thread>

#include "../src/FunkyQueue.h"
#include "../src/HelperSources/Helper.hpp"
#include "../src/HelperSources/TimeHelper.hpp"

struct TestElement{
  std::chrono::steady_clock::time_point tp;
  std::shared_ptr<std::vector<uint8_t>> data;
};

static std::shared_ptr<TestElement> make_test_element(){
  auto ret=std::make_shared<TestElement>();
  ret->tp=std::chrono::steady_clock::now();
  ret->data=GenericHelper::createRandomDataBuffer2(1000);
  return ret;
}

int main(int argc, char *const *argv) {

  using FunkyQueueImpl=FunkyQueue<std::shared_ptr<TestElement>>;

  auto funky_queue=std::make_shared<FunkyQueueImpl>(2);

  auto packet1=make_test_element();
  auto packet2=make_test_element();
  auto packet3=make_test_element();
  auto packet4=make_test_element();

  assert(funky_queue->try_enqueue(packet1)== true);
  assert(funky_queue->try_enqueue(packet2)== true);
  assert(funky_queue->get_current_size()==2);
  assert(funky_queue->try_enqueue(packet3)== false);
  assert(funky_queue->get_current_size()==2);
  // Drops 2 currently enqueued packets
  assert(funky_queue->enqueue_or_clear_enqueue(packet3)== 2);
  assert(funky_queue->get_current_size()==1);

  auto tmp=funky_queue->wait_dequeue_timed(std::chrono::milliseconds(100));
  assert(tmp.has_value());
  assert(funky_queue->get_current_size()==0);

  const auto before_wait_no_data=std::chrono::steady_clock::now();
  auto tmp2=funky_queue->wait_dequeue_timed(std::chrono::milliseconds(100));
  assert(!tmp2.has_value());
  assert(std::chrono::steady_clock::now()-before_wait_no_data>=std::chrono::milliseconds(100));
  assert(funky_queue->get_current_size()==0);

  // Now queue is empty again
  int poll_thread_n_dequeued_packets=0;
  auto poll_thread=std::make_unique<std::thread>([&funky_queue,&poll_thread_n_dequeued_packets]{
    const auto begin=std::chrono::steady_clock::now();
    while (std::chrono::steady_clock::now()-begin<std::chrono::seconds(10)){
      auto tmp=funky_queue->wait_dequeue_timed(std::chrono::milliseconds(100));
      if(tmp.has_value()){
        auto& dequeued=*tmp.value();
        std::cout<<"Got element, delay:"<<MyTimeHelper::R(std::chrono::steady_clock::now()-dequeued.tp)<<std::endl;
        poll_thread_n_dequeued_packets++;
      }
    }
  });
  for(int i=0;i<10;i++){
    auto packet=make_test_element();
    assert(funky_queue->try_enqueue(packet)== true);
    // During this time the poll_thread should dequeue the packet
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  poll_thread->join();
  assert(funky_queue->get_current_size()==0);

  return 0;
}