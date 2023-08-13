//
// Created by consti10 on 05.12.20.
//

#ifndef WIFIBROADCAST_HELPER_H
#define WIFIBROADCAST_HELPER_H

#include <chrono>
#include <memory>
#include <cassert>
#include <cstring>
#include <algorithm>

#include "StringHelper.hpp"

// Generic "UINT16SeqNrHelper" code that does not depend on anything else other than the std libraries

namespace GenericHelper {
// fill buffer with random bytes
static void fillBufferWithRandomData(std::vector<uint8_t> &data) {
  const std::size_t size = data.size();
  for (std::size_t i = 0; i < size; i++) {
    data[i] = rand() % 255;
  }
}
template<std::size_t size>
static void fillBufferWithRandomData(std::array<uint8_t, size> &data) {
  for (std::size_t i = 0; i < size; i++) {
    data[i] = rand() % 255;
  }
}
// Create a buffer filled with random data of size sizeByes
static std::vector<uint8_t> createRandomDataBuffer(const ssize_t sizeBytes) {
  std::vector<uint8_t> buf(sizeBytes);
  fillBufferWithRandomData(buf);
  return buf;
}
// same as above but return shared ptr
static std::shared_ptr<std::vector<uint8_t>> createRandomDataBuffer2(const ssize_t sizeBytes) {
  return std::make_shared<std::vector<uint8_t>>(createRandomDataBuffer(sizeBytes));
}

// Create a random number in range  [min,...,max]
// https://stackoverflow.com/questions/12657962/how-do-i-generate-a-random-number-between-two-variables-that-i-have-stored
static ssize_t create_random_number_between(const ssize_t minSizeB, const ssize_t maxSizeB){
  const auto sizeBytes = rand() % (maxSizeB - minSizeB + 1) + minSizeB;
  assert(sizeBytes <= maxSizeB);
  assert(sizeBytes >= minSizeB);
  if (minSizeB == maxSizeB) {
    assert(sizeBytes == minSizeB);
  }
  return sizeBytes;
}

static std::vector<std::shared_ptr<std::vector<uint8_t>>> convert_vec_of_vec_to_shared(std::vector<std::vector<uint8_t>> in){
  std::vector<std::shared_ptr<std::vector<uint8_t>>> ret;
  for(auto data:in){
    std::shared_ptr<std::vector<uint8_t>> shared=std::make_shared<std::vector<uint8_t>>(data.begin(),data.end());
    ret.push_back(shared);
  }
  return ret;
}

// Create a buffer filled with random data where size is chosen Randomly between [minSizeB,...,maxSizeB]
static std::vector<uint8_t> createRandomDataBuffer(const ssize_t minSizeB, const ssize_t maxSizeB) {
  return createRandomDataBuffer(create_random_number_between(minSizeB,maxSizeB));
}
// create n random data buffers with size [minSizeB,...,maxSizeB]
static std::vector<std::vector<uint8_t>> createRandomDataBuffers(const std::size_t nBuffers,
                                                                 const std::size_t minSizeB,
                                                                 const std::size_t maxSizeB) {
  assert(minSizeB >= 0);
  std::vector<std::vector<uint8_t>> buffers;
  for (std::size_t i = 0; i < nBuffers; i++) {
    buffers.push_back(GenericHelper::createRandomDataBuffer(minSizeB, maxSizeB));
  }
  return buffers;
}
static std::vector<std::shared_ptr<std::vector<uint8_t>>> createRandomDataBuffers_shared(const std::size_t nBuffers,
                                                                 const std::size_t minSizeB,
                                                                 const std::size_t maxSizeB) {
  assert(minSizeB >= 0);
  std::vector<std::shared_ptr<std::vector<uint8_t>>> buffers;
  for (std::size_t i = 0; i < nBuffers; i++) {
    auto buf=GenericHelper::createRandomDataBuffer(minSizeB,maxSizeB);
    auto buf_shared=std::make_shared<std::vector<uint8_t>>(buf.begin(),buf.end());
    buffers.push_back(buf_shared);
  }
  return buffers;
}

template<std::size_t size>
static std::vector<std::array<uint8_t, size>> createRandomDataBuffers(const std::size_t nBuffers) {
  std::vector<std::array<uint8_t, size>> ret(nBuffers);
  for (auto &buff: ret) {
    GenericHelper::fillBufferWithRandomData(buff);
  }
  return ret;
}
static bool compareVectors(const std::vector<uint8_t> &sb, const std::vector<uint8_t> &rb) {
  if (sb.size() != rb.size()) {
    return false;
  }
  const int result = memcmp(sb.data(), rb.data(), sb.size());
  return result == 0;
}
static void assertVectorsEqual(const std::vector<uint8_t> &sb, const std::vector<uint8_t> &rb) {
  assert(sb.size() == rb.size());
  const int result = memcmp(sb.data(), rb.data(), sb.size());
  assert(result == 0);
}
static void assertVectorsOfVectorsEqual(const std::vector<std::vector<uint8_t>> &sbl, const std::vector<std::vector<uint8_t>> &rbl){
  for(int i=0;i<sbl.size();i++){
    const auto& sb=sbl[i];
    const auto& rb=rbl[i];
    assertVectorsEqual(sb,rb);
  }
}
template<std::size_t S>
static void assertArraysEqual(const std::array<uint8_t, S> &sb, const std::array<uint8_t, S> &rb) {
  const int result = memcmp(sb.data(), rb.data(), sb.size());
  if (result != 0) {
    //std::cout<<"Data1:"<<StringHelper::arrayAsString(sb)<<"\n";
    //std::cout<<"Data2:"<<StringHelper::arrayAsString(rb)<<"\n";
  }
  assert(result == 0);
}
/**
 * take @param nElements random elements from @param values, without duplicates
 */
static std::vector<unsigned int> takeNRandomElements(std::vector<unsigned int> values, const std::size_t nElements) {
  assert(nElements <= values.size());
  std::vector<unsigned int> ret;
  for (std::size_t i = 0; i < nElements; i++) {
    const auto idx = rand() % values.size();
    ret.push_back(values[idx]);
    values.erase(values.begin() + idx);
  }
  assert(ret.size() == nElements);
  std::sort(ret.begin(), ret.end());
  return ret;
}
static std::vector<unsigned int> createIndices(const std::size_t nIndices) {
  std::vector<unsigned int> ret(nIndices);
  for (std::size_t i = 0; i < ret.size(); i++) {
    ret[i] = i;
  }
  return ret;
}
static bool vec_contains(std::vector<unsigned int> indices,int index){
  for(const auto i:indices){
    if(i==index)return true;
  }
  return false;
}
template<std::size_t S>
static std::vector<uint8_t *> convertToP(std::vector<std::array<uint8_t, S>> &buff,
                                         std::size_t offset = 0,
                                         std::size_t n = -1) {
  if (n == -1)n = buff.size();
  std::vector<uint8_t *> ret(n);
  for (int i = 0; i < ret.size(); i++) {
    ret[i] = buff[offset + i].data();
  }
  return ret;
}
template<std::size_t S>
static std::vector<const uint8_t *> convertToP_const(std::vector<std::array<uint8_t, S>> &buff,
                                                     std::size_t offset = 0,
                                                     std::size_t n = -1) {
  if (n == -1)n = buff.size();
  std::vector<const uint8_t *> ret(n);
  for (int i = 0; i < ret.size(); i++) {
    ret[i] = buff[offset + i].data();
  }
  return ret;
}
// given an array of available indices, for each index int the rane [0...range[, check if this index is contained in the input array.
// if not, the index is "missing" and added to the return array
static std::vector<unsigned int> findMissingIndices(const std::vector<unsigned int> &indicesAvailable,
                                                    const std::size_t range) {
  std::vector<unsigned int> indicesMissing;
  for (unsigned int i = 0; i < range; i++) {
    auto found = indicesAvailable.end() != std::find(indicesAvailable.begin(), indicesAvailable.end(), i);
    if (!found) {
      // if not found, add to missing
      //std::cout<<"Not found:"<<i<<"\n";
      indicesMissing.push_back(i);
    }
  }
  return indicesMissing;
}
static constexpr timeval durationToTimeval(std::chrono::nanoseconds dur) {
  const auto secs = std::chrono::duration_cast<std::chrono::seconds>(dur);
  dur -= secs;
  const auto us = std::chrono::duration_cast<std::chrono::microseconds>(dur);
  return timeval{secs.count(), (long int)us.count()};
}
}



#endif //WIFIBROADCAST_HELPER_H
