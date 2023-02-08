#pragma once

#include <array>
#include <functional>
#include <iostream>
#include <memory>
#include <type_traits>
#include <typeinfo>
#include <utility>

#include "simeng/kernel/Process.hh"

namespace simeng {
namespace memory {

template <class...>
using void_t = void;

template <class B, class = void>
struct is_valid_data : std::false_type {};

template <class B>
struct is_valid_data<B, void_t<typename B::value_type>> : std::true_type {};

template <class Data>
struct PacketInfo : private Data::value_type {
  using data_type = typename Data::value_type;

  uint64_t address_;
  size_t size_;

  PacketInfo<Data>(uint64_t addr, size_t size) {
    address_ = addr;
    size_ = size;
    static_assert(is_valid_data<Data>::value,
                  "template <class Data> does not have a valid type.");
  };
  PacketInfo<Data>(uint64_t addr, size_t size,
                   typename Data::value_type const& pkt)
      : Data::value_type(pkt) {
    address_ = addr;
    size_ = size;
    static_assert(is_valid_data<Data>::value,
                  "template <class Data> does not have a valid type.");
  };
  typename Data::value_type& data() { return *this; };
  typename Data::value_type const& data() const { return *this; };
};

template <bool isRequest, class Data>
struct DataPacket;

template <class Data>
struct DataPacket<true, Data> : public PacketInfo<Data> {
  DataPacket<true, Data>(uint64_t addr, size_t size)
      : PacketInfo<Data>(addr, size){};
  DataPacket<true, Data>(uint64_t addr, size_t size,
                         typename Data::value_type const& pktdata)
      : PacketInfo<Data>(addr, size, pktdata){

        };
};

template <class Data>
struct DataPacket<false, Data> : public PacketInfo<Data> {
  DataPacket<false, Data>(uint64_t addr, size_t size)
      : PacketInfo<Data>(addr, size){};
  DataPacket<false, Data>(uint64_t addr, size_t size,
                          typename Data::value_type const& pktdata)
      : PacketInfo<Data>(addr, size, pktdata){};
};

struct empty_data {
  struct value_type {};
};

struct dword_array_data {
  using value_type = std::array<char, 64>;
};

using ReadRequest = DataPacket<true, empty_data>;
using WriteRequest = DataPacket<true, dword_array_data>;

using ReadResponse = DataPacket<false, dword_array_data>;
using WriteResponse = DataPacket<false, empty_data>;

class Mem {
 public:
  virtual ~Mem() = default;
  /** This method accesses memory with both Read and Write requests. */
  virtual ReadResponse readData(ReadRequest req) = 0;
  virtual WriteResponse writeData(WriteRequest req) = 0;

  /** This method returns the size of memory. */
  virtual size_t getMemorySize() = 0;
  /** This method write data to memory without incurring any latency. */
  virtual void sendUntimedData(char* data, uint64_t addr, size_t size) = 0;
  /** This method sets the translator for memory requests. */
  virtual char* getUntimedData(uint64_t paddr, size_t size) = 0;

  virtual ReadResponse handleIgnoredRequest(ReadRequest req) = 0;
  virtual WriteResponse handleIgnoredRequest(WriteRequest req) = 0;
};

}  // namespace memory
}  // namespace simeng
