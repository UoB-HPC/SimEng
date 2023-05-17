#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stack>
#include <vector>

#include "simeng/memory/MemPacket.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

typedef uint32_t RequestBufferIndex;

template <uint16_t initLen = 512>
class RequestBuffer {
 public:
  RequestBuffer() { buffer_.reserve(initLen); };

  uint32_t allocate(std::unique_ptr<MemPacket>& pkt) {
    if (freeIndeces_.size()) {
      RequestBufferIndex index = freeIndeces_.top();
      buffer_[index] = std::move(pkt);
      freeIndeces_.pop();
      return index;
    }
    RequestBufferIndex index = buffer_.size();
    buffer_.push_back(std::move(pkt));
    return index;
  }

  std::unique_ptr<MemPacket>& operator[](RequestBufferIndex index) {
    if (index >= buffer_.size()) {
      std::cerr << "[SimEng::RequestBuffer] Tried to index the request buffer "
                   "with an index greater than size of request buffer."
                << std::endl;
      std::exit(1);
    }
    return buffer_[index];
  }

  std::unique_ptr<MemPacket> remove(RequestBufferIndex index) {
    if (index >= buffer_.size()) {
      std::cerr << "[SimEng::RequestBuffer] Tried to remove an entry from the "
                   "request buffer at an index greater than size of request "
                   "buffer. (Index: "
                << index << ")" << std::endl;
      std::exit(1);
    }
    freeIndeces_.push(index);
    std::unique_ptr<MemPacket> pkt = nullptr;
    std::swap(buffer_[index], pkt);
    return pkt;
  }

 private:
  std::vector<std::unique_ptr<MemPacket>> buffer_;
  std::stack<RequestBufferIndex> freeIndeces_;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
