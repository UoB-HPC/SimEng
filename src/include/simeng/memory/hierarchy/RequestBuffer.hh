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

/** The RequestBuffer class is used to store all std::unique_ptr<MemPacket>.
 * The class exposes functions to add and remove unique pointers from the
 * buffer. It also exposes a operator[] to reference a unique pointer given its
 * index in the buffer. This class was implemented to facilate request
 * processing in caches by reducing the number of std::move operations required
 * to move std::unique_ptr<MemPacket> to different queues. By using the
 * RequestBuffer we only need to store the RequestBufferIndex of a
 * std::unique_ptr<MemPacket> which can then be used to reference it. */
class RequestBuffer {
 public:
  /** Constructor of the RequestBuffer. */
  RequestBuffer(uint16_t initSize = 512) { buffer_.reserve(initSize); };

  /** Function used to add a std::unique_ptr<MemPacket> to the RequestBuffer. */
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

  /** Function used to reference a std::unique_ptr<MemPacket> stored inside the
   * RequestBuffer given its RequestBufferIndex. */
  std::unique_ptr<MemPacket>& operator[](RequestBufferIndex index) {
    if (index >= buffer_.size()) {
      std::cerr << "[SimEng::RequestBuffer] Tried to index the request buffer "
                   "with an index greater than size of request buffer."
                << std::endl;
      std::exit(1);
    }
    return buffer_[index];
  }

  /** Function used to remove a std::unique_ptr<MemPacket> from the
   * RequestBuffer given its index. */
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

  /** Function used to return the size of the RequestBuffer. */
  auto getSize() { return buffer_.size(); }

 private:
  /** Vector used to store std::unique_ptr<MemPacket>. */
  std::vector<std::unique_ptr<MemPacket>> buffer_;
  /** Stack used to stores RequestBufferIndex(s) that can be used again. */
  std::stack<RequestBufferIndex> freeIndeces_;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
