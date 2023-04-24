#pragma once

#include <math.h>

#include <cstdint>
#include <functional>
#include <memory>

#include "simeng/OS/Process.hh"
#include "simeng/Port.hh"
#include "simeng/memory/MemPacket.hh"

namespace simeng {
namespace memory {

/* This is a very basic implementation of an interface for simulation memory
 * in SimEng, it has been kept simple just to get dynamic linking and
 * multicore simulation to work. It is very similar to the previous
 * implementation but unifies both instruction and data memory. Previously,
 * multiple copies of process memory were made for instruction and data
 * memory interfaces. */
class Mem {
 public:
  virtual ~Mem() = default;

  /** This method requests access to simulation memory for read and write
   * requests. */
  virtual void requestAccess(std::unique_ptr<MemPacket> pkt) = 0;

  /** This method returns the size of memory. */
  virtual size_t getMemorySize() = 0;

  /** This method writes data to memory without incurring any latency. */
  virtual void sendUntimedData(std::vector<char> data, uint64_t addr,
                               size_t size) = 0;

  /** This method reads data from memory without incurring any latency. */
  virtual std::vector<char> getUntimedData(uint64_t paddr, size_t size) = 0;

  /** This method handles a memory request to an ignored address range. */
  virtual void handleIgnoredRequest(std::unique_ptr<MemPacket>& pkt) = 0;

  /** This method is initialises a Port for establishing bidirectional
   * communication with other classes. */
  virtual Port<std::unique_ptr<MemPacket>>* initPort() = 0;

  /** Method to tick the memory. */
  virtual void tick() = 0;
};

}  // namespace memory
}  // namespace simeng
