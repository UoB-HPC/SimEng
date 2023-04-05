#pragma once

#include <math.h>

#include <cstdint>
#include <functional>
#include <memory>

#include "simeng/OS/Process.hh"
#include "simeng/PubSub.hh"
#include "simeng/memory/MemPacket.hh"

namespace simeng {
namespace memory {

/* This is a very basic implementation of an interface for simulation memory
 * in SimEng, it has been kept simple just to get dynamic linking and
 * multicore simulation to work. It is very similar to the previous
 * implementation but unifies both instruction and data memory. Previously,
 * multiple copies of process memory were made for instruction and data
 * memory interfaces. */
class Mem : public SubscriberInterface<std::unique_ptr<MemPacket>>,
            public SoloPublisher<std::unique_ptr<MemPacket>> {
 public:
  virtual ~Mem() = default;

  /** This method requests access to simulation memory for read and write
   * requests. */
  virtual std::unique_ptr<MemPacket> requestAccess(
      std::unique_ptr<MemPacket> pkt) = 0;

  /** This method returns the size of memory. */
  virtual size_t getMemorySize() = 0;

  /** This method writes data to memory without incurring any latency. */
  virtual void sendUntimedData(std::vector<char> data, uint64_t addr,
                               size_t size) = 0;

  /** This method reads data from memory without incurring any latency. */
  virtual std::vector<char> getUntimedData(uint64_t paddr, size_t size) = 0;

  /** This method handles a memory request to an ignored address range. */
  virtual std::unique_ptr<MemPacket> handleIgnoredRequest(
      std::unique_ptr<MemPacket> pkt) = 0;

  virtual void subscribe(
      std::shared_ptr<SubscriberInterface<std::unique_ptr<MemPacket>>>
          data) = 0;
  virtual void notify(std::unique_ptr<MemPacket> data) = 0;
  virtual void update(std::unique_ptr<MemPacket> packet) = 0;
};

}  // namespace memory
}  // namespace simeng
