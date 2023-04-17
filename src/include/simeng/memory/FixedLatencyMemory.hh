#pragma once
#include <stdint.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <queue>

#include "simeng/memory/Mem.hh"
#include "simeng/span.hh"

namespace simeng {
namespace memory {

struct LatencyPacket {
  std::unique_ptr<MemPacket> req = nullptr;
  uint64_t endLat = 0;
};

/** The FixedLatencyMemory class implements the Mem interface and represents a
 * timed model of simulation memory which responds to requests after a fixed
 * number of clock cycles. */
class FixedLatencyMemory : public Mem {
 public:
  FixedLatencyMemory(size_t bytes, uint16_t latency);

  virtual ~FixedLatencyMemory() override { delete port_; };

  /** This method requests access to memory for both read and write requests. */
  void requestAccess(std::unique_ptr<MemPacket> pkt) override;

  /** This method returns the size of memory. */
  size_t getMemorySize() override;

  /** This method writes data to memory without incurring any latency.  */
  void sendUntimedData(std::vector<char> data, uint64_t addr,
                       size_t size) override;

  /** This method reads data from memory without incurring any latency. */
  std::vector<char> getUntimedData(uint64_t paddr, size_t size) override;

  /** This method handles a memory request to an ignored address range. */
  std::unique_ptr<MemPacket> handleIgnoredRequest(
      std::unique_ptr<MemPacket> pkt) override;

  /** Function used to initialise a Port used for bidirection communication. */
  Port<std::unique_ptr<MemPacket>>* initPort() override;

  /** Method to tick the memory. */
  void tick() override;

 private:
  /** Vector which represents the internal simulation memory array. */
  std::vector<char> memory_;

  /** This variable holds the size of the memory array. */
  size_t memSize_;

  /** The latency to be applied to all MemPackets. */
  uint16_t latency_;

  /** A counter for number of ticks elapsed. */
  uint64_t ticks_;

  /** A queue to all store all incoming requests. */
  std::queue<LatencyPacket> reqQueue_;

  /** Port used for communication with other classes. */
  Port<std::unique_ptr<MemPacket>>* port_ = nullptr;

  /** This method handles DataPackets of type READ_REQUEST. */
  std::unique_ptr<MemPacket> handleReadRequest(std::unique_ptr<MemPacket> req);

  /** This method handles DataPackets of type WRITE_REQUEST. */
  std::unique_ptr<MemPacket> handleWriteRequest(std::unique_ptr<MemPacket> req);
};

}  // namespace memory
}  // namespace simeng
