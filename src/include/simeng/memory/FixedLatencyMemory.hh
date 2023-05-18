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

  virtual ~FixedLatencyMemory() override{};

  /** This method requests access to memory for both read and write requests. */
  void requestAccess(std::unique_ptr<MemPacket>& pkt) override;

  /** This method returns the size of memory. */
  size_t getMemorySize() override;

  /** This method writes data to memory without incurring any latency.  */
  void sendUntimedData(std::vector<char> data, uint64_t addr,
                       size_t size) override;

  /** This method reads data from memory without incurring any latency. */
  std::vector<char> getUntimedData(uint64_t paddr, size_t size) override;

  /** Function used to initialise a Port used for bidirection communication. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initPort() override;

  /** Function used to initialise a Port used for untimed memory access. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initUntimedPort() override;

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
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> timedPort_ = nullptr;

  /** Port used for recieving untimed memory requests. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> untimedPort_ = nullptr;

  /** This method handles MemPackets of type READ_REQUEST. */
  void handleReadRequest(std::unique_ptr<MemPacket>& req);

  /** This method handles MemPackets of type WRITE_REQUEST. */
  void handleWriteRequest(std::unique_ptr<MemPacket>& req);
};

}  // namespace memory
}  // namespace simeng
