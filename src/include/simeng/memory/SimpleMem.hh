#pragma once
#include <stdint.h>

#include <cstddef>
#include <memory>

#include "simeng/memory/Mem.hh"
#include "simeng/span.hh"

namespace simeng {
namespace memory {

/** The SimpleMem class implements the Mem interface and represents a
 * simple and untimed model of simulation memory. */
class SimpleMem : public Mem {
 public:
  SimpleMem(size_t bytes);

  virtual ~SimpleMem() override { delete port_; };

  /** This method requests access to memory for both read and write requests. */
  std::unique_ptr<MemPacket> requestAccess(
      std::unique_ptr<MemPacket> pkt) override;

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

  Port<std::unique_ptr<MemPacket>>* initPort() override;

 private:
  /** Vector which represents the internal simulation memory array. */
  std::vector<char> memory_;

  /** This variable holds the size of the memory array. */
  size_t memSize_;

  /** This method handles DataPackets of type READ_REQUEST. */
  std::unique_ptr<MemPacket> handleReadRequest(std::unique_ptr<MemPacket> req);

  /** This method handles DataPackets of type WRITE_REQUEST. */
  std::unique_ptr<MemPacket> handleWriteRequest(std::unique_ptr<MemPacket> req);

  Port<std::unique_ptr<MemPacket>>* port_ = nullptr;
};

}  // namespace memory
}  // namespace simeng
