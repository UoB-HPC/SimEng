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

  virtual ~SimpleMem() override{};

  /** This method requests access to memory for both read and write requests. */
  DataPacket requestAccess(struct DataPacket pkt) override;

  /** This method returns the size of memory. */
  size_t getMemorySize() override;

  /** This method writes data to memory without incurring any latency.  */
  void sendUntimedData(std::vector<char> data, uint64_t addr,
                       size_t size) override;

  /** This method reads data from memory without incurring any latency. */
  std::vector<char> getUntimedData(uint64_t paddr, size_t size) override;

  /** This method handles a memory request to an ignored address range. */
  DataPacket handleIgnoredRequest(struct DataPacket pkt) override;

 private:
  /** Vector which represents the internal simulation memory array. */
  std::vector<char> memory_;

  /** This variable holds the size of the memory array. */
  size_t memSize_;

  /** This method handles DataPackets of type READ_REQUEST. */
  DataPacket handleReadRequest(struct DataPacket req);

  /** This method handles DataPackets of type WRITE_REQUEST. */
  DataPacket handleWriteRequest(struct DataPacket req);
};

}  // namespace memory
}  // namespace simeng
