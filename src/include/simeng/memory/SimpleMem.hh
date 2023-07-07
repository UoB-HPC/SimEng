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

  virtual ~SimpleMem() override {}

  /** This method requests access to memory for both read and write requests. */
  void requestAccess(std::unique_ptr<MemPacket>& pkt) override;

  /** This method returns the size of memory. */
  size_t getMemorySize() override;

  /** This method writes data to memory without incurring any latency.  */
  void sendUntimedData(std::vector<char> data, uint64_t addr,
                       size_t size) override;

  /** This method reads data from memory without incurring any latency. */
  std::vector<char> getUntimedData(uint64_t paddr, size_t size) override;

  void handleIgnoredRequest(std::unique_ptr<MemPacket>& pkt) override;

  /** Function used to initialise a Port used for bidirection communication
   * between this class and the memory hierarchy. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initMemPort() override;

  /** Function used to initialise a Port used for bidirection communication
   * between this class and system classes. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> initSystemPort() override;

  /** Method to tick the memory. */
  void tick() override{};

 private:
  /** Vector which represents the internal simulation memory array. */
  std::vector<char> memory_;

  /** This variable holds the size of the memory array. */
  size_t memSize_;

  /** This method handles DataPackets of type READ_REQUEST. */
  void handleReadRequest(std::unique_ptr<MemPacket>& req);

  /** This method handles DataPackets of type WRITE_REQUEST. */
  void handleWriteRequest(std::unique_ptr<MemPacket>& req);

  /** Port used for communication with the memory hierarchy. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> memPort_ = nullptr;

  /** Port used for communication with system classes. */
  std::shared_ptr<Port<std::unique_ptr<MemPacket>>> sysPort_ = nullptr;
};

}  // namespace memory
}  // namespace simeng
