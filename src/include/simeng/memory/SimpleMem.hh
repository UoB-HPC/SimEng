#pragma once
#include <stdint.h>

#include <cstddef>
#include <memory>

#include "simeng/memory/Mem.hh"
#include "simeng/span.hh"

namespace simeng {
namespace memory {

// Simple memory class this will be replaced by more complex memory models in
// the future.
class SimpleMem : public Mem {
 public:
  SimpleMem(size_t bytes);
  virtual ~SimpleMem() override;

  size_t getMemorySize() override;
  DataPacket* requestAccess(struct DataPacket* desc) override;
  void sendUntimedData(char* data, uint64_t addr, size_t size) override;
  char* getUntimedData(uint64_t paddr, size_t size) override;
  void setTranslator(std::function<uint64_t(uint64_t)> translator) override;
  DataPacket* handleFaultySpeculationRequest(struct DataPacket* pkt) override;

  /** Returns a copy of internal memory. Used only for testing purposes. */
  char* getMemCpy();

 private:
  std::function<uint64_t(uint64_t)> translator_;
  /** Reference of to internal memory array. */
  char* memRef;
  /** This variables holds a char array, which represent memory in SimEng. */
  span<char> memory_;
  char* faultMemory_;
  /** This variable holds the size of the memory array. */
  size_t memSize_;

  /** This method handles ReadPackets. */
  ReadRespPacket* handleReadRequest(struct ReadPacket* req);
  /** This method handles WritePackets. */
  WriteRespPacket* handleWriteRequest(struct WritePacket* req);
};

}  // namespace memory
}  // namespace simeng
