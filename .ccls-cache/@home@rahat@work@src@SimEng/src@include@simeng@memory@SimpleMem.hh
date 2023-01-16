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

  /** Returns a copy of internal memory. Used only for testing purposes. */
  char* getMemCpy();

 private:
  /** Reference of to internal memory array. */
  char* memRef;
  /** This variables holds a char array, which represent memory in SimEng. */
  span<char> memory_;
  /** This variable holds the size of the memory array. */
  size_t memSize_;

  /** This method handles ReadPackets. */
  ReadRespPacket* handleReadRequest(struct ReadPacket* req);
  /** This method handles WritePackets. */
  WriteRespPacket* handleWriteRequest(struct WritePacket* req);
};

}  // namespace memory
}  // namespace simeng