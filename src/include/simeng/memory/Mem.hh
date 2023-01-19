#pragma once

#include <functional>
#include <memory>

#include "simeng/kernel/Process.hh"

namespace simeng {
namespace memory {
// This is a very basic implementation of Memory in SimEng, it has been kept
// simple just to get dynamic linking and multicore simulation working. It is
// very similar to the previous implementation but unifies both instruction and
// data memory. Whereas, previously two different copies of process memory were
// for instruction and data memory interfaces.

/* Enum for classifying data access. */
enum DataPacketAccessType { READ, WRITE };

/* A data packet represents access to memory. This has named and cnstruct such
 * that future improvements to memory system can be facilitated
 */
struct DataPacket {
  uint64_t address;
  static uint64_t pktIdCtr;
  uint64_t id;
  DataPacketAccessType type;
  DataPacket(DataPacketAccessType accType, uint64_t addr);
};

/* Response to a read packed. */
struct ReadRespPacket : public DataPacket {
  uint64_t reqId;
  size_t bytesRead;
  char* data;
  ReadRespPacket(uint64_t req_id, size_t bytes_read, char* dt, uint64_t addr);
};

/* ReadPacket represents a read access to data packet. */
struct ReadPacket : public DataPacket {
  size_t size;

  ReadPacket(uint64_t addr, size_t sz);
  ReadRespPacket* makeResponse(uint64_t bytesRead, char* data);
};

/* Response to a write packed. */
struct WriteRespPacket : public DataPacket {
  uint64_t reqId;
  size_t bytesWritten;
  WriteRespPacket(uint64_t req_id, size_t bytes_written, uint64_t addr);
};

/* WritePacket represents a write access to a data packet. */
struct WritePacket : public DataPacket {
  size_t size;
  const char* data;

  WritePacket(uint64_t addr, size_t sz, const char* dt);
  WriteRespPacket* makeResponse(uint64_t bytesReturned);
};

class Mem {
 public:
  virtual ~Mem() = default;
  /** This method accesses memory with both Read and Write requests. */
  virtual DataPacket* requestAccess(struct DataPacket* pkt) = 0;
  /** This method returns the size of memory. */
  virtual size_t getMemorySize() = 0;
  /** This method write data to memory without incurring any latency. */
  virtual void sendUntimedData(char* data, uint64_t addr, size_t size) = 0;
  /** This method sets the translator for memory requests. */
  virtual void setTranslator(std::function<uint64_t(uint64_t)> translator) = 0;
};

}  // namespace memory
}  // namespace simeng
