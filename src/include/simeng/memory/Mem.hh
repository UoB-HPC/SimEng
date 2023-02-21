#pragma once

#include <functional>
#include <memory>

#include "simeng/OS/Process.hh"

namespace simeng {
namespace memory {
/* Enum for classifying DataPacket type. */
enum DataPacketType {
  /** This type signifies a read request to memory. */
  READ_REQUEST,

  /** This type signifies a write request to memory.*/
  WRITE_REQUEST,

  /** This type signifies the response to a read request. */
  READ_RESPONSE,

  /** This type signifies the response to a write request. */
  WRITE_RESPONSE,

  /** This type signifies a faulty or empty request of no type. */
  NONE
};

/* A data packet struct contains information which enables access to the
 * simulation memory. */
struct DataPacket {
  /** The address at which the memory is to be accessed. */
  uint64_t address_ = 0;

  /** The size of the memory operation to be performed. */
  uint64_t size_ = 0;

  /** The type of a DataPacket. */
  DataPacketType type_ = NONE;

  /** The id of a DataPacket, this is set by the memory interface. For write
   * requests it is 0 as the memory interface doesn't specify an id for write
   * requests. */
  uint64_t id_ = 0;

  /** The data carried by a DataPacket, this is used to deliver and receive data
   * to/from the simulation memory. */
  std::vector<char> data_;

  /** This bool signifies if the memory operation specified by the DataPacket
   * resulted in a fault. */
  bool inFault_ = false;

  /** Default constructor for the DataPacket. */
  DataPacket() {}

  /** Constructor to create a faulty DataPacket. */
  DataPacket(bool fault) : inFault_(true) {}

  /** Constructor for DataPackets which do not hold any data. */
  DataPacket(uint64_t address, uint64_t size, DataPacketType type,
             uint64_t reqId, bool fault = false);

  /** Constructor for DataPackers which hold data. */
  DataPacket(uint64_t address, uint64_t size, DataPacketType type,
             uint64_t reqId, std::vector<char> data, bool fault = false);

  /** Default copy constructor for DataPacket. */
  DataPacket(const DataPacket& packet) = default;

  /** Default move constructor for DataPacket to enable copy elision whenever it
   * is possible. */
  DataPacket(DataPacket&& packet) = default;

  /** Default copy assignment operator for DataPacket. */
  DataPacket& operator=(const DataPacket& packet) = default;

  /** Default move assignment operator for DataPacket to enable copy elision
   * whenever it is possible. */
  DataPacket& operator=(DataPacket&& packet) = default;

  /** Method which converts a DataPacket of type READ_REQUEST to READ_RESPONSE.
   * Faulty Packet is returned if this method is called on a DataPacket which
   * does not have a type of READ_REQUEST. */
  DataPacket makeIntoReadResponse(std::vector<char> data);

  /** Method which converts a DataPacket of type WRITE_REQUEST to
   * WRITE_RESPONSE. Faulty Packet is returned if this method is called on a
   * DataPacket which does not have a type of WRITE_REQUEST. */
  DataPacket makeIntoWriteResponse();
};

/* This is a very basic implementation of an interface for simulation memory in
 * SimEng, it has been kept simple just to get dynamic linking and multicore
 * simulation to work. It is very similar to the previous implementation but
 * unifies both instruction and data memory. Previously, multiple copies of
 * process memory were made for instruction and data memory interfaces. */
class Mem {
 public:
  virtual ~Mem() = default;

  /** This method requests access to simulation memory for read and write
   * requests. */
  virtual DataPacket requestAccess(struct DataPacket pkt) = 0;

  /** This method returns the size of memory. */
  virtual size_t getMemorySize() = 0;

  /** This method writes data to memory without incurring any latency. */
  virtual void sendUntimedData(std::vector<char> data, uint64_t addr,
                               size_t size) = 0;

  /** This method reads data from memory without incurring any latency. */
  virtual std::vector<char> getUntimedData(uint64_t paddr, size_t size) = 0;

  /** This method handles a memory request to an ignored address range. */
  virtual DataPacket handleIgnoredRequest(struct DataPacket pkt) = 0;
};

}  // namespace memory
}  // namespace simeng
