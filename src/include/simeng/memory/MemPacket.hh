#pragma once

#include <bitset>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

namespace simeng {
namespace memory {

/** Enum representing the different types of MemPackets. */
enum MemPacketType : uint8_t {
  READ_REQUEST = 0b11000000,
  WRITE_REQUEST = 0b01000000,
  READ_RESPONSE = 0b10000000,
  WRITE_RESPONSE = 0b00000000,
};

/** Masks used for manipulating the metadata associated with a MemPacket. */
static constexpr uint8_t PacketTypeMask = 0b01000000;
static constexpr uint8_t AccessTypeMask = 0b10000000;
static constexpr uint8_t FaultMask = 0b00100000;
static constexpr uint8_t IgnoreMask = 0b00010000;
static constexpr uint8_t PayloadMask = 0b00001000;

/** A MemPacket class is used to access memory to perform read and write
 * operations. */
class MemPacket {
 public:
  /** The address at which the memory is to be accessed. */
  uint64_t address_ = 0;

  /** The size of the memory operation to be performed. */
  uint64_t size_ = 0;

  /** The id of a DataPacket, this is set by the memory interface. For write
   * requests it is 0 as the memory interface doesn't specify an id for write
   * requests. */
  uint64_t id_ = 0;

  /** Function which indicates whether a MemPacket is a request. */
  inline bool isRequest() const { return metadata_ & PacketTypeMask; }

  /** Function which indicates whether a MemPacket is a response. */
  inline bool isResponse() const { return !isRequest(); }

  /** Function which indicates whether a MemPacket initiates a read
   * memory access. */
  inline bool isRead() const { return metadata_ & AccessTypeMask; }

  /** Function which indicates whether a MemPacket initiates a write
   * memory access. */
  inline bool isWrite() const { return !isRead(); }

  /** Function which indicates whether a MemPacket is faulty or not. */
  inline bool isFaulty() const { return metadata_ & FaultMask; }

  /** Function which indicates whether a MemPacket should be ignored or not. */
  inline bool ignore() const { return metadata_ & IgnoreMask; }

  /** Function which indicates whether a MemPacket contains a payload.  */
  inline bool hasPayload() const { return metadata_ & PayloadMask; }

  /** Function used to mark a MemPacket as ignored. */
  inline void setIgnored() { metadata_ = metadata_ | IgnoreMask; }

  /** Function used to mark a MemPacket as faulty. */
  inline void setFault() { metadata_ = metadata_ | FaultMask; }

  /** Virtual function used to return the payload of a MemPacket. */
  virtual std::vector<char>& data() {
    std::cerr << "[SimEng:MemPacket] MemPacket cannot contain a payload, "
                 "please use DataPacket instead."
              << std::endl;
    std::exit(1);
  }

  /** Function used to print the metadata assosciated with a MemPacket. */
  void printMetadata() {
    std::cout << "[SimEng:MemPacket] Metadata: " << std::bitset<8>(metadata_)
              << std::endl;
  }

  /** Static function used to create a read request. */
  static std::unique_ptr<MemPacket> createReadRequest(uint64_t address,
                                                      uint64_t size,
                                                      uint64_t reqId);

  /** Static function used to create a write request. */
  static std::unique_ptr<MemPacket> createWriteRequest(uint64_t address,
                                                       uint64_t size,
                                                       uint64_t reqId,
                                                       std::vector<char> data);

  /** Static function used to create a response to a read request. */
  static std::unique_ptr<MemPacket> createReadResponse(uint64_t address,
                                                       uint64_t size,
                                                       uint64_t reqId,
                                                       std::vector<char> data);

  /** Static function used to create a response to a write request. */
  static std::unique_ptr<MemPacket> createWriteResponse(uint64_t address,
                                                        uint64_t size,
                                                        uint64_t reqId);

  /** Static function used to create a faulty MemPacket. */
  static std::unique_ptr<MemPacket> createFaultyMemPacket();

 protected:
  /** Metadata data associated with a MemPacket.
   * Each bit is used to convey the following  information (From MSB to LSB):
   * 1st bit indicates whether a MemPacket is a Request (1) or Response (0).
   * 2nd bit indicates whether a MemPacket initiates a read (1) or write (0).
   * 3rd bit indicates whether a MemPacket is faulty (1) or not (0).
   * 4th bit indicates whether a MemPacket should be ignored (1) or not (0).
   * 5th bit indicates whether a MemPacket contains a payload (1) or not (0). */
  uint8_t metadata_ = 0;

  /** Default constructor of a MemPacket. */
  MemPacket() {}

  /** Constructor for DataPackets which do not hold any data. */
  MemPacket(uint64_t address, uint64_t size, MemPacketType type,
            uint64_t reqId);
};

/** A DataPacket class inherits the MemPacket class and represents a MemPacket
 * which contains some data. A DataPacket is used represent write requests and
 * read responses as the both of these packet types contain some data. */
class DataPacket : public MemPacket {
  // MemPacket is declared as a friend class because the creational static
  // function is MemPacket require access to the DataPacket constructor.
  friend class MemPacket;

 public:
  /** Function used to print the metadata assosciated with a DataPacket. */
  std::vector<char>& data() override { return data_; }

 private:
  /** Constructor of a DataPacket. */
  DataPacket(uint64_t address, uint64_t size, MemPacketType type,
             uint64_t reqId, std::vector<char> data);

  /** Payload vector used to store data assosciate with a DataPacket. */
  std::vector<char> data_;
};

}  // namespace memory
}  // namespace simeng
