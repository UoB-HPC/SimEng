#pragma once

#include <bitset>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

#include "simeng/memory/MemRequests.hh"

namespace simeng {
namespace memory {

/** Enum representing the different types of MemPackets. */
enum MemPacketType : uint8_t {
  READ_REQUEST = 0b11000000,
  READ_RESPONSE = 0b01000000,
  WRITE_REQUEST = 0b10000000,
  WRITE_RESPONSE = 0b00000000,
};

/** Masks used for manipulating the metadata associated with a MemPacket. */
static constexpr uint8_t AccessTypeMask = 0b10000000;
static constexpr uint8_t PacketTypeMask = 0b01000000;
static constexpr uint8_t FaultMask = 0b00100000;
static constexpr uint8_t IgnoreMask = 0b00010000;
static constexpr uint8_t PayloadMask = 0b00001000;
static constexpr uint8_t InstrReadMask = 0b00000100;
static constexpr uint8_t UntimedMemAccessMask = 0b00000010;

/** A MemPacket class is used to access memory to perform read and write
 * operations. */
class MemPacket {
 public:
  /** The virtual address at which the memory is to be accessed. */
  uint64_t vaddr_ = 0;

  /** The physical address at which the memory is to be accessed. */
  uint64_t paddr_ = 0;

  /** The size of the memory operation to be performed. */
  uint16_t size_ = 0;

  /* Uniquely identifies a memory packet and is set by the MMU. Instruction-read
   * and data-write requests can have an ID of 0. */
  uint64_t id_ = 0;

  /** Function which indicates whether a MemPacket is a request. */
  inline bool isRequest() const { return metadata_ & AccessTypeMask; }

  /** Function which indicates whether a MemPacket is a response. */
  inline bool isResponse() const { return !isRequest(); }

  /** Function which indicates whether a MemPacket initiates a read
   * memory access. */
  inline bool isRead() const { return metadata_ & PacketTypeMask; }

  /** Function which indicates whether a MemPacket initiates a write
   * memory access. */
  inline bool isWrite() const { return !isRead(); }

  /** Function which indicates whether a MemPacket is faulty or not. */
  inline bool isFaulty() const { return metadata_ & FaultMask; }

  /** Function which indicates whether a MemPacket corresponds to Instruction
   * Read. */
  inline bool isInstrRead() const { return metadata_ & InstrReadMask; };

  /** Function which indicates whether a MemPacket does an untimed memory
   * access. */
  inline bool isUntimed() const { return metadata_ & UntimedMemAccessMask; }

  /** Function which indicates whether a MemPacket should be ignored or not. */
  inline bool ignore() const { return metadata_ & IgnoreMask; }

  /** Function which indicates whether a MemPacket contains a payload.  */
  inline bool hasPayload() const { return metadata_ & PayloadMask; }

  /** Function used to mark a MemPacket as ignored. */
  inline void markAsIgnored() { metadata_ = metadata_ | IgnoreMask; }

  /** Function used to mark a MemPacket as faulty. */
  inline void markAsFaulty() { metadata_ = metadata_ | FaultMask; }

  /** Function used to mark that a MemPacket is used to read an instruction. */
  inline void markAsInstrRead() { metadata_ = metadata_ | InstrReadMask; }

  /** Function used to mark a MemPacket to do untimed memory access. */
  inline void markAsUntimed() { metadata_ = metadata_ | UntimedMemAccessMask; }

  /** Function to return the data assosciated with a MemPacket. */
  std::vector<char>& payload() { return payload_; }

  /** Function used to print the metadata assosciated with a MemPacket. */
  void printMetadata() {
    std::cout << "[SimEng:MemPacket] Metadata: " << std::bitset<8>(metadata_)
              << std::endl;
  }

  /** Static function used to create a read request. */
  static std::unique_ptr<MemPacket> createReadRequest(uint64_t vaddr,
                                                      uint16_t size,
                                                      uint64_t reqId);

  /** Static function used to create a write request. */
  static std::unique_ptr<MemPacket> createWriteRequest(uint64_t vaddr,
                                                       uint16_t size,
                                                       uint64_t reqId,
                                                       std::vector<char> data);

  /** Static function used to create a faulty MemPacket. */
  static std::unique_ptr<MemPacket> createFaultyMemPacket(bool isRead);

  /** Function to change a Read MemPacket into a Response. */
  void turnIntoReadResponse(std::vector<char> payload);

  /** Function to change a Write MemPacket into a Response. */
  void turnIntoWriteResponse();

 protected:
  /** Metadata data associated with a MemPacket.
   * Each bit is used to convey the following  information (From MSB to LSB):
   * 1st bit indicates whether a MemPacket is a Request (1) or Response (0).
   * 2nd bit indicates whether a MemPacket initiates a read (1) or write (0).
   * 3rd bit indicates whether a MemPacket is faulty (1) or not (0).
   * 4th bit indicates whether a MemPacket should be ignored (1) or not (0).
   * 5th bit indicates whether a MemPacket contains a payload (1) or not (0).
   * 6th bit indicates whether a MemPacket reads an instruction (1) or not (0).
   * 7th bit indicates whether an untimed (1) or timed (0) memory access occurs.
   */
  uint8_t metadata_ = 0;

  /** Payload assosciate with a MemPacket. */
  std::vector<char> payload_;

  /** Default constructor of a MemPacket. */
  MemPacket() {}

  /** Constructor for MemPackets which do not hold any data. */
  MemPacket(uint64_t vaddr, uint16_t size, MemPacketType type, uint64_t reqId);

  /** Constructor for MemPackets which hold any data. */
  MemPacket(uint64_t vaddr, uint16_t size, MemPacketType type, uint64_t reqId,
            std::vector<char> data);
};

}  // namespace memory
}  // namespace simeng
