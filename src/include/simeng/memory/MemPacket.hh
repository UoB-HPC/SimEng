#include <bitset>
#include <cstdint>
#include <iostream>
#include <vector>

namespace simeng {
namespace memory {

enum MemPacketType : uint8_t {
  READ_REQUEST = 0b11000000,
  WRITE_REQUEST = 0b01000000,
  READ_RESPONSE = 0b10000000,
  WRITE_RESPONSE = 0b00000000,
};

static constexpr uint8_t PacketTypeMask = 0b01000000;
static constexpr uint8_t AccessTypeMask = 0b10000000;
static constexpr uint8_t FaultMask = 0b00100000;
static constexpr uint8_t IgnoreMask = 0b00010000;
static constexpr uint8_t PayloadMask = 0b00001000;

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

  /** Method which converts a DataPacket of type READ_REQUEST to READ_RESPONSE.
   * Faulty Packet is returned if this method is called on a DataPacket which
   * does not have a type of READ_REQUEST. */
  virtual MemPacket* makeIntoReadResponse(std::vector<char> data);

  /** Method which converts a DataPacket of type WRITE_REQUEST to
   * WRITE_RESPONSE. Faulty Packet is returned if this method is called on a
   * DataPacket which does not have a type of WRITE_REQUEST. */
  virtual MemPacket* makeIntoWriteResponse();

  inline bool isRequest() const { return metadata_ & PacketTypeMask; }

  inline bool isResponse() const { return !isRequest(); }

  inline bool isRead() const { return metadata_ & AccessTypeMask; }

  inline bool isWrite() const { return !isRead(); }

  inline bool isFaulty() const { return metadata_ & FaultMask; }

  inline bool ignore() const { return metadata_ & IgnoreMask; }

  inline bool hasPayload() const { return metadata_ & PayloadMask; }

  inline void setIgnored() { metadata_ = metadata_ | IgnoreMask; }

  inline void setFault() { metadata_ = metadata_ | FaultMask; }

  virtual std::vector<char>& data() {
    std::cerr << "[SimEng:MemPacket] MemPacket cannot contain a payload, "
                 "please use DataPacket instead."
              << std::endl;
    std::exit(1);
  }

  static MemPacket* createReadRequest(uint64_t address, uint64_t size,
                                      uint64_t reqId);

  static MemPacket* createWriteRequest(uint64_t address, uint64_t size,
                                       uint64_t reqId, std::vector<char> data);

  static MemPacket* createFaultyMemPacket();

 protected:
  uint8_t metadata_ = 0;

  MemPacket() {}

  /** Constructor for DataPackets which do not hold any data. */
  MemPacket(uint64_t address, uint64_t size, MemPacketType type,
            uint64_t reqId);

  static MemPacket* createReadResponse(uint64_t address, uint64_t size,
                                       uint64_t reqId, std::vector<char> data);

  static MemPacket* createWriteResponse(uint64_t address, uint64_t size,
                                        uint64_t reqId);
};

class DataPacket : public MemPacket {
  friend class MemPacket;

 public:
  std::vector<char>& data() override { return data_; }
  MemPacket* makeIntoWriteResponse() override;
  MemPacket* makeIntoReadResponse(std::vector<char> data) override;

 private:
  DataPacket(uint64_t address, uint64_t size, MemPacketType type,
             uint64_t reqId, std::vector<char> data);
  std::vector<char> data_;
};

}  // namespace memory
}  // namespace simeng
