#pragma once
#include <stdint.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <queue>

#include "simeng/memory/Mem.hh"
#include "simeng/memory/MemPacket.hh"
#include "simeng/span.hh"

namespace simeng {
namespace memory {

template <class T>
struct LatencyPacket {
  T req;
  uint64_t endLat = 0;
};

/** The FixedLatencyMemory class implements the Mem interface and represents a
 * timed model of simulation memory which responds to requests after a fixed
 * number of clock cycles. */
enum class FixedLatencyMemoryType : uint8_t { WithHierarchy, NoHierarchy };

class FixedLatencyMemory : public Mem {
 public:
  static std::shared_ptr<FixedLatencyMemory> build(bool hasHierarchy,
                                                   size_t bytes,
                                                   uint16_t latency);

  virtual ~FixedLatencyMemory() override{};

  /** This method returns the size of memory. */
  size_t getMemorySize() override;

  /** This method writes data to memory without incurring any latency.  */
  void sendUntimedData(std::vector<char> data, uint64_t addr,
                       size_t size) override;

  /** This method reads data from memory without incurring any latency. */
  std::vector<char> getUntimedData(uint64_t paddr, size_t size) override;

  /***/
  virtual std::shared_ptr<Port<CPUMemoryPacket>> initDirectAccessDataPort()
      override = 0;

  /** Function used to initialise a Port used for bidirection communication. */
  virtual std::shared_ptr<Port<MemoryHierarchyPacket>> initDataPort()
      override = 0;

  /** Function used to initialise a Port used for untimed memory access. */
  std::shared_ptr<Port<CPUMemoryPacket>> initUntimedInstrReadPort() override;

  /** Method to tick the memory. */
  virtual void tick() override = 0;

 protected:
  FixedLatencyMemory(size_t bytes, uint16_t latency);

  /** Vector which represents the internal simulation memory array. */
  std::vector<char> memory_;

  /** This variable holds the size of the memory array. */
  size_t memSize_;

  /** The latency to be applied to all MemPackets. */
  uint16_t latency_;

  /** A counter for number of ticks elapsed. */
  uint64_t ticks_;

  /** Port used for recieving untimed memory requests. */
  std::shared_ptr<Port<CPUMemoryPacket>> untimedInstrReadPort_ = nullptr;
};

template <FixedLatencyMemoryType TValue>
class DerivedFixedLatencyMemory;

template <>
class DerivedFixedLatencyMemory<FixedLatencyMemoryType::NoHierarchy>
    : public FixedLatencyMemory {
 public:
  friend class FixedLatencyMemory;

  /***/
  std::shared_ptr<Port<CPUMemoryPacket>> initDirectAccessDataPort() override;

  /** Function used to initialise a Port used for bidirection communication. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> initDataPort() override;

  /***/
  void tick() override;

 protected:
  /***/
  DerivedFixedLatencyMemory<FixedLatencyMemoryType::NoHierarchy>(
      size_t bytes, uint16_t latency);

 private:
  /***/
  void requestAccess(CPUMemoryPacket& pkt);

  /** A queue to all store all incoming CPU requests. */
  std::queue<LatencyPacket<CPUMemoryPacket>> cpuReqQueue_;

  /***/
  std::shared_ptr<Port<CPUMemoryPacket>> directAccessDataPort_ = nullptr;

  /***/
  void handleReadRequest(CPUMemoryPacket& req);

  /***/
  void handleWriteRequest(CPUMemoryPacket& req);
};

template <>
class DerivedFixedLatencyMemory<FixedLatencyMemoryType::WithHierarchy>
    : public FixedLatencyMemory {
 public:
  friend class FixedLatencyMemory;

  /** This method requests access to memory for both read and write requests. */
  void requestAccess(MemoryHierarchyPacket& pkt);

  /***/
  std::shared_ptr<Port<CPUMemoryPacket>> initDirectAccessDataPort() override;

  /** Function used to initialise a Port used for bidirection communication. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> initDataPort() override;

  /***/
  void tick() override;

 protected:
  /***/
  DerivedFixedLatencyMemory<FixedLatencyMemoryType::WithHierarchy>(
      size_t bytes, uint16_t latency);

 private:
  /** A queue to all store all incoming requests. */
  std::queue<LatencyPacket<MemoryHierarchyPacket>> reqQueue_;

  /** Port used for communication with other classes. */
  std::shared_ptr<Port<MemoryHierarchyPacket>> timedPort_ = nullptr;

  /** This method handles MemPackets of type READ_REQUEST. */
  void handleReadRequest(MemoryHierarchyPacket& req);

  /** This method handles MemPackets of type WRITE_REQUEST. */
  void handleWriteRequest(MemoryHierarchyPacket& req);
};

}  // namespace memory
}  // namespace simeng
