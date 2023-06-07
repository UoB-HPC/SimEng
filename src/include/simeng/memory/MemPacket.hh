#pragma once

#include <bitset>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

#include "simeng/RegisterValue.hh"
#include "simeng/memory/MemRequests.hh"
#include "simeng/memory/hierarchy/CacheInfo.hh"

namespace simeng {
namespace memory {

enum class MemoryAccessType : uint8_t { NONE, READ, WRITE };

struct BasePacket {
  MemoryAccessType type_ = MemoryAccessType::NONE;
  uint64_t vaddr_ = -1;
  uint64_t paddr_ = -1;
  uint16_t size_ = 0;
  uint64_t id_ = ++id_ctr;
  BasePacket(MemoryAccessType type, uint64_t vaddr, uint64_t paddr,
             uint16_t size)
      : type_(type), vaddr_(vaddr), paddr_(paddr), size_(size) {}
  BasePacket(){};

 private:
  static inline uint64_t id_ctr = 0;
};

struct CPUMemoryPacket : public BasePacket {
  uint64_t insnReqId_;
  uint16_t insnPktId_;
  uint16_t packetOrder_;
  std::vector<char> payload_;
  CPUMemoryPacket(MemoryAccessType type, uint64_t vaddr, uint64_t paddr,
                  uint16_t size, uint64_t insnReqId, uint16_t insnPktId,
                  uint16_t packetOrder)
      : BasePacket(type, vaddr, paddr, size),
        insnReqId_(insnReqId),
        insnPktId_(insnPktId),
        packetOrder_(packetOrder) {}
  CPUMemoryPacket() {}
};

struct MemoryHierarchyPacket : public BasePacket {
  static inline uint16_t clw = 0;
  uint64_t clineAddr_;
  uint64_t cpuPktId_;
  bool isDirty;
  std::vector<char> payload_;
  MemoryHierarchyPacket(MemoryAccessType type, uint64_t vaddr, uint64_t paddr,
                        uint16_t size, uint64_t clineAddr, uint64_t cpuPktId,
                        bool dirty = false)
      : BasePacket(type, vaddr, paddr, size),
        clineAddr_(clineAddr),
        cpuPktId_(cpuPktId),
        isDirty(dirty) {}

  MemoryHierarchyPacket() {}
};

}  // namespace memory
}  // namespace simeng
