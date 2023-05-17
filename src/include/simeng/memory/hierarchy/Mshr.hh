#pragma once

#include <algorithm>
#include <bitset>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <vector>

#include "simeng/memory/MemPacket.hh"
#include "simeng/memory/hierarchy/CacheImpl.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

struct MshrEntry {
  static const uint8_t MshrEntryBusyMask = 0b00000001;

  enum class Type : uint8_t {
    Secondary = 0b00000000,
    PrimaryFetch = 0b10000000,
    PrimaryEviction = 0b01000000,
    BusyFetch = 0b10000001,
    BusyEviction = 0b01000001,
  };

  RequestBufferIndex reqBufIdx;
  MshrEntry::Type type_ = MshrEntry::Type::Secondary;
};

struct MshrReg {
  std::vector<MshrEntry> entries;
  bool dirty = false;
  bool valid = false;
  uint16_t clineIdx = 0;
  MshrEntry& getPrimaryEntry() { return entries[0]; }
};

class Mshr {
 public:
  bool inMshr(uint64_t basePaddr) {
    return mshrRegs_.find(basePaddr) != mshrRegs_.end();
  }

  void allocateMshr(RequestBufferIndex index, uint64_t paddr, uint16_t clw,
                    AccessInfo& info, bool busy) {
    uint64_t addr = downAlign(paddr, clw);
    auto itr = mshrRegs_.find(addr);

    uint8_t busyMask = busy ? MshrEntry::MshrEntryBusyMask : 0;
    // If no entry in MshrReg exists at cache line address then this is a
    // primary miss.
    if (itr == mshrRegs_.end()) {
      MshrEntry::Type type =
          info.dirty ? applyMaskOnMshrEntryType(
                           MshrEntry::Type::PrimaryEviction, busyMask)
                     : applyMaskOnMshrEntryType(MshrEntry::Type::PrimaryFetch,
                                                busyMask);
      MshrReg reg{{{index, type}}, info.dirty, info.valid, info.lineIdx};
      mshrRegs_.insert({addr, reg});
    } else {
      // If MshrReg entry exists then it is secondary miss.
      itr->second.entries.push_back({index});
    }
  }

  // Todo: rename getAndRemove
  MshrReg getAndRemoveMshrReg(uint64_t paddr, uint16_t clw) {
    uint64_t blockAddr = downAlign(paddr, clw);
    auto itr = mshrRegs_.find(blockAddr);
    if (itr == mshrRegs_.end()) {
      std::cerr << "MSHR entry with paddr: " << paddr << " does not exist."
                << std::endl;
      std::exit(1);
    }
    MshrReg reg = itr->second;
    mshrRegs_.erase(itr);
    return reg;
  }

  MshrReg& getMshrReg(uint64_t paddr, uint16_t clw) {
    uint64_t blockAddr = downAlign(paddr, clw);
    auto itr = mshrRegs_.find(blockAddr);
    if (itr == mshrRegs_.end()) {
      std::cerr << "MSHR entry with paddr: " << paddr << " does not exist."
                << std::endl;
      std::exit(1);
    }
    return itr->second;
  }

  MshrEntry::Type applyMaskOnMshrEntryType(MshrEntry::Type type, uint8_t mask) {
    return (MshrEntry::Type)(static_cast<uint8_t>(type) | mask);
  }

 private:
  std::map<uint64_t, MshrReg> mshrRegs_;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
