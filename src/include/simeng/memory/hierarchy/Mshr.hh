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

/** The MshrEntry struct represent single memory request entry inside an MSHR
 * register. The struct also holds information regarding the type of MSHR entry.
 */
struct MshrEntry {
  /** Mask applied to MshrEntry::Type::PrimaryFetch and
   * MshrEntry::Type::PrimaryEviction to turn into MshrEntry::Type::BusyFetch
   * and MshrEntry::Type::BusyEviction respectively. */
  static const uint8_t MshrEntryBusyMask = 0b00000001;

  /** Enum which holds the different types of MshrEntry. */
  enum class Type : uint8_t {
    /** Secondary type indicates that a memory request (primary) has already
       been made to cache line which is already being fetched or evicted. */
    Secondary = 0b00000000,
    /** PrimaryFetch indicates that the memory request corresponding to
       this entry has caused an invalid cache line to be fetched from memory.
       The request corresponding to this type is first missed request to a cache
       line.  */
    PrimaryFetch = 0b10000000,
    /** PrimaryEviction indicates that the memory request corresponding to this
       entry has caused a valid and dirty cache to be fetched from memory. It is
       always caused by a replacement and the memory request corresping to this
       entry is the first request which caused the eviction. */
    PrimaryEviction = 0b01000000,
    /** BusyFetch indicates that the memory request corresponding to this entry
       needs to fetch a cache line from memory that is currently being fetched
       from memory because of another memory request. BusyFetch is always caused
       by a replacement and the memory request corresping to this entry is the
       first request which tries to cause another fetch. */
    BusyFetch = 0b10000001,

    /** BusyEviction indicates that the memory request corresponding to this
       entry needs to fetch a cache line from memory that is currently being
       evicted from memory because of another memory request. BusyEviction is
       always caused by a replacement and the memory request corresping to this
       entry is the first request which tries to cause another fetch. */
    BusyEviction = 0b01000001,
  };

  /** The RequestBufferIndex of the memory request corresponding to this
   * MshrEntry. */
  RequestBufferIndex reqBufIdx;
  /** The type of the MshrEntry. */
  MshrEntry::Type type_ = MshrEntry::Type::Secondary;
};

/** The MshrReg represent a single entry in the Miss status handling register
 * which only holds miss information for a single physical address range of
 * cache line width. This data of this entire address range will be cached on a
 * cache line. */
struct MshrReg {
  /** All MshrEntries related to this MshrReg. */
  std::vector<MshrEntry> entries;
  /** Indicates if the cache line on which the primary request missed is dirty
   * or not. */
  bool dirty = false;
  /** Indicates if the cache line on which the primary request missed is valid
   * or not. */
  bool valid = false;
  /** The index of cache line in the cache. */
  uint16_t clineIdx = 0;
  /** Function which return the first request (primary) which missed on the
   * cache line under consideration. */
  MshrEntry& getPrimaryEntry() { return entries[0]; }
};

/**The MSHR class represents an ideal Miss Status Handling Register which can
 * hold miss status information regarding any number of cache lines; recording
 * any number of misses without incurring any storage constraints. A
 * cache line inside the MSHR is characterised by its starting physical address.
 * the starting physical address is always aligned to cache line width.
 */
class Mshr {
 public:
  /** Function to check if an MshrReg is present for a cache line which caches
   * data of physical address range starting at basePaddr. basePaddr is always
   * cache line width aligned. */
  bool inMshr(uint64_t basePaddr) {
    return mshrRegs_.find(basePaddr) != mshrRegs_.end();
  }
  /** Function which is used to allocate a MshrEntry or MshrReg. If an MshrReg
   * is already present for a cache line, then a MshrEntry is added to
   * corresponding MshrReg. If an MshrReg is not present then a new MshrReg is
   * allocated.  */
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

  /** Function to retrieve and remove a MshrReg. */
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

  /** Function which return the reference to a MshrReg. */
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

  /** Utility function which applies a Mask on MshrEntry::Type. */
  MshrEntry::Type applyMaskOnMshrEntryType(MshrEntry::Type type, uint8_t mask) {
    return (MshrEntry::Type)(static_cast<uint8_t>(type) | mask);
  }

 private:
  /** Map which contains all MshrReg(s); This represents an ideal MSHR. */
  std::map<uint64_t, MshrReg> mshrRegs_;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
