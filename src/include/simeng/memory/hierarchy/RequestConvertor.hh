#pragma once

#include <cstdint>
#include <map>

#include "simeng/memory/MemPacket.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

class RequestConvertor {
 public:
  RequestConvertor(uint16_t clw) : clw_(clw){};
  RequestConvertor() {}

  MemoryHierarchyPacket convert(CPUMemoryPacket& cpuPkt) {
    MemoryHierarchyPacket hpkt(cpuPkt.type_, cpuPkt.vaddr_, cpuPkt.paddr_, 0,
                               cpuPkt.id_);
    reqMap.insert({cpuPkt.id_, cpuPkt});
    if (cpuPkt.type_ == MemoryAccessType::WRITE) {
      hpkt.payload_ = cpuPkt.payload_;
    }
    return hpkt;
  }

  CPUMemoryPacket convert(MemoryHierarchyPacket& pkt) {
    auto itr = reqMap.find(pkt.cpuPktId_);
    if (itr == reqMap.end()) {
      // TODO: Error Message
      std::exit(1);
    }
    auto cpuPkt = itr->second;
    if (pkt.type_ == MemoryAccessType::READ) {
      uint16_t offset = pkt.paddr_ - downAlign(pkt.paddr_, clw_);
      cpuPkt.payload_ =
          std::vector(pkt.payload_.begin() + offset,
                      pkt.payload_.begin() + offset + cpuPkt.size_);
    }
    reqMap.erase(itr);
    return cpuPkt;
  }

 private:
  uint16_t clw_ = 0;
  std::map<uint32_t, CPUMemoryPacket> reqMap;
};

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
