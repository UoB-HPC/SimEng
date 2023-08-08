#include "simeng/memory/hierarchy/SetAssosciativeCache.hh"

#include <algorithm>
#include <bitset>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <memory>
#include <vector>

#include "simeng/memory/MemPacket.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

AccessInfo BaseSetAssosciativeCache::checkHit(MemoryHierarchyPacket& pkt) {
  uint16_t setIndex = tagScheme_->calcSetIndex(pkt);
  uint64_t tag = tagScheme_->calcTag(pkt);
  uint16_t startIdx = setIndex * assosciativity_;
  uint16_t endIdx = startIdx + assosciativity_;
  for (uint16_t x = startIdx; x < endIdx; x++) {
    if (cacheLines_[x].getTag() == tag) {
      return AccessInfo{cacheLines_[x].isValid(), cacheLines_[x].isDirty(),
                        true, x};
    }
  }
  auto ainfo = AccessInfo{};
  ainfo.lineIdx = startIdx;
  return ainfo;
}

void BaseSetAssosciativeCache::invalidateAll() {
  for (auto& cacheLine : cacheLines_) {
    cacheLine.setInvalid();
  }
}

std::shared_ptr<Port<MemoryHierarchyPacket>>
SetAssosciativeCache<CacheLevel::L1>::initTopPort() {
  std::cerr << "[SimEng:SetAssosciativeCache] Cannot initiate top port on an "
               "L1 cache. L1 caches can only "
               "have a bottom port and a cpu port"
            << std::endl;
  std::exit(1);
}

std::shared_ptr<Port<CPUMemoryPacket>>
SetAssosciativeCache<CacheLevel::L1>::initCpuPort() {
  cpuPort_ = std::make_shared<Port<CPUMemoryPacket>>();
  auto fn = [this](CPUMemoryPacket cpuPkt) {
    MemoryHierarchyPacket mpkt(cpuPkt.type_, cpuPkt.vaddr_, cpuPkt.paddr_, clw_,
                               0, cpuPkt.id_);
    reqMap_.insert({cpuPkt.id_, cpuPkt});
    waitQueue_.push({mpkt, ticks_ + latencyInfo_.hitLatency});
  };
  cpuPort_->registerReceiver(fn);
  return cpuPort_;
}

std::shared_ptr<Port<MemoryHierarchyPacket>>
SetAssosciativeCache<CacheLevel::L1>::initBottomPort() {
  bottomPort_ = std::make_shared<Port<MemoryHierarchyPacket>>();
  auto fn = [this](MemoryHierarchyPacket mpkt) {
    handleResponseFromBottomPort(mpkt);
  };
  bottomPort_->registerReceiver(fn);
  return bottomPort_;
}

void SetAssosciativeCache<CacheLevel::L1>::tick() {
  ticks_++;

  // while () processOutGoingToLMem
  while (queueToLowerLevel_.size() &&
         ticks_ >= queueToLowerLevel_.front().endLatency) {
    auto& clatpkt = queueToLowerLevel_.front();
    auto req = clatpkt.payload;
    bottomPort_->send(req);
    queueToLowerLevel_.pop();
  }

  // Process all requests that can be responded to.
  auto pBuffItr = processBuffer_.begin();
  while (pBuffItr != processBuffer_.end()) {
    auto& cpkt = *pBuffItr;
    if (ticks_ < cpkt.endLatency) {
      pBuffItr++;
    } else {
      auto& req = cpkt.payload;
      if (req.type_ == MemoryAccessType::READ) {
        queueToCpu_.push(doRead(req, cpkt.clineIdx));
      } else {
        queueToCpu_.push(doWrite(req, cpkt.clineIdx));
      }
      pBuffItr = processBuffer_.erase(pBuffItr);
    }
  }

  auto itr = mshrPrimaryReqs_.begin();
  while (mshrPrimaryReqs_.size() && itr != mshrPrimaryReqs_.end()) {
    auto clatpkt = *itr;
    auto& req = clatpkt.payload;
    auto& cline = cacheLines_[clatpkt.clineIdx];

    if (!cline.isBusy()) {
      auto& mshrReg = mshr_.getMshrReg(req.paddr_, clw_);
      mshrReg.dirty = cline.isDirty();
      mshrReg.valid = cline.isValid();

      req.clineAddr_ = cline.getPaddr();

      if (cline.isDirty()) {
        req.isDirty = true;
        req.payload_ = std::vector<char>(cline.begin(), cline.end());
      }

      cline.setBusy();
      queueToLowerLevel_.push(clatpkt);

      itr = mshrPrimaryReqs_.erase(itr);
    } else {
      itr++;
    }
  }

  // while () processPendingReqs
  while (waitQueue_.size() && ticks_ >= waitQueue_.front().endLatency) {
    auto clatpkt = waitQueue_.front();
    auto& req = clatpkt.payload;
    AccessInfo info = checkHit(req);
    if (info.hit && info.valid) {
      uint64_t latency = ticks_ + latencyInfo_.accessLatency;
      processBuffer_.push_back({req, latency, info.lineIdx});
      waitQueue_.pop();
      continue;
    }

    uint64_t basePaddr = downAlign(req.paddr_, clw_);
    // Primary miss i.e there is no entry in the MSHR corresponding to the
    // basePAddr
    if (!mshr_.inMshr(basePaddr)) {
      // Use replacement policy to find a new replacement.
      uint16_t set = tagScheme_->calcSetIndex(req);
      uint16_t clineIdxInSet = replacementPolicy_.findReplacement(set);
      uint16_t clineIdx = clineIdxInSet + (set * assosciativity_);
      auto& cline = cacheLines_[clineIdx];

      req.clineAddr_ = cline.getPaddr();

      // Construct the AccessInfo struct and determine if replacement is dirty.
      info = {cline.isValid(), cline.isDirty(), false, clineIdx};

      if (cline.isBusy()) {
        clatpkt.clineIdx = clineIdx;
        mshr_.allocateMshr(req, basePaddr, clw_, info, true);
        mshrPrimaryReqs_.push_back(clatpkt);
        waitQueue_.pop();
        continue;
      }

      cline.setBusy();

      // If replacement is dirty, copy the cache line into CacheInfo struct
      if (cline.isDirty()) {
        req.isDirty = 1;
        req.payload_ = std::vector<char>(cline.begin(), cline.end());
      }
      clatpkt.endLatency = ticks_ + latencyInfo_.missPenalty;
      // Put request into outgoing queue towards lower memory hierarchy
      queueToLowerLevel_.push(clatpkt);
    }
    mshr_.allocateMshr(req, basePaddr, clw_, info, false);
    waitQueue_.pop();
  }

  while (queueToCpu_.size()) {
    auto& cpuPkt = queueToCpu_.front();
    cpuPort_->send(cpuPkt);
    queueToCpu_.pop();
  }
}

CPUMemoryPacket SetAssosciativeCache<CacheLevel::L1>::doRead(
    MemoryHierarchyPacket& memPkt, uint16_t clineIdx) {
  auto itr = reqMap_.find(memPkt.cpuPktId_);
  auto cpuPkt = itr->second;

  auto& cline = cacheLines_[clineIdx];
  uint16_t byteOffset = tagScheme_->calcByteOffset(memPkt);

  uint16_t setNum = tagScheme_->calcSetIndex(memPkt);
  cpuPkt.payload_ = std::vector<char>(
      cline.begin() + byteOffset, cline.begin() + byteOffset + cpuPkt.size_);
  replacementPolicy_.updateUsage(setNum, clineIdx);

  reqMap_.erase(itr);
  return cpuPkt;
}

CPUMemoryPacket SetAssosciativeCache<CacheLevel::L1>::doWrite(
    MemoryHierarchyPacket& memPkt, uint16_t clineIdx) {
  auto itr = reqMap_.find(memPkt.cpuPktId_);
  auto cpuPkt = itr->second;

  auto& cline = cacheLines_[clineIdx];
  uint16_t byteOffset = tagScheme_->calcByteOffset(memPkt);
  uint16_t setNum = tagScheme_->calcSetIndex(memPkt);
  cline.supplyData(cpuPkt.payload_, byteOffset);
  cline.setDirty();

  replacementPolicy_.updateUsage(setNum, clineIdx);
  reqMap_.erase(itr);
  return cpuPkt;
}

void SetAssosciativeCache<CacheLevel::L1>::handleResponseFromBottomPort(
    MemoryHierarchyPacket& pkt) {
  uint64_t downAlignedAddr = downAlign(pkt.paddr_, clw_);
  MshrReg mshrReg = mshr_.getAndRemoveMshrReg(downAlignedAddr, clw_);
  uint16_t clineIdx = mshrReg.clineIdx;

  auto& cline = cacheLines_[clineIdx];
  uint64_t tag = tagScheme_->calcTag(pkt);

  cline.setTag(tag);
  cline.setPaddr(downAlignedAddr);
  cline.setValid();
  cline.supplyData(pkt.payload_, 0);
  cline.setNotBusy();

  MshrEntry& primaryEntry = mshrReg.getPrimaryEntry();
  primaryEntry.memPacket = pkt;

  for (auto& mshrEntry : mshrReg.entries) {
    processBuffer_.push_back({mshrEntry.memPacket, 0, clineIdx});
  }
}

/**
std::shared_ptr<Port<MemoryHierarchyPacket>>
SetAssosciativeCache<CacheLevel::LL>::initTopPort() {
  topPort_ = std::make_shared<Port<MemoryHierarchyPacket>>();
  auto fn = [this](MemoryHierarchyPacket mpkt) { accessCache(mpkt); };
  topPort_->registerReceiver(fn);
  return topPort_;
}

std::shared_ptr<Port<MemoryHierarchyPacket>>
SetAssosciativeCache<CacheLevel::LL>::initBottomPort() {
  bottomPort_ = std::make_shared<Port<MemoryHierarchyPacket>>();
  // TODO: Complete function definition.
  return bottomPort_;
}

std::shared_ptr<Port<CPUMemoryPacket>>
SetAssosciativeCache<CacheLevel::LL>::initCpuPort() {
  std::cerr << "[SimEng:SetAssosciativeCache] Cannot initiate a cpu port on a "
               "cache that is not L1. Non L1 caches can only have a bottom "
               "port and top port."
            << std::endl;
  std::exit(1);
};

void BaseSetAssosciativeCache::accessCache(MemoryHierarchyPacket& pkt) {
  uint64_t latency = ticks_ + latencyInfo_.hitLatency;
  waitQueue_.push({pkt, latency});
}

void SetAssosciativeCache<CacheLevel::LL>::tick() {
  ticks_++;

  // while () processOutGoingToLMem
  while (queueToLowerLevel_.size() &&
         ticks_ >= queueToLowerLevel_.front().endLatency) {
    auto& clatpkt = queueToLowerLevel_.front();
    auto req = clatpkt.payload;
    bottomPort_->send(req);
    queueToLowerLevel_.pop();
  }

  // Process all Mshr requests.
  while (mshrSecondaryQueue_.size()) {
    auto& cpkt = mshrSecondaryQueue_.front();
    auto& req = cpkt.payload;
    if (req.type_ == MemoryAccessType::READ) {
      doRead(req, cpkt.clineIdx);
    } else {
      doWrite(req, cpkt.clineIdx);
    }
    queueToTopLevel_.push(cpkt);
    mshrSecondaryQueue_.pop();
  }

  auto itr = mshrPrimaryReqs_.begin();
  while (mshrPrimaryReqs_.size() && itr != mshrPrimaryReqs_.end()) {
    auto& clatpkt = *itr;
    auto& req = clatpkt.payload;
    auto& cline = cacheLines_[clatpkt.clineIdx];

    if (!cline.isBusy()) {
      auto& mshrReg = mshr_.getMshrReg(req.paddr_, clw_);
      mshrReg.dirty = cline.isDirty();
      mshrReg.valid = cline.isValid();

      req.clineAddr_ = cline.getPaddr();

      if (cline.isDirty()) {
        req.payload_ = std::vector<char>(cline.begin(), cline.end());
      }

      cline.setBusy();
      itr = mshrPrimaryReqs_.erase(itr);
      queueToLowerLevel_.push(clatpkt);
    } else {
      itr++;
    }
  }

  // while () processPendingReqs
  while (waitQueue_.size() && ticks_ >= waitQueue_.front().endLatency) {
    auto& clatpkt = waitQueue_.front();
    auto& req = clatpkt.payload;
    AccessInfo info = checkHit(req);

    if (info.hit && info.valid) {
      uint64_t latency = ticks_ + latencyInfo_.accessLatency;
      hitQueue_.push({req, latency, info.lineIdx});
      waitQueue_.pop();
      continue;
    }

    uint64_t basePaddr = downAlign(req.paddr_, clw_);
    // Primary miss i.e there is no entry in the MSHR corresponding to the
    // basePAddr
    if (!mshr_.inMshr(basePaddr)) {
      // Use replacement policy to find a new replacement.
      uint16_t set = tagScheme_->calcSetIndex(req);
      uint16_t clineIdxInSet = replacementPolicy_.findReplacement(set);
      uint16_t clineIdx = clineIdxInSet + (set * assosciativity_);
      auto& cline = cacheLines_[clineIdx];

      req.clineAddr_ = cline.getPaddr();

      // Construct the AccessInfo struct and determine if replacement is dirty.
      info = {cline.isValid(), cline.isDirty(), false, clineIdx};

      if (cline.isBusy()) {
        clatpkt.clineIdx = clineIdx;
        mshr_.allocateMshr(req, basePaddr, clw_, info, true);
        mshrPrimaryReqs_.push_back(clatpkt);
        waitQueue_.pop();
        continue;
      };

      cline.setBusy();

      // If replacement is dirty, copy the cache line into CacheInfo struct
      if (cline.isDirty()) {
        req.payload_ = std::vector<char>(cline.begin(), cline.end());
      }
      // BufferIndex is -1 because this is a primary miss and we will have send
      // the MemPacket to a lower memory level. This memory packet will be
      // removed from the L1 request buffer in the while loop which deals with
      // the queueToLowerMem_ queue.
      clatpkt.endLatency = ticks_ + latencyInfo_.missPenalty;
      // Put request into outgoing queue towards lower memory hierarchy
      queueToLowerLevel_.push(clatpkt);
    }
    mshr_.allocateMshr(clatpkt.payload, basePaddr, clw_, info, false);
    waitQueue_.pop();
  }

  // while () processHits
  while (hitQueue_.size() && ticks_ >= hitQueue_.front().endLatency) {
    auto& clatpkt = hitQueue_.front();
    auto& req = clatpkt.payload;
    if (req.type_ == MemoryAccessType::READ) {
      doRead(req, clatpkt.clineIdx);
    } else {
      doWrite(req, clatpkt.clineIdx);
    }
    queueToTopLevel_.push(clatpkt);
    hitQueue_.pop();
  }

  // while () processOutGoingToCpu
  while (queueToTopLevel_.size()) {
    auto& cpkt = queueToTopLevel_.front();
    auto& req = cpkt.payload;
    topPort_->send(req);
    queueToTopLevel_.pop();
  }
}

template <CacheLevel TValue>
void SetAssosciativeCache<TValue>::doRead(MemoryHierarchyPacket& req,
                                          uint16_t clineIdx){};

template <>
void SetAssosciativeCache<CacheLevel::L1>::doRead(MemoryHierarchyPacket& req,
                                                  uint16_t clineIdx){};

*/

/**

template <>

*/

/**
template <CacheLevel TValue>
void SetAssosciativeCache<TValue>::doRead(MemoryHierarchyPacket& memPkt,
                                          uint16_t clineIdx) {
  // TODO: assert size assert
  auto& cline = cacheLines_[clineIdx];
  uint16_t setNum = tagScheme_->calcSetIndex(memPkt);
  memPkt.payload_ = std::vector<char>(cline.begin(), cline.end());
  replacementPolicy_.updateUsage(setNum, clineIdx);
}

template <CacheLevel TValue>
void SetAssosciativeCache<TValue>::doWrite(MemoryHierarchyPacket& memPkt,
                                           uint16_t clineIdx) {
  // TODO: assert size assert
  auto& cline = cacheLines_[clineIdx];
  uint16_t setNum = tagScheme_->calcSetIndex(memPkt);
  cline.supplyData(memPkt.payload_, 0);
  cline.setDirty();
  replacementPolicy_.updateUsage(setNum, clineIdx);
}

template <CacheLevel TValue>
void SetAssosciativeCache<TValue>::handleResponseFromBottomPort(
    MemoryHierarchyPacket& pkt) {
  uint64_t downAlignedAddr = downAlign(pkt.paddr_, clw_);
  MshrReg mshrReg = mshr_.getAndRemoveMshrReg(downAlignedAddr, clw_);
  uint16_t clineIdx = mshrReg.clineIdx;

  auto& cline = cacheLines_[clineIdx];
  uint64_t tag = tagScheme_->calcTag(pkt);

  cline.setTag(tag);
  cline.setPaddr(downAlignedAddr);
  cline.setValid();
  cline.supplyData(pkt.payload_, 0);
  cline.setNotBusy();

  MshrEntry& primaryEntry = mshrReg.getPrimaryEntry();
  primaryEntry.memPacket = pkt;

  for (auto& mshrEntry : mshrReg.entries) {
    mshrSecondaryQueue_.push({mshrEntry.memPacket, 0, clineIdx});
  }
}

*/

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
