#include "simeng/memory/hierarchy/SetAssosciativeCache.hh"

#include <algorithm>
#include <bitset>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <memory>
#include <vector>

#include "simeng/memory/MemPacket.hh"
#include "simeng/memory/hierarchy/RequestBuffer.hh"
#include "simeng/util/Math.hh"

namespace simeng {
namespace memory {
namespace hierarchy {

std::shared_ptr<Port<std::unique_ptr<MemPacket>>>
SetAssosciativeCache::initTopPort() {
  topPort_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> pkt) { accessCache(pkt); };
  topPort_->registerReceiver(fn);
  return topPort_;
}

std::shared_ptr<Port<std::unique_ptr<MemPacket>>>
SetAssosciativeCache::initBottomPort() {
  bottomPort_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> pkt) {
    handleResponseFromBottomPort(pkt);
  };
  bottomPort_->registerReceiver(fn);
  return bottomPort_;
}

void SetAssosciativeCache::invalidateAll() {
  for (auto& cacheLine : cacheLines_) {
    cacheLine.setInvalid();
  }
}

void SetAssosciativeCache::accessCache(std::unique_ptr<MemPacket>& pkt) {
  RequestBufferIndex idx = requestBuffer_.allocate(pkt);
  uint64_t latency = ticks_ + latencyInfo_.hitLatency;
  waitQueue_.push({idx, latency});
}

AccessInfo SetAssosciativeCache::checkHit(std::unique_ptr<MemPacket>& pkt) {
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

void SetAssosciativeCache::tick() {
  ticks_++;

  // while () processOutGoingToLMem
  while (queueToLowerLevel_.size() &&
         ticks_ >= queueToLowerLevel_.front().endLatency) {
    auto& clatpkt = queueToLowerLevel_.front();
    auto req = requestBuffer_.remove(clatpkt.reqBufIdx);
    bottomPort_->send(std::move(req));
    queueToLowerLevel_.pop();
  }

  // Process all Mshr requests.
  while (mshrSecondaryQueue_.size()) {
    auto& cpkt = mshrSecondaryQueue_.front();
    auto& req = requestBuffer_[cpkt.reqBufIdx];
    if (req->isRead()) {
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
    auto& req = requestBuffer_[clatpkt.reqBufIdx];
    auto& cline = cacheLines_[clatpkt.clineIdx];

    if (!cline.isBusy()) {
      auto& mshrReg = mshr_.getMshrReg(req->cinfo.basePaddr, clw_);
      mshrReg.dirty = cline.isDirty();
      mshrReg.valid = cline.isValid();

      req->cinfo.clineAddr = cline.getPaddr();

      if (cline.isDirty()) {
        req->cinfo.dirty = 1;
        req->cinfo.data = std::vector<char>(cline.begin(), cline.end());
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
    uint32_t reqBufferIdx = clatpkt.reqBufIdx;
    auto& req = requestBuffer_[reqBufferIdx];
    AccessInfo info = checkHit(req);

    if (info.hit && info.valid) {
      uint64_t latency = ticks_ + latencyInfo_.accessLatency;
      hitQueue_.push({reqBufferIdx, latency, info.lineIdx});
      waitQueue_.pop();
      continue;
    }

    uint64_t basePaddr = downAlign(req->paddr_, clw_);
    // Primary miss i.e there is no entry in the MSHR corresponding to the
    // basePAddr
    req->cinfo.basePaddr = basePaddr;
    req->cinfo.size = clw_;

    if (!mshr_.inMshr(basePaddr)) {
      // Use replacement policy to find a new replacement.
      uint16_t set = tagScheme_->calcSetIndex(req);
      uint16_t clineIdxInSet = replacementPolicy_.findReplacement(set);
      uint16_t clineIdx = clineIdxInSet + (set * assosciativity_);
      auto& cline = cacheLines_[clineIdx];

      req->cinfo.clineAddr = cline.getPaddr();

      // Construct the AccessInfo struct and determine if replacement is dirty.
      info = {cline.isValid(), cline.isDirty(), false, clineIdx};

      if (cline.isBusy()) {
        clatpkt.clineIdx = clineIdx;
        mshr_.allocateMshr(reqBufferIdx, basePaddr, clw_, info, true);
        mshrPrimaryReqs_.push_back(clatpkt);
        waitQueue_.pop();
        continue;
      };

      cline.setBusy();

      // If replacement is dirty, copy the cache line into CacheInfo struct
      if (cline.isDirty()) {
        req->cinfo.dirty = 1;
        req->cinfo.data = std::vector<char>(cline.begin(), cline.end());
      }
      // BufferIndex is -1 because this is a primary miss and we will have send
      // the MemPacket to a lower memory level. This memory packet will be
      // removed from the L1 request buffer in the while loop which deals with
      // the queueToLowerMem_ queue.
      reqBufferIdx = -1;
      clatpkt.endLatency = ticks_ + latencyInfo_.missPenalty;
      // Put request into outgoing queue towards lower memory hierarchy
      queueToLowerLevel_.push(clatpkt);
    }
    mshr_.allocateMshr(reqBufferIdx, basePaddr, clw_, info, false);
    waitQueue_.pop();
  }

  // while () processHits
  while (hitQueue_.size() && ticks_ >= hitQueue_.front().endLatency) {
    auto& clatpkt = hitQueue_.front();
    auto& req = requestBuffer_[clatpkt.reqBufIdx];
    if (req->isRead()) {
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
    auto req = requestBuffer_.remove(cpkt.reqBufIdx);
    topPort_->send(std::move(req));
    queueToTopLevel_.pop();
  }
}

void SetAssosciativeCache::doRead(std::unique_ptr<MemPacket>& memPkt,
                                  uint16_t clineIdx) {
  // TODO: assert size assert
  auto& cline = cacheLines_[clineIdx];
  uint16_t byteOffset = tagScheme_->calcByteOffset(memPkt);
  uint16_t setNum = tagScheme_->calcSetIndex(memPkt);
  const char* src = cline.begin() + byteOffset;
  memPkt->turnIntoReadResponse(std::vector<char>(src, src + memPkt->size_));
  replacementPolicy_.updateUsage(setNum, clineIdx);
}

void SetAssosciativeCache::doWrite(std::unique_ptr<MemPacket>& memPkt,
                                   uint16_t clineIdx) {
  // TODO: assert size assert
  auto& cline = cacheLines_[clineIdx];
  uint16_t byteOffset = tagScheme_->calcByteOffset(memPkt);
  uint16_t setNum = tagScheme_->calcSetIndex(memPkt);
  cline.supplyData(memPkt->payload(), byteOffset);
  memPkt->turnIntoWriteResponse();
  cline.setDirty();
  replacementPolicy_.updateUsage(setNum, clineIdx);
}

void SetAssosciativeCache::handleResponseFromBottomPort(
    std::unique_ptr<MemPacket>& pkt) {
  MshrReg mshrReg = mshr_.getAndRemoveMshrReg(pkt->cinfo.basePaddr, clw_);
  uint16_t clineIdx = mshrReg.clineIdx;

  auto& cline = cacheLines_[clineIdx];
  uint64_t tag = tagScheme_->calcTag(pkt);

  cline.setTag(tag);
  cline.setPaddr(pkt->cinfo.basePaddr);
  cline.setValid();
  cline.supplyData(pkt->cinfo.data, 0);
  cline.setNotBusy();

  MshrEntry& primaryEntry = mshrReg.getPrimaryEntry();
  primaryEntry.reqBufIdx = requestBuffer_.allocate(pkt);

  for (auto& mshrEntry : mshrReg.entries) {
    mshrSecondaryQueue_.push({mshrEntry.reqBufIdx, 0, clineIdx});
  }
}

}  // namespace hierarchy
}  // namespace memory
}  // namespace simeng
