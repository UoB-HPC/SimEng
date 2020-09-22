#include "simeng/pipeline/LoadStoreQueue.hh"

#include <cassert>
#include <cstring>

#include <iostream>

namespace simeng {
namespace pipeline {

/** Check whether requests `a` and `b` overlap. */
bool requestsOverlap(MemoryAccessTarget a, MemoryAccessTarget b) {
  // Check whether one region ends before the other begins, implying no overlap,
  // and negate
  return !(a.address + a.size <= b.address || b.address + b.size <= a.address);
}

LoadStoreQueue::LoadStoreQueue(
    unsigned int maxCombinedSpace, MemoryInterface& memory,
    span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
    std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
      uint64_t L1Bandwidth, uint8_t permittedRequests,
      uint8_t permittedLoads, uint8_t permittedStores)
    : completionSlots_(completionSlots),
      forwardOperands_(forwardOperands),
      maxCombinedSpace_(maxCombinedSpace),
      combined_(true),
      memory_(memory),
      L1Bandwidth_(L1Bandwidth),
      totalLimit_(permittedRequests) {
  // Set per-cycle limits for each request type
  reqLimits_ = {permittedLoads, permittedStores};
};

LoadStoreQueue::LoadStoreQueue(
    unsigned int maxLoadQueueSpace, unsigned int maxStoreQueueSpace,
    MemoryInterface& memory,
    span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
    std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
      uint64_t L1Bandwidth, uint8_t permittedRequests,
      uint8_t permittedLoads, uint8_t permittedStores)
    : completionSlots_(completionSlots),
      forwardOperands_(forwardOperands),
      maxLoadQueueSpace_(maxLoadQueueSpace),
      maxStoreQueueSpace_(maxStoreQueueSpace),
      combined_(false),
      memory_(memory),
      L1Bandwidth_(L1Bandwidth),
      totalLimit_(permittedRequests) {
  // Set per-cycle limits for each request type
  reqLimits_ = {permittedLoads, permittedStores};
};

unsigned int LoadStoreQueue::getLoadQueueSpace() const {
  if (combined_) {
    return getCombinedSpace();
  } else {
    return getLoadQueueSplitSpace();
  }
}
unsigned int LoadStoreQueue::getStoreQueueSpace() const {
  if (combined_) {
    return getCombinedSpace();
  } else {
    return getStoreQueueSplitSpace();
  }
}
unsigned int LoadStoreQueue::getTotalSpace() const {
  if (combined_) {
    return getCombinedSpace();
  } else {
    return getLoadQueueSplitSpace() + getStoreQueueSplitSpace();
  }
}

unsigned int LoadStoreQueue::getLoadQueueSplitSpace() const {
  return maxLoadQueueSpace_ - loadQueue_.size();
}
unsigned int LoadStoreQueue::getStoreQueueSplitSpace() const {
  return maxStoreQueueSpace_ - storeQueue_.size();
}
unsigned int LoadStoreQueue::getCombinedSpace() const {
  return maxCombinedSpace_ - loadQueue_.size() - storeQueue_.size();
}

bool LoadStoreQueue::withinLoadWindow(const std::shared_ptr<Instruction>& insn) const {
  if(insn->getSequenceId() <= loadWindowSeq_) {
    return true;
  }
  return false;
}
bool LoadStoreQueue::withinStoreWindow(const std::shared_ptr<Instruction>& insn) const {
  if(insn->getSequenceId() <= storeWindowSeq_) {
    return true;
  }
  return false;
}

void LoadStoreQueue::addLoad(const std::shared_ptr<Instruction>& insn) {
  // uint8_t entries = insn->isPair() ? 2 : 1;
  // for(int i = 0; i < entries; i++){
    if(loadQueue_.size() - 1 == loadWindow_) {
      loadWindowSeq_ = insn->getSequenceId();
    }
    loadQueue_.push_back(insn);
  // }
}
void LoadStoreQueue::addStore(const std::shared_ptr<Instruction>& insn) {
  // uint8_t entries = insn->isPair() ? 2 : 1;
  // for(int i = 0; i < entries; i++){
    if(storeQueue_.size() - 1 == storeWindow_) {
      storeWindowSeq_ = insn->getSequenceId();
    }
    storeQueue_.push_back(insn);
  // }
  // addLoad(insn);
}

void LoadStoreQueue::startLoad(const std::shared_ptr<Instruction>& insn) {
  const auto& addresses = insn->getGeneratedAddresses();
  if(addresses.size() == 0) {
    insn->execute();
    completedLoads_.push(insn);
  } else {
    for (size_t i = 0; i < addresses.size(); i++) {
      requestQueue_.push_back({i, insn});
    }
    requestedLoads_.emplace(insn->getSequenceId(), insn);
  }
}

bool LoadStoreQueue::commitStore(const std::shared_ptr<Instruction>& uop) {
  assert(storeQueue_.size() > 0 &&
         "Attempted to commit a store from an empty queue");
  assert(storeQueue_.front()->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a store that wasn't present at the front of the "
         "store queue");
  const auto& addresses = uop->getGeneratedAddresses();
  const auto& data = uop->getData();
  for (size_t i = 0; i < addresses.size(); i++) {
    memory_.requestWrite(addresses[i], data[i]);
    requestQueue_.push_back({i, uop});
  }

  // Check all loads that have requested memory
  violatingLoad_ = nullptr;
  for (const auto& load : requestedLoads_) {
    // Skip loads that are younger than the oldest violating load
    if (violatingLoad_ &&
        load.second->getSequenceId() > violatingLoad_->getSequenceId())
      continue;

    const auto& loadedAddresses = load.second->getGeneratedAddresses();
    // Iterate over store addresses
    for (const auto& storeReq : addresses) {
      // Iterate over load addresses
      for (const auto& loadReq : loadedAddresses) {
        // Check for overlapping requests, and flush if discovered
        if (requestsOverlap(storeReq, loadReq)) {
          violatingLoad_ = load.second;
        }
      }
    }
  }

  // if(uop->isPair()) storeQueue_.pop_front();
  storeQueue_.pop_front();
  // storeWindowSeq_ = UINT64_MAX;
  // if(storeQueue_.size() > storeWindow_) {
  //   storeWindowSeq_ = storeQueue_[storeWindow_]->getSequenceId();
  // }

  // auto it = loadQueue_.begin();
  // while (it != loadQueue_.end()) {
  //   auto& entry = *it;
  //   if (entry->isStore()) {
  //     if(uop->isPair()) it = loadQueue_.erase(it);
  //     it = loadQueue_.erase(it);
  //     break;
  //   } else {
  //     it++;
  //   }
  // }
  // loadWindowSeq_ = UINT64_MAX;
  // if(loadQueue_.size() > loadWindow_) {
  //   loadWindowSeq_ = loadQueue_[loadWindow_]->getSequenceId();
  // }

  return violatingLoad_ != nullptr;
}

void LoadStoreQueue::commitLoad(const std::shared_ptr<Instruction>& uop) {
  assert(loadQueue_.size() > 0 &&
         "Attempted to commit a load from an empty queue");
  assert(loadQueue_.front()->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a load that wasn't present at the front of the "
         "load queue");

  auto it = loadQueue_.begin();
  while (it != loadQueue_.end()) {
    auto& entry = *it;
    if (entry->isLoad()) {
      requestedLoads_.erase(entry->getSequenceId()); 
      // if(uop->isPair()) it = loadQueue_.erase(it);     
      it = loadQueue_.erase(it);
      break;
    } else {
      it++;
    }
  }
  // loadWindowSeq_ = UINT64_MAX;
  // if(loadQueue_.size() > loadWindow_) {
  //   loadWindowSeq_ = loadQueue_[loadWindow_]->getSequenceId();
  // }
}

void LoadStoreQueue::purgeFlushed() {
  auto it = loadQueue_.begin();
  while (it != loadQueue_.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      requestedLoads_.erase(entry->getSequenceId());
      // if(entry->isPair()) it = loadQueue_.erase(it);
      it = loadQueue_.erase(it);
    } else {
      it++;
    }
  }
  // loadWindowSeq_ = UINT64_MAX;
  // if(loadQueue_.size() > loadWindow_) {
  //   loadWindowSeq_ = loadQueue_[loadWindow_]->getSequenceId();
  // }

  it = storeQueue_.begin();
  while (it != storeQueue_.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      // if(entry->isPair()) it = storeQueue_.erase(it);
      it = storeQueue_.erase(it);
    } else {
      it++;
    }
  }
  // storeWindowSeq_ = UINT64_MAX;
  // if(storeQueue_.size() > storeWindow_) {
  //   storeWindowSeq_ = storeQueue_[storeWindow_]->getSequenceId();
  // }

  auto it2 = requestQueue_.begin();
  while (it2 != requestQueue_.end()) {
    auto& entry = it2->second;
    if (entry->isFlushed()) {
      it2 = requestQueue_.erase(it2);
    } else {
      it2++;
    }
  }
}

void LoadStoreQueue::tick() {
  // Send memory requests adhering to set bandwidth and number of permitted loads per cycle
  uint64_t dataTransfered = 0;
  std::vector<uint8_t> reqCounts = {0, 0};
  uint64_t seq = 0;
  while(requestQueue_.size() > 0) {
    uint8_t isWrite = 0;
    auto& entry = requestQueue_.front();
    const auto& addresses = entry.second->getGeneratedAddresses();
    if(entry.second->isStore()) { isWrite = 1; }
    if(entry.second->getSequenceId() != seq || !entry.second->isSVE()) { reqCounts[isWrite]++; }

    if(reqCounts[isWrite] > reqLimits_[isWrite] || reqCounts[isWrite] + reqCounts[!isWrite] > totalLimit_) { break; }
    else if(dataTransfered + addresses[entry.first].size > L1Bandwidth_) { break; }

    dataTransfered += addresses[entry.first].size;
    seq = entry.second->getSequenceId();
    if(!isWrite) { memory_.requestRead(addresses[entry.first], entry.second->getSequenceId()); }
    requestQueue_.pop_front();
  }

  // Process completed read requests
  for (const auto& response : memory_.getCompletedReads()) {
    auto address = response.target.address;
    const auto& data = response.data;

    // TODO: Detect and handle non-fatal faults (e.g. page fault)

    // Find instruction that requested the memory read
    auto itr = requestedLoads_.find(response.requestId);
    if (itr == requestedLoads_.end()) {
      continue;
    }

    // Supply data to the instruction and execute if it is ready
    auto load = itr->second;
    load->supplyData(address, data);
    if (load->hasAllData()) {
      // This load has completed
      load->execute();
      completedLoads_.push(load);
    }
  }
  memory_.clearCompletedReads();

  // Pop from the front of the completed loads queue and send to writeback
  size_t count = 0;
  while (completedLoads_.size() > 0 && count < completionSlots_.size()) {
    const auto& insn = completedLoads_.front();

    // Forward the results
    forwardOperands_(insn->getDestinationRegisters(), insn->getResults());

    completionSlots_[count].getTailSlots()[0] = std::move(insn);

    completedLoads_.pop();

    count++;
  }
}

std::shared_ptr<Instruction> LoadStoreQueue::getViolatingLoad() const {
  return violatingLoad_;
}

bool LoadStoreQueue::isCombined() const { return combined_; }

}  // namespace pipeline
}  // namespace simeng
