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
    uint8_t L1Bandwidth, uint8_t permittedRequests, uint8_t permittedLoads,
    uint8_t permittedStores)
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
    uint8_t L1Bandwidth, uint8_t permittedRequests, uint8_t permittedLoads,
    uint8_t permittedStores)
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

void LoadStoreQueue::addLoad(const std::shared_ptr<Instruction>& insn) {
  loadQueue_.push_back(insn);
}
void LoadStoreQueue::addStore(const std::shared_ptr<Instruction>& insn) {
  storeQueue_.push_back(insn);
}

void LoadStoreQueue::startLoad(const std::shared_ptr<Instruction>& insn) {
  const auto& addresses = insn->getGeneratedAddresses();
  if (addresses.size() == 0) {
    insn->execute();
    completedLoads_.push(insn);
  } else {
    if (insn->shouldSplitRequests()) {
      std::cout << "SPLIT LOAD REQ:" << insn->getSequenceId() << ":" << std::hex
                << insn->getInstructionAddress() << std::dec << ":"
                << tickCounter_ + insn->getLSQLatency() << ":{";
      for (size_t i = 0; i < addresses.size(); i++) {
        std::cout << (addresses.data() + i)->address << ", ";
        requestQueue_.push_back({tickCounter_ + insn->getLSQLatency(),
                                 {addresses.data() + i, 1},
                                 insn->getSequenceId()});
      }
      std::cout << "}:" << insn->getSequenceId() << std::endl;
    } else {
      std::cout << "COMBINED LOAD REQ:" << insn->getSequenceId() << ":"
                << std::hex << insn->getInstructionAddress() << std::dec << ":"
                << tickCounter_ + insn->getLSQLatency() << ":{";
      for (size_t i = 0; i < addresses.size(); i++) {
        std::cout << (addresses.data() + i)->address << ", ";
      }
      std::cout << "}:" << insn->getSequenceId() << std::endl;
      requestQueue_.push_back({tickCounter_ + insn->getLSQLatency(), addresses,
                               insn->getSequenceId()});
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
  if (uop->shouldSplitRequests()) {
    std::cout << "SPLIT WRITE REQ:" << uop->getSequenceId() << ":" << std::hex
              << uop->getInstructionAddress() << std::dec << ":"
              << tickCounter_ + uop->getLSQLatency() << ":{";
    for (size_t i = 0; i < addresses.size(); i++) {
      std::cout << (addresses.data() + i)->address << ", ";
      memory_.requestWrite(addresses[i], data[i]);
      requestQueue_.push_back({tickCounter_ + uop->getLSQLatency(),
                               {addresses.data() + i, 1},
                               uop->getSequenceId(),
                               true});
    }
    std::cout << "}:" << uop->getSequenceId() << std::endl;
  } else {
    std::cout << "COMBINED WRITE REQ:" << uop->getSequenceId() << ":"
              << std::hex << uop->getInstructionAddress() << std::dec << ":"
              << tickCounter_ + uop->getLSQLatency() << ":{";
    for (size_t i = 0; i < addresses.size(); i++) {
      std::cout << (addresses.data() + i)->address << ", ";
    }
    std::cout << "}:" << uop->getSequenceId() << std::endl;
    requestQueue_.push_back({tickCounter_ + uop->getLSQLatency(), addresses,
                             uop->getSequenceId(), true});
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

  storeQueue_.pop_front();

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
      it = loadQueue_.erase(it);
      break;
    } else {
      it++;
    }
  }
}

void LoadStoreQueue::purgeFlushed() {
  uint64_t earliestFlush = UINT64_MAX;
  auto it = loadQueue_.begin();
  while (it != loadQueue_.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      earliestFlush = (entry->getSequenceId() < earliestFlush)
                          ? entry->getSequenceId()
                          : earliestFlush;
      requestedLoads_.erase(entry->getSequenceId());
      it = loadQueue_.erase(it);
    } else {
      it++;
    }
  }

  it = storeQueue_.begin();
  while (it != storeQueue_.end()) {
    auto& entry = *it;
    if (entry->isFlushed()) {
      earliestFlush = (entry->getSequenceId() < earliestFlush)
                          ? entry->getSequenceId()
                          : earliestFlush;
      it = storeQueue_.erase(it);
    } else {
      it++;
    }
  }

  auto it2 = requestQueue_.begin();
  while (it2 != requestQueue_.end()) {
    if (it2->callingSeqId >= earliestFlush) {
      it2 = requestQueue_.erase(it2);
    } else {
      it2++;
    }
  }
}

void LoadStoreQueue::tick() {
  tickCounter_++;
  // Send memory requests adhering to set bandwidth and number of permitted
  // requests per cycle
  uint64_t dataTransfered = 0;
  std::vector<uint8_t> reqCounts = {0, 0};
  while (requestQueue_.size() > 0) {
    uint8_t isWrite = 0;
    auto& entry = requestQueue_.front();
    std::cout << entry.callingSeqId << ":";
    if (entry.readyAt <= tickCounter_) {
      if (entry.isWrite) {
        isWrite = 1;
      }
      reqCounts[isWrite]++;

      if (reqCounts[isWrite] > reqLimits_[isWrite] ||
          reqCounts[isWrite] + reqCounts[!isWrite] > totalLimit_) {
        std::cout << "EXCEEDED REQ COUNT" << std::endl;
        break;
      }
      if (dataTransfered >= L1Bandwidth_) {
        std::cout << "EXCEEDED BANDWIDTH" << std::endl;
        break;
      }
      std::cout << "{";
      for (const MemoryAccessTarget& req : entry.reqAddresses) {
        dataTransfered += req.size;
        if (!isWrite) {
          std::cout << req.address << ", ";
          memory_.requestRead(req, entry.callingSeqId);
        }
      }
      std::cout << "}" << std::endl;
      requestQueue_.pop_front();
    } else {
      std::cout << "NOT READY" << std::endl;
    }
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
