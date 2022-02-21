#include "simeng/pipeline/LoadStoreQueue.hh"

#include <array>
#include <cassert>
#include <cstring>

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
      totalLimit_(permittedRequests),
      // Set per-cycle limits for each request type
      reqLimits_{permittedLoads, permittedStores} {};

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
      totalLimit_(permittedRequests),
      // Set per-cycle limits for each request type
      reqLimits_{permittedLoads, permittedStores} {};

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
  storeQueue_.push_back({insn, {}});
}

void LoadStoreQueue::startLoad(const std::shared_ptr<Instruction>& insn) {
  const auto& ld_addresses = insn->getGeneratedAddresses();
  if (ld_addresses.size() == 0) {
    // Early execution if not addresses need to be accessed
    insn->execute();
    completedLoads_.push(insn);
  } else {
    // Store load addresses in vector temporarily so that conflictions are
    // only regsitered once on most recent (program order) store
    std::vector<simeng::MemoryAccessTarget> temp_load_addr;
    for (const auto& ld : ld_addresses) {
      temp_load_addr.push_back(ld);
    }
    // Detect reordering conflicts
    if (storeQueue_.size() > 0) {
      uint64_t seqId = insn->getSequenceId();
      for (auto itSt = storeQueue_.rbegin(); itSt != storeQueue_.rend();
           itSt++) {
        const auto& store = itSt->first;
        // If entry is earlier in the program order than load, detect conflicts
        if (store->getSequenceId() < seqId) {
          const auto& str_addresses = store->getGeneratedAddresses();
          // Iterate over possible matches between store and load addresses
          for (const auto& str : str_addresses) {
            auto itLd = temp_load_addr.begin();
            while (itLd != temp_load_addr.end()) {
              // If conflict exists, register in conflictionMap_ and delay
              // load request(s) until conflicting store retires
              if (itLd->address == str.address) {
                conflictionMap_[store->getSequenceId()][str.address].push_back(
                    {insn, itLd->size});
                // Remove from temporary vector so the confliction can't be
                // registered again
                temp_load_addr.erase(itLd);
              } else {
                itLd++;
              }
            }
          }
        }
      }
    }
    // If addresses remain that had no conflictions, generate those load
    // request(s)
    if (temp_load_addr.size() > 0) {
      requestQueue_.push_back({tickCounter_ + insn->getLSQLatency(), {}, insn});
      for (size_t i = 0; i < temp_load_addr.size(); i++) {
        requestQueue_.back().reqAddresses.push(temp_load_addr[i]);
      }
    }
    requestedLoads_.emplace(insn->getSequenceId(), insn);
  }
}

void LoadStoreQueue::supplyStoreData(const std::shared_ptr<Instruction>& insn) {
  // Get identifier values
  const uint64_t seqId = insn->getSequenceId();
  // Get data
  span<const simeng::RegisterValue> data = insn->getData();

  // Find storeQueue_ entry which is linked to the store data operation
  auto itSt = storeQueue_.begin();
  while (itSt != storeQueue_.end()) {
    auto& entry = itSt->first;
    // Pair entry and incoming store data operation with sequenceID
    if (entry->getSequenceId() == seqId) {
      // Supply data to be stored by operations
      itSt->second = data;
      break;
    } else {
      itSt++;
    }
  }
}

bool LoadStoreQueue::commitStore(const std::shared_ptr<Instruction>& uop) {
  assert(storeQueue_.size() > 0 &&
         "Attempted to commit a store from an empty queue");
  assert(storeQueue_.front().first->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a store that wasn't present at the front of the "
         "store queue");

  const auto& addresses = uop->getGeneratedAddresses();
  span<const simeng::RegisterValue> data = storeQueue_.front().second;

  requestQueue_.push_back({tickCounter_ + uop->getLSQLatency(), {}, uop});
  // Submit request write to memory interface early as the architectural state
  // considers the store to be retired and thus its operation complete
  for (size_t i = 0; i < addresses.size(); i++) {
    memory_.requestWrite(addresses[i], data[i]);
    // Still add addresses to requestQueue_ to ensure contention of resources is
    // correctly simulated
    requestQueue_.back().reqAddresses.push(addresses[i]);
  }

  // Resolve any conflicts caused by this store instruction
  const auto& itSt = conflictionMap_.find(uop->getSequenceId());
  if (itSt != conflictionMap_.end()) {
    for (size_t i = 0; i < addresses.size(); i++) {
      const auto& itAddr = itSt->second.find(addresses[i].address);
      if (itAddr != itSt->second.end()) {
        for (const auto& pair : itAddr->second) {
          const auto& load = pair.first;
          load->supplyData(addresses[i].address,
                           data[i].zeroExtend(pair.second, pair.second));
          if (load->hasAllData()) {
            // This load has completed
            load->execute();
            if (load->isStore()) {
              supplyStoreData(load);
            }
            completedLoads_.push(load);
          }
        }
      }
    }
    conflictionMap_.erase(itSt);
  }

  // Check all loads that have requested memory
  violatingLoad_ = nullptr;
  for (const auto& load : requestedLoads_) {
    // Skip loads that are younger than the oldest violating load
    if (violatingLoad_ &&
        load.second->getSequenceId() > violatingLoad_->getSequenceId())
      continue;
    // Violation invalid if the load and store entries are generated by the same
    // uop
    if (load.second->getSequenceId() != uop->getSequenceId()) {
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
    const auto& entry = *it;
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
  // Remove flushed loads from load queue
  auto itLd = loadQueue_.begin();
  while (itLd != loadQueue_.end()) {
    const auto& entry = *itLd;
    if (entry->isFlushed()) {
      requestedLoads_.erase(entry->getSequenceId());
      itLd = loadQueue_.erase(itLd);
    } else {
      itLd++;
    }
  }

  // Remove flushed stores from store queue and confliction queue if an entry
  // exists
  auto itSt = storeQueue_.begin();
  while (itSt != storeQueue_.end()) {
    const auto& entry = itSt->first;
    if (entry->isFlushed()) {
      conflictionMap_.erase(entry->getSequenceId());
      itSt = storeQueue_.erase(itSt);
    } else {
      itSt++;
    }
  }

  // Remove flushed loads from confliction queue
  for (auto itCnflct = conflictionMap_.begin();
       itCnflct != conflictionMap_.end(); itCnflct++) {
    // Iterate over addresses of store
    for (auto itAddr = itCnflct->second.begin();
         itAddr != itCnflct->second.end(); itAddr++) {
      // Iterate over vector of instructions conflicting with store address
      auto pair = itAddr->second.begin();
      while (pair != itAddr->second.end()) {
        if (pair->first->isFlushed()) {
          pair = itAddr->second.erase(pair);
        } else {
          pair++;
        }
      }
    }
  }

  // Remove flushed loads and stores from request queue
  auto itReq = requestQueue_.begin();
  while (itReq != requestQueue_.end()) {
    auto& entry = itReq->insn;
    if (entry->isFlushed()) {
      itReq = requestQueue_.erase(itReq);
    } else {
      itReq++;
    }
  }
}

void LoadStoreQueue::tick() {
  tickCounter_++;
  // Send memory requests adhering to set bandwidth and number of permitted
  // requests per cycle
  uint64_t dataTransfered = 0;
  std::array<uint8_t, 2> reqCounts = {0, 0};
  bool remove = true;
  while (requestQueue_.size() > 0) {
    uint8_t isWrite = 0;
    auto& entry = requestQueue_.front();
    if (entry.readyAt <= tickCounter_) {
      if (!entry.insn->isLoad()) {
        isWrite = 1;
      }
      // Deal with requests from queue of addresses in requestQueue_ entry
      auto& addressQueue = entry.reqAddresses;
      while (addressQueue.size()) {
        const simeng::MemoryAccessTarget req = addressQueue.front();

        // Ensure the limit on the number of permitted operations is adhered to
        reqCounts[isWrite]++;
        if (reqCounts[isWrite] > reqLimits_[isWrite] ||
            reqCounts[isWrite] + reqCounts[!isWrite] > totalLimit_) {
          remove = false;
          break;
        }

        // Ensure the limit on the data transfered per cycle is adhered to
        assert(req.size < L1Bandwidth_ &&
               "Individual memory request from LoadStoreQueue exceeds L1 "
               "bandwidth set and thus will never be submitted");
        dataTransfered += req.size;
        if (dataTransfered > L1Bandwidth_) {
          remove = false;
          break;
        }
        // Request a read from the memory interface if the requestQueue_ entry
        // represents a read
        if (!isWrite) {
          memory_.requestRead(req, entry.insn->getSequenceId());
        }
        addressQueue.pop();
      }
      // Only remove entry from requestQueue_ if all addresses in entry are
      // processed
      if (remove)
        requestQueue_.pop_front();
      else
        break;
    } else {
      break;
    }
  }

  // Process completed read requests
  for (const auto& response : memory_.getCompletedReads()) {
    const auto& address = response.target.address;
    const auto& data = response.data;

    // TODO: Detect and handle non-fatal faults (e.g. page fault)

    // Find instruction that requested the memory read
    const auto& itr = requestedLoads_.find(response.requestId);
    if (itr == requestedLoads_.end()) {
      continue;
    }

    // Supply data to the instruction and execute if it is ready
    const auto& load = itr->second;
    load->supplyData(address, data);
    if (load->hasAllData()) {
      // This load has completed
      load->execute();
      if (load->isStore()) {
        supplyStoreData(load);
      }
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
