#include "simeng/pipeline/LoadStoreQueue.hh"

#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <list>

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
    bool exclusive, uint16_t loadBandwidth, uint16_t storeBandwidth,
    uint16_t permittedRequests, uint16_t permittedLoads,
    uint16_t permittedStores)
    : completionSlots_(completionSlots),
      forwardOperands_(forwardOperands),
      maxCombinedSpace_(maxCombinedSpace),
      combined_(true),
      memory_(memory),
      exclusive_(exclusive),
      loadBandwidth_(loadBandwidth),
      storeBandwidth_(storeBandwidth),
      totalLimit_(permittedRequests),
      // Set per-cycle limits for each request type
      reqLimits_{permittedLoads, permittedStores} {};

LoadStoreQueue::LoadStoreQueue(
    unsigned int maxLoadQueueSpace, unsigned int maxStoreQueueSpace,
    MemoryInterface& memory,
    span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
    std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
    bool exclusive, uint16_t loadBandwidth, uint16_t storeBandwidth,
    uint16_t permittedRequests, uint16_t permittedLoads,
    uint16_t permittedStores)
    : completionSlots_(completionSlots),
      forwardOperands_(forwardOperands),
      maxLoadQueueSpace_(maxLoadQueueSpace),
      maxStoreQueueSpace_(maxStoreQueueSpace),
      combined_(false),
      memory_(memory),
      exclusive_(exclusive),
      loadBandwidth_(loadBandwidth),
      storeBandwidth_(storeBandwidth),
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
    // Create a speculative entry for the load
    requestLoadQueue_[tickCounter_ + insn->getLSQLatency()].push_back(
        {{}, insn});
    // Store a reference to the reqAddresses queue for easy access
    auto& reqAddrQueue = requestLoadQueue_[tickCounter_ + insn->getLSQLatency()]
                             .back()
                             .reqAddresses;
    // Store load addresses temporarily so that conflictions are
    // only regsitered once on most recent (program order) store
    std::list<simeng::MemoryAccessTarget> temp_load_addr(ld_addresses.begin(),
                                                         ld_addresses.end());

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
                // Load access size must be no larger than the store access size
                // to ensure all data is encapsulated in the later forwarding
                if (itLd->size <= str.size) {
                  conflictionMap_[store->getSequenceId()][str.address]
                      .push_back({insn, itLd->size});
                } else {
                  // To ensure load doesn't match on an earlier store, generate
                  // load request for address
                  reqAddrQueue.push(*itLd);
                }
                // Remove from temporary vector so the confliction can't be
                // registered again
                itLd = temp_load_addr.erase(itLd);
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
    for (const auto& ld_addr : temp_load_addr) reqAddrQueue.emplace(ld_addr);
  }
  // Register active load
  requestedLoads_.emplace(insn->getSequenceId(), insn);
}

void LoadStoreQueue::supplyStoreData(const std::shared_ptr<Instruction>& insn) {
  if (!insn->isStoreData()) return;
  // Get identifier values
  const uint64_t macroOpNum = insn->getInstructionId();
  const int microOpNum = insn->getMicroOpIndex();

  // Get data
  span<const simeng::RegisterValue> data = insn->getData();

  // Find storeQueue_ entry which is linked to the store data operation
  auto itSt = storeQueue_.begin();
  while (itSt != storeQueue_.end()) {
    auto& entry = itSt->first;
    // Pair entry and incoming store data operation with macroOp identifier and
    // microOp index value pre-detemined in microDecoder
    if (entry->getInstructionId() == macroOpNum &&
        entry->getMicroOpIndex() == microOpNum) {
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

  // Early exit if there's no addresses to process
  if (addresses.size() == 0) {
    storeQueue_.pop_front();
    return false;
  }

  requestStoreQueue_[tickCounter_ + uop->getLSQLatency()].push_back({{}, uop});
  // Submit request write to memory interface early as the architectural state
  // considers the store to be retired and thus its operation complete
  for (size_t i = 0; i < addresses.size(); i++) {
    memory_.requestWrite(addresses[i], data[i]);
    // Still add addresses to requestQueue_ to ensure contention of resources is
    // correctly simulated
    requestStoreQueue_[tickCounter_ + uop->getLSQLatency()]
        .back()
        .reqAddresses.push(addresses[i]);
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

  // Resolve any conflicts caused by this store instruction
  const auto& itSt = conflictionMap_.find(uop->getSequenceId());
  if (itSt != conflictionMap_.end()) {
    for (size_t i = 0; i < addresses.size(); i++) {
      const auto& itAddr = itSt->second.find(addresses[i].address);
      if (itAddr != itSt->second.end()) {
        for (const auto& pair : itAddr->second) {
          const auto& load = pair.first;
          load->supplyData(addresses[i].address,
                           data[i].zeroExtend(
                               std::min(pair.second, (uint16_t)data[i].size()),
                               pair.second));
          if (load->hasAllData()) {
            // This load has completed
            load->execute();
            if (load->isStoreData()) {
              supplyStoreData(load);
            }
            completedLoads_.push(load);
          }
        }
      }
    }
    conflictionMap_.erase(itSt);
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

  // Remove flushed loads and stores from request queues
  auto itLdReq = requestLoadQueue_.begin();
  while (itLdReq != requestLoadQueue_.end()) {
    auto itInsn = itLdReq->second.begin();
    while (itInsn != itLdReq->second.end()) {
      if (itInsn->insn->isFlushed()) {
        itInsn = itLdReq->second.erase(itInsn);
      } else {
        itInsn++;
      }
    }
    if (itLdReq->second.size() == 0) {
      itLdReq = requestLoadQueue_.erase(itLdReq);
    } else {
      itLdReq++;
    }
  }
  auto itStReq = requestStoreQueue_.begin();
  while (itStReq != requestStoreQueue_.end()) {
    auto itInsn = itStReq->second.begin();
    while (itInsn != itStReq->second.end()) {
      if (itInsn->insn->isFlushed()) {
        itInsn = itStReq->second.erase(itInsn);
      } else {
        itInsn++;
      }
    }
    if (itStReq->second.size() == 0) {
      itStReq = requestStoreQueue_.erase(itStReq);
    } else {
      itStReq++;
    }
  }
}

void LoadStoreQueue::tick() {
  tickCounter_++;
  // Send memory requests adhering to set bandwidth and number of permitted
  // requests per cycle
  // Index 0: loads, index 1: stores
  std::array<uint16_t, 2> reqCounts = {0, 0};
  std::array<uint64_t, 2> dataTransfered = {0, 0};
  std::array<bool, 2> exceededLimits = {false, false};
  auto itLoad = requestLoadQueue_.begin();
  auto itStore = requestStoreQueue_.begin();
  while (requestLoadQueue_.size() + requestStoreQueue_.size() > 0) {
    // Choose which request type to schedule next
    bool chooseLoad = false;
    std::pair<bool, uint64_t> earliestLoad;
    std::pair<bool, uint64_t> earliestStore;
    // Determine if a load request can be scheduled
    if (requestLoadQueue_.size() == 0 || exceededLimits[accessType::LOAD]) {
      earliestLoad = {false, 0};
    } else {
      earliestLoad = {true, itLoad->first};
    }
    // Determine if a store request can be scheduled
    if (requestStoreQueue_.size() == 0 || exceededLimits[accessType::STORE]) {
      earliestStore = {false, 0};
    } else {
      earliestStore = {true, itStore->first};
    }
    // Choose between available requests favouring those constructed earlier
    // (store requests on a tie)
    if (earliestLoad.first) {
      chooseLoad = !(earliestStore.first &&
                     (earliestLoad.second >= earliestStore.second));
    } else if (!earliestStore.first) {
      break;
    }

    // Get next request to schedule
    auto& itReq = chooseLoad ? itLoad : itStore;
    auto itInsn = itReq->second.begin();
    auto bandwidth = chooseLoad ? loadBandwidth_ : storeBandwidth_;

    // Check if earliest request is ready
    if (itReq->first <= tickCounter_) {
      // Identify request type
      uint8_t isStore = 0;
      if (!chooseLoad) {
        isStore = 1;
      }
      // If LSQ only allows one type of request within a cycle, prevent other
      // type from being scheduled
      if (exclusive_) exceededLimits[!isStore] = true;

      // Iterate over requests ready this cycle
      while (itInsn != itReq->second.end()) {
        // Speculatively increment count of this request type
        reqCounts[isStore]++;

        // Ensure the limit on the number of permitted operations is adhered
        // to
        if (reqCounts[isStore] + reqCounts[!isStore] > totalLimit_) {
          // No more requests can be scheduled this cycle
          exceededLimits = {true, true};
          break;
        } else if (reqCounts[isStore] > reqLimits_[isStore]) {
          // No more requests of this type can be scheduled this cycle
          exceededLimits[isStore] = true;
          // Remove speculative increment to ensure it doesn't count for
          // comparisons aginast the totalLimit_
          reqCounts[isStore]--;
          break;
        } else {
          // Schedule requests from the queue of addresses in
          // request[Load|Store]Queue_ entry
          auto& addressQueue = itInsn->reqAddresses;
          while (addressQueue.size()) {
            const simeng::MemoryAccessTarget req = addressQueue.front();

            // Ensure the limit on the data transfered per cycle is adhered to
            assert(req.size <= bandwidth &&
                   "Individual memory request from LoadStoreQueue exceeds L1 "
                   "bandwidth set and thus will never be submitted");
            dataTransfered[isStore] += req.size;
            if (dataTransfered[isStore] > bandwidth) {
              // No more requests can be scheduled this cycle
              exceededLimits[isStore] = true;
              itInsn = itReq->second.end();
              break;
            }

            // Request a read from the memory interface if the requestQueue_
            // entry represents a read
            if (!isStore) {
              memory_.requestRead(req, itInsn->insn->getSequenceId());
            }

            // Remove processed address from queue
            addressQueue.pop();
          }
          // Remove entry from vector iff all of its requests have been
          // scheduled
          if (addressQueue.size() == 0) {
            itInsn = itReq->second.erase(itInsn);
          }
        }
      }

      // If all uops for currently selected cycle in request[Load|Store]Queue_
      // have been scheduled, erase entry
      if (itReq->second.size() == 0) {
        if (chooseLoad) {
          itReq = requestLoadQueue_.erase(itReq);
        } else {
          itReq = requestStoreQueue_.erase(itReq);
        }
      }
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
      if (load->isStoreData()) {
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

    // Don't process load instruction if it has been flushed
    if (insn->isFlushed()) {
      completedLoads_.pop();
      continue;
    }

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
