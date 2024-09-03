#include "simeng/pipeline/LoadStoreQueue.hh"

#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <list>

namespace simeng {
namespace pipeline {

bool stbPrint = false;

/** Check whether requests `a` and `b` overlap. */
bool requestsOverlap(memory::MemoryAccessTarget a,
                     memory::MemoryAccessTarget b) {
  // Check whether one region ends before the other begins, implying no overlap,
  // and negate
  return !(a.vaddr + a.size <= b.vaddr || b.vaddr + b.size <= a.vaddr);
}

LoadStoreQueue::LoadStoreQueue(
    unsigned int maxCombinedSpace, std::shared_ptr<memory::MMU> mmu,
    span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
    std::function<void(span<Register>, span<RegisterValue>, const uint16_t)>
        forwardOperands,
    CompletionOrder completionOrder)
    : completionSlots_(completionSlots),
      forwardOperands_(forwardOperands),
      maxCombinedSpace_(maxCombinedSpace),
      combined_(true),
      mmu_(mmu),
      completionOrder_(completionOrder){};

LoadStoreQueue::LoadStoreQueue(
    unsigned int maxLoadQueueSpace, unsigned int maxStoreQueueSpace,
    std::shared_ptr<memory::MMU> mmu,
    span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
    std::function<void(span<Register>, span<RegisterValue>, const uint16_t)>
        forwardOperands,
    CompletionOrder completionOrder)
    : completionSlots_(completionSlots),
      forwardOperands_(forwardOperands),
      maxLoadQueueSpace_(maxLoadQueueSpace),
      maxStoreQueueSpace_(maxStoreQueueSpace),
      combined_(false),
      mmu_(mmu),
      completionOrder_(completionOrder){};

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
    completedRequests_.push(insn);
  } else {
    if (insn->isPrefetch()) {
      requestLoadQueue_[tickCounter_].push_back(insn);
      return;
    }
    // If the completion order is inorder, reserve an entry in
    // completedRequests_ now
    if (completionOrder_ == CompletionOrder::INORDER)
      completedRequests_.push(insn);

    // Detect reordering conflicts
    if (storeQueue_.size() > 0) {
      uint64_t seqId = insn->getSequenceId();
      for (auto itSt = storeQueue_.rbegin(); itSt != storeQueue_.rend();
           itSt++) {
        const auto& store = itSt->first;
        // If entry is earlier in the program order than load, detect conflicts
        if (store->getSequenceId() < seqId) {
          const auto& str_addresses = store->getGeneratedAddresses();
          // Iterate over possible overlaps between store and load addresses
          for (const auto& strAddr : str_addresses) {
            for (const auto& ldAddr : ld_addresses) {
              if (requestsOverlap(strAddr, ldAddr)) {
                // Conflict exists, add load instruction to conflictionMap_ and
                // delay until store retires
                conflictionMap_[store->getSequenceId()].push_back(insn);
                conflicts_++;
                return;
              }
            }
          }
        }
      }
    }
    // No conflict found, process load
    requestLoadQueue_[tickCounter_ + insn->getLSQLatency()].push_back(insn);
    // Register active load
    requestedLoads_.emplace(
        insn->getSequenceId(),
        std::pair<std::shared_ptr<Instruction>, uint64_t>({insn, 0}));
  }
}

void LoadStoreQueue::supplyStoreData(const std::shared_ptr<Instruction>& insn) {
  if (!insn->isStoreData()) return;
  // Get identifier values
  const uint64_t macroOpNum = insn->getInstructionId();
  const int microOpNum = insn->getMicroOpIndex();

  // Get data
  const auto& data = insn->getData();

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

void LoadStoreQueue::startStore(const std::shared_ptr<Instruction>& uop) {
  const auto& addresses = uop->getGeneratedAddresses();
  const auto& data = storeQueue_.front().second;

  // Early exit if there's no addresses to process
  if (addresses.size() == 0) {
    // TODO: Check if atomic lock needs to be released (not LL/SC monitor)
    return;
  }
  // Supply the data to store to the instruction. Can't be done in
  // `supplyStoreData` as addresses may not have been calculated
  assert(addresses.size() == data.size() &&
         "[SimEng:LoadStoreQueue] Tried to supply data to an store instruction "
         "with un-equal addresses and data items.");

  // If this instruction is a store conditional operation, track it
  if (uop->isStoreCond() && !uop->isCondResultReady()) {
    assert(requestedCondStore_.first == nullptr &&
           "[SimEng:LoadStoreQueue] Tried to issue a second conditional store "
           "whilst one is already in flight.");
    for (int i = 0; i < data.size(); i++) {
      uop->supplyData(addresses[i].vaddr, data[i]);
    }
    requestedCondStore_ = {uop, false};

    // Reset store's commit ready status as we need to determine any
    // post-memory-request values to be committed
    uop->setCommitReady(false);

    // If the completion order is inorder, reserve an entry in
    // completedRequests_ now
    if (completionOrder_ == CompletionOrder::INORDER)
      completedRequests_.push(uop);
  } else if (uop->isAcquire()) {
    for (int i = 0; i < data.size(); i++) {
      mmu_->requestWrite(addresses[i], data[i]);
    }
  } else {
    for (int i = 0; i < data.size(); i++) {
      requestStoreQueue_.push({addresses[i], data[i]});
    }

    // uint64_t seqId = uop->getSequenceId();
    // std::vector<storeBufferEntry> entries;
    // for (int i = 0; i < data.size(); i++) {
    //   if (stbPrint) {
    //     std::cerr << "Start Store " << seqId << " - " << std::hex
    //               << addresses[i].vaddr << std::dec << ":" <<
    //               addresses[i].size
    //               << "[" << std::hex;
    //     for (int j = addresses[i].size - 1; j >= 0; j--) {
    //       if (data[i].getAsVector<uint8_t>()[j] < 16) std::cerr << "0";
    //       std::cerr << unsigned(data[i].getAsVector<uint8_t>()[j]) << " ";
    //     }
    //     std::cerr << std::dec << "\b]" << std::endl;
    //   }
    //   storeBufferEntry newEntry;
    //   newEntry.target.vaddr = addresses[i].vaddr;
    //   newEntry.target.size = addresses[i].size;
    //   newEntry.target.id = seqId;
    //   newEntry.data = data[i];
    //   storeBufferEntry remainder = newEntry.split(storeBufferEntryWidth_);
    //   entries.push_back(newEntry);
    //   if (remainder.target.size != 0) {
    //     entries.push_back(remainder);
    //   }
    // }

    // for (auto newEntry : entries) {
    //   uint64_t baseVaddr = newEntry.target.vaddr -
    //                        (newEntry.target.vaddr % storeBufferEntryWidth_);
    //   bool inserted = false;
    //   auto itr = storeBuffer_.find(baseVaddr);
    //   if (itr != storeBuffer_.end()) {
    //     // Determine if there's space for a new target
    //     auto nextTgtItr = itr->second.first.begin();
    //     auto prevTgtItr = itr->second.first.end();
    //     while (nextTgtItr != itr->second.first.end()) {
    //       if (stbPrint)
    //         std::cerr << "\tTrying " << nextTgtItr -
    //         itr->second.first.begin()
    //                   << "..." << std::endl;
    //       if (nextTgtItr == itr->second.first.begin()) {
    //         // Check for valid address position
    //         if (newEntry.target.vaddr + newEntry.target.size <=
    //             nextTgtItr->target.vaddr) {
    //           if (stbPrint) std::cerr << "\tValid at start..." << std::endl;
    //           // Check for space
    //           if (nextTgtItr->target.vaddr - baseVaddr >=
    //               newEntry.target.size) {
    //             if (stbPrint) std::cerr << "\tSpace at start..." <<
    //             std::endl;
    //             // Attempt merge, simply insert otherwise
    //             inserted = nextTgtItr->mergeBefore(newEntry);
    //             if (!inserted) {
    //               nextTgtItr = itr->second.first.insert(nextTgtItr,
    //               newEntry); if (stbPrint)
    //                 std::cerr << "\tInserted at start as new block"
    //                           << std::endl;
    //               inserted = true;
    //             } else {
    //               if (stbPrint)
    //                 std::cerr << "\tInserted at start via merge" <<
    //                 std::endl;
    //             }
    //           } else {
    //             break;
    //           }
    //         }
    //       }
    //       if (inserted) break;

    //       if (nextTgtItr != itr->second.first.begin() &&
    //           prevTgtItr != itr->second.first.end()) {
    //         // Check for valid address position
    //         if ((newEntry.target.vaddr + newEntry.target.size <=
    //              nextTgtItr->target.vaddr) &&
    //             (prevTgtItr->target.vaddr + prevTgtItr->target.size <=
    //              newEntry.target.vaddr)) {
    //           if (stbPrint)
    //             std::cerr << "\tValid at "
    //                       << nextTgtItr - itr->second.first.begin() << "..."
    //                       << std::endl;
    //           // Check for space
    //           if ((nextTgtItr->target.vaddr -
    //                (prevTgtItr->target.vaddr + prevTgtItr->target.size)) >=
    //               newEntry.target.size) {
    //             if (stbPrint)
    //               std::cerr << "\tSpace at "
    //                         << nextTgtItr - itr->second.first.begin() <<
    //                         "..."
    //                         << std::endl;
    //             // Attempt merge, simply insert otherwise
    //             inserted = nextTgtItr->mergeBefore(newEntry);
    //             if (!inserted) {
    //               nextTgtItr = itr->second.first.insert(nextTgtItr,
    //               newEntry); if (stbPrint)
    //                 std::cerr << "\tInserted at "
    //                           << nextTgtItr - itr->second.first.begin()
    //                           << " as new block" << std::endl;
    //               inserted = true;
    //             } else {
    //               if (stbPrint)
    //                 std::cerr << "\tInserted at "
    //                           << nextTgtItr - itr->second.first.begin()
    //                           << " via merge" << std::endl;
    //             }
    //           } else {
    //             break;
    //           }
    //         }
    //       }
    //       if (inserted) break;

    //       if (nextTgtItr == itr->second.first.end() - 1) {
    //         // Check for valid address position
    //         if (nextTgtItr->target.vaddr + nextTgtItr->target.size <=
    //             newEntry.target.vaddr) {
    //           if (stbPrint) std::cerr << "\tValid at end..." << std::endl;
    //           // Check for space
    //           if (baseVaddr + storeBufferEntryWidth_ -
    //                   nextTgtItr->target.vaddr >=
    //               newEntry.target.size) {
    //             if (stbPrint) std::cerr << "\tSpace at end..." << std::endl;
    //             // Attempt merge, simply insert otherwise
    //             inserted = nextTgtItr->mergeAfter(newEntry);
    //             if (!inserted) {
    //               itr->second.first.push_back(newEntry);
    //               if (stbPrint)
    //                 std::cerr << "\tInserted at end as new block" <<
    //                 std::endl;
    //               inserted = true;
    //             } else {
    //               if (stbPrint)
    //                 std::cerr << "\tInserted at end via merge" << std::endl;
    //             }
    //           }
    //         }
    //       }
    //       if (inserted) break;

    //       prevTgtItr = nextTgtItr;
    //       nextTgtItr++;
    //     }
    //     // Identify any final merges
    //     auto baseTgtItr = itr->second.first.begin();
    //     nextTgtItr = itr->second.first.begin() + 1;
    //     while (nextTgtItr != itr->second.first.end()) {
    //       if (baseTgtItr->mergeAfter((*nextTgtItr))) {
    //         nextTgtItr = itr->second.first.erase(nextTgtItr);
    //       } else {
    //         baseTgtItr = nextTgtItr;
    //         nextTgtItr++;
    //       }
    //     }

    //     if (!inserted) {
    //       // If not inserted, drain STB entry and create fresh one with
    //       newEntry for (auto tgt : itr->second.first) {
    //         requestStoreQueue_.push({tgt.target, tgt.data});
    //       }
    //       itr->second.first = {};
    //       itr->second.first.push_back(newEntry);
    //       itr->second.second = tickCounter_;
    //       if (stbPrint)
    //         std::cerr << "\tInserted via conflict replacement" << std::endl;
    //     }
    //   } else {
    //     // Determine if there's space for a new STB entry
    //     if (storeBuffer_.size() >= storeBufferSize_) {
    //       // Drain oldest entry and create fresh one with newEntry
    //       uint64_t oldest = storeBuffer_.begin()->second.second;
    //       uint64_t index = storeBuffer_.begin()->first;
    //       for (const auto& entry : storeBuffer_) {
    //         if (entry.second.second < oldest) {
    //           oldest = entry.second.second;
    //           index = entry.first;
    //         }
    //       }

    //       auto baseTgtItr = storeBuffer_[index].first.begin();
    //       auto nextTgtItr = storeBuffer_[index].first.begin() + 1;
    //       while (nextTgtItr != storeBuffer_[index].first.end()) {
    //         if (baseTgtItr->mergeAfter((*nextTgtItr))) {
    //           nextTgtItr = storeBuffer_[index].first.erase(nextTgtItr);
    //         } else {
    //           baseTgtItr = nextTgtItr;
    //           nextTgtItr++;
    //         }
    //       }

    //       for (auto tgt : storeBuffer_[index].first) {
    //         requestStoreQueue_.push({tgt.target, tgt.data});
    //       }

    //       storeBuffer_.erase(storeBuffer_.find(index));

    //       storeBuffer_[baseVaddr].first.push_back(newEntry);
    //       storeBuffer_[baseVaddr].second = tickCounter_;
    //       if (stbPrint)
    //         std::cerr << "\tInserted via capacity replacement" << std::endl;
    //     } else {
    //       // If there's space, create new STB entry
    //       storeBuffer_[baseVaddr].first.push_back(newEntry);
    //       storeBuffer_[baseVaddr].second = tickCounter_;
    //       if (stbPrint) std::cerr << "\tInserted as new entry" << std::endl;
    //     }
    //   }
    // }
  }
}

bool LoadStoreQueue::commitStore(const std::shared_ptr<Instruction>& uop) {
  assert(storeQueue_.size() > 0 &&
         "Attempted to commit a store from an empty queue");
  assert(storeQueue_.front().first->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a store that wasn't present at the front of the "
         "store queue");

  const auto& addresses = uop->getGeneratedAddresses();

  // Early exit if there's no addresses to process
  if (addresses.size() == 0) {
    // TODO: Check if atomic lock needs to be released (not LL/SC monitor)
    storeQueue_.pop_front();
    return false;
  }

  // Check all loads that have requested memory
  violatingLoad_ = nullptr;
  for (const auto& load : requestedLoads_) {
    // Skip loads that are younger than the oldest violating load
    if (violatingLoad_ &&
        load.second.first->getSequenceId() > violatingLoad_->getSequenceId())
      continue;
    // Violation invalid if the load and store entries are generated by the same
    // instruction
    if (load.second.first->getSequenceId() != uop->getSequenceId()) {
      const auto& loadedAddresses = load.second.first->getGeneratedAddresses();
      // Iterate over store addresses
      for (const auto& storeReq : addresses) {
        // Iterate over load addresses
        for (const auto& loadReq : loadedAddresses) {
          // if (!loadReq.wasForwarded) {
          // Check for overlapping requests, and flush if discovered
          if (requestsOverlap(storeReq, loadReq)) {
            violatingLoad_ = load.second.first;
          }
          // }
        }
      }
    }
  }

  // Resolve any conflictions on this store
  auto itr = conflictionMap_.find(uop->getSequenceId());
  if (itr != conflictionMap_.end()) {
    // For each load, we can now execute them given the conflicting
    // store has now been triggered
    auto ldVec = itr->second;
    for (auto load : ldVec) {
      requestLoadQueue_[tickCounter_ + 1 + load->getLSQLatency()].push_back(
          load);
      requestedLoads_.emplace(
          load->getSequenceId(),
          std::pair<std::shared_ptr<Instruction>, uint64_t>({load, 0}));
    }
    // Remove all entries for this store from conflictionMap_
    conflictionMap_.erase(itr);
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
      // Can erase all load entries as they must be younger than flushed store
      conflictionMap_.erase(entry->getSequenceId());
      itSt = storeQueue_.erase(itSt);
    } else {
      itSt++;
    }
  }

  // Remove flushed loads from confliction queue
  for (auto itCnflct = conflictionMap_.begin();
       itCnflct != conflictionMap_.end(); itCnflct++) {
    auto ldItr = itCnflct->second.begin();
    while (ldItr != itCnflct->second.end()) {
      if ((*ldItr)->isFlushed()) {
        ldItr = itCnflct->second.erase(ldItr);
      } else {
        ldItr++;
      }
    }
  }

  // Remove flushed loads and stores from request queues
  auto itLdReq = requestLoadQueue_.begin();
  while (itLdReq != requestLoadQueue_.end()) {
    auto itInsn = itLdReq->second.begin();
    while (itInsn != itLdReq->second.end()) {
      if ((*itInsn)->isFlushed()) {
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
  // Don't need to purge stores as they will only be sent at commit
}

void LoadStoreQueue::drainSTB() {
  // Drain all STB entries when pipeline is flushed
  auto itr = storeBuffer_.begin();
  while (itr != storeBuffer_.end()) {
    auto baseTgtItr = itr->second.first.begin();
    auto nextTgtItr = itr->second.first.begin() + 1;
    while (nextTgtItr != itr->second.first.end()) {
      if (baseTgtItr->mergeAfter((*nextTgtItr))) {
        nextTgtItr = itr->second.first.erase(nextTgtItr);
      } else {
        baseTgtItr = nextTgtItr;
        nextTgtItr++;
      }
    }

    for (auto tgt : itr->second.first) {
      requestStoreQueue_.push({tgt.target, tgt.data});
    }
    itr = storeBuffer_.erase(itr);
  }

  while (requestStoreQueue_.size() > 0) {
    mmu_->requestWrite(requestStoreQueue_.front().first,
                       requestStoreQueue_.front().second);
    numStoreReqs_++;
    if (stbPrint) {
      std::cerr << "Pipeline Flush Sent Store Req "
                << requestStoreQueue_.front().first.id << " - " << std::hex
                << requestStoreQueue_.front().first.vaddr << std::dec << ":"
                << requestStoreQueue_.front().first.size << "[" << std::hex;
      for (int j = requestStoreQueue_.front().first.size - 1; j >= 0; j--) {
        if (requestStoreQueue_.front().second.getAsVector<uint8_t>()[j] < 16)
          std::cerr << "0";
        std::cerr << unsigned(requestStoreQueue_.front()
                                  .second.getAsVector<uint8_t>()[j])
                  << " ";
      }
      std::cerr << std::dec << "\b]" << std::endl;
    }
    requestStoreQueue_.pop();
  }
}

void LoadStoreQueue::tick() {
  tickCounter_++;
  if (stbPrint) {
    if (storeBuffer_.size()) {
      std::cerr << "===V===" << std::endl;
      for (const auto& entry : storeBuffer_) {
        std::cerr << std::hex << entry.first << std::dec << ":";
        for (const auto& tgt : entry.second.first) {
          std::cerr << "[" << tgt.target.id << "|" << std::hex
                    << tgt.target.vaddr << std::dec << "|" << tgt.target.size
                    << "]";
        }
        std::cerr << " - " << entry.second.second << std::endl;
      }
      std::cerr << "===^===" << std::endl;
    }
  }
  // std::cerr << "LSQ TICK IN " << tickCounter_ << std::endl;
  // Send memory requests
  // Index 0: loads, index 1: stores
  std::array<bool, 2> exceededLimits = {false, false};
  // auto itLoad = requestLoadQueue_.begin();
  // auto itStore = requestStoreQueue_.begin();
  // std::cerr << "\tCONSIDER LSQ STORE COND" << std::endl;
  if (requestedCondStore_.second == false) {
    bool accepted = mmu_->requestWrite(requestedCondStore_.first,
                                       requestedCondStore_.first->getData());
    if (accepted) {
      requestedCondStore_.second = true;
      numStoreReqs_++;
      // std::cerr << "STORE COND LSQ: "
      //           << requestedCondStore_.first->getSequenceId() << std::endl;
    }
  }

  // std::cerr << "\tCONSIDER LSQ STORES" << std::endl;
  while (requestStoreQueue_.size() > 0) {
    bool accepted =
        mmu_->requestWrite(requestStoreQueue_.front().first,
                           requestStoreQueue_.front().second, false);
    if (accepted) {
      // std::cerr << "STORE LSQ: " << requestStoreQueue_.front().first.id
      //           << std::endl;
      if (stbPrint) {
        std::cerr << "Sent Store Req " << requestStoreQueue_.front().first.id
                  << " - " << std::hex << requestStoreQueue_.front().first.vaddr
                  << std::dec << ":" << requestStoreQueue_.front().first.size
                  << "[" << std::hex;
        for (int j = requestStoreQueue_.front().first.size - 1; j >= 0; j--) {
          if (requestStoreQueue_.front().second.getAsVector<uint8_t>()[j] < 16)
            std::cerr << "0";
          std::cerr << unsigned(requestStoreQueue_.front()
                                    .second.getAsVector<uint8_t>()[j])
                    << " ";
        }
        std::cerr << std::dec << "\b]" << std::endl;
      }
      requestStoreQueue_.pop();
      numStoreReqs_++;
    } else
      break;
  }

  // std::cerr << "\tCONSIDER LSQ LOADS" << std::endl;
  auto itLoad = requestLoadQueue_.begin();
  while (requestLoadQueue_.size() > 0 && !exceededLimits[0]) {
    // Choose which request type to schedule next
    // bool chooseLoad = false;
    // std::pair<bool, uint64_t> earliestLoad;
    // std::pair<bool, uint64_t> earliestStore;
    // Determine if a load request can be scheduled
    // if (requestLoadQueue_.size() == 0 || exceededLimits[accessType::LOAD]) {
    //   earliestLoad = {false, 0};
    // } else {
    //   earliestLoad = {true, itLoad->first};
    // }
    // Determine if a store request can be scheduled
    // if (requestStoreQueue_.size() == 0 || exceededLimits[accessType::STORE])
    // {
    //   earliestStore = {false, 0};
    // } else {
    //   earliestStore = {true, itStore->first};
    // }
    // Choose between available requests favouring those constructed earlier
    // (store requests on a tie)
    // if (earliestLoad.first) {
    //   chooseLoad = !(earliestStore.first &&
    //                  (earliestLoad.second >= earliestStore.second));
    // } else if (!earliestStore.first) {
    //   break;
    // }

    // Get next request to schedule
    // auto& itReq = chooseLoad ? itLoad : itStore;

    // Check if earliest request is ready
    if (itLoad->first <= tickCounter_) {
      // Identify request type
      // uint8_t isStore = 0;
      // Iterate over requests ready this cycle
      auto itInsn = itLoad->second.begin();
      while (itInsn != itLoad->second.end()) {
        if (stbPrint)
          std::cerr << "Start Load " << (*itInsn)->getSequenceId() << std::endl;
        // Check for entry in storeBuffer
        auto addresses = (*itInsn)->getGeneratedAddresses();
        bool requestNeeded = false;
        std::vector<uint64_t> drainSTB = {};

        for (auto addr : addresses) {
          // Find STB entry for addresses to be loaded
          uint64_t baseLoadAddr =
              addr.vaddr - (addr.vaddr % storeBufferEntryWidth_);
          if (stbPrint)
            std::cerr << "\tConsidering address " << std::hex << addr.vaddr
                      << std::dec << " with base addr " << std::hex
                      << baseLoadAddr << std::dec << "..." << std::endl;
          auto block = storeBuffer_.find(baseLoadAddr);
          if (block != storeBuffer_.end()) {
            if ((*itInsn)->isPrefetch() || (*itInsn)->isLoadReserved()) {
              requestNeeded = true;
              drainSTB.push_back(baseLoadAddr);
            } else {
              bool found = false;
              // See if data exists for the exact load address range
              for (auto tgt : block->second.first) {
                if ((tgt.target.vaddr <= addr.vaddr) &&
                    (tgt.target.vaddr + tgt.target.size >=
                     addr.vaddr + addr.size)) {
                  if (stbPrint)
                    std::cerr << "\tSupplying data from STB entry" << std::endl;
                  // If found, extract and supply data
                  char* newData = (char*)calloc(addr.size, sizeof(uint8_t));
                  uint64_t loadTrace = addr.vaddr;
                  for (int i = 0; i < tgt.target.size; i++) {
                    if (tgt.target.vaddr + i >= addr.vaddr + addr.size) break;
                    if (tgt.target.vaddr + i == loadTrace) {
                      newData[loadTrace - addr.vaddr] =
                          tgt.data.getAsVector<uint8_t>()[i];
                      loadTrace++;
                    }
                  }
                  (*itInsn)->supplyData(
                      addr.vaddr, RegisterValue(newData, addr.size), true);
                  free(newData);
                  found = true;
                  stbSupplies_++;
                  break;
                }
              }
              if (!found) {
                // If no valid block was found, check for straddle
                if (stbPrint)
                  std::cerr << "\t\tNo satisfying block" << std::endl;
                //   uint64_t straddleLoadAddr =
                //       baseLoadAddr + storeBufferEntryWidth_;
                //   if ((addr.vaddr + addr.size) > straddleLoadAddr) {
                //     // Identifed straddle, check for next STB entry
                //     if (stbPrint) std::cerr << "\t\tStraddle found" <<
                //     std::endl; auto straddledBlock =
                //     storeBuffer_.find(straddleLoadAddr); if (straddledBlock
                //     != storeBuffer_.end()) {
                //       // Found STB entry, see if base STB contains enough
                //       data if (stbPrint)
                //         std::cerr << "\t\tSTB has straddled entry" <<
                //         std::endl;
                //       auto baseTgt = block->second.first.rbegin();
                //       auto straddedTgt =
                //       straddledBlock->second.first.begin(); if
                //       ((baseTgt->target.vaddr + baseTgt->target.size) ==
                //           straddleLoadAddr) {
                //         // Does satisfy, see if straddled STB contains enough
                //         data if (stbPrint)
                //           std::cerr << "\t\tBase block has enough data"
                //                     << std::endl;
                //         if (straddedTgt->target.vaddr == straddleLoadAddr) {
                //           // Does satisfy, see if base STB contains address
                //           range if (stbPrint)
                //             std::cerr << "\t\tStraddled block has enough
                //             data"
                //                       << std::endl;
                //           if (baseTgt->target.vaddr <= addr.vaddr) {
                //             // Does satisfy, see if straddled STB contains
                //             address
                //             // range
                //             if (stbPrint)
                //               std::cerr << "\t\tBase block satisyfies addr
                //               range"
                //                         << std::endl;
                //             if ((straddedTgt->target.vaddr +
                //                  straddedTgt->target.size) >=
                //                 addr.vaddr + addr.size) {
                //               // Does satisfy, supply data
                //               if (stbPrint)
                //                 std::cerr
                //                     << "\t\tStraddled block satisyfies addr "
                //                        "range, supplying data"
                //                     << std::endl;
                //               // If found, extract and supply data
                //               char* newData =
                //                   (char*)calloc(addr.size, sizeof(uint8_t));
                //               uint64_t loadTrace = addr.vaddr;
                //               // Load from pre-straddle
                //               for (int i = (addr.vaddr -
                //               baseTgt->target.vaddr);
                //                    i < baseTgt->target.size; i++) {
                //                 newData[loadTrace - addr.vaddr] =
                //                     baseTgt->data.getAsVector<uint8_t>()[i];
                //                 loadTrace++;
                //               }
                //               // Load from post-straddle
                //               for (int i = 0; i < (addr.vaddr + addr.size -
                //                                    straddedTgt->target.vaddr);
                //                    i++) {
                //                 newData[loadTrace - addr.vaddr] =
                //                     straddedTgt->data.getAsVector<uint8_t>()[i];
                //                 loadTrace++;
                //               }
                //               (*itInsn)->supplyData(
                //                   addr.vaddr, RegisterValue(newData,
                //                   addr.size), true);
                //               free(newData);
                //               found = true;
                //               stbSupplies_++;
                //             }
                //           }
                //         }
                //       }
                //     }
                //   }
                // }
                // if (!found) {
                requestNeeded = true;
                drainSTB.push_back(baseLoadAddr);
              }
            }
          } else {
            if (stbPrint) std::cerr << "\tNo STB entry" << std::endl;
            // Check that no STB entry straddling exists
            uint64_t straddleLoadAddr = baseLoadAddr + storeBufferEntryWidth_;
            if ((addr.vaddr + addr.size) > straddleLoadAddr) {
              if (stbPrint)
                std::cerr << "\t\tConsidering straddled STB entry 0x"
                          << std::hex << straddleLoadAddr << std::dec << "... "
                          << std::endl;
              if (storeBuffer_.find(straddleLoadAddr) != storeBuffer_.end()) {
                drainSTB.push_back(straddleLoadAddr);
                if (stbPrint)
                  std::cerr << "\t\tSTB straddled entry found" << std::endl;
              } else {
                if (stbPrint)
                  std::cerr << "\t\tNo STB straddled entry found" << std::endl;
              }
            }
            // If no valid STB entry was found, send memory access request
            requestNeeded = true;
          }
        }

        bool accepted = false;
        if (requestNeeded) {
          if (stbPrint)
            std::cerr << "\tRequest still needed, " << storeBuffer_.size()
                      << " STB entries" << std::endl;
          // Drain all STB entries is a Load missed it
          // std::cerr << "\tDRAINING LSQ STB" << std::endl;
          if (drainSTB.size()) {
            stbDrains_++;
            for (const auto& stbEntry : drainSTB) {
              auto itr = storeBuffer_.find(stbEntry);
              if (itr != storeBuffer_.end()) {
                auto baseTgtItr = itr->second.first.begin();
                auto nextTgtItr = itr->second.first.begin() + 1;
                while (nextTgtItr != itr->second.first.end()) {
                  if (baseTgtItr->mergeAfter((*nextTgtItr))) {
                    nextTgtItr = itr->second.first.erase(nextTgtItr);
                  } else {
                    baseTgtItr = nextTgtItr;
                    nextTgtItr++;
                  }
                }

                for (auto tgt : itr->second.first) {
                  requestStoreQueue_.push({tgt.target, tgt.data});
                }

                itr = storeBuffer_.erase(itr);
              }
            }
            // std::cerr << "\tFINISHED DRAINING LSQ STB" << std::endl;

            if (stbPrint)
              std::cerr << "\t" << requestStoreQueue_.size()
                        << " store queue entries" << std::endl;
            while (requestStoreQueue_.size() > 0) {
              if (mmu_->requestWrite(requestStoreQueue_.front().first,
                                     requestStoreQueue_.front().second,
                                     false)) {
                // std::cerr << "STORE LSQ: " <<
                // requestStoreQueue_.front().first.id
                //           << std::endl;
                if (stbPrint) {
                  std::cerr << "Load Drained Store Req "
                            << requestStoreQueue_.front().first.id << " - "
                            << std::hex
                            << requestStoreQueue_.front().first.vaddr
                            << std::dec << ":"
                            << requestStoreQueue_.front().first.size << "["
                            << std::hex;
                  for (int j = requestStoreQueue_.front().second.size() - 1;
                       j >= 0; j--) {
                    if (requestStoreQueue_.front()
                            .second.getAsVector<uint8_t>()[j] < 16)
                      std::cerr << "0";
                    std::cerr << unsigned(requestStoreQueue_.front()
                                              .second.getAsVector<uint8_t>()[j])
                              << " ";
                  }
                  std::cerr << std::dec << "\b]" << std::endl;
                }
                requestStoreQueue_.pop();
                numStoreReqs_++;
              } else
                break;
            }
          }

          if (requestStoreQueue_.size() == 0) {
            // Schedule requests from the queue of addresses in
            // request[Load|Store]Queue_ entry
            if ((*itInsn)->isPrefetch()) {
              accepted = mmu_->requestPrefetch((*itInsn));
            } else {
              accepted = mmu_->requestRead((*itInsn));
              if (accepted) {
                numLoadReqs_++;
                idTracking_[(*itInsn)->getSequenceId()] = tickCounter_;
              }
            }
          }
        } else {
          accepted = true;
        }
        // Remove entry from vector if accepted (available bandwidth this
        // cycle)
        if (accepted) {
          // std::cerr << "LOAD LSQ: " << (*itInsn)->getSequenceId() <<
          // std::endl;
          itInsn = itLoad->second.erase(itInsn);
        } else {
          // No more requests of this type can be scheduled this cycle
          exceededLimits[0] = true;
          break;
        }
      }

      // If all instructions for currently selected cycle in
      // request[Load|Store]Queue_ have been scheduled, erase entry
      if (itLoad->second.size() == 0) {
        itLoad = requestLoadQueue_.erase(itLoad);
      }
    } else {
      break;
    }
  }

  // Initialise completion counter
  size_t count = 0;

  // Process completed conditional store request
  // This only applies to a completion order of OoO
  // There's no need to check if it has been flushed as a conditional store
  // must be the next-to-retire instruction std::cerr << "\tCHECK LSQ STORE
  // COND STATE" << std::endl;
  if (completionOrder_ == CompletionOrder::OUTOFORDER &&
      (requestedCondStore_.first != nullptr)) {
    // Check to see if conditional store is ready, if yes then add to
    // completedRequests_ for result forwarding and passing to writeback
    if (requestedCondStore_.first->isCondResultReady()) {
      completedRequests_.push(requestedCondStore_.first);
      requestedCondStore_ = {nullptr, true};
    }
  }

  // Process completed read requests
  // bool found = false;
  // std::cerr << "\tCHECK LSQ LOADS DATA STATE" << std::endl;
  auto load = requestedLoads_.begin();
  while (load != requestedLoads_.end()) {
    // if (load->second.first->getInstructionId() == 0x58d3) found = true;
    if (load->second.first->hasAllData() &&
        !load->second.first->hasExecuted()) {
      // This load has completed
      load->second.first->execute();
      if (load->second.first->isStoreData()) {
        supplyStoreData(load->second.first);
      }
      // If the completion order is OoO, add entry to completedRequests_
      if (completionOrder_ == CompletionOrder::OUTOFORDER)
        completedRequests_.push(load->second.first);
    }
    load++;
  }

  // std::cerr << "\tCHECK LSQ COMPLETED REQUESTS" << std::endl;
  // Pop from the front of the completed loads queue and send to writeback
  while (completedRequests_.size() > 0 && count < completionSlots_.size()) {
    // Skip a completion slot if stalled
    if (completionSlots_[count].isStalled()) {
      count++;
      continue;
    }

    auto& insn = completedRequests_.front();

    auto itrLat = idTracking_.find(insn->getSequenceId());
    if (itrLat != idTracking_.end()) {
      uint64_t lat = tickCounter_ - idTracking_[insn->getSequenceId()];
      if (latMap_.find(lat) == latMap_.end())
        latMap_[lat] = 1;
      else
        latMap_[lat]++;
      idTracking_.erase(itrLat);
    }

    // Don't process load instruction if it has been flushed
    if (insn->isFlushed()) {
      completedRequests_.pop();
      continue;
    }

    // If the load at the front of the queue is yet to execute, continue
    // processing next cycle
    if (insn->isLoad() && !insn->hasExecuted()) {
      break;
    }

    if (insn->isStoreCond() && !insn->isCondResultReady()) {
      break;
    }

    // Forward the results
    forwardOperands_(insn->getDestinationRegisters(), insn->getResults(),
                     insn->getGroup());

    completionSlots_[count].getTailSlots()[0] = std::move(insn);

    completedRequests_.pop();

    count++;
  }
  // std::cerr << "LSQ TICK OUT " << tickCounter_ << std::endl;
}

std::shared_ptr<Instruction> LoadStoreQueue::getViolatingLoad() const {
  return violatingLoad_;
}

bool LoadStoreQueue::isCombined() const { return combined_; }

void LoadStoreQueue::setTid(uint64_t tid) { tid_ = tid; }
uint64_t LoadStoreQueue::getTid() { return tid_; }

}  // namespace pipeline
}  // namespace simeng
