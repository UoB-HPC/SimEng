#include "simeng/pipeline/LoadStoreQueue.hh"

#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <list>

namespace simeng {
namespace pipeline {

/** Check whether requests `a` and `b` overlap. */
bool requestsOverlap(memory::MemoryAccessTarget a,
                     memory::MemoryAccessTarget b) {
  // Check whether one region ends before the other begins, implying no overlap,
  // and negate
  uint32_t aMinSize = std::min(a.size, (uint32_t)4);
  uint32_t bMinSize = std::min(b.size, (uint32_t)4);
  return (a.vaddr <= b.vaddr && (a.vaddr + aMinSize) > b.vaddr) ||
         (a.vaddr >= b.vaddr && a.vaddr < b.vaddr + bMinSize);
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
  insn->setLSQEntry(tickCounter_);
}
void LoadStoreQueue::addStore(const std::shared_ptr<Instruction>& insn) {
  storeQueue_.push_back({insn, {}});
  insn->setLSQEntry(tickCounter_);
}

void LoadStoreQueue::startLoad(const std::shared_ptr<Instruction>& insn) {
  if (accessPrint_)
    std::cerr << "[SimEng]\tStarting load addr @ " << tickCounter_ << " for "
              << tickCounter_ + insn->getLSQLatency() << " " << std::hex
              << insn->getInstructionAddress() << std::dec << " - "
              << insn->getSequenceId() << " - " << insn->getOpcode()
              << std::endl;
  const auto& ld_addresses = insn->getGeneratedAddresses();
  if (ld_addresses.size() == 0) {
    // Early execution if not addresses need to be accessed
    insn->execute();
    completedRequests_.push_front({insn, tickCounter_});
    insn->setLSQRequest(tickCounter_);
    insn->setLSQIssue(tickCounter_);
  } else {
    if (insn->isPrefetch()) {
      requestLoadQueue_[tickCounter_].push_back(insn);
      if (accessPrint_)
        std::cerr << "[SimEng]\t\tRegister prefetch addr @ " << tickCounter_
                  << " for " << tickCounter_ + insn->getLSQLatency() << " "
                  << std::hex << insn->getInstructionAddress() << std::dec
                  << " - " << insn->getSequenceId() << " - "
                  << insn->getOpcode() << std::endl;
      insn->setLSQRequest(tickCounter_);
      return;
    }

    bool inserted = false;
    if (requestLoadQueue_[tickCounter_].size()) {
      auto itEntry = requestLoadQueue_[tickCounter_].begin();
      while (itEntry != requestLoadQueue_[tickCounter_].end()) {
        if ((*itEntry)->getSequenceId() > insn->getSequenceId()) {
          requestLoadQueue_[tickCounter_].insert(itEntry, insn);
          inserted = true;
          break;
        }
        itEntry++;
      }
    }
    if (!inserted) requestLoadQueue_[tickCounter_].push_back(insn);
    insn->setLSQRequest(tickCounter_);

    if (accessPrint_)
      std::cerr << "[SimEng]\t\tRegister load addr @ " << tickCounter_
                << " for " << tickCounter_ + insn->getLSQLatency() << " "
                << std::hex << insn->getInstructionAddress() << std::dec
                << " - " << insn->getSequenceId() << " - " << insn->getOpcode()
                << std::endl;
    // Register active load
    requestedLoads_.emplace(
        insn->getSequenceId(),
        std::pair<std::shared_ptr<Instruction>, uint64_t>({insn, 0}));
  }
}

void LoadStoreQueue::supplyStoreInfo(const std::shared_ptr<Instruction>& insn) {
  if (insn->isStoreAddress() && !insn->isLoad()) {
    if (!insn->getGeneratedAddresses().size()) {
      insn->setCommitReady();
      return;
    }
    if (insn->isStoreCond()) {
      // If the store is marked Exclusive then it isn't sent to writeback
      // straight away.
      // Set commit ready and return early.
      insn->setCommitReady();
    } else {
      uint64_t insertTick = tickCounter_;
      bool inserted = false;
      if (requestStoreAddrQueue_[insertTick].size()) {
        auto itEntry = requestStoreAddrQueue_[insertTick].begin();
        while (itEntry != requestStoreAddrQueue_[insertTick].end()) {
          if ((*itEntry)->getSequenceId() > insn->getSequenceId()) {
            requestStoreAddrQueue_[insertTick].insert(itEntry, insn);
            inserted = true;
            break;
          }
          itEntry++;
        }
      }
      if (!inserted) requestStoreAddrQueue_[insertTick].push_back(insn);
      insn->setLSQRequest(tickCounter_);
      if (accessPrint_)
        std::cerr << "[SimEng]\tRegister store addr @ " << tickCounter_
                  << " for " << insertTick << " " << std::hex
                  << insn->getInstructionAddress() << std::dec << " - "
                  << insn->getSequenceId() << " - " << insn->getOpcode()
                  << std::endl;
      requestedStoreAddrs_.emplace(
          insn->getSequenceId(),
          std::pair<std::shared_ptr<Instruction>, uint64_t>({insn, 0}));
    }
  }

  if (insn->isStoreData()) {
    if (accessPrint_)
      std::cerr << "[SimEng]\tStore data supplied @ " << tickCounter_ << " "
                << std::hex << insn->getInstructionAddress() << std::dec
                << " - " << insn->getSequenceId() << " - " << insn->getOpcode()
                << std::endl;
    // Get identifier values
    const uint64_t macroOpNum = insn->getInstructionId();
    const int microOpNum = insn->getMicroOpIndex();

    // Get data
    const auto& data = insn->getData();

    // Find storeQueue_ entry which is linked to the store data operation
    auto itSt = storeQueue_.begin();
    while (itSt != storeQueue_.end()) {
      auto& entry = itSt->first;
      // Pair entry and incoming store data operation with macroOp identifier
      // and microOp index value pre-detemined in microDecoder
      if (entry->getInstructionId() == macroOpNum &&
          entry->getMicroOpIndex() == microOpNum) {
        // Supply data to be stored by operations
        itSt->second = data;
        const auto& addresses = entry->getGeneratedAddresses();
        auto itr = conflictionMap_.find(entry->getSequenceId());
        if (itr != conflictionMap_.end()) {
          // For each load, we can now execute them given the conflicting
          // store has now been triggered
          auto ldVec = itr->second;
          for (auto load : ldVec) {
            // requestLoadQueue_[tickCounter_].push_back(load);
            if (accessPrint_)
              std::cerr << "[SimEng]\tConflict release load addr @ "
                        << tickCounter_ << " for " << tickCounter_ << " "
                        << std::hex << load->getInstructionAddress() << std::dec
                        << " - " << load->getSequenceId() << " - "
                        << load->getOpcode() << std::endl;
            requestedLoads_.emplace(
                load->getSequenceId(),
                std::pair<std::shared_ptr<Instruction>, uint64_t>({load, 0}));

            for (const auto& addr : load->getGeneratedAddresses()) {
              for (int i = 0; i < addresses.size(); i++) {
                auto& strAddr = addresses[i];
                // Check if store matches load vAddr
                if (strAddr.vaddr <= addr.vaddr &&
                    (addr.vaddr + addr.size) <=
                        (strAddr.vaddr + strAddr.size)) {
                  // If found, extract and supply data
                  char* newData = (char*)calloc(addr.size, sizeof(uint8_t));
                  uint64_t loadTrace = addr.vaddr;
                  for (int j = 0; j < strAddr.size; j++) {
                    if ((strAddr.vaddr + j) >= (addr.vaddr + addr.size)) break;
                    if ((strAddr.vaddr + j) == loadTrace) {
                      newData[loadTrace - addr.vaddr] =
                          data[i].getAsVector<uint8_t>()[j];
                      loadTrace++;
                    }
                  }
                  load->supplyData(addr.vaddr,
                                   RegisterValue(newData, addr.size),
                                   entry->getSequenceId());
                  free(newData);
                  if (stbPrint_)
                    std::cerr << "[SimEng]\t\tSupplying data from SQ entry"
                              << std::endl;
                  break;
                }
              }
            }

            if (load->hasAllData()) {
              load->setLSQIssue(tickCounter_);
              if (accessPrint_)
                std::cerr << "[SimEng]\t\tAll load data supplied @ "
                          << tickCounter_ << " " << std::hex
                          << load->getInstructionAddress() << std::dec << " - "
                          << load->getSequenceId() << " - " << load->getOpcode()
                          << std::endl;
              // This load has completed
              load->execute();
              // If the completion order is OoO, add entry to completedRequests_
              if (completionOrder_ == CompletionOrder::OUTOFORDER)
                completedRequests_.push_front({load, tickCounter_});
            } else {
              bool inserted = false;
              if (requestLoadQueue_[tickCounter_].size()) {
                auto itEntry = requestLoadQueue_[tickCounter_].begin();
                while (itEntry != requestLoadQueue_[tickCounter_].end()) {
                  if ((*itEntry)->getSequenceId() > load->getSequenceId()) {
                    requestLoadQueue_[tickCounter_].insert(itEntry, load);
                    inserted = true;
                    break;
                  }
                  itEntry++;
                }
              }
              if (!inserted) requestLoadQueue_[tickCounter_].push_back(load);
            }
          }
          // Remove all entries for this store from conflictionMap_
          conflictionMap_.erase(itr);
        }
        break;
      } else {
        itSt++;
      }
    }
  }
}

void LoadStoreQueue::recursiveSTBaddition(
    uint64_t baseAddr, uint64_t id, const memory::MemoryAccessTarget& target,
    const RegisterValue& data) {
  bool crossedEntry = false;
  // Add new stb entry if one does not exist for baseAddr
  if (storeBuffer_.find(baseAddr) == storeBuffer_.end()) {
    storeBufferEntry newEntry(baseAddr, storeBufferEntryWidth_, id);
    storeBuffer_[baseAddr] = {newEntry, tickCounter_};
    // if (stbPrint_) storeBuffer_[baseAddr].first.debug_ = true;
  }
  // Add data to stb entry
  crossedEntry = storeBuffer_[baseAddr].first.addToEntry(target, data);

  // Update id to be oldest
  if (storeBuffer_[baseAddr].first.id_ > id)
    storeBuffer_[baseAddr].first.id_ = id;
  storeBuffer_[baseAddr].second = tickCounter_;

  // If an entry was crossed, add data to next stb entry
  if (crossedEntry)
    recursiveSTBaddition(baseAddr + storeBufferEntryWidth_, id, target, data);
}

bool LoadStoreQueue::startStore(const std::shared_ptr<Instruction>& uop) {
  if (accessPrint_)
    std::cerr << "[SimEng]\tStore data registered @ " << tickCounter_ << " "
              << std::hex << uop->getInstructionAddress() << std::dec << " - "
              << uop->getSequenceId() << " - " << uop->getOpcode() << std::endl;
  assert(storeQueue_.size() > 0 &&
         "Attempted to commit a store from an empty queue");
  assert(storeQueue_.front().first->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a store that wasn't present at the front of the "
         "store queue");
  const auto& addresses = uop->getGeneratedAddresses();
  const auto& data = storeQueue_.front().second;

  // Early exit if there's no addresses to process
  if (addresses.size() == 0) {
    // TODO: Check if atomic lock needs to be released (not LL/SC monitor)
    return true;
  }
  // Supply the data to store to the instruction. Can't be done in
  // `supplyStoreInfo` as addresses may not have been calculated
  assert(addresses.size() == data.size() &&
         "[SimEng:LoadStoreQueue] Tried to supply data to an store instruction "
         "with un-equal addresses and data items.");

  // If this instruction is a store conditional operation, track it
  if (uop->isStoreCond() && !uop->isCondResultReady()) {
    if (requestedCondStore_.first != nullptr) return false;

    for (int i = 0; i < data.size(); i++) {
      uop->supplyData(addresses[i].vaddr, data[i]);
    }
    requestedCondStore_ = {uop, false};

    // Reset store's commit ready status as we need to determine any
    // post-memory-request values to be committed
    uop->setCommitReady(false);

    // If the completion order is inorder, reserve an entry in
    // completedRequests_ now
    // if (completionOrder_ == CompletionOrder::INORDER)
    //   completedRequests_.push({uop, tickCounter_ + uop->getLSQLatency()});
  } else if (uop->isAcquire()) {
    for (int i = 0; i < data.size(); i++) {
      mmu_->requestWrite(addresses[i], data[i]);
      storeDataReqs_++;
    }
  } else {
    uint64_t seqId = uop->getSequenceId();
    for (int i = 0; i < addresses.size(); i++) {
      if (stbPrint_) {
        std::cerr << "[SimEng]\t\tNew STB entry for store " << std::hex
                  << uop->getInstructionAddress() << std::dec << " - " << seqId
                  << " - " << std::hex << addresses[i].vaddr << std::dec << " ("
                  << std::hex
                  << addresses[i].vaddr -
                         (addresses[i].vaddr % storeBufferEntryWidth_)
                  << std::dec << "):" << addresses[i].size << std::endl;
      }

      // Find if an STB Entry exists
      uint64_t baseAddr =
          addresses[i].vaddr - (addresses[i].vaddr % storeBufferEntryWidth_);
      // Add to store buffer recursively
      recursiveSTBaddition(baseAddr, seqId, addresses[i], data[i]);

      // Remove stb entries until the capacity isn't exceeded
      while (storeBuffer_.size() > storeBufferSize_) {
        stbCapacityDrains_++;
        // Drain LRU entry and create fresh one with newEntry
        uint64_t oldest = storeBuffer_.begin()->second.second;
        uint64_t index = storeBuffer_.begin()->first;
        for (const auto& entry : storeBuffer_) {
          if (entry.second.second < oldest) {
            oldest = entry.second.second;
            index = entry.first;
          }
        }

        std::vector<std::pair<memory::MemoryAccessTarget, RegisterValue>>
            requests = storeBuffer_[index].first.createRequests(stbReqIds_);
        stbReqIds_ += requests.size();
        for (auto req : requests) {
          requestStoreDataQueue_.push_back(
              {std::make_shared<memory::MemoryAccessTarget>(req.first),
               req.second});
          requestedStoreDatas_[requestStoreDataQueue_.back().first->id] = {
              requestStoreDataQueue_.back().first, req.second};
        }
        storeBuffer_.erase(storeBuffer_.find(index));
      }
    }
  }
  return true;
}

bool LoadStoreQueue::commitStore(const std::shared_ptr<Instruction>& uop) {
  assert(storeQueue_.size() > 0 &&
         "Attempted to commit a store from an empty queue");
  assert(storeQueue_.front().first->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a store that wasn't present at the front of the "
         "store queue");
  if (accessPrint_)
    std::cerr << "[SimEng]\tCommitted Store @ " << tickCounter_ << " "
              << std::hex << uop->getInstructionAddress() << std::dec << " - "
              << uop->getSequenceId() << " - " << uop->getOpcode() << std::endl;

  const auto& addresses = uop->getGeneratedAddresses();

  // Early exit if there's no addresses to process
  if (addresses.size() == 0) {
    // TODO: Check if atomic lock needs to be released (not LL/SC monitor)
    // requestedStoreAddrs_.erase(uop->getSequenceId());
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
    // Violation invalid if the load and store entries are generated by the
    // same instruction
    if (load.second.first->getSequenceId() != uop->getSequenceId()) {
      const auto& loadedAddresses = load.second.first->getGeneratedAddresses();
      // Iterate over store addresses
      for (const auto& storeReq : addresses) {
        // Iterate over load addresses
        for (const auto& loadReq : loadedAddresses) {
          if (loadReq.forwarder != uop->getSequenceId()) {
            // Check for overlapping requests, and flush if discovered
            if (requestsOverlap(storeReq, loadReq)) {
              violatingLoad_ = load.second.first;
            }
          }
        }
      }
    }
  }

  // Resolve any conflictions on this store
  // const auto& data = storeQueue_.front().second;
  auto itr = conflictionMap_.find(uop->getSequenceId());
  if (itr != conflictionMap_.end()) {
    // For each load, we can now execute them given the conflicting
    // store has now been triggered
    auto ldVec = itr->second;
    for (auto load : ldVec) {
      // requestLoadQueue_[tickCounter_].push_back(load);
      if (accessPrint_)
        std::cerr << "[SimEng]\tConflict release load addr @ " << tickCounter_
                  << " for " << tickCounter_ << " " << std::hex
                  << load->getInstructionAddress() << std::dec << " - "
                  << load->getSequenceId() << " - " << load->getOpcode()
                  << std::endl;
      requestedLoads_.emplace(
          load->getSequenceId(),
          std::pair<std::shared_ptr<Instruction>, uint64_t>({load, 0}));

      for (const auto& addr : load->getGeneratedAddresses()) {
        for (int i = 0; i < addresses.size(); i++) {
          auto& strAddr = addresses[i];
          // Check if store matches load vAddr
          if (strAddr.vaddr <= addr.vaddr &&
              (addr.vaddr + addr.size) <= (strAddr.vaddr + strAddr.size)) {
            // If found, extract and supply data
            char* newData = (char*)calloc(addr.size, sizeof(uint8_t));
            uint64_t loadTrace = addr.vaddr;
            for (int j = 0; j < strAddr.size; j++) {
              if ((strAddr.vaddr + j) >= (addr.vaddr + addr.size)) break;
              if ((strAddr.vaddr + j) == loadTrace) {
                newData[loadTrace - addr.vaddr] =
                    storeQueue_.front().second[i].getAsVector<uint8_t>()[j];
                loadTrace++;
              }
            }
            load->supplyData(addr.vaddr, RegisterValue(newData, addr.size),
                             uop->getSequenceId());
            free(newData);
            if (stbPrint_)
              std::cerr << "[SimEng]\t\tSupplying data from SQ entry"
                        << std::endl;
            break;
          }
        }
      }

      if (load->hasAllData()) {
        load->setLSQIssue(tickCounter_);
        if (accessPrint_)
          std::cerr << "[SimEng]\t\tAll load data supplied @ " << tickCounter_
                    << " " << std::hex << load->getInstructionAddress()
                    << std::dec << " - " << load->getSequenceId() << " - "
                    << load->getOpcode() << std::endl;
        // This load has completed
        load->execute();
        // If the completion order is OoO, add entry to completedRequests_
        if (completionOrder_ == CompletionOrder::OUTOFORDER)
          completedRequests_.push_front({load, tickCounter_});
      } else {
        bool inserted = false;
        if (requestLoadQueue_[tickCounter_].size()) {
          auto itEntry = requestLoadQueue_[tickCounter_].begin();
          while (itEntry != requestLoadQueue_[tickCounter_].end()) {
            if ((*itEntry)->getSequenceId() > load->getSequenceId()) {
              requestLoadQueue_[tickCounter_].insert(itEntry, load);
              inserted = true;
              break;
            }
            itEntry++;
          }
        }
        if (!inserted) requestLoadQueue_[tickCounter_].push_back(load);
      }
    }
    // Remove all entries for this store from conflictionMap_
    conflictionMap_.erase(itr);
  }

  // requestedStoreAddrs_.erase(uop->getSequenceId());
  storeQueue_.pop_front();

  if (accessPrint_ && violatingLoad_ != nullptr)
    std::cerr << "[SimEng]\t\tIdentified violating load " << std::hex
              << violatingLoad_->getInstructionAddress() << std::dec << ":"
              << violatingLoad_->getSequenceId() << std::endl;
  return violatingLoad_ != nullptr;
}

void LoadStoreQueue::commitLoad(const std::shared_ptr<Instruction>& uop) {
  assert(loadQueue_.size() > 0 &&
         "Attempted to commit a load from an empty queue");
  assert(loadQueue_.front()->getSequenceId() == uop->getSequenceId() &&
         "Attempted to commit a load that wasn't present at the front of the "
         "load queue");
  if (accessPrint_)
    std::cerr << "[SimEng]\tCommitted Load @ " << tickCounter_ << " "
              << std::hex << uop->getInstructionAddress() << std::dec << " - "
              << uop->getSequenceId() << " - " << uop->getOpcode() << std::endl;

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
  if (accessPrint_) std::cerr << "[SimEng] Flushing unit" << std::endl;
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

  // Remove flushed stores from store queue and confliction queue if an
  // entry exists
  auto itSt = storeQueue_.begin();
  while (itSt != storeQueue_.end()) {
    const auto& entry = itSt->first;
    if (entry->isFlushed()) {
      // Can erase all load entries as they must be younger than flushed
      // store
      conflictionMap_.erase(entry->getSequenceId());
      requestedStoreAddrs_.erase(entry->getSequenceId());
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

  auto itStrReq = requestStoreAddrQueue_.begin();
  while (itStrReq != requestStoreAddrQueue_.end()) {
    auto itInsn = itStrReq->second.begin();
    while (itInsn != itStrReq->second.end()) {
      if ((*itInsn)->isFlushed()) {
        itInsn = itStrReq->second.erase(itInsn);
      } else {
        itInsn++;
      }
    }
    if (itStrReq->second.size() == 0) {
      itStrReq = requestStoreAddrQueue_.erase(itStrReq);
    } else {
      itStrReq++;
    }
  }
}

void LoadStoreQueue::drainSTB() {
  // Drain all STB entries when pipeline is flushed
  auto itr = storeBuffer_.begin();
  while (itr != storeBuffer_.end()) {
    stbSystemDrains_++;

    std::vector<std::pair<memory::MemoryAccessTarget, RegisterValue>> requests =
        itr->second.first.createRequests(stbReqIds_);
    stbReqIds_ += requests.size();
    for (auto req : requests) {
      requestStoreDataQueue_.push_back(
          {std::make_shared<memory::MemoryAccessTarget>(req.first),
           req.second});
      requestedStoreDatas_[requestStoreDataQueue_.back().first->id] = {
          requestStoreDataQueue_.back().first, req.second};
    }
    itr = storeBuffer_.erase(itr);
  }

  while (requestStoreDataQueue_.size() > 0) {
    mmu_->requestWrite(requestStoreDataQueue_.front().first,
                       requestStoreDataQueue_.front().second);
    storeDataReqs_++;
    if (stbPrint_) {
      std::cerr << "[SimEng]\tPipeline Flush drained STB entry "
                << (((1ull << 63) - 1) &
                    requestStoreDataQueue_.front().first->id)
                << " - " << std::hex
                << requestStoreDataQueue_.front().first->vaddr << std::dec
                << ":" << requestStoreDataQueue_.front().first->size
                << std::endl;
    }
    requestStoreDataQueue_.pop_front();
  }
}

void LoadStoreQueue::tick() {
  tickCounter_++;
  if (stbPrint_) {
    std::cerr << "[SimEng] ========== " << tickCounter_
              << " ==========" << std::endl;
    // std::cerr << "[SimEng] === " << tickCounter_
    //           << ", Req Loads: " << requestedLoads_.size()
    //           << ", InFlight Loads: " << requestLoadQueue_.size()
    //           << ", Req StoreAddrs: " << requestedStoreAddrs_.size()
    //           << ", InFlight StoreAddrs: " << requestStoreAddrQueue_.size()
    //           << ", Req StoreDatas: " << requestedStoreDatas_.size()
    //           << ", InFlight StoreDatas: " << requestStoreDataQueue_.size()
    //           << ", Loads: " << loadQueue_.size()
    //           << ", Stores: " << storeQueue_.size() << " ===" << std::endl;
    if (storeBuffer_.size()) {
      std::cerr << "[SimEng]\tSTB:" << std::endl;
      for (const auto& entry : storeBuffer_) {
        std::cerr << "[SimEng]\t" << std::hex << entry.first << std::dec << ":"
                  << entry.second.first.id_ << ":";
        bool extracting = false;
        uint64_t currAddr = 0;
        for (int i = 0; i < entry.second.first.entryWidth_; i++) {
          if (entry.second.first.activeBytes_[std::ceil(i / 64)] &
              (1ull << i % 64)) {
            if (!extracting) {
              extracting = true;
              currAddr = entry.first + i;
            }
          } else if (extracting) {
            extracting = false;
            std::cerr << "[" << std::hex << currAddr << std::dec << "|"
                      << (entry.first + i - currAddr) << "]";
          }
        }
        if (extracting) {
          extracting = false;
          std::cerr << "[" << std::hex << currAddr << std::dec << "|"
                    << (entry.first + entry.second.first.entryWidth_ - currAddr)
                    << "]";
        }
        std::cerr << " - " << entry.second.second << std::endl;
      }
    }
    if (storeQueue_.size()) {
      std::cerr << "[SimEng]\tSQ:" << std::endl;
      for (const auto& str : storeQueue_) {
        std::cerr << "[SimEng]\t" << std::hex
                  << str.first->getInstructionAddress() << std::dec << ":"
                  << str.first->getSequenceId() << " - ";
        for (const auto& addr : str.first->getGeneratedAddresses())
          std::cerr << "[" << std::hex << addr.vaddr << std::dec << ":"
                    << addr.size << "]";
        std::cerr << " - " << str.first->getLSQEntry() << ":"
                  << str.first->getLSQRequest() << ":"
                  << str.first->getLSQIssue() << ":" << str.first->getLSQExit()
                  << std::endl;
      }
    }
    if (loadQueue_.size()) {
      std::cerr << "[SimEng]\tLQ:" << std::endl;
      for (const auto& ldr : loadQueue_) {
        std::cerr << "[SimEng]\t" << std::hex << ldr->getInstructionAddress()
                  << std::dec << ":" << ldr->getSequenceId() << " - ";
        for (const auto& addr : ldr->getGeneratedAddresses())
          std::cerr << "[" << std::hex << addr.vaddr << std::dec << ":"
                    << addr.size << "]";
        std::cerr << " - " << ldr->getLSQEntry() << ":" << ldr->getLSQRequest()
                  << ":" << ldr->getLSQIssue() << ":" << ldr->getLSQExit()
                  << std::endl;
      }
    }
    std::cerr << "[SimEng] -----------------------------" << std::endl;
  } else if (accessPrint_) {
    // std::cerr << "[SimEng] === " << tickCounter_
    //           << ", Req Loads: " << requestedLoads_.size()
    //           << ", InFlight Loads: " << requestLoadQueue_.size()
    //           << ", Req StoreAddrs: " << requestedStoreAddrs_.size()
    //           << ", InFlight StoreAddrs: " << requestStoreAddrQueue_.size()
    //           << ", Req StoreDatas: " << requestedStoreDatas_.size()
    //           << ", InFlight StoreDatas: " << requestStoreDataQueue_.size()
    //           << ", Loads: " << loadQueue_.size()
    //           << ", Stores: " << storeQueue_.size() << " ===" << std::endl;
    std::cerr << "[SimEng] ========== " << tickCounter_
              << " ==========" << std::endl;
  }

  if (pauseUntil_ > tickCounter_) {
    if (accessPrint_) std::cerr << "[SimEng]\tPaused" << std::endl;
    return;
  }
  // Index 0: loads, index 1: stores
  std::array<bool, 2> exceededLimits = {false, false};
  uint8_t numLoads = 0;
  uint8_t numStoreAddr = 0;
  uint8_t numStoreData = 0;

  if (requestedCondStore_.second == false) {
    if (accessPrint_ && !stbPrint_)
      std::cerr << "[SimEng]\tTrying store cond @ " << tickCounter_ << " "
                << std::hex
                << requestedCondStore_.first->getInstructionAddress()
                << std::dec << " - "
                << requestedCondStore_.first->getSequenceId() << " - "
                << requestedCondStore_.first->getOpcode() << std::endl;
    memory::requestSuccess accepted = mmu_->requestWrite(
        requestedCondStore_.first, requestedCondStore_.first->getData());
    if (accessPrint_) {
      if (accepted != memory::requestSuccess::SUCCESS) {
        std::cerr << "[SimEng]\t\tFailed due to ";
        if (accepted == memory::requestSuccess::LIMIT)
          std::cerr << "LIMIT";
        else if (accepted == memory::requestSuccess::TLB_MSHR)
          std::cerr << "TLB_MSHR";
        else if (accepted == memory::requestSuccess::CACHE_MSHR)
          std::cerr << "CACHE_MSHR";
        std::cerr << std::endl;
      }
    }
    exceededLimits = {true, false};
    // if (accepted != memory::requestSuccess::TLB_MSHR)
    numStoreData++;
    if (accepted == memory::requestSuccess::SUCCESS) {
      requestedCondStore_.second = true;
      storeDataReqs_++;
    }
  }

  while (requestStoreDataQueue_.size() > 0) {
    if (numStoreData != 0) break;
    if (accessPrint_)
      std::cerr << "[SimEng]\tTrying store data for addr " << std::hex
                << requestStoreDataQueue_.front().first->vaddr << std::dec
                << " - "
                << (((1ull << 63) - 1) &
                    requestStoreDataQueue_.front().first->id)
                << std::endl;
    memory::requestSuccess accepted =
        mmu_->requestWrite(requestStoreDataQueue_.front().first,
                           requestStoreDataQueue_.front().second, false);
    if (accessPrint_) {
      if (accepted != memory::requestSuccess::SUCCESS) {
        std::cerr << "[SimEng]\t\tFailed due to ";
        if (accepted == memory::requestSuccess::LIMIT)
          std::cerr << "LIMIT";
        else if (accepted == memory::requestSuccess::TLB_MSHR)
          std::cerr << "TLB_MSHR";
        else if (accepted == memory::requestSuccess::CACHE_MSHR)
          std::cerr << "CACHE_MSHR";
        std::cerr << std::endl;
      }
    }
    exceededLimits = {true, false};
    // if (accepted != memory::requestSuccess::TLB_MSHR)
    numStoreData++;
    if (accepted == memory::requestSuccess::SUCCESS) {
      if (stbPrint_) {
        std::cerr << "[SimEng]\t\tSent STB entry "
                  << (((1ull << 63) - 1) &
                      requestStoreDataQueue_.front().first->id)
                  << " - " << std::hex
                  << requestStoreDataQueue_.front().first->vaddr << std::dec
                  << ":" << requestStoreDataQueue_.front().first->size
                  << std::endl;
      }
      idTracking_[requestStoreDataQueue_.front().first->id] = tickCounter_;
      requestStoreDataQueue_.pop_front();
      storeDataReqs_++;
    } else {
      break;
    }
  }

  // Choose which request type to schedule next
  auto reqItrLoad = requestLoadQueue_.begin();
  auto reqItrStore = requestStoreAddrQueue_.begin();
  while (reqItrLoad != requestLoadQueue_.end() ||
         reqItrStore != requestStoreAddrQueue_.end()) {
    if ((numStoreAddr + numStoreData + numLoads) > 1) break;
    bool chooseLoad = false;
    std::pair<bool, uint64_t> earliestLoad;
    std::pair<bool, uint64_t> earliestStore;
    // Determine if a load request can be scheduled
    if (reqItrLoad == requestLoadQueue_.end() ||
        exceededLimits[accessType::LOAD]) {
      earliestLoad = {false, 0};
      if (accessPrint_) std::cerr << "[SimEng]\t\tNo load" << std::endl;
    } else {
      earliestLoad = {true, reqItrLoad->first};
      if (accessPrint_)
        std::cerr << "[SimEng]\t\tGot load for " << reqItrLoad->first << ":"
                  << (*reqItrLoad->second.begin())->getSequenceId()
                  << std::endl;
    }
    // Determine if a store request can be scheduled
    if (reqItrStore == requestStoreAddrQueue_.end() ||
        exceededLimits[accessType::STORE]) {
      earliestStore = {false, 0};
      if (accessPrint_) std::cerr << "[SimEng]\t\tNo store" << std::endl;
    } else {
      earliestStore = {true, reqItrStore->first};
      if (accessPrint_)
        std::cerr << "[SimEng]\t\tGot store addr for " << reqItrStore->first
                  << ":" << (*reqItrStore->second.begin())->getSequenceId()
                  << std::endl;
    }
    // Choose between available requests favouring those constructed earlier
    // (store requests on a tie)
    if (earliestLoad.first) {
      chooseLoad = !(earliestStore.first &&
                     ((earliestLoad.second >= earliestStore.second) ||
                      (earliestStore.second <= tickCounter_ &&
                       ((*reqItrLoad->second.begin())->getSequenceId() >
                        (*reqItrStore->second.begin())->getSequenceId()))));
    } else if (!earliestStore.first) {
      break;
    }
    if (accessPrint_)
      std::cerr << "[SimEng]\t\tchooseLoad: " << chooseLoad << std::endl;

    // Get next request to schedule
    auto& itReq = chooseLoad ? reqItrLoad : reqItrStore;

    if (itReq->first <= tickCounter_) {
      auto itInsn = itReq->second.begin();
      while (itInsn != itReq->second.end()) {
        if (!chooseLoad) {
          if (accessPrint_)
            std::cerr << "[SimEng]\tTrying store addr @ " << tickCounter_ << " "
                      << std::hex << (*itInsn)->getInstructionAddress()
                      << std::dec << " - " << (*itInsn)->getSequenceId()
                      << " - " << (*itInsn)->getOpcode() << std::endl;
          if ((numStoreAddr + numStoreData + numLoads) > 1) {
            exceededLimits[accessType::STORE] = true;
            if (accessPrint_)
              std::cerr << "[SimEng]\t\tExceeded limits "
                        << unsigned(numStoreData) << ":"
                        << unsigned(numStoreAddr) << ":" << unsigned(numLoads)
                        << std::endl;
            break;
          }

          // Apply restrictions on dual issue of store data and addr flows
          if (numStoreData != 0) {
            bool unAligned = false;
            for (const auto& addr : (*itInsn)->getGeneratedAddresses()) {
              if (addr.vaddr % 8 != 0) {
                itInsn++;
                unAligned = true;
                if (accessPrint_)
                  std::cerr << "[SimEng]\t\tNot aligned to 8 bytes ("
                            << addr.vaddr % 8 << ")" << std::endl;
                break;
              }
            }
            if (unAligned) {
              continue;
            }
          }

          memory::requestSuccess accepted = mmu_->requestTranslation(*itInsn);
          if (accessPrint_) {
            if (accepted != memory::requestSuccess::SUCCESS) {
              std::cerr << "[SimEng]\t\tFailed due to ";
              if (accepted == memory::requestSuccess::LIMIT)
                std::cerr << "LIMIT";
              else if (accepted == memory::requestSuccess::TLB_MSHR)
                std::cerr << "TLB_MSHR";
              else if (accepted == memory::requestSuccess::CACHE_MSHR)
                std::cerr << "CACHE_MSHR";
              std::cerr << std::endl;
            }
          }
          if (accepted == memory::requestSuccess::SUCCESS) {
            (*itInsn)->setLSQIssue(tickCounter_);
            itInsn = reqItrStore->second.erase(itInsn);
            storeAddrReqs_++;
          } else {
            itInsn++;
          }
          // if (accepted != memory::requestSuccess::TLB_MSHR)
          numStoreAddr++;
        } else if (chooseLoad) {
          if (accessPrint_)
            std::cerr << "[SimEng]\tTrying load @ " << tickCounter_ << " "
                      << std::hex << (*itInsn)->getInstructionAddress()
                      << std::dec << " - " << (*itInsn)->getSequenceId()
                      << " - " << (*itInsn)->getOpcode() << std::endl;
          if ((numStoreAddr + numStoreData + numLoads) > 1) {
            exceededLimits[accessType::STORE] = true;
            if (accessPrint_)
              std::cerr << "[SimEng]\t\tExceeded limits "
                        << unsigned(numStoreData) << ":"
                        << unsigned(numStoreAddr) << ":" << unsigned(numLoads)
                        << std::endl;
            break;
          }

          std::vector<uint64_t> drainSTB = {};
          uint16_t idx = 0;
          uint64_t conflictID = 0;
          // Check for entry in storeBuffer
          auto addresses = (*itInsn)->getGeneratedAddresses();
          for (auto addr : addresses) {
            numLoads++;
            bool entryMatch = false;
            uint64_t baseLoadAddr =
                addr.vaddr - (addr.vaddr % storeBufferEntryWidth_);
            if (stbPrint_)
              std::cerr << "[SimEng]\t\tConsidering bypass for load "
                        << std::hex << (*itInsn)->getInstructionAddress()
                        << std::dec << " - " << (*itInsn)->getSequenceId()
                        << " with address " << std::hex << addr.vaddr
                        << std::dec << ":" << addr.size << " (" << std::hex
                        << baseLoadAddr << std::dec << ")..." << std::endl;
            // Detect reordering conflicts
            uint64_t seqId = (*itInsn)->getSequenceId();
            for (auto itSt = storeQueue_.rbegin(); itSt != storeQueue_.rend();
                 itSt++) {
              if ((*itInsn)->isPrefetch()) {
                if (accessPrint_)
                  std::cerr << "[SimEng]\t\tPrefetch so no SQ supply"
                            << std::endl;
                break;
              }
              const auto& store = itSt->first;
              // If entry is earlier in the program order than load,
              // detect conflicts
              if (store->getSequenceId() < seqId) {
                const auto& str_addresses = store->getGeneratedAddresses();
                // Iterate over possible overlaps between store and load
                // addresses
                if (accessPrint_)
                  std::cerr << "[SimEng]\t\tChecking overlap on Id "
                            << store->getSequenceId() << std::endl;
                for (const auto& strAddr : str_addresses) {
                  // Check if there's an overlap
                  if (requestsOverlap(addr, strAddr)) {
                    entryMatch = true;
                    // Check if store matches load vAddr
                    if (strAddr.vaddr <= addr.vaddr &&
                        (addr.vaddr + addr.size) <=
                            (strAddr.vaddr + strAddr.size)) {
                      // Check to see if there's data
                      if (itSt->second.size()) {
                        // If found, extract and supply data
                        char* newData =
                            (char*)calloc(addr.size, sizeof(uint8_t));
                        uint64_t loadTrace = addr.vaddr;
                        for (int i = 0; i < strAddr.size; i++) {
                          if ((strAddr.vaddr + i) >= (addr.vaddr + addr.size))
                            break;
                          if ((strAddr.vaddr + i) == loadTrace) {
                            newData[loadTrace - addr.vaddr] =
                                itSt->second[idx].getAsVector<uint8_t>()[i];
                            loadTrace++;
                          }
                        }
                        (*itInsn)->supplyData(addr.vaddr,
                                              RegisterValue(newData, addr.size),
                                              store->getSequenceId());
                        free(newData);
                        if (stbPrint_)
                          std::cerr
                              << "[SimEng]\t\t\tSupplying data from SQ entry"
                              << std::endl;
                        sqSupplies_++;
                        break;
                      }
                    }
                    if (store->getSequenceId() > conflictID) {
                      if (accessPrint_)
                        std::cerr << "[SimEng]\t\tPossible conflict on Id  "
                                  << store->getSequenceId() << std::endl;
                      conflictID = store->getSequenceId();
                    }
                  }
                }
              }
            }
            idx++;

            if (!entryMatch) {
              // Find STB entry for addresses to be loaded
              auto stbEntry = storeBuffer_.find(baseLoadAddr);
              if (stbEntry != storeBuffer_.end()) {
                if ((*itInsn)->isLoadReserved()) {
                  if (stbPrint_)
                    std::cerr << "[SimEng]\t\t\tLoad reserve draining entry "
                              << std::hex << baseLoadAddr << std::dec
                              << std::endl;
                  drainSTB.push_back(baseLoadAddr);
                } else {
                  // See if data exists for the exact load address range
                  stbOverlap overlapStatus =
                      stbEntry->second.first.doesContain(addr);
                  if (overlapStatus == stbOverlap::FULL) {
                    if (!(*itInsn)->isPrefetch()) {
                      (*itInsn)->supplyData(
                          addr.vaddr, stbEntry->second.first.extractData(addr),
                          stbEntry->second.first.id_);
                      if (stbPrint_)
                        std::cerr
                            << "[SimEng]\t\t\tSupplying data from STB entry"
                            << std::endl;
                      stbSupplies_++;
                    } else if (stbPrint_)
                      std::cerr
                          << "[SimEng]\t\t\tPrefetched data already in STB"
                          << std::endl;
                    // Update LRU value
                    stbEntry->second.second = tickCounter_;
                  } else if (overlapStatus == stbOverlap::PARTIAL) {
                    // If no valid block was found, drain STB
                    if (stbPrint_) {
                      if ((*itInsn)->isPrefetch())
                        std::cerr << "[SimEng]\t\t\tPrefetched data only "
                                     "partially in STB, draining entry"
                                  << std::hex << baseLoadAddr << std::dec
                                  << std::endl;
                      else
                        std::cerr
                            << "[SimEng]\t\t\tNo satisfying data in entry, "
                               "draining entry "
                            << std::hex << baseLoadAddr << std::dec
                            << std::endl;
                    }
                    drainSTB.push_back(baseLoadAddr);
                  }
                }
              } else if (stbPrint_) {
                std::cerr << "[SimEng]\t\t\tNo matching entry" << std::endl;
              }

              // Check that no STB entry straddling exists
              uint64_t straddleLoadAddr = baseLoadAddr + storeBufferEntryWidth_;
              if ((addr.vaddr + addr.size) > straddleLoadAddr) {
                if (stbPrint_)
                  std::cerr
                      << "[SimEng]\t\t\tChecking for existence of straddeled "
                         "entry "
                      << std::hex << straddleLoadAddr << std::dec << "..."
                      << std::endl;
                if (storeBuffer_.find(straddleLoadAddr) != storeBuffer_.end()) {
                  drainSTB.push_back(straddleLoadAddr);
                  if (stbPrint_)
                    std::cerr
                        << "[SimEng]\t\t\tDraining STB straddled entry found"
                        << std::endl;
                } else {
                  if (stbPrint_)
                    std::cerr << "[SimEng]\t\t\tNo STB straddled entry found"
                              << std::endl;
                }
              }
            }
          }

          if (drainSTB.size()) {
            exceededLimits = {true, false};
            stbMismatchDrains_ += drainSTB.size();
            for (const auto& stbEntry : drainSTB) {
              auto itr = storeBuffer_.find(stbEntry);
              if (itr != storeBuffer_.end()) {
                std::vector<
                    std::pair<memory::MemoryAccessTarget, RegisterValue>>
                    requests = itr->second.first.createRequests(stbReqIds_);
                stbReqIds_ += requests.size();
                for (auto req : requests) {
                  requestStoreDataQueue_.push_back(
                      {std::make_shared<memory::MemoryAccessTarget>(req.first),
                       req.second});
                  requestedStoreDatas_[requestStoreDataQueue_.back()
                                           .first->id] = {
                      requestStoreDataQueue_.back().first, req.second};
                }

                itr = storeBuffer_.erase(itr);
              }
            }

            // Send off a data request
            if ((numLoads + numStoreData == 0) && numStoreAddr > 1) {
              if (accessPrint_)
                std::cerr << "[SimEng]\tTrying store data for addr " << std::hex
                          << requestStoreDataQueue_.front().first->vaddr
                          << std::dec << " - "
                          << (((1ull << 63) - 1) &
                              requestStoreDataQueue_.front().first->id)
                          << std::endl;
              memory::requestSuccess accepted = mmu_->requestWrite(
                  requestStoreDataQueue_.front().first,
                  requestStoreDataQueue_.front().second, false);
              if (accessPrint_) {
                if (accepted != memory::requestSuccess::SUCCESS) {
                  std::cerr << "[SimEng]\t\tFailed due to ";
                  if (accepted == memory::requestSuccess::LIMIT)
                    std::cerr << "LIMIT";
                  else if (accepted == memory::requestSuccess::TLB_MSHR)
                    std::cerr << "TLB_MSHR";
                  else if (accepted == memory::requestSuccess::CACHE_MSHR)
                    std::cerr << "CACHE_MSHR";
                  std::cerr << std::endl;
                }
              }
              exceededLimits = {true, false};
              // if (accepted != memory::requestSuccess::TLB_MSHR)
              numStoreData++;
              if (accepted == memory::requestSuccess::SUCCESS) {
                if (stbPrint_) {
                  std::cerr << "[SimEng]\t\tSent STB entry "
                            << (((1ull << 63) - 1) &
                                requestStoreDataQueue_.front().first->id)
                            << " - " << std::hex
                            << requestStoreDataQueue_.front().first->vaddr
                            << std::dec << ":"
                            << requestStoreDataQueue_.front().first->size
                            << std::endl;
                }
                idTracking_[requestStoreDataQueue_.front().first->id] =
                    tickCounter_;
                requestStoreDataQueue_.pop_front();
                storeDataReqs_++;
              }
            }
          }
          if ((*itInsn)->hasAllData()) {
            if (accessPrint_)
              std::cerr << "[SimEng]\t\tAll load data already supplied @ "
                        << tickCounter_ << " " << std::hex
                        << (*itInsn)->getInstructionAddress() << std::dec
                        << " - " << (*itInsn)->getSequenceId() << " - "
                        << (*itInsn)->getOpcode() << std::endl;
            (*itInsn)->setLSQIssue(tickCounter_);
            (*itInsn)->setreadTLBRet(true);
            (*itInsn)->setcycleMemSent(tickCounter_);
            (*itInsn)->setcycleMemRecv(tickCounter_);
            idTracking_[(*itInsn)->getSequenceId()] = tickCounter_;
            itInsn = reqItrLoad->second.erase(itInsn);
          } else {
            if (conflictID != 0) {
              // Transfer load to conflict map
              if (accessPrint_)
                std::cerr << "[SimEng]\t\tIdentified conflict on store "
                          << conflictID << std::endl;
              conflictionMap_[conflictID].push_back((*itInsn));
              conflicts_++;
              requestedLoads_.erase((*itInsn)->getSequenceId());
              itInsn = reqItrLoad->second.erase(itInsn);
              continue;
            }
            if (!drainSTB.size()) {
              memory::requestSuccess accepted = mmu_->requestRead((*itInsn));
              if (accessPrint_) {
                if (accepted != memory::requestSuccess::SUCCESS) {
                  std::cerr << "[SimEng]\t\tFailed due to ";
                  if (accepted == memory::requestSuccess::LIMIT)
                    std::cerr << "LIMIT";
                  else if (accepted == memory::requestSuccess::TLB_MSHR)
                    std::cerr << "TLB_MSHR";
                  else if (accepted == memory::requestSuccess::CACHE_MSHR)
                    std::cerr << "CACHE_MSHR";
                  std::cerr << std::endl;
                }
              }
              // if (accepted == memory::requestSuccess::TLB_MSHR) {
              //   numLoads -= addresses.size();
              // }
              if (accepted == memory::requestSuccess::SUCCESS) {
                (*itInsn)->setLSQIssue(tickCounter_);
                loadReqs_++;
                idTracking_[(*itInsn)->getSequenceId()] = tickCounter_;
                itInsn = reqItrLoad->second.erase(itInsn);
              } else {
                itInsn++;
              }
            } else {
              break;
            }
          }
        }
      }

      // If all instructions for currently selected cycle in
      // request[Load|Store]Queue_ have been scheduled, erase entry
      if (chooseLoad) {
        if (reqItrLoad->second.size() == 0) {
          reqItrLoad = requestLoadQueue_.erase(reqItrLoad);
        } else {
          reqItrLoad++;
        }
      } else {
        if (reqItrStore->second.size() == 0) {
          reqItrStore = requestStoreAddrQueue_.erase(reqItrStore);
        } else {
          reqItrStore++;
        }
      }
    } else {
      if (accessPrint_) std::cerr << "[SimEng]\tToo soon" << std::endl;
      break;
    }
  }

  if ((numLoads + numStoreData + numStoreAddr) == 0) {
    // Generate data request from STB if queue is empty
    uint64_t oldest = UINT64_MAX;
    uint64_t index = 0;
    if (requestStoreDataQueue_.size() == 0) {
      // Find LRU entry thats had at least 1000 cycles since use
      for (const auto& stbEntry : storeBuffer_) {
        if (stbEntry.second.second < oldest &&
            (tickCounter_ - stbEntry.second.second) > 1000) {
          oldest = stbEntry.second.second;
          index = stbEntry.first;
        }
      }
      // If valid entry was found, generate memory request(s)
      if (oldest != UINT64_MAX) {
        stbQuietDrain_++;
        std::vector<std::pair<memory::MemoryAccessTarget, RegisterValue>>
            requests = storeBuffer_[index].first.createRequests(stbReqIds_);
        stbReqIds_ += requests.size();
        for (auto req : requests) {
          requestStoreDataQueue_.push_back(
              {std::make_shared<memory::MemoryAccessTarget>(req.first),
               req.second});
          requestedStoreDatas_[requestStoreDataQueue_.back().first->id] = {
              requestStoreDataQueue_.back().first, req.second};
        }
        storeBuffer_.erase(storeBuffer_.find(index));
      }
    }

    // If a data request exists
    if (requestStoreDataQueue_.size() != 0) {
      if (accessPrint_)
        std::cerr << "[SimEng]\tTrying store data for addr " << std::hex
                  << requestStoreDataQueue_.front().first->vaddr << std::dec
                  << " - "
                  << (((1ull << 63) - 1) &
                      requestStoreDataQueue_.front().first->id)
                  << std::endl;
      memory::requestSuccess accepted =
          mmu_->requestWrite(requestStoreDataQueue_.front().first,
                             requestStoreDataQueue_.front().second, false);
      if (accessPrint_) {
        if (accepted != memory::requestSuccess::SUCCESS) {
          std::cerr << "[SimEng]\t\tFailed due to ";
          if (accepted == memory::requestSuccess::LIMIT)
            std::cerr << "LIMIT";
          else if (accepted == memory::requestSuccess::TLB_MSHR)
            std::cerr << "TLB_MSHR";
          else if (accepted == memory::requestSuccess::CACHE_MSHR)
            std::cerr << "CACHE_MSHR";
          std::cerr << std::endl;
        }
      }
      if (accepted == memory::requestSuccess::SUCCESS) {
        if (stbPrint_) {
          std::cerr << "[SimEng]\t\tSent STB entry "
                    << (((1ull << 63) - 1) &
                        requestStoreDataQueue_.front().first->id)
                    << " - " << std::hex
                    << requestStoreDataQueue_.front().first->vaddr << std::dec
                    << ":" << requestStoreDataQueue_.front().first->size
                    << std::endl;
        }
        idTracking_[requestStoreDataQueue_.front().first->id] = tickCounter_;
        requestStoreDataQueue_.pop_front();
        storeDataReqs_++;
      }
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
      completedRequests_.push_back(
          {requestedCondStore_.first,
           tickCounter_ + requestedCondStore_.first->getLSQLatency()});
      requestedCondStore_ = {nullptr, true};
    }
  }

  // Process completed read requests
  if (accessPrint_)
    std::cerr << "[SimEng]\t" << requestedLoads_.size() << " loads to consider"
              << std::endl;
  auto load = requestedLoads_.begin();
  while (load != requestedLoads_.end()) {
    if (load->second.first->getshouldMIMO()) {
      // Pause to mimic MI/MO flows
      pauseUntil_ =
          (pauseUntil_ > tickCounter_) ? pauseUntil_ + 5 : tickCounter_ + 5;
      load->second.first->setshouldMIMO(false);
    }

    if (load->second.first->getreadTLBRet()) {
      if (load->second.first->getmissedTLB()) {
        // Re-issue TLB read
        load->second.first->setreadTLBRet(false);
        load->second.first->setmissedTLB(false);

        bool inserted = false;
        uint64_t insertTick = tickCounter_;
        if (requestLoadQueue_[insertTick].size()) {
          auto itEntry = requestLoadQueue_[insertTick].begin();
          while (itEntry != requestLoadQueue_[insertTick].end()) {
            if ((*itEntry)->getSequenceId() >
                load->second.first->getSequenceId()) {
              requestLoadQueue_[insertTick].insert(itEntry, load->second.first);
              inserted = true;
              break;
            }
            itEntry++;
          }
        }
        if (!inserted)
          requestLoadQueue_[insertTick].push_back(load->second.first);

        if (accessPrint_)
          std::cerr << "[SimEng]\t\tLoad missed L1 TLB " << std::hex
                    << load->second.first->getInstructionAddress() << std::dec
                    << " - " << load->second.first->getSequenceId() << " - "
                    << load->second.first->getOpcode() << std::endl;
        loadTLBReadReIssues_++;
      } else if (load->second.first->getcycleMemRecv() != 0) {
        if (load->second.first->getmissedCache()) {
          // Re-issue Data read
          load->second.first->setcycleMemRecv(0);
          load->second.first->setmissedCache(false);
          load->second.first->setresubmittedMem(true);

          bool inserted = false;
          uint64_t insertTick = tickCounter_;
          if (requestLoadQueue_[insertTick].size()) {
            auto itEntry = requestLoadQueue_[insertTick].begin();
            while (itEntry != requestLoadQueue_[insertTick].end()) {
              if ((*itEntry)->getSequenceId() >
                  load->second.first->getSequenceId()) {
                requestLoadQueue_[insertTick].insert(itEntry,
                                                     load->second.first);
                inserted = true;
                break;
              }
              itEntry++;
            }
          }
          if (!inserted)
            requestLoadQueue_[insertTick].push_back(load->second.first);

          if (accessPrint_)
            std::cerr << "[SimEng]\t\tLoad missed L1D " << std::hex
                      << load->second.first->getInstructionAddress() << std::dec
                      << " - " << load->second.first->getSequenceId() << " - "
                      << load->second.first->getOpcode() << std::endl;
          loadDataReadReIssues_++;
        } else if (load->second.first->hasAllData() &&
                   !load->second.first->hasExecuted()) {
          if (accessPrint_)
            std::cerr << "[SimEng]\t\tLoad hit @ " << tickCounter_ << " "
                      << std::hex << load->second.first->getInstructionAddress()
                      << std::dec << " - "
                      << load->second.first->getSequenceId() << " - "
                      << load->second.first->getOpcode() << std::endl;
          // This load has completed
          load->second.first->execute();

          auto itrLat = idTracking_.find(load->second.first->getSequenceId());
          int64_t lat = -1;
          if (itrLat != idTracking_.end()) {
            lat =
                tickCounter_ - idTracking_[load->second.first->getSequenceId()];
            if (latMap_.find(lat) == latMap_.end())
              latMap_[lat] = 1;
            else
              latMap_[lat]++;
            idTracking_.erase(itrLat);
          }

          if (completionOrder_ == CompletionOrder::OUTOFORDER) {
            // If the completion order is OoO, add entry to completedRequests_
            bool inserted = false;
            uint64_t insertTick =
                tickCounter_ + load->second.first->getLSQLatency();
            if (completedRequests_.size()) {
              auto itEntry = completedRequests_.begin();
              while (itEntry != completedRequests_.end()) {
                if ((*itEntry).second > insertTick) {
                  completedRequests_.insert(itEntry,
                                            {load->second.first, insertTick});
                  inserted = true;
                  break;
                }
                itEntry++;
              }
            }
            if (!inserted)
              completedRequests_.push_back(
                  {load->second.first,
                   tickCounter_ + load->second.first->getLSQLatency()});
          }
        }
      }
    }
    load++;
  }

  if (accessPrint_)
    std::cerr << "[SimEng]\t" << requestedStoreAddrs_.size()
              << " store addrs to consider" << std::endl;
  auto storeAddr = requestedStoreAddrs_.begin();
  while (storeAddr != requestedStoreAddrs_.end()) {
    if (storeAddr->second.first->getshouldMIMO()) {
      // Pause to mimic MI/MO flows
      pauseUntil_ =
          (pauseUntil_ > tickCounter_) ? pauseUntil_ + 5 : tickCounter_ + 5;
      storeAddr->second.first->setshouldMIMO(false);
    }
    if (storeAddr->second.first->getreadTLBRet() &&
        !storeAddr->second.first->getcompletedTLBFlow()) {
      if (storeAddr->second.first->getmissedTLB()) {
        // Re-issue TLB read
        storeAddr->second.first->setreadTLBRet(false);
        storeAddr->second.first->setmissedTLB(false);

        bool inserted = false;
        uint64_t insertTick = tickCounter_;
        if (requestStoreAddrQueue_[insertTick].size()) {
          auto itEntry = requestStoreAddrQueue_[insertTick].begin();
          while (itEntry != requestStoreAddrQueue_[insertTick].end()) {
            if ((*itEntry)->getSequenceId() >
                storeAddr->second.first->getSequenceId()) {
              requestStoreAddrQueue_[insertTick].insert(
                  itEntry, storeAddr->second.first);
              inserted = true;
              break;
            }
            itEntry++;
          }
        }
        if (!inserted)
          requestStoreAddrQueue_[insertTick].push_back(storeAddr->second.first);

        if (accessPrint_)
          std::cerr << "[SimEng]\t\tStore addr missed L1 TLB " << std::hex
                    << storeAddr->second.first->getInstructionAddress()
                    << std::dec << " - "
                    << storeAddr->second.first->getSequenceId() << " - "
                    << storeAddr->second.first->getOpcode() << std::endl;
        storeAddrReIssues_++;
      } else {
        storeAddr->second.first->setcompletedTLBFlow(true);
        if (accessPrint_)
          std::cerr << "[SimEng]\t\tStore addr hit L1 TLB " << std::hex
                    << storeAddr->second.first->getInstructionAddress()
                    << std::dec << " - "
                    << storeAddr->second.first->getSequenceId() << " - "
                    << storeAddr->second.first->getOpcode() << std::endl;
        if (completionOrder_ == CompletionOrder::OUTOFORDER) {
          // If the completion order is OoO, add entry to completedRequests_
          bool inserted = false;
          uint64_t insertTick = tickCounter_;
          if (completedRequests_.size()) {
            auto itEntry = completedRequests_.begin();
            while (itEntry != completedRequests_.end()) {
              if ((*itEntry).second > insertTick) {
                completedRequests_.insert(
                    itEntry, {storeAddr->second.first, insertTick});
                inserted = true;
                break;
              }
              itEntry++;
            }
          }
          if (!inserted)
            completedRequests_.push_back({storeAddr->second.first, insertTick});
        }
      }
      storeAddr++;
    } else if (storeAddr->second.first->getcompletedTLBFlow() &&
               storeAddr->second.first->getcycleMemRecv() != 0) {
      if (storeAddr->second.first->getretroMSHRResub()) {
        // Re-issue Data read
        storeAddr->second.first->setcycleMemSent(0);
        storeAddr->second.first->setcycleMemRecv(0);
        storeAddr->second.first->setmissedCache(false);
        storeAddr->second.first->setresubmittedMem(true);
        storeAddr->second.first->setretroMSHRResub(false);

        bool inserted = false;
        uint64_t insertTick = tickCounter_;
        if (requestStoreAddrQueue_[insertTick].size()) {
          auto itEntry = requestStoreAddrQueue_[insertTick].begin();
          while (itEntry != requestStoreAddrQueue_[insertTick].end()) {
            if ((*itEntry)->getSequenceId() >
                storeAddr->second.first->getSequenceId()) {
              requestStoreAddrQueue_[insertTick].insert(
                  itEntry, storeAddr->second.first);
              inserted = true;
              break;
            }
            itEntry++;
          }
        }
        if (!inserted)
          requestStoreAddrQueue_[insertTick].push_back(storeAddr->second.first);

        if (accessPrint_)
          std::cerr << "[SimEng]\t\tStore addr L1 MSHR resubmission "
                    << std::hex
                    << storeAddr->second.first->getInstructionAddress()
                    << std::dec << " - "
                    << storeAddr->second.first->getSequenceId() << " - "
                    << storeAddr->second.first->getOpcode() << std::endl;
        storeAddr++;
      } else {
        if (accessPrint_)
          std::cerr << "[SimEng]\t\tStore addr L1 DATA resolved " << std::hex
                    << storeAddr->second.first->getInstructionAddress()
                    << std::dec << " - "
                    << storeAddr->second.first->getSequenceId() << " - "
                    << storeAddr->second.first->getOpcode() << std::endl;
        storeAddr = requestedStoreAddrs_.erase(storeAddr);
      }
    } else {
      storeAddr++;
    }
  }

  if (accessPrint_)
    std::cerr << "[SimEng]\t" << requestedStoreDatas_.size()
              << " store datas to consider" << std::endl;
  auto storeData = requestedStoreDatas_.begin();
  while (storeData != requestedStoreDatas_.end()) {
    if (storeData->second.first->shouldMIMO_) {
      // Pause to mimic MI/MO flows
      pauseUntil_ =
          (pauseUntil_ > tickCounter_) ? pauseUntil_ + 5 : tickCounter_ + 5;
      storeData->second.first->shouldMIMO_ = false;
    }
    if (storeData->second.first->cycleMemRecv_ != 0) {
      if (storeData->second.first->missedCache_) {
        // Re-issue data write
        storeData->second.first->cycleMemRecv_ = 0;
        storeData->second.first->missedCache_ = false;
        storeData->second.first->reSubmittedMem_ = true;

        bool inserted = false;
        if (requestStoreDataQueue_.size()) {
          auto itEntry = requestStoreDataQueue_.begin();
          while (itEntry != requestStoreDataQueue_.end()) {
            if (itEntry->first->id > storeData->second.first->id) {
              requestStoreDataQueue_.insert(
                  itEntry, {storeData->second.first, storeData->second.second});
              inserted = true;
              break;
            }
            itEntry++;
          }
        }
        if (!inserted)
          requestStoreDataQueue_.push_back(
              {storeData->second.first, storeData->second.second});

        if (accessPrint_)
          std::cerr << "[SimEng]\tStore Data missed @ " << tickCounter_
                    << " for vaddr " << std::hex
                    << storeData->second.first->vaddr << " - " << std::dec
                    << (((1ull << 63) - 1) & storeData->second.first->id)
                    << std::endl;
        storeDataReIssues_++;
        storeData++;
      } else {
        if (accessPrint_)
          std::cerr << "[SimEng]\tStore Data hit"
                    << (storeData->second.first->reSubmittedMem_
                            ? " after miss "
                            : " ")
                    << "@ " << tickCounter_ << " for vaddr " << std::hex
                    << storeData->second.first->vaddr << std::dec << " - "
                    << (((1ull << 63) - 1) & storeData->second.first->id)
                    << std::endl;

        // auto itrLat = idTracking_.find(storeData->second.first->id);
        // int64_t lat = -1;
        // if (itrLat != idTracking_.end()) {
        //   lat = tickCounter_ - idTracking_[storeData->second.first->id];
        //   if (latMap_.find(lat) == latMap_.end())
        //     latMap_[lat] = 1;
        //   else
        //     latMap_[lat]++;
        //   idTracking_.erase(itrLat);
        // }
        storeData = requestedStoreDatas_.erase(storeData);
      }
    } else {
      storeData++;
    }
  }

  // Pop from the front of the completed loads queue and send to writeback
  if (accessPrint_)
    std::cerr << "[SimEng]\t" << completedRequests_.size()
              << " completed requests to consider" << std::endl;
  while (completedRequests_.size() > 0 && count < completionSlots_.size()) {
    // Skip a completion slot if stalled
    if (completionSlots_[count].isStalled()) {
      count++;
      continue;
    }

    if (completedRequests_.front().second > tickCounter_) {
      if (accessPrint_)
        std::cerr << "[SimEng]\tWaiting to completed flow @ "
                  << completedRequests_.front().second << " for " << std::hex
                  << completedRequests_.front().first->getInstructionAddress()
                  << std::dec << " - "
                  << completedRequests_.front().first->getSequenceId() << " - "
                  << completedRequests_.front().first->getOpcode() << std::endl;
      break;
    }
    auto& insn = completedRequests_.front().first;

    // Don't process load instruction if it has been flushed
    if (insn->isFlushed()) {
      completedRequests_.pop_front();
      continue;
    }

    // If the load at the front of the queue is yet to execute, continue
    // processing next cycle
    if (insn->isLoad()) {
      if (!insn->hasExecuted()) break;
      if (insn->isStoreData()) {
        supplyStoreInfo(insn);
      }
    }

    if (insn->isStoreCond() && !insn->isCondResultReady()) {
      break;
    }
    if (accessPrint_)
      std::cerr << "[SimEng]\tCompleted flow @ " << tickCounter_ << " (in "
                << tickCounter_ - insn->getLSQIssue() << " cycles) for "
                << std::hex << insn->getInstructionAddress() << std::dec
                << " - " << insn->getSequenceId() << " - " << insn->getOpcode()
                << std::endl;

    // std::cerr << "[SimEng]\tLSQ: " << std::hex <<
    // insn->getInstructionAddress()
    //           << std::dec << ":" << insn->getSequenceId() << std::endl;

    // std::cerr << "[SimEng] Execute " << std::hex
    //           << insn->getInstructionAddress() << std::dec << " - "
    //           << insn->getSequenceId() << " - " << insn->getGroup()
    //           << std::endl;
    // Forward the results
    forwardOperands_(insn->getDestinationRegisters(), insn->getResults(),
                     insn->getGroup());
    insn->setLSQExit(tickCounter_);
    completionSlots_[count].getTailSlots()[0] = std::move(insn);

    completedRequests_.pop_front();

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
