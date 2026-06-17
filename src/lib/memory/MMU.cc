#include "simeng/memory/MMU.hh"

#include <algorithm>
#include <cstdint>
#include <memory>

namespace simeng {
namespace memory {

MMU::MMU(VAddrTranslator fn, std::function<void()> signalPFQClear)
    : cacheLineWidth_(config::SimInfo::getValue<uint64_t>(
          config::SimInfo::getConfig()["Memory-Hierarchy"]
                                      ["Cache-Line-Width"])),
      translate_(fn),
      signalPFQClear_(signalPFQClear) {
  // Initialise Memory bandwidth and request limits
  // TODO: replace with cleaner solution in the ModelConfig itself
  ryml::ConstNodeRef config = config::SimInfo::getConfig();
  if (config::SimInfo::getValue<std::string>(
          config["Core"]["Simulation-Mode"]) != "emulation") {
    loadBandwidth_ = config::SimInfo::getValue<uint64_t>(
        config["LSQ-Memory-Interface"]["Load-Bandwidth"]);
    storeBandwidth_ = config::SimInfo::getValue<uint64_t>(
        config["LSQ-Memory-Interface"]["Store-Bandwidth"]);
    requestLimit_ = config::SimInfo::getValue<uint64_t>(
        config["LSQ-Memory-Interface"]["Permitted-Requests-Per-Cycle"]);
    loadRequestLimit_ = config::SimInfo::getValue<uint64_t>(
        config["LSQ-Memory-Interface"]["Permitted-Loads-Per-Cycle"]);
    storeRequestLimit_ = config::SimInfo::getValue<uint64_t>(
        config["LSQ-Memory-Interface"]["Permitted-Stores-Per-Cycle"]);
    exclusiveRequests_ = config::SimInfo::getValue<bool>(
        config["LSQ-Memory-Interface"]["Exclusive"]);
  } else {
    // If core model is emulation, remove all bandwidth and request limits. This
    // ensures single cycle processing of each instruction.
    loadBandwidth_ = UINT64_MAX;
    storeBandwidth_ = UINT64_MAX;
    requestLimit_ = UINT64_MAX;
    loadRequestLimit_ = UINT64_MAX;
    storeRequestLimit_ = UINT64_MAX;
    exclusiveRequests_ = true;
  }
}

void MMU::tick() {
  ticks_++;
  numReqsInCycle_ = prfsInCycle;
  prfsInCycle = 0;
  bandwidthUsed_ = prfBandwith;
  prfBandwith = 0;

  if (numInFlightRequestsTally_.find(inFlightRequests_.size()) ==
      numInFlightRequestsTally_.end())
    numInFlightRequestsTally_[inFlightRequests_.size()] = 0;
  numInFlightRequestsTally_[inFlightRequests_.size()]++;

  if (print_) {
    std::cerr << "[SimEng] -----------------------------" << std::endl;
    // std::cerr << "[SimEng]\tTLB Reqs: " << tlbReqs_.size() << std::endl;
    // std::cerr << "[SimEng]\tTLB MSHRs: " << activeTLBMSHRs_ << std::endl;
    std::cerr << "[SimEng]\tCache MSHRs: " << totalActiveMSHRs_ << std::endl;
    // for (auto& entry : l1MSHRs_) {
    //   if (entry.second.hasMissed_)
    //     std::cerr << "[SimEng]\t\t: " << std::hex << entry.first << std::dec
    //               << " with " << entry.second.associatedRequests_.size()
    //               << " entries" << std::endl;
    // }
    //   std::cerr << std::endl;
    // std::cerr << "[SimEng]\t\tIdle Entries" << std::endl;
    // for (auto& subentry : entry.idleEntries_) {
    //   if (subentry.insn_ != nullptr)
    //     std::cerr << "[SimEng]\t\t\t- " << subentry.insn_->getSequenceId()
    //               << "(" << subentry.reqId_ << ")" << std::endl;
    //   else
    //     std::cerr << "[SimEng]\t\t\t- "
    //               << (((1ull << 63) - 1) & subentry.target_->id) << "("
    //               << subentry.reqId_ << ")" << std::endl;
    // }
    // }
    std::cerr << "[SimEng]\tInFlight MMU: " << inFlightRequests_.size()
              << std::endl;
    uint64_t numRead = 0;
    uint64_t numStoreAddr = 0;
    uint64_t numStoreData = 0;
    for (auto& entry : inFlightRequests_) {
      if (entry->insn_ == nullptr) {
        numStoreData++;
      } else if (entry->insn_->isStoreAddress()) {
        numStoreAddr++;
      } else {
        numRead++;
      }
    }
    std::cerr << "[SimEng]\t\tReads: " << numRead << std::endl;
    std::cerr << "[SimEng]\t\tStore Addrs: " << numStoreAddr << std::endl;
    std::cerr << "[SimEng]\t\tStore Datas: " << numStoreData << std::endl;
  }

  /** NOTE: The number of instructions present in each of the load / store
   * vectors is limited inside the `requestRead()` and `requestWrite()`
   * functions when we add to these vectors.
   * - Total instructions across loads and stores will equal (at most) to
   *   requestLimit_.
   * - Total loads will not exceed loadRequestLimit_.
   * - Total stores will not exceed storeRequestLimit_.
   * - If exclusiveRequests_ == true, then there will only be stores or
   * loads at any one time. */
  if (exclusiveRequests_) {
    // If exclusive access, see which access type has available
    // instructions.
    bool isStore = loadsStores_[STR].size() != 0;
    processRequests(isStore);
  } else {
    // Process Stores first (same as LSQ)
    processRequests(STR);
    processRequests(LD);
  }

  // while (tlbReqs_.size()) {
  //   if (tlbReqs_.front().returnCycle_ <= ticks_) {
  //     if (!tlbReqs_.front().completedReq_) {
  //       if (print_)
  //         std::cerr << "[SimEng]\t\tL2 TLB request for " << std::hex
  //                   << tlbReqs_.front().pageAddr_ << std::dec << std::endl;
  //       tlbL1_.push_back(tlbReqs_.front().pageAddr_);
  //       tlbReqs_.front().completedReq_ = true;
  //       while (tlbL1_.size() > tlbL1Size_) tlbL1_.pop_front();
  //     }
  //     bool shouldTransfer = true;
  //     // If an associated instruction exists, mark its TLB read as complete
  //     if (tlbReqs_.front().associatedPackets_.front().first != nullptr) {
  //       if (tlbReqs_.front().associatedPackets_.front().first->insn_ !=
  //           nullptr) {
  //         tlbReqs_.front()
  //             .associatedPackets_.front()
  //             .first->insn_->setreadTLBRet(true);
  //         if (print_)
  //           std::cerr << "[SimEng]\t\t" << std::hex
  //                     << tlbReqs_.front()
  //                            .associatedPackets_.front()
  //                            .first->insn_->getInstructionAddress()
  //                     << std::dec << " - "
  //                     << tlbReqs_.front()
  //                            .associatedPackets_.front()
  //                            .first->insn_->getSequenceId()
  //                     << " returning on missed TLB" << std::endl;
  //         if (tlbReqs_.front()
  //                 .associatedPackets_.front()
  //                 .first->insn_->isStoreAddress()) {
  //           shouldTransfer = false;
  //           auto reqItr = inFlightRequests_.begin();
  //           while (reqItr != inFlightRequests_.end()) {
  //             if ((*reqItr)->reqId_ ==
  //                 tlbReqs_.front().associatedPackets_.front().first->reqId_)
  //               break;
  //             reqItr++;
  //           }
  //           if (reqItr != inFlightRequests_.end())
  //             inFlightRequests_.erase(reqItr);
  //         }
  //       }
  //     }
  //     // Transfer to loadsStores_ array
  //     if (shouldTransfer &&
  //         tlbReqs_.front().associatedPackets_.front().second.size() != 0) {
  //       loadsStores_[LD].push_back({});
  //       for (int i = 0;
  //            i < tlbReqs_.front().associatedPackets_.front().second.size();
  //            i++) {
  //         loadsStores_[LD].back().push_back(
  //             std::move(tlbReqs_.front().associatedPackets_.front().second[i]));
  //       }
  //     }
  //     activeTLBMSHRs_ -=
  //         tlbReqs_.front().associatedPackets_.front().second.size();
  //     // Decrement/clear TLB MSHR
  //     tlbReqs_.front().associatedPackets_.pop_front();
  //     if (tlbReqs_.front().associatedPackets_.size() == 0) {
  //       tlbReqs_.pop_front();
  //     }
  //   }
  //   break;
  // }
}

void MMU::processRequests(uint8_t type) {
  uint64_t bandwidthLimit = 128;
  if (type == LD)
    bandwidthLimit = loadBandwidth_;
  else if (type == STR)
    bandwidthLimit = storeBandwidth_;

  auto memPkts = loadsStores_[type].begin();
  while (memPkts != loadsStores_[type].end()) {
    // Process as many requests as possible within bandwidth limit
    auto pkt = memPkts->begin();
    while (pkt != memPkts->end()) {
      // If packet is untimed, skip any limit checking
      if ((*pkt)->isUntimed()) {
        issueRequest(std::move(*pkt));
        pkt = memPkts->erase(pkt);
      } else {
        // Check that sending this packet won't exceed bandwidth
        if ((bandwidthUsed_ + (*pkt)->size_) <= bandwidthLimit) {
          bandwidthUsed_ += (*pkt)->size_;

          if (numReqsInCycle_ >= 2) return;

          // Determine if lacking TLB/Cache MSHRs is blocking the cache
          // if (activeTLBMSHRs_ >= maxL1TLBMSHRs_ ||
          //     totalActiveMSHRs_ >= miBufferSize_) {
          //   // Only allow through those requests already marked as missed
          //   uint64_t cl = downAlign((*pkt)->vaddr_, cacheLineWidth_);
          //   if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
          //     if (!l1MSHRs_.at(cl).hasMissed_) return;
          //   }
          // }

          issueRequest(std::move(*pkt));
          pkt = memPkts->erase(pkt);
        } else {
          // Bandwidth will be exceeded. Stop sending instruction packets
          if ((*pkt)->size_ > bandwidthLimit) {
            std::cerr << "[SimEng:MMU] Bandwidth exceeded on ";
            if (type == LD)
              std::cerr << "load";
            else if (type == STR)
              std::cerr << "store";
            std::cerr << " - " << (*pkt)->insnSeqId_ << " - " << (*pkt)->size_
                      << std::endl;
          }
          return;
        }
      }
    }
    memPkts = loadsStores_[type].erase(memPkts);
  }
}

requestSuccess MMU::requestRead(const std::shared_ptr<Instruction>& uop) {
  uint64_t seqId = uop->getSequenceId();
  if (uop->hasAllData()) return requestSuccess::SUCCESS;
  // Check if space for instruction
  // If exclusive then no loads permitted if store still being processed
  if (exclusiveRequests_ && (loadsStores_[STR].size() != 0))
    return requestSuccess::LIMIT;
  // Check total limit isn't met if not exclusive
  if (!exclusiveRequests_ &&
      (loadsStores_[LD].size() + loadsStores_[STR].size() >= requestLimit_)) {
    return requestSuccess::LIMIT;
  }
  // Check space left for a load
  if (loadsStores_[LD].size() >= loadRequestLimit_) {
    std::cerr << "\t\tTotal load bandwidth reached" << std::endl;
    return requestSuccess::LIMIT;
  }

  // Determine if lacking TLB/Cache MSHRs is blocking the cache
  // if (activeTLBMSHRs_ >= maxL1TLBMSHRs_) {
  //   numTLBMSHRBlocks_++;
  //   return requestSuccess::TLB_MSHR;
  // } else
  if (totalActiveMSHRs_ >= miBufferSize_) {
    numCacheMSHRBlocks_++;
    return requestSuccess::CACHE_MSHR;
  }

  const auto& targets = uop->getGeneratedAddresses();
  if (uop->getPendingTranslation() != pendingState::COMPLETE) {
    for (const auto& tgt : targets) {
      uint64_t paddr = translate_(tgt.vaddr, tid_, false);
      if (simeng::OS::masks::faults::getFaultCode(paddr) ==
          simeng::OS::masks::faults::pagetable::PENDING) {
        uop->setPendingTranslation(pendingState::WAITING);
        pendingInsnRequests_[downAlign(tgt.vaddr,
                                       simeng::OS::defaults::PAGE_SIZE)]
            .push_back(uop);
        return requestSuccess::TRANSLATION;
      }
    }
    uop->setPendingTranslation(pendingState::COMPLETE);
  }

  // Check page address in L1 TLB
  // auto tlbMiss = tlbReqs_.begin();
  // bool missed = false;
  // for (int i = 0; i < targets.size(); i++) {
  // uint64_t pageAddr =
  //     downAlign(targets[i].vaddr, simeng::OS::defaults::PAGE_SIZE);
  // if (std::find(tlbL1_.begin(), tlbL1_.end(), pageAddr) == tlbL1_.end()) {
  //   if (print_)
  //     std::cerr << "[SimEng]\t\tLoad " << seqId << " missed TLB" <<
  //     std::endl;
  //   missed = true;

  //   tlbMiss = tlbReqs_.begin();
  //   while (tlbMiss != tlbReqs_.end()) {
  //     if (tlbMiss->pageAddr_ == pageAddr) {
  //       break;
  //     }
  //     tlbMiss++;
  //   }
  //   if (tlbMiss == tlbReqs_.end()) {
  //     if (print_)
  //       std::cerr << "[SimEng]\t\t\tNew TLB miss for page " << std::hex
  //                 << pageAddr << std::dec << " with return on cycle "
  //                 << ticks_ + l2TLBmissPen_ << std::endl;
  //     // Add as entry
  //     tlbReqs_.push_back({pageAddr, ticks_ + l2TLBmissPen_, false, {}});
  //     tlbMiss = tlbReqs_.end() - 1;
  //   }
  //   // Current limitation only allows one active TLB miss per uop
  //   numTLBMisses_++;
  //   tlbMiss->associatedPackets_.push_back({});
  //   break;
  // }
  // }
  // if (!missed) {
  uop->setreadTLBRet(true);
  loadsStores_[LD].push_back({});
  // }

  reqIds_++;

  // Initialise space
  // std::vector<std::unique_ptr<MemPacket>>& memPkts =
  //     missed ? tlbMiss->associatedPackets_.back().second
  //            : loadsStores_[LD].back();
  std::vector<std::unique_ptr<MemPacket>>& memPkts = loadsStores_[LD].back();

  // Create new inflight request
  std::shared_ptr<reqEntry> newReq =
      std::make_shared<reqEntry>(reqIds_, 0, uop);
  inFlightRequests_.push_back(newReq);

  // Generate requests
  uint16_t orderId = 0;
  for (int i = 0; i < targets.size(); i++) {
    if (!uop->hasData(i)) {
      createReadMemPackets(targets[i], memPkts, reqIds_, orderId);
      orderId++;
    }
  }
  // Set MemPackets to be atomic if uop is an atomic operation
  if (uop->isLoadReserved()) {
    for (int i = 0; i < memPkts.size(); i++) {
      memPkts[i]->markAsAtomic();
    }
  }

  // Record total number of requests
  uint16_t totalReqs = static_cast<uint16_t>(memPkts.size());
  inFlightRequests_.back()->totalPacketsRemaining_ = totalReqs;
  // If missed L1 TLB, increment number of active L1 TLB misses and link
  // inflight request
  // if (missed) {
  //   activeTLBMSHRs_ += totalReqs;
  //   tlbMiss->associatedPackets_.back().first = newReq;
  // }

  uop->setcycleMemSent(ticks_);

  // Match or create MSHR for CLs accessed
  for (int i = 0; i < memPkts.size(); i++) {
    uint64_t cl = downAlign(memPkts[i]->vaddr_, cacheLineWidth_);
    if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
      l1MSHRs_[cl] = {false, {}, 0, ticks_};
    }

    if (l1MSHRs_.at(cl).associatedRequests_.size() == 0 &&
        l1MSHRs_.at(cl).lastInteraction_ + 1000 < ticks_) {
      l1MSHRs_.at(cl) = {false, {}, 0, ticks_};
    }

    // Update mshr counts if entry has missed
    if (l1MSHRs_.at(cl).hasMissed_) {
      totalActiveMSHRs_ += (l1MSHRs_.at(cl).associatedRequests_.size())
                               ? 1
                               : 1 + l1MSHRs_.at(cl).assocPRFs_;
      // std::cerr << "[SimEng]\tMSHR count at " << totalActiveMSHRs_
      //           << " in requestRead(" << std::hex << cl << std::dec << ")"
      //           << std::endl;
      // for (const auto& ent : l1MSHRs_) {
      //   if (ent.second.hasMissed_ && ent.second.associatedRequests_.size())
      //     std::cerr << "[SimEng]\t\t" << std::hex << ent.first << std::dec
      //               << " " << ent.second.associatedRequests_.size()
      //               << " associated requests and " << ent.second.assocPRFs_
      //               << " associated prefetches" << std::endl;
      // }
    }
    l1MSHRs_.at(cl).associatedRequests_.push_back(newReq);
    l1MSHRs_.at(cl).lastInteraction_ = ticks_;
  }

  if (print_)
    std::cerr << "[SimEng]\t\tLoad " << std::hex << seqId << std::dec << "("
              << std::hex << reqIds_ << std::dec << ") with " << totalReqs
              << " reqs" << std::endl;
  return requestSuccess::SUCCESS;
}

requestSuccess MMU::requestPrefetch(uint64_t vAddr, uint32_t size) {
  // Determine if lacking TLB/Cache MSHRs is blocking the cache
  requestSuccess retSucc = requestSuccess::SUCCESS;
  // if (activeTLBMSHRs_ >= maxL1TLBMSHRs_) {
  //   numTLBMSHRBlocks_++;
  //   retSucc = requestSuccess::TLB_MSHR;
  //   if (print_)
  //     std::cerr << "[SimEng]\t\tPrefetch " << std::hex << vAddr << std::dec
  //               << " blocked by TLB MSHRs" << std::endl;
  // } else if (totalActiveMSHRs_ >= miBufferSize_ ||
  //            uniqueActiveMSHRs_ >= moBufferSize_) {
  //   numCacheMSHRBlocks_++;
  //   retSucc = requestSuccess::CACHE_MSHR;
  //   if (print_)
  //     std::cerr << "[SimEng]\t\tPrefetch " << std::hex << vAddr << std::dec
  //               << " blocked by Cache MSHRs" << std::endl;
  // }

  // if (retSucc != requestSuccess::SUCCESS) {
  //   prefetchQueue_.push_back({vAddr, size});
  //   return retSucc;
  // }

  // auto tlbMiss = tlbReqs_.begin();
  // bool missed = false;
  // uint64_t pageAddr = downAlign(vAddr, simeng::OS::defaults::PAGE_SIZE);
  // if (std::find(tlbL1_.begin(), tlbL1_.end(), pageAddr) == tlbL1_.end()) {
  //   if (print_)
  //     std::cerr << "[SimEng]\t\tPrefetch " << std::hex << vAddr << std::dec
  //               << " missed TLB" << std::endl;
  //   missed = true;

  //   tlbMiss = tlbReqs_.begin();
  //   while (tlbMiss != tlbReqs_.end()) {
  //     if (tlbMiss->pageAddr_ == pageAddr) {
  //       break;
  //     }
  //     tlbMiss++;
  //   }
  //   if (tlbMiss == tlbReqs_.end()) {
  //     if (print_)
  //       std::cerr << "[SimEng]\t\t\tNew TLB miss for page " << std::hex
  //                 << pageAddr << std::dec << " with return on cycle "
  //                 << ticks_ + l2TLBmissPen_ << std::endl;
  //     // Add as entry
  //     tlbReqs_.push_back({pageAddr, ticks_ + l2TLBmissPen_, false, {}});
  //     tlbMiss = tlbReqs_.end() - 1;
  //   }
  //   // Current limitation only allows one active TLB miss per uop
  //   numTLBMisses_++;
  //   tlbMiss->associatedPackets_.push_back({});
  // } else {
  //   loadsStores_[PRF].push_back({});
  // }

  // if (missed) {
  //   // Communicate to prefetcher that a TLB miss has occured for the prefetch
  //   signalPFQClear_();
  // }

  // reqIds_++;

  // // Initialise space
  // std::vector<std::unique_ptr<MemPacket>>& memPkts =
  //     missed ? tlbMiss->associatedPackets_.back().second
  //            : loadsStores_[PRF].back();

  // // Create target
  // const simeng::memory::MemoryAccessTarget target = {vAddr, size};

  // // Create new inflight request
  // std::shared_ptr<reqEntry> newReq =
  //     std::make_shared<reqEntry>(reqIds_, 0, nullptr);
  // inFlightRequests_.push_back(newReq);

  // // Generate requests
  // createReadMemPackets(target, memPkts, reqIds_, 0, true);
  // // Mark MemPackets as prefetches
  // for (int i = 0; i < memPkts.size(); i++) {
  //   memPkts[i]->markAsPrefetch();
  // }

  // // Record total number of requests
  // uint16_t totalReqs = static_cast<uint16_t>(memPkts.size());
  // inFlightRequests_.back()->totalPacketsRemaining_ = totalReqs;
  // // If missed L1 TLB, increment number of active L1 TLB misses and link
  // // inflight request
  // if (missed) {
  //   activeTLBMSHRs_ += totalReqs;
  //   inFlightRequests_.pop_back();
  // } else {
  //   // Match or create MSHR for CLs accessed
  //   for (int i = 0; i < memPkts.size(); i++) {
  //     uint64_t cl = downAlign(memPkts[i]->vaddr_, cacheLineWidth_);
  //     if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
  //       l1MSHRs_[cl] = {false, {}};
  //     }
  //     l1MSHRs_.at(cl).associatedRequests_.push_back(newReq);
  //     // Update mshr counts if entry has missed
  //     if (l1MSHRs_.at(cl).hasMissed_) totalActiveMSHRs_++;
  //   }
  // }

  // if (print_)
  //   std::cerr << "[SimEng]\t\tPrefetch " << std::hex << vAddr << std::dec <<
  //   "("
  //             << reqIds_ << ") with " << totalReqs << " reqs" << std::endl;
  return retSucc;
}

requestSuccess MMU::requestWrite(const std::shared_ptr<Instruction>& uop,
                                 const std::vector<RegisterValue>& data) {
  // Check if space for instruction
  // If exclusive then no stores permitted if load still being processed
  if (exclusiveRequests_ && (loadsStores_[LD].size() != 0))
    return requestSuccess::LIMIT;
  // Check total limit isn't met if not exclusive
  if (!exclusiveRequests_ &&
      (loadsStores_[LD].size() + loadsStores_[STR].size() >= requestLimit_))
    return requestSuccess::LIMIT;
  // Check space left for a store
  if (loadsStores_[STR].size() >= storeRequestLimit_)
    return requestSuccess::LIMIT;

  // if (activeTLBMSHRs_ >= maxL1TLBMSHRs_) {
  //   numTLBMSHRBlocks_++;
  //   return requestSuccess::TLB_MSHR;
  // } else
  if (totalActiveMSHRs_ >= miBufferSize_) {
    numCacheMSHRBlocks_++;
    return requestSuccess::CACHE_MSHR;
  }

  const auto& targets = uop->getGeneratedAddresses();
  if (uop->getPendingTranslation() != pendingState::COMPLETE) {
    for (const auto& tgt : targets) {
      uint64_t paddr = translate_(tgt.vaddr, tid_, false);
      if (simeng::OS::masks::faults::getFaultCode(paddr) ==
          simeng::OS::masks::faults::pagetable::PENDING) {
        uop->setPendingTranslation(pendingState::WAITING);
        pendingInsnRequests_[downAlign(tgt.vaddr,
                                       simeng::OS::defaults::PAGE_SIZE)]
            .push_back(uop);
        return requestSuccess::TRANSLATION;
      }
    }
    uop->setPendingTranslation(pendingState::COMPLETE);
  }

  reqIds_++;

  // Initialise space in stores
  loadsStores_[STR].push_back({});

  // Create new inflight request
  std::shared_ptr<reqEntry> newReq =
      std::make_shared<reqEntry>(reqIds_, 0, uop);
  inFlightRequests_.push_back(newReq);

  // Generate requests
  assert(data.size() == targets.size() &&
         "[SimEng:MMU] Number of addresses does not match the number of data "
         "elements to write.");
  for (int i = 0; i < targets.size(); i++) {
    const auto& target = targets[i];
    // Format data
    const char* wdata = data[i].getAsVector<char>();
    std::vector<char> dt(wdata, wdata + target.size);
    // Create requests
    createWriteMemPackets(target, loadsStores_[STR].back(), dt, reqIds_, i);
  }
  // Mark MemPackets to be atomic if uop is an atomic operation
  if (uop->isStoreCond()) {
    for (int i = 0; i < loadsStores_[STR].back().size(); i++) {
      loadsStores_[STR].back()[i]->markAsAtomic();
    }
  }

  // Record total number of requests
  uint16_t totalReqs = static_cast<uint16_t>(loadsStores_[STR].back().size());
  inFlightRequests_.back()->totalPacketsRemaining_ = totalReqs;

  // Match or create MSHR for CLs accessed
  for (int i = 0; i < loadsStores_[STR].back().size(); i++) {
    uint64_t cl =
        downAlign(loadsStores_[STR].back()[i]->vaddr_, cacheLineWidth_);
    if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
      l1MSHRs_[cl] = {false, {}, 0};
    }

    if (l1MSHRs_.at(cl).associatedRequests_.size() == 0 &&
        l1MSHRs_.at(cl).lastInteraction_ + 1000 < ticks_) {
      l1MSHRs_.at(cl) = {false, {}, 0, ticks_};
    }

    // Update mshr counts if entry has missed
    if (l1MSHRs_.at(cl).hasMissed_) {
      totalActiveMSHRs_ += (l1MSHRs_.at(cl).associatedRequests_.size())
                               ? 1
                               : 1 + l1MSHRs_.at(cl).assocPRFs_;
      // std::cerr << "[SimEng]\tMSHR count at " << totalActiveMSHRs_
      //           << " in requestWrite(" << std::hex << cl << std::dec << ")"
      //           << std::endl;
      // for (const auto& ent : l1MSHRs_) {
      //   if (ent.second.hasMissed_ && ent.second.associatedRequests_.size())
      //     std::cerr << "[SimEng]\t\t" << std::hex << ent.first << std::dec
      //               << " " << ent.second.associatedRequests_.size()
      //               << " associated requests and " << ent.second.assocPRFs_
      //               << " associated prefetches" << std::endl;
      // }
    }
    l1MSHRs_.at(cl).associatedRequests_.push_back(newReq);
    l1MSHRs_.at(cl).lastInteraction_ = ticks_;
  }

  uop->setcycleMemSent(ticks_);
  uop->setcycleMemRecv(ticks_);
  return requestSuccess::SUCCESS;
}

requestSuccess MMU::requestWrite(
    const std::shared_ptr<MemoryAccessTarget> target, const RegisterValue& data,
    bool bypassRestrictions) {
  if (!bypassRestrictions) {
    // Check if space for request
    // If exclusive then no stores permitted if load still being processed
    if (exclusiveRequests_ && (loadsStores_[LD].size() != 0))
      return requestSuccess::LIMIT;
    // Check total limit isn't met if not exclusive
    if (!exclusiveRequests_ &&
        (loadsStores_[LD].size() + loadsStores_[STR].size() >= requestLimit_))
      return requestSuccess::LIMIT;
    // Check space left for a store
    if (loadsStores_[STR].size() >= storeRequestLimit_)
      return requestSuccess::LIMIT;

    // if (activeTLBMSHRs_ >= maxL1TLBMSHRs_) {
    //   numTLBMSHRBlocks_++;
    //   return requestSuccess::TLB_MSHR;
    // } else
    if (totalActiveMSHRs_ >= miBufferSize_) {
      numCacheMSHRBlocks_++;
      return requestSuccess::CACHE_MSHR;
    }

    if (target->pendingTranslation_ != pendingState::COMPLETE) {
      uint64_t paddr = translate_(target->vaddr, tid_, false);
      if (simeng::OS::masks::faults::getFaultCode(paddr) ==
          simeng::OS::masks::faults::pagetable::PENDING) {
        target->pendingTranslation_ = pendingState::WAITING;
        pendingMemRequests_[downAlign(target->vaddr,
                                      simeng::OS::defaults::PAGE_SIZE)]
            .push_back(target);
        return requestSuccess::TRANSLATION;
      }
    }
    target->pendingTranslation_ = pendingState::COMPLETE;
  }

  reqIds_++;

  // Initialise space in stores
  loadsStores_[STR].push_back({});

  // Create new inflight request
  std::shared_ptr<reqEntry> newReq =
      std::make_shared<reqEntry>(reqIds_, 0, nullptr);
  inFlightRequests_.push_back(newReq);

  // Format data
  const char* wdata = data.getAsVector<char>();
  std::vector<char> dt(wdata, wdata + target->size);
  // Generate requests
  createWriteMemPackets(*(target.get()), loadsStores_[STR].back(), dt, reqIds_,
                        0);
  // Mark MemPackets to be untimed if bypassing restrictions
  if (bypassRestrictions) {
    for (int i = 0; i < loadsStores_[STR].back().size(); i++) {
      loadsStores_[STR].back()[i]->markAsUntimed();
    }
  }

  // Record total number of requests
  uint16_t totalReqs = static_cast<uint16_t>(loadsStores_[STR].back().size());
  inFlightRequests_.back()->totalPacketsRemaining_ = totalReqs;

  // Match or create MSHR for CLs accessed
  for (int i = 0; i < loadsStores_[STR].back().size(); i++) {
    uint64_t cl =
        downAlign(loadsStores_[STR].back()[i]->vaddr_, cacheLineWidth_);
    if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
      l1MSHRs_[cl] = {false, {}, 0};
    }

    if (l1MSHRs_.at(cl).associatedRequests_.size() == 0 &&
        l1MSHRs_.at(cl).lastInteraction_ + 1000 < ticks_) {
      l1MSHRs_.at(cl) = {false, {}, 0, ticks_};
    }

    // Update mshr counts if entry has missed
    if (l1MSHRs_.at(cl).hasMissed_) {
      totalActiveMSHRs_ += (l1MSHRs_.at(cl).associatedRequests_.size())
                               ? 1
                               : 1 + l1MSHRs_.at(cl).assocPRFs_;
      // std::cerr << "[SimEng]\tMSHR count at " << totalActiveMSHRs_
      //           << " in requestWrite(" << std::hex << cl << std::dec << ")"
      //           << std::endl;
      // for (const auto& ent : l1MSHRs_) {
      //   if (ent.second.hasMissed_ && ent.second.associatedRequests_.size())
      //     std::cerr << "[SimEng]\t\t" << std::hex << ent.first << std::dec
      //               << " " << ent.second.associatedRequests_.size()
      //               << " associated requests and " << ent.second.assocPRFs_
      //               << " associated prefetches" << std::endl;
      // }
    }
    l1MSHRs_.at(cl).associatedRequests_.push_back(newReq);
    l1MSHRs_.at(cl).lastInteraction_ = ticks_;
  }
  if (print_)
    std::cerr << "[SimEng]\t\tStore Data " << std::hex
              << (((1ull << 63) - 1) & target->id) << std::dec << "("
              << std::hex << reqIds_ << std::dec << ") with " << totalReqs
              << " reqs" << std::endl;

  return requestSuccess::SUCCESS;
}

requestSuccess MMU::requestWrite(const MemoryAccessTarget& target,
                                 const RegisterValue& data) {
  // Format data
  const char* wdata = data.getAsVector<char>();
  std::vector<char> dt(wdata, wdata + target.size);

  // Initialise space in stores
  reqIds_++;
  loadsStores_[STR].push_back({});

  // Create new inflight request
  std::shared_ptr<reqEntry> newReq =
      std::make_shared<reqEntry>(reqIds_, 0, nullptr);
  inFlightRequests_.push_back(newReq);

  // Create requests
  createWriteMemPackets(target, loadsStores_[STR].back(), dt, reqIds_, 0);

  // Record total number of requests
  uint16_t totalReqs = static_cast<uint16_t>(loadsStores_[STR].back().size());
  inFlightRequests_.back()->totalPacketsRemaining_ = totalReqs;

  for (uint16_t i = 0; i < totalReqs; i++)
    loadsStores_[STR].back()[i]->markAsUntimed();

  // Match or create MSHR for CLs accessed
  for (int i = 0; i < loadsStores_[STR].back().size(); i++) {
    uint64_t cl =
        downAlign(loadsStores_[STR].back()[i]->vaddr_, cacheLineWidth_);
    if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
      l1MSHRs_[cl] = {false, {}, 0};
    }

    if (l1MSHRs_.at(cl).associatedRequests_.size() == 0 &&
        l1MSHRs_.at(cl).lastInteraction_ + 1000 < ticks_) {
      l1MSHRs_.at(cl) = {false, {}, 0, ticks_};
    }

    // Update mshr counts if entry has missed
    if (l1MSHRs_.at(cl).hasMissed_) {
      totalActiveMSHRs_ += (l1MSHRs_.at(cl).associatedRequests_.size())
                               ? 1
                               : 1 + l1MSHRs_.at(cl).assocPRFs_;
      // std::cerr << "[SimEng]\tMSHR count at " << totalActiveMSHRs_
      //           << " in requestWrite(" << std::hex << cl << std::dec << ")"
      //           << std::endl;
      // for (const auto& ent : l1MSHRs_) {
      //   if (ent.second.hasMissed_ && ent.second.associatedRequests_.size())
      //     std::cerr << "[SimEng]\t\t" << std::hex << ent.first << std::dec
      //               << " " << ent.second.associatedRequests_.size()
      //               << " associated requests and " << ent.second.assocPRFs_
      //               << " associated prefetches" << std::endl;
      // }
    }
    l1MSHRs_.at(cl).associatedRequests_.push_back(newReq);
    l1MSHRs_.at(cl).lastInteraction_ = ticks_;
  }
  return requestSuccess::SUCCESS;
}

void MMU::requestInstrRead(const MemoryAccessTarget& target) {
  assert(isAligned(target) &&
         "[SimEng:MMU] Unaligned instruction read requests are not "
         "permitted.");
  // Create and fire off request
  std::unique_ptr<memory::MemPacket> insRequest = MemPacket::createReadRequest(
      target.vaddr, target.size, target.id, 0, tid_);
  insRequest->packetId_ = packetIds_++;
  insRequest->markAsUntimed();
  insRequest->markAsInstrRead();
  issueRequest(std::move(insRequest));
}

requestSuccess MMU::requestTranslation(
    const std::shared_ptr<Instruction>& uop) {
  uint64_t seqId = uop->getSequenceId();

  // Determine if lacking TLB/Cache MSHRs is blocking the cache
  // if (activeTLBMSHRs_ >= maxL1TLBMSHRs_) {
  //   numTLBMSHRBlocks_++;
  //   return requestSuccess::TLB_MSHR;
  // } else
  if (totalActiveMSHRs_ >= miBufferSize_) {
    numCacheMSHRBlocks_++;
    return requestSuccess::CACHE_MSHR;
  }
  // else if (totalActiveMSHRs_ >= miBufferSize_ ||
  //            uniqueActiveMSHRs_ >= moBufferSize_) {
  //   numCacheMSHRBlocks_++;
  //   return requestSuccess::CACHE_MSHR;
  // }

  const auto& targets = uop->getGeneratedAddresses();
  if (uop->getPendingTranslation() != pendingState::COMPLETE) {
    for (const auto& tgt : targets) {
      uint64_t paddr = translate_(tgt.vaddr, tid_, false);
      if (simeng::OS::masks::faults::getFaultCode(paddr) ==
          simeng::OS::masks::faults::pagetable::PENDING) {
        uop->setPendingTranslation(pendingState::WAITING);
        pendingInsnRequests_[downAlign(tgt.vaddr,
                                       simeng::OS::defaults::PAGE_SIZE)]
            .push_back(uop);
        return requestSuccess::TRANSLATION;
      }
    }
    uop->setPendingTranslation(pendingState::COMPLETE);
  }

  // Check page address in L1 TLB
  // auto tlbMiss = tlbReqs_.begin();
  // bool missed = false;
  // for (int i = 0; i < targets.size(); i++) {
  //   uint64_t pageAddr =
  //       downAlign(targets[i].vaddr, simeng::OS::defaults::PAGE_SIZE);
  //   if (std::find(tlbL1_.begin(), tlbL1_.end(), pageAddr) == tlbL1_.end()) {
  //     if (print_)
  //       std::cerr << "[SimEng]\t\tStore Addr " << seqId << " missed TLB"
  //                 << std::endl;
  //     missed = true;

  //     tlbMiss = tlbReqs_.begin();
  //     while (tlbMiss != tlbReqs_.end()) {
  //       if (tlbMiss->pageAddr_ == pageAddr) {
  //         break;
  //       }
  //       tlbMiss++;
  //     }
  //     if (tlbMiss == tlbReqs_.end()) {
  //       if (print_)
  //         std::cerr << "[SimEng]\t\t\tNew TLB miss for page " << std::hex
  //                   << pageAddr << std::dec << " with return on cycle "
  //                   << ticks_ + l2TLBmissPen_ << std::endl;
  //       // Add as entry
  //       tlbReqs_.push_back({pageAddr, ticks_ + l2TLBmissPen_, false, {}});
  //       tlbMiss = tlbReqs_.end() - 1;
  //     }
  //     // Current limitation only allows one active TLB miss per uop
  //     numTLBMisses_++;
  //     tlbMiss->associatedPackets_.push_back({});
  //     break;
  //   }
  // }
  // if (!missed) {
  // if (print_)
  //   std::cerr << "[SimEng]\t\tStore Addr " << seqId << " hit L1 TLB"
  //             << std::endl;
  uop->setreadTLBRet(true);
  // loadsStores_[LD].push_back({});
  // } else {
  //   reqIds_++;

  //   // Initialise space
  //   // std::vector<std::unique_ptr<MemPacket>>& memPkts =
  //   //     missed ? tlbMiss->associatedPackets_.back().second
  //   //            : loadsStores_[LD].back();

  //   // Create new inflight request
  //   std::shared_ptr<reqEntry> newReq =
  //       std::make_shared<reqEntry>(reqIds_, 0, uop);
  //   inFlightRequests_.push_back(newReq);

  //   // Generate requests
  //   uint16_t orderId = 0;
  //   for (int i = 0; i < targets.size(); i++) {
  //     createReadMemPackets(targets[i],
  //                          tlbMiss->associatedPackets_.back().second,
  //                          reqIds_, orderId, true);
  //     orderId++;
  //   }

  //   for (int i = 0; i < tlbMiss->associatedPackets_.back().second.size();
  //   i++) {
  //     tlbMiss->associatedPackets_.back().second[i]->markAsStoreAddr();
  //     // Zero size the requests to ensure no bandwith is incorrectly consumed
  //     tlbMiss->associatedPackets_.back().second[i]->size_ = 0;
  //   }

  //   // Record total number of requests
  //   uint16_t totalReqs =
  //       static_cast<uint16_t>(tlbMiss->associatedPackets_.back().second.size());
  //   inFlightRequests_.back()->totalPacketsRemaining_ = totalReqs;
  //   // If missed L1 TLB, increment number of active L1 TLB misses and link
  //   // inflight request
  //   if (missed) {
  //     activeTLBMSHRs_ += totalReqs;
  //     tlbMiss->associatedPackets_.back().first = newReq;
  //   }

  //   uop->setcycleMemSent(ticks_);

  //   // Match or create MSHR for CLs accessed
  //   // for (int i = 0; i < memPkts.size(); i++) {
  //   //   uint64_t cl = downAlign(memPkts[i]->vaddr_, cacheLineWidth_);
  //   //   if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
  //   //     l1MSHRs_[cl] = {false, {}};
  //   //   }
  //   //   l1MSHRs_.at(cl).associatedRequests_.push_back(newReq);
  //   //   // Update mshr counts if entry has missed
  //   //   if (l1MSHRs_.at(cl).hasMissed_) totalActiveMSHRs_++;
  //   // }
  //   if (print_)
  //     std::cerr << "[SimEng]\t\tStore Addr " << seqId << "(" << reqIds_
  //               << ") with " << totalReqs << " reqs" << std::endl;
  // }
  return requestSuccess::SUCCESS;
}

const span<MemoryReadResult> MMU::getCompletedInstrReads() const {
  return {const_cast<MemoryReadResult*>(completedInstrReads_.data()),
          completedInstrReads_.size()};
}

void MMU::supplyDelayedTranslation(uint64_t vaddr, uint64_t paddr) {
  uint64_t alignedVaddr = downAlign(vaddr, simeng::OS::defaults::PAGE_SIZE);
  // uint64_t alignedPaddr = downAlign(paddr, simeng::OS::defaults::PAGE_SIZE);
  auto it = pendingRequests_.find(alignedVaddr);
  if (it != pendingRequests_.end()) {
    // Check for translation failure
    uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);
    if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
      for (int i = 0; i < it->second.size(); i++) {
        it->second[i]->markAsFaulty();
        port_->recieve(std::move(it->second[i]));
      }
    } else {
      // Release MemPacket back to loadsStores_
      for (int i = 0; i < it->second.size(); i++) {
        uint8_t idx = it->second[i]->isRead() ? LD : STR;
        loadsStores_[idx].push_back({});
        loadsStores_[idx].back().push_back(std::move(it->second[i]));
      }
    }
    pendingRequests_.erase(it);
  }

  auto itI = pendingInsnRequests_.find(alignedVaddr);
  if (itI != pendingInsnRequests_.end()) {
    for (int i = 0; i < itI->second.size(); i++) {
      itI->second[i]->setPendingTranslation(pendingState::COMPLETE);
    }
    pendingInsnRequests_.erase(itI);
  }

  auto itM = pendingMemRequests_.find(alignedVaddr);
  if (itM != pendingMemRequests_.end()) {
    for (int i = 0; i < itM->second.size(); i++) {
      itM->second[i]->pendingTranslation_ = pendingState::COMPLETE;
    }
    pendingMemRequests_.erase(itM);
  }
}

void MMU::clearCompletedIntrReads() { completedInstrReads_.clear(); }

bool MMU::hasPendingRequests() const {
  return (pendingInsnRequests_.size() + pendingMemRequests_.size() +
          pendingRequests_.size() + inFlightRequests_.size()) > 0;
}

void MMU::setTid(uint64_t tid) { tid_ = tid; }
uint64_t MMU::getTid() { return tid_; }

std::shared_ptr<Port<std::unique_ptr<MemPacket>>> MMU::initPort() {
  port_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    uint64_t pktCL = downAlign(packet->vaddr_, cacheLineWidth_);
    if (print_)
      std::cerr << "[SimEng]\t\t\t" << std::hex
                << (((1ull << 63) - 1) & packet->insnSeqId_) << std::dec
                << " returned on CL " << (packet->isRead() ? "read" : "write")
                << (packet->isStoreAddr() ? " (storeAddr)" : "")
                << (packet->isStoreData() ? " (storeData)" : "")
                << (packet->isInstrRead() ? " (insnRead)" : "")
                << (packet->isPrefetch() ? " (prefetch)" : "") << " access "
                << std::hex << pktCL << std::dec << "(" << std::hex
                << packet->vaddr_ << std::dec << ":" << packet->size_ << ")"
                << std::endl;

    if (packet->isInstrRead()) {
      if (packet->isFaulty() || packet->ignore()) {
        // If faulty or ignored, return no data. This signals a data abort.
        completedInstrReads_.push_back({{packet->vaddr_, packet->size_},
                                        RegisterValue(),
                                        packet->insnSeqId_});
        return;
      }
      completedInstrReads_.push_back(
          {{packet->vaddr_, packet->size_},
           RegisterValue(packet->payload().data(), packet->size_),
           packet->insnSeqId_});
      return;
    }

    // Get inflight entry
    uint64_t seqId = packet->insnSeqId_;
    auto reqItr = inFlightRequests_.begin();
    while (reqItr != inFlightRequests_.end()) {
      if ((*reqItr)->reqId_ == seqId) break;
      reqItr++;
    }
    if (reqItr == inFlightRequests_.end()) return;

    // Remove from MSHR if present
    if (l1MSHRs_.find(pktCL) != l1MSHRs_.end()) {
      l1MSHRs_.at(pktCL).lastInteraction_ = ticks_;

      auto mshrItr = l1MSHRs_.at(pktCL).associatedRequests_.begin();
      while (mshrItr != l1MSHRs_.at(pktCL).associatedRequests_.end()) {
        if ((*mshrItr)->reqId_ == (*reqItr)->reqId_) {
          mshrItr = l1MSHRs_.at(pktCL).associatedRequests_.erase(mshrItr);
          if (l1MSHRs_.at(pktCL).hasMissed_) {
            totalActiveMSHRs_--;
            // std::cerr << "[SimEng]\tMSHR count at " << totalActiveMSHRs_
            //           << " in initPort(" << std::hex << pktCL << std::dec <<
            //           ")"
            //           << std::endl;
            // for (const auto& ent : l1MSHRs_) {
            //   if (ent.second.hasMissed_ &&
            //       ent.second.associatedRequests_.size())
            //     std::cerr << "[SimEng]\t\t" << std::hex << ent.first <<
            //     std::dec
            //               << " " << ent.second.associatedRequests_.size()
            //               << " associated requests and "
            //               << ent.second.assocPRFs_ << " associated
            //               prefetches"
            //               << std::endl;
            // }
            if (print_)
              std::cerr << "[SimEng]\t\t\t\t" << std::hex << pktCL << std::dec
                        << " MSHR deducted from "
                        << l1MSHRs_.at(pktCL).associatedRequests_.size()
                        << " request remain" << std::endl;
          }
          break;
        }
        mshrItr++;
      }

      if (l1MSHRs_.at(pktCL).associatedRequests_.size() == 0) {
        if (l1MSHRs_.at(pktCL).hasMissed_) {
          totalActiveMSHRs_ -= l1MSHRs_.at(pktCL).assocPRFs_;
          // std::cerr << "[SimEng]\t\t\tMSHR removed leaving "
          //           << totalActiveMSHRs_ << " active MSHRs" << std::endl;
        }
        l1MSHRs_.erase(pktCL);
      }
    }

    // Early return on software prefetch packet
    if (packet->isPrefetch()) {
      inFlightRequests_.erase(reqItr);
      return;
    }

    if (packet->isRead()) {
      if (packet->isStoreData()) {
        (*reqItr)->totalPacketsRemaining_--;
        if ((*reqItr)->totalPacketsRemaining_ == 0) {
          inFlightRequests_.erase(reqItr);
        } else {
          if (print_) {
            std::cerr << "[SimEng]\t\t\t" << (*reqItr)->totalPacketsRemaining_
                      << " resubmitted store data packets left" << std::endl;
          }
        }
      } else if (packet->isStoreAddr()) {
        (*reqItr)->totalPacketsRemaining_--;
        if ((*reqItr)->totalPacketsRemaining_ == 0) {
          (*reqItr)->insn_->setcycleMemRecv(ticks_);
          inFlightRequests_.erase(reqItr);
        } else {
          if (print_) {
            std::cerr << "[SimEng]\t\t\t" << (*reqItr)->totalPacketsRemaining_
                      << " store addr packets left" << std::endl;
          }
        }
      } else {
        readResponses_.at((*reqItr)->reqId_)
            .at(packet->packetOrderId_)
            .at(packet->packetSplitId_) = std::move(packet);
        (*reqItr)->totalPacketsRemaining_--;
        if ((*reqItr)->totalPacketsRemaining_ == 0) {
          // All packets have come back, supply load instruction all data
          supplyLoadInsnData(seqId);
        } else {
          if (print_)
            std::cerr << "[SimEng]\t\t\t" << (*reqItr)->totalPacketsRemaining_
                      << " load packets left" << std::endl;
        }
      }
    } else if (packet->isWrite()) {
      (*reqItr)->totalPacketsRemaining_--;
      // If any one packet belonging to the uop fails, currently mark is
      // as failed
      if (packet->hasFailed()) (*reqItr)->failed_ = true;

      if ((*reqItr)->totalPacketsRemaining_ == 0) {
        if ((*reqItr)->insn_ != nullptr) {
          if ((*reqItr)->insn_->isStoreCond()) {
            (*reqItr)->insn_->updateCondStoreResult(!(*reqItr)->failed_);
          }
        }
        inFlightRequests_.erase(reqItr);
      } else {
        if (print_) {
          std::cerr << "[SimEng]\t\t\t" << (*reqItr)->totalPacketsRemaining_
                    << " store data packets left" << std::endl;
        }
      }
    }
  };
  port_->registerReceiver(fn);
  return port_;
}

void MMU::issueRequest(std::unique_ptr<MemPacket> request,
                       uint64_t delayedTranslation) {
  numReqsInCycle_++;
  if (print_)
    std::cerr << "[SimEng]\t\t\tAttempting issue of "
              << (request->isRead() ? "read " : "write ")
              << (request->isStoreAddr() ? "(storeAddr) " : "")
              << (request->isStoreData() ? "(storeData) " : "")
              << (request->isInstrRead() ? "(insnRead) " : "") << std::hex
              << (((1ull << 63) - 1) & request->insnSeqId_) << std::dec << ":"
              << std::hex << request->vaddr_ << std::dec << std::endl;

  // TLB miss and consult the page table.
  uint64_t paddr = (delayedTranslation != -1)
                       ? delayedTranslation
                       : translate_(request->vaddr_, tid_, false);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(paddr);

  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
    if (print_) {
      std::cerr << "[SimEng]\t\t\tDATA_ABORT" << std::endl;
    }
    request->markAsFaulty();
    port_->recieve(std::move(request));
    return;
  }

  if (faultCode == simeng::OS::masks::faults::pagetable::PENDING) {
    if (print_) std::cerr << "[SimEng]\t\t\tPENDING" << std::endl;
    // Record the wanted translation if it is currently bein resolved
    // asynchronously
    uint64_t alignedVaddr =
        downAlign(request->vaddr_, simeng::OS::defaults::PAGE_SIZE);
    pendingRequests_[alignedVaddr].push_back(std::move(request));
    return;
  }

  if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    if (print_) std::cerr << "[SimEng]\t\t\tIGNORED" << std::endl;
    request->markAsIgnored();
  } else {
    request->paddr_ = paddr;
  }

  if (print_) std::cerr << "[SimEng]\t\t\tSENT" << std::endl;
  if (request->isInstrRead())
    numInsnReads_++;
  else if (request->isRead()) {
    numDataReads_++;
  } else if (request->isWrite()) {
    numDataWrites_++;
  }

  port_->send(std::move(request));
}

bool MMU::isAligned(const MemoryAccessTarget& target) const {
  assert(target.size != 0 &&
         "[SimEng:MMU] Cannot have a memory target size of 0.");
  uint64_t startAddr = target.vaddr;
  // Must -1 from end address as vaddr + size will give the address at end
  // of region, but this address is not written to. i.e. vaddr = 0, size =
  // 4 :  | | | | | | | |
  //                      Addr:  0 1 2 3 4 5 6 7
  //                             ^-------^
  //                              Payload
  // End address is 4, but we do not write to address 4 hence this is
  // allowed to be a cache line boundary.
  uint64_t endAddr = target.vaddr + target.size - 1;
  // If start and end address down align to same value (w.r.t cache line
  // width), then memory target is aligned.
  // std::cerr << "\t" << std::hex << startAddr << std::dec << "("
  //           << cacheLineWidth_ << "):" << std::hex
  //           << downAlign(startAddr, cacheLineWidth_) << std::dec <<
  //           std::endl;
  // std::cerr << "\t" << std::hex << endAddr << std::dec << "(" <<
  // cacheLineWidth_
  //           << "):" << std::hex << downAlign(endAddr, cacheLineWidth_)
  //           << std::dec << std::endl;
  return (downAlign(startAddr, cacheLineWidth_) ==
          downAlign(endAddr, cacheLineWidth_));
}

void MMU::createReadMemPackets(
    const MemoryAccessTarget& target,
    std::vector<std::unique_ptr<MemPacket>>& outputVec, const uint64_t rId,
    const uint16_t pktOrderId, bool noResponse) {
  if (isAligned(target)) {
    std::unique_ptr<memory::MemPacket> req = MemPacket::createReadRequest(
        target.vaddr, target.size, rId, pktOrderId, tid_);
    req->packetId_ = packetIds_++;
    outputVec.push_back(std::move(req));
    if (!noResponse) {
      // Resize response data structure to equal the number of packets
      // created
      if (readResponses_.find(rId) == readResponses_.end())
        readResponses_[rId] =
            std::map<uint16_t, std::vector<std::unique_ptr<MemPacket>>>();

      if (readResponses_.at(rId).find(pktOrderId) ==
          readResponses_.at(rId).end())
        readResponses_.at(rId)[pktOrderId] =
            std::vector<std::unique_ptr<MemPacket>>();

      readResponses_.at(rId).at(pktOrderId).resize(1);
    }
  } else {
    uint64_t nextAddr = target.vaddr;
    uint64_t remSize = static_cast<uint64_t>(target.size);
    uint16_t nextSplitId = 0;
    while (remSize != 0) {
      // Get size of next target region
      uint16_t regSize = std::min(
          (downAlign(nextAddr, cacheLineWidth_) + cacheLineWidth_) - nextAddr,
          remSize);
      // Create MemPacket
      auto req = MemPacket::createReadRequest(nextAddr, regSize, rId,
                                              pktOrderId, tid_);
      req->packetId_ = packetIds_++;
      req->packetSplitId_ = nextSplitId;
      outputVec.push_back(std::move(req));
      // Update vars
      nextAddr += regSize;
      remSize -= regSize;
      nextSplitId++;
    }
    if (!noResponse) {
      // Resize response data structure to equal the number of packets
      // created
      if (readResponses_.find(rId) == readResponses_.end())
        readResponses_[rId] =
            std::map<uint16_t, std::vector<std::unique_ptr<MemPacket>>>();

      if (readResponses_.at(rId).find(pktOrderId) ==
          readResponses_.at(rId).end())
        readResponses_.at(rId)[pktOrderId] =
            std::vector<std::unique_ptr<MemPacket>>();

      readResponses_.at(rId).at(pktOrderId).resize(nextSplitId);
    }
  }
}

void MMU::createWriteMemPackets(
    const MemoryAccessTarget& target,
    std::vector<std::unique_ptr<MemPacket>>& outputVec,
    const std::vector<char>& data, const uint64_t rId,
    const uint16_t pktOrderId) {
  if (isAligned(target)) {
    std::unique_ptr<MemPacket> req = MemPacket::createWriteRequest(
        target.vaddr, target.size, rId, pktOrderId, tid_, data);
    req->packetId_ = packetIds_++;
    outputVec.push_back(std::move(req));
  } else {
    uint64_t nextAddr = target.vaddr;
    uint64_t remSize = static_cast<uint64_t>(target.size);
    uint16_t nextSplitId = 0;
    std::vector<char> remData = data;
    while (remSize != 0) {
      // Get size of next target region
      uint16_t regSize = std::min(
          (downAlign(nextAddr, cacheLineWidth_) + cacheLineWidth_) - nextAddr,
          remSize);
      // Get data for this region
      auto regData =
          std::vector<char>(remData.begin(), remData.begin() + regSize);
      // Create MemPacket
      auto req = MemPacket::createWriteRequest(nextAddr, regSize, rId,
                                               pktOrderId, tid_, regData);
      req->packetId_ = packetIds_++;
      req->packetSplitId_ = nextSplitId;
      outputVec.push_back(std::move(req));
      // Update vars
      nextAddr += regSize;
      remSize -= regSize;
      nextSplitId++;
      remData = std::vector<char>(remData.begin() + regSize, remData.end());
    }
  }
}

void MMU::supplyLoadInsnData(const uint64_t rId) {
  // Get reference to instruction for easier access
  auto reqItr = inFlightRequests_.begin();
  while (reqItr != inFlightRequests_.end()) {
    if ((*reqItr)->reqId_ == rId) break;
    reqItr++;
  }

  auto& insn = (*reqItr)->insn_;
  insn->setcycleMemRecv(ticks_);

  // Get map of all packets, grouped by packetOrderId
  auto& packets = readResponses_.at(rId);

  // bool foundFault = false;
  // for (const auto& pkts : packets) {
  //   for (const auto& pkt : pkts.second) {
  //     if (pkt->isFaulty()) {
  //       foundFault = true;
  //       break;
  //     }
  //   }
  // }
  // if (foundFault == false && insn->getmissedCache()) {
  //   if (print_)
  //     std::cerr << "[SimEng]\t\t\tLoad took too long ("
  //               << (*reqItr)->insn_->getcycleMemSent() << ":"
  //               << ticks_ - (*reqItr)->insn_->getcycleMemSent() << ") - "
  //               << insn->getSequenceId() << "(" << rId << ")" << std::endl;
  //   inFlightRequests_.erase(reqItr);
  //   return;
  // } else {
  //   insn->setmissedCache(false);
  // }
  for (int i = 0; i < packets.size(); i++) {
    // Get vector containing all packets associated to a single target
    auto& pktVec = packets[i];
    assert(pktVec.size() > 0 &&
           "[SimEng:MMU] Empty read response packet vector.");

    uint64_t addr = pktVec[0]->vaddr_;
    // Do early check on first packet for data abort
    if (pktVec[0]->isFaulty()) {
      // If faulty, return no data. This signals a data abort.
      insn->supplyData(addr, RegisterValue());
      continue;
    }
    // Initialise values with first package
    std::vector<char> mergedData = pktVec[0]->payload();
    uint16_t mergedSize = pktVec[0]->size_;
    bool isFaulty = false;
    // Loop over any remaining packets due to a split
    for (int j = 1; j < pktVec.size(); j++) {
      if (pktVec[j]->isFaulty()) {
        // If faulty, return no data. This signals a data abort.
        insn->supplyData(addr, RegisterValue());
        isFaulty = true;
        break;
      }
      // Increase merged size
      mergedSize += pktVec[j]->size_;
      // Concatonate the payload data
      auto& tempData = pktVec[j]->payload();
      mergedData.insert(mergedData.end(), tempData.begin(), tempData.end());
    }
    // Supply data to instruction
    if (!isFaulty) {
      insn->supplyData(addr, {mergedData.data(), mergedSize});
    }
  }
  assert(insn->hasAllData() &&
         "[SimEng:MMU] Load instruction was supplied memory data but is "
         "still "
         "waiting on further data to be supplied.");
  // Instruction now has all data, remove entry
  inFlightRequests_.erase(reqItr);
}

void MMU::markMiss(uint64_t vAddr, uint8_t type) {
  numCacheMisses_++;
  // Record which address missed so the totalActiveMSHRs_ can be appropriately
  // decremented later
  uint64_t cl = downAlign(vAddr, cacheLineWidth_);
  if (l1MSHRs_.find(cl) != l1MSHRs_.end()) {
    l1MSHRs_.at(cl).lastInteraction_ = ticks_;
    if (l1MSHRs_.at(cl).hasMissed_ == false) {
      l1MSHRs_.at(cl).hasMissed_ = true;
      if (type != 3 ||
          (type == 3 && l1MSHRs_.at(cl).associatedRequests_.size())) {
        totalActiveMSHRs_ += l1MSHRs_.at(cl).associatedRequests_.size() +
                             l1MSHRs_.at(cl).assocPRFs_;
        // std::cerr << "[SimEng]\tMSHR count at " << totalActiveMSHRs_
        //           << " in markMiss(" << std::hex << cl << std::dec << ")"
        //           << std::endl;
        // for (const auto& ent : l1MSHRs_) {
        //   if (ent.second.hasMissed_ && ent.second.associatedRequests_.size())
        //     std::cerr << "[SimEng]\t\t" << std::hex << ent.first << std::dec
        //               << " " << ent.second.associatedRequests_.size()
        //               << " associated requests and " << ent.second.assocPRFs_
        //               << " associated prefetches" << std::endl;
        // }
      }

      if (print_) {
        std::cerr << "[SimEng]\t\t\t\t";
        if (type == 0)
          std::cerr << "Read ";
        else if (type == 1)
          std::cerr << "Write ";
        else if (type == 3)
          std::cerr << "Prf ";
        std::cerr << std::hex << cl << std::dec
                  << " MSHR marked as missed, adding "
                  << l1MSHRs_.at(cl).associatedRequests_.size() +
                         l1MSHRs_.at(cl).assocPRFs_
                  << " requests to the activeTLBMSHRs_ count" << std::endl;
        for (const auto& req : l1MSHRs_.at(cl).associatedRequests_) {
          std::cerr << "[SimEng]\t\t\t\t\t" << std::hex << req->reqId_
                    << std::dec << std::endl;
        }
      }
    }
  }
}

void MMU::notifyPrefetch(uint64_t paddr, uint64_t vaddr, uint64_t size) {
  prfsInCycle++;
  prfBandwith += size;

  if (l1MSHRs_.find(vaddr) == l1MSHRs_.end()) {
    l1MSHRs_[vaddr] = {false, {}, 1, ticks_};
  } else if (l1MSHRs_.at(vaddr).associatedRequests_.size() == 0 &&
             l1MSHRs_.at(vaddr).lastInteraction_ + 1000 < ticks_) {
    l1MSHRs_.at(vaddr) = {false, {}, 1, ticks_};
  } else {
    l1MSHRs_.at(vaddr).assocPRFs_++;
  }

  // Update mshr counts if entry has missed
  if (l1MSHRs_.at(vaddr).hasMissed_ &&
      l1MSHRs_.at(vaddr).associatedRequests_.size()) {
    totalActiveMSHRs_++;
    // std::cerr << "[SimEng]\tMSHR count at " << totalActiveMSHRs_
    //           << " in notifyPrefetch(" << std::hex << vaddr << std::dec <<
    //           ")"
    //           << std::endl;
    // for (const auto& ent : l1MSHRs_) {
    //   if (ent.second.hasMissed_ && ent.second.associatedRequests_.size())
    //     std::cerr << "[SimEng]\t\t" << std::hex << ent.first << std::dec << "
    //     "
    //               << ent.second.associatedRequests_.size()
    //               << " associated requests and " << ent.second.assocPRFs_
    //               << " associated prefetches" << std::endl;
    // }
  }
}
}  // namespace memory
}  // namespace simeng
