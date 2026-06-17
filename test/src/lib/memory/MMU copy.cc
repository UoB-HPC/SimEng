#include "simeng/memory/MMU.hh"

#include <algorithm>
#include <cstdint>
#include <memory>

namespace simeng {
namespace memory {

MMU::MMU(VAddrTranslator fn)
    : cacheLineWidth_(config::SimInfo::getValue<uint64_t>(
          config::SimInfo::getConfig()["Memory-Hierarchy"]
                                      ["Cache-Line-Width"])),
      translate_(fn) {
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
  numReqsInCycle_ = 0;

  // if (print_)
  //   std::cerr << "--- " << ticks_ << " with " << missedReqs_
  //             << " active misses and " << requestedLoads_.size() << " Loads/"
  //             << requestedStores_.size() << " Stores/" <<
  //             readResponses_.size()
  //             << " Read Responses/" << pendingRequests_.size()
  //             << " Pending Requests/" << loadsStores_.size() << " LoadStore/"
  //             << accessedCachedLines_.size() << " Accessed Cache Lines ---"
  //             << std::endl;

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

  if (print_) {
    std::cerr << "[SimEng] -----------------------------" << std::endl;
    // std::cerr << "[SimEng]\tTLB:" << std::endl;
    // for (auto& entry : tlbL1_) {
    //   std::cerr << "[SimEng]\t" << std::hex << entry << std::dec <<
    //   std::endl;
    // }
    std::cerr << "[SimEng]\tTLB Reqs: " << tlbReqs_.size() << std::endl;
    std::cerr << "[SimEng]\tCache MSHR: totalActiveMSHRs_ = "
              << totalActiveMSHRs_
              << " | uniqueActiveMSHRs_ = " << uniqueActiveMSHRs_ << std::endl;
    // for (auto& entry : l1MSHRs_) {
    //   std::cerr << "[SimEng]\t\tCL: " << std::hex << entry.second.clAddr_
    //             << std::dec << std::endl;
    //   std::cerr << "[SimEng]\t\tHead of queue cycle sent: " << std::hex
    //             << entry.second.associatedRequests_.front()->cycleSent_
    //             << std::dec << std::endl;
    //   std::cerr << "[SimEng]\t\t\tMissed: " << entry.second.hasMissed_
    //             << std::endl;
    //   std::cerr << "[SimEng]\t\t\tAssociated Entries: ";
    //   for (auto subentry : entry.second.associatedRequests_) {
    //     if (subentry->insn_ != nullptr)
    //       std::cerr << "[" << subentry->insn_->getSequenceId() << "("
    //                 << subentry->reqId_ << ")"
    //                 << "]";
    //     else
    //       std::cerr << "[" << (((1ull << 63) - 1) & subentry->target_->id)
    //                 << "(" << subentry->reqId_ << ")"
    //                 << "]";
    //   }
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
    // for (auto& entry : inFlightRequests_) {
    //   if (entry.insn_ != nullptr) {
    //     std::cerr << "[SimEng]\tInsn - " << std::hex
    //               << entry.insn_->getInstructionAddress() << std::dec << ":"
    //               << entry.insn_->getSequenceId() << std::endl;
    //   } else {
    //     std::cerr << "[SimEng]\tTarget - " << std::hex <<
    //     entry.target_->vaddr
    //               << std::dec << ":" << (((1ull << 63) - 1) &
    //               entry.target_->id)
    //               << std::endl;
    //   }
    // }
  }

  while (tlbReqs_.size()) {
    if (tlbReqs_.front().returnCycle_ <= ticks_) {
      if (!tlbReqs_.front().completedReq_) {
        if (print_)
          std::cerr << "[SimEng]\t\tL2 TLB request for " << std::hex
                    << tlbReqs_.front().pageAddr_ << std::dec << std::endl;
        tlbL1_.push_back(tlbReqs_.front().pageAddr_);
        tlbReqs_.front().completedReq_ = true;
        while (tlbL1_.size() > tlbL1Size_) tlbL1_.pop_front();
      }
      // if (tlbReqs_.front().toggle_) {
      if (print_)
        std::cerr
            << "[SimEng]\t\t" << std::hex
            << tlbReqs_.front().missQueue_.front()->getInstructionAddress()
            << std::dec << " - "
            << tlbReqs_.front().missQueue_.front()->getSequenceId()
            << " returning on missed TLB" << std::endl;
      tlbReqs_.front().missQueue_.front()->setreadTLBRet(true);
      tlbReqs_.front().missQueue_.front()->setmissedTLB(true);
      tlbReqs_.front().missQueue_.pop_front();
      if (tlbReqs_.front().missQueue_.size() == 0) {
        tlbReqs_.pop_front();
      }
      // } else {
      //   tlbReqs_.front().toggle_ = !tlbReqs_.front().toggle_;
      // }
    } else {
      break;
    }
  }

  // bool shouldFlush = false;
  // auto reqItr = inFlightRequests_.begin();
  // // std::vector<uint64_t> mimoedCLs = {};
  // while (reqItr != inFlightRequests_.end()) {
  //   // Find associated MSHRs
  //   if ((*reqItr)->setMSHRS_) {
  //     reqItr++;
  //     continue;
  //   }

  //   if ((*reqItr)->cycleSent_ + assumedCacheMissedCycles_ > ticks_) {
  //     break;
  //   }
  //   (*reqItr)->setMSHRS_ = true;

  //   // Mark as missed if not yet returned and collate CL accesses
  //   std::vector<uint64_t> clsAccessed = {};
  //   bool isInsn = ((*reqItr)->target_ == nullptr) ? true : false;
  //   if (isInsn) {
  //     if ((*reqItr)->insn_->getcycleMemRecv() == 0) {
  //       // if (!(*reqItr)->insn_->getresubmittedMem())
  //       //   (*reqItr)->insn_->setmissedCache(true);
  //       for (const auto& cl : (*reqItr)->insn_->getCLSAccessed()) {
  //         clsAccessed.push_back(cl);
  //         if (print_)
  //           std::cerr << "[SimEng]\t\t" << (*reqItr)->insn_->getSequenceId()
  //                     << "(" << (*reqItr)->reqId_ << ")'s CL " << std::hex <<
  //                     cl
  //                     << std::dec << " accesses considered missed" <<
  //                     std::endl;
  //       }
  //     }
  //   } else {
  //     if ((*reqItr)->target_->cycleMemRecv_ == 0) {
  //       // if (!(*reqItr)->target_->reSubmittedMem_)
  //       //   (*reqItr)->target_->missedCache_ = true;
  //       for (const auto& cl : (*reqItr)->target_->clsAccessed_) {
  //         clsAccessed.push_back(cl);
  //         if (print_)
  //           std::cerr << "[SimEng]\t\t"
  //                     << (((1ull << 63) - 1) & (*reqItr)->target_->id) << "("
  //                     << (*reqItr)->reqId_ << ")'s CL " << std::hex << cl
  //                     << std::dec << " accesses considered missed" <<
  //                     std::endl;
  //       }
  //     }
  //   }
  //   numCacheMisses_ += clsAccessed.size();

  //   // Register appropriate MSHRs
  //   for (const auto& cl : clsAccessed) {
  //     // Ensure we haven't gone over the MSHR limit
  //     // uint8_t numCacheMSHRs = 0;
  //     // uint8_t numCacheSubMSHRs = 0;
  //     // for (const auto& entry : l1MSHRs_) {
  //     //   numCacheMSHRs++;
  //     //   numCacheSubMSHRs += entry.activeEntries_ +
  //     entry.idleEntries_.size();
  //     // }
  //     // if (numCacheSubMSHRs >= miBufferSize_) {
  //     //   shouldFlush = true;
  //     //   if (print_) {
  //     //     if ((*reqItr)->insn_ != nullptr) {
  //     //       std::cerr << "[SimEng]\tFlushing inflights from "
  //     //                 << (*reqItr)->insn_->getSequenceId() << "(" <<
  //     //                 (*reqItr)->reqId_
  //     //                 << ")" << std::endl;
  //     //     } else {
  //     //       std::cerr << "[SimEng]\tFlushing inflights from "
  //     //                 << (((1ull << 63) - 1) & (*reqItr)->target_->id) <<
  //     "("
  //     //                 << (*reqItr)->reqId_ << ")" << std::endl;
  //     //     }
  //     //   }
  //     //   break;
  //     // }

  //     // Append to/create MSHR entries
  //     // bool found = false;
  //     if (!l1MSHRs_.at(cl).hasMissed_) {
  //       uniqueActiveMSHRs_++;
  //       l1MSHRs_.at(cl).hasMissed_ = true;
  //       totalActiveMSHRs_ += l1MSHRs_.at(cl).associatedRequests_.size();
  //       if (print_)
  //         std::cerr << "[SimEng]\t\t" << std::hex << cl << std::dec
  //                   << " MSHR marked as missed. uniqueActiveMSHRs_: "
  //                   << uniqueActiveMSHRs_
  //                   << " totalActiveMSHRs_: " << totalActiveMSHRs_ <<
  //                   std::endl;
  //     }

  //     // Increment later associated requests ready cycle to represent MSHR
  //     // stalling
  //     // auto incItr = l1MSHRs_.at(cl).associatedRequests_.begin();
  //     // incItr++;
  //     // bool startIncrementing = false;
  //     // while (incItr != l1MSHRs_.at(cl).associatedRequests_.end()) {
  //     //   if (startIncrementing) {
  //     //     (*incItr)->cycleSent_++;
  //     //     continue;
  //     //   }
  //     //   if ((*incItr)->reqId_ == (*reqItr)->reqId_) startIncrementing =
  //     true;
  //     // }

  //     // for (auto& mshr : l1MSHRs_) {
  //     //   if (mshr.clAddr_ == cl) {
  //     //     auto waitingItr =
  //     //         std::find(mshr.waitingEntries_.begin(),
  //     //                   mshr.waitingEntries_.end(), (*reqItr)->reqId_);
  //     //     if (waitingItr != mshr.waitingEntries_.end())
  //     //       mshr.waitingEntries_.erase(waitingItr);

  //     //     mshr.activeEntries_++;
  //     //     found = true;
  //     //     if (print_)
  //     //       std::cerr << "[SimEng]\t\tMSHR for CL " << std::hex << cl
  //     //                 << std::dec << " now has " << mshr.activeEntries_
  //     //                 << " entries" << std::endl;
  //     //     break;
  //     //   }
  //     // }
  //     // if (!found) {
  //     //   // if (numCacheMSHRs >= moBufferSize_) {
  //     //   // shouldFlush = true;
  //     //   // if (print_) {
  //     //   //   if ((*reqItr)->insn_ != nullptr) {
  //     //   //     std::cerr << "[SimEng]\tFlushing inflights from "
  //     //   //               << (*reqItr)->insn_->getSequenceId() << "(" <<
  //     //   //               (*reqItr)->reqId_
  //     //   //               << ")" << std::endl;
  //     //   //   } else {
  //     //   //     std::cerr << "[SimEng]\tFlushing inflights from "
  //     //   //               << (((1ull << 63) - 1) & (*reqItr)->target_->id)
  //     <<
  //     //   "("
  //     //   //               << (*reqItr)->reqId_ << ")" << std::endl;
  //     //   //   }
  //     //   // }
  //     //   // break;
  //     //   // }
  //     //   l1MSHRs_.push_back({cl, {}, {}, 1});
  //     //   if (print_)
  //     //     std::cerr << "[SimEng]\t\tNew MSHR for CL " << std::hex << cl
  //     //               << std::dec << std::endl;
  //     // }

  //     // // Create MI/MO flows for accessed cls
  //     // if (std::find(mimoedCLs.begin(), mimoedCLs.end(), cl) ==
  //     //     mimoedCLs.end()) {
  //     //   mimoedCLs.push_back(cl);
  //     //   if (isInsn)
  //     //     (*reqItr)->insn_->setshouldMIMO(true);
  //     //   else
  //     //     (*reqItr)->target_->shouldMIMO_ = true;
  //     // }
  //   }
  //   // if (shouldFlush) break;
  //   reqItr++;
  // }

  // if (shouldFlush) {
  //   // Retroactively remove all newer requests to represent their prior
  //   // refusal due to MSHR entry capacity reach
  //   if (print_)
  //     std::cerr << "[SimEng]\tRetroactive flush for "
  //               << (inFlightRequests_.end() - reqItr) << " entries"
  //               << std::endl;
  //   while (reqItr != inFlightRequests_.end()) {
  //     bool isInsn = (reqItr->target_ == nullptr) ? true : false;
  //     // Early return on flow back to LSQ
  //     if (isInsn) {
  //       if (print_)
  //         std::cerr << "[SimEng]\tRetroactive flush on for insn " << std::hex
  //                   << reqItr->insn_->getInstructionAddress() << std::dec
  //                   << " - " << reqItr->insn_->getSequenceId() << "("
  //                   << reqItr->reqId_
  //                   << "):" << (reqItr->insn_->isLoad() ? "LOAD" : "STORE")
  //                   << std::endl;
  //       // reqItr->insn_->setcycleMemRecv(ticks_);
  //       // reqItr->insn_->setmissedCache(true);
  //       // reqItr->insn_->setretroMSHRResub(true);
  //     } else {
  //       if (print_)
  //         std::cerr << "[SimEng]\tRetroactive flush on for target "
  //                   << reqItr->target_->id << "(" << reqItr->reqId_ << ")"
  //                   << std::endl;
  //       reqItr->target_->cycleMemRecv_ = ticks_;
  //       // reqItr->target_->missedCache_ = true;
  //     }

  //     // Remove active MSHR entry if necessary
  //     if (reqItr->hasMSHR_) {
  //       // Get access CLs which would have had a MSHR entry registered
  //       std::vector<uint64_t> clsAccessed = {};
  //       if (isInsn) {
  //         for (const auto& cl : reqItr->insn_->getCLSAccessed())
  //           clsAccessed.push_back(cl);

  //       } else {
  //         for (const auto& cl : reqItr->target_->clsAccessed_)
  //           clsAccessed.push_back(cl);
  //       }

  //       // Find any MSHR matches
  //       for (auto cl : clsAccessed) {
  //         auto mshrItr = l1MSHRs_.begin();
  //         while (mshrItr != l1MSHRs_.end()) {
  //           if (cl == mshrItr->clAddr_) {
  //             if (mshrItr->activeEntries_ == 1) {
  //               // Release inactive entries from MSHR
  //               for (auto& entry : mshrItr->idleEntries_) {
  //                 if (entry.insn_ != nullptr) {
  //                   if (print_) {
  //                     std::cerr
  //                         << "[SimEng]\t\t\t" << std::hex
  //                         << entry.insn_->getInstructionAddress() << std::dec
  //                         << " - " << entry.insn_->getSequenceId() << "("
  //                         << entry.reqId_ << ") released in MSHR" <<
  //                         std::endl;
  //                   }
  //                   // entry.insn_->setcycleMemRecv(ticks_);
  //                   // entry.insn_->setmissedCache(true);
  //                   // entry.insn_->setretroMSHRResub(true);
  //                 } else {
  //                   if (print_) {
  //                     std::cerr << "[SimEng]\t\t\t"
  //                               << (((1ull << 63) - 1) & entry.target_->id)
  //                               << "(" << entry.reqId_ << ") released in
  //                               MSHR"
  //                               << std::endl;
  //                   }
  //                   // entry.target_->cycleMemRecv_ = ticks_;
  //                   // entry.target_->missedCache_ = true;
  //                 }
  //               }
  //               mshrItr = l1MSHRs_.erase(mshrItr);
  //             } else {
  //               mshrItr->activeEntries_--;
  //             }
  //             break;
  //           } else {
  //             mshrItr++;
  //           }
  //         }
  //       }
  //     }
  //     reqItr = inFlightRequests_.erase(reqItr);
  //     if (print_) std::cerr << "[SimEng]\t\tFlushed" << std::endl;
  //   }
  // }
}

void MMU::processRequests(const bool isStore) {
  uint64_t bandwidthLimit = isStore ? storeBandwidth_ : loadBandwidth_;
  uint64_t bandwidthUsed = 0;
  while (loadsStores_[isStore].size() > 0) {
    auto insn = loadsStores_[isStore].begin();
    // Process as many requests as possible within bandwidth limit
    auto pkt = insn->begin();
    while (pkt != insn->end()) {
      // Check that sending this packet won't exceed bandwidth
      if ((*pkt).first->isUntimed() ||
          (bandwidthUsed + (*pkt).first->size_) <= bandwidthLimit) {
        if ((*pkt).second <= ticks_) {
          bandwidthUsed += (*pkt).first->size_;
          if (numReqsInCycle_ >= 2) return;
          issueRequest(std::move(*pkt).first);
          pkt = insn->erase(pkt);
        } else {
          return;
        }
      } else {
        // Bandwidth will be exceeded. Stop sending instruction packets
        if ((*pkt).first->size_ > bandwidthLimit) {
          std::cerr << "[SimEng:MMU] Bandwidth exceeded on "
                    << (isStore ? "store" : "load") << " - "
                    << (*pkt).first->insnSeqId_ << " - " << (*pkt).first->size_
                    << std::endl;
        }
        return;
      }
    }
    // If insn is now empty (all requests have been sent) then remove it
    // from the vector
    if (insn->size() == 0) {
      loadsStores_[isStore].erase(insn);
    }
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

  // Determine if lacking TLB MSHRs is blocking the cache
  uint8_t numTLBMSHRs = 0;
  for (const auto& entry : tlbReqs_) {
    numTLBMSHRs += entry.missQueue_.size();
  }
  if (numTLBMSHRs >= l1TLBMSHRSize_) {
    numTLBMSHRBlocks_++;
    return requestSuccess::TLB_MSHR;
  }

  // Ensure we don't got over the MSHR limit
  if (totalActiveMSHRs_ >= miBufferSize_ ||
      uniqueActiveMSHRs_ >= moBufferSize_) {
    numCacheMSHRBlocks_++;
    return requestSuccess::CACHE_MSHR;
  }

  // Check page address in L1 TLB if no prior read
  bool missL1TLB = false;
  const auto& targets = uop->getGeneratedAddresses();
  // uop->setreadTLBRet(true);
  if (!uop->getreadTLBRet()) {
    for (int i = 0; i < targets.size(); i++) {
      uint64_t pageAddr =
          downAlign(targets[i].vaddr, simeng::OS::defaults::PAGE_SIZE);
      if (std::find(tlbL1_.begin(), tlbL1_.end(), pageAddr) == tlbL1_.end()) {
        missL1TLB = true;

        bool found = false;
        for (auto& entry : tlbReqs_) {
          if (entry.pageAddr_ == pageAddr) {
            // Add as subentry
            entry.missQueue_.push_back(uop);
            found = true;
            break;
          }
        }
        if (!found) {
          if (print_)
            std::cerr << "[SimEng]\t\t\tNew TLB miss for page " << std::hex
                      << pageAddr << std::dec << " with return on cycle "
                      << ticks_ + l2TLBmissPen_ << std::endl;
          // Add as entry
          tlbReqs_.push_back({pageAddr, ticks_ + l2TLBmissPen_, false, {uop}});
        }
        // Current limitation only allows one active TLB miss per uop
        numTLBMisses_++;
        break;
      }
    }
  }
  if (!missL1TLB) {
    uop->setreadTLBRet(true);
  } else {
    if (print_)
      std::cerr << "[SimEng]\t\tLoad " << seqId << " missed TLB" << std::endl;
    return requestSuccess::SUCCESS;
  }

  reqIds_++;

  // Initialise space in loads
  loadsStores_[LD].push_back({});
  std::shared_ptr<reqEntry> newReq = std::make_shared<reqEntry>(
      reqIds_, uop, nullptr, 0, false, false, ticks_);
  inFlightRequests_.push_back(newReq);
  // Generate and fire off requests
  uint16_t orderId = 0;
  for (int i = 0; i < targets.size(); i++) {
    if (!uop->hasData(i)) {
      createReadMemPackets(targets[i], loadsStores_[LD].back(), reqIds_,
                           orderId);
      orderId++;
    }
  }
  if (uop->isLoadReserved()) {
    // Set MemPackets to be atomic if uop is an atomic operation
    for (int i = 0; i < loadsStores_[LD].back().size(); i++) {
      loadsStores_[LD].back()[i].first->markAsAtomic();
    }
  }

  std::vector<uint64_t> clsAccessed = {};
  for (int i = 0; i < loadsStores_[LD].back().size(); i++) {
    uint64_t reqCL =
        downAlign(loadsStores_[LD].back()[i].first->vaddr_, cacheLineWidth_);
    clsAccessed.push_back(reqCL);
    if (print_)
      std::cerr << "[SimEng]\t\tCL " << std::hex << reqCL << std::dec
                << " accessed" << std::endl;
  }

  uop->setCLSAccessed(clsAccessed);
  uint16_t totalReqs = static_cast<uint16_t>(loadsStores_[LD].back().size());
  inFlightRequests_.back()->totalPacketsRemaining_ = totalReqs;

  uop->setcycleMemSent(ticks_);

  // Match or create MSHR for CLs accessed
  for (const auto& cl : clsAccessed) {
    if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
      l1MSHRs_[cl] = {cl, false, {}};
    }
    l1MSHRs_.at(cl).associatedRequests_.push_back(newReq);
    // Update mshr counts if entry has missed
    if (l1MSHRs_.at(cl).hasMissed_) totalActiveMSHRs_++;
  }

  if (print_)
    std::cerr << "[SimEng]\t\tLoad " << seqId << "(" << reqIds_ << ") with "
              << totalReqs << " reqs" << std::endl;
  return requestSuccess::SUCCESS;
}

requestSuccess MMU::requestPrefetch(const std::shared_ptr<Instruction>& uop) {
  const auto& targets = uop->getGeneratedAddresses();
  for (int i = 0; i < targets.size(); i++) {
    std::unique_ptr<memory::MemPacket> prefetchRequest =
        MemPacket::createReadRequest(targets[i].vaddr, targets[i].size,
                                     uop->getSequenceId(), i, tid_);
    prefetchRequest->packetId_ = packetIds_++;
    prefetchRequest->markAsPrefetch();
    issueRequest(std::move(prefetchRequest));
  }
  return requestSuccess::SUCCESS;
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

  reqIds_++;
  // Initialise space in stores
  loadsStores_[STR].push_back({});
  std::shared_ptr<reqEntry> newReq = std::make_shared<reqEntry>(
      reqIds_, uop, nullptr, 0, false, false, ticks_);
  inFlightRequests_.push_back(newReq);
  // Create and fire off requests
  const auto& targets = uop->getGeneratedAddresses();
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

  if (uop->isStoreCond()) {
    // Set MemPackets to be atomic if uop is an atomic operation
    for (int i = 0; i < loadsStores_[STR].back().size(); i++) {
      loadsStores_[STR].back()[i].first->markAsAtomic();
    }
  }

  std::vector<uint64_t> clsAccessed = {};
  for (int i = 0; i < loadsStores_[STR].back().size(); i++) {
    uint64_t reqCL =
        downAlign(loadsStores_[STR].back()[i].first->vaddr_, cacheLineWidth_);
    clsAccessed.push_back(reqCL);
    if (print_)
      std::cerr << "[SimEng]\t\tCL " << std::hex << reqCL << std::dec
                << " accessed" << std::endl;
  }

  uop->setCLSAccessed(clsAccessed);
  uint16_t totalReqs = static_cast<uint16_t>(loadsStores_[STR].back().size());
  inFlightRequests_.back()->totalPacketsRemaining_ = totalReqs;

  uop->setcycleMemSent(ticks_);
  uop->setcycleMemRecv(ticks_);

  // Match or create MSHR for CLs accessed
  for (const auto& cl : clsAccessed) {
    if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
      l1MSHRs_[cl] = {cl, false, {}};
    }
    l1MSHRs_.at(cl).associatedRequests_.push_back(newReq);
    // Update mshr counts if entry has missed
    if (l1MSHRs_.at(cl).hasMissed_) totalActiveMSHRs_++;
  }
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

    // Determine if lacking TLB MSHRs is blocking the cache
    // uint8_t numTLBMSHRs = 0;
    // for (const auto& entry : tlbReqs_) {
    //   numTLBMSHRs += entry.missQueue_.size();
    // }
    // if (numTLBMSHRs >= l1TLBMSHRSize_) {
    //   numTLBMSHRBlocks_++;
    //   return requestSuccess::TLB_MSHR;
    // }

    // Ensure we don't got over the MSHR limit
    if (totalActiveMSHRs_ >= miBufferSize_ ||
        uniqueActiveMSHRs_ >= moBufferSize_) {
      numCacheMSHRBlocks_++;
      return requestSuccess::CACHE_MSHR;
    }
  }

  uint8_t idx = target->reSubmittedMem_ ? LD : STR;
  reqIds_++;
  // Initialise space for stores
  loadsStores_[idx].push_back({});
  std::shared_ptr<reqEntry> newReq = std::make_shared<reqEntry>(
      reqIds_, nullptr, target, 0, false, false, ticks_);
  inFlightRequests_.push_back(newReq);

  if (idx == LD) {
    createReadMemPackets((*target), loadsStores_[LD].back(), reqIds_, 0);
    for (int i = 0; i < loadsStores_[LD].back().size(); i++) {
      loadsStores_[LD].back()[i].first->markAsStoreData();
    }
  } else {
    // Format data
    const char* wdata = data.getAsVector<char>();
    std::vector<char> dt(wdata, wdata + target->size);
    // Create requests
    createWriteMemPackets(*(target.get()), loadsStores_[STR].back(), dt,
                          reqIds_, 0);
  }

  std::vector<uint64_t> clsAccessed = {};
  for (int i = 0; i < loadsStores_[idx].back().size(); i++) {
    uint64_t reqCL =
        downAlign(loadsStores_[idx].back()[i].first->vaddr_, cacheLineWidth_);
    clsAccessed.push_back(reqCL);
    if (print_)
      std::cerr << "[SimEng]\t\tCL " << std::hex << reqCL << std::dec
                << " accessed" << std::endl;
  }

  target->clsAccessed_ = clsAccessed;
  uint16_t totalReqs = static_cast<uint16_t>(loadsStores_[idx].back().size());
  inFlightRequests_.back()->totalPacketsRemaining_ = totalReqs;

  target->cycleMemSent_ = ticks_;
  target->cycleMemRecv_ = ticks_;

  // if (!bypassRestrictions && idx == LD) {
  // Match or create MSHR for CLs accessed
  for (const auto& cl : clsAccessed) {
    if (l1MSHRs_.find(cl) == l1MSHRs_.end()) {
      l1MSHRs_[cl] = {cl, false, {}};
    }
    l1MSHRs_.at(cl).associatedRequests_.push_back(newReq);
    // Update mshr counts if entry has missed
    if (l1MSHRs_.at(cl).hasMissed_) totalActiveMSHRs_++;
  }
  // }
  if (print_)
    std::cerr << "[SimEng]\t\tStore data (" << unsigned(idx) << ") "
              << (((1ull << 63) - 1) & target->id) << "(" << reqIds_
              << ") with " << totalReqs << " reqs" << std::endl;

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

  // Create requests
  createWriteMemPackets(target, loadsStores_[STR].back(), dt, reqIds_, 0);

  for (int i = 0; i < loadsStores_[STR].back().size(); i++)
    loadsStores_[STR].back()[i].first->markAsUntimed();
  return requestSuccess::SUCCESS;
}

void MMU::requestInstrRead(const MemoryAccessTarget& target) {
  assert(isAligned(target) &&
         "[SimEng:MMU] Unlaigned instruction read requests are not "
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

  // Determine if lacking TLB MSHRs is blocking the cache
  uint8_t numTLBMSHRs = 0;
  for (const auto& entry : tlbReqs_) {
    numTLBMSHRs += entry.missQueue_.size();
  }
  if (numTLBMSHRs >= l1TLBMSHRSize_) {
    numTLBMSHRBlocks_++;
    return requestSuccess::TLB_MSHR;
  }

  // Ensure we don't got over the MSHR limit
  // uint8_t numCacheSubMSHRs = 0;
  // for (const auto& entry : l1MSHRs_) {
  //   numCacheSubMSHRs += entry.activeEntries_ + entry.waitingEntries_.size();
  // }
  // if (numCacheSubMSHRs >= miBufferSize_ || l1MSHRs_.size() >= moBufferSize_)
  // {
  //   return requestSuccess::CACHE_MSHR;
  // }

  // Check page address in L1 TLB if no prior read
  bool missL1TLB = false;
  const auto& targets = uop->getGeneratedAddresses();
  // uop->setreadTLBRet(true);
  if (!uop->getreadTLBRet()) {
    for (int i = 0; i < targets.size(); i++) {
      uint64_t pageAddr =
          downAlign(targets[i].vaddr, simeng::OS::defaults::PAGE_SIZE);
      if (std::find(tlbL1_.begin(), tlbL1_.end(), pageAddr) == tlbL1_.end()) {
        missL1TLB = true;

        bool found = false;
        for (auto& entry : tlbReqs_) {
          if (entry.pageAddr_ == pageAddr) {
            // Add as subentry
            entry.missQueue_.push_back(uop);
            found = true;
            break;
          }
        }
        if (!found) {
          if (print_)
            std::cerr << "[SimEng]\t\t\tNew TLB miss for page " << std::hex
                      << pageAddr << std::dec << " with return on cycle "
                      << ticks_ + l2TLBmissPen_ << std::endl;
          // Add as entry
          tlbReqs_.push_back({pageAddr, ticks_ + l2TLBmissPen_, false, {uop}});
        }
        // Current limitation only allows one active TLB miss per uop
        numTLBMisses_++;
        break;
      }
    }
  }
  if (!missL1TLB) {
    uop->setreadTLBRet(true);
  } else {
    if (print_)
      std::cerr << "[SimEng]\t\tStore addr " << seqId << " missed TLB"
                << std::endl;
    return requestSuccess::SUCCESS;
  }

  // if (uop->getcycleMemSent() == 0) {
  //   reqIds_++;
  //   loadsStores_[LD].push_back({});
  //   inFlightRequests_.push_back(
  //       {reqIds_, uop, nullptr, 0, {}, false, false, ticks_});
  //   uint16_t orderId = 0;
  //   for (int i = 0; i < targets.size(); i++) {
  //     createReadMemPackets(targets[i], loadsStores_[LD].back(), reqIds_,
  //                          orderId);
  //     orderId++;
  //   }

  //   for (int i = 0; i < loadsStores_[LD].back().size(); i++) {
  //     loadsStores_[LD].back()[i].first->markAsStoreAddr();
  //     // Zero size the requests to ensure no bandwith is incorrectly consumed
  //     loadsStores_[LD].back()[i].first->size_ = 0;
  //   }

  //   std::vector<uint64_t> clsAccessed = {};
  //   for (int i = 0; i < loadsStores_[LD].back().size(); i++) {
  //     uint64_t reqCL =
  //         downAlign(loadsStores_[LD].back()[i].first->vaddr_,
  //         cacheLineWidth_);
  //     clsAccessed.push_back(reqCL);
  //     if (print_)
  //       std::cerr << "[SimEng]\t\tCL " << std::hex << reqCL << std::dec
  //                 << " accessed" << std::endl;
  //   }

  //   uop->setCLSAccessed(clsAccessed);
  //   uint16_t totalReqs =
  //   static_cast<uint16_t>(loadsStores_[LD].back().size());
  //   inFlightRequests_.back().totalPacketsRemaining_ = totalReqs;

  //   uop->setcycleMemSent(ticks_);
  //   // If there's matched MSHRs, move the request over
  //   for (auto& mshr : l1MSHRs_) {
  //     for (const auto& cl : clsAccessed) {
  //       if (cl == mshr.clAddr_) {
  //         // inFlightRequests_.back().hasMSHR_ = true;
  //         // mshr.idleEntries_.push_back(
  //         //     {inFlightRequests_.back().reqId_,
  //         //      inFlightRequests_.back().insn_,
  //         //      inFlightRequests_.back().target_,
  //         //      inFlightRequests_.back().totalPacketsRemaining_,
  //         //      {},
  //         //      inFlightRequests_.back().failed,
  //         //      inFlightRequests_.back().hasMSHR_,
  //         //      inFlightRequests_.back().cycleSent_});
  //         // inFlightRequests_.pop_back();
  //         // loadsStores_[LD].pop_back();
  //         // if (print_)
  //         //   std::cerr << "[SimEng]\t\tStore addr " << seqId << "(" <<
  //         reqIds_
  //         //             << ") added to mshr for cl " << std::hex << cl <<
  //         //             std::dec
  //         //             << std::endl;
  //         // return requestSuccess::SUCCESS;
  //         mshr.activeEntries_++;
  //       }
  //     }
  //   }
  //   // uop->setcycleMemRecv(ticks_);
  //   if (print_)
  //     std::cerr << "[SimEng]\t\tStore addr " << seqId << "(" << reqIds_
  //               << ") with " << totalReqs << " reqs" << std::endl;
  // }

  uop->setcycleMemRecv(ticks_);
  return requestSuccess::SUCCESS;
}

const span<MemoryReadResult> MMU::getCompletedInstrReads() const {
  return {const_cast<MemoryReadResult*>(completedInstrReads_.data()),
          completedInstrReads_.size()};
}

void MMU::supplyDelayedTranslation(uint64_t vaddr, uint64_t paddr) {
  uint64_t alignedVaddr = downAlign(vaddr, simeng::OS::defaults::PAGE_SIZE);
  uint64_t alignedPaddr = downAlign(paddr, simeng::OS::defaults::PAGE_SIZE);
  auto it = pendingRequests_.find(alignedVaddr);
  if (it != pendingRequests_.end()) {
    // If a delayed virtual address translation exists, re-issue the request
    // so that the new translation can be supplied
    for (int i = 0; i < it->second.size(); i++) {
      issueRequest(std::move(it->second[i].first),
                   alignedPaddr + it->second[i].second);
    }
    pendingRequests_.erase(it);
  }
}

void MMU::clearCompletedIntrReads() { completedInstrReads_.clear(); }

bool MMU::hasPendingRequests() const {
  return pendingRequests_.size() > 0 || inFlightRequests_.size() != 0;
}

void MMU::setTid(uint64_t tid) { tid_ = tid; }
uint64_t MMU::getTid() { return tid_; }

std::shared_ptr<Port<std::unique_ptr<MemPacket>>> MMU::initPort() {
  port_ = std::make_shared<Port<std::unique_ptr<MemPacket>>>();
  auto fn = [this](std::unique_ptr<MemPacket> packet) -> void {
    uint64_t pktCL = downAlign(packet->vaddr_, cacheLineWidth_);
    if (print_)
      std::cerr << "[SimEng]\t\t\t" << (((1ull << 63) - 1) & packet->insnSeqId_)
                << " returned on CL " << (packet->isRead() ? "read" : "write")
                << (packet->isStoreAddr() ? " (storeAddr)" : "")
                << (packet->isStoreData() ? " (storeData)" : "")
                << (packet->isInstrRead() ? " (insnRead)" : "") << " access "
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

    // Early return on software prefetch packet
    if (packet->isPrefetch()) {
      inFlightRequests_.erase(reqItr);
      return;
    }

    // Remove from MSHR if present
    if (l1MSHRs_.find(pktCL) != l1MSHRs_.end()) {
      auto mshrItr = l1MSHRs_.at(pktCL).associatedRequests_.begin();
      while (mshrItr != l1MSHRs_.at(pktCL).associatedRequests_.end()) {
        if ((*mshrItr)->reqId_ == (*reqItr)->reqId_) {
          mshrItr = l1MSHRs_.at(pktCL).associatedRequests_.erase(mshrItr);
          if (l1MSHRs_.at(pktCL).hasMissed_) totalActiveMSHRs_--;
          if (print_)
            std::cerr << "[SimEng]\t\t\t\tRemoved from MSHR, "
                      << totalActiveMSHRs_ << " total remain" << std::endl;
          break;
        }
        mshrItr++;
      }

      if (l1MSHRs_.at(pktCL).associatedRequests_.size() == 0) {
        if (l1MSHRs_.at(pktCL).hasMissed_) uniqueActiveMSHRs_--;
        l1MSHRs_.erase(pktCL);
        if (print_)
          std::cerr << "[SimEng]\t\t\t\tRemoved " << std::hex << pktCL
                    << std::dec << " MSHR" << std::endl;
      }
    }

    // auto itr = l1MSHRs_.begin();
    // for (; itr != l1MSHRs_.end(); itr++) {
    //   if (itr->clAddr_ == pktCL) {
    //     auto waitingItr = std::find(itr->waitingEntries_.begin(),
    //                                 itr->waitingEntries_.end(),
    //                                 reqItr->reqId_);
    //     if (waitingItr != itr->waitingEntries_.end()) {
    //       itr->waitingEntries_.erase(waitingItr);
    //       if (print_)
    //         std::cerr << "[SimEng]\t\t\t\tRemoved from waiting entries of "
    //                   << std::hex << pktCL << std::dec << "'s MSHR"
    //                   << std::endl;
    //       break;
    //     } else if (itr->activeEntries_ != 0) {
    //       if (print_)
    //         std::cerr << "[SimEng]\t\t\t\tRemoved from active entries of "
    //                   << std::hex << pktCL << std::dec << "'s MSHR"
    //                   << std::endl;
    //       itr->activeEntries_--;
    //       break;
    //     }
    //   }
    // }
    // if (itr != l1MSHRs_.end()) {
    //   if ((itr->activeEntries_ + itr->waitingEntries_.size()) == 0) {
    //     if (print_)
    //       std::cerr << "[SimEng]\t\t\t\tRemoved " << std::hex << pktCL
    //                 << std::dec << "'s MSHR" << std::endl;
    //     // Release inactive entries from MSHR
    //     // for (auto& entry : itr->idleEntries_) {
    //     //   if (entry.insn_ != nullptr) {
    //     //     if (print_) {
    //     //       std::cerr << "[SimEng]\t\t\t" << std::hex
    //     //                 << entry.insn_->getInstructionAddress() <<
    //     //                 std::dec
    //     //                 << " - " << entry.insn_->getSequenceId() << "("
    //     //                 << entry.reqId_ << ") released in MSHR"
    //     //                 << std::endl;
    //     //     }
    //     //     // entry.insn_->setcycleMemRecv(ticks_);
    //     //     // entry.insn_->setmissedCache(true);
    //     //     // entry.insn_->setretroMSHRResub(true);
    //     //   } else {
    //     //     if (print_) {
    //     //       std::cerr << "[SimEng]\t\t\t"
    //     //                 << (((1ull << 63) - 1) & entry.target_->id) <<
    //     //                 "("
    //     //                 << entry.reqId_ << ") released in MSHR"
    //     //                 << std::endl;
    //     //     }
    //     //     // entry.target_->cycleMemRecv_ = ticks_;
    //     //     // entry.target_->missedCache_ = true;
    //     //   }
    //     // }
    //     itr = l1MSHRs_.erase(itr);
    //   }
    // }

    if (packet->isRead()) {
      if (packet->isStoreData()) {
        (*reqItr)->totalPacketsRemaining_--;
        if ((*reqItr)->totalPacketsRemaining_ == 0) {
          (*reqItr)->target_->cycleMemRecv_ = ticks_;
          inFlightRequests_.erase(reqItr);
        } else {
          if (print_) {
            std::cerr << "[SimEng]\t\t\t" << (*reqItr)->totalPacketsRemaining_
                      << " resubmitted store data packets left" << std::endl;
          }
          // Remove from accessed cls to avoid adding to an MSHR
          std::vector<uint64_t> clsAccessed = (*reqItr)->target_->clsAccessed_;
          auto itr = std::find(clsAccessed.begin(), clsAccessed.end(), pktCL);
          if (itr != clsAccessed.end())
            (*reqItr)->target_->clsAccessed_.erase(itr);
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
          // Remove from accessed cls to avoid adding to an MSHR
          std::vector<uint64_t> clsAccessed =
              (*reqItr)->insn_->getCLSAccessed();
          auto itr = std::find(clsAccessed.begin(), clsAccessed.end(), pktCL);
          if (itr != clsAccessed.end()) clsAccessed.erase(itr);
          (*reqItr)->insn_->setCLSAccessed(clsAccessed);
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
          // Remove from accessed cls to avoid adding to an MSHR
          std::vector<uint64_t> clsAccessed =
              (*reqItr)->insn_->getCLSAccessed();
          auto itr = std::find(clsAccessed.begin(), clsAccessed.end(), pktCL);
          if (itr != clsAccessed.end()) clsAccessed.erase(itr);
          (*reqItr)->insn_->setCLSAccessed(clsAccessed);
        }
      }
    } else if (packet->isWrite()) {
      (*reqItr)->totalPacketsRemaining_--;
      // If any one packet belonging to the uop fails, currently mark is
      // as failed
      if (packet->hasFailed()) (*reqItr)->failed_ = true;

      if ((*reqItr)->totalPacketsRemaining_ == 0) {
        if ((*reqItr)->insn_ == nullptr) {
          (*reqItr)->target_->cycleMemRecv_ = ticks_;
        } else if ((*reqItr)->insn_->isStoreCond()) {
          (*reqItr)->insn_->updateCondStoreResult(!(*reqItr)->failed_);
        }
        inFlightRequests_.erase(reqItr);
      } else {
        if (print_) {
          std::cerr << "[SimEng]\t\t\t" << (*reqItr)->totalPacketsRemaining_
                    << " store data packets left" << std::endl;
        }
        if ((*reqItr)->target_ != nullptr) {
          // Remove from accessed cls to avoid adding to an MSHR
          std::vector<uint64_t> clsAccessed = (*reqItr)->target_->clsAccessed_;
          auto itr = std::find(clsAccessed.begin(), clsAccessed.end(), pktCL);
          if (itr != clsAccessed.end())
            (*reqItr)->target_->clsAccessed_.erase(itr);
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
              << (request->isInstrRead() ? "(insnRead) " : "")
              << (((1ull << 63) - 1) & request->insnSeqId_) << ":" << std::hex
              << request->vaddr_ << std::dec << std::endl;

  // TLB miss and consult the page table.
  uint64_t paddr = (delayedTranslation != -1)
                       ? delayedTranslation
                       : translate_(request->vaddr_, tid_);
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
    pendingRequests_[alignedVaddr].push_back(
        {std::move(request), request->vaddr_ - alignedVaddr});
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
    std::vector<std::pair<std::unique_ptr<MemPacket>, uint64_t>>& outputVec,
    const uint64_t insnSeqId, const uint16_t pktOrderId) {
  if (isAligned(target)) {
    // std::cerr << "\tIs Aligned" << std::endl;
    std::unique_ptr<memory::MemPacket> req = MemPacket::createReadRequest(
        target.vaddr, target.size, insnSeqId, pktOrderId, tid_);
    req->packetId_ = packetIds_++;
    outputVec.push_back({std::move(req), ticks_ + 2});
    // Resize response data structure to equal the number of packets
    // created
    if (readResponses_.find(insnSeqId) == readResponses_.end())
      readResponses_[insnSeqId] =
          std::map<uint16_t, std::vector<std::unique_ptr<MemPacket>>>();

    if (readResponses_.at(insnSeqId).find(pktOrderId) ==
        readResponses_.at(insnSeqId).end())
      readResponses_.at(insnSeqId)[pktOrderId] =
          std::vector<std::unique_ptr<MemPacket>>();

    readResponses_.at(insnSeqId).at(pktOrderId).resize(1);
  } else {
    // std::cerr << "\tIs Not Aligned" << std::endl;
    uint64_t nextAddr = target.vaddr;
    uint64_t remSize = static_cast<uint64_t>(target.size);
    uint16_t nextSplitId = 0;
    while (remSize != 0) {
      // Get size of next target region
      uint16_t regSize = std::min(
          (downAlign(nextAddr, cacheLineWidth_) + cacheLineWidth_) - nextAddr,
          remSize);
      // Create MemPacket
      auto req = MemPacket::createReadRequest(nextAddr, regSize, insnSeqId,
                                              pktOrderId, tid_);
      req->packetId_ = packetIds_++;
      req->packetSplitId_ = nextSplitId;
      outputVec.push_back({std::move(req), ticks_ + 2});
      // Update vars
      nextAddr += regSize;
      remSize -= regSize;
      nextSplitId++;
    }
    // Resize response data structure to equal the number of packets
    // created
    if (readResponses_.find(insnSeqId) == readResponses_.end())
      readResponses_[insnSeqId] =
          std::map<uint16_t, std::vector<std::unique_ptr<MemPacket>>>();

    if (readResponses_.at(insnSeqId).find(pktOrderId) ==
        readResponses_.at(insnSeqId).end())
      readResponses_.at(insnSeqId)[pktOrderId] =
          std::vector<std::unique_ptr<MemPacket>>();

    readResponses_.at(insnSeqId).at(pktOrderId).resize(nextSplitId);
  }
}

void MMU::createWriteMemPackets(
    const MemoryAccessTarget& target,
    std::vector<std::pair<std::unique_ptr<MemPacket>, uint64_t>>& outputVec,
    const std::vector<char>& data, const uint64_t insnSeqId,
    const uint16_t pktOrderId) {
  if (isAligned(target)) {
    std::unique_ptr<MemPacket> req = MemPacket::createWriteRequest(
        target.vaddr, target.size, insnSeqId, pktOrderId, tid_, data);
    req->packetId_ = packetIds_++;
    outputVec.push_back({std::move(req), ticks_ + 2});
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
      auto req = MemPacket::createWriteRequest(nextAddr, regSize, insnSeqId,
                                               pktOrderId, tid_, regData);
      req->packetId_ = packetIds_++;
      req->packetSplitId_ = nextSplitId;
      outputVec.push_back({std::move(req), ticks_ + 2});
      // Update vars
      nextAddr += regSize;
      remSize -= regSize;
      nextSplitId++;
      remData = std::vector<char>(remData.begin() + regSize, remData.end());
    }
  }
}

void MMU::supplyLoadInsnData(const uint64_t insnSeqId) {
  // Get reference to instruction for easier access
  auto reqItr = inFlightRequests_.begin();
  while (reqItr != inFlightRequests_.end()) {
    if ((*reqItr)->reqId_ == insnSeqId) break;
    reqItr++;
  }

  auto& insn = (*reqItr)->insn_;
  insn->setcycleMemRecv(ticks_);

  // Get map of all packets, grouped by packetOrderId
  auto& packets = readResponses_.at(insnSeqId);

  bool foundFault = false;
  for (const auto& pkts : packets) {
    for (const auto& pkt : pkts.second) {
      if (pkt->isFaulty()) {
        foundFault = true;
        break;
      }
    }
  }
  if (foundFault == false && insn->getmissedCache()) {
    if (print_)
      std::cerr << "[SimEng]\t\t\tLoad took too long (" << (*reqItr)->cycleSent_
                << ":" << ticks_ - (*reqItr)->cycleSent_ << ") - "
                << insn->getSequenceId() << "(" << insnSeqId << ")"
                << std::endl;
    inFlightRequests_.erase(reqItr);
    return;
  } else {
    insn->setmissedCache(false);
  }
  // std::cerr << packets.size() << std::endl;
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

void MMU::markMiss(uint64_t vAddr) {
  if (print_)
    std::cerr << "[SimEng]\t\tRecieved miss on vAddr " << std::hex << vAddr
              << std::dec << std::endl;
  const uint64_t clAddr = downAlign(vAddr, cacheLineWidth_);
  auto reqItr = l1MSHRs_.find(clAddr);
  if (reqItr != l1MSHRs_.end()) {
    numCacheMisses_++;
    // Find associated MSHRs
    if (!reqItr->second.hasMissed_) {
      reqItr->second.hasMissed_ = true;

      if (print_) {
        std::cerr << "[SimEng]\t\t" << std::hex << vAddr << std::dec
                  << " missed on CL " << std::hex << clAddr << std::dec
                  << std::endl;
      }

      // Register appropriate MSHRs
      // Append to/create MSHR entries
      uniqueActiveMSHRs_++;
      totalActiveMSHRs_ += reqItr->second.associatedRequests_.size();
      if (print_)
        std::cerr << "[SimEng]\t\t" << std::hex << clAddr << std::dec
                  << " MSHR marked as missed. uniqueActiveMSHRs_: "
                  << uniqueActiveMSHRs_
                  << " totalActiveMSHRs_: " << totalActiveMSHRs_ << std::endl;
    }
  }
}

}  // namespace memory
}  // namespace simeng
