#include "L1L2Prefetcher.h"

#include <cstdlib>
#include <iostream>

#include "ForwardListener.hh"
#include "PrefetcherShim.h"
#include "sst/core/params.h"

using namespace SST;
using namespace SST::SSTSimEng;

L1L2Prefetcher::L1L2Prefetcher(SST::ComponentId_t id, SST::Params& params)
    : SST::Component(id) {
  verbosity = params.find<int>("verbose", 0);

  char* new_prefix = (char*)malloc(sizeof(char) * 128);
  snprintf(new_prefix, sizeof(char) * 128, "L1L2Prefetcher[%s | @p]\t",
           getName().c_str());
  output = new Output(new_prefix, verbosity, 0, Output::STDOUT);
  free(new_prefix);

  Link* link;
  int fromPRF = 0;

  output->output(CALL_INFO, "Configuring Ports with verbosity %d\n", verbosity);

  // Iterate over prefetch shim port names with sequential incrementing index
  // until one isn't found
  while (true) {
    std::string linkName = "from_prefetch_link_" + std::to_string(fromPRF);
    link = configureLink(linkName, "1ps",
                         new Event::Handler<L1L2Prefetcher>(
                             this, &L1L2Prefetcher::handleFromPrefetchEvent));
    if (link) {
      fromPRF_links.push_back(link);
      output->output(CALL_INFO, "From Prefetch Port %d = Link %d\n",
                     link->getId(), fromPRF);
      portIdMappings[link->getId()] = fromPRF;
      fromPRF++;
    } else {
      break;
    }
  }
  if (fromPRF < 1)
    output->fatal(
        CALL_INFO, -1,
        "Did not find any connected links on ports from_prefetch_link_n\n");

  // Iterate over cache listener port names with sequential incrementing index
  // until one isn't found
  int fromCache = 0;
  while (true) {
    std::string linkName = "from_cache_link_" + std::to_string(fromCache);
    link = configureLink(linkName, "1ps",
                         new Event::Handler<L1L2Prefetcher>(
                             this, &L1L2Prefetcher::handleFromCacheEvent));
    if (link) {
      fromCache_links.push_back(link);
      output->output(CALL_INFO, "From Cache Port %d = Link %d\n", link->getId(),
                     fromCache);
      portIdMappings[link->getId()] = fromCache;
      fromCache++;
    } else {
      break;
    }
  }
  if (fromCache < 1)
    output->fatal(
        CALL_INFO, -1,
        "Did not find any connected links on ports from_cache_link_n\n");

  // Configure link to processor
  fromCore_link =
      configureLink(std::string("from_core_link"), "1ps",
                    new Event::Handler<L1L2Prefetcher>(
                        this, &L1L2Prefetcher::handleFromProcessorEvent));
  if (!fromCore_link) {
    output->fatal(CALL_INFO, -1,
                  "Did not find any connected links on port fromCore_link\n");
  }
  output->output(CALL_INFO, "From Core Link Id %d\n", fromCore_link->getId());

  clSize = params.find<uint64_t>("cache_line_size", 256);

  pfqSize = params.find<size_t>("pfq_size", 16);
  pfq = new std::deque<pfqEntry>();

  numFetchAhead = params.find<size_t>("num_fetch_ahead", 2);

  initialDistance = params.find<uint64_t>("initial_distance", clSize);
  maxL1Distance = params.find<size_t>("max_l1_distance", 1024);
  maxL2Distance = params.find<size_t>("max_l2_distance", 4096);

  addrHistoryLength = params.find<size_t>("addr_history_length", 16);
  addrHistory = new std::deque<Addr>();

  output->verbose(
      CALL_INFO, 1, 0,
      "StreamDetectMode prefetcher created\n\tcache line: %" PRIu64
      "\n\tPFQ size: %zu\n\tNum Fetch Ahead: %" PRIu64
      "\n\tInitial Distance: %" PRIu64 "\n\tMax L1 Distance: %" PRIu64
      "\n\tMax L2 Distance: %" PRIu64 "\n\tAddr History Length: %" PRIu64 "\n",
      clSize, pfqSize, numFetchAhead, initialDistance, maxL1Distance,
      maxL2Distance, addrHistoryLength);

  statL1PrefetchEventsIssued =
      registerStatistic<uint64_t>("l1_prefetches_issued");
  statL2PrefetchEventsIssued =
      registerStatistic<uint64_t>("l2_prefetches_issued");
  statPFQEvictions = registerStatistic<uint64_t>("pfq_evictions");
  statHistCancelled = registerStatistic<uint64_t>("cancelled_by_history");
  statPRFClears = registerStatistic<uint64_t>("pfq_clears");
  statPFQResets = registerStatistic<uint64_t>("pfq_entry_reset");
  statPFQRestarts = registerStatistic<uint64_t>("pfq_entry_restart");
  statPFQPauses = registerStatistic<uint64_t>("pfq_entry_pause");
}

L1L2Prefetcher::~L1L2Prefetcher() {}

void L1L2Prefetcher::init(unsigned int phase) {}

void L1L2Prefetcher::setup() {}

bool L1L2Prefetcher::clockTick(SST::Cycle_t current_cycle) { return false; }

void L1L2Prefetcher::finish() {}

void L1L2Prefetcher::handleFromPrefetchEvent(Event* ev) {
  NotifyEvent* event = dynamic_cast<NotifyEvent*>(ev);

  uint32_t size = event->getSize();
  Addr targAddr = event->getTargetAddress();
  Addr physAddr = event->getPhysicalAddress();
  Addr virtAddr = event->getVirtualAddress();
  Addr instPtr = event->getInstructionPointer();
  NotifyAccessType access = event->getAccessType();
  NotifyResultType result = event->getResultType();
  uint32_t srcId = event->getSrcId();
  bool isL2 = event->getIsL2();

  if (access == EVICT) {
    delete event;
    return;
  }

  output->verbose(
      CALL_INFO, 2, 0,
      "Got from prefetcher shim over port %d -  size: %d, targAddr: %" PRIx64
      ", physAddr: %" PRIx64 ", virtAddr: %" PRIx64 ", instPtr: %" PRIx64
      ", access: %d, result: %d\n",
      srcId, size, targAddr, physAddr, virtAddr, instPtr, access, result);

  // Evaluate if a prefetch event should be sent back
  processShimEvent(virtAddr, physAddr, instPtr, result == MISS, isL2);
  delete event;
}

void L1L2Prefetcher::handleFromCacheEvent(Event* ev) {
  CacheListenerEvent* event = dynamic_cast<CacheListenerEvent*>(ev);

  uint32_t size = event->getSize();
  Addr targAddr = event->getTargetAddress();
  Addr physAddr = event->getPhysicalAddress();
  Addr virtAddr = event->getVirtualAddress();
  Addr instPtr = event->getInstructionPointer();
  NotifyAccessType access = event->getAccessType();
  NotifyResultType result = event->getResultType();
  bool isL2 = event->isFromL2();

  if (access != PREFETCH) {
    delete event;
    return;
  }

  // if (isL2) {
  //   auto pfqItr = pfq->begin();
  //   while (pfqItr != pfq->end()) {
  //     if (pfqItr->pAddr <= physAddr && physAddr <= pfqItr->lastPrefetch) {
  //       if (result == HIT) {
  //         pfqItr->hitCount++;
  //         if (!pfqItr->l2Paused && pfqItr->hitCount >= 8) {
  //           pfqItr->l2Paused = true;
  //           statPFQPauses->addData(1);
  //           output->verbose(CALL_INFO, 2, 0,
  //                           "PFQ entry %" PRIx64 " paused L2 prefetches\n",
  //                           pfqItr->pAddr);
  //         }
  //       } else if (result == MISS) {
  //         if (pfqItr->l2Paused) {
  //           pfqItr->l2Distance = pfqItr->l1Distance;
  //           pfqItr->atMaxL2Distance = false;
  //           pfqItr->l2Paused = false;
  //           statPFQRestarts->addData(1);
  //           output->verbose(CALL_INFO, 2, 0,
  //                           "PFQ entry %" PRIx64 " restarted L2
  //                           prefetches\n", pfqItr->pAddr);
  //         }
  //         pfqItr->hitCount = 0;
  //       }

  //       // pfqItr->lruRank = -1;
  //       incLRURankings();
  //       break;
  //     }
  //     pfqItr++;
  //   }
  // }
  if (isL2) {
    if (result == HIT) contL2Hits++;
    if (result == MISS) contL2Hits = 0;
    if (contL2Hits >= 10)
      pauseL2 = true;
    else
      pauseL2 = false;
  }
  delete event;
}

void L1L2Prefetcher::handleFromProcessorEvent(Event* ev) {
  ControlEvent* event = dynamic_cast<ControlEvent*>(ev);

  if (event->shouldClearPFQ()) {
    pfq->clear();
    output->verbose(CALL_INFO, 2, 0,
                    "Got from processor a control event to clear PFQ\n");
  }

  delete event;
}

void L1L2Prefetcher::processShimEvent(Addr vaddr, Addr paddr, Addr insnPtr,
                                      bool wasMiss, bool fromL2) {
  // Ignore lower 7 bits as we're only concerned with the cacheline address
  Addr addr = paddr & ~0xff;

  // bool pageFound = false;
  // Addr pageAddr = paddr & ~0xffff;
  // auto pageItr = pageHistory.begin();
  // while (pageItr != pageHistory.end()) {
  //   if (*pageItr == pageAddr) {
  //     pageFound = true;
  //     break;
  //   }
  //   pageItr++;
  // }
  // if (!pageFound) {
  //   pfq->clear();
  //   pageHistory.push_back(pageAddr);
  //   // if (pageHistory.size() > 16) pageHistory.pop_front();
  //   statPRFClears->addData(1);
  //   output->verbose(CALL_INFO, 2, 0, "\tPFQ cleared on page %" PRIx64 "\n",
  //                   pageAddr);
  // }

  auto pfqItr = pfq->begin();
  bool needNewEntry = true;
  while (pfqItr != pfq->end()) {
    if (pfqItr->comparing) {
      bool found = false;
      // Compare and Match
      if (pfqItr->predictedAddress == addr) {
        // found = false;
        pfqItr->comparing = false;

        // pfqItr->lruRank = -1;
        // incLRURankings();

        // pfqItr->vAddr += ((pfqItr->ascending) ? 1 : -1) * (clSize * 2);

        // output->verbose(
        //     CALL_INFO, 2, 0,
        //     "\tUpdating %" PRIx64 " entry to be predictedAddress: %" PRIx64
        //     " l1Distance: %" PRIx64 " offset: %" PRIx64 " lruRank: %d\n",
        //     pfqItr->pAddr, pfqItr->predictedAddress, pfqItr->l1Distance,
        //     pfqItr->offset, pfqItr->lruRank);
      } else if (pfqItr->directionalPredcitedAddresses.first == addr) {
        found = true;
        // if (wasMiss) {
        output->verbose(CALL_INFO, 2, 0,
                        "\tMatched on %" PRIx64 "'s ascending\n",
                        (pfqItr->directionalPredcitedAddresses.first - clSize));
        // Matched, set prediction
        pfqItr->predictedAddress = pfqItr->directionalPredcitedAddresses.first;
        // if (!isL2)
        pfqItr->predictedAddress += clSize;
        pfqItr->ascending = true;
        // }
      } else if (pfqItr->directionalPredcitedAddresses.second == addr) {
        found = true;
        // if (wasMiss) {
        output->verbose(
            CALL_INFO, 2, 0, "\tMatched on %" PRIx64 "'s descending\n",
            (pfqItr->directionalPredcitedAddresses.second + clSize));
        // Matched, set prediction
        pfqItr->predictedAddress = pfqItr->directionalPredcitedAddresses.second;
        // if (!isL2)
        pfqItr->predictedAddress -= clSize;
        pfqItr->ascending = false;
        // }
      } else if (pfqItr->pAddr == addr) {
        // Consider to be an interaction regarding LRU rank
        found = true;
      }
      if (found) {
        needNewEntry = false;
        // pfqItr->lruRank = -1;
        // incLRURankings();
        // Set initial distance and offset
        // pfqItr->l1Distance = initialDistance;
        // pfqItr->l2Distance = initialDistance;
        // pfqItr->offset = clSize;
        // Progress entry state
        // pfqItr->comparing = false;

        // pfqItr->lruRank = -1;
        // incLRURankings();

        // output->verbose(
        //     CALL_INFO, 2, 0,
        //     "\tUpdating %" PRIx64 " entry to be predictedAddress: %" PRIx64
        //     " l1Distance: %" PRIx64 " offset: %" PRIx64 " lruRank: %d\n",
        //     pfqItr->pAddr, pfqItr->predictedAddress, pfqItr->l1Distance,
        //     pfqItr->offset, pfqItr->lruRank);
        break;
      }
    }

    if (pfqItr->predictedAddress == addr && !pfqItr->comparing) {
      // Find if we have a matching prediction
      needNewEntry = false;
      generatePrefetches(pfqItr);
      break;
    }
    pfqItr++;
  }

  if (needNewEntry) {
    if (wasMiss) {
      // auto histItr = addrHistory->begin();
      // while (histItr != addrHistory->end()) {
      //   if (*histItr == addr) {
      //     output->verbose(
      //         CALL_INFO, 2, 0,
      //         "\tEntry creation for %" PRIx64 " cancelled by history\n",
      //         addr);
      //     statHistCancelled->addData(1);
      //     return;
      //   }
      //   histItr++;
      // }
      // Identify whether the missed line has been fetched within current PFQ
      // context

      // auto pfqItr = pfq->begin();
      // while (pfqItr != pfq->end()) {
      //   if (pfqItr->pAddr <= addr && addr <= pfqItr->lastPrefetch) {
      //     needNewEntry = false;
      //     // Reset pfq entry to align with current miss
      //     pfqItr->predictedAddress =
      //         addr + ((pfqItr->ascending ? 1 : -1) * pfqItr->offset);
      //     pfqItr->l1Distance = pfqItr->offset;
      //     pfqItr->l2Distance = pfqItr->offset;
      //     pfqItr->lastPrefetch = pfqItr->predictedAddress;
      //     pfqItr->atMaxL1Distance = false;
      //     pfqItr->atMaxL2Distance = false;
      //     pfqItr->lruRank = -1;
      //     pfqItr->hitCount = 0;
      //     output->verbose(
      //         CALL_INFO, 2, 0,
      //         "\tResetting %" PRIx64 " entry to be predictedAddress: %"
      //         PRIx64 " l1Distance: %" PRIx64 " l2Distance: %" PRIx64 "
      //         offset: %" PRIx64 " atMaxL1Distance: %d atMaxL2Distance: %d
      //         lruRank: %d\n ", pfqItr->pAddr, pfqItr->predictedAddress,
      //         pfqItr->l1Distance, pfqItr->l2Distance, pfqItr->offset,
      //         pfqItr->atMaxL1Distance, pfqItr->atMaxL2Distance,
      //         pfqItr->lruRank);
      //     statPFQResets->addData(1);
      //     break;
      //   }

      //   pfqItr++;
      // }

      bool canAdd = false;
      int64_t oldest = -1;
      if (pfq->size() < pfqSize)
        canAdd = true;
      else {
        auto pfqItr = pfq->begin();
        auto stale = pfq->begin();
        while (pfqItr != pfq->end()) {
          if (pfqItr->lruRank > oldest) {
            oldest = pfqItr->lruRank;
            stale = pfqItr;
          }
          pfqItr++;
        }
        if (oldest >= 10) {
          output->verbose(
              CALL_INFO, 2, 0,
              "\tEvicted PFQ entry %" PRIx64
              " with LRU rank %d, directionalPredcitedAddresses: "
              "{%" PRIx64 ", %" PRIx64 "}, predictedAddress: %" PRIx64 "\n",
              stale->pAddr, oldest, stale->directionalPredcitedAddresses.first,
              stale->directionalPredcitedAddresses.second,
              stale->predictedAddress);
          statPFQEvictions->addData(1);
          pfq->erase(stale);
          output->verbose(CALL_INFO, 2, 0, "\tRemaining entires:\n");
          pfqItr = pfq->begin();
          while (pfqItr != pfq->end()) {
            output->verbose(
                CALL_INFO, 2, 0,
                "\t\tPFQ entry %" PRIx64
                " directionalPredcitedAddresses: {%" PRIx64 ", %" PRIx64
                "} predictedAddress: %" PRIx64 " l1Distance: %" PRIx64
                " l2Distance: %" PRIx64 " LRU rank: %d\n",
                pfqItr->pAddr, pfqItr->directionalPredcitedAddresses.first,
                pfqItr->directionalPredcitedAddresses.second,
                pfqItr->predictedAddress, pfqItr->l1Distance,
                pfqItr->l2Distance, pfqItr->lruRank);
            pfqItr++;
          }
          canAdd = true;
        }
      }

      // if (needNewEntry) {
      // Register new PFQ entry with asc and desc predictions
      if (canAdd) {
        pfq->push_back({paddr & ~0xff,
                        vaddr & ~0xff,
                        {addr + clSize, addr - clSize},
                        0,
                        initialDistance,
                        initialDistance,
                        addr,
                        clSize,
                        true,
                        false,
                        false,
                        false,
                        0,
                        false,
                        -1});
        output->verbose(CALL_INFO, 2, 0,
                        "\tCreated PFQ entry for %" PRIx64
                        " with directionalPredcitedAddresses: "
                        "{%" PRIx64 ", %" PRIx64 "}\n",
                        pfq->back().pAddr,
                        pfq->back().directionalPredcitedAddresses.first,
                        pfq->back().directionalPredcitedAddresses.second);
      } else {
        output->verbose(CALL_INFO, 2, 0,
                        "\tSkipped creation of PFQ entry for %" PRIx64
                        " with directionalPredcitedAddresses: "
                        "{%" PRIx64 ", %" PRIx64
                        "} as oldest LRU rank was %d\n",
                        paddr & ~0xff, addr + clSize, addr - clSize, oldest);
      }
      incLRURankings();
    }
    // trimPFQ();
    // }
  }

  // addrHistory->push_back(addr);
  // if (addrHistory->size() > addrHistoryLength)
  //   addrHistory->pop_front();
}

void L1L2Prefetcher::generatePrefetches(std::deque<pfqEntry>::iterator itr) {
  uint64_t l1Dist = itr->l1Distance;
  uint64_t l2Dist = itr->l2Distance;
  Addr finalPrefetch = 0;

  // Send off prefetch events to L1 for next n cache lines
  if (itr->ascending) {
    finalPrefetch = itr->predictedAddress + l1Dist;
    sendL1Prefetch(finalPrefetch, itr->vAddr + (finalPrefetch - itr->pAddr),
                   itr->offset);
    // If not at max distance, issue more prefetches
    if (!itr->atMaxL1Distance) {
      for (uint8_t i = 1; i < numFetchAhead; i++) {
        finalPrefetch = itr->predictedAddress + l1Dist + (itr->offset * i);
        sendL1Prefetch(finalPrefetch, itr->vAddr + (finalPrefetch - itr->pAddr),
                       itr->offset);
      }
    }
  } else {
    finalPrefetch = itr->predictedAddress - l1Dist;
    sendL1Prefetch(finalPrefetch, itr->vAddr - (itr->pAddr - finalPrefetch),
                   itr->offset);
    // If not at max distance, issue more prefetches
    if (!itr->atMaxL1Distance) {
      for (uint8_t i = 1; i < numFetchAhead; i++) {
        finalPrefetch = itr->predictedAddress - l1Dist - (itr->offset * i);
        sendL1Prefetch(finalPrefetch, itr->vAddr - (itr->pAddr - finalPrefetch),
                       itr->offset);
      }
    }
  }

  // Send off prefetch events to L2 for next n cache lines
  if (!pauseL2) {
    if (itr->ascending) {
      finalPrefetch = itr->predictedAddress + l2Dist;
      sendL2Prefetch(finalPrefetch, itr->vAddr + (finalPrefetch - itr->pAddr),
                     itr->offset);
      // If not at max distance, issue more prefetches
      if (!itr->atMaxL2Distance) {
        for (uint8_t i = 1; i < numFetchAhead; i++) {
          finalPrefetch = itr->predictedAddress + l2Dist + (itr->offset * i);
          sendL2Prefetch(finalPrefetch,
                         itr->vAddr + (finalPrefetch - itr->pAddr),
                         itr->offset);
        }
      }
    } else {
      finalPrefetch = itr->predictedAddress - l2Dist;
      sendL2Prefetch(finalPrefetch, itr->vAddr - (itr->pAddr - finalPrefetch),
                     itr->offset);
      // If not at max distance, issue more prefetches
      if (!itr->atMaxL2Distance) {
        for (uint8_t i = 1; i < numFetchAhead; i++) {
          finalPrefetch = itr->predictedAddress - l2Dist - (itr->offset * i);
          sendL2Prefetch(finalPrefetch,
                         itr->vAddr - (itr->pAddr - finalPrefetch),
                         itr->offset);
        }
      }
    }
  }

  itr->lastPrefetch = finalPrefetch;

  // Update entry
  if (itr->ascending) {
    itr->predictedAddress += itr->offset;
    // itr->vAddr += itr->offset;
  } else {
    itr->predictedAddress -= itr->offset;
    // itr->vAddr -= itr->offset;
  }

  // If at max l1 distance, stop increasing l1 distance
  if (!itr->atMaxL1Distance)
    itr->l1Distance += (itr->offset * (numFetchAhead - 1));
  if (itr->l1Distance >= maxL1Distance) itr->atMaxL1Distance = true;

  // If at max l2 distance, stop increasing l2 distance
  if (!itr->atMaxL2Distance)
    itr->l2Distance += (itr->offset * (numFetchAhead - 1));
  if (itr->l2Distance >= maxL2Distance) itr->atMaxL2Distance = true;

  itr->lruRank = -1;
  incLRURankings();

  output->verbose(
      CALL_INFO, 2, 0,
      "\tUpdating %" PRIx64 " entry to be predictedAddress: %" PRIx64
      " l1Distance: %" PRIx64 " l2Distance: %" PRIx64 " offset: %" PRIx64
      " atMaxL1Distance: %d atMaxL2Distance: %d lruRank: %d\n",
      itr->pAddr, itr->predictedAddress, itr->l1Distance, itr->l2Distance,
      itr->offset, itr->atMaxL1Distance, itr->atMaxL2Distance, itr->lruRank);
}

void L1L2Prefetcher::sendL1Prefetch(Addr pAddr, Addr vAddr, size_t size) {
  // auto histItr = addrHistory->begin();
  // while (histItr != addrHistory->end()) {
  //   if (*histItr == pAddr) {
  //     output->verbose(CALL_INFO, 2, 0,
  //                     "\tPrefetch for %" PRIx64 " cancelled by history\n",
  //                     pAddr);
  //     statHistCancelled->addData(1);
  //     return;
  //   }
  //   histItr++;
  // }
  output->verbose(CALL_INFO, 2, 0,
                  "\tReturn prefetch to shim for address: %" PRIx64 "/%" PRIx64
                  "\n",
                  pAddr, vAddr);
  // Create event
  PrefetchEvent* prfEv = new PrefetchEvent(size, pAddr, vAddr);
  // Broadcast to processor and L2 shim
  fromCore_link->send(new PrefetchEvent(*prfEv));
  fromPRF_links[0]->send(new PrefetchEvent(*prfEv));

  // addrHistory->push_back(pAddr);
  // if (addrHistory->size() > addrHistoryLength) addrHistory->pop_front();

  delete prfEv;

  statL1PrefetchEventsIssued->addData(1);
}

void L1L2Prefetcher::sendL2Prefetch(Addr pAddr, Addr vAddr, size_t size) {
  // auto histItr = addrHistory->begin();
  // while (histItr != addrHistory->end()) {
  //   if (*histItr == pAddr) {
  //     output->verbose(CALL_INFO, 2, 0,
  //                     "\tPrefetch for %" PRIx64 " cancelled by history\n",
  //                     pAddr);
  //     statHistCancelled->addData(1);
  //     return;
  //   }
  //   histItr++;
  // }
  output->verbose(CALL_INFO, 2, 0,
                  "\tReturn prefetch to shim for address: %" PRIx64 "/%" PRIx64
                  "\n",
                  pAddr, vAddr);
  // Create event
  PrefetchEvent* prfEv = new PrefetchEvent(size, pAddr, vAddr);
  // Broadcast to processor and L2 shim
  fromPRF_links[1]->send(new PrefetchEvent(*prfEv));

  // addrHistory->push_back(pAddr);
  // if (addrHistory->size() > addrHistoryLength) addrHistory->pop_front();

  delete prfEv;

  statL2PrefetchEventsIssued->addData(1);
}

void L1L2Prefetcher::incLRURankings() {
  auto pfqItr = pfq->begin();
  while (pfqItr != pfq->end()) {
    pfqItr->lruRank++;
    pfqItr++;
  }
}

void L1L2Prefetcher::trimPFQ() {
  // Ensure we haven't exceeded the PFQ size
  while (pfq->size() > pfqSize) {
    int16_t oldest = INT16_MIN;
    auto entry = pfq->begin();
    auto pfqItr = pfq->begin();
    while (pfqItr != pfq->end()) {
      if (pfqItr->lruRank >= oldest) {
        if (entry->l2Distance >= maxL2Distance ||
            pfqItr->lruRank >= pfqSize * 2) {
          oldest = pfqItr->lruRank;
          entry = pfqItr;
        }
      }
      pfqItr++;
    }
    output->verbose(
        CALL_INFO, 2, 0,
        "\tEvicted PFQ entry %" PRIx64
        " with LRU rank %d, directionalPredcitedAddresses: "
        "{%" PRIx64 ", %" PRIx64 "}, predictedAddress: %" PRIx64 "\n",
        entry->pAddr, oldest, entry->directionalPredcitedAddresses.first,
        entry->directionalPredcitedAddresses.second, entry->predictedAddress);
    pfq->erase(entry);
    statPFQEvictions->addData(1);

    output->verbose(CALL_INFO, 2, 0, "\tRemaining entires:\n");
    pfqItr = pfq->begin();
    while (pfqItr != pfq->end()) {
      output->verbose(
          CALL_INFO, 2, 0,
          "\t\tPFQ entry %" PRIx64 " directionalPredcitedAddresses: {%" PRIx64
          ", %" PRIx64 "} predictedAddress: %" PRIx64 " l1Distance: %" PRIx64
          " l2Distance: %" PRIx64 " LRU rank: %d\n",
          pfqItr->pAddr, pfqItr->directionalPredcitedAddresses.first,
          pfqItr->directionalPredcitedAddresses.second,
          pfqItr->predictedAddress, pfqItr->l1Distance, pfqItr->l2Distance,
          pfqItr->lruRank);
      pfqItr++;
    }
  }
}