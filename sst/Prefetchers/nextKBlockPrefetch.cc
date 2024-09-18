// Copyright 2009-2022 NTESS. Under the terms
// of Contract DE-NA0003525 with NTESS, the U.S.
// Government retains certain rights in this software.
//
// Copyright (c) 2009-2022, NTESS
// All rights reserved.
//
// Portions are copyright of other developers:
// See the file CONTRIBUTORS.TXT in the top level directory
// of the distribution for more information.
//
// This file is part of the SST software package. For license
// information, see the LICENSE file in the top level directory of the
// distribution.

// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include "sst/core/sst_config.h"
// clang-format on

#include "Prefetchers/nextKBlockPrefetch.hh"

#include <stdint.h>
#include <vector>

#include "sst/core/params.h"

using namespace SST;
using namespace SST::MemHierarchy;
using namespace SST::Cassini;


NextKBlockPrefetcher::NextKBlockPrefetcher(ComponentId_t id, Params& params) : CacheListener(id, params) {
    requireLibrary("memHierarchy");

    blockSize = params.find<uint64_t>("cache_line_size", 64);
    aggressiveness = params.find<uint64_t>("aggressiveness", 1);

    statPrefetchEventsIssued = registerStatistic<uint64_t>("prefetches_issued");
    statMissEventsProcessed  = registerStatistic<uint64_t>("miss_events_processed");
    statHitEventsProcessed   = registerStatistic<uint64_t>("hit_events_processed");
}

NextKBlockPrefetcher::~NextKBlockPrefetcher() {}

void NextKBlockPrefetcher::notifyAccess(const CacheListenerNotification& notify) {
    const NotifyAccessType notifyType = notify.getAccessType();
    const NotifyResultType notifyResType = notify.getResultType();
    const Addr addr = notify.getPhysicalAddress();

    if (notifyType == READ || notifyType == WRITE) { // ignore evicts
        if(notifyResType == MISS) {
            statMissEventsProcessed->addData(1);

            Addr nextBlockAddr = (addr - (addr % blockSize)) + blockSize;
            std::vector<Event::HandlerBase*>::iterator callbackItr;
            statPrefetchEventsIssued->addData(1);

            for(Addr blockAddr = nextBlockAddr; blockAddr < (nextBlockAddr + (aggressiveness*blockSize)); blockAddr+=blockSize){
                // Cycle over each registered call back and notify them that we want to issue a prefetch request
                for(callbackItr = registeredCallbacks.begin(); callbackItr != registeredCallbacks.end(); callbackItr++) {
                    // Create a new read request, we cannot issue a write because the data will get
                    // overwritten and corrupt memory (even if we really do want to do a write)
                    MemEvent* newEv = new MemEvent(getName(), blockAddr, blockAddr, Command::GetS);
                    newEv->setSize(blockSize);
                    newEv->setPrefetchFlag(true);
                    (*(*callbackItr))(newEv);
                }
            }
        } else {
            statHitEventsProcessed->addData(1);
        }
    }
}

void NextKBlockPrefetcher::registerResponseCallback(Event::HandlerBase *handler) {
    registeredCallbacks.push_back(handler);
}

void NextKBlockPrefetcher::printStats(Output& out) {

}
