#include "PrefetcherShim.h"

#include <cstdlib>
#include <iostream>

#include "sst/core/params.h"

using namespace SST;
using namespace SST::SSTSimEng;

PrefetcherShim::PrefetcherShim(ComponentId_t id, Params& params)
    : CacheListener(id, params),
      toPrefetcher(nullptr),
      fromPrefetcher(nullptr) {
  requireLibrary("memHierarchy");

  verbosity = params.find<int>("verbose", 0);

  char* new_prefix = (char*)malloc(sizeof(char) * 128);
  snprintf(new_prefix, sizeof(char) * 128, "PrefetcherShim[%s | @p]\t",
           getName().c_str());
  output = new Output(new_prefix, verbosity, 0, Output::STDOUT);
  free(new_prefix);

  shouldForward = params.find<bool>("should_forward", true);
  isL2 = params.find<bool>("is_l2", false);

  // Configure link to Prefetcher
  output->output(CALL_INFO,
                 "Configuring port with shouldForward: %d, isL2: %d\n",
                 shouldForward, isL2);
  toPrefetcher = configureLink(std::string("to_prefetcher_link"), "1ps",
                               new Event::Handler<PrefetcherShim>(
                                   this, &PrefetcherShim::recvPrefetchRequest));

  output->output(CALL_INFO, "To prefetcher Port %d\n", toPrefetcher->getId());
}
PrefetcherShim::~PrefetcherShim() {}

void PrefetcherShim::notifyAccess(const CacheListenerNotification& notify) {
  if (!shouldForward) return;

  // Only forward READ/WRITE accesses
  if (notify.getAccessType() == MemHierarchy::NotifyAccessType::READ ||
      notify.getAccessType() == MemHierarchy::NotifyAccessType::WRITE) {
    // Forward access over link to attached prefetcher component
    NotifyEvent* event =
        new NotifyEvent(notify.getSize(), notify.getTargetAddress(),
                        notify.getPhysicalAddress(), notify.getVirtualAddress(),
                        notify.getInstructionPointer(), notify.getAccessType(),
                        notify.getResultType(), toPrefetcher->getId(), isL2);

    // output->verbose(
    //     CALL_INFO, 2, 0,
    //     "Forwarding prefetch event over port %d -  size: %d, targAddr: %"
    //     PRIx64
    //     ", physAddr: %" PRIx64 ", virtAddr: %" PRIx64 ", instPtr: %" PRIx64
    //     ", access: %d, result: %d, isL2: %d\n",
    //     toPrefetcher->getId(), notify.getSize(), notify.getTargetAddress(),
    //     notify.getPhysicalAddress(), notify.getVirtualAddress(),
    //     notify.getInstructionPointer(), notify.getAccessType(),
    //     notify.getResultType(), isL2);

    toPrefetcher->send(event);
  }
}

void PrefetcherShim::recvPrefetchRequest(Event* ev) {
  PrefetchEvent* event = dynamic_cast<PrefetchEvent*>(ev);

  uint32_t size = event->getSize();
  Addr pAddr = event->getPAddr();
  Addr vAddr = event->getVAddr();

  output->verbose(CALL_INFO, 2, 0,
                  "\tGot from prefetcher - prefetch addr: %" PRIx64 " (%" PRIx64
                  "), size: %d\n",
                  pAddr, vAddr, size);

  std::vector<Event::HandlerBase*>::iterator callbackItr;
  for (callbackItr = registeredCallbacks.begin();
       callbackItr != registeredCallbacks.end(); callbackItr++) {
    MemEvent* newEv = new MemEvent(getName(), pAddr, pAddr, Command::GetS);
    newEv->setVirtualAddress(vAddr);
    newEv->setSize(size);
    newEv->setPrefetchFlag(true);
    (*(*callbackItr))(newEv);
  }

  delete event;
}

void PrefetcherShim::registerResponseCallback(Event::HandlerBase* handler) {
  registeredCallbacks.push_back(handler);
}

void PrefetcherShim::printStats(Output& out) {}