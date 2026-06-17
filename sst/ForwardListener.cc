#include "ForwardListener.hh"

#include <cstdlib>
#include <iostream>

#include "sst/core/params.h"

using namespace SST::SSTSimEng;
using namespace SST::Interfaces;

ForwardListener::ForwardListener(ComponentId_t id, Params& params)
    : CacheListener(id, params), forwardLink(nullptr) {
  requireLibrary("memHierarchy");

  verbosity = params.find<int>("verbose", 0);

  char* new_prefix = (char*)malloc(sizeof(char) * 128);
  snprintf(new_prefix, sizeof(char) * 128, "ForwardListener[%s | @p]\t",
           getName().c_str());
  output = new Output(new_prefix, verbosity, 0, Output::STDOUT);
  free(new_prefix);

  output->output(CALL_INFO, "Configuring Link\n");

  // Configure link to Prefetcher
  forwardLink = configureLink(std::string("forward_link"), "1ps",
                              new Event::Handler<ForwardListener>(
                                  this, &ForwardListener::recvLinkEvent));
  if (!forwardLink) {
    output->fatal(CALL_INFO, -1,
                  "Did not find any connected links on port forward_link\n");
  }

  onlyMisses = params.find<bool>("only_misses", false);
  isL2 = params.find<bool>("is_l2", false);

  output->output(CALL_INFO, "Forward Link Id: %d\n", forwardLink->getId());

  readMiss = registerStatistic<uint64_t>("read_miss");
  readHit = registerStatistic<uint64_t>("read_hit");
  writeMiss = registerStatistic<uint64_t>("write_miss");
  writeHit = registerStatistic<uint64_t>("write_hit");
  prfMiss = registerStatistic<uint64_t>("prf_miss");
  prfHit = registerStatistic<uint64_t>("prf_hit");
}
ForwardListener::~ForwardListener() {}

void ForwardListener::notifyAccess(
    const MemHierarchy::CacheListenerNotification& notify) {
  if (notify.getResultType() == MemHierarchy::NotifyResultType::NA) return;
  if (notify.getAccessType() == MemHierarchy::NotifyAccessType::EVICT) return;

  if (notify.getAccessType() == MemHierarchy::NotifyAccessType::READ) {
    if (notify.getResultType() == MemHierarchy::NotifyResultType::MISS)
      readMiss->addData(1);
    else if (notify.getResultType() == MemHierarchy::NotifyResultType::HIT)
      readHit->addData(1);
  } else if (notify.getAccessType() == MemHierarchy::NotifyAccessType::WRITE) {
    if (notify.getResultType() == MemHierarchy::NotifyResultType::MISS)
      writeMiss->addData(1);
    else if (notify.getResultType() == MemHierarchy::NotifyResultType::HIT)
      writeHit->addData(1);
  } else if (notify.getAccessType() ==
             MemHierarchy::NotifyAccessType::PREFETCH) {
    if (notify.getResultType() == MemHierarchy::NotifyResultType::MISS)
      prfMiss->addData(1);
    else if (notify.getResultType() == MemHierarchy::NotifyResultType::HIT)
      prfHit->addData(1);
  }

  output->verbose(
      CALL_INFO, 2, 0,
      "Forwarding cache access event -  size: %d, targAddr: %" PRIx64
      ", physAddr: %" PRIx64 ", virtAddr: %" PRIx64 ", instPtr: %" PRIx64
      ", access: %d, result: %d\n",
      notify.getSize(), notify.getTargetAddress(), notify.getPhysicalAddress(),
      notify.getVirtualAddress(), notify.getInstructionPointer(),
      notify.getAccessType(), notify.getResultType());

  // Forward access over link
  CacheListenerEvent* event = new CacheListenerEvent(
      notify.getTargetAddress(), notify.getPhysicalAddress(),
      notify.getVirtualAddress(), notify.getInstructionPointer(),
      notify.getSize(), notify.getAccessType(), notify.getResultType(), isL2);

  // Don't forward non-miss if only forwarding misses
  if (onlyMisses &&
      notify.getResultType() != MemHierarchy::NotifyResultType::MISS)
    return;

  forwardLink->send(event);
}