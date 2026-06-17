#include "Listener.hh"

#include <cstdlib>
#include <iostream>

#include "sst/core/params.h"

using namespace SST::SSTSimEng;
using namespace SST::Interfaces;

Listener::Listener(ComponentId_t id, Params& params)
    : CacheListener(id, params) {
  requireLibrary("memHierarchy");

  verbosity = params.find<int>("verbose", 0);

  char* new_prefix = (char*)malloc(sizeof(char) * 128);
  snprintf(new_prefix, sizeof(char) * 128, "Listener[%s | @p]\t",
           getName().c_str());
  output = new Output(new_prefix, verbosity, 0, Output::STDOUT);
  free(new_prefix);
}
Listener::~Listener() {}

void Listener::notifyAccess(
    const MemHierarchy::CacheListenerNotification& notify) {
  // if (notify.getResultType() == MemHierarchy::NotifyResultType::NA) return;
  // if (notify.getAccessType() == MemHierarchy::NotifyAccessType::EVICT)
  // return;

  output->verbose(
      CALL_INFO, 2, 0,
      "Forwarding cache access event -  size: %d, targAddr: %" PRIx64
      ", physAddr: %" PRIx64 ", virtAddr: %" PRIx64 ", instPtr: %" PRIx64
      ", access: %d, result: %d\n",
      notify.getSize(), notify.getTargetAddress(), notify.getPhysicalAddress(),
      notify.getVirtualAddress(), notify.getInstructionPointer(),
      notify.getAccessType(), notify.getResultType());
}