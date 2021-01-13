#include "simeng/trace.hh"

namespace simeng {

Trace::Trace() {}

// Write formatted instruction cycle trace to output file
int Trace::writeCycleOut(char (&str)[1000], uint64_t traceId,
                         std::string model) {
  if (cycleTrace_.finished == 1) {
    cycleTrace element = cycleTrace_;
    fetchTrace fetch = element.fetch;
    // char buffer[1000];
    // If the model is an o3 pipeline
    if (model == std::string("outoforder")) {
      sprintf(str,
              "%" PRId64 ":%" PRId64 ":%" PRId64 ":%" PRId64 ":%" PRId64
              ":%" PRId64 ":%" PRId64 ":0x%02X:%d:%" PRId64 ":%s\n",
              fetch.cycle, element.decode, element.rename, element.dispatch,
              element.issue, element.complete, element.retire, fetch.address,
              fetch.microOpNum, traceId, fetch.disasm.c_str());
    } else {
      sprintf(str,
              "%" PRId64 ":%" PRId64 ":%" PRId64 ":%" PRId64
              ":%#010x:%d:%" PRId64 ":%s\n",
              fetch.cycle, element.decode, element.complete, element.retire,
              fetch.address, fetch.microOpNum, traceId, fetch.disasm.c_str());
    }
    // Kept so we can print for gem5 and compare visualisers
    // if(model == std::string("outoforder")){
    //   sprintf(str, "O3PipeView:fetch:%" PRId64 ":%#010x:%d:%" PRId64
    //   ":%s\nO3PipeView:decode:%" PRId64 "\nO3PipeView:rename:%" PRId64
    //   "\nO3PipeView:dispatch:%" PRId64 "\nO3PipeView:issue:%" PRId64
    //   "\nO3PipeView:complete:%" PRId64 "\nO3PipeView:retire:%" PRId64 "\n",
    //     fetch.cycle, fetch.address, fetch.microOpNum, traceId,
    //     fetch.disasm.c_str(), element.decode, element.rename,
    //     element.dispatch, element.issue, element.complete, element.retire);
    // } else {
    //   sprintf(str, "O3PipeView:fetch:%" PRId64 ":%#010x:%d:%" PRId64
    //   ":%s\nO3PipeView:decode:%" PRId64 "\nO3PipeView:complete:%" PRId64
    //   "\nO3PipeView:retire:%" PRId64 "\n",
    //     fetch.cycle, fetch.address, fetch.microOpNum, traceId,
    //     fetch.disasm.c_str(), element.decode, element.complete,
    //     element.retire);
    // }
    return 1;
  } else {
    return 0;
  }
}

// Write formatted probe events to output file
int Trace::writeProbeOut(char (&str)[4], uint64_t index, int newline,
                         int start) {
  if (!start) {
    if (newline)
      sprintf(str, "\n%d,%" PRId64 "", probeTrace_.event, probeTrace_.insn_num);
    else
      sprintf(str, ":%d,%" PRId64 "", probeTrace_.event, probeTrace_.insn_num);
  } else {
    sprintf(str, "%d,%" PRId64 "", probeTrace_.event, probeTrace_.insn_num);
  }
  int val = 1;
  return val;
}

// Getters and setters
void Trace::setCycleTraces(cycleTrace cycle) { cycleTrace_ = cycle; }
cycleTrace Trace::getCycleTraces() { return cycleTrace_; }

void Trace::setProbeTraces(probeTrace probe) { probeTrace_ = probe; }
probeTrace Trace::getProbeTraces() { return probeTrace_; }

}  // namespace simeng
