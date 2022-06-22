#pragma once

#include <inttypes.h>

#include <fstream>
#include <list>
#include <map>

namespace simeng {

// Struct for fetch details
struct fetchTrace {
  uint64_t cycle;
  uint32_t insnHex;
  uint64_t address;
  int microOpNum;
  std::string disasm;
};
// Struct for probe event ticks
struct probeTrace {
  int event;
  uint64_t cycle;
  uint64_t insn_num;
};
// Struct for cycle event ticks
struct cycleTrace {
  fetchTrace fetch;
  uint64_t decode;
  uint64_t rename;
  uint64_t dispatch;
  uint64_t issue;
  uint64_t complete;
  uint64_t retire;
  int finished;
};

// Class for storing the trace of a instruction through the pipeline
class Trace {
 public:
  // Constructor
  Trace();

  /** Write out cycle trace and return success int */
  int writeCycleOut(char* str, uint64_t traceId, std::string model);
  /** Write out probe trace and return success int */
  int writeProbeOut(char* str, uint64_t index, int newline, int start);

  /** Set cycle trace data */
  void setCycleTraces(cycleTrace cycle);
  /** Set probe trace data */
  void setProbeTraces(probeTrace probe);

  /** Retrieve the cycle trace data */
  cycleTrace getCycleTraces();
  /** Retrieve the probe trace data */
  probeTrace getProbeTraces();

 protected:
  /** The cycle trace data for one instruction cycle */
  cycleTrace cycleTrace_;
  /** The probe trace data for one instruction cycle */
  probeTrace probeTrace_;
};
}  // namespace simeng