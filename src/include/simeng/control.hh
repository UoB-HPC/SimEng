#pragma once

#include <cstdint>
#include <list>
#include <map>

#include "simeng/trace.hh"

// Counters for tracing
extern uint64_t trace_cycle;
extern uint64_t traceId;
// Containers for storing traces/probes
extern std::map<uint64_t, simeng::Trace*> traceMap;
extern std::list<simeng::Trace*> probeList;
