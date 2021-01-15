#include "simeng/control.hh"

uint64_t trace_cycle = 1;
uint64_t traceId = 1;
std::map<uint64_t, simeng::Trace*> traceMap;
std::list<simeng::Trace*> probeList;