#include "RegisterAllocationTable.hh"

#include <cassert>

namespace simeng {
namespace outoforder {

RegisterAllocationTable::RegisterAllocationTable(
    std::vector<std::pair<uint8_t, uint16_t>> architecturalStructure,
    std::vector<uint16_t> physicalRegisterCounts)
    : mappingTable(architecturalStructure.size()) {
  assert(architecturalStructure.size() == physicalRegisterCounts.size() &&
         "Physical register quantities do not map to architectural register "
         "structure");

  for (size_t type = 0; type < architecturalStructure.size(); type++) {
    auto archCount = architecturalStructure[type].second;
    auto physCount = physicalRegisterCounts[type];
    assert(archCount <= physCount &&
           "Cannot have fewer physical registers than architectural registers");

    // Set up the initial mapping table state for this register type
    mappingTable[type].resize(archCount);
    for (size_t tag = 0; tag < archCount; tag++) {
      // Pre-assign a physical register to each architectural register
      mappingTable[type][tag] = tag;
    }

    // Add remaining physical registers to free queue
    for (size_t tag = archCount; tag < physCount; tag++) {
      freeQueues[type].push(tag);
    }
  }
};

Register RegisterAllocationTable::getMapping(Register architectural) const {
  auto tag = mappingTable[architectural.type][architectural.tag];
  return {architectural.type, tag};
}

bool RegisterAllocationTable::canAllocate(Register architectural) const {
  return (freeQueues[architectural.type].size() > 0);
}

Register RegisterAllocationTable::allocate(Register architectural) {
  auto freeQueue = freeQueues[architectural.type];
  assert(freeQueue.size() > 0 &&
         "Attempted to allocate free register when none were available");

  auto tag = freeQueue.front();
  freeQueue.pop();
  mappingTable[architectural.type][architectural.tag] = tag;

  return {architectural.type, tag};
}

void RegisterAllocationTable::free(Register physical) {
  freeQueues[physical.tag].push(physical.tag);
}

}  // namespace outoforder
}  // namespace simeng
