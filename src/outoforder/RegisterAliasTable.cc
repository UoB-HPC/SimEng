#include "RegisterAliasTable.hh"

#include <cassert>

namespace simeng {
namespace outoforder {

RegisterAliasTable::RegisterAliasTable(
    std::vector<RegisterFileStructure> architecturalStructure,
    std::vector<uint16_t> physicalRegisterCounts)
    : mappingTable(architecturalStructure.size()),
      historyTable(architecturalStructure.size()),
      destinationTable(architecturalStructure.size()),
      freeQueues(architecturalStructure.size()) {
  assert(architecturalStructure.size() == physicalRegisterCounts.size() &&
         "The number of physical register types does not match the number of "
         "architectural register types");

  for (size_t type = 0; type < architecturalStructure.size(); type++) {
    auto archCount = architecturalStructure[type].quantity;
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

    // Set up history/destination tables
    historyTable[type].resize(physCount);
    destinationTable[type].resize(physCount);
  }
};

Register RegisterAliasTable::getMapping(Register architectural) const {
  auto tag = mappingTable[architectural.type][architectural.tag];
  return {architectural.type, tag};
}

bool RegisterAliasTable::canAllocate(uint8_t type,
                                     unsigned int quantity) const {
  return (freeQueues[type].size() >= quantity);
}

Register RegisterAliasTable::allocate(Register architectural) {
  std::queue<uint16_t>& freeQueue = freeQueues[architectural.type];
  assert(freeQueue.size() > 0 &&
         "Attempted to allocate free register when none were available");

  auto tag = freeQueue.front();
  freeQueue.pop();

  // Keep the old physical register in the history table
  historyTable[architectural.type][tag] =
      mappingTable[architectural.type][architectural.tag];

  // Update the mapping table with the new tag, and mark the architectural
  // register it replaces in the destination table
  mappingTable[architectural.type][architectural.tag] = tag;
  destinationTable[architectural.type][tag] = architectural.tag;

  return {architectural.type, tag};
}

void RegisterAliasTable::commit(Register physical) {
  // Find the register previously mapped to the same architectural register and
  // free it
  auto oldTag = historyTable[physical.type][physical.tag];
  freeQueues[physical.type].push(oldTag);
}
void RegisterAliasTable::rewind(Register physical) {
  // Find which architectural tag this referred to
  auto destinationTag = destinationTable[physical.type][physical.tag];
  // Rewind the mapping table to the old physical tag
  mappingTable[physical.type][destinationTag] =
      historyTable[physical.type][physical.tag];
  // Add the rewound physical tag back to the free queue
  freeQueues[physical.type].push(physical.tag);
}
void RegisterAliasTable::free(Register physical) {
  freeQueues[physical.type].push(physical.tag);
}

}  // namespace outoforder
}  // namespace simeng
