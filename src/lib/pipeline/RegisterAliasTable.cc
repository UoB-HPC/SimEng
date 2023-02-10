#include "simeng/pipeline/RegisterAliasTable.hh"

#include <cassert>

namespace simeng {
namespace pipeline {

RegisterAliasTable::RegisterAliasTable(
    std::vector<RegisterFileStructure> architecturalStructure,
    std::vector<uint16_t> physicalRegisterCounts)
    : mappingTable_(architecturalStructure.size()),
      historyTable_(architecturalStructure.size()),
      destinationTable_(architecturalStructure.size()),
      freeQueues_(architecturalStructure.size()) {
  assert(architecturalStructure.size() == physicalRegisterCounts.size() &&
         "The number of physical register types does not match the number of "
         "architectural register types");

  for (size_t type = 0; type < architecturalStructure.size(); type++) {
    auto archCount = architecturalStructure[type].quantity;
    auto physCount = physicalRegisterCounts[type];
    assert(archCount <= physCount &&
           "Cannot have fewer physical registers than architectural registers");

    // Set up the initial mapping table state for this register type
    mappingTable_[type].resize(archCount);

    for (size_t tag = 0; tag < archCount; tag++) {
      // Pre-assign a physical register to each architectural register
      mappingTable_[type][tag] = tag;
    }

    // Add remaining physical registers to free queue
    for (size_t tag = archCount; tag < physCount; tag++) {
      freeQueues_[type].push(tag);
    }

    // Set up history/destination tables
    historyTable_[type].resize(physCount);
    destinationTable_[type].resize(physCount);
  }
};

Register RegisterAliasTable::getMapping(Register architectural) const {
  // Asserts to ensure mapping isn't attempted for an out-of-bound index (i.e.
  // mapping of WZR / XZR)
  assert(architectural.type < mappingTable_.size() &&
         "Invalid register type. Cannot find RAT mapping.");
  assert(architectural.type >= 0 &&
         "Invalid register type. Cannot find RAT mapping.");

  auto tag = mappingTable_[architectural.type][architectural.tag];
  return {architectural.type, tag};
}

bool RegisterAliasTable::canAllocate(uint8_t type,
                                     unsigned int quantity) const {
  return (freeQueues_[type].size() >= quantity);
}

bool RegisterAliasTable::canRename(uint8_t type) const {
  // Renaming possible iff there are more physical than architectural registers
  return destinationTable_[type].size() > mappingTable_[type].size();
}

unsigned int RegisterAliasTable::freeRegistersAvailable(uint8_t type) const {
  return freeQueues_[type].size();
}

Register RegisterAliasTable::allocate(Register architectural) {
  std::queue<uint16_t>& freeQueue = freeQueues_[architectural.type];
  assert(freeQueue.size() > 0 &&
         "Attempted to allocate free register when none were available");

  auto tag = freeQueue.front();
  freeQueue.pop();

  // Keep the old physical register in the history table
  historyTable_[architectural.type][tag] =
      mappingTable_[architectural.type][architectural.tag];

  // Update the mapping table with the new tag, and mark the architectural
  // register it replaces in the destination table
  mappingTable_[architectural.type][architectural.tag] = tag;
  destinationTable_[architectural.type][tag] = architectural.tag;

  return {architectural.type, tag};
}

void RegisterAliasTable::commit(Register physical) {
  // Find the register previously mapped to the same architectural register and
  // free it
  auto oldTag = historyTable_[physical.type][physical.tag];
  freeQueues_[physical.type].push(oldTag);
}
void RegisterAliasTable::rewind(Register physical) {
  // Find which architectural tag this referred to
  auto destinationTag = destinationTable_[physical.type][physical.tag];
  // Rewind the mapping table to the old physical tag
  mappingTable_[physical.type][destinationTag] =
      historyTable_[physical.type][physical.tag];
  // Add the rewound physical tag back to the free queue
  freeQueues_[physical.type].push(physical.tag);
}
void RegisterAliasTable::free(Register physical) {
  freeQueues_[physical.type].push(physical.tag);
}

void RegisterAliasTable::reset(
    const std::vector<RegisterFileStructure>& architecturalStructure,
    const std::vector<uint16_t>& physicalRegisterCounts) {
  // Get number of register types
  size_t archStructSize = architecturalStructure.size();
  for (size_t type = 0; type < archStructSize; type++) {
    uint16_t archCount = architecturalStructure[type].quantity;
    uint16_t physCount = physicalRegisterCounts[type];

    for (uint16_t tag = 0; tag < archCount; tag++) {
      // Pre-assign a physical register to each architectural register
      mappingTable_[type][tag] = tag;
    }
    // Reset rest of mappingTable_ to NULL
    std::fill(mappingTable_[type].begin() + archCount,
              mappingTable_[type].end(), NULL);

    // Delete current freeQueues_
    freeQueues_[type] = std::queue<uint16_t>();
    // Add remaining physical registers to free queue
    for (uint16_t tag = archCount; tag < physCount; tag++) {
      freeQueues_[type].push(tag);
    }

    // Fill history and destination Tables with defualt values
    std::fill(historyTable_[type].begin(), historyTable_[type].end(), NULL);
    std::fill(destinationTable_[type].begin(), destinationTable_[type].end(),
              NULL);
  }
}

}  // namespace pipeline
}  // namespace simeng
