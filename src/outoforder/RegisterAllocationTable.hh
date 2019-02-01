#pragma once

#include <queue>

#include "../RegisterFile.hh"

namespace simeng {
namespace outoforder {

class RegisterAllocationTable {
 public:
  RegisterAllocationTable(
      std::vector<std::pair<uint8_t, uint16_t>> architecturalStructure,
      std::vector<uint16_t> physicalStructure);
  Register getMapping(Register architectural) const;
  bool canAllocate(Register architectural) const;
  Register allocate(Register architectural);
  void free(Register physical);

 private:
  std::vector<std::vector<uint16_t>> mappingTable;
  std::vector<std::queue<uint16_t>> freeQueues;
};

}  // namespace outoforder
}  // namespace simeng
