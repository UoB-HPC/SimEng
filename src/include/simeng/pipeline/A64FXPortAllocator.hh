#pragma once

#include "simeng/pipeline/PortAllocator.hh"
#include <vector>

namespace simeng {
namespace pipeline {

/** The A64FX defined instruction attribute groups. */
namespace InstructionAttribute {
  const uint8_t RSX = 0;
  const uint8_t RSE = 1;
  const uint8_t RSA = 2;
  const uint8_t RSE0 = 3;
  const uint8_t RSE1 = 4;
  const uint8_t BR = 5;
}

/** An A64FX port allocator implementation. Follows the functionality
 * described in the A64FX Microarchitecture manual. */
class A64FXPortAllocator : public PortAllocator {
 public:
  A64FXPortAllocator(std::vector<std::vector<std::vector<std::pair<uint16_t, uint8_t>>>> portArrangement);

  uint8_t allocate(uint16_t instructionGroup) override;

  void issued(uint8_t port) override;

  void deallocate(uint8_t port) override;

  /** A mapping from instruction group to instruction attribute */
  uint8_t attributeMapping(uint16_t group);

  /** Set function from DispatchIssueUnit to retrieve reservation 
   * station sizes during execution. */
  void setRSSizeGetter(std::function<void(std::vector<uint64_t>&)> rsSizes) override;

  void tick() override;

 private:
  /** The instruction group support matrix. An instruction-group-indexed map
   * containing lists of the ports that support each instruction group. */
  std::vector<std::vector<uint8_t>> supportMatrix;

  /** The instruction group attribute matrix. An instruction-group-indexed map
   * containing the instruction attribute that relates to each instruction group. */
  std::vector<uint8_t> attributeMatrix;

  /** A list of the A64FX allocation table row selection indicators based on previous allocations. */
  std::vector<uint8_t> rowSelection;

  /** Get the current sizes an capacity of the reservation stations */
  std::function<void(std::vector<uint64_t>&)> rsSizes_;

  /** Mapping from reservation station to ports */
  std::vector<std::vector<uint8_t>> rsToPort_;
  
  std::vector<uint64_t> freeEntries_;
};

}  // namespace pipeline
}  // namespace simeng
