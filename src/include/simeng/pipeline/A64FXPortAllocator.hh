#pragma once

#include <vector>

#include "simeng/pipeline/PortAllocator.hh"

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
}  // namespace InstructionAttribute

/** An A64FX port allocator implementation. Follows the functionality
 * described in the A64FX Microarchitecture manual. */
class A64FXPortAllocator : public PortAllocator {
 public:
  A64FXPortAllocator(std::vector<std::vector<uint16_t>> portArrangement);

  uint8_t allocate(std::vector<uint8_t> ports) override;

  void issued(uint8_t port) override;

  void deallocate(uint8_t port) override;

  /** A mapping from issye ports to instruction attribute */
  uint8_t attributeMapping(std::vector<uint8_t> ports);

  /** Set function from DispatchIssueUnit to retrieve reservation
   * station sizes during execution. */
  void setRSSizeGetter(
      std::function<void(std::vector<uint64_t>&)> rsSizes) override;

  /** Tick the port allocator to allow it to process internal tasks. */
  void tick() override;

 private:
  /** An approximate estimation of the index of an instruction within the input
   * buffer of the dispatch unit. Increments slot at each allocation thus cannot
   * account for nullptr entries in buffer.*/
  uint8_t dispatchSlot_;

  /** Get the current sizes an capacity of the reservation stations. */
  std::function<void(std::vector<uint64_t>&)> rsSizes_;

  /** Mapping from reservation station to ports. */
  std::vector<std::vector<uint8_t>> rsToPort_;

  /** Vector of free entires across all reservation stations. */
  std::vector<uint64_t> freeEntries_;

  /** Reservation station classifications as detailed in manual. */
  /** RSE with most free entries. */
  uint8_t RSEm_;
  /** RSE with least free entries. */
  uint8_t RSEf_;
  /** RSA with most free entries. */
  uint8_t RSAm_;
  /** RSA with least free entries. */
  uint8_t RSAf_;
};

}  // namespace pipeline
}  // namespace simeng
