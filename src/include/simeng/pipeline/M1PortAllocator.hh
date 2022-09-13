#pragma once

#include <cstdint>
#include <vector>

#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {
namespace pipeline {

/** A load-balancing port allocator implementation. Maintains demand weightings
 * for each port, and allocates instructions to the suitable port with the
 * lowest weighting. */
class M1PortAllocator : public PortAllocator {
 public:
  /** Construct a load-balancing port allocator, providing a port arrangement
   * specification. Each element of the port arrangement should represent a
   * port, and contain a list of the instruction groups that port supports and
   * a port type which denotes the matching requirements of said instruction
   * groups. */
  M1PortAllocator(const std::vector<std::vector<uint16_t>>& portArrangement,
                  std::vector<std::pair<uint8_t, uint64_t>> rsArrangement);

  /** Allocate the lowest weighted port available for the specified instruction
   * group. Returns the allocated port, and increases the weight of the port.
   */
  uint8_t allocate(const std::vector<uint8_t>& ports) override;

  /** Decrease the weight for the specified port. */
  void issued(uint8_t port) override;

  /** Decrease the weight for the specified port. */
  void deallocate(uint8_t port) override;

  /** Set function from DispatchIssueUnit to retrieve reservation
   * station sizes during execution. */
  void setRSSizeGetter(
      std::function<void(std::vector<uint64_t>&)> rsSizes) override;

  /** Tick the port allocator to allow it to process internal tasks. */
  void tick() override;

 private:
  /** The instruction group support matrix. An instruction-group-indexed map
   * containing lists of the ports that support each instruction group. */
  std::vector<std::vector<uint8_t>> supportMatrix;

  /** The port weighting map. Each element corresponds to a port, and contains a
   * weighting representing the number of in-flight instructions allocated to
   * that port. */
  std::vector<uint16_t> weights;

  std::vector<uint64_t> rsFreeSpaces;

  /** Get the current capacity of the reservation stations */
  std::function<void(std::vector<uint64_t>&)> rsSizes_;

  /** Mapping from port index to reservation station <index, size> */
  std::vector<std::pair<uint8_t, uint64_t>> rsArrangement_;
};

}  // namespace pipeline
}  // namespace simeng
