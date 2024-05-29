#pragma once

#include <vector>

#include "simeng/config/SimInfo.hh"
#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {
namespace pipeline {

class CapacityAwarePortAllocator : public PortAllocator {
  struct usageEntry {
    uint16_t slotsUsed_ = 0;
    uint16_t maxSlots_ = 0;
    uint32_t totalStallCycles_ = 0;
    uint16_t maxRate_ = 0;
    // std::vector<uint16_t> portWeightings_;
  };

 public:
  CapacityAwarePortAllocator(
      const std::vector<std::vector<uint16_t>>& portArrangement,
      ryml::ConstNodeRef config = config::SimInfo::getConfig());

  uint16_t allocate(const std::vector<uint16_t>& ports,
                    const uint16_t stallCycles = 0) override;

  void issued(uint16_t port, const uint16_t stallCycles = 0) override;

  void deallocate(uint16_t port, const uint16_t stallCycles = 0) override;

  void setRSSizeGetter(
      std::function<void(std::vector<uint64_t>&)> rsSizes) override;

  /** Tick the port allocator to allow it to process internal tasks. */
  void tick() override;

 private:
  std::vector<uint16_t> supportVector_;

  std::vector<usageEntry> portUsage_;

  std::vector<uint64_t> weights_;

  std::vector<uint16_t> dispatches_;

  std::vector<std::map<uint16_t, uint8_t>> rsPortMappings_;

  std::function<void(std::vector<uint64_t>&)> rsSizes_;

  bool print_ = false;
};

}  // namespace pipeline
}  // namespace simeng
