#include "simeng/pipeline/CapacityAwarePortAllocator.hh"

#include <cassert>

namespace simeng {
namespace pipeline {

CapacityAwarePortAllocator::CapacityAwarePortAllocator(
    const std::vector<std::vector<uint16_t>>& portArrangement,
    ryml::ConstNodeRef config) {
  supportVector_.resize(config["Ports"].num_children());
  weights_.resize(config["Ports"].num_children());
  rsPortMappings_.resize(config["Reservation-Stations"].num_children());
  dispatches_.resize(config["Reservation-Stations"].num_children());
  for (uint16_t i = 0; i < config["Reservation-Stations"].num_children(); i++) {
    portUsage_.push_back(
        {.slotsUsed_ = 0,
         .maxSlots_ = config["Reservation-Stations"][i]["Size"].as<uint16_t>(),
         .totalStallCycles_ = 0,
         .maxRate_ = config["Reservation-Stations"][i]["Dispatch-Rate"]
                         .as<uint16_t>()});
    for (uint16_t j = 0;
         j < config["Reservation-Stations"][i]["Port-Nums"].num_children();
         j++) {
      uint16_t portNum =
          config["Reservation-Stations"][i]["Port-Nums"][j].as<uint16_t>();
      supportVector_[portNum] = i;
      rsPortMappings_[i][portNum] = j;
    }
  }
}

uint16_t CapacityAwarePortAllocator::allocate(
    const std::vector<uint16_t>& ports, const uint16_t stallCycles) {
  assert(ports.size() &&
         "No supported ports supplied; cannot allocate from a empty set");
  uint16_t largestSpace = 0;
  uint32_t smallestStallCycles = 0xFFFFFFFF;
  uint16_t bestRS = supportVector_[ports[0]];
  uint16_t bestPort = ports[0];
  uint64_t lowestWeight = 0xFFFFFFFFFFFFFFFF;
  if (print_) std::cerr << "Had";
  // Select RSs with free entries
  std::vector<std::pair<uint16_t, uint16_t>> freeRSs = {};
  for (const auto& portIndex : ports) {
    uint16_t rs = supportVector_[portIndex];
    if (print_) {
      std::cerr << "\tIDX:" << portIndex << " (" << rs
                << ") CAPACITY:" << portUsage_[rs].slotsUsed_ << "/"
                << portUsage_[rs].maxSlots_
                << " TOTAL_STALL_CYCLES:" << portUsage_[rs].totalStallCycles_
                << std::endl;
    }
    if ((portUsage_[rs].maxSlots_ - portUsage_[rs].slotsUsed_) > 0 &&
        dispatches_[rs] < portUsage_[rs].maxRate_)
      freeRSs.push_back({rs, portIndex});
  }

  // Preference for RSs with lowest cumulative cycle counts
  // On a tie, choose RS with more free entries
  // On a tie, choose port used least recently
  for (const auto& rspt : freeRSs) {
    uint16_t rs = rspt.first;
    uint16_t portIndex = rspt.second;
    uint16_t entryDiff = portUsage_[rs].maxSlots_ - portUsage_[rs].slotsUsed_;
    uint32_t totalStallCycles = portUsage_[rs].totalStallCycles_;
    if (totalStallCycles < smallestStallCycles) {
      smallestStallCycles = totalStallCycles;
      largestSpace = entryDiff;
      bestRS = rs;
      bestPort = portIndex;
      lowestWeight = weights_[portIndex];
    } else if (totalStallCycles == smallestStallCycles) {
      if (entryDiff > largestSpace) {
        largestSpace = entryDiff;
        bestRS = rs;
        bestPort = portIndex;
        lowestWeight = weights_[portIndex];
      } else if (entryDiff == largestSpace) {
        if (weights_[portIndex] < lowestWeight) {
          bestRS = rs;
          bestPort = portIndex;
          lowestWeight = weights_[portIndex];
        }
      }
    }
  }

  if (print_) {
    std::cerr << "\tWith weights: ";
    for (const auto& wgh : weights_) {
      std::cerr << wgh << ", ";
    }
    std::cerr << "]" << std::endl;
  }

  // Choose port in chosen RS
  // uint64_t lowestWeight = 0xFFFFFFFFFFFFFFFF;
  // for (const auto& portIndex : ports) {
  //   uint16_t rs = supportVector_[portIndex];
  //   if (rs == bestRS) {
  //     if (weights_[portIndex] < lowestWeight) {
  //       lowestWeight = weights_[portIndex];
  //       bestPort = portIndex;
  //     }
  //   }
  // }

  // Increment the weight of the allocated port
  portUsage_[bestRS].slotsUsed_++;
  portUsage_[bestRS].totalStallCycles_ += stallCycles;
  dispatches_[bestRS]++;
  weights_[bestPort]++;

  if (print_) {
    std::cerr << "\tChose " << bestPort << " with lowestWeight=" << lowestWeight
              << " with totalStallCycles=" << smallestStallCycles
              << " and largestSpace=" << largestSpace
              << " left IDX:" << bestPort << " (" << bestRS
              << ") CAPACITY:" << portUsage_[bestRS].slotsUsed_ << "/"
              << portUsage_[bestRS].maxSlots_
              << " TOTAL_STALL_CYCLES:" << portUsage_[bestRS].totalStallCycles_
              << std::endl;
  }
  return bestPort;
}

void CapacityAwarePortAllocator::issued(uint16_t port,
                                        const uint16_t stallCycles) {
  uint16_t rs = supportVector_[port];
  assert(portUsage_[rs].slotsUsed_ > 0);
  assert(portUsage_[rs].totalStallCycles_ > stallCycles);
  portUsage_[rs].slotsUsed_--;
  portUsage_[rs].totalStallCycles_ -= stallCycles;
  // portUsage_[rs].portWeightings_[rsPortMappings_[rs][port]]--;
  // weights_[port]--;
  if (print_) std::cerr << "Issued " << port << std::endl;
}
void CapacityAwarePortAllocator::deallocate(uint16_t port,
                                            const uint16_t stallCycles) {
  weights_[port]--;
  issued(port, stallCycles);
};

void CapacityAwarePortAllocator::setRSSizeGetter(
    std::function<void(std::vector<uint64_t>&)> rsSizes) {
  rsSizes_ = rsSizes;
}

void CapacityAwarePortAllocator::tick() {
  if (print_) std::cerr << " ============ " << std::endl;
  for (auto& dp : dispatches_) dp = 0;
}

}  // namespace pipeline
}  // namespace simeng
