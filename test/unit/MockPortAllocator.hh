#pragma once

#include "gmock/gmock.h"
#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {
namespace pipeline {

/** Mock implementation of the `PortAllocator` interface. */
class MockPortAllocator : public pipeline::PortAllocator {
 public:
  MOCK_METHOD2(allocate, uint16_t(const std::vector<uint16_t>& ports,
                                  const uint16_t stallCycles));
  MOCK_METHOD2(issued, void(uint16_t port, const uint16_t stallCycles));
  MOCK_METHOD2(deallocate, void(uint16_t port, const uint16_t stallCycles));
  MOCK_METHOD1(setRSSizeGetter,
               void(std::function<void(std::vector<uint32_t>&)> rsSizes));
  MOCK_METHOD0(tick, void());
};

}  // namespace pipeline
}  // namespace simeng
