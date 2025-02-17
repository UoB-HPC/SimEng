#pragma once

#include "gmock/gmock.h"
#include "simeng/pipeline/PortAllocator.hh"

namespace simeng {
namespace pipeline {

/** Mock implementation of the `PortAllocator` interface. */
class MockPortAllocator : public pipeline::PortAllocator {
 public:
  MOCK_METHOD1(allocate, uint16_t(const std::vector<uint16_t>& ports));
  MOCK_METHOD1(issued, void(uint16_t port));
  MOCK_METHOD1(deallocate, void(uint16_t port));
  MOCK_METHOD1(setRSSizeGetter,
               void(std::function<void(std::vector<uint32_t>&)> rsSizes));
  MOCK_METHOD0(tick, void());
};

}  // namespace pipeline
}  // namespace simeng
