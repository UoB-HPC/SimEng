#pragma once

#include "MemoryInterface.hh"
#include "gmock/gmock.h"

namespace simeng {

/** Mock implementation of MemoryInterface */
class MockMemoryInterface : public MemoryInterface {
 public:
  MOCK_METHOD1(requestRead, void(const MemoryAccessTarget& target));

  MOCK_METHOD2(requestWrite, void(const MemoryAccessTarget& target,
                                  const RegisterValue& data));

  MOCK_CONST_METHOD0(
      getCompletedReads,
      const span<std::pair<MemoryAccessTarget, RegisterValue>>());

  MOCK_METHOD0(clearCompletedReads, void());
};

}  // namespace simeng
