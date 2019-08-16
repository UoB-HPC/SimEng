#pragma once

#include "gmock/gmock.h"
#include "simeng/MemoryInterface.hh"

namespace simeng {

/** Mock implementation of MemoryInterface */
class MockMemoryInterface : public MemoryInterface {
 public:
  MOCK_METHOD2(requestRead,
               void(const MemoryAccessTarget& target, uint64_t id));

  MOCK_METHOD2(requestWrite, void(const MemoryAccessTarget& target,
                                  const RegisterValue& data));

  MOCK_CONST_METHOD0(getCompletedReads, const span<MemoryReadResult>());

  MOCK_METHOD0(clearCompletedReads, void());

  MOCK_CONST_METHOD0(hasPendingRequests, bool());

  MOCK_METHOD0(tick, void());
};

}  // namespace simeng
