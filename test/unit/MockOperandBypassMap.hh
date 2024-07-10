#pragma once

#include "gmock/gmock.h"
#include "simeng/OperandBypassMap.hh"

namespace simeng {

/** Mock implementation of the `OperandBypassMap` abstract class. */
class MockOperandBypassMap : public OperandBypassMap {
 public:
  MOCK_CONST_METHOD3(getBypassLatency,
                     int64_t(const uint16_t producerGroup,
                             const uint16_t consumerGroup,
                             const span<Register>& producerDestRegs));
};

}  // namespace simeng
