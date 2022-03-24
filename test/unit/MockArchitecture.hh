#pragma once

#include "gmock/gmock.h"
#include "simeng/arch/Architecture.hh"

namespace simeng {

/** Mock implementation of the `Architecture` interface. */
class MockArchitecture : public arch::Architecture {
 public:
  MOCK_CONST_METHOD5(predecode,
                     uint8_t(const void* ptr, uint8_t bytesAvailable,
                             uint64_t instructionAddress,
                             BranchPrediction prediction, MacroOp& output));
  MOCK_CONST_METHOD0(getRegisterFileStructures,
                     std::vector<RegisterFileStructure>());
  MOCK_CONST_METHOD1(canRename, bool(Register reg));
  MOCK_CONST_METHOD1(getSystemRegisterTag, uint16_t(uint16_t reg));
  MOCK_CONST_METHOD3(handleException,
                     std::shared_ptr<arch::ExceptionHandler>(
                         const std::shared_ptr<Instruction>& instruction,
                         const Core& core, MemoryInterface& memory));
  MOCK_CONST_METHOD0(getInitialState, arch::ProcessStateChange());
  MOCK_CONST_METHOD0(getMaxInstructionSize, uint8_t());
  MOCK_CONST_METHOD1(updateCounterTimer,
                     arch::ProcessStateChange(uint64_t iterations));
};

}  // namespace simeng
