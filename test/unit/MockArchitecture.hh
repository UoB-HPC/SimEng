#pragma once

#include "gmock/gmock.h"
#include "simeng/arch/Architecture.hh"

namespace simeng {

/** Mock implementation of the `Architecture` interface. */
class MockArchitecture : public arch::Architecture {
 public:
  MockArchitecture(kernel::Linux& kernel) : arch::Architecture(kernel) {}
  MOCK_CONST_METHOD4(predecode,
                     uint8_t(const uint8_t* ptr, uint16_t bytesAvailable,
                             uint64_t instructionAddress, MacroOp& output));
  MOCK_CONST_METHOD1(canRename, bool(Register reg));
  MOCK_CONST_METHOD1(getSystemRegisterTag, int32_t(uint16_t reg));
  MOCK_CONST_METHOD3(handleException,
                     std::shared_ptr<arch::ExceptionHandler>(
                         const std::shared_ptr<Instruction>& instruction,
                         const Core& core, memory::MemoryInterface& memory));
  MOCK_CONST_METHOD0(getInitialState, arch::ProcessStateChange());
  MOCK_CONST_METHOD0(getMaxInstructionSize, uint8_t());
  MOCK_CONST_METHOD0(getMinInstructionSize, uint8_t());
  MOCK_CONST_METHOD2(updateSystemTimerRegisters,
                     void(RegisterFileSet* regFile, const uint64_t iterations));
};

}  // namespace simeng
