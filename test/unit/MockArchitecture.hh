#pragma once

#include "Architecture.hh"
#include "gmock/gmock.h"

namespace simeng {

/** Mock implementation of the `Architecture` interface. */
class MockArchitecture : public Architecture {
 public:
  MOCK_CONST_METHOD5(predecode,
                     uint8_t(const void* ptr, uint8_t bytesAvailable,
                             uint64_t instructionAddress,
                             BranchPrediction prediction, MacroOp& output));
  MOCK_CONST_METHOD0(getRegisterFileStructures,
                     std::vector<RegisterFileStructure>());
  MOCK_CONST_METHOD1(canRename, bool(Register reg));
  MOCK_CONST_METHOD1(handleException,
                     void(const std::shared_ptr<Instruction>& instruction));
};

}  // namespace simeng
