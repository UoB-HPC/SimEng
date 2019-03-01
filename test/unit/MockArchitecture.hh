#pragma once

#include "Architecture.hh"
#include "gmock/gmock.h"

namespace simeng {

class MockArchitecture : public Architecture {
 public:
  MOCK_CONST_METHOD5(predecode,
                     uint8_t(const void* ptr, uint8_t bytesAvailable,
                             uint64_t instructionAddress,
                             BranchPrediction prediction, MacroOp& output));
  MOCK_CONST_METHOD0(getRegisterFileStructure,
                     std::vector<RegisterFileStructure>());
  MOCK_CONST_METHOD1(canRename, bool(Register reg));
};

}  // namespace simeng
