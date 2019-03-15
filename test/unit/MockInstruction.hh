#pragma once

#include "Instruction.hh"
#include "gmock/gmock.h"

namespace simeng {

/** Mock implementation of the `Instruction` interface. */
class MockInstruction : public Instruction {
 public:
  MOCK_CONST_METHOD0(getException, InstructionException());
  MOCK_CONST_METHOD0(getOperandRegisters, const span<Register>());
  MOCK_CONST_METHOD0(getDestinationRegisters, const span<Register>());
  MOCK_METHOD2(renameSource, void(uint8_t i, Register renamed));
  MOCK_METHOD2(renameDestination, void(uint8_t i, Register renamed));
  MOCK_METHOD2(supplyOperand,
               void(const Register& reg, const RegisterValue& value));
  MOCK_CONST_METHOD1(isOperandReady, bool(int i));
  MOCK_CONST_METHOD0(canExecute, bool());
  MOCK_METHOD0(execute, void());
  MOCK_CONST_METHOD0(hasExecuted, bool());
  MOCK_METHOD0(setCommitReady, void());
  MOCK_CONST_METHOD0(canCommit, bool());
  MOCK_CONST_METHOD0(getResults, const span<RegisterValue>());
  MOCK_METHOD0(generateAddresses, std::vector<std::pair<uint64_t, uint8_t>>());
  MOCK_METHOD2(supplyData, void(uint64_t address, const RegisterValue& data));
  MOCK_CONST_METHOD0(getGeneratedAddresses,
                     std::vector<std::pair<uint64_t, uint8_t>>());
  MOCK_CONST_METHOD0(getData, std::vector<RegisterValue>());

  MOCK_CONST_METHOD0(checkEarlyBranchMisprediction,
                     std::tuple<bool, uint64_t>());

  MOCK_CONST_METHOD0(wasBranchMispredicted, bool());
  MOCK_CONST_METHOD0(getBranchAddress, uint64_t());
  MOCK_CONST_METHOD0(wasBranchTaken, bool());
  MOCK_CONST_METHOD0(isStore, bool());
  MOCK_CONST_METHOD0(isLoad, bool());
  MOCK_CONST_METHOD0(isBranch, bool());
  MOCK_CONST_METHOD0(getInstructionAddress, uint64_t());
  MOCK_METHOD1(setSequenceId, void(uint64_t seqId));
  MOCK_CONST_METHOD0(getSequenceId, uint64_t());
  MOCK_METHOD0(setFlushed, void());
  MOCK_CONST_METHOD0(isFlushed, bool());
  MOCK_CONST_METHOD0(getGroup, uint16_t());
};

}  // namespace simeng
