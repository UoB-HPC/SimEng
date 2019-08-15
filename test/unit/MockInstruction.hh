#pragma once

#include "gmock/gmock.h"
#include "simeng/Instruction.hh"

namespace simeng {

/** Mock implementation of the `Instruction` interface. */
class MockInstruction : public Instruction {
 public:
  MOCK_CONST_METHOD0(getException, InstructionException());
  MOCK_CONST_METHOD0(getOperandRegisters, const span<Register>());
  MOCK_CONST_METHOD0(getDestinationRegisters, const span<Register>());
  MOCK_METHOD2(renameSource, void(uint8_t i, Register renamed));
  MOCK_METHOD2(renameDestination, void(uint8_t i, Register renamed));
  MOCK_METHOD2(supplyOperand, void(uint8_t i, const RegisterValue& value));
  MOCK_CONST_METHOD1(isOperandReady, bool(int i));
  MOCK_CONST_METHOD0(canExecute, bool());
  MOCK_METHOD0(execute, void());
  MOCK_CONST_METHOD0(getResults, const span<RegisterValue>());
  MOCK_METHOD0(generateAddresses, span<const MemoryAccessTarget>());
  MOCK_METHOD2(supplyData, void(uint64_t address, const RegisterValue& data));
  MOCK_CONST_METHOD0(getGeneratedAddresses, span<const MemoryAccessTarget>());
  MOCK_CONST_METHOD0(getData, span<const RegisterValue>());

  MOCK_CONST_METHOD0(checkEarlyBranchMisprediction,
                     std::tuple<bool, uint64_t>());

  MOCK_CONST_METHOD0(isStore, bool());
  MOCK_CONST_METHOD0(isLoad, bool());
  MOCK_CONST_METHOD0(isBranch, bool());
  MOCK_CONST_METHOD0(getGroup, uint16_t());

  void setBranchResults(bool wasTaken, uint64_t targetAddress) {
    branchTaken_ = wasTaken;
    branchAddress_ = targetAddress;
  }

  void setExecuted(bool executed) { executed_ = executed; }

  void setExceptionEncountered(bool exceptionEncountered) {
    exceptionEncountered_ = exceptionEncountered;
  }

  void setDataPending(uint8_t value) { dataPending_ = value; }
};

}  // namespace simeng
