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
  MOCK_METHOD0(generateAddresses,
               const std::vector<memory::MemoryAccessTarget>&());
  MOCK_METHOD2(supplyData, void(uint64_t address, const RegisterValue& data));
  MOCK_CONST_METHOD0(getGeneratedAddresses,
                     const std::vector<memory::MemoryAccessTarget>&());
  MOCK_CONST_METHOD0(getData, const std::vector<RegisterValue>&());

  MOCK_CONST_METHOD0(checkEarlyBranchMisprediction,
                     std::tuple<bool, uint64_t>());

  MOCK_CONST_METHOD0(isStoreAddress, bool());
  MOCK_CONST_METHOD0(isStoreData, bool());
  MOCK_CONST_METHOD0(isLoad, bool());
  MOCK_CONST_METHOD0(isBranch, bool());
  MOCK_CONST_METHOD0(isAtomic, bool());
  MOCK_CONST_METHOD0(isAcquire, bool());
  MOCK_CONST_METHOD0(isRelease, bool());
  MOCK_CONST_METHOD0(isLoadReserved, bool());
  MOCK_CONST_METHOD0(isStoreCond, bool());
  MOCK_CONST_METHOD0(isPredicate, bool());
  MOCK_CONST_METHOD0(getGroup, uint16_t());

  MOCK_METHOD0(getSupportedPorts, const std::vector<uint16_t>&());

  MOCK_METHOD1(updateCondStoreResult, void(const bool success));

  void setBranchResults(bool wasTaken, uint64_t targetAddress) {
    branchTaken_ = wasTaken;
    branchAddress_ = targetAddress;
  }

  void setExecuted(bool executed) { executed_ = executed; }

  void setExceptionEncountered(bool exceptionEncountered) {
    exceptionEncountered_ = exceptionEncountered;
  }

  void setDataPending(uint8_t value) { dataPending_ = value; }

  void setLatency(uint16_t cycles) { latency_ = cycles; }

  void setStallCycles(uint16_t cycles) { stallCycles_ = cycles; }
};

}  // namespace simeng
