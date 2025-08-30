#pragma once

#include "gmock/gmock.h"
#include "simeng/Instruction.hh"

namespace simeng {

/** Mock implementation of the `Instruction` interface. */
class MockInstruction final : public Instruction {
 public:
  MOCK_CONST_METHOD0(getSourceRegisters, const span<Register>());
  MOCK_CONST_METHOD0(getSourceOperands, const span<RegisterValue>());
  MOCK_CONST_METHOD0(getDestinationRegisters, const span<Register>());
  MOCK_METHOD2(renameSource, void(uint16_t i, Register renamed));
  MOCK_METHOD2(renameDestination, void(uint16_t i, Register renamed));
  MOCK_METHOD2(supplyOperand, void(uint16_t i, const RegisterValue& value));
  MOCK_CONST_METHOD1(isOperandReady, bool(int i));
  MOCK_CONST_METHOD0(canExecute, bool());
  MOCK_METHOD0(execute, void());
  MOCK_CONST_METHOD0(getResults, const span<RegisterValue>());
  MOCK_METHOD0(generateAddresses, span<const memory::MemoryAccessTarget>());
  MOCK_METHOD2(supplyData, void(uint64_t address, const RegisterValue& data));
  MOCK_CONST_METHOD0(getGeneratedAddresses,
                     span<const memory::MemoryAccessTarget>());
  MOCK_CONST_METHOD0(hasAllData, bool());
  MOCK_CONST_METHOD0(getData, span<const RegisterValue>());

  MOCK_CONST_METHOD0(checkEarlyBranchMisprediction,
                     std::tuple<bool, uint64_t>());
  MOCK_CONST_METHOD0(getBranchType, BranchType());
  MOCK_CONST_METHOD0(getKnownOffset, int64_t());

  MOCK_CONST_METHOD0(isStoreAddress, bool());
  MOCK_CONST_METHOD0(isStoreData, bool());
  MOCK_CONST_METHOD0(isLoad, bool());
  MOCK_CONST_METHOD0(isBranch, bool());
  MOCK_CONST_METHOD0(getGroup, uint16_t());

  MOCK_CONST_METHOD0(getLSQLatency, uint16_t());

  MOCK_METHOD0(getSupportedPorts, const std::vector<uint16_t>&());

  MOCK_METHOD1(setExecutionInfo, void(const ExecutionInfo& info));

  std::unique_ptr<Instruction> clone() const override {
    auto clone = std::make_unique<MockInstruction>();
    baseCloneInto(clone.get());
    return clone;
  }

  void serializeIntoImpl(std::vector<uint8_t>& buffer) const override {
    assert(false && "Unimplemented");
  }

  void moveOffloadedResultsImpl(
      std::shared_ptr<Instruction>& offloadedSrc) override {}

  bool canBeOffloaded() const override { return false; }

  void setBranchResults(const bool wasTaken, const uint64_t targetAddress) {
    branchTaken_ = wasTaken;
    branchAddress_ = targetAddress;
  }

  void setExecuted(const bool executed) { executed_ = executed; }

  void setExceptionEncountered(const bool exceptionEncountered) {
    exceptionEncountered_ = exceptionEncountered;
  }

  void setDataPending(const uint8_t value) { dataPending_ = value; }

  void setLatency(const uint16_t cycles) { latency_ = cycles; }

  void setLSQLatency(const uint16_t cycles) { lsqExecutionLatency_ = cycles; }

  void setStallCycles(const uint16_t cycles) { stallCycles_ = cycles; }

  void setIsMicroOp(const bool isMicroOp) { isMicroOp_ = isMicroOp; }

  void setIsLastMicroOp(const bool isLastOp) { isLastMicroOp_ = isLastOp; }
};

}  // namespace simeng
