#pragma once

#include "Instruction.hh"
#include "gmock/gmock.h"

namespace simeng {

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

  // /** Provide data from a requested memory address. */
  // virtual void supplyData(uint64_t address, const RegisterValue& data) = 0;

  // /** Retrieve previously generated memory addresses. */
  // virtual std::vector<std::pair<uint64_t, uint8_t>> getGeneratedAddresses()
  //     const = 0;

  // /** Retrieve supplied memory data. */
  // virtual std::vector<RegisterValue> getData() const = 0;

  // /** Early misprediction check; see if it's possible to determine whether
  // the
  //  * next instruction address was mispredicted without executing the
  //  * instruction. Returns a {mispredicted, target} tuple representing whether
  //  * the instruction was mispredicted, and the correct target address. */

  // /** Check for misprediction. */
  // virtual bool wasBranchMispredicted() const = 0;

  // /** Retrieve branch address. */
  // virtual uint64_t getBranchAddress() const = 0;

  // /** Was the branch taken? */
  // virtual bool wasBranchTaken() const = 0;

  // /** Is this a store operation? */
  // virtual bool isStore() const = 0;

  // /** Is this a load operation? */
  // virtual bool isLoad() const = 0;

  // /** Is this a branch operation? */
  // virtual bool isBranch() const = 0;

  // /** Get this instruction's instruction memory address. */

  // /** Set this instruction's sequence ID. */
  // virtual void setSequenceId(uint64_t seqId) = 0;

  // /** Retrieve this instruction's sequence ID. */
  // virtual uint64_t getSequenceId() const = 0;

  // /** Mark this instruction as flushed. */
  // virtual void setFlushed() = 0;

  // /** Check whether this instruction has been flushed. */
  // virtual bool isFlushed() const = 0;
};

}  // namespace simeng
