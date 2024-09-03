#pragma once

#include <vector>

#include "capstone/capstone.h"
#include "simeng/Register.hh"
#include "simeng/RegisterValue.hh"
#include "simeng/branchpredictors/BranchPrediction.hh"
#include "simeng/memory/MemoryInterface.hh"
#include "simeng/span.hh"

using InstructionException = short;

namespace simeng {

/** A struct holding user-defined execution information for an instruction. */
struct ExecutionInfo {
  /** The latency for the instruction. */
  uint16_t latency = 1;

  /** The execution throughput for the instruction. */
  uint16_t stallCycles = 1;

  /** The ports that support the instruction. */
  std::vector<uint16_t> ports = {};
};

/** An abstract instruction definition.
 * Each supported ISA should provide a derived implementation of this class. */
class Instruction {
 public:
  virtual ~Instruction(){};

  /** Retrieve the source registers this instruction reads. */
  virtual const span<Register> getSourceRegisters() const = 0;

  /** Retrieve the data contained in the source registers this instruction
   * reads.*/
  virtual const span<RegisterValue> getSourceOperands() const = 0;

  /** Retrieve the destination registers this instruction will write to.
   * A register value of -1 signifies a Zero Register read, and should not be
   * renamed. */
  virtual const span<Register> getDestinationRegisters() const = 0;

  /** Override the specified source register with a renamed physical register.
   */
  virtual void renameSource(uint16_t i, Register renamed) = 0;

  /** Override the specified destination register with a renamed physical
   * register. */
  virtual void renameDestination(uint16_t i, Register renamed) = 0;

  /** Provide a value for the operand at the specified index. */
  virtual void supplyOperand(uint16_t i, const RegisterValue& value) = 0;

  /** Check whether the operand at index `i` has had a value supplied. */
  virtual bool isOperandReady(int i) const = 0;

  /** Retrieve register results. */
  virtual const span<RegisterValue> getResults() const = 0;

  /** Generate memory addresses this instruction wishes to access. */
  virtual span<const memory::MemoryAccessTarget> generateAddresses() = 0;

  /** Retrieve previously generated memory addresses. */
  virtual span<const memory::MemoryAccessTarget> getGeneratedAddresses()
      const = 0;

  /** Provide data from a requested memory address. */
  virtual void supplyData(uint64_t address, const RegisterValue& data) = 0;

  /** Retrieve supplied memory data. */
  virtual span<const RegisterValue> getData() const = 0;

  /** Early misprediction check; see if it's possible to determine whether the
   * next instruction address was mispredicted without executing the
   * instruction. Returns a {mispredicted, target} tuple representing whether
   * the instruction was mispredicted, and the correct target address. */
  virtual std::tuple<bool, uint64_t> checkEarlyBranchMisprediction() const = 0;

  /** Retrieve branch type. */
  virtual BranchType getBranchType() const = 0;

  /** Retrieve a branch offset from the instruction's metadata if known. */
  virtual int64_t getKnownOffset() const = 0;

  /** Is this a store address operation (a subcategory of store operations which
   * deal with the generation of store addresses to store data at)? */
  virtual bool isStoreAddress() const = 0;

  /** Is this a store data operation (a subcategory of store operations which
   * deal with the supply of data to be stored)? */
  virtual bool isStoreData() const = 0;

  /** Is this a load operation? */
  virtual bool isLoad() const = 0;

  /** Is this a branch operation? */
  virtual bool isBranch() const = 0;

  /** Retrieve the instruction group this instruction belongs to. */
  virtual uint16_t getGroup() const = 0;

  /** Check whether all operand values have been supplied, and the instruction
   * is ready to execute. */
  virtual bool canExecute() const = 0;

  /** Execute the instruction. */
  virtual void execute() = 0;

  /** Get this instruction's supported set of ports. */
  virtual const std::vector<uint16_t>& getSupportedPorts() = 0;

  /** Set this instruction's execution information including it's execution
   * latency and throughput, and the set of ports which support it. */
  virtual void setExecutionInfo(const ExecutionInfo& info) = 0;

  /** Set this instruction's sequence ID. */
  void setSequenceId(uint64_t seqId) { sequenceId_ = seqId; }

  /** Retrieve this instruction's sequence ID. */
  uint64_t getSequenceId() const { return sequenceId_; }

  /** Set this instruction's instruction ID. */
  void setInstructionId(uint64_t insnId) { instructionId_ = insnId; }

  /** Retrieve this instruction's instruction ID. */
  uint64_t getInstructionId() const { return instructionId_; }

  /** Set this instruction's instruction memory address. */
  void setInstructionAddress(uint64_t address) {
    instructionAddress_ = address;
  }

  /** Get this instruction's instruction memory address. */
  uint64_t getInstructionAddress() const { return instructionAddress_; }

  /** Supply a branch prediction. */
  void setBranchPrediction(BranchPrediction prediction) {
    prediction_ = prediction;
  }

  /** Get a branch prediction. */
  BranchPrediction getBranchPrediction() const { return prediction_; }

  /** Retrieve branch address. */
  uint64_t getBranchAddress() const { return branchAddress_; }

  /** Was the branch taken? */
  bool wasBranchTaken() const { return branchTaken_; }

  /** Check for misprediction. */
  bool wasBranchMispredicted() const {
    assert(executed_ &&
           "Branch misprediction check requires instruction to have executed");
    // Flag as mispredicted if taken state was wrongly predicted, or taken
    // and predicted target is wrong
    return ((branchTaken_ != prediction_.isTaken) ||
            (prediction_.target != branchAddress_));
  }

  /** Check whether an exception has been encountered while processing this
   * instruction. */
  bool exceptionEncountered() const { return exceptionEncountered_; }

  /** Check whether all required data has been supplied. */
  bool hasAllData() const { return (dataPending_ == 0); }

  /** Check whether the instruction has executed and has results ready to
   * write back. */
  bool hasExecuted() const { return executed_; }

  /** Retrieve the number of cycles this instruction will take to execute. */
  uint16_t getLatency() const { return latency_; }

  /** Retrieve the number of cycles this instruction will block the unit
   * executing it. */
  uint16_t getStallCycles() const { return stallCycles_; }

  /** Retrieve the number of cycles this instruction will take to be processed
   * by the LSQ. */
  uint16_t getLSQLatency() const { return lsqExecutionLatency_; }

  /** Set the micro-operation in an awaiting commit signal state. */
  void setWaitingCommit() { waitingCommit_ = true; }

  /** Is the micro-operation in an awaiting commit state? */
  bool isWaitingCommit() const { return waitingCommit_; }

  /** Mark the instruction as ready to commit. */
  void setCommitReady() { canCommit_ = true; }

  /** Check whether the instruction has written its values back and is ready to
   * commit. */
  bool canCommit() const { return canCommit_; }

  /** Mark this instruction as flushed. */
  void setFlushed() { flushed_ = true; }

  /** Check whether this instruction has been flushed. */
  bool isFlushed() const { return flushed_; }

  /** Is this a micro-operation? */
  bool isMicroOp() const { return isMicroOp_; }

  /** Is this the last uop in the possible sequence of decoded uops? */
  bool isLastMicroOp() const { return isLastMicroOp_; }

  /** Get arbitrary micro-operation index. */
  int getMicroOpIndex() const { return microOpIndex_; }

 protected:
  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(
      const std::vector<memory::MemoryAccessTarget>& addresses) {
    memoryData_.resize(addresses.size());
    memoryAddresses_ = addresses;
    dataPending_ = addresses.size();
  }

  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(std::vector<memory::MemoryAccessTarget>&& addresses) {
    dataPending_ = addresses.size();
    memoryData_.resize(addresses.size());
    memoryAddresses_ = std::move(addresses);
  }

  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(memory::MemoryAccessTarget address) {
    dataPending_ = 1;
    memoryData_.resize(1);
    memoryAddresses_.push_back(address);
  }

  // Instruction Info
  /** This instruction's instruction ID used to group micro-operations together
   * by macro-op; a higher ID represents a chronologically newer instruction. */
  uint64_t instructionId_ = 0;

  /** This instruction's sequence ID; a higher ID represents a chronologically
   * newer instruction. */
  uint64_t sequenceId_ = 0;

  /** The location in memory of this instruction was decoded at. */
  uint64_t instructionAddress_ = 0;

  // Execution
  /** Whether or not this instruction has been executed. */
  bool executed_ = false;

  /** The number of cycles this instruction takes to execute. */
  uint16_t latency_ = 1;

  /** The number of cycles a load or store instruction takes to execute within
   * the load/store queue. */
  uint16_t lsqExecutionLatency_ = 1;

  /** The number of cycles this instruction will stall the unit executing it
   * for. */
  uint16_t stallCycles_ = 1;

  /** The execution ports that this instruction can be issued to. */
  std::vector<uint16_t> supportedPorts_ = {};

  /** Whether or not this instruction is ready to commit. */
  bool canCommit_ = false;

  // Memory
  /** The memory addresses this instruction accesses, as a vector of {offset,
   * width} pairs. */
  std::vector<memory::MemoryAccessTarget> memoryAddresses_;

  /** A vector of memory values, that were either loaded memory, or are prepared
   * for sending to memory (according to instruction type). Each entry
   * corresponds to a `memoryAddresses` entry. */
  std::vector<RegisterValue> memoryData_;

  /** The number of data items that still need to be supplied. */
  uint8_t dataPending_ = 0;

  // Branches
  /** The predicted branching result. */
  BranchPrediction prediction_ = {false, 0};

  /** A branching address calculated by this instruction during execution. */
  uint64_t branchAddress_ = 0;

  /** Was the branch taken? */
  bool branchTaken_ = false;

  /** What type of branch this instruction is. */
  BranchType branchType_ = BranchType::Unknown;

  /** The branch offset that may be known at the time of instruction decoding.
   * The default value of 0 represents an unknown branch offset.*/
  int64_t knownOffset_ = 0;

  // Flushing
  /** Has this instruction been flushed? */
  bool flushed_ = false;

  /** Whether an exception has been encountered. */
  bool exceptionEncountered_ = false;

  // Micro operations
  /** Is a resultant micro-operation from an instruction split? */
  bool isMicroOp_ = false;

  /** Whether or not this instruction is the last uop in the possible sequence
   * of decoded uops. Default case is that it is. */
  bool isLastMicroOp_ = true;

  /** Is the micro-operation in a committable state but must wait for all
   * associated micro-operations to also be committable? */
  bool waitingCommit_ = false;

  /** An arbitrary index value for the micro-operation. Its use is based on the
   * implementation of specific micro-operations. */
  int microOpIndex_ = 0;
};

}  // namespace simeng