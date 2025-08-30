#pragma once

#include <optional>
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
  /** A unique identifier of an accelerator instance.
   * The value of 0 indicates no accelerator. */
  using accelerator_id_t = uint16_t;

  /** An ID signifying no accelerator
   * (see `simeng::config::OffloadingLogic::instruction_filter`). */
  static constexpr accelerator_id_t NO_ACCELERATOR = 0;

  virtual ~Instruction() {}

  /** Performs a polymorphic deep copy of the object. */
  virtual std::unique_ptr<Instruction> clone() const = 0;

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

  /** Set this instruction's execution information including its execution
   * latency and throughput, and the set of ports which support it. */
  virtual void setExecutionInfo(const ExecutionInfo& info) = 0;

  /** Serializes the instruction, writing into the provided buffer. */
  void serializeInto(std::vector<uint8_t>& buffer) const;

  /** Set this instruction's sequence ID. */
  void setSequenceId(uint64_t seqId);

  /** Retrieve this instruction's sequence ID. */
  uint64_t getSequenceId() const;

  /** Whether this instruction's sequence ID is valid. */
  bool isSequenceIdValid() const;

  /** Set this instruction's instruction ID. */
  void setInstructionId(uint64_t insnId);

  /** Retrieve this instruction's instruction ID. */
  uint64_t getInstructionId() const;

  /** Set this instruction's instruction memory address. */
  void setInstructionAddress(uint64_t address);

  /** Get this instruction's instruction memory address. */
  uint64_t getInstructionAddress() const;

  /** Supply a branch prediction. */
  void setBranchPrediction(BranchPrediction prediction);

  /** Get a branch prediction. */
  BranchPrediction getBranchPrediction() const;

  /** Retrieve branch address. */
  uint64_t getBranchAddress() const;

  /** Was the branch taken? */
  bool wasBranchTaken() const;

  /** Check for misprediction. */
  bool wasBranchMispredicted() const;

  /** Check whether an exception has been encountered while processing this
   * instruction. */
  bool exceptionEncountered() const;

  /** Check whether all required data has been supplied. */
  bool hasAllData() const;

  /** Check whether the instruction has executed and has results ready to
   * write back. */
  bool hasExecuted() const;

  /** Retrieve the number of cycles this instruction will take to execute. */
  uint16_t getLatency() const;

  /** Retrieve the number of cycles this instruction will block the unit
   * executing it. */
  uint16_t getStallCycles() const;

  /** Retrieve the number of cycles this instruction will take to be processed
   * by the LSQ. */
  uint16_t getLSQLatency() const;

  /** Marks this instruction as being offloaded to the specified accelerator.
   * Note that this ID cannot be equal to `Accelerator::NO_ACCELERATOR`. */
  void markOffloaded(accelerator_id_t accelerator);

  /** Marks this instruction as being on the accelerator. */
  void markAccelerated();

  /** Check whether this instruction is ready to be offloaded. */
  virtual bool canBeOffloaded() const;

  /** Returns whether this instruction is being offloaded to an accelerator. */
  bool isOffloaded() const noexcept;

  /** Marks the instruction as waiting for accelerator to commit. */
  void setWaitingAcceleratorCommit() noexcept;

  /** Mark the instruction as commited by the accelerator. */
  void setAcceleratorCommited() noexcept;

  /** Returns whether this instruction is waiting to be commited
   * by the accelerator. */
  bool isWaitingAcceleratorCommit() const noexcept;

  /** Check whether operand at index `i` is only present on an accelerator
   * and should be ignored on the core. */
  bool isRegisterOffloaded(const Register& reg) const;

  /** Moves relevant execution information from `offloadedSrc` into `this`,
   * invalidating `offloadedSrc`.  */
  void moveOffloadedResults(std::shared_ptr<Instruction>& offloadedSrc);

  /** Set the micro-operation in an awaiting commit signal state. */
  void setWaitingCommit();

  /** Is the micro-operation in an awaiting commit state? */
  bool isWaitingCommit() const;

  /** Mark the instruction as ready to commit. */
  void setCommitReady();

  /** Check whether the instruction has written its values back and is ready to
   * commit. */
  bool canCommit() const;

  /** Mark this instruction as flushed. */
  void setFlushed();

  /** Check whether this instruction has been flushed. */
  bool isFlushed() const;

  /** Is this a micro-operation? */
  bool isMicroOp() const;

  /** Is this the last uop in the possible sequence of decoded uops? */
  bool isLastMicroOp() const;

  /** Get arbitrary micro-operation index. */
  int getMicroOpIndex() const;

 protected:
  Instruction() = default;

  /** Deserializes the base instruction from the provided span of bytes. */
  explicit Instruction(span<uint8_t>& serialized);

  /** Moves relevant execution information from `offloadedSrc` into `this`.
   * Implementors are allowed to invalidate data in `offloadedSrc`. */
  virtual void moveOffloadedResultsImpl(
      std::shared_ptr<Instruction>& offloadedSrc) = 0;

  /** Serializes the concrete type into the provided buffer. */
  virtual void serializeIntoImpl(std::vector<uint8_t>& buffer) const = 0;

  /** Copies all data into `dest`
   * (i.e. performs a deep copy of this abstract class). */
  void baseCloneInto(Instruction* dest) const;

  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(
      const std::vector<memory::MemoryAccessTarget>& addresses);

  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(std::vector<memory::MemoryAccessTarget>&& addresses);

  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(memory::MemoryAccessTarget address);

  // Instruction Info
  /** This instruction's instruction ID used to group micro-operations together
   * by macro-op; a higher ID represents a chronologically newer instruction. */
  uint64_t instructionId_ = 0;

  /** This instruction's sequence ID; a higher ID represents a chronologically
   * newer instruction. */
  std::optional<uint64_t> sequenceId_ = std::nullopt;

  /** The location in memory of this instruction was decoded at. */
  uint64_t instructionAddress_ = 0;

  // Offloading
  /** Which accelerator (if any) is this instruction being offloaded to. */
  accelerator_id_t offloaded_ = NO_ACCELERATOR;

  /** Whether the micro-operation in waiting for the accelerator to return
   * results. */
  bool waitingAcceleratorCommit_ = false;

  // Execution
  /** Whether this instruction has been executed. */
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

  /** Whether this instruction is ready to commit. */
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

  /** Whether this instruction is the last uop in the possible sequence
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
