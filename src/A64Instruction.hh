#pragma once

#include "Instruction.hh"

#include <array>

#include "BranchPredictor.hh"

namespace simeng {

namespace A64RegisterType {
/** The 64-bit general purpose register set: [w|x]0-31. */
const uint8_t GENERAL = 0;
/** The 128+ bit vector register set: v0-31. */
const uint8_t VECTOR = 1;
/** The 4-bit NZCV condition flag register. */
const uint8_t NZCV = 2;
}  // namespace A64RegisterType

/** The decoded metadata for an instruction. Produced during decoding and used
 * during operation - most fields are only used for some instructions. Variable
 * names match those from ARMv8 Reference Manual. Future versions (or
 * automatically generated versions) may use a heavily `union`-ed datastructure
 * to minimise footprint.
 *
 * Potential alternative approach: store the original
 * instruction word and only extract these values during execution? Pros:
 * reduced memory footprint, cleaner; cons: slight performance penalty as values
 * can't be cached during decoding. */
struct A64DecodeMetadata {
  /** Size flag; 0 = 32-bit; 1 = 64-bit. */
  uint8_t sf;
  uint8_t N;
  union {
    /** An unsigned 64-bit immediate. Mutually exclusive with `offset`. */
    uint64_t imm;
    /** A signed 64-bit immediate offset. Mutually exclusive with `imm`. */
    int64_t offset;
  };
  /** Memory: index writeback? */
  bool wback;
  /** Memory: post-index writeback or pre-index writeback? */
  bool postindex;
  /** Scaling mode identifier. Instruction-dependent behaviour. */
  uint8_t scale;
  /** Condition code; identifies condition mode for instructions with
   * conditional behaviour. */
  uint8_t cond;
  /** Bit position; used for bit testing instructions. */
  uint8_t bitPos;
};

enum class A64InstructionException {
  None = 0,
  EncodingUnallocated,
  EncodingNotYetImplemented,
  ExecutionNotYetImplemented
};

/** A64 instruction opcode identifier. */
enum class A64Opcode {
  ADD_I,
  ADDS_I,
  B,
  B_cond,
  LDR_I,
  ORR_I,
  STR_I,
  SUB_Shift,
  SUB_I,
  SUBS_I,
  TBNZ,
};

/** A basic ARMv8-a implementation of the `Instruction` interface. */
class A64Instruction : public Instruction {
 public:
  A64Instruction(){};

  /** Construct an instruction instance by decoding a provided instruction word.
   */
  A64Instruction(uint32_t insn);

  /** Supply an instruction address. Performed after construction to prevent
   * values being cached. */
  void setInstructionAddress(uint64_t address);

  /** Supply a branch prediction. Performed after construction to prevent values
   * being cached. */
  void setBranchPrediction(BranchPrediction prediction);

  /** Retrieve the identifier for the first exception that occurred during
   * decoding or execution. */
  InstructionException getException() const override;

  /** Retrieve the source registers this instruction reads. */
  const span<Register> getOperandRegisters() const override;

  /** Retrieve the destination registers this instruction will write to.
   * A register value of -1 signifies a Zero Register read, and should not be
   * renamed. */
  const span<Register> getDestinationRegisters() const override;

  /** Check whether the operand at index `i` has had a value supplied. */
  bool isOperandReady(int index) const override;

  /** Override the specified source register with a renamed physical register.
   */
  void renameSource(uint8_t i, Register renamed) override;

  /** Override the specified destination register with a renamed physical
   * register. */
  void renameDestination(uint8_t i, Register renamed) override;

  /** Provide a value for the specified physical register. */
  void supplyOperand(const Register& reg, const RegisterValue& value) override;

  /** Check whether all operand values have been supplied, and the instruction
   * is ready to execute. */
  bool canExecute() const override;

  /** Execute the instruction. */
  void execute() override;

  /** Check whether the instruction has executed and has results ready to
   * write back. */
  bool hasExecuted() const override;

  /** Mark the instruction as ready to commit. */
  void setCommitReady() override;

  /** Check whether the instruction has written its values back and is ready to
   * commit. */
  bool canCommit() const override;

  /** Retrieve register results. */
  const span<RegisterValue> getResults() const override;

  /** Generate memory addresses this instruction wishes to access. */
  std::vector<std::pair<uint64_t, uint8_t>> generateAddresses() override;

  /** Retrieve previously generated memory addresses. */
  std::vector<std::pair<uint64_t, uint8_t>> getGeneratedAddresses()
      const override;

  /** Provide data from a requested memory address. */
  void supplyData(uint64_t address, const RegisterValue& data) override;

  /** Retrieve supplied memory data. */
  std::vector<RegisterValue> getData() const override;

  /** Early misprediction check; see if it's possible to determine whether the
   * next instruction address was mispredicted without executing the
   * instruction. */
  std::tuple<bool, uint64_t> checkEarlyBranchMisprediction() const override;

  /** Check for misprediction. */
  bool wasBranchMispredicted() const override;

  /** Was the branch taken? */
  bool wasBranchTaken() const override;

  /** Retrieve branch address. */
  uint64_t getBranchAddress() const override;

  /** Is this a store operation? */
  bool isStore() const override;

  /** Is this a load operation? */
  bool isLoad() const override;

  /** Is this a branch operation? */
  bool isBranch() const override;

  /** Get this instruction's instruction memory address. */
  uint64_t getInstructionAddress() const override;

  /** Set this instruction's sequence ID. */
  void setSequenceId(uint64_t seqId) override;

  /** Retrieve this instruction's sequence ID. */
  uint64_t getSequenceId() const override;

  /** Mark this instruction as flushed. */
  void setFlushed() override;

  /** Check whether this instruction has been flushed. */
  bool isFlushed() const override;

  /** A special register value representing the zero register. If passed to
   * `setSourceRegisters`/`setDestinationRegisters`, the value will be
   * automatically supplied as zero. */
  static const Register ZERO_REGISTER;

 private:
  /** The maximum number of source registers any supported A64 instruction can
   * have. */
  static const size_t MAX_SOURCE_REGISTERS = 4;
  /** The maximum number of destination registers any supported A64 instruction
   * can have. */
  static const size_t MAX_DESTINATION_REGISTERS = 3;

  /** This instruction's opcode. */
  A64Opcode opcode;

  /** The location in memory of this instruction was decoded at. */
  uint64_t instructionAddress;

  /** Metadata for this instruction; used for operation logic */
  A64DecodeMetadata metadata;

  /** An array of source registers. */
  std::array<Register, MAX_SOURCE_REGISTERS> sourceRegisters;
  /** The number of source registers this instruction reads from. */
  size_t sourceRegisterCount = 0;

  /** An array of destination registers. */
  std::array<Register, MAX_DESTINATION_REGISTERS> destinationRegisters;
  /** The number of destination registers this instruction writes to. */
  size_t destinationRegisterCount = 0;

  /** An array of provided operand values. Each entry corresponds to a
   * `sourceRegisters` entry. */
  std::array<RegisterValue, MAX_SOURCE_REGISTERS> operands;

  /** An array of generated output results. Each entry corresponds to a
   * `destinationRegisters` entry. */
  std::array<RegisterValue, MAX_DESTINATION_REGISTERS> results;

  /** The current exception state of this instruction. */
  A64InstructionException exception = A64InstructionException::None;

  // Decoding
  /** Decode the instruction word `encoding` and populate this instruction with
   * the appropriate values. **/
  void decodeA64(uint32_t encoding);

  /** Generate an EncodingNotYetImplemented exception. */
  void nyi();

  /** Generate an EncodingUnallocated exception. */
  void unallocated();

  /** Decode an instruction under the "Data Processing - Immediate" category. */
  void decodeA64DataImmediate(uint32_t insn);

  /** Decode an instruction under the "Branches, Exception Generating and System
   * instructions" category. */
  void decodeA64BranchSystem(uint32_t insn);

  /** Decode an instruction under the "Loads and Stores" category. */
  void decodeA64LoadStore(uint32_t insn);

  /** Decode an instruction under the "Data Processing - Register" category. */
  void decodeA64DataRegister(uint32_t insn);

  /** Decode an instruction under the "Data Processing - Scalar Floating-Point
   * and Advanced SIMD" category. */
  void decodeA64DataFPSIMD(uint32_t insn);

  /** Set the source registers of the instruction, and create a corresponding
   * operands vector. Zero register references will be pre-supplied with a value
   * of 0. */
  void setSourceRegisters(const std::vector<Register>& registers);

  /** Set the destination registers for the instruction, and create a
   * corresponding results vector. */
  void setDestinationRegisters(const std::vector<Register>& registers);

  // Scheduling
  /** The number of operands that have not yet had values supplied. Used to
   * determine execution readiness. */
  short operandsPending = 0;

  /** Whether or not this instruction has been executed. */
  bool executed = false;

  /** Whether or not this instruction is ready to commit. */
  bool canCommit_ = false;

  // Metadata
  /** Is this a store operation? */
  bool isStore_ = false;
  /** Is this a load operation? */
  bool isLoad_ = false;
  /** Is this a branch operation? */
  bool isBranch_ = false;

  // Memory
  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(
      const std::vector<std::pair<uint64_t, uint8_t>>& addresses);

  /** The memory addresses this instruction accesses, as a vector of {offset,
   * width} pairs. */
  std::vector<std::pair<uint64_t, uint8_t>> memoryAddresses;

  /** A vector of memory values, that were either loaded memory, or are prepared
   * for sending to memory (according to instruction type). Each entry
   * corresponds to a `memoryAddresses` entry. */
  std::vector<RegisterValue> memoryData;

  // Branches
  /** The predicted branching result. */
  BranchPrediction prediction;
  /** A branching address calculated by this instruction during execution. */
  uint64_t branchAddress;
  /** Was the branch taken? */
  bool branchTaken;

  /** This instruction's sequence ID; a higher ID represents a chronologically
   * newer instruction. */
  uint64_t sequenceId;

  /** Has this instruction been flushed? */
  bool flushed = false;
};

}  // namespace simeng
