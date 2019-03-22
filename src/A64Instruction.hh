#pragma once

#include "Instruction.hh"

#include <array>

#include "BranchPredictor.hh"

namespace simeng {

struct A64InstructionMetadata;

namespace A64RegisterType {
/** The 64-bit general purpose register set: [w|x]0-31. */
const uint8_t GENERAL = 0;
/** The 128+ bit vector register set: v0-31. */
const uint8_t VECTOR = 1;
/** The 4-bit NZCV condition flag register. */
const uint8_t NZCV = 2;
}  // namespace A64RegisterType

/** The IDs of the instruction groups for A64 instructions. */
namespace A64InstructionGroups {
const uint8_t ARITHMETIC = 0;
const uint8_t LOAD = 1;
const uint8_t STORE = 2;
const uint8_t BRANCH = 3;
}  // namespace A64InstructionGroups

enum class A64InstructionException {
  None = 0,
  EncodingUnallocated,
  EncodingNotYetImplemented,
  ExecutionNotYetImplemented
};

/** A basic ARMv8-a implementation of the `Instruction` interface. */
class A64Instruction : public Instruction {
 public:
  /** Construct an instruction instance by decoding a provided instruction word.
   */
  A64Instruction(const A64InstructionMetadata& metadata);

  /** Retrieve the identifier for the first exception that occurred during
   * processing this instruction. */
  virtual A64InstructionException getException() const;

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

  /** Is this a store operation? */
  bool isStore() const override;

  /** Is this a load operation? */
  bool isLoad() const override;

  /** Is this a branch operation? */
  bool isBranch() const override;

  /** Retrieve the instruction group this instruction belongs to. */
  uint16_t getGroup() const override;

  /** Retrieve the instruction's metadata. */
  const A64InstructionMetadata& getMetadata() const;

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

  /** A reference to the decoding metadata for this instruction. */
  const A64InstructionMetadata& metadata;

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
  /** Process the instruction's metadata to determine source/destination
   * registers. */
  void decode();

  /** Generate an EncodingNotYetImplemented exception. */
  void nyi();

  /** Generate an EncodingUnallocated exception. */
  void unallocated();

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

  // Execution
  /** Generate an ExecutionNotYetImplemented exception. */
  void executionNYI();

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
};

}  // namespace simeng
