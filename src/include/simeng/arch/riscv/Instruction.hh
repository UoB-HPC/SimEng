#pragma once

#include <array>
#include <cfenv>
#include <functional>
#include <unordered_map>

#include "simeng/Instruction.hh"
#include "simeng/arch/riscv/InstructionGroups.hh"
#include "simeng/branchpredictors/BranchPredictor.hh"

namespace simeng {
namespace arch {
namespace riscv {

class Architecture;
struct InstructionMetadata;

namespace RegisterType {
/** The 64-bit general purpose register set. */
const uint8_t GENERAL = 0;
/** The 64-bit bit floating point register set. */
const uint8_t FLOAT = 1;
/** The system registers. */
const uint8_t SYSTEM = 2;

/** A special register value representing the zero register. */
const Register ZERO_REGISTER = {GENERAL, (uint16_t)0};
}  // namespace RegisterType

/** The various exceptions that can be raised by an individual instruction. */
enum class InstructionException {
  None = 0,
  EncodingUnallocated,
  ExecutionNotYetImplemented,
  AliasNotYetImplemented,
  MisalignedPC,
  DataAbort,
  SupervisorCall,
  HypervisorCall,
  SecureMonitorCall,
  NoAvailablePort,
  IllegalInstruction,
  PipelineFlush
};

// RISC-V Instruction Identifier Masks
enum class InsnType : uint16_t {
  /** Is this a store operation? */
  isStore = 1 << 0,
  /** Is this a load operation? */
  isLoad = 1 << 1,
  /** Is this a branch operation? */
  isBranch = 1 << 2,
  /** Is this a multiply operation? */
  isMultiply = 1 << 3,
  /** Is this a divide operation? */
  isDivide = 1 << 4,
  /** Is this a shift operation? */
  isShift = 1 << 5,
  /** Is this an atomic instruction? */
  isAtomic = 1 << 6,
  /** Is this a logical instruction? */
  isLogical = 1 << 7,
  /** Is this a compare instruction? */
  isCompare = 1 << 8,
  /** Is this a floating point operation? */
  isFloat = 1 << 9,
  /** Is this a floating point <-> integer convert operation? */
  isConvert = 1 << 10,
};

/** The maximum number of source registers any supported RISC-V instruction
 * can have. */
const uint8_t MAX_SOURCE_REGISTERS = 3;

/** The maximum number of destination registers any supported RISC-V
 * instruction can have. */
const uint8_t MAX_DESTINATION_REGISTERS = 1;

/** A basic RISC-V implementation of the `Instruction` interface. */
class Instruction : public simeng::Instruction {
 public:
  /** Construct an instruction instance by decoding a provided instruction word.
   */
  Instruction(const Architecture& architecture,
              const InstructionMetadata& metadata);

  /** Construct an instruction instance that raises an exception. */
  Instruction(const Architecture& architecture,
              const InstructionMetadata& metadata,
              InstructionException exception);

  /** Retrieve the source registers this instruction reads. */
  const span<Register> getSourceRegisters() const override;

  /** Retrieve the data contained in the source registers this instruction
   * reads.*/
  const span<RegisterValue> getSourceOperands() const override;

  /** Retrieve the destination registers this instruction will write to.
   * A register value of -1 signifies a Zero Register read, and should not be
   * renamed. */
  const span<Register> getDestinationRegisters() const override;

  /** Override the specified source register with a renamed physical register.
   */
  void renameSource(uint16_t i, Register renamed) override;

  /** Override the specified destination register with a renamed physical
   * register. */
  void renameDestination(uint16_t i, Register renamed) override;

  /** Provide a value for the operand at the specified index. */
  void supplyOperand(uint16_t i, const RegisterValue& value) override;

  /** Check whether the operand at index `i` has had a value supplied. */
  bool isOperandReady(int index) const override;

  /** Retrieve register results. */
  const span<RegisterValue> getResults() const override;

  /** Generate memory addresses this instruction wishes to access. */
  span<const memory::MemoryAccessTarget> generateAddresses() override;

  /** Retrieve previously generated memory addresses. */
  span<const memory::MemoryAccessTarget> getGeneratedAddresses() const override;

  /** Provide data from a requested memory address. */
  void supplyData(uint64_t address, const RegisterValue& data) override;

  /** Retrieve supplied memory data. */
  span<const RegisterValue> getData() const override;

  /** Early misprediction check; see if it's possible to determine whether the
   * next instruction address was mispredicted without executing the
   * instruction. Returns a {mispredicted, target} tuple representing whether
   * the instruction was mispredicted, and the correct target address. */
  std::tuple<bool, uint64_t> checkEarlyBranchMisprediction() const override;

  /** Retrieve branch type. */
  BranchType getBranchType() const override;

  /** Retrieve a branch offset from the instruction's metadata if known. */
  int64_t getKnownOffset() const override;

  /** Is this a store address operation (a subcategory of store operations which
   * deal with the generation of store addresses to store data at)? */
  bool isStoreAddress() const override;

  /** Is this a store data operation (a subcategory of store operations which
   * deal with the supply of data to be stored)? */
  bool isStoreData() const override;

  /** Is this a load operation? */
  bool isLoad() const override;

  /** Is this a branch operation? */
  bool isBranch() const override;

  /** Retrieve the instruction group this instruction belongs to. */
  uint16_t getGroup() const override;

  /** Check whether all operand values have been supplied, and the instruction
   * is ready to execute. */
  bool canExecute() const override;

  /** Execute the instruction. */
  void execute() override;

  /** Get this instruction's supported set of ports. */
  const std::vector<uint16_t>& getSupportedPorts() override;

  /** Set this instruction's execution information including it's execution
   * latency and throughput, and the set of ports which support it. */
  void setExecutionInfo(const ExecutionInfo& info) override;

  /** Retrieve the instruction's metadata. */
  const InstructionMetadata& getMetadata() const;

  /** Retrieve the instruction's associated architecture. */
  const Architecture& getArchitecture() const;

  /** Retrieve the identifier for the first exception that occurred during
   * processing this instruction. */
  InstructionException getException() const;

 private:
  /** Process the instruction's metadata to determine source/destination
   * registers. */
  void decode();

  /** Update the instruction's identifier with an additional field. */
  constexpr void setInstructionType(InsnType identifier) {
    instructionIdentifier_ |=
        static_cast<std::underlying_type_t<InsnType>>(identifier);
  }

  /** Tests whether this instruction has the given identifier set. */
  constexpr bool isInstruction(InsnType identifier) const {
    return (instructionIdentifier_ &
            static_cast<std::underlying_type_t<InsnType>>(identifier));
  }

  /** For instructions with a valid rm field, extract the rm value and change
   * the CPP rounding mode accordingly, then call the function "operation"
   * before reverting the CPP rounding mode to its initial value. "Operation"
   * should contain the entire execution logic of the instruction */
  void setStaticRoundingModeThen(std::function<void(void)> operation);

  /** Generate an ExecutionNotYetImplemented exception. */
  void executionNYI();

  /** A reference to the ISA instance this instruction belongs to. */
  const Architecture& architecture_;

  /** A reference to the decoding metadata for this instruction. */
  const InstructionMetadata& metadata_;

  /** An array of source registers. */
  std::array<Register, MAX_SOURCE_REGISTERS> sourceRegisters_;

  /** The number of source registers this instruction reads from. */
  uint8_t sourceRegisterCount_ = 0;

  /** An array of destination registers. */
  std::array<Register, MAX_DESTINATION_REGISTERS> destinationRegisters_;

  /** The number of destination registers this instruction writes to. */
  uint8_t destinationRegisterCount_ = 0;

  /** An array of provided operand values. Each entry corresponds to a
   * `sourceRegisters` entry. */
  std::array<RegisterValue, MAX_SOURCE_REGISTERS> sourceValues_;

  /** The immediate source operand for which there is only ever one. Remains 0
   * if unused. */
  int64_t sourceImm_ = 0;

  /** An array of generated output results. Each entry corresponds to a
   * `destinationRegisters` entry. */
  std::array<RegisterValue, MAX_DESTINATION_REGISTERS> results_;

  /** The current exception state of this instruction. */
  InstructionException exception_ = InstructionException::None;

  /** The number of source operands that have not yet had values supplied. Used
   * to determine execution readiness. */
  uint16_t sourceOperandsPending_ = 0;

  /** Used to denote what type of instruction this is. Utilises the constants in
   * the `InsnType` namespace allowing each bit to represent a unique
   * identifier such as `isLoad` or `isMultiply` etc. */
  uint16_t instructionIdentifier_ = 0;
};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
