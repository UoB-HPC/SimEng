#pragma once

#include <array>
#include <cfenv>
#include <functional>
#include <unordered_map>

#include "simeng/BranchPredictor.hh"
#include "simeng/Instruction.hh"
#include "simeng/arch/riscv/InstructionGroups.hh"

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

/** A struct holding user-defined execution information for a aarch64
 * instruction. */
struct executionInfo {
  /** The latency for the instruction. */
  uint16_t latency = 1;
  /** The execution throughput for the instruction. */
  uint16_t stallCycles = 1;
  /** The ports that support the instruction. */
  std::vector<uint16_t> ports = {};
};

/** The various exceptions that can be raised by an individual instruction. */
enum class InstructionException : uint8_t {
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

/** Masks used for manipulating the insnTypeMetadata associated with a RISC-V
 * Instruction. */
static constexpr uint16_t isStoreMask = 0b1000000000000000;
static constexpr uint16_t isLoadMask = 0b0100000000000000;
static constexpr uint16_t isBranchMask = 0b0010000000000000;
static constexpr uint16_t isMultiplyMask = 0b0001000000000000;
static constexpr uint16_t isDivideMask = 0b0000100000000000;
static constexpr uint16_t isShiftMask = 0b0000010000000000;
static constexpr uint16_t isAtomicMask = 0b0000001000000000;
static constexpr uint16_t isLogicalMask = 0b0000000100000000;
static constexpr uint16_t isCompareMask = 0b0000000010000000;
static constexpr uint16_t isAcquireMask = 0b0000000001000000;
static constexpr uint16_t isReleaseMask = 0b0000000000100000;
static constexpr uint16_t isLoadReservedMask = 0b0000000000010000;
static constexpr uint16_t isStoreCondMask = 0b0000000000001000;
static constexpr uint16_t isConvertMask = 0b0000000000000100;
static constexpr uint16_t isFloatMask = 0b0000000000000010;

/** A basic RISC-V implementation of the `Instruction` interface. */
class Instruction : public simeng::Instruction {
 public:
  /** Construct an instruction instance by decoding a provided instruction word.
   */
  Instruction(const Architecture& architecture,
              const InstructionMetadata& metadata);

  /** Construct an instruction instance by decoding a provided instruction word.
   */
  Instruction(const Architecture& architecture,
              const InstructionMetadata& metadata, uint8_t latency,
              uint8_t stallCycles);

  /** Construct an instruction instance that raises an exception. */
  Instruction(const Architecture& architecture,
              const InstructionMetadata& metadata,
              InstructionException exception);

  /** Retrieve the identifier for the first exception that occurred during
   * processing this instruction. */
  virtual InstructionException getException() const;

  /** Retrieve the source registers this instruction reads. */
  const span<Register> getOperandRegisters() const override;

  const span<RegisterValue> getSourceOperands() const override;

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

  /** Provide a value for the operand at the specified index. */
  virtual void supplyOperand(uint8_t i, const RegisterValue& value) override;

  /** Check whether all operand values have been supplied, and the instruction
   * is ready to execute. */
  bool canExecute() const override;

  /** Execute the instruction. */
  void execute() override;

  /** Retrieve register results. */
  const span<RegisterValue> getResults() const override;

  /** Generate memory addresses this instruction wishes to access. */
  const std::vector<memory::MemoryAccessTarget>& generateAddresses() override;

  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(
      const std::vector<memory::MemoryAccessTarget>& addresses) override;

  /** Provide data from a requested memory address. */
  void supplyData(uint64_t address, const RegisterValue& data,
                  bool forwarded = false) override;

  /** Early misprediction check; see if it's possible to determine whether the
   * next instruction address was mispredicted without executing the
   * instruction. */
  std::tuple<bool, uint64_t> checkEarlyBranchMisprediction() const override;

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

  /** Is this an atomic instruction? */
  bool isAtomic() const override;

  /** Does this instruction enforce acquire semantics? */
  bool isAcquire() const override;

  /** Does this instruction enforce release semantics? */
  bool isRelease() const override;

  /** Is this a Load-Reserved operation? */
  bool isLoadReserved() const override;

  /** Is this a Store-Conditional operation? */
  bool isStoreCond() const override;

  /** Is this a prefetch operation? */
  bool isPrefetch() const override;

  uint64_t getOpcode() const override;

  /** Retrieve the instruction group this instruction belongs to. */
  uint16_t getGroup() const override;

  /** Set this instruction's execution information including it's execution
   * latency and throughput, and the set of ports which support it. */
  void setExecutionInfo(const executionInfo& info);

  /** Get this instruction's supported set of ports. */
  const std::vector<uint16_t>& getSupportedPorts() override;

  /** Retrieve the instruction's metadata. */
  const InstructionMetadata& getMetadata() const;

  /** Update the result register for a conditional store instruction. */
  void updateCondStoreResult(const bool success) override;

  /** A special register value representing the zero register. If passed to
   * `setSourceRegisters`/`setDestinationRegisters`, the value will be
   * automatically supplied as zero. */
  // static const Register ZERO_REGISTER;

 private:
  /** The maximum number of source registers any supported RISC-V instruction
   * can have. */
  static const uint8_t MAX_SOURCE_REGISTERS = 3;
  /** The maximum number of destination registers any supported RISC-V
   * instruction can have. */
  static const uint8_t MAX_DESTINATION_REGISTERS = 1;

  /** A reference to the ISA instance this instruction belongs to. */
  const Architecture& architecture_;

  /** A reference to the decoding metadata for this instruction. */
  const InstructionMetadata& metadata_;

  /** An array of provided operand values. Each entry corresponds to a
   * `sourceRegisters` entry. */
  std::array<RegisterValue, MAX_SOURCE_REGISTERS> operands;

  /** The immediate source operand for which there is only ever one. Remains 0
   * if unused. */
  int64_t sourceImm_ = 0;

  /** An array of generated output results. Each entry corresponds to a
   * `destinationRegisters` entry. */
  std::array<RegisterValue, MAX_DESTINATION_REGISTERS> results_;

  /** For instructions with a valid rm field, extract the rm value and change
   * the CPP rounding mode accordingly, then call the function "operation"
   * before reverting the CPP rounding mode to its initial value. "Operation"
   * should contain the entire execution logic of the instruction */
  void setStaticRoundingModeThen(std::function<void(void)> operation);

  /** The current exception state of this instruction. */
  InstructionException exception_ = InstructionException::None;

  // ------ Decoding ------
  /** Process the instruction's metadata to determine source/destination
   * registers. */
  void decode();

  /** An array of source registers. */
  std::array<Register, MAX_SOURCE_REGISTERS> sourceRegisters;

  /** The number of source registers this instruction reads from. */
  uint8_t sourceRegisterCount = 0;

  /** An array of destination registers. */
  std::array<Register, MAX_DESTINATION_REGISTERS> destinationRegisters;

  /** The number of destination registers this instruction writes to. */
  uint8_t destinationRegisterCount = 0;

  /** Metadat defining what type of Instruction this is.
   * Each bit is used to convey the following information (From MSB to LSB):
   * 1st bit indicates whether this is a store operation.
   * 2nd bit indicates whether this is a load operation.
   * 3rd bit indicates whether this is a branch operation.
   * 4th bit indicates whether this is a multiply operation.
   * 5th bit indicates whether this is a divide operation.
   * 6th bit indicates whether this is a shift operation.
   * 7th bit indicates whether this is an atomic instruction.
   * 8th bit indicates whether this is a logical instruction.
   * 9th bit indicates whether this is a compare instruction
   * 10th bit indicates whether this enforces aqcuire semantics.
   * 11th bit indicates whether this enforces release semantics.
   * 12th bit indicates whether this is a load-reserved instruction.
   * 13th bit indicates whether this is a store-conditional instruction.
   */
  uint16_t insnTypeMetadata = 0;

  /** Invalidate instructions that are currently not yet implemented. This
 prevents errors during speculated branches with unknown destinations;
 non-executable assertions. memory is decoded into valid but not implemented
 instructions tripping assertions.
 TODO remove once all extensions are supported*/
  void invalidateIfNotImplemented();

  // ------ Scheduling ------
  /** The number of operands that have not yet had values supplied. Used to
   * determine execution readiness. */
  short operandsPending = 0;

  // ------ Execution ------
  /** Generate an ExecutionNotYetImplemented exception. */
  void executionNYI();
};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
