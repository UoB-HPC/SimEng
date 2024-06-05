#pragma once

#include <array>
#include <unordered_map>

#include "simeng/Instruction.hh"
#include "simeng/arch/aarch64/InstructionGroups.hh"
#include "simeng/arch/aarch64/operandContainer.hh"
#include "simeng/branchpredictors/BranchPredictor.hh"

struct cs_arm64_op;

namespace simeng {
namespace arch {
namespace aarch64 {

class Architecture;
struct InstructionMetadata;

// operandContainer type aliases - used to improve readability of source and
// destination operand containers.
using srcRegContainer = operandContainer<Register, MAX_SOURCE_REGISTERS>;
using srcValContainer = operandContainer<RegisterValue, MAX_SOURCE_REGISTERS>;
using destRegContainer = operandContainer<Register, MAX_DESTINATION_REGISTERS>;
using destValContainer =
    operandContainer<RegisterValue, MAX_DESTINATION_REGISTERS>;

namespace RegisterType {
/** The 64-bit general purpose register set: [w|x]0-31. */
const uint8_t GENERAL = 0;
/** The 128|2048 bit vector register set: [v|z]0-31. */
const uint8_t VECTOR = 1;
/** The 32 bit predicate register set: p0-15. */
const uint8_t PREDICATE = 2;
/** The 4-bit NZCV condition flag register. */
const uint8_t NZCV = 3;
/** The system registers. */
const uint8_t SYSTEM = 4;
/** The [256-byte x (SVL / 8)] SME matrix register za. */
const uint8_t MATRIX = 5;

/** A special register value representing the zero register. */
const Register ZERO_REGISTER = {GENERAL, (uint16_t)-1};
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
  UnmappedSysReg,
  StreamingModeUpdate,
  ZAregisterStatusUpdate,
  SMZAUpdate,
  ZAdisabled,
  SMdisabled
};

/** The opcodes of simeng aarch64 micro-operations. */
namespace MicroOpcode {
const uint8_t OFFSET_IMM = 0;
const uint8_t OFFSET_REG = 1;
const uint8_t LDR_ADDR = 2;
const uint8_t STR_ADDR = 3;
const uint8_t STR_DATA = 4;
// INVALID is the default value reserved for non-micro-operation instructions
const uint8_t INVALID = 255;
}  // namespace MicroOpcode

/** A struct to group micro-operation information together. */
struct MicroOpInfo {
  bool isMicroOp = false;
  uint8_t microOpcode = MicroOpcode::INVALID;
  uint8_t dataSize = 0;
  bool isLastMicroOp = true;
  int microOpIndex = 0;
};

/** Get the size of the data to be accessed from/to memory. */
inline uint8_t getDataSize(cs_arm64_op op) {
  // Check from top of the range downwards

  // ARM64_REG_V0 -> {end} are vector registers
  if (op.reg >= ARM64_REG_V0) {
    // Data size for vector registers relies on opcode, get vector access
    // specifier
    arm64_vas vas = op.vas;
    assert(vas != ARM64_VAS_INVALID && "Invalid VAS type");
    switch (vas) {
      case ARM64_VAS_16B:
      case ARM64_VAS_8H:
      case ARM64_VAS_4S:
      case ARM64_VAS_2D:
      case ARM64_VAS_1Q: {
        return 16;
      }
      case ARM64_VAS_8B:
      case ARM64_VAS_4H:
      case ARM64_VAS_2S:
      case ARM64_VAS_1D: {
        return 8;
      }
      case ARM64_VAS_4B:
      case ARM64_VAS_2H:
      case ARM64_VAS_1S: {
        return 4;
      }
      case ARM64_VAS_1H: {
        return 2;
      }
      case ARM64_VAS_1B: {
        return 1;
      }
      default: {
        assert(false && "Unknown VAS type");
      }
    }
  }

  // ARM64_REG_ZAB0 -> +31 are tiles of the matrix register (ZA)
  if (op.reg >= ARM64_REG_ZAB0 || op.reg == ARM64_REG_ZA) {
    // Data size for tile registers relies on opcode thus return 0
    return 0;
  }

  // ARM64_REG_Z0 -> +31 are scalable vector registers (Z)
  if (op.reg >= ARM64_REG_Z0) {
    // Data size for vector registers relies on opcode thus return 0
    return 0;
  }

  // ARM64_REG_X0 -> +28 are 64-bit (X) registers
  if (op.reg >= ARM64_REG_X0) {
    return 8;
  }

  // ARM64_REG_W0 -> +30 are 32-bit (W) registers
  if (op.reg >= ARM64_REG_W0) {
    return 4;
  }

  // ARM64_REG_S0 -> +31 are 32-bit arranged (S) neon registers
  if (op.reg >= ARM64_REG_S0) {
    return 4;
  }

  // ARM64_REG_Q0 -> +31 are 128-bit arranged (Q) neon registers
  if (op.reg >= ARM64_REG_Q0) {
    return 16;
  }

  // ARM64_REG_P0 -> +15 are 256-bit (P) registers
  if (op.reg >= ARM64_REG_P0) {
    return 1;
  }

  // ARM64_REG_H0 -> +31 are 16-bit arranged (H) neon registers
  if (op.reg >= ARM64_REG_H0) {
    return 2;
  }

  // ARM64_REG_D0 -> +31 are 64-bit arranged (D) neon registers
  if (op.reg >= ARM64_REG_D0) {
    return 8;
  }

  // ARM64_REG_B0 -> +31 are 8-bit arranged (B) neon registers
  if (op.reg >= ARM64_REG_B0) {
    return 1;
  }

  // ARM64_REG_XZR is the 64-bit zero register
  if (op.reg == ARM64_REG_XZR) {
    return 8;
  }

  // ARM64_REG_WZR is the 32-bit zero register
  if (op.reg == ARM64_REG_WZR) {
    return 4;
  }

  // ARM64_REG_WSP (w31) is the 32-bit stack pointer register
  if (op.reg == ARM64_REG_WSP) {
    return 4;
  }

  // ARM64_REG_SP (x31) is the 64-bit stack pointer register
  if (op.reg == ARM64_REG_SP) {
    return 8;
  }

  // ARM64_REG_NZCV is the NZCV flag register
  if (op.reg == ARM64_REG_NZCV) {
    return 1;
  }

  // ARM64_REG_X30 is the 64-bit link register
  if (op.reg == ARM64_REG_X30) {
    return 8;
  }

  // ARM64_REG_X29 is the 64-bit frame pointer
  if (op.reg == ARM64_REG_X29) {
    return 8;
  }

  // ARM64_REG_FFR (p15) is a special purpose predicate register
  if (op.reg == ARM64_REG_FFR) {
    return 1;
  }

  // ARM64_REG_INVALID is an invalid capstone register so return 0 bytes as size
  if (op.reg == ARM64_REG_INVALID) {
    return 0;
  }

  assert(false && "Failed to find register in macroOp metadata");
  return 0;
}

// AArch64 Instruction Identifier Masks
enum class InsnType : uint32_t {
  /** Writes scalar values to one or more registers and/or memory locations. */
  isScalarData = 1 << 0,
  /** Writes NEON vector values to one or more registers and/or memory
     locations. */
  isVectorData = 1 << 1,
  /** Writes SVE vector values to one or more registers and/or memory locations.
   */
  isSVEData = 1 << 2,
  /** Writes SME matrix values to one or more registers and/or memory locations.
   */
  isSMEData = 1 << 3,
  /** Has a shift operand. */
  isShift = 1 << 4,
  /** Is a logical operation. */
  isLogical = 1 << 5,
  /** Is a compare operation. */
  isCompare = 1 << 6,
  /** Is a convert operation. */
  isConvert = 1 << 7,
  /** Is a multiply operation. */
  isMultiply = 1 << 8,
  /** Is a divide or square root operation */
  isDivideOrSqrt = 1 << 9,
  /** Writes to a predicate register */
  isPredicate = 1 << 10,
  /** Is a load operation. */
  isLoad = 1 << 11,
  /** Is a store address operation. */
  isStoreAddress = 1 << 12,
  /** Is a store data operation. */
  isStoreData = 1 << 13,
  /** Is a branch operation. */
  isBranch = 1 << 14
};

/** A basic Armv9.2-a implementation of the `Instruction` interface. */
class Instruction : public simeng::Instruction {
 public:
  /** Construct an instruction instance by decoding a provided instruction word.
   */
  Instruction(const Architecture& architecture,
              const InstructionMetadata& metadata,
              MicroOpInfo microOpInfo = MicroOpInfo());

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

  /** Generate an ExecutionNotYetImplemented exception. */
  void executionNYI();

  /** Generate an EncodingUnallocated exception. */
  void executionINV();

  /** Generate an StreamingModeUpdate exception. */
  void streamingModeUpdated();

  /** Generate an ZAregisterStatusUpdate exception. */
  void zaRegisterStatusUpdated();

  /** Generate an SMZAupdate exception. */
  void SMZAupdated();

  /** Generate a ZAdisabled exception. */
  void ZAdisabled();

  /** Generate a SMdisabled exception. */
  void SMdisabled();

  /** A reference to the ISA instance this instruction belongs to. */
  const Architecture& architecture_;

  /** A reference to the decoding metadata for this instruction. */
  const InstructionMetadata& metadata_;

  /** An operandContainer of source registers. */
  srcRegContainer sourceRegisters_;

  /** The number of source registers this instruction reads from. */
  uint16_t sourceRegisterCount_ = 0;

  /** An operandContainer of destination registers. */
  destRegContainer destinationRegisters_;

  /** The number of destination registers this instruction writes to. */
  uint16_t destinationRegisterCount_ = 0;

  /** An operandContainer of provided operand values. Each entry corresponds to
   * a `sourceRegisters` entry. */
  srcValContainer sourceValues_;

  /** An operandContainer of generated output results. Each entry corresponds to
   * a `destinationRegisters` entry. */
  destValContainer results_;

  /** The current exception state of this instruction. */
  InstructionException exception_ = InstructionException::None;

  /** The number of source operands that have not yet had values supplied. Used
   * to determine execution readiness. */
  uint16_t sourceOperandsPending_ = 0;

  /** Is the micro-operation opcode of the instruction, where appropriate. */
  uint8_t microOpcode_ = MicroOpcode::INVALID;

  /** Is the micro-operation opcode of the instruction, where appropriate. */
  uint8_t dataSize_ = 0;

  /** Used to denote what type of instruction this is. Utilises the constants in
   * the `InsnType` namespace allowing each bit to represent a unique
   * identifier such as `isLoad` or `isMultiply` etc. */
  uint32_t instructionIdentifier_ = 0;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
