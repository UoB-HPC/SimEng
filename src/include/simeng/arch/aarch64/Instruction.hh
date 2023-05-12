#pragma once

#include <array>
#include <unordered_map>

#include "simeng/BranchPredictor.hh"
#include "simeng/Instruction.hh"
#include "simeng/arch/aarch64/InstructionGroups.hh"

struct cs_arm64_op;

namespace simeng {
namespace arch {
namespace aarch64 {

/** Apply the shift specified by `shiftType` to the unsigned integer `value`,
 * shifting by `amount`. */
template <typename T>
std::enable_if_t<std::is_integral_v<T> && std::is_unsigned_v<T>, T> shiftValue(
    T value, uint8_t shiftType, uint8_t amount) {
  switch (shiftType) {
    case ARM64_SFT_LSL:
      return value << amount;
    case ARM64_SFT_LSR:
      return value >> amount;
    case ARM64_SFT_ASR:
      return static_cast<std::make_signed_t<T>>(value) >> amount;
    case ARM64_SFT_ROR: {
      // Assuming sizeof(T) is a power of 2.
      const auto mask = sizeof(T) * 8 - 1;
      assert((amount <= mask) && "Rotate amount exceeds type width");
      amount &= mask;
      return (value >> amount) | (value << ((-amount) & mask));
    }
    case ARM64_SFT_MSL: {
      // pad in with ones instead of zeros
      const auto mask = (1 << amount) - 1;
      return (value << amount) | mask;
    }
    case ARM64_SFT_INVALID:
      return value;
    default:
      assert(false && "Unknown shift type");
      return 0;
  }
}

/** Get the size of the data to be accessed from/to memory. */
inline uint8_t getDataSize(cs_arm64_op op) {
  // Check from top of the range downwards

  // ARM64_REG_V0 -> {end} are vector registers
  if (op.reg >= ARM64_REG_V0) {
    // Data size for vector registers relies on opcode thus return 0
    return 0;
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

class Architecture;
struct InstructionMetadata;

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
}  // namespace RegisterType

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

/** A struct holding user-defined execution information for a aarch64
 * instruction. */
struct ExecutionInfo {
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
  EncodingNotYetImplemented,
  ExecutionNotYetImplemented,
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

/** Masks used for manipulating the insnTypeMetadata associated with an AArch64
 * Instruction. */

static constexpr uint32_t isScalarDataMask = 0b10000000000000000000000000000000;
static constexpr uint32_t isVectorDataMask = 0b01000000000000000000000000000000;
static constexpr uint32_t isSVEDataMask = 0b00100000000000000000000000000000;
static constexpr uint32_t isSMEDataMask = 0b00010000000000000000000000000000;
static constexpr uint32_t isNoShiftMask = 0b00001000000000000000000000000000;
static constexpr uint32_t isLogicalMask = 0b00000100000000000000000000000000;
static constexpr uint32_t isCompareMask = 0b00000010000000000000000000000000;
static constexpr uint32_t isConvertMask = 0b00000001000000000000000000000000;
static constexpr uint32_t isMultiplyMask = 0b00000000100000000000000000000000;
static constexpr uint32_t isDivOrSqrtMask = 0b00000000010000000000000000000000;
static constexpr uint32_t isPredicateMask = 0b00000000001000000000000000000000;
static constexpr uint32_t isLoadMask = 0b00000000000100000000000000000000;
static constexpr uint32_t isStoreAddrMask = 0b00000000000010000000000000000000;
static constexpr uint32_t isStoreDataMask = 0b00000000000001000000000000000000;
static constexpr uint32_t isBranchMask = 0b00000000000000100000000000000000;
static constexpr uint32_t isAtomicMask = 0b00000000000000010000000000000000;
static constexpr uint32_t isAcquireMask = 0b00000000000000001000000000000000;
static constexpr uint32_t isReleaseMask = 0b00000000000000000100000000000000;
static constexpr uint32_t isLoadRsrvdMask = 0b00000000000000000010000000000000;
static constexpr uint32_t isStoreCondMask = 0b00000000000000000001000000000000;

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

  /** Retrieve the identifier for the first exception that occurred during
   * processing this instruction. */
  virtual InstructionException getException() const;

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
  void supplyData(uint64_t address, const RegisterValue& data) override;

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

  /** Is this an atomic operation? */
  bool isAtomic() const override;

  /** Does this instruction enforce acquire semantics? */
  bool isAcquire() const override;

  /** Does this instruction enforce release semantics? */
  bool isRelease() const override;

  /** Is this a Load-Reserved operation? */
  bool isLoadReserved() const override;

  /** Is this a Store-Conditional operation? */
  bool isStoreCond() const override;

  /** Retrieve the instruction group this instruction belongs to. */
  uint16_t getGroup() const override;

  /** Set this instruction's execution information including it's execution
   * latency and throughput, and the set of ports which support it. */
  void setExecutionInfo(const ExecutionInfo& info);

  /** Get this instruction's supported set of ports. */
  const std::vector<uint16_t>& getSupportedPorts() override;

  /** Retrieve the instruction's metadata. */
  const InstructionMetadata& getMetadata() const;

  /** Retrieve the instruction's associated architecture. */
  const Architecture& getArchitecture() const;

  /** Update the result register for a conditional store instruction. */
  void updateCondStoreResult(const bool success) override;

  /** A special register value representing the zero register. If passed to
   * `setSourceRegisters`/`setDestinationRegisters`, the value will be
   * automatically supplied as zero. */
  static const Register ZERO_REGISTER;

 private:
  /** A reference to the ISA instance this instruction belongs to. */
  const Architecture& architecture_;

  /** A reference to the decoding metadata for this instruction. */
  const InstructionMetadata& metadata;

  /** A vector of provided operand values. Each entry corresponds to a
   * `sourceRegisters` entry. */
  std::vector<RegisterValue> operands;

  /** A vector of generated output results. Each entry corresponds to a
   * `destinationRegisters` entry. */
  std::vector<RegisterValue> results;

  /** The current exception state of this instruction. */
  InstructionException exception_ = InstructionException::None;

  // ------ Decoding ------
  /** Process the instruction's metadata to determine source/destination
   * registers. */
  void decode();

  /** A vector of source registers. */
  std::vector<Register> sourceRegisters;

  /** The number of source registers this instruction reads from. */
  uint16_t sourceRegisterCount = 0;

  /** A vector of destination registers. */
  std::vector<Register> destinationRegisters;

  /** The number of destination registers this instruction writes to. */
  uint16_t destinationRegisterCount = 0;

  /** Is the micro-operation opcode of the instruction, where appropriate. */
  uint8_t microOpcode_ = MicroOpcode::INVALID;
  /** Size of data to be stored. */
  uint8_t dataSize_ = 0;

  /** Metadat defining what type of Instruction this is.
   * Each bit is used to convey the following information (From MSB to LSB):
   * 1st bit indicates whether this instruction operates on scalar values.
   * 2nd bit indicates whether this instruction operates on vector values.
   * 3rd bit indicates whether this instruction uses Z registers as source
   *                   and/or destination operands.
   * 4th bit indicates whether this instruction uses the ZA register or
   *                   tiles of ZA as source and/or destination operands.
   * 5th bit indicates whether this instruction doesn't have a shift operand.
   * 6th bit indicates whether this is a logical instruction.
   * 7th bit indicates whether this is a compare instruction.
   * 8th bit indicates whether this is a convert instruction.
   * 9th bit indicates whether this is a multiply operation.
   * 10th bit indicates whether this is a divide or square root operation.
   * 11th bit indicates whether this instruction writes to a predicate register.
   * 12th bit indicates whether this is a load operation.
   * 13th bit indicates whether this is a store address operation.
   * 14th bit indicates whether this is a store data operation.
   * 15th bit indicates whether this is a branch operation.
   * 16th bit indicates whether this is an atomic operation.
   * 17th bit indicates whether this instruction enforces acquire semantics.
   * 18th bit indicates whether this instruction enforces release semantics.
   * 19th bit indicates whether this is a load-reserved instruction.
   * 20th bit indicates whether this is a store-conditional instruction.
   */
  uint32_t insnTypeMetadata = isNoShiftMask;

  // ------ Scheduling ------
  /** The number of operands that have not yet had values supplied. Used to
   * determine execution readiness. */
  uint16_t operandsPending = 0;

  // ------ Execution ------
  /** Extend `value` according to `extendType`, and left-shift the result by
   * `shift` */
  uint64_t extendValue(uint64_t value, uint8_t extendType, uint8_t shift) const;

  /** Extend `value` using extension/shifting rules defined in `op`. */
  uint64_t extendOffset(uint64_t value, const cs_arm64_op& op) const;

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

  // ------ Memory ------
  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(std::vector<memory::MemoryAccessTarget>&& addresses);
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
