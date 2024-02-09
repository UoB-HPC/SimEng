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
  const span<Register> getSourceRegisters() const override;

  /** Retrieve the data contained in the source registers this instruction
   * reads.*/
  const span<RegisterValue> getSourceOperands() const override;

  /** Retrieve the destination registers this instruction will write to.
   * A register value of -1 signifies a Zero Register read, and should not be
   * renamed. */
  const span<Register> getDestinationRegisters() const override;

  /** Check whether the operand at index `i` has had a value supplied. */
  bool isOperandReady(int index) const override;

  /** Override the specified source register with a renamed physical register.
   */
  void renameSource(uint16_t i, Register renamed) override;

  /** Override the specified destination register with a renamed physical
   * register. */
  void renameDestination(uint16_t i, Register renamed) override;

  /** Provide a value for the operand at the specified index. */
  virtual void supplyOperand(uint16_t i, const RegisterValue& value) override;

  /** Check whether all operand values have been supplied, and the instruction
   * is ready to execute. */
  bool canExecute() const override;

  /** Execute the instruction. */
  void execute() override;

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
   * instruction. */
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

  /** Set this instruction's execution information including it's execution
   * latency and throughput, and the set of ports which support it. */
  void setExecutionInfo(const ExecutionInfo& info);

  /** Get this instruction's supported set of ports. */
  const std::vector<uint16_t>& getSupportedPorts() override;

  /** Retrieve the instruction's metadata. */
  const InstructionMetadata& getMetadata() const;

  /** Retrieve the instruction's associated architecture. */
  const Architecture& getArchitecture() const;

 private:
  /** A reference to the ISA instance this instruction belongs to. */
  const Architecture& architecture_;

  /** A reference to the decoding metadata for this instruction. */
  const InstructionMetadata& metadata_;

  /** A vector of source registers. */
  std::vector<Register> sourceRegisters_;

  /** A vector of destination registers. */
  std::vector<Register> destinationRegisters_;

  /** The number of destination registers this instruction writes to. */
  uint16_t destinationRegisterCount_ = 0;

  /** A vector of provided operand values. Each entry corresponds to a
   * `sourceRegisters` entry. */
  std::vector<RegisterValue> sourceValues_;

  /** A vector of generated output results. Each entry corresponds to a
   * `destinationRegisters` entry. */
  std::vector<RegisterValue> results_;

  /** The current exception state of this instruction. */
  InstructionException exception_ = InstructionException::None;

  // Decoding
  /** Process the instruction's metadata to determine source/destination
   * registers. */
  void decode();

  // Scheduling
  /** The number of operands that have not yet had values supplied. Used to
   * determine execution readiness. */
  short sourceOperandsPending_ = 0;

  // Execution
  /** Generate an ExecutionNotYetImplemented exception. */
  void executionNYI();

  // Execution
  /** Generate an EncodingUnallocated exception. */
  void executionINV();

  // Execution
  /** Generate an StreamingModeUpdate exception. */
  void streamingModeUpdated();

  // Execution
  /** Generate an ZAregisterStatusUpdate exception. */
  void zaRegisterStatusUpdated();

  // Execution
  /** Generate an SMZAupdate exception. */
  void SMZAupdated();

  // Execution
  /** Generate a ZAdisabled exception. */
  void ZAdisabled();

  // Execution
  /** Generate a SMdisabled exception. */
  void SMdisabled();

  // Instruction Identifiers
  /** Operates on scalar values */
  bool isScalarData_ = false;
  /** Operates on vector values. */
  bool isVectorData_ = false;
  /** Uses Z registers as source and/or destination operands. */
  bool isSVEData_ = false;
  /** Uses ZA register or tiles of ZA as destination. */
  bool isSMEData_ = false;
  /** Doesn't have a shift operand. */
  bool isNoShift_ = true;
  /** Is a logical operation. */
  bool isLogical_ = false;
  /** Is a compare operation. */
  bool isCompare_ = false;
  /** Is a convert operation. */
  bool isConvert_ = false;
  /** Is a multiply operation. */
  bool isMultiply_ = false;
  /** Is a divide or square root operation */
  bool isDivideOrSqrt_ = false;
  /** Writes to a predicate register */
  bool isPredicate_ = false;
  /** Is a load operation. */
  bool isLoad_ = false;
  /** Is a store address operation. */
  bool isStoreAddress_ = false;
  /** Is a store data operation. */
  bool isStoreData_ = false;
  /** Is a branch operation. */
  bool isBranch_ = false;
  /** Is the micro-operation opcode of the instruction, where appropriate. */
  uint8_t microOpcode_ = MicroOpcode::INVALID;
  /** Is the micro-operation opcode of the instruction, where appropriate. */
  uint8_t dataSize_ = 0;

  // Memory
  /** Set the accessed memory addresses, and create a corresponding memory data
   * vector. */
  void setMemoryAddresses(
      const std::vector<memory::MemoryAccessTarget>& addresses);

  void setMemoryAddresses(std::vector<memory::MemoryAccessTarget>&& addresses);

  void setMemoryAddresses(memory::MemoryAccessTarget address);

  /** The memory addresses this instruction accesses, as a vector of {offset,
   * width} pairs. */
  std::vector<memory::MemoryAccessTarget> memoryAddresses_;

  /** A vector of memory values, that were either loaded memory, or are prepared
   * for sending to memory (according to instruction type). Each entry
   * corresponds to a `memoryAddresses` entry. */
  std::vector<RegisterValue> memoryData_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
