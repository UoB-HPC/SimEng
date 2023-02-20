#pragma once

#include <forward_list>
#include <queue>
#include <unordered_map>

#include "simeng/Config.hh"
#include "simeng/OS/SyscallHandler.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/MicroDecoder.hh"

using csh = size_t;

namespace simeng {
namespace arch {
namespace aarch64 {

/** Enum which holds AArch64 System register tags used by SimEng. */
enum ARM64_SYSREG_TAGS : uint16_t {
  DCZID_EL0,
  FPCR,
  FPSR,
  TPIDR_EL0,
  MIDR_ELI,
  CNTVCT_EL0,
  PMCCNTR_EL0,
  SVCR
};

/* A basic Armv9.2-a implementation of the `Architecture` interface. */
class Architecture : public arch::Architecture {
 public:
  Architecture();

  ~Architecture();

  /** Pre-decode instruction memory into a macro-op of `Instruction`
   * instances. Returns the number of bytes consumed to produce it (always 4),
   * and writes into the supplied macro-op vector. */
  uint8_t predecode(const void* ptr, uint8_t bytesAvailable,
                    uint64_t instructionAddress,
                    MacroOp& output) const override;

  /** Returns a zero-indexed register tag for a system register encoding.
   * Returns -1 in the case that the system register has no mapping. */
  int32_t getSystemRegisterTag(uint16_t reg) const override;

  /** Returns the number of system registers that have a mapping. */
  uint16_t getNumSystemRegisters() const override;

  /** Returns the maximum size of a valid instruction in bytes. */
  uint8_t getMaxInstructionSize() const override;

  /** Returns the current vector length set by the provided configuration. */
  uint64_t getVectorLength() const;

  /** Returns the current streaming vector length set by the provided
   * configuration. */
  uint64_t getStreamingVectorLength() const;

  /** Updates System registers of any system-based timers. */
  void updateSystemTimerRegisters(RegisterFileSet* regFile,
                                  const uint64_t iterations) const override;

  /** Returns the physical register structure as defined within the config file
   */
  std::vector<RegisterFileStructure> getConfigPhysicalRegisterStructure()
      const override;

  /** Returns the physical register quantities as defined within the config file
   */
  std::vector<uint16_t> getConfigPhysicalRegisterQuantities() const override;

  /** Retrieve an ExecutionInfo object for the requested instruction. If a
   * opcode-based override has been defined for the latency and/or
   * port information, return that instead of the group-defined execution
   * information. */
  ExecutionInfo getExecutionInfo(Instruction& insn) const;

  /** Returns the current value of SVCRval_. */
  uint64_t getSVCRval() const;

  /** Update the value of SVCRval_. */
  void setSVCRval(const uint64_t newVal) const;

  /** After a context switch, update any required variables. */
  void updateAfterContextSwitch(
      const simeng::OS::cpuContext& context) const override;

 private:
  /** A decoding cache, mapping an instruction word to a previously decoded
   * instruction. Instructions are added to the cache as they're decoded, to
   * reduce the overhead of future decoding. */
  static std::unordered_map<uint32_t, Instruction> decodeCache;
  /** A decoding metadata cache, mapping an instruction word to a previously
   * decoded instruction metadata bundle. Metadata is added to the cache as it's
   * decoded, to reduce the overhead of future decoding. */
  static std::forward_list<InstructionMetadata> metadataCache;

  /** A copy of the value of the SVCR system register. */
  mutable uint64_t SVCRval_ = 0;

  /** A mapping from system register encoding to a zero-indexed tag. */
  std::unordered_map<uint16_t, uint16_t> systemRegisterMap_;

  /** A map to hold the relationship between aarch64 instruction groups and
   * user-defined execution information. */
  std::unordered_map<uint16_t, ExecutionInfo> groupExecutionInfo_;

  /** A map to hold the relationship between aarch64 instruction opcode and
   * user-defined execution information. */
  std::unordered_map<uint16_t, ExecutionInfo> opcodeExecutionInfo_;

  /** A Capstone decoding library handle, for decoding instructions. */
  csh capstoneHandle;

  /** A reference to a micro decoder object to split macro operations. */
  std::unique_ptr<MicroDecoder> microDecoder_;

  /** The vector length used by the SVE extension in bits. */
  uint64_t VL_;

  /** The streaming vector length used by the SME extension in bits. */
  uint64_t SVL_;

  /** System Register of Virtual Counter Timer. */
  simeng::Register VCTreg_;

  /** System Register of Processor Cycle Counter. */
  simeng::Register PCCreg_;

  /** Modulo component used to define the frequency at which the VCT is updated.
   */
  double vctModulo_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
