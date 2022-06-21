#pragma once

#include <functional>

#include "simeng/arch/Architecture.hh"
#include "simeng/arch/GenericExceptionHandler.hh"
#include "simeng/arch/riscv/Instruction.hh"
#include "simeng/kernel/Linux.hh"

namespace simeng {
namespace arch {
namespace riscv {

/** A RISCV exception handler. */
class RISCVExceptionHandler : public simeng::arch::GenericExceptionHandler {
 public:
  /** Create an exception handler with references to the instruction that caused
   * the exception, along with the core model object and process memory. */
  RISCVExceptionHandler(const std::shared_ptr<simeng::Instruction>& instruction,
                        const Core& core, MemoryInterface& memory,
                        kernel::Linux& linux);

  [[nodiscard]] uint64_t callNumberConversion(
      uint64_t AArch64SyscallNumber) const override;

  [[nodiscard]] uint64_t getSyscallID() const override;

  void printException() const override;

  [[nodiscard]] bool isSupervisorCall() const override;

  [[nodiscard]] Register getSupervisorCallRegister(
      int regNumber) const override;

  [[nodiscard]] uint64_t getInstructionSequenceID() const override;

  [[nodiscard]] uint64_t getInstructionAddress() const override;

  ProcessStateChange uname(uint64_t base, Register RO) const override;

 private:
  /** The instruction generating an exception. */
  const Instruction& instruction_;
};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
