#pragma once

#include <functional>

#include "simeng/arch/Architecture.hh"
#include "simeng/arch/GenericExceptionHandler.hh"
#include "simeng/arch/aarch64/Instruction.hh"
#include "simeng/kernel/Linux.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** A AArch64 exception handler. */
class AArch64ExceptionHandler : public simeng::arch::GenericExceptionHandler {
 public:
  /** Create an exception handler with references to the instruction that caused
   * the exception, along with the core model object and process memory. */
  AArch64ExceptionHandler(
      const std::shared_ptr<simeng::Instruction>& instruction, const Core& core,
      MemoryInterface& memory, kernel::Linux& linux);

  /** Return the syscall number with AArch64 identification. See
   * https://marcin.juszkiewicz.com.pl/download/tables/syscalls.html */
  [[nodiscard]] uint64_t callNumberConversionToAArch64(
      uint64_t syscallNumber) const override;

  /** Return the system call number */
  [[nodiscard]] uint64_t getSyscallID() const override;

  /** Prints a description of the exception and the instruction that generated
   * it. */
  void printException() const override;

  /** Returns whether this is a supervisor call exception */
  [[nodiscard]] bool isSupervisorCall() const override;

  /** Get the regNumber'th register, used to hold data for supervisor calls */
  [[nodiscard]] Register getSupervisorCallRegister(
      int regNumber) const override;

  /** Returns the sequence ID of the instructions throwing this exception */
  [[nodiscard]] uint64_t getInstructionSequenceID() const override;

  /** Returns the address of the instructions throwing this exception */
  [[nodiscard]] uint64_t getInstructionAddress() const override;

  /** Implements the ISA specific uname syscall, return a processStateChange */
  ProcessStateChange uname(uint64_t base, Register R0) const override;

 private:
  /** The instruction generating an exception. */
  const Instruction& instruction_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
