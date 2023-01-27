#pragma once

#include <functional>

#include "simeng/OS/SyscallHandler.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** An AArch64 exception handler. */
class ExceptionHandler : public simeng::arch::ExceptionHandler {
 public:
  /** Create an exception handler with references to the instruction that caused
   * the exception, along with the core model object and process memory. */
  ExceptionHandler(const std::shared_ptr<simeng::Instruction>& instruction,
                   const Core& core);

  /** Progress handling of the exception, by calling and returning the result of
   * the handler currently assigned to `resumeHandling_`. Returns `false` if
   * further ticks are required, and `true` when completed. */
  bool tick() override;

  /** Process the result of a syscall from the SyscallHandler. */
  void processSyscallResult(
      const simeng::OS::SyscallResult syscallResult) override;

  /** Retrieve the results of the handled exception. */
  const ExceptionResult& getResult() const override;

 private:
  /** Prints a description of the exception and the instruction that generated
   * it. */
  void printException(const Instruction& insn) const;

  /** The initial handling logic. Returns `true` if no further cycles are
   * required or `false` otherwise, in which case `resumeHandling_` has been set
   * to the next step. */
  bool init();

  /** Conclude a syscall, setting the return address and state change in the
   * exception results. */
  bool concludeSyscall();

  /** Sets a generic fatal result and returns true. */
  bool fatal();

  /** The instruction generating an exception. */
  const Instruction& instruction_;

  /** The core model object. */
  const Core& core_;

  /** Whether an active syscall result has been recieved. */
  bool syscallReturned_ = false;

  /** The results of a syscall. */
  simeng::OS::SyscallResult syscallResult_;

  /** The results of the exception. */
  ExceptionResult result_;

  /** A function to call to resume handling an exception. */
  std::function<bool()> resumeHandling_;

  /** Helper constants for AArch64 general-purpose registers. */
  static constexpr Register R0 = {RegisterType::GENERAL, 0};
  static constexpr Register R1 = {RegisterType::GENERAL, 1};
  static constexpr Register R2 = {RegisterType::GENERAL, 2};
  static constexpr Register R3 = {RegisterType::GENERAL, 3};
  static constexpr Register R4 = {RegisterType::GENERAL, 4};
  static constexpr Register R5 = {RegisterType::GENERAL, 5};
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
