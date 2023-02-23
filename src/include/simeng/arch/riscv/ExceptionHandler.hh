#pragma once

#include <functional>

#include "simeng/OS/SyscallHandler.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/riscv/Instruction.hh"

namespace simeng {
namespace arch {
namespace riscv {

/** A RISC-V exception handler. */
class ExceptionHandler : public simeng::arch::ExceptionHandler {
 public:
  /** Create an exception handler with a reference to the core model object. */
  ExceptionHandler(const Core& core);

  /** Progress handling of the exception. Either this handler will process the
   * exception alone and instantly complete its processing, or, the simulated
   * Operating System's syscall handler will be envoked and this handler must
   * wait for the result. Returns `false` if further ticks are required, and
   * `true` when completed. */
  bool tick() override;

  /** Register the instruction which contains the exception with the exception
   * handler. */
  void registerException(
      std::shared_ptr<simeng::Instruction> instruction) override;

  /** Process the result of a syscall from the SyscallHandler. */
  void processSyscallResult(
      const simeng::OS::SyscallResult syscallResult) override;

  /** Retrieve the results of the handled exception. */
  const ExceptionResult& getResult() const override;

 private:
  /** Prints a description of the exception and the instruction that generated
   * it. */
  void printException() const;

  /** This function begins the handling of the generated exception passed via
   * registerException(). Returns `true` if no further cycles are required or
   * `false` otherwise. */
  bool handleException();

  /** Conclude a syscall, setting the return address and state change in the
   * exception results. */
  bool concludeSyscall();

  /** Sets a generic fatal result and returns true. */
  bool fatal();

  /** Resets the state of the exception handler so that it's ready to process
   * the next instruction. */
  void resetState();

  /** The instruction generating an exception. */
  std::shared_ptr<Instruction> instruction_ = nullptr;

  /** The core model object. */
  const Core& core_;

  /** Indicates whether the generated exception required the use of the syscall
   * handler and, therefore, the exception handler must wait for the syscall
   * result to be returned. */
  bool envokingSycallHandler_ = false;

  /** Indicates whether the return value of an active syscall has been received.
   */
  bool syscallReturned_ = false;

  /** The results of a syscall. */
  simeng::OS::SyscallResult syscallResult_ = {false, 0, 0, {}};

  /** The results of the exception. */
  ExceptionResult result_;

  /** Helper constants for RISC-V general-purpose registers. */
  static constexpr Register R0 = {RegisterType::GENERAL, 10};
  static constexpr Register R1 = {RegisterType::GENERAL, 11};
  static constexpr Register R2 = {RegisterType::GENERAL, 12};
  static constexpr Register R3 = {RegisterType::GENERAL, 13};
  static constexpr Register R4 = {RegisterType::GENERAL, 14};
  static constexpr Register R5 = {RegisterType::GENERAL, 15};
};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
