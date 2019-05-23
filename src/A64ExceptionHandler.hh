#pragma once

#include "Architecture.hh"

#include "A64Instruction.hh"
#include "kernel/Linux.hh"

namespace simeng {

/** An A64 exception handler. */
class A64ExceptionHandler : public ExceptionHandler {
 public:
  /** Create an exception handler with references to the instruction that caused
   * the exception, along with the architectural register files and process
   * memory. */
  A64ExceptionHandler(const std::shared_ptr<Instruction>& instruction,
                      const ArchitecturalRegisterFileSet& registerFileSet,
                      const char* memory, kernel::Linux& linux);

  /** Progress handling of the exception. Returns `false` if further ticks are
   * required, and `true` when completed. */
  bool tick() override;

  /** Retrieve the results of the handled exception. */
  const ExceptionResult& getResult() const override;

 private:
  /** Prints a description of the exception and the instruction that generated
   * it. */
  void printException(const A64Instruction& insn) const;

  /** Sets a generic fatal result and returns true. */
  bool fatal();

  /** The instruction generating an exception. */
  const A64Instruction& instruction_;

  /** The core's architectural register file set. */
  const ArchitecturalRegisterFileSet& registerFileSet_;

  /** The process memory. */
  const char* memory_;

  /** The Linux kernel to forward syscalls to. */
  kernel::Linux& linux_;

  /** The results of the exception. */
  ExceptionResult result_;
};

}  // namespace simeng
