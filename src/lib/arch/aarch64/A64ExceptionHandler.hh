#pragma once

#include "Architecture.hh"

#include <functional>

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
                      MemoryInterface& memory, kernel::Linux& linux);

  /** Progress handling of the exception, by calling and returning the result of
   * the handler currently assigned to `resumeHandling_`. Returns `false` if
   * further ticks are required, and `true` when completed. */
  bool tick() override;

  /** Retrieve the results of the handled exception. */
  const ExceptionResult& getResult() const override;

 private:
  /** Prints a description of the exception and the instruction that generated
   * it. */
  void printException(const A64Instruction& insn) const;

  /** The initial handling logic. Returns `true` if no further cycles are
   * required or `false` otherwise, in which case `resumeHandling_` has been set
   * to the next step. */
  bool init();

  /** Attempt to read a string of max length `maxLength` from address `address`
   * into the supplied buffer, starting from character `offset`. An offset of
   * `-1` (default) will queue a read operation for the first character.
   *
   * This function will repeatedly set itself as the handler for the next cycle
   * until it either reads a null character or reaches the maximum length, at
   * which point it will call `then`, supplying the length of the read string.
   */
  bool readStringThen(char* buffer, uint64_t address, int maxLength,
                      std::function<bool(size_t length)> then, int offset = -1);

  /** Performs a readlinkat syscall using the path supplied. */
  void readLinkAt(span<char> path);

  /** Conclude a syscall, setting the return address and state change in the
   * exception results. */
  bool concludeSyscall(ProcessStateChange& stateChange);

  /** Sets a generic fatal result and returns true. */
  bool fatal();

  /** The instruction generating an exception. */
  const A64Instruction& instruction_;

  /** The core's architectural register file set. */
  const ArchitecturalRegisterFileSet& registerFileSet_;

  /** The process memory. */
  MemoryInterface& memory_;

  /** The Linux kernel to forward syscalls to. */
  kernel::Linux& linux_;

  /** The results of the exception. */
  ExceptionResult result_;

  /** A function to call to resume handling an exception. */
  std::function<bool()> resumeHandling_;

  /** Helper constants for A64 general-purpose registers. */
  static constexpr Register R0 = {A64RegisterType::GENERAL, 0};
  static constexpr Register R1 = {A64RegisterType::GENERAL, 1};
  static constexpr Register R2 = {A64RegisterType::GENERAL, 2};
  static constexpr Register R3 = {A64RegisterType::GENERAL, 3};
};

}  // namespace simeng
