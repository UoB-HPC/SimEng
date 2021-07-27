#pragma once

#include "simeng/arch/Architecture.hh"

#include <functional>

#include "simeng/arch/riscv/Instruction.hh"
#include "simeng/kernel/Linux.hh"

namespace simeng {
namespace arch {
namespace riscv {

/** An AArch64 exception handler. */
class ExceptionHandler : public simeng::arch::ExceptionHandler {
 public:
  /** Create an exception handler with references to the instruction that caused
   * the exception, along with the core model object and process memory. */
  ExceptionHandler(const std::shared_ptr<simeng::Instruction>& instruction,
                   const Core& core, MemoryInterface& memory,
                   kernel::Linux& linux);

  /** Progress handling of the exception, by calling and returning the result of
   * the handler currently assigned to `resumeHandling_`. Returns `false` if
   * further ticks are required, and `true` when completed. */
  bool tick() override;

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

  /** Read `length` bytes of data from `ptr`, and then call `then`.
   *
   * This function will repeatedly set itself as the handler for the next cycle
   * until it has read `length` bytes of data. The data may be read in chunks if
   * it is larger than can be read in a single memory request. The data will be
   * appended to the member vector `dataBuffer`.
   */
  bool readBufferThen(uint64_t ptr, uint64_t length, std::function<bool()> then,
                      bool firstCall = true);

  /** A data buffer used for reading data from memory. */
  std::vector<uint8_t> dataBuffer;

  /** Performs a readlinkat syscall using the path supplied. */
  void readLinkAt(span<char> path);

  /** Conclude a syscall, setting the return address and state change in the
   * exception results. */
  bool concludeSyscall(ProcessStateChange& stateChange);

  /** Sets a generic fatal result and returns true. */
  bool fatal();

  /** The instruction generating an exception. */
  const Instruction& instruction_;

  /** The core model object. */
  const Core& core;

  /** The process memory. */
  MemoryInterface& memory_;

  /** The Linux kernel to forward syscalls to. */
  kernel::Linux& linux_;

  /** The results of the exception. */
  ExceptionResult result_;

  /** A function to call to resume handling an exception. */
  std::function<bool()> resumeHandling_;

  /** Helper constants for RISCV general-purpose registers. */
  static constexpr Register R0 = {RegisterType::GENERAL, 10};
  static constexpr Register R1 = {RegisterType::GENERAL, 11};
  static constexpr Register R2 = {RegisterType::GENERAL, 12};
  static constexpr Register R3 = {RegisterType::GENERAL, 13};
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
