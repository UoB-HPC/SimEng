#pragma once

#include <functional>

#include "simeng/Instruction.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/kernel/Linux.hh"

namespace simeng {
namespace arch {

/** A generic exception handler. */
class GenericExceptionHandler : public simeng::arch::ExceptionHandler {
 public:
  /** Create an exception handler with references to the instruction that caused
   * the exception, along with the core model object and process memory. */
  GenericExceptionHandler(const Core& core, MemoryInterface& memory,
                          kernel::Linux& linux);

  /** Progress handling of the exception, by calling and returning the result of
   * the handler currently assigned to `resumeHandling_`. Returns `false` if
   * further ticks are required, and `true` when completed. */
  bool tick() override;

  /** Retrieve the results of the handled exception. */
  [[nodiscard]] const ExceptionResult& getResult() const override;

 protected:
  [[nodiscard]] virtual uint64_t callNumberConversion(
      uint64_t AArch64SyscallNumber) const = 0;

  [[nodiscard]] virtual uint64_t getSyscallID() const = 0;

  /** Prints a description of the exception and the instruction that generated
   * it. */
  virtual void printException() const = 0;

  [[nodiscard]] virtual bool isSupervisorCall() const = 0;

  [[nodiscard]] virtual Register getSupervisorCallRegister(
      int regNumber) const = 0;

  [[nodiscard]] virtual uint64_t getInstructionSequenceID() const = 0;

  [[nodiscard]] virtual uint64_t getInstructionAddress() const = 0;

  virtual ProcessStateChange uname(uint64_t base, Register R0) const = 0;

  /** The core model object. */
  const Core& core;

 private:
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

  /** The process memory. */
  MemoryInterface& memory_;

  /** The Linux kernel to forward syscalls to. */
  kernel::Linux& linux_;

  /** The results of the exception. */
  ExceptionResult result_;

  /** A function to call to resume handling an exception. */
  std::function<bool()> resumeHandling_;

  /** Helper constants for general-purpose registers. */
  Register R0;
  Register R1;
  Register R2;
  Register R3;
  Register R4;
  Register R5;
};

}  // namespace arch
}  // namespace simeng
