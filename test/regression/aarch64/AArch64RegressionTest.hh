#pragma once

#include "RegressionTest.hh"

#include "simeng/arch/aarch64/Instruction.hh"

/** A helper macro to run a snippet of Armv8 assembly code, returning from the
 * calling function if a fatal error occurs. Four bytes containing zeros are
 * appended to the source to ensure that the program will terminate with an
 * illegal instruction exception instead of running into the heap. */
#define RUN_AARCH64(source)                    \
  {                                            \
    std::string sourceWithTerminator = source; \
    sourceWithTerminator += "\n.word 0";       \
    run(sourceWithTerminator.c_str());         \
  }                                            \
  if (HasFatalFailure()) return

/** The test fixture for all AArch64 regression tests. */
class AArch64RegressionTest : public RegressionTest {
 protected:
  virtual ~AArch64RegressionTest() {}

  /** Run the assembly code in `source`. */
  void run(const char* source);

  /** Create an ISA instance from a kernel. */
  virtual std::unique_ptr<simeng::arch::Architecture> createArchitecture(
      simeng::kernel::Linux& kernel) const override;

  /** Create a port allocator for an out-of-order core model. */
  virtual std::unique_ptr<simeng::pipeline::PortAllocator> createPortAllocator()
      const override;

  /** Get the value of a general purpose register. */
  template <typename T>
  T getGeneralRegister(uint8_t tag) const {
    return getRegister<T>({simeng::arch::aarch64::RegisterType::GENERAL, tag});
  }

  /** Get the value of a vector register. */
  template <typename T>
  T getVectorRegister(uint8_t tag) const {
    return getRegister<T>({simeng::arch::aarch64::RegisterType::VECTOR, tag});
  }

  /** Get the value of the NZCV register. */
  uint8_t getNZCV() const;

  /** Get the negative flag from the NZCV register. */
  bool getNegativeFlag() const;

  /** Get the zero flag from the NZCV register. */
  bool getZeroFlag() const;

  /** Get the carry flag from the NZCV register. */
  bool getCarryFlag() const;

  /** Get the overflow flag from the NZCV register. */
  bool getOverflowFlag() const;
};
