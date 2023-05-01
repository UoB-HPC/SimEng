#include "gtest/gtest.h"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

namespace {

// Test that we can create an AArch64 Architecture object
TEST(ISATest, CreateAArch64) {
  simeng::kernel::Linux kernel;
  simeng::config::SimInfo::addToConfig(
      "{Core: {ISA: AArch64, Simulation-Mode: emulation, Clock-Frequency: 2.5, "
      "Timer-Frequency: 100, Micro-Operations: True, Vector-Length: 512, "
      "Streaming-Vector-Length: 512}, CPU-Info: {Generate-Special-Dir: "
      "False}}");

  std::unique_ptr<simeng::arch::Architecture> isa =
      std::make_unique<simeng::arch::aarch64::Architecture>(kernel);

  EXPECT_GT(isa->getNumSystemRegisters(), 0);
}

// Test that we can set a value in a register file set
TEST(ISATest, CreateRegisterFileSet) {
  auto registerFileSet = simeng::RegisterFileSet({{8, 32}, {16, 32}, {1, 1}});
  auto reg = simeng::Register{simeng::arch::aarch64::RegisterType::GENERAL, 0};

  registerFileSet.set(reg, static_cast<uint64_t>(42));

  EXPECT_TRUE(registerFileSet.get(reg));
}

}  // namespace
