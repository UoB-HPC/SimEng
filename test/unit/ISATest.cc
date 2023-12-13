#include "gtest/gtest.h"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

namespace {

// Test that we can create an AArch64 Architecture object
TEST(ISATest, CreateAArch64) {
  simeng::kernel::Linux kernel;
  simeng::config::SimInfo::addToConfig("{Core: {Micro-Operations: True}}");

  std::unique_ptr<simeng::arch::Architecture> isa =
      std::make_unique<simeng::arch::aarch64::Architecture>(kernel);
}

// Test that we can set a value in a register file set
TEST(ISATest, CreateRegisterFileSet) {
  auto registerFileSet = simeng::RegisterFileSet({{8, 32}, {16, 32}, {1, 1}});
  auto reg = simeng::Register{simeng::arch::aarch64::RegisterType::GENERAL, 0};

  registerFileSet.set(reg, static_cast<uint64_t>(42));

  EXPECT_TRUE(registerFileSet.get(reg));
}

}  // namespace
