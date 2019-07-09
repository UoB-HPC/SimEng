#include "RegisterFileSet.hh"
#include "arch/aarch64/A64Architecture.hh"
#include "arch/aarch64/A64Instruction.hh"
#include "gtest/gtest.h"

namespace {

// Test that we can create an A64Architecture object
TEST(ISATest, CreateA64Arch) {
  simeng::kernel::Linux kernel;
  std::unique_ptr<simeng::arch::Architecture> isa =
      std::make_unique<simeng::arch::aarch64::A64Architecture>(kernel);

  EXPECT_GT(isa->getRegisterFileStructures().size(), 0);
}

// Test that we can set a value in a register file set
TEST(ISATest, CreateRegisterFileSet) {
  auto registerFileSet = simeng::RegisterFileSet({{8, 32}, {16, 32}, {1, 1}});
  auto reg =
      simeng::Register{simeng::arch::aarch64::A64RegisterType::GENERAL, 0};

  registerFileSet.set(reg, static_cast<uint64_t>(42));

  EXPECT_TRUE(registerFileSet.get(reg));
}

}  // namespace
