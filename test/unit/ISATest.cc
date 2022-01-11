#include "gtest/gtest.h"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

namespace {

// Test that we can create an AArch64 Architecture object
TEST(ISATest, CreateAArch64) {
  simeng::kernel::Linux kernel;
  YAML::Node config = YAML::Load(
      "{Core: {Simulation-Mode: emulation, Micro-Operations: True, "
      "Vector-Length: 512}}");
  // Pass a config file with only the options required by the aarch64
  // architecture class to function
  std::unique_ptr<simeng::arch::Architecture> isa =
      std::make_unique<simeng::arch::aarch64::Architecture>(kernel, config);

  EXPECT_GT(isa->getRegisterFileStructures().size(), 0);
}

// Test that we can set a value in a register file set
TEST(ISATest, CreateRegisterFileSet) {
  auto registerFileSet = simeng::RegisterFileSet({{8, 32}, {16, 32}, {1, 1}});
  auto reg = simeng::Register{simeng::arch::aarch64::RegisterType::GENERAL, 0};

  registerFileSet.set(reg, static_cast<uint64_t>(42));

  EXPECT_TRUE(registerFileSet.get(reg));
}

}  // namespace
