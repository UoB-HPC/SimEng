#include "gtest/gtest.h"
#include "simeng/RegisterFileSet.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"

namespace {

// Test that we can create an AArch64 Architecture object
TEST(ISATest, CreateAArch64) {
  // Create instance of address translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();

  char* code = "";
  // Create a linux process from the empty code block
  std::unique_ptr<simeng::kernel::LinuxProcess> process =
      std::make_unique<simeng::kernel::LinuxProcess>(
          simeng::span<char>(code, 0), *address_translator);

  simeng::kernel::Linux kernel(*process, *address_translator);
  // Pass a config file with only the options required by the aarch64
  // architecture class to function
  std::unique_ptr<simeng::arch::Architecture> isa =
      std::make_unique<simeng::arch::aarch64::Architecture>(
          kernel, YAML::Load("{Core: {Simulation-Mode: emulation}}"));

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
