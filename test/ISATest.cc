#include "A64Architecture.hh"
#include "A64Instruction.hh"
#include "RegisterFile.hh"
#include "gtest/gtest.h"

namespace {

// Test that we can create an A64Architecture object
TEST(ISATest, CreateA64Arch) {
  std::unique_ptr<simeng::Architecture> isa =
      std::make_unique<simeng::A64Architecture>();

  EXPECT_GT(isa->getRegisterFileStructure().size(), 0);
}

// Test that we can set a value in a register file
TEST(ISATest, CreateRegisterFile) {
  auto registerFile = simeng::RegisterFile({32, 32, 1});
  auto reg = simeng::Register{simeng::A64RegisterType::GENERAL, 0};

  registerFile.set(reg, 42);

  EXPECT_TRUE(registerFile.get(reg));
}

}  // namespace
