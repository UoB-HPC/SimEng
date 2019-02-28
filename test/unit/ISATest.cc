#include "A64Architecture.hh"
#include "A64Instruction.hh"
#include "RegisterFileSet.hh"
#include "gtest/gtest.h"

namespace {

// Test that we can create an A64Architecture object
TEST(ISATest, CreateA64Arch) {
  std::unique_ptr<simeng::Architecture> isa =
      std::make_unique<simeng::A64Architecture>();

  EXPECT_GT(isa->getRegisterFileStructures().size(), 0);
}

// Test that we can set a value in a register file set
TEST(ISATest, CreateRegisterFileSet) {
  auto registerFileSet = simeng::RegisterFileSet({{32, 8}, {32, 16}, {1, 1}});
  auto reg = simeng::Register{simeng::A64RegisterType::GENERAL, 0};

  registerFileSet.set(reg, 42);

  EXPECT_TRUE(registerFileSet.get(reg));
}

}  // namespace
