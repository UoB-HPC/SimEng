#include "AArch64RegressionTest.hh"

#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"

using namespace simeng::arch::aarch64;

void AArch64RegressionTest::run(const char* source) {
  RegressionTest::run(source, "aarch64");
}

std::unique_ptr<simeng::arch::Architecture>
AArch64RegressionTest::createArchitecture(simeng::kernel::Linux& kernel) const {
  return std::make_unique<Architecture>(kernel);
}

std::unique_ptr<simeng::pipeline::PortAllocator>
AArch64RegressionTest::createPortAllocator() const {
  // TODO: this is currently tightly coupled to the number of execution units,
  // which is specified in the out-of-order core model
  const std::vector<std::vector<std::vector<std::pair<uint16_t, uint8_t>>>>
      portArrangement = {
          {{{simeng::arch::aarch64::InstructionGroups::LOAD, 0},
            {simeng::arch::aarch64::InstructionGroups::SHIFT, 1},
            {simeng::arch::aarch64::InstructionGroups::ASIMD, 1}}},  // Port 4
          {{{simeng::arch::aarch64::InstructionGroups::LOAD, 0},
            {simeng::arch::aarch64::InstructionGroups::SHIFT, 1},
            {simeng::arch::aarch64::InstructionGroups::ASIMD, 1}}},  // Port 5
          {{{simeng::arch::aarch64::InstructionGroups::STORE, 0},
            {simeng::arch::aarch64::InstructionGroups::SHIFT, 1},
            {simeng::arch::aarch64::InstructionGroups::ASIMD, 1}}},  // Port 3
          {{{simeng::arch::aarch64::InstructionGroups::ARITHMETIC, 0},
            {simeng::arch::aarch64::InstructionGroups::SHIFT, 1},
            {simeng::arch::aarch64::InstructionGroups::MULTIPLY, 1}},
           {{simeng::arch::aarch64::InstructionGroups::BRANCH, 0}}},  // Port 2
          {{{simeng::arch::aarch64::InstructionGroups::ARITHMETIC, 0},
            {simeng::arch::aarch64::InstructionGroups::SHIFT, 1},
            {simeng::arch::aarch64::InstructionGroups::MULTIPLY, 1}},
           {{simeng::arch::aarch64::InstructionGroups::ASIMD, 0},
            {simeng::arch::aarch64::InstructionGroups::SHIFT, 1},
            {simeng::arch::aarch64::InstructionGroups::MULTIPLY, 1},
            {simeng::arch::aarch64::InstructionGroups::DIVIDE, 1}}},  // Port 0
          {{{simeng::arch::aarch64::InstructionGroups::ARITHMETIC, 0},
            {simeng::arch::aarch64::InstructionGroups::SHIFT, 1},
            {simeng::arch::aarch64::InstructionGroups::MULTIPLY, 1},
            {simeng::arch::aarch64::InstructionGroups::DIVIDE, 1}},
           {{simeng::arch::aarch64::InstructionGroups::ASIMD, 0},
            {simeng::arch::aarch64::InstructionGroups::SHIFT, 1},
            {simeng::arch::aarch64::InstructionGroups::MULTIPLY, 1},
            {simeng::arch::aarch64::InstructionGroups::DIVIDE, 1}}}  // Port 1
      };

  return std::make_unique<simeng::pipeline::BalancedPortAllocator>(
      portArrangement);
}

uint8_t AArch64RegressionTest::getNZCV() const {
  return getRegister<uint8_t>({RegisterType::NZCV, 0});
}

bool AArch64RegressionTest::getNegativeFlag() const {
  return (getNZCV() >> 3) & 1;
}

bool AArch64RegressionTest::getZeroFlag() const { return (getNZCV() >> 2) & 1; }

bool AArch64RegressionTest::getCarryFlag() const {
  return (getNZCV() >> 1) & 1;
}

bool AArch64RegressionTest::getOverflowFlag() const {
  return (getNZCV() >> 0) & 1;
}
