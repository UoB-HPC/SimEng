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
  const std::vector<std::vector<uint16_t>> portArrangement = {
      {InstructionGroups::LOAD, InstructionGroups::STORE},
      {InstructionGroups::ARITHMETIC},
      {InstructionGroups::ARITHMETIC, InstructionGroups::BRANCH}};
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
