#include "AArch64RegressionTest.hh"

#include "arch/aarch64/Architecture.hh"
#include "pipeline/BalancedPortAllocator.hh"

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

bool AArch64RegressionTest::getNegativeFlag() const {
  return (getRegister<uint8_t>({RegisterType::NZCV, 0}) >> 3) & 1;
}

bool AArch64RegressionTest::getZeroFlag() const {
  return (getRegister<uint8_t>({RegisterType::NZCV, 0}) >> 2) & 1;
}

bool AArch64RegressionTest::getCarryFlag() const {
  return (getRegister<uint8_t>({RegisterType::NZCV, 0}) >> 1) & 1;
}

bool AArch64RegressionTest::getOverflowFlag() const {
  return (getRegister<uint8_t>({RegisterType::NZCV, 0}) >> 0) & 1;
}
