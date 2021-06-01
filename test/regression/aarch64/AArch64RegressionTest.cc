#include "AArch64RegressionTest.hh"

#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"

using namespace simeng::arch::aarch64;

void AArch64RegressionTest::run(const char* source) {
  RegressionTest::run(source, "aarch64");
}

YAML::Node AArch64RegressionTest::generateConfig() const {
  YAML::Node config = YAML::Load(TX2_CONFIG);
  switch (GetParam()) {
    case EMULATION:
      config["Core"]["Simulation-Mode"] = "emulation";
      break;
    case INORDER:
      config["Core"]["Simulation-Mode"] = "inorderpipeline";
      break;
    case OUTOFORDER:
      config["Core"]["Simulation-Mode"] = "outoforder";
      break;
  }
  return config;
}

std::unique_ptr<simeng::arch::Architecture>
AArch64RegressionTest::createArchitecture(simeng::kernel::Linux& kernel,
                                          YAML::Node config) const {
  return std::make_unique<Architecture>(kernel, config);
}

std::unique_ptr<simeng::pipeline::PortAllocator>
AArch64RegressionTest::createPortAllocator() const {
  // TODO: this is currently tightly coupled to the number of execution units,
  // which is specified in the out-of-order core model
  const std::vector<std::vector<uint16_t>> portArrangement = {
      {simeng::arch::aarch64::InstructionGroups::INT_SIMPLE,
       simeng::arch::aarch64::InstructionGroups::INT_MUL,
       simeng::arch::aarch64::InstructionGroups::FP_SIMPLE,
       simeng::arch::aarch64::InstructionGroups::FP_MUL,
       simeng::arch::aarch64::InstructionGroups::FP_DIV_OR_SQRT},  // Port 0
      {simeng::arch::aarch64::InstructionGroups::INT_SIMPLE,
       simeng::arch::aarch64::InstructionGroups::INT_MUL,
       simeng::arch::aarch64::InstructionGroups::INT_DIV_OR_SQRT,
       simeng::arch::aarch64::InstructionGroups::FP_SIMPLE,
       simeng::arch::aarch64::InstructionGroups::FP_MUL,
       simeng::arch::aarch64::InstructionGroups::FP_DIV_OR_SQRT},  // Port 1
      {simeng::arch::aarch64::InstructionGroups::INT_SIMPLE,
       simeng::arch::aarch64::InstructionGroups::INT_MUL,
       simeng::arch::aarch64::InstructionGroups::BRANCH},  // Port 2
      {simeng::arch::aarch64::InstructionGroups::LOAD},    // Port 4
      {simeng::arch::aarch64::InstructionGroups::LOAD},    // Port 5
      {simeng::arch::aarch64::InstructionGroups::STORE}    // Port 3
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
