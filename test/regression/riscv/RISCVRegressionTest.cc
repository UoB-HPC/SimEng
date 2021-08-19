#include "RISCVRegressionTest.hh"

#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"

using namespace simeng::arch::riscv;

void RISCVRegressionTest::run(const char* source) {
  // Initialise LLVM
  LLVMInitializeRISCVTargetInfo();
  LLVMInitializeRISCVTargetMC();
  LLVMInitializeRISCVAsmParser();

  RegressionTest::run(source, "riscv64", "+m,+a,+f,+d");
}
// TODO create yaml
YAML::Node RISCVRegressionTest::generateConfig() const {
  YAML::Node config = YAML::Load(RISCV_CONFIG);
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
RISCVRegressionTest::createArchitecture(simeng::kernel::Linux& kernel,
                                        YAML::Node config) const {
  return std::make_unique<Architecture>(kernel, config);
}

std::unique_ptr<simeng::pipeline::PortAllocator>
RISCVRegressionTest::createPortAllocator() const {
  // TODO: this is currently tightly coupled to the number of execution units,
  // which is specified in the out-of-order core model
  const std::vector<std::vector<uint16_t>> portArrangement = {
      {simeng::arch::riscv::InstructionGroups::ARITHMETIC}};

  return std::make_unique<simeng::pipeline::BalancedPortAllocator>(
      portArrangement);
}
