#include "RISCVRegressionTest.hh"

#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"

using MacroOp = std::vector<std::shared_ptr<simeng::Instruction>>;
using namespace simeng::arch::riscv;

void RISCVRegressionTest::run(const char* source, const char* extensions) {
  // Initialise LLVM
  LLVMInitializeRISCVTargetInfo();
  LLVMInitializeRISCVTargetMC();
  LLVMInitializeRISCVAsmParser();

  RegressionTest::run(source, "riscv64", extensions);
}

void RISCVRegressionTest::generateConfig() const {
  // Re-generate the default config for the rv64 ISA
  simeng::config::SimInfo::generateDefault(simeng::config::ISA::RV64, true);

  // Add the base additional RISCV test suite config options
  simeng::config::SimInfo::addToConfig(RISCV_ADDITIONAL_CONFIG);
  std::string mode;
  switch (std::get<0>(GetParam())) {
    case EMULATION:
      mode = "emulation";
      break;
    case INORDER:
      mode = "inorderpipelined";
      break;
    case OUTOFORDER:
      mode = "outoforder";
      break;
  }

  simeng::config::SimInfo::addToConfig("{Core: {Simulation-Mode: " + mode +
                                       "}}");

  // Add the test specific config options
  simeng::config::SimInfo::addToConfig(std::get<1>(GetParam()));
}

std::unique_ptr<simeng::arch::Architecture>
RISCVRegressionTest::instantiateArchitecture(
    simeng::kernel::Linux& kernel) const {
  return std::make_unique<Architecture>(kernel);
}

std::unique_ptr<simeng::pipeline::PortAllocator>
RISCVRegressionTest::createPortAllocator(ryml::ConstNodeRef config) const {
  // Extract the port arrangement from the config file
  std::vector<std::vector<uint16_t>> portArrangement(
      config["Ports"].num_children());
  for (size_t i = 0; i < config["Ports"].num_children(); i++) {
    auto config_groups = config["Ports"][i]["Instruction-Group-Support-Nums"];
    // Read groups in associated port
    for (size_t j = 0; j < config_groups.num_children(); j++) {
      portArrangement[i].push_back(config_groups[j].as<uint16_t>());
    }
  }
  return std::make_unique<simeng::pipeline::BalancedPortAllocator>(
      portArrangement);
}

void RISCVRegressionTest::checkGroup(const char* source,
                                     const std::vector<int> expectedGroups,
                                     const char* extensions) {
  // Initialise LLVM
  LLVMInitializeRISCVTargetInfo();
  LLVMInitializeRISCVTargetMC();
  LLVMInitializeRISCVAsmParser();

  RegressionTest::createArchitecture(source, "riscv64", extensions);

  MacroOp macroOp;
  architecture_->predecode(code_, 4, 0, macroOp);

  // Check that there is one expectation group per micro-op
  EXPECT_EQ(macroOp.size(), expectedGroups.size());

  // Check the assigned and expected group for each micro-op match
  for (size_t i = 0; i < macroOp.size(); i++) {
    auto group = macroOp[i]->getGroup();
    EXPECT_EQ(group, expectedGroups[i]);
  }
}
