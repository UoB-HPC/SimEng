#include "RISCVRegressionTest.hh"

#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"

using namespace simeng::arch::riscv;

void RISCVRegressionTest::run(const char* source, bool compressed) {
  initialiseLLVM();
  std::string subtargetFeatures = getSubtargetFeaturesString(compressed);

  RegressionTest::run(source, "riscv64", subtargetFeatures.c_str());
}

void RISCVRegressionTest::checkGroup(
    const char* source, const std::vector<uint16_t>& expectedGroups,
    bool compressed) {
  initialiseLLVM();
  std::string subtargetFeatures = getSubtargetFeaturesString(compressed);

  RegressionTest::checkGroup(source, "riscv64", subtargetFeatures.c_str(),
                             expectedGroups);
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
