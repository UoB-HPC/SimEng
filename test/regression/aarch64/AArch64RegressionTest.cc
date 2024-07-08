#include "AArch64RegressionTest.hh"

#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"

using MacroOp = std::vector<std::shared_ptr<simeng::Instruction>>;
using namespace simeng::arch::aarch64;

void AArch64RegressionTest::run(const char* source) {
  // Initialise LLVM
  LLVMInitializeAArch64TargetInfo();
  LLVMInitializeAArch64TargetMC();
  LLVMInitializeAArch64AsmParser();

  const char* subtargetFeatures;
#if SIMENG_LLVM_VERSION < 14
  subtargetFeatures = "+sve,+lse";
#else
  subtargetFeatures = "+sve,+lse,+sve2,+sme,+sme-f64";
#endif

  RegressionTest::run(source, "aarch64", subtargetFeatures);
}

void AArch64RegressionTest::generateConfig() const {
  // Re-generate the default config for the AArch64 ISA
  simeng::config::SimInfo::generateDefault(simeng::config::ISA::AArch64, true);

  // Add the base additional AArch64 test suite config options
  simeng::config::SimInfo::addToConfig(AARCH64_ADDITIONAL_CONFIG);
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
AArch64RegressionTest::instantiateArchitecture(
    simeng::kernel::Linux& kernel) const {
  return std::make_unique<Architecture>(kernel);
}

std::unique_ptr<simeng::pipeline::PortAllocator>
AArch64RegressionTest::createPortAllocator(ryml::ConstNodeRef config) const {
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

void AArch64RegressionTest::checkGroup(const char* source,
                                       const std::vector<int> expectedGroups,
                                       const char* extensions) {
  // Initialise LLVM
  LLVMInitializeAArch64TargetInfo();
  LLVMInitializeAArch64TargetMC();
  LLVMInitializeAArch64AsmParser();

  const char* subtargetFeatures;
#if SIMENG_LLVM_VERSION < 14
  subtargetFeatures = "+sve,+lse";
#else
  subtargetFeatures = "+sve,+lse,+sve2,+sme,+sme-f64";
#endif

  RegressionTest::createArchitecture(source, "aarch64", subtargetFeatures);

  MacroOp macroOp;
  architecture_->predecode(code_, 4, 0, macroOp);

  // TODO doesn't stop execution so for loop below could access out of bounds
  // memory
  // Check that there is one expectation group per micro-op
  EXPECT_EQ(macroOp.size(), expectedGroups.size());

  // Check each
  for (size_t i = 0; i < macroOp.size(); i++) {
    auto group = macroOp[i]->getGroup();
    EXPECT_EQ(group, expectedGroups[i]);
  }
}
