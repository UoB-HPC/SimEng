#include "simeng/CoreInstance.hh"

namespace simeng {

CoreInstance::CoreInstance(std::shared_ptr<memory::MMU> mmu,
                           arch::sendSyscallToHandler handleSyscall)
    : config_(Config::get()), mmu_(mmu), handleSyscall_(handleSyscall) {
  setSimulationMode();
  createCore();
}

void CoreInstance::createCore() {
  // Create the architecture, with knowledge of the OS
  if (SimInfo::getISA() == ISA::RV64) {
    arch_ = std::make_unique<simeng::arch::riscv::Architecture>();
  } else if (SimInfo::getISA() == ISA::AArch64) {
    arch_ = std::make_unique<simeng::arch::aarch64::Architecture>();
  }

  // Construct branch predictor object
  predictor_ = std::make_unique<simeng::GenericPredictor>();

  // Extract port arrangement from config file
  auto config_ports = config_["Ports"];
  std::vector<std::vector<uint16_t>> portArrangement(config_ports.size());
  for (size_t i = 0; i < config_ports.size(); i++) {
    auto config_groups = config_ports[i]["Instruction-Group-Support"];
    // Read groups in associated port
    for (size_t j = 0; j < config_groups.size(); j++) {
      portArrangement[i].push_back(config_groups[j].as<uint16_t>());
    }
  }
  portAllocator_ = std::make_unique<simeng::pipeline::BalancedPortAllocator>(
      portArrangement);

  // Construct the core object based on the defined simulation mode
  if (SimInfo::getSimMode() == simMode::emulation) {
    core_ = std::make_shared<simeng::models::emulation::Core>(*arch_, mmu_,
                                                              handleSyscall_);
  } else if (SimInfo::getSimMode() == simMode::inorder) {
    core_ = std::make_shared<simeng::models::inorder::Core>(
        *arch_, *predictor_, mmu_, handleSyscall_);
  } else if (SimInfo::getSimMode() == simMode::outoforder) {
    core_ = std::make_shared<simeng::models::outoforder::Core>(
        *arch_, *predictor_, mmu_, *portAllocator_, handleSyscall_);
  }
  return;
}

std::shared_ptr<simeng::Core> CoreInstance::getCore() const {
  if (core_ == nullptr) {
    std::cerr
        << "[SimEng:CoreInstance] Core object not constructed. If either data "
           "or instruction memory "
           "interfaces are marked as an `External` type, they must be set "
           "manually and then core's creation must be called manually."
        << std::endl;
    exit(1);
  }
  return core_;
}

}  // namespace simeng
