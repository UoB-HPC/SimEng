#include "simeng/AcceleratorInstance.hh"

#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/riscv/Architecture.hh"
#include "simeng/models/outoforder/Core.hh"
#include "simeng/pipeline/A64FXPortAllocator.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"
#include "simeng/pipeline/M1PortAllocator.hh"

namespace simeng {

AcceleratorInstance::AcceleratorInstance(
    const std::string& configPath, Accelerator::gateway_t::send_fn_t sendFn,
    Accelerator::gateway_t::receive_fn_t recvFn)
    : info_(std::make_unique<config::AcceleratorInfo>(configPath)),
      sendFn_(std::move(sendFn)),
      recvFn_(std::move(recvFn)),
      kernel_(
          kernel::Linux(info_->getConfig()["CPU-Info"]["Special-File-Dir-Path"]
                            .as<std::string>())) {
  generateAcceleratorModel();
}

void AcceleratorInstance::generateAcceleratorModel() {
  const auto memTypeStr =
      info_->getConfig()["L1-Data-Memory"]["Interface-Type"].as<std::string>();
  // TODO: Do other types of interfaces work as well?
  assert(memTypeStr == "External" &&
         "Only External data memory interface is currently supported");
  constexpr auto memType = memory::MemInterfaceType::External;
  if constexpr (memType == memory::MemInterfaceType::External) {
    setMemory_ = true;
  }
}

void AcceleratorInstance::setL1DataMemory(
    std::shared_ptr<memory::MemoryInterface> memRef) {
  assert(setMemory_ &&
         "setL1DataMemory(...) called but the interface was created by the "
         "AcceleratorInstance class.");
  dataMemory_ = std::move(memRef);
}

void AcceleratorInstance::createAccelerator() {
  const auto config = info_->getConfig();

  // If memory interface must be manually set, ensure it has been
  if (setMemory_ && dataMemory_ == nullptr) {
    std::cerr << "[SimEng:AcceleratorInstance] Data memory not set. "
                 "External Data memory must be manually "
                 "set using the setL1DataMemory(...) function."
              << std::endl;
    exit(EXIT_FAILURE);
  }

  // Create the architecture, with knowledge of the OS
  if (info_->getISA() == config::ISA::RV64) {
    arch_ = std::make_unique<arch::riscv::Architecture>(kernel_);
  } else if (info_->getISA() == config::ISA::AArch64) {
    arch_ = std::make_unique<arch::aarch64::Architecture>(kernel_, info_);
  }

  // Extract the port arrangement from the config file
  const auto config_ports = config["Ports"];
  std::vector<std::vector<uint16_t>> portArrangement(
      config_ports.num_children());
  for (size_t i = 0; i < config_ports.num_children(); i++) {
    const auto config_groups =
        config_ports[i]["Instruction-Group-Support-Nums"];
    // Read groups in associated port
    for (size_t j = 0; j < config_groups.num_children(); j++) {
      const auto grp = config_groups[j].as<uint16_t>();
      portArrangement[i].push_back(grp);
    }
  }

  // Initialize the desired port allocator
  const auto portAllocatorType =
      config["Port-Allocator"]["Type"].as<std::string>();
  if (portAllocatorType == "Balanced") {
    portAllocator_ =
        std::make_unique<pipeline::BalancedPortAllocator>(portArrangement);
  } else if (portAllocatorType == "A64FX") {
    portAllocator_ =
        std::make_unique<pipeline::A64FXPortAllocator>(portArrangement);
  } else if (portAllocatorType == "M1") {
    // Extract the reservation station arrangement from the config file
    const auto config_rs = config["Reservation-Stations"];
    std::vector<std::pair<uint16_t, uint64_t>> rsArrangement;
    for (size_t i = 0; i < config_rs.num_children(); i++) {
      auto config_rs_ports = config_rs[i]["Port-Nums"];
      for (size_t j = 0; j < config_rs_ports.num_children(); j++) {
        const auto port = config_rs_ports[j].as<uint16_t>();
        if (static_cast<uint16_t>(rsArrangement.size()) < port + 1) {
          rsArrangement.resize(port + 1);
        }
        rsArrangement[port] = {i, config_rs[i]["Size"].as<uint64_t>()};
      }
    }
    portAllocator_ = std::make_unique<pipeline::M1PortAllocator>(
        portArrangement, rsArrangement);
  } else {
    std::cerr
        << "[SimEng:AcceleratorInstance] Invalid Port Allocator type selected."
        << std::endl;
    exit(EXIT_FAILURE);
  }

  // Construct the accelerator object based on the defined type
  switch (info_->getType()) {
    using config::AcceleratorType;

    case AcceleratorType::AArch64_SME: {
      accelerator_ = std::make_shared<models::accelerator::SmeAccelerator>(
          sendFn_, recvFn_, *dataMemory_, *portAllocator_, info_);
      break;
    }
    case AcceleratorType::Undefined: {
      std::cerr << "[SimEng:AcceleratorInstance] Undefined accelerator type."
                << std::endl;
      exit(EXIT_FAILURE);
    }
  }
}

std::shared_ptr<Accelerator> AcceleratorInstance::getAccelerator() const {
  if (accelerator_ == nullptr) {
    std::cerr
        << "[SimEng:AcceleratorInstance] Accelerator object not constructed. "
           "If data memory interface is marked as an `External` type, it must "
           "be set manually and then accelerator's creation must be called "
           "manually."
        << std::endl;
    exit(EXIT_FAILURE);
  }
  return accelerator_;
}

std::shared_ptr<memory::MemoryInterface> AcceleratorInstance::getDataMemory()
    const {
  if (setMemory_ && dataMemory_ == nullptr) {
    std::cerr
        << "[SimEng:AcceleratorInstance] `External` data memory object not set."
        << std::endl;
    exit(EXIT_FAILURE);
  }
  return dataMemory_;
}

const config::AcceleratorInfo& AcceleratorInstance::getAcceleratorInfo() const {
  return *info_;
}

const arch::Architecture& AcceleratorInstance::getArch() const {
  return *arch_;
}

std::vector<config::AcceleratorType>
AcceleratorInstance::getAcceleratorTypesFromNames(
    const std::vector<std::string>& names) {
  std::vector<config::AcceleratorType> types;
  types.reserve(names.size());
  for (const auto& name : names) {
    types.push_back(config::parseAcceleratorType(name));
  }
  return types;
}

config::OffloadingLogic::is_ready_vtable_t
AcceleratorInstance::getIsReadyVTable(
    const std::vector<config::AcceleratorType>& accelerators) {
  config::OffloadingLogic::is_ready_vtable_t vtable{};
  for (const auto& accelerator : accelerators) {
    const auto id = config::acceleratorIdFromType(accelerator);
    switch (accelerator) {
      case config::AcceleratorType::Undefined: {
        assert(false && "Undefined accelerator type");
      }
      case config::AcceleratorType::AArch64_SME: {
        vtable[id] = models::accelerator::SmeAccelerator::isInstructionReady;
        break;
      }
    }
  }
  return vtable;
}

config::OffloadingLogic::register_filter_vtable_t
AcceleratorInstance::getRegisterFilterVTable(
    const std::vector<config::AcceleratorType>& accelerators) {
  config::OffloadingLogic::register_filter_vtable_t vtable{};
  for (const auto& accelerator : accelerators) {
    const auto id = config::acceleratorIdFromType(accelerator);
    switch (accelerator) {
      case config::AcceleratorType::Undefined: {
        assert(false && "Undefined accelerator type");
      }
      case config::AcceleratorType::AArch64_SME: {
        vtable[id] = models::accelerator::SmeAccelerator::isRegisterOffloaded;
        break;
      }
    }
  }
  return vtable;
}

}  // namespace simeng
