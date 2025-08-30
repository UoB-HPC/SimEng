#include "SimEngAcceleratorWrapper.hh"

#include "OffloadingEvent.hh"
#include "simeng/models/accelerator/SmeAccelerator.hh"

using namespace SST::SSTSimEng;
using namespace SST::Interfaces;

SimEngAcceleratorWrapper::SimEngAcceleratorWrapper(const ComponentId_t id,
                                                   const Params& params)
    : Component(id) {
  output_.init("[SSTSimEng:SimEngAcceleratorWrapper] " + getName() + ":@p:@l ",
               999, 0, Output::STDOUT);
  clock_ = registerClock(params.find<std::string>("clock", "1GHz"),
                         new Clock::Handler<SimEngAcceleratorWrapper>(
                             this, &SimEngAcceleratorWrapper::clockTick));

  // Extract variables from config.py
  simengConfigPath_ = params.find<std::string>("simeng_config_path", "");
  cacheLineWidth_ = params.find<uint64_t>("cache_line_width", "64");
  maxAddrMemory_ = params.find<uint64_t>("max_addr_memory", "0");
  debug_ = params.find<bool>("debug", false);
  debugLevel_ =
      static_cast<DebugLevel>(params.find("debug_level", debug_ ? 2 : 0));

  // Connect with a SimEng core
  coreLink_ = configureLink("core_link");
  if (coreLink_ == nullptr) {
    output_.verbose(CALL_INFO, 1, 0,
                    "Could not configure the link with the core");
    std::exit(EXIT_FAILURE);
  }

  // Instantiate the StandardMem Interface defined in config.py
  sstMem_ = loadUserSubComponent<StandardMem>(
      "memory", ComponentInfo::SHARE_NONE, clock_,
      new StandardMem::Handler<SimEngAcceleratorWrapper>(
          this, &SimEngAcceleratorWrapper::handleMemoryEvent));

  dataMemory_ = std::make_shared<SimEngMemInterface>(
      sstMem_, cacheLineWidth_, maxAddrMemory_,
      debugLevel_ >= DebugLevel::Memory);

  handlers_ = new SimEngMemInterface::SimEngMemHandlers(*dataMemory_, &output_);
}

SimEngAcceleratorWrapper::~SimEngAcceleratorWrapper() = default;

void SimEngAcceleratorWrapper::setup() {
  sstMem_->setup();
  output_.verbose(CALL_INFO, 1, 0, "Memory setup complete\n");
}

// ReSharper disable once CppMemberFunctionMayBeConst
void SimEngAcceleratorWrapper::handleMemoryEvent(
    StandardMem::Request* memEvent) {
  memEvent->handle(handlers_);
}

void SimEngAcceleratorWrapper::finish() {}

void SimEngAcceleratorWrapper::init(const unsigned int phase) {
  sstMem_->init(phase);
  // Init can have multiple phases, only fabricate the accelerator once
  // at the correct phase (i.e. after the core)
  if (phase == LAST_INIT_PHASE) {
    fabricateSimEngAccelerator();
  }
}

// ReSharper disable once CppMemberFunctionMayBeConst
bool SimEngAcceleratorWrapper::clockTick(Cycle_t currentCycle) {
  // Tick the data memory
  dataMemory_->tick();

  // Tick the accelerator
  accelerator_->tick();

  return false;
}

void SimEngAcceleratorWrapper::fabricateSimEngAccelerator() {
  output_.verbose(CALL_INFO, 1, 0, "Setting up SimEng Accelerator\n");
  if (simengConfigPath_.empty()) {
    output_.verbose(CALL_INFO, 1, 0,
                    "No SimEng accelerator configuration provided\n");
    std::exit(EXIT_FAILURE);
  }

  acceleratorInstance_ = std::make_unique<AcceleratorInstance>(
      simengConfigPath_,
      [this](const auto& insn) { return sendOffloadingEvent(insn); },
      [this] { return recvOffloadingEvent(); });

  // Set the SST data memory SimEng should use
  acceleratorInstance_->setL1DataMemory(dataMemory_);

  // Construct accelerator
  acceleratorInstance_->createAccelerator();
  accelerator_ = acceleratorInstance_->getAccelerator();

  output_.verbose(CALL_INFO, 1, 0, "SimEng accelerator setup successfully\n");

  // Output general simulation details
  const auto& info = acceleratorInstance_->getAcceleratorInfo();
  constexpr auto PREFIX = "[SimEng]        ";
  std::cout << "[SimEng] Accelerator info:" << std::endl;
  std::cout << PREFIX << "Type: " << info.getTypeString() << std::endl;
  std::cout << PREFIX << "Config file: " << info.getConfigPath() << std::endl;
  std::cout << PREFIX << "ISA: " << info.getISAString() << std::endl;
  std::cout << PREFIX << "Simulation mode: " << info.getSimModeString()
            << std::endl;
  std::cout << std::endl;
}

bool SimEngAcceleratorWrapper::sendOffloadingEvent(
    const OffloadingEvent::packet_t& packet) const {
  if (debugLevel_ >= DebugLevel::Offloading) {
    switch (packet.data_.payload_.type_) {
      case OffloadingPayload::Type::Schedule: {
        assert(false &&
               "Accelerators cannot schedule instructions on the core");
      }
      case OffloadingPayload::Type::Commit: {
        const auto* addr = reinterpret_cast<void*>(
            packet.data_.payload_.insn_->getInstructionAddress());
        std::cout << "[SimEng:Aclr] SEND: " << packet.data_.payload_.id_ << " ("
                  << addr << ')' << std::endl;
        break;
      }
      case OffloadingPayload::Type::Flush: {
        std::cout << "[SimEng:Aclr] FLSH: " << packet.data_.payload_.id_
                  << std::endl;
        break;
      }
      case OffloadingPayload::Type::Flushed: {
        assert(false && "Accelerators cannot confirm flushes");
      }
    }
  }

  coreLink_->send(new OffloadingEvent(packet));
  return true;
}

std::optional<OffloadingEvent::packet_t>
SimEngAcceleratorWrapper::recvOffloadingEvent() const {
  const auto* event = dynamic_cast<OffloadingEvent*>(coreLink_->recv());
  if (event == nullptr) return std::nullopt;

  auto packet = event->deserialize(acceleratorInstance_->getArch());
  delete event;

  if (debugLevel_ >= DebugLevel::Offloading) {
    switch (packet.data_.payload_.type_) {
      case OffloadingPayload::Type::Schedule: {
        const auto* addr = reinterpret_cast<void*>(
            packet.data_.payload_.insn_->getInstructionAddress());
        std::cout << "[SimEng:Aclr] RECV: " << packet.data_.payload_.id_ << " ("
                  << addr << ')' << std::endl;
        break;
      }
      case OffloadingPayload::Type::Commit: {
        assert(false && "Cores cannot commit instructions on accelerators");
      }
      case OffloadingPayload::Type::Flush: {
        assert(false && "Cores cannot request flushes from accelerators");
      }
      case OffloadingPayload::Type::Flushed: {
        std::cout << "[SimEng:Aclr] FLED: " << packet.data_.payload_.id_
                  << std::endl;
        break;
      }
    }
  }

  return std::move(packet);
}
