// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include "SimengCoreWrapper.hh"

#include <cstdlib>
#include <iostream>

using namespace SST::SSTSimeng;
using namespace SST::Interfaces;

enum class SimulationMode { Emulation, InOrderPipelined, OutOfOrder };

SimengCoreWrapper::SimengCoreWrapper(SST::ComponentId_t id, SST::Params& params)
    : SST::Component(id) {
  output_.init("SimengCoreWrapper[" + getName() + ":@p:@t]:", 999, 0,
               SST::Output::STDOUT);
  clock_ = registerClock(params.find<std::string>("clock", "1GHz"),
                         new SST::Clock::Handler<SimengCoreWrapper>(
                             this, &SimengCoreWrapper::clockTick));

  // Extract variables from config.py
  executablePath_ = params.find<std::string>("executable_path", "");
  executableArgs_ = params.find<std::string>("executable_args", "");
  configPath_ = params.find<std::string>("config_path", "");
  cacheLineWidth_ = params.find<uint64_t>("cache_line_width", "64");
  maxAddrMemory_ = params.find<uint64_t>("max_addr_memory", "0");

  if (executablePath_.length() == 0) {
    output_.fatal(CALL_INFO, 10, 0,
                  "Simeng executable binary filepath not provided.");
  }
  if (maxAddrMemory_ == 0) {
    output_.fatal(CALL_INFO, 10, 0,
                  "Maximum address range for memory not provided");
  }

  iterations_ = 0;
  vitrualCounter_ = 0;

  // Instantiate the StandardMem Interface defined in config.py
  mem_ = loadUserSubComponent<SST::Interfaces::StandardMem>(
      "memory", ComponentInfo::SHARE_NONE, clock_,
      new StandardMem::Handler<SimengCoreWrapper>(
          this, &SimengCoreWrapper::handleEvent));

  dataMemory_ = std::make_unique<SimengMemInterface>(mem_, cacheLineWidth_,
                                                     maxAddrMemory_, &output_);

  handlers_ = new SimengMemInterface::SimengMemHandlers(*dataMemory_, &output_);

  // Protected methods from SST::Component used to start simulation
  registerAsPrimaryComponent();
  primaryComponentDoNotEndSim();
}

SimengCoreWrapper::~SimengCoreWrapper() {}

void SimengCoreWrapper::setup() {
  mem_->setup();
  output_.verbose(CALL_INFO, 1, 0, "Memory setup complete\n");
}

void SimengCoreWrapper::handleEvent(StandardMem::Request* ev) {
  ev->handle(handlers_);
}

void SimengCoreWrapper::finish() {
  output_.verbose(CALL_INFO, 1, 0,
                  "Simulation complete. Finalising stats....\n");

  auto endTime = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                      endTime - startTime_)
                      .count();
  double hz = iterations_ / (static_cast<double>(duration) / 1000.0);
  double khz = hz / 1000.0;
  uint64_t retired = core_->getInstructionsRetiredCount();
  double mips = retired / static_cast<double>(duration) / 1000.0;

  // Print stats
  std::cout << "\n";
  auto stats = core_->getStats();
  for (const auto& [key, value] : stats) {
    std::cout << key << ": " << value << "\n";
  }

  std::cout << "\nFinished " << iterations_ << " ticks in " << duration
            << "ms (" << std::round(khz) << " kHz, " << std::setprecision(2)
            << mips << " MIPS)" << std::endl;

  delete[] processMemory_;
}

void SimengCoreWrapper::init(unsigned int phase) {
  mem_->init(phase);
  // Init can have multiple phases, only fabricate the core once at phase 0
  if (phase == 0) {
    fabricateSimengCore();
  }
}

bool SimengCoreWrapper::clockTick(SST::Cycle_t current_cycle) {
  // Tick the core and memory interfaces until the program has halted
  if (!core_->hasHalted() || dataMemory_->hasPendingRequests()) {
    // Tick the core
    core_->tick();
    // Update Virtual Counter Timer at correct frequency.
    if (iterations_ % (uint64_t)timerModulo_ == 0) {
      vitrualCounter_++;
      core_->incVCT(vitrualCounter_);
    }

    // Tick memory
    instructionMemory_->tick();
    dataMemory_->tick();

    iterations_++;

    return false;
  } else {
    // Protected method from SST::Component used to end SST simulation
    primaryComponentOKToEndSim();
    return true;
  }
}

void SimengCoreWrapper::fabricateSimengCore() {
  output_.verbose(CALL_INFO, 1, 0, "Setting up SimEng Core\n");

  SimulationMode mode = SimulationMode::InOrderPipelined;
  std::string modeString;
  YAML::Node config;

  if (configPath_ != "") {
    config = simeng::ModelConfig(configPath_).getConfigFile();
  } else {
    config = YAML::Load(DEFAULT_CONFIG);
  }

  if (config["Core"]["Simulation-Mode"].as<std::string>() == "inorder") {
    output_.fatal(CALL_INFO, 1, 0,
                  "SimEng SST build does not support in-order mode yet!\n");
  }

  if (config["Core"]["Simulation-Mode"].as<std::string>() == "outoforder") {
    mode = SimulationMode::OutOfOrder;
    modeString = "Out-of-Order";
  } else {
    mode = SimulationMode::Emulation;
    modeString = "Emulation";
  }

  float clockFreq_ = config["Core"]["Clock-Frequency"].as<float>();
  uint32_t timerFreq_ = config["Core"]["Timer-Frequency"].as<uint32_t>();
  timerModulo_ = (clockFreq_ * 1e9) / (timerFreq_ * 1e6);

  // Create the process Image
  std::vector<std::string> commandLine({executablePath_, executableArgs_});
  process_ =
      std::make_unique<simeng::kernel::LinuxProcess>(commandLine, config);
  if (!process_->isValid())
    output_.fatal(CALL_INFO, 1, 0, "Could not read/parse %s", executablePath_);

  auto processImage = process_->getProcessImage();
  size_t processMemorySize = processImage.size();
  processMemory_ = new char[processMemorySize]();
  std::copy(processImage.begin(), processImage.end(), processMemory_);

  // This check ensure that SST has enough memory to store the entire
  // processImage constructed by SimEng.
  if (maxAddrMemory_ < processMemorySize) {
    output_.verbose(
        CALL_INFO, 1, 0,
        "Error: SST backend memory is less than processImage size. Please "
        "increase the memory allocated to memHierarchy.memBackend and "
        "ensure it is consistent with \'max_addr_memory\' and "
        "\'addr_range_end\'. \n");
    primaryComponentOKToEndSim();
    std::exit(EXIT_FAILURE);
  }

  uint64_t entryPoint = process_->getEntryPoint();

  // Create the OS kernel with the process
  kernel_ = std::make_unique<simeng::kernel::Linux>();
  kernel_->createProcess(*process_.get());

  instructionMemory_ = std::make_unique<simeng::FlatMemoryInterface>(
      processMemory_, processMemorySize);

  // Create the architecture, with knowledge of the kernel
  arch_ =
      std::make_unique<simeng::arch::aarch64::Architecture>(*kernel_, config);

  predictor_ = std::make_unique<simeng::BTBPredictor>(
      config["Branch-Predictor"]["BTB-bitlength"].as<uint8_t>());
  auto config_ports = config["Ports"];
  std::vector<std::vector<uint16_t>> portArrangement(config_ports.size());
  // Extract number of ports
  for (size_t i = 0; i < config_ports.size(); i++) {
    auto config_groups = config_ports[i]["Instruction-Group-Support"];
    // Extract number of groups in port
    for (size_t j = 0; j < config_groups.size(); j++) {
      portArrangement[i].push_back(config_groups[j].as<uint16_t>());
    }
  }
  portAllocator_ = std::make_unique<simeng::pipeline::BalancedPortAllocator>(
      portArrangement);

  // Configure reservation station arrangment
  std::vector<std::pair<uint8_t, uint64_t>> rsArrangement;
  for (size_t i = 0; i < config["Reservation-Stations"].size(); i++) {
    auto reservation_station = config["Reservation-Stations"][i];
    for (size_t j = 0; j < reservation_station["Ports"].size(); j++) {
      uint8_t port = reservation_station["Ports"][j].as<uint8_t>();
      if (rsArrangement.size() < port + 1) {
        rsArrangement.resize(port + 1);
      }
      rsArrangement[port] = {i, reservation_station["Size"].as<uint16_t>()};
    }
  }

  if (mode == SimulationMode::OutOfOrder) {
    modeString = "Out-of-Order";
    core_ = std::make_unique<simeng::models::outoforder::Core>(
        *instructionMemory_, *dataMemory_, processMemorySize, entryPoint,
        *arch_, *predictor_, *portAllocator_, rsArrangement, config);
  } else {
    modeString = "Emulation";
    core_ = std::make_unique<simeng::models::emulation::Core>(
        *instructionMemory_, *dataMemory_, entryPoint, processMemorySize,
        *arch_);
  }

  simeng::SpecialFileDirGen SFdir = simeng::SpecialFileDirGen(config);
  // Create the Special Files directory if indicated to do so in Config
  if (config["CPU-Info"]["Generate-Special-Dir"].as<std::string>() == "T") {
    // Remove any current special files dir
    SFdir.RemoveExistingSFDir();
    // Create new special files dir
    SFdir.GenerateSFDir();
  }

  dataMemory_->sendProcessImageToSST(processImage);

  output_.verbose(CALL_INFO, 1, 0, "SimEng core setup successfully.\n");
  std::cout << "Running in " << modeString << " mode." << std::endl;
  output_.verbose(CALL_INFO, 1, 0, "Starting simulation.\n");
  startTime_ = std::chrono::high_resolution_clock::now();
}
