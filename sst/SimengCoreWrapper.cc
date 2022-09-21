// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include "SimengCoreWrapper.hh"

#include <cstdlib>
#include <iostream>

using namespace SST::SSTSimeng;
using namespace SST::Interfaces;

SimengCoreWrapper::SimengCoreWrapper(SST::ComponentId_t id, SST::Params& params)
    : SST::Component(id) {
  output_.init("SimengCoreWrapper[" + getName() + ":@p:@t]:", 999, 0,
               SST::Output::STDOUT);
  clock_ = registerClock(params.find<std::string>("clock", "1GHz"),
                         new SST::Clock::Handler<SimengCoreWrapper>(
                             this, &SimengCoreWrapper::clockTick));

  // Extract variables from config.py
  executablePath_ = params.find<std::string>("executable_path", "");
  executableArgs_ = splitArgs(params.find<std::string>("executable_args", ""));
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

  // Instantiate the StandardMem Interface defined in config.py
  mem_ = loadUserSubComponent<SST::Interfaces::StandardMem>(
      "memory", ComponentInfo::SHARE_NONE, clock_,
      new StandardMem::Handler<SimengCoreWrapper>(
          this, &SimengCoreWrapper::handleEvent));

  dataMemory_ = std::make_shared<SimengMemInterface>(mem_, cacheLineWidth_,
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
  double khz =
      (iterations_ / (static_cast<double>(duration) / 1000.0)) / 1000.0;
  uint64_t retired = core_->getInstructionsRetiredCount();
  double mips = retired / (static_cast<double>(duration) / 1000.0);

  // Print stats
  std::cout << "\n";
  auto stats = core_->getStats();
  for (const auto& [key, value] : stats) {
    std::cout << key << ": " << value << "\n";
  }

  std::cout << "\nFinished " << iterations_ << " ticks in " << duration
            << "ms (" << std::round(khz) << " kHz, " << std::setprecision(2)
            << mips << " MIPS)" << std::endl;
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

std::vector<std::string> SimengCoreWrapper::splitArgs(std::string argString) {
  std::vector<std::string> arguments = {};

  // Using a custom delimiter, split the argString string into individual
  // arguments and collate in a vector
  for (int c = 0; c < argString.length(); c++) {
    // Find starting delimiter
    if (argString[c] == '[') {
      c++;
      std::string newArg = "";
      while (argString[c] != ']') {
        newArg += argString[c];
        c++;
      }
      arguments.push_back(newArg);
    }
  }

  return arguments;
}

void SimengCoreWrapper::fabricateSimengCore() {
  output_.verbose(CALL_INFO, 1, 0, "Setting up SimEng Core\n");

  // Create the instance of the core to be simulated
  if (configPath_ != "") {
    coreInstance_ = std::make_unique<simeng::CoreInstance>(
        configPath_, executablePath_, executableArgs_);
  } else {
    coreInstance_ = std::make_unique<simeng::CoreInstance>(executablePath_,
                                                           executableArgs_);
  }

  // Set the SST data memory SimEng should use
  coreInstance_->setL1DataMemory(dataMemory_);

  // Construct core
  coreInstance_->createCore();

  // Get remaining simulation objects needed to forward simulation
  core_ = coreInstance_->getCore();
  instructionMemory_ = coreInstance_->getInstructionMemory();

  // This check ensure that SST has enough memory to store the entire
  // processImage constructed by SimEng.
  if (maxAddrMemory_ < coreInstance_->getProcessImageSize()) {
    output_.verbose(
        CALL_INFO, 1, 0,
        "Error: SST backend memory is less than processImage size. Please "
        "increase the memory allocated to memHierarchy.memBackend and "
        "ensure it is consistent with \'max_addr_memory\' and "
        "\'addr_range_end\'. \n");
    primaryComponentOKToEndSim();
    std::exit(EXIT_FAILURE);
  }

  // Send the process image data over to the SST memory
  dataMemory_->sendProcessImageToSST(coreInstance_->getProcessImage().get(),
                                     coreInstance_->getProcessImageSize());

  output_.verbose(CALL_INFO, 1, 0, "SimEng core setup successfully.\n");
  // Print out build metadata
  std::cout << "Build metadata:" << std::endl;
  std::cout << "\tVersion: " SIMENG_VERSION << std::endl;
  std::cout << "\tCompile Time - Date: " __TIME__ " - " __DATE__ << std::endl;
  std::cout << "\tBuild type: " SIMENG_BUILD_TYPE << std::endl;
  std::cout << "\tCompile options: " SIMENG_COMPILE_OPTIONS << std::endl;
  std::cout << "\tTest suite: " SIMENG_ENABLE_TESTS << std::endl;
  std::cout << std::endl;
  std::cout << "Running in " << coreInstance_->getSimulationModeString()
            << " mode." << std::endl;
  output_.verbose(CALL_INFO, 1, 0, "Starting simulation.\n");
  startTime_ = std::chrono::high_resolution_clock::now();
}
