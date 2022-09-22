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
  simengConfigPath_ = params.find<std::string>("simeng_config_path", "");
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
                                                     maxAddrMemory_);

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
std::string SimengCoreWrapper::trimSpaces(std::string strArgs) {
  int trailingEnd = -1;
  int leadingEnd = -1;
  for (int x = 0; x < strArgs.size(); x++) {
    int end = strArgs.size() - 1 - x;
    // Find the index, from the start of the string, which is not a space.
    if (strArgs.at(x) != ' ' && leadingEnd == -1) {
      leadingEnd = x;
    }
    // Find the index, from the end of the string, which is not a space.
    if (strArgs.at(end) != ' ' && trailingEnd == -1) {
      trailingEnd = end;
    }
    if (trailingEnd != -1 && leadingEnd != -1) {
      break;
    }
  }
  // The string has leading or trailing spaces, return the substring which
  // doesn't have those spaces.
  if (trailingEnd != -1 && leadingEnd != -1) {
    return strArgs.substr(leadingEnd, trailingEnd - leadingEnd + 1);
  }
  // The string does not have leading or trailing spaces, return the original
  // string.
  return strArgs;
};

std::vector<std::string> SimengCoreWrapper::splitArgs(std::string strArgs) {
  std::string trimmedStrArgs = trimSpaces(strArgs);
  std::string str = "";
  std::vector<std::string> args;
  std::size_t argSize = trimmedStrArgs.size();
  bool escapeSingle = false;
  bool escapeDouble = false;
  bool captureEscape = false;

  if (argSize == 0) {
    return args;
  }

  for (int x = 0; x < argSize; x++) {
    bool escaped = escapeDouble || escapeSingle;
    char currChar = trimmedStrArgs.at(x);
    if (captureEscape) {
      captureEscape = false;
      str += currChar;
    }
    // This if statement check for an escaped '\' in the string.
    // Any character after the '\' is appended to the current argument,
    // without any delimiting or escape behaviour.
    else if (currChar == '\\') {
      captureEscape = true;
    } else if (escaped) {
      // If a portion of the argument string starts with a single quote (") and
      // we encounter another single quote, capture the substring enclosed by a
      // valid set of single quotes into an argument without producing any
      // delimiting or escape behavior even with double quotes.
      // e.g "arg1=1 arg2='"Hi"' arg3=2" will be parsed as
      // std::vector<std::string>{arg1=1, arg2="Hi", arg3=2}
      if (currChar == '\'' && escapeSingle) {
        escapeSingle = 0;
      }
      // If a portion of the argument string starts with a double quote (") and
      // we encounter another double quote, capture the substring enclosed by a
      // valid set of double quotes into an argument without producing any
      // delimiting or escape behavior even with single quotes.
      // e.g "arg1=1 arg2="James' Car" arg3=2" will be parsed as
      // std::vector<std::string>{arg1=1, arg2=James' Car, arg3=2}
      else if (currChar == '\"' && escapeDouble) {
        escapeDouble = 0;
      } else {
        str += currChar;
      }
    } else {
      if (currChar == ' ') {
        if (str != "") {
          args.push_back(str);
          str = "";
        }
      }
      // Check for escape character ("), this signals the algorithm to capture
      // any char inside a set of ("") without producing any delimiting or
      // escape behavior.
      else if (currChar == '\"') {
        escapeDouble = 1;
        // Check for escape character ('), this signals the algorithm to capture
        // any char inside a set of ('') without producing any delimiting or
        // escape behavior.
      } else if (currChar == '\'') {
        escapeSingle = 1;
      } else {
        str += currChar;
      }
    }
  }
  if (escapeSingle || escapeDouble) {
    std::cerr << "Parsing failed: Invalid format - Please make sure all "
                 "characters/strings are escaped properly."
              << std::endl;
    exit(1);
  }
  args.push_back(str);
  return args;
}

void SimengCoreWrapper::fabricateSimengCore() {
  output_.verbose(CALL_INFO, 1, 0, "Setting up SimEng Core\n");

  // Create the instance of the core to be simulated
  if (simengConfigPath_ != "") {
    coreInstance_ = std::make_unique<simeng::CoreInstance>(
        simengConfigPath_, executablePath_, executableArgs_);
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

  // This check ensures that SST has enough memory to store the entire
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
