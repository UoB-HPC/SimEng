// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include "SimEngCoreWrapper.hh"

#include <cstdlib>
#include <iostream>

#include "Assemble.hh"

using namespace SST::SSTSimEng;
using namespace SST::Interfaces;

SimEngCoreWrapper::SimEngCoreWrapper(SST::ComponentId_t id, SST::Params& params)
    : SST::Component(id) {
  output_.init("[SSTSimEng:SimEngCoreWrapper] " + getName() + "@p:@l ", 999, 0,
               SST::Output::STDOUT);
  clock_ = registerClock(params.find<std::string>("clock", "1GHz"),
                         new SST::Clock::Handler<SimEngCoreWrapper>(
                             this, &SimEngCoreWrapper::clockTick));

  // Extract variables from config.py
  executablePath_ = params.find<std::string>("executable_path", "");
  executableArgs_ = splitArgs(params.find<std::string>("executable_args", ""));
  simengConfigPath_ = params.find<std::string>("simeng_config_path", "");
  cacheLineWidth_ = params.find<uint64_t>("cache_line_width", "64");
  maxAddrMemory_ = params.find<uint64_t>("max_addr_memory", "0");
  source_ = params.find<std::string>("source", "");
  assembleWithSource_ = params.find<bool>("assemble_with_source", false);
  heapStr_ = params.find<std::string>("heap", "");
  debug_ = params.find<bool>("debug", false);

  if (executablePath_.length() == 0 && !assembleWithSource_) {
    output_.verbose(CALL_INFO, 10, 0,
                    "SimEng executable binary filepath not provided.");
    std::exit(EXIT_FAILURE);
  }
  if (maxAddrMemory_ == 0) {
    output_.verbose(CALL_INFO, 10, 0,
                    "Maximum address range for memory not provided");
    std::exit(EXIT_FAILURE);
  }

  iterations_ = 0;

  // Instantiate the StandardMem Interface defined in config.py
  sstMem_ = loadUserSubComponent<SST::Interfaces::StandardMem>(
      "memory", ComponentInfo::SHARE_NONE, clock_,
      new StandardMem::Handler<SimEngCoreWrapper>(
          this, &SimEngCoreWrapper::handleMemoryEvent));

  dataMemory_ = std::make_shared<SimEngMemInterface>(sstMem_, cacheLineWidth_,
                                                     maxAddrMemory_, debug_);

  handlers_ = new SimEngMemInterface::SimEngMemHandlers(*dataMemory_, &output_);

  // Protected methods from SST::Component used to start simulation
  registerAsPrimaryComponent();
  primaryComponentDoNotEndSim();
}

SimEngCoreWrapper::~SimEngCoreWrapper() {}

void SimEngCoreWrapper::setup() {
  sstMem_->setup();
  output_.verbose(CALL_INFO, 1, 0, "Memory setup complete\n");
  // Run Simulation
  std::cout << "[SimEng] Starting...\n" << std::endl;
  startTime_ = std::chrono::high_resolution_clock::now();
}

void SimEngCoreWrapper::handleMemoryEvent(StandardMem::Request* memEvent) {
  memEvent->handle(handlers_);
}

void SimEngCoreWrapper::finish() {
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
    std::cout << "[SimEng] " << key << ": " << value << "\n";
  }

  std::cout << "\n[SimEng] Finished " << iterations_ << " ticks in " << duration
            << "ms (" << std::round(khz) << " kHz, " << std::setprecision(2)
            << mips << " MIPS)" << std::endl;
}

void SimEngCoreWrapper::init(unsigned int phase) {
  sstMem_->init(phase);
  // Init can have multiple phases, only fabricate the core once at phase 0
  if (phase == 0) {
    fabricateSimEngCore();
  }
}

bool SimEngCoreWrapper::clockTick(SST::Cycle_t current_cycle) {
  // Tick the core and memory interfaces until the program has halted
  if (!core_->hasHalted() || dataMemory_->hasPendingRequests()) {
    // Tick the data memory.
    dataMemory_->tick();

    // Tick the core.
    core_->tick();

    // Tick the instruction memory.
    instructionMemory_->tick();

    iterations_++;

    return false;
  } else {
    // Protected method from SST::Component used to end SST simulation
    primaryComponentOKToEndSim();
    return true;
  }
}
std::string SimEngCoreWrapper::trimSpaces(std::string strArgs) {
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

std::vector<std::string> SimEngCoreWrapper::splitArgs(std::string strArgs) {
  std::string trimmedStrArgs = trimSpaces(strArgs);
  std::string str = "";
  std::vector<std::string> args;
  std::size_t argSize = trimmedStrArgs.size();
  bool escapeSingle = false;
  bool escapeDouble = false;
  bool captureEscape = false;
  uint64_t index = 0;
  if (argSize == 0) {
    return args;
  }

  for (int x = 0; x < argSize; x++) {
    index = x;
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
    std::string err;
    output_.verbose(CALL_INFO, 1, 0, R"(
           Parsing failed: Invalid format - Please make sure all
           characters/strings are escaped properly within a set single or 
           double quotes. To escape quotes use (\\\) instead of (\).\n
           )");
    std::cerr << "Error occured at index " << index
              << " of the argument string - substring: "
              << "[ " << str << " ]" << std::endl;
    std::exit(EXIT_FAILURE);
  }
  args.push_back(str);
  return args;
}

void SimEngCoreWrapper::fabricateSimEngCore() {
  output_.verbose(CALL_INFO, 1, 0, "Setting up SimEng Core\n");
  if (simengConfigPath_ != "") {
#ifdef SIMENG_ENABLE_SST_TESTS
    if (assembleWithSource_) {
      output_.verbose(CALL_INFO, 1, 0,
                      "Assembling source instructions using LLVM\n");
      Assembler assemble = Assembler(source_);
      coreInstance_ = std::make_unique<simeng::CoreInstance>(
          assemble.getAssembledSource(), assemble.getAssembledSourceSize(),
          simengConfigPath_);
    } else {
      coreInstance_ = std::make_unique<simeng::CoreInstance>(
          simengConfigPath_, executablePath_, executableArgs_);
    }
#else
    coreInstance_ = std::make_unique<simeng::CoreInstance>(
        simengConfigPath_, executablePath_, executableArgs_);
#endif
  } else {
#ifdef SIMENG_ENABLE_SST_TESTS
    std::string a64fxConfigPath = std::string(SIMENG_BUILD_DIR) +
                                  "/simeng-configs/sst-cores/a64fx-sst.yaml";
    output_.verbose(
        CALL_INFO, 1, 0,
        "No config path provided so defaulting to a64fx-sst.yaml\n");
    if (assembleWithSource_) {
      output_.verbose(CALL_INFO, 1, 0,
                      "Assembling source instructions using LLVM\n");
      Assembler assemble = Assembler(source_);
      coreInstance_ = std::make_unique<simeng::CoreInstance>(
          assemble.getAssembledSource(), assemble.getAssembledSourceSize(),
          a64fxConfigPath);
    } else {
      coreInstance_ = std::make_unique<simeng::CoreInstance>(
          a64fxConfigPath, executablePath_, executableArgs_);
    }
#else
    coreInstance_ = std::make_unique<simeng::CoreInstance>(executablePath_,
                                                           executableArgs_);
#endif
  }
  if (coreInstance_->getSimulationMode() !=
      simeng::SimulationMode::OutOfOrder) {
    output_.verbose(CALL_INFO, 1, 0,
                    "SimEng currently only supports Out-of-Order "
                    "archetypes with SST.");
    std::exit(EXIT_FAILURE);
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
        "Error: SST backend memory is less than processImage size. "
        "Please increase the memory allocated to memHierarchy.memBackend and "
        "ensure it is consistent with \'max_addr_memory\' and "
        "\'addr_range_end\'. \n");
    primaryComponentOKToEndSim();
    std::exit(EXIT_FAILURE);
  }
// If testing is enabled populate heap if heap values have been specified.
#ifdef SIMENG_ENABLE_SST_TESTS
  if (heapStr_ != "") {
    std::vector<uint8_t> initialHeapData;
    std::vector<uint64_t> heapVals = splitHeapStr();
    uint64_t heapSize = heapVals.size() * 8;
    initialHeapData.resize(heapSize);
    uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData.data());
    for (size_t x = 0; x < heapVals.size(); x++) {
      heap[x] = heapVals[x];
    }
    uint64_t heapStart = coreInstance_->getHeapStart();
    std::copy(initialHeapData.begin(), initialHeapData.end(),
              coreInstance_->getProcessImage().get() + heapStart);
  }
#endif
  // Send the process image data over to the SST memory
  dataMemory_->sendProcessImageToSST(coreInstance_->getProcessImage().get(),
                                     coreInstance_->getProcessImageSize());

  output_.verbose(CALL_INFO, 1, 0, "SimEng core setup successfully.\n");
  // Print out build metadata
  std::cout << "[SimEng] Build metadata:" << std::endl;
  std::cout << "[SimEng] \tVersion: " SIMENG_VERSION << std::endl;
  std::cout << "[SimEng] \tCompile Time - Date: " __TIME__ " - " __DATE__
            << std::endl;
  std::cout << "[SimEng] \tBuild type: " SIMENG_BUILD_TYPE << std::endl;
  std::cout << "[SimEng] \tCompile options: " SIMENG_COMPILE_OPTIONS
            << std::endl;
  std::cout << "[SimEng] \tTest suite: " SIMENG_ENABLE_TESTS << std::endl;
  std::cout << std::endl;

  std::cout << "[SimEng] Running in "
            << coreInstance_->getSimulationModeString() << " mode" << std::endl;
  std::cout << "[SimEng] Workload: " << executablePath_;
  for (const auto& arg : executableArgs_) std::cout << " " << arg;
  std::cout << std::endl;
  std::cout << "[SimEng] Config file: " << simengConfigPath_ << std::endl;
}

std::vector<uint64_t> SimEngCoreWrapper::splitHeapStr() {
  std::vector<uint64_t> out;
  std::string acc = "";
  for (size_t a = 0; a < heapStr_.size(); a++) {
    if (heapStr_[a] == ',') {
      out.push_back(static_cast<uint64_t>(std::stoull(acc)));
      acc = "";
    } else {
      acc += heapStr_[a];
    }
  }
  out.push_back(static_cast<uint64_t>(std::stoull(acc)));
  return out;
}