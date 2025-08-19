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

SimEngCoreWrapper::SimEngCoreWrapper(const ComponentId_t id,
                                     const Params& params)
    : Component(id) {
  output_.init("[SSTSimEng:SimEngCoreWrapper] " + getName() + ":@p:@l ", 999, 0,
               Output::STDOUT);
  clock_ = registerClock(params.find<std::string>("clock", "1GHz"),
                         new Clock::Handler<SimEngCoreWrapper>(
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

  if (executablePath_.empty() && !assembleWithSource_) {
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
  sstMem_ = loadUserSubComponent<StandardMem>(
      "memory", ComponentInfo::SHARE_NONE, clock_,
      new StandardMem::Handler<SimEngCoreWrapper>(
          this, &SimEngCoreWrapper::handleMemoryEvent));

  dataMemory_ = std::make_shared<SimEngMemInterface>(sstMem_, cacheLineWidth_,
                                                     maxAddrMemory_, debug_);

  handlers_ = new SimEngMemInterface::SimEngMemHandlers(*dataMemory_, &output_);

  // TODO: Configure accelerators based on a config file
  //       and only if that file is provided
  // Accelerator setup
  coreToAcceleratorLink_ = configureSelfLink("core_accelerator_link");
  acceleratorToCoreLink_ = configureSelfLink("accelerator_core_link");
  if (coreToAcceleratorLink_ == nullptr || acceleratorToCoreLink_ == nullptr) {
    output_.verbose(CALL_INFO, 1, 0,
                    "Could not configure links to/from the accelerator.");
    std::exit(EXIT_FAILURE);
  }
  acceleratorClock_ =
      registerClock(params.find<std::string>("acceleratorClock", "2GHz"),
                    new Clock::Handler<SimEngCoreWrapper>(
                        this, &SimEngCoreWrapper::acceleratorClockTick),
                    false);

  // Protected methods from SST::Component used to start simulation
  registerAsPrimaryComponent();
  primaryComponentDoNotEndSim();
}

SimEngCoreWrapper::~SimEngCoreWrapper() = default;

void SimEngCoreWrapper::setup() {
  sstMem_->setup();
  output_.verbose(CALL_INFO, 1, 0, "Memory setup complete\n");
  // Run Simulation
  std::cout << "[SimEng] Starting...\n" << std::endl;
  startTime_ = std::chrono::high_resolution_clock::now();
}

// ReSharper disable once CppMemberFunctionMayBeConst
void SimEngCoreWrapper::handleMemoryEvent(StandardMem::Request* memEvent) {
  memEvent->handle(handlers_);
}

void SimEngCoreWrapper::finish() {
  output_.verbose(CALL_INFO, 1, 0,
                  "Simulation complete. Finalising stats....\n");

  const auto endTime = std::chrono::high_resolution_clock::now();
  const auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                            endTime - startTime_)
                            .count();
  const double khz =
      iterations_ / (static_cast<double>(duration) / 1000.0) / 1000.0;
  const uint64_t retired = core_->getInstructionsRetiredCount();
  const double mips = retired / static_cast<double>(duration) / 1000.0;

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

void SimEngCoreWrapper::init(const unsigned int phase) {
  sstMem_->init(phase);
  // Init can have multiple phases, only fabricate the core once at phase 0
  if (phase == 0) {
    configureOffloadingLogic();
    fabricateSimEngCore();
    fabricateSimEngAccelerator();
  }
}

bool SimEngCoreWrapper::clockTick(const Cycle_t currentCycle) {
  // Tick the core and memory interfaces until the program has halted
  if (core_->hasHalted() && !dataMemory_->hasPendingRequests()) {
    // Protected method from SST::Component used to end SST simulation
    primaryComponentOKToEndSim();
    return true;
  }

  // Tick the data memory.
  dataMemory_->tick();

  // Tick the core.
  core_->tick();

  // Tick the instruction memory.
  instructionMemory_->tick();

  iterations_++;

  accelerator_->tick();
  return false;
}

std::string SimEngCoreWrapper::trimSpaces(const std::string& argsStr) {
  int trailingEnd = -1;
  int leadingEnd = -1;
  const int size = static_cast<int>(argsStr.size());
  for (int x = 0; x < size; x++) {
    const int end = size - 1 - x;
    // Find the index, from the start of the string, which is not a space.
    if (argsStr.at(x) != ' ' && leadingEnd == -1) {
      leadingEnd = x;
    }
    // Find the index, from the end of the string, which is not a space.
    if (argsStr.at(end) != ' ' && trailingEnd == -1) {
      trailingEnd = end;
    }
    if (trailingEnd != -1 && leadingEnd != -1) {
      break;
    }
  }
  // The string has leading or trailing spaces, return the substring which
  // doesn't have those spaces.
  if (trailingEnd != -1 && leadingEnd != -1) {
    return argsStr.substr(leadingEnd, trailingEnd - leadingEnd + 1);
  }
  // The string does not have leading or trailing spaces, return the original
  // string.
  return argsStr;
}

std::vector<std::string> SimEngCoreWrapper::splitArgs(
    const std::string& argString) const {
  const std::string trimmedStrArgs = trimSpaces(argString);
  std::string str;
  std::vector<std::string> args;
  const std::size_t argSize = trimmedStrArgs.size();
  bool escapeSingle = false;
  bool escapeDouble = false;
  bool captureEscape = false;
  uint64_t index = 0;
  if (argSize == 0) {
    return args;
  }

  for (int x = 0; x < argSize; x++) {
    index = x;
    const bool escaped = escapeDouble || escapeSingle;
    const char currChar = trimmedStrArgs.at(x);
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
        escapeSingle = false;
      }
      // If a portion of the argument string starts with a double quote (") and
      // we encounter another double quote, capture the substring enclosed by a
      // valid set of double quotes into an argument without producing any
      // delimiting or escape behavior even with single quotes.
      // e.g "arg1=1 arg2="James' Car" arg3=2" will be parsed as
      // std::vector<std::string>{arg1=1, arg2=James' Car, arg3=2}
      else if (currChar == '\"' && escapeDouble) {
        escapeDouble = false;
      } else {
        str += currChar;
      }
    } else {
      if (currChar == ' ') {
        if (!str.empty()) {
          args.push_back(str);
          str = "";
        }
      }
      // Check for escape character ("), this signals the algorithm to capture
      // any char inside a set of ("") without producing any delimiting or
      // escape behavior.
      else if (currChar == '\"') {
        escapeDouble = true;
        // Check for escape character ('), this signals the algorithm to capture
        // any char inside a set of ('') without producing any delimiting or
        // escape behavior.
      } else if (currChar == '\'') {
        escapeSingle = true;
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
    std::cerr << "[SSTSimEng:SimEngCoreWrapper] Error occurred at index "
              << index << " of the argument string - substring: "
              << "[ " << str << " ]" << std::endl;
    std::exit(EXIT_FAILURE);
  }
  args.push_back(str);
  return args;
}

void SimEngCoreWrapper::initialiseHeapData() {
  std::vector<uint8_t> initialHeapData;
  const std::vector<uint64_t> heapVals = splitHeapStr();
  const uint64_t heapSize = heapVals.size() * 8;
  initialHeapData.resize(heapSize);
  const auto heap = reinterpret_cast<uint64_t*>(initialHeapData.data());
  for (size_t x = 0; x < heapVals.size(); x++) {
    heap[x] = heapVals[x];
  }
  const uint64_t heapStart = coreInstance_->getHeapStart();
  std::copy(initialHeapData.begin(), initialHeapData.end(),
            coreInstance_->getProcessImage().get() + heapStart);
}

void SimEngCoreWrapper::fabricateSimEngCore() {
  output_.verbose(CALL_INFO, 1, 0, "Setting up SimEng Core\n");
  uint8_t* assembled_source = nullptr;
  size_t assembled_source_size = 0;
  if (assembleWithSource_) {
    output_.verbose(CALL_INFO, 1, 0,
                    "Assembling source instructions using LLVM\n");
    auto assemble = Assembler(source_);
    assembled_source = assemble.getAssembledSource();
    assembled_source_size = assemble.getAssembledSourceSize();
  }
  if (!simengConfigPath_.empty()) {
    // Set the global config file to one at the file path defined
    config::SimInfo::setConfig(simengConfigPath_);

    coreInstance_ =
        assembleWithSource_
            ? std::make_unique<CoreInstance>(assembled_source,
                                             assembled_source_size)
            : std::make_unique<CoreInstance>(executablePath_, executableArgs_);
  } else {
    output_.verbose(CALL_INFO, 1, 0,
                    "No SimEng configuration provided. Using the default "
                    "a64fx-sst.yaml configuration file.\n");
    // Set the global config file to the default a64fx-sst.yaml file
    config::SimInfo::setConfig(a64fxConfigPath_);

    coreInstance_ =
        assembleWithSource_
            ? std::make_unique<CoreInstance>(assembled_source,
                                             assembled_source_size)
            : std::make_unique<CoreInstance>(executablePath_, executableArgs_);
  }
  if (config::SimInfo::getSimMode() != config::SimulationMode::Outoforder) {
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
    initialiseHeapData();
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

  // Output general simulation details
  std::cout << "[SimEng] Running in " << config::SimInfo::getSimModeStr()
            << " mode" << std::endl;
  std::cout << "[SimEng] Workload: " << executablePath_;
  for (const auto& arg : executableArgs_) std::cout << " " << arg;
  std::cout << std::endl;
  std::cout << "[SimEng] Config file: " << config::SimInfo::getConfigPath()
            << std::endl;
  std::cout << "[SimEng] ISA: " << config::SimInfo::getISAString() << std::endl;
  std::cout << "[SimEng] Auto-generated Special File directory: ";
  if (config::SimInfo::getGenSpecFiles())
    std::cout << "True";
  else
    std::cout << "False";
  std::cout << std::endl;
  std::cout << "[SimEng] Special File directory used: "
            << config::SimInfo::getConfig()["CPU-Info"]["Special-File-Dir-Path"]
                   .as<std::string>()
            << std::endl;
  std::cout
      << "[SimEng] Number of Cores: "
      << config::SimInfo::getConfig()["CPU-Info"]["Core-Count"].as<uint16_t>()
      << std::endl;
}

std::vector<uint64_t> SimEngCoreWrapper::splitHeapStr() const {
  std::vector<uint64_t> out;
  std::string acc;
  for (const char a : heapStr_) {
    if (a == ',') {
      out.push_back(std::stoull(acc));
      acc = "";
    } else {
      acc += a;
    }
  }
  out.push_back(std::stoull(acc));
  return out;
}

// ReSharper disable once CppMemberFunctionMayBeConst
bool SimEngCoreWrapper::acceleratorClockTick(const Cycle_t currentCycle) {
  // std::endl; accelerator_->tick();
  return false;
}

// TODO: Add dynamic mapping for multiple accelerators
//       (probably from a config file)
constexpr static Accelerator::id_t SME_ACCELERATOR_ID = 1;

void SimEngCoreWrapper::configureOffloadingLogic() {
  auto logic = config::OffloadingLogic(
      [](const Instruction& insn) {
        // TODO: Proper mapping if multiple accelerators
        //       (possibly from a config file)
        if (models::accelerator::SmeAccelerator::shouldAccelerate(insn))
          return SME_ACCELERATOR_ID;

        return Accelerator::NO_ACCELERATOR;
      },
      {{SME_ACCELERATOR_ID,
        models::accelerator::SmeAccelerator::isInstructionReady}},
      {{SME_ACCELERATOR_ID,
        models::accelerator::SmeAccelerator::isRegisterOffloaded}},
      [this](const OffloadingEvent::packet_t& packet) {
        coreToAcceleratorLink_->send(new OffloadingEvent(packet));
        return true;
      },
      [this] {
        auto* event =
            dynamic_cast<OffloadingEvent*>(acceleratorToCoreLink_->recv());

        if (event == nullptr) {
          return std::optional<OffloadingEvent::packet_t>();
        }

        auto packet = std::move(event->packet_);
        delete event;
        return std::optional(std::move(packet));
      });
  config::SimInfo::setOffloadingLogic(std::move(logic));
}

void SimEngCoreWrapper::fabricateSimEngAccelerator() {
  // TODO Extract to an AcceleratorInstance object
  const auto config_ports = config::SimInfo::getConfig()["Ports"];
  std::vector<std::vector<uint16_t>> portArrangement(
      config_ports.num_children());
  for (size_t i = 0; i < config_ports.num_children(); i++) {
    auto config_groups = config_ports[i]["Instruction-Group-Support-Nums"];
    // Read groups in associated port
    for (size_t j = 0; j < config_groups.num_children(); j++) {
      auto grp = config_groups[j].as<uint16_t>();
      portArrangement[i].push_back(grp);
    }
  }
  acceleratorPortAllocator_ =
      std::make_unique<pipeline::BalancedPortAllocator>(portArrangement);

  accelerator_ = std::make_unique<models::accelerator::SmeAccelerator>(
      // TODO: Assign unique IDs if multiple accelerators
      //       (probably get from config file)
      SME_ACCELERATOR_ID,
      [this](const OffloadingEvent::packet_t& packet) {
        acceleratorToCoreLink_->send(new OffloadingEvent(packet));
        return true;
      },
      [this] {
        auto* event =
            dynamic_cast<OffloadingEvent*>(coreToAcceleratorLink_->recv());

        if (event == nullptr) {
          return std::optional<OffloadingEvent::packet_t>();
        }

        auto packet = std::move(event->packet_);
        delete event;
        return std::optional(std::move(packet));
      },
      *dataMemory_, *acceleratorPortAllocator_);
}
