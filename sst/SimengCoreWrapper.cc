#include <sst/core/sst_config.h>
#include "SimengCoreWrapper.hh"

#include <iostream>

using namespace SST::SSTSimeng;
using namespace SST::Interfaces;

enum class SimulationMode { Emulation, InOrderPipelined, OutOfOrder };

SimengCoreWrapper::SimengCoreWrapper(SST::ComponentId_t id, SST::Params& params): SST::Component(id) {
    output.init("SimengCoreWrapper[" + getName() + ":@p:@t]:", 999, 0, SST::Output::STDOUT);
    clock = registerClock(params.find<std::string>("clock", "1GHz"), new SST::Clock::Handler<SimengCoreWrapper>(this, &SimengCoreWrapper::clockTick));

    /** Extract variables from config.py */
    executable_path = params.find<std::string>("executable_path", "");
    executable_args = params.find<std::string>("executable_args", "");
    config_path = params.find<std::string>("config_path", "");
    cache_line_width  = params.find<uint64_t>("cache_line_width", "64");
    max_addr_memory = params.find<uint64_t>("max_addr_memory", "0");

    if (executable_path.length() == 0) {
        output.fatal(CALL_INFO, 10, 0, "Simeng executable binary filepath not provided.");
    }
    if (max_addr_memory == 0) {
      output.fatal(CALL_INFO, 10, 0, "Maximum address range for memory not provided");
    }

    iterations = 0;
    vitrual_counter = 0;
    size = 0;

    /** Instantiate the StandardMem Interface defined in config.py*/
    mem = loadUserSubComponent<SST::Interfaces::StandardMem>("memory", ComponentInfo::SHARE_NONE, clock,
      new StandardMem::Handler<SimengCoreWrapper>(this, &SimengCoreWrapper::handleEvent));

    data_memory = std::make_unique<SimengMemInterface>(mem, cache_line_width, max_addr_memory, &output);

    handlers = new SimengMemInterface::SimengMemHandlers(*data_memory, &output);

    /** Protected methods from SST::Component used to start simulation */
    registerAsPrimaryComponent();
    primaryComponentDoNotEndSim();
}

SimengCoreWrapper::~SimengCoreWrapper() {}

void SimengCoreWrapper::setup() {
  mem->setup();
  output.verbose(CALL_INFO, 1, 0, "Memory setup complete\n");

}

void SimengCoreWrapper::handleEvent( StandardMem::Request* ev) {
  ev->handle(handlers);
}

void SimengCoreWrapper::finish() {

    output.verbose(CALL_INFO, 1, 0, "Simulation complete. Finalising stats....\n");

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(endTime - start_time)
          .count();
    auto hz = iterations / (static_cast<double>(duration) / 1000.0);
    auto khz = hz / 1000.0;
    auto retired = core->getInstructionsRetiredCount();
    auto mips = retired / static_cast<double>(duration) / 1000.0;

  // Print stats
    std::cout << "\n";
    auto stats = core->getStats();
    for (const auto& [key, value] : stats) {
    std::cout << key << ": " << value << "\n";
    }

    std::cout << "\nFinished " << iterations << " ticks in " << duration << "ms ("
            << std::round(khz) << " kHz, " << std::setprecision(2) << mips
            << " MIPS)" << std::endl;

    delete[] process_memory;
}

void SimengCoreWrapper::init(unsigned int phase) {
    mem->init(phase);
    /** Init can have multiple phases, only fabricate the core once at phase 0 */
    if (phase == 0) {
      fabricateSimengCore();
    }
}

bool SimengCoreWrapper::clockTick(SST::Cycle_t current_cycle) {
    // Tick the core and memory interfaces until the program has halted
    if (!core->hasHalted() || data_memory->hasPendingRequests()) {
    // Tick the core
    core->tick();
    // Update Virtual Counter Timer at correct frequency.
    if (iterations % (uint64_t)timer_modulo == 0) {
        vitrual_counter++;
        core->incVCT(vitrual_counter);
    }

    // Tick memory
    instruction_memory->tick();
    data_memory->tick();

    iterations++;

    return false;
    } else {
        /** Protected method from SST::Component used to end SST simulation */
        primaryComponentOKToEndSim();
        return true;
    }
}

void SimengCoreWrapper::fabricateSimengCore() {
     output.verbose(CALL_INFO, 1, 0, "Setting up SimEng Core\n");

    SimulationMode mode = SimulationMode::InOrderPipelined;
    std::string modeString;
    YAML::Node config;

    if (config_path != "") {
      config = simeng::ModelConfig(config_path).getConfigFile();
    } else {
      config = YAML::Load(DEFAULT_CONFIG);
    }

    if (config["Core"]["Simulation-Mode"].as<std::string>() == "inorder") {
      mode = SimulationMode::InOrderPipelined;
      modeString = "Emulation";
    } else if (config["Core"]["Simulation-Mode"].as<std::string>() ==
               "outoforder") {
      mode = SimulationMode::OutOfOrder;
      modeString = "Out-of-Order";
    } else {
      mode = SimulationMode::Emulation;
      modeString = "Emulation";
    }

    float clockFreq_ = config["Core"]["Clock-Frequency"].as<float>();
    uint32_t timerFreq_ = config["Core"]["Timer-Frequency"].as<uint32_t>();
    timer_modulo = (clockFreq_ * 1e9) / (timerFreq_ * 1e6);

    // // Create the process Image
    std::vector<std::string> commandLine({executable_path, executable_args});
    process = std::make_unique<simeng::kernel::LinuxProcess>(commandLine, config);
    if (!process->isValid()) output.fatal(CALL_INFO, 1, 0, "Could not read/parse %s", executable_path);

    auto processImage = process->getProcessImage();
    size_t processMemorySize = processImage.size();
    process_memory = new char[processMemorySize]();
    std::copy(processImage.begin(), processImage.end(), process_memory);

    uint64_t entryPoint = process->getEntryPoint();

    // Create the OS kernel with the process
    kernel = std::make_unique<simeng::kernel::Linux>();
    kernel->createProcess(*process.get());

    instruction_memory = std::make_unique<simeng::FlatMemoryInterface>(
        process_memory, processMemorySize);

    // // Create the architecture, with knowledge of the kernel
    arch =
        std::make_unique<simeng::arch::aarch64::Architecture>(*kernel, config);
    
    predictor = std::make_unique<simeng::BTBPredictor>(
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
    port_allocator = std::make_unique<simeng::pipeline::BalancedPortAllocator>(
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

    modeString = "Out-of-Order";

    core = std::make_unique<simeng::models::outoforder::Core>(
        *instruction_memory, *data_memory, processMemorySize, entryPoint, *arch,
        *predictor, *port_allocator, rsArrangement, config);

    simeng::SpecialFileDirGen SFdir = simeng::SpecialFileDirGen(config);
    // Create the Special Files directory if indicated to do so in Config
    if (config["CPU-Info"]["Generate-Special-Dir"].as<std::string>() == "T") {
        // Remove any current special files dir
        SFdir.RemoveExistingSFDir();
        // Create new special files dir
        SFdir.GenerateSFDir();
    }
    
    data_memory->sendProcessImageToSST(processImage);

    output.verbose(CALL_INFO, 1, 0, "SimEng core setup successfully.\n");
    std::cout << "Running in " << modeString << " mode." << std::endl;
    output.verbose(CALL_INFO, 1, 0, "Starting simulation.\n");
    start_time = std::chrono::high_resolution_clock::now();
}
 