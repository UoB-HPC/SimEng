// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include "SimOSWrapper.hh"

#include <cstdlib>
#include <iostream>

#include "Assemble.hh"

using namespace SST::SSTSimEng;
using namespace SST::Interfaces;

SimOSWrapper::SimOSWrapper(SST::ComponentId_t id, SST::Params& params)
    : SST::Component(id) {
  output_.init("[SSTSimEng:SimOSWrapper] " + getName() + ":@p:@l ", 999, 0,
               SST::Output::STDOUT);
  clock_ = registerClock(
      params.find<std::string>("clock", "1GHz"),
      new SST::Clock::Handler<SimOSWrapper>(this, &SimOSWrapper::clockTick));

  // Extract remaining variables from config.py
  numCores_ = params.find<uint16_t>("num_cores", "1");
  simengConfigPath_ = params.find<std::string>("simeng_config_path", "");
  executablePath_ = params.find<std::string>("executable_path", DEFAULT_STR);
  executableArgs_ = splitArgs(params.find<std::string>("executable_args", ""));
  cacheLineWidth_ = params.find<uint64_t>("cache_line_width", "64");
  maxAddrMemory_ = params.find<uint64_t>("max_addr_memory", "0");
  debug_ = params.find<bool>("debug", false);

  if (maxAddrMemory_ == 0) {
    output_.verbose(CALL_INFO, 10, 0,
                    "Maximum address range for memory not provided");
    std::exit(EXIT_FAILURE);
  }

  iterations_ = 0;

  // Instantiate the StandardMem Interface defined in config.py
  output_.verbose(CALL_INFO, 1, 0, "Declare dataInterface_\n");
  dataInterface_ = loadUserSubComponent<SST::Interfaces::StandardMem>(
      "dataMemory", ComponentInfo::SHARE_NONE, clock_,
      new StandardMem::Handler<SimOSWrapper>(this,
                                             &SimOSWrapper::handleMemoryEvent));

  output_.verbose(CALL_INFO, 1, 0, "Declare instrInterface_\n");
  instrInterface_ = loadUserSubComponent<SST::Interfaces::StandardMem>(
      "instrMemory", ComponentInfo::SHARE_NONE, clock_,
      new StandardMem::Handler<SimOSWrapper>(this,
                                             &SimOSWrapper::handleMemoryEvent));

  output_.verbose(CALL_INFO, 1, 0, "Declare memInterface_\n");
  memInterface_ = std::make_shared<SimEngMemInterface>(
      dataInterface_, instrInterface_, cacheLineWidth_, maxAddrMemory_, debug_);

  output_.verbose(CALL_INFO, 1, 0, "Declare handlers_\n");
  handlers_ =
      new SimEngMemInterface::SimEngMemHandlers(*memInterface_, &output_);

  // Instantiate the NOC
  output_.verbose(CALL_INFO, 1, 0, "Declare noc_\n");
  sstNoc_ = loadUserSubComponent<nocAPI>("noc");
  sstNoc_->setRecvNotifyHandler(new Event::Handler<SimOSWrapper>(
      this, &SimOSWrapper::handleNetworkEvent));

  // Protected methods from SST::Component used to start simulation
  registerAsPrimaryComponent();
  primaryComponentDoNotEndSim();
  output_.verbose(CALL_INFO, 1, 0, "Constructor complete\n");
}

SimOSWrapper::~SimOSWrapper() {}

void SimOSWrapper::init(unsigned int phase) {
  dataInterface_->init(phase);
  instrInterface_->init(phase);
  output_.verbose(CALL_INFO, 1, 0, "Memory init complete phase %d\n", phase);
  sstNoc_->init(phase);
  output_.verbose(CALL_INFO, 1, 0, "NOC init complete phase %d\n", phase);
}

void SimOSWrapper::setup() {
  dataInterface_->setup();
  instrInterface_->setup();
  output_.verbose(CALL_INFO, 1, 0, "Memory setup complete\n");
  sstNoc_->setup();
  output_.verbose(CALL_INFO, 1, 0, "NOC setup complete\n");

  // Ensure the number of devices connected to the NOC is equivalent to the
  // number of cores set to be used
  if (sstNoc_->getNumDevices() != numCores_) {
    output_.verbose(CALL_INFO, 10, 0,
                    "Number of cores connected to the NOC is not equal to the "
                    "number defined in the passed config\n");
    std::exit(EXIT_FAILURE);
  }

  fabricateSimOS();

  // Run Simulation
  std::cout << "[SimEng] Running in "
            << simeng::config::SimInfo::getSimModeStr() << " mode" << std::endl;
  std::cout << "[SimEng] Workload: " << executablePath_;
  for (const auto& arg : executableArgs_) std::cout << " " << arg;
  std::cout << std::endl;
  std::cout << "[SimEng] Config file: "
            << simeng::config::SimInfo::getConfigPath() << std::endl;
  std::cout << "[SimEng] Local Special File directory: ";
  if (simeng::config::SimInfo::getGenSpecFiles())
    std::cout << "True";
  else
    std::cout << "False";
  std::cout << std::endl;
  std::cout
      << "[SimEng] Number of Cores: "
      << simeng::config::SimInfo::getValue<uint64_t>(
             simeng::config::SimInfo::getConfig()["CPU-Info"]["Core-Count"])
      << std::endl;

  // Run simulation
  std::cout << "[SimEng] Starting...\n" << std::endl;
}

bool SimOSWrapper::clockTick(SST::Cycle_t current_cycle) {
  sstNoc_->clockTick(current_cycle);
  if (!initialProcessImageWritten_) {
    // Tick Memory
    memInterface_->tick();

    iterations_++;

    return false;
  }
  // for (int i = 0; i < numCores_; i++) {
  //   emptyEv* cntx = new emptyEv(getName());
  //   sstNoc_->send(cntx, i);
  // }
  // for (int i = 0; i < numCores_; i++) {
  //   contextEv* cntx = new contextEv(getName());
  //   uint64_t i64 = i;
  //   cntx->setPayload({i64,
  //                     i64 * 2,
  //                     i64 * 3,
  //                     i64 * 4,
  //                     {{{i, 4}, {i * 2, 4}}, {{i64 * 3, 8}, {i64 * 4, 8}}}});
  //   sstNoc_->send(cntx, i);
  // }
  // Tick the core and memory interfaces until the program has halted
  if (!simOS_->hasHalted()) {
    // Tick SimOS
    simOS_->tick();

    // Tick Memory
    memInterface_->tick();

    iterations_++;

    return false;
  } else {
    // Protected method from SST::Component used to end SST simulation
    primaryComponentOKToEndSim();
    return true;
  }
}

void SimOSWrapper::finish() {
  output_.verbose(CALL_INFO, 1, 0,
                  "Simulation complete. Finalising stats....\n");
}

void SimOSWrapper::fabricateSimOS() {
  simeng::config::SimInfo::setConfig(simengConfigPath_);

  // Create the Special Files directory if indicated to do so in Config file
  if (config::SimInfo::getGenSpecFiles() == true) createSpecialFileDirectory();

  sendSyscallResultToCore_ = [&](simeng::OS::SyscallResult result) {
    syscallEv* sysRes = new syscallEv(getName(), 0);
    sysRes->setPayload(result);
    sstNoc_->send(sysRes, result.coreId);
    return;
  };

  processImageSent_ = [&]() { initialProcessImageWritten_ = true; };

  if (executablePath_ == DEFAULT_STR) {
    // Use default program
    simeng::span<char> defaultPrg = simeng::span<char>(
        reinterpret_cast<char*>(simeng::OS::hex_), sizeof(simeng::OS::hex_));
    simOS_ = std::make_unique<simeng::OS::SimOS>(
        memInterface_, defaultPrg, sendSyscallResultToCore_, processImageSent_);
  } else {
    simOS_ = std::make_unique<simeng::OS::SimOS>(
        memInterface_, executablePath_, executableArgs_,
        sendSyscallResultToCore_, processImageSent_);
  }

  proxy_.getCoreInfo = [&](uint16_t coreId, bool forClone) {
    coreInfoReqEv* cinfoReq = new coreInfoReqEv(getName(), 0, forClone);
    // std::cerr << "CoreInfo packet to " << coreId << std::endl;
    sstNoc_->send(cinfoReq, coreId);
    return;
  };

  proxy_.interrupt = [&](uint16_t coreId) {
    interruptEv* intrpt = new interruptEv(getName(), 0);
    // std::cerr << "Interupt packet to " << coreId << std::endl;
    sstNoc_->send(intrpt, coreId);
    return;
  };

  proxy_.schedule = [&](uint16_t coreId, simeng::OS::cpuContext ctx) {
    contextEv* cntxEv = new contextEv(getName(), 0);
    // std::cerr << "Schedule packet to " << coreId << std::endl;
    cntxEv->setPayload(ctx);
    sstNoc_->send(cntxEv, coreId);
    return;
  };

  // Send core registration network events to all available core components
  for (int i = 0; i < numCores_; i++) {
    registerEv* regReq = new registerEv(getName(), 0);
    sstNoc_->send(regReq, i + 1);
  }

  simOS_->registerCoreProxy(proxy_);
}

void SimOSWrapper::createSpecialFileDirectory() const {
  simeng::SpecialFileDirGen SFdir = simeng::SpecialFileDirGen();
  // Remove any current special files dir
  SFdir.RemoveExistingSFDir();
  // Create new special files dir
  SFdir.GenerateSFDir();
}

void SimOSWrapper::handleMemoryEvent(StandardMem::Request* memEvent) {
  memEvent->handle(handlers_);
}

void SimOSWrapper::handleNetworkEvent(SST::Event* netEvent) {
  simengNetEv* event = static_cast<simengNetEv*>(netEvent);
  switch (event->getType()) {
    case PacketType::Empty: {
      if (debug_) {
        output_.verbose(CALL_INFO, 1, 0,
                        "Received PacketType::Empty from %s\n\t- CoreId: %u\n",
                        event->getSource().c_str(), event->getSourceId());
      }
      break;
    }
    case PacketType::Context: {
      contextEv* cntxEv = static_cast<contextEv*>(netEvent);
      simeng::OS::cpuContext cntx = cntxEv->getPayload();
      if (debug_) {
        output_.verbose(CALL_INFO, 1, 0,
                        "Received PacketType::Context msg from %s\n\t- CoreId: "
                        "%u\n\t- TID: %llu\n",
                        cntxEv->getSource().c_str(), cntxEv->getSourceId(),
                        cntxEv->getPayload().TID);
      }
      break;
    }
    case PacketType::Syscall: {
      syscallInfoEv* sysInfo = static_cast<syscallInfoEv*>(netEvent);
      if (debug_) {
        output_.verbose(CALL_INFO, 1, 0,
                        "Received PacketType::Syscall msg from %s\n\t- CoreId: "
                        "%u\n\t- SyscallId: %llu\n",
                        sysInfo->getSource().c_str(), sysInfo->getSourceId(),
                        sysInfo->getPayload().syscallId);
      }
      simOS_->receiveSyscall(sysInfo->getPayload());
      break;
    }
    case PacketType::Translate: {
      transEv* translationReq = static_cast<transEv*>(netEvent);
      uint64_t paddr = simOS_->handleVAddrTranslation(
          translationReq->getVirtualAddr(), translationReq->getPID());
      // if (debug_) {
      //   output_.verbose(
      //       CALL_INFO, 1, 0,
      //       "Received PacketType::Translate msg from %s\n\t- CoreId: "
      //       "%u\n\t- VAddr: %llx\n\t- PID: %llu\n\t- PAddr: %llx\n",
      //       translationReq->getSource().c_str(),
      //       translationReq->getSourceId(), translationReq->getVirtualAddr(),
      //       translationReq->getPID(), paddr);
      // }
      transEv* translationRes = static_cast<transEv*>(translationReq->clone());
      translationRes->setPhysicalAddr(paddr);
      sstNoc_->send(translationRes, translationReq->getSourceId());
      break;
    }
    case PacketType::CoreInfo: {
      coreInfoEv* cinfoEv = static_cast<coreInfoEv*>(netEvent);
      simeng::OS::CoreInfo cinfo = cinfoEv->getPayload();
      if (debug_) {
        output_.verbose(CALL_INFO, 1, 0,
                        "Received PacketType::CoreInfo msg from %s\n\t- "
                        "CoreId: %u\n\t- FromOS: %u\n\t- TID: %llu\n",
                        cinfoEv->getSource().c_str(), cinfoEv->getSourceId(),
                        cinfoEv->isReqFromOS(), cinfo.ctx.TID);
      }
      if (!cinfoEv->isReqFromOS()) {
        simOS_->updateCoreDesc(cinfo.ctx, cinfo.coreId, cinfo.status,
                               cinfo.ticks);
      } else {
        simOS_->recieveCoreInfo(cinfo, cinfoEv->isForClone());
      }
      break;
    }
    case PacketType::Interrupt: {
      interruptEv* intrpt = static_cast<interruptEv*>(netEvent);
      if (debug_) {
        output_.verbose(CALL_INFO, 1, 0,
                        "Received PacketType::Interrupt msg from %s\n\t- "
                        "CoreId: %u\n\t- WasSuccess: %u\n",
                        intrpt->getSource().c_str(), intrpt->getSourceId(),
                        intrpt->wasSuccess());
      }
      simOS_->recieveInterruptResponse(intrpt->wasSuccess(),
                                       intrpt->getSourceId());
      break;
    }
    case PacketType::Register: {
      registerEv* regReq = static_cast<registerEv*>(netEvent);
      if (debug_) {
        output_.verbose(CALL_INFO, 1, 0,
                        "Received PacketType::Register msg from %s\n\t- "
                        "CoreId: %u\n\t- TID: %llu\n\t- Status: %u\n",
                        regReq->getSource().c_str(), regReq->getCoreId(),
                        regReq->getContext().TID,
                        unsigned(regReq->getCoreStatus()));
      }
      simOS_->registerCore(regReq->getCoreId(), regReq->getCoreStatus(),
                           regReq->getContext(), true);
      break;
    }
    default:
      break;
  }
  delete event;
}

std::string SimOSWrapper::trimSpaces(std::string strArgs) {
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

std::vector<std::string> SimOSWrapper::splitArgs(std::string strArgs) {
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
      // If a portion of the argument string starts with a single quote (")
      // and we encounter another single quote, capture the substring enclosed
      // by a valid set of single quotes into an argument without producing
      // any delimiting or escape behavior even with double quotes. e.g
      // "arg1=1 arg2='"Hi"' arg3=2" will be parsed as
      // std::vector<std::string>{arg1=1, arg2="Hi", arg3=2}
      if (currChar == '\'' && escapeSingle) {
        escapeSingle = 0;
      }
      // If a portion of the argument string starts with a double quote (")
      // and we encounter another double quote, capture the substring enclosed
      // by a valid set of double quotes into an argument without producing
      // any delimiting or escape behavior even with single quotes. e.g
      // "arg1=1 arg2="James' Car" arg3=2" will be parsed as
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
        // Check for escape character ('), this signals the algorithm to
        // capture any char inside a set of ('') without producing any
        // delimiting or escape behavior.
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
    std::cerr << "[SSTSimEng:SimOSWrapper] Error occured at index " << index
              << " of the argument string - substring: "
              << "[ " << str << " ]" << std::endl;
    std::exit(EXIT_FAILURE);
  }
  args.push_back(str);
  return args;
}