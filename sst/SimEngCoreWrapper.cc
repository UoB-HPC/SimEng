// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include "SimEngCoreWrapper.hh"

#include <cstdlib>
#include <iostream>

#include "Assemble.hh"
#include "simeng/util/Math.hh"

using namespace SST::SSTSimEng;
using namespace SST::Interfaces;

SimEngCoreWrapper::SimEngCoreWrapper(SST::ComponentId_t id, SST::Params& params)
    : SST::Component(id) {
  output_.init("[SSTSimEng:SimEngCoreWrapper] " + getName() + ":@p:@l ", 999, 0,
               SST::Output::STDOUT);
  clock_ = registerClock(params.find<std::string>("clock", "1GHz"),
                         new SST::Clock::Handler<SimEngCoreWrapper>(
                             this, &SimEngCoreWrapper::clockTick));

  // Extract variables from config.py
  simengConfigPath_ = params.find<std::string>("simeng_config_path", "");
  cacheLineWidth_ = params.find<uint64_t>("cache_line_width", "64");
  maxAddrMemory_ = params.find<uint64_t>("max_addr_memory", "0");
  //   source_ = params.find<std::string>("source", "");
  //   assembleWithSource_ = params.find<bool>("assemble_with_source", false);
  //   heapStr_ = params.find<std::string>("heap", "");
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
      new StandardMem::Handler<SimEngCoreWrapper>(
          this, &SimEngCoreWrapper::handleMemoryEvent));

  output_.verbose(CALL_INFO, 1, 0, "Declare instrInterface_\n");
  instrInterface_ = loadUserSubComponent<SST::Interfaces::StandardMem>(
      "instrMemory", ComponentInfo::SHARE_NONE, clock_,
      new StandardMem::Handler<SimEngCoreWrapper>(
          this, &SimEngCoreWrapper::handleMemoryEvent));

  output_.verbose(CALL_INFO, 1, 0, "Declare memInterface_\n");
  memInterface_ = std::make_shared<SimEngMemInterface>(
      dataInterface_, instrInterface_, cacheLineWidth_, maxAddrMemory_, debug_);

  output_.verbose(CALL_INFO, 1, 0, "Declare handlers_\n");
  handlers_ =
      new SimEngMemInterface::SimEngMemHandlers(*memInterface_, &output_);

  // Instantiate the NOC
  output_.verbose(CALL_INFO, 1, 0, "Declare noc_\n");
  sstNoc_ = loadUserSubComponent<nocAPI>("noc");
  sstNoc_->setRecvNotifyHandler(new Event::Handler<SimEngCoreWrapper>(
      this, &SimEngCoreWrapper::handleNetworkEvent));

  // Protected methods from SST::Component used to start simulation
  // registerAsPrimaryComponent();
  // primaryComponentDoNotEndSim();
  output_.verbose(CALL_INFO, 1, 0, "Constructor complete\n");
}

SimEngCoreWrapper::~SimEngCoreWrapper() {}

void SimEngCoreWrapper::init(unsigned int phase) {
  dataInterface_->init(phase);
  instrInterface_->init(phase);
  output_.verbose(CALL_INFO, 1, 0, "Memory init complete phase %d\n", phase);

  sstNoc_->init(phase);
  output_.verbose(CALL_INFO, 1, 0, "NOC init complete phase %d\n", phase);
}

void SimEngCoreWrapper::setup() {
  dataInterface_->setup();
  instrInterface_->setup();
  output_.verbose(CALL_INFO, 1, 0, "Memory setup complete\n");

  sstNoc_->setup();
  output_.verbose(CALL_INFO, 1, 0, "NOC setup complete\n");

  fabricateSimEngCore();

  // Run Simulation
  // std::cout << "[SimEng] Starting...\n" << std::endl;
  startTime_ = std::chrono::high_resolution_clock::now();
}

void SimEngCoreWrapper::finish() {
  // Get timing information
  auto endTime = std::chrono::high_resolution_clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                      endTime - startTime_)
                      .count();
  double khz =
      (iterations_ / (static_cast<double>(duration) / 1000.0)) / 1000.0;
  uint64_t retired = core_->getInstructionsRetiredCount();
  double mips = (retired / (static_cast<double>(duration))) / 1000.0;

  // Print stats
  std::cout << std::endl;
  auto stats = core_->getStats();
  for (const auto& [key, value] : stats) {
    std::cout << "[SimEng] " << key << ": " << value << std::endl;
  }
  std::cout << std::endl;
  std::cout << "[SimEng] Finished " << iterations_ << " ticks in " << duration
            << "ms (" << std::round(khz) << " kHz, " << std::setprecision(2)
            << mips << " MIPS)" << std::endl;
}

bool SimEngCoreWrapper::clockTick(SST::Cycle_t current_cycle) {
  sstNoc_->clockTick(current_cycle);
  // output_.verbose(CALL_INFO, 1, 0, "tick %llu\n", current_cycle);
  // Tick the core and memory interfaces until the program has halted
  if (core_->getStatus() != simeng::CoreStatus::halted ||
      mmu_->hasPendingRequests()) {
    // Tick the core
    core_->tick();

    // Tick MMU
    mmu_->tick();

    // Tick Memory
    memInterface_->tick();

    iterations_++;

    return false;
  } else {
    //   Protected method from SST::Component used to end SST simulation
    // primaryComponentOKToEndSim();
    return true;
  }
}

void SimEngCoreWrapper::fabricateSimEngCore() {
  output_.verbose(CALL_INFO, 1, 0, "Setting up SimEng Core\n");

  simeng::config::SimInfo::setConfig(simengConfigPath_);

  mmu_ = std::make_shared<simeng::memory::MMU>(
      [this](uint64_t vaddr, uint64_t pid) -> uint64_t {
        return translateVAddr(vaddr, pid);
      });

  mmuPort_ = mmu_->initPort();
  memPort_ = memInterface_->initMemPort();

  connection_->connect(mmuPort_, memPort_);

  coreInstance_ = std::make_unique<simeng::CoreInstance>(
      mmu_,
      [this](simeng::OS::SyscallInfo info) -> void {
        return sendSyscall(info);
      },
      [this](simeng::OS::cpuContext ctx, uint16_t coreId,
             simeng::CoreStatus status, uint64_t ticks) -> void {
        return updateCoreDescInOS(ctx, coreId, status, ticks);
      });

  core_ = coreInstance_->getCore();

  core_->setCoreId(static_cast<uint16_t>(sstNoc_->getEndpointId()));

  output_.verbose(CALL_INFO, 1, 0, "SimEng core %u setup successfully.\n",
                  core_->getCoreId());
}

void SimEngCoreWrapper::handleMemoryEvent(StandardMem::Request* memEvent) {
  memEvent->handle(handlers_);
}

void SimEngCoreWrapper::handleNetworkEvent(SST::Event* netEvent) {
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
      core_->schedule(cntx);
      break;
    }
    case PacketType::Syscall: {
      syscallEv* sysRes = static_cast<syscallEv*>(netEvent);
      if (debug_) {
        output_.verbose(CALL_INFO, 1, 0,
                        "Received PacketType::Syscall msg from %s\n\t- CoreId: "
                        "%u\n\t- SyscallId: %llu\n",
                        sysRes->getSource().c_str(), sysRes->getSourceId(),
                        sysRes->getPayload().syscallId);
      }
      core_->receiveSyscallResult(sysRes->getPayload());
      break;
    }
    case PacketType::Translate: {
      transEv* translation = static_cast<transEv*>(netEvent);
      uint64_t vaddr = translation->getVirtualAddr();
      uint64_t paddr = translation->getPhysicalAddr();
      if (debug_) {
        // output_.verbose(
        //     CALL_INFO, 1, 0,
        //     "Received PacketType::Translate msg from %s\n\t- CoreId: %u\n\t-
        //     " "VAddr: %llx (%llx)\n\t- PID: %llu\n\t- PAddr: %llx (% llx)\n
        //     ", translation->getSource().c_str(), translation->getSourceId(),
        //     translation->getVirtualAddr(),
        //     downAlign(vaddr, simeng::OS::PAGE_SIZE), translation->getPID(),
        //     translation->getPhysicalAddr(),
        //     downAlign(paddr, simeng::OS::PAGE_SIZE));
      }

      fakeTLB_[downAlign(vaddr, simeng::OS::PAGE_SIZE)] =
          downAlign(paddr, simeng::OS::PAGE_SIZE);
      mmu_->supplyDelayedTranslation(vaddr, paddr);
      break;
    }
    case PacketType::RequestCoreInfo: {
      coreInfoReqEv* cinfoReq = static_cast<coreInfoReqEv*>(netEvent);
      if (debug_) {
        output_.verbose(
            CALL_INFO, 1, 0,
            "Received PacketType::RequestCoreInfo msg from %s\n\t- CoreId: "
            "%u\n",
            cinfoReq->getSource().c_str(), cinfoReq->getSourceId());
      }

      coreInfoEv* cinfo = new coreInfoEv(getName(), core_->getCoreId(), true,
                                         cinfoReq->isForClone());
      cinfo->setPayload({core_->getCoreId(), core_->getStatus(),
                         core_->getCurrentContext(),
                         core_->getCurrentProcTicks()});
      sstNoc_->send(cinfo, 0);
      break;
    }
    case PacketType::Interrupt: {
      interruptEv* intrpt = static_cast<interruptEv*>(netEvent);
      if (debug_) {
        output_.verbose(
            CALL_INFO, 1, 0,
            "Received PacketType::Interrupt msg from %s\n\t- CoreId: %u\n",
            intrpt->getSource().c_str(), intrpt->getSourceId());
      }
      bool success = core_->interrupt();
      interruptEv* intrptRet = static_cast<interruptEv*>(intrpt->clone());
      intrptRet->setSuccess(success);

      sstNoc_->send(intrptRet, 0);
      break;
    }
    case PacketType::Register: {
      registerEv* regReq = static_cast<registerEv*>(netEvent);
      if (debug_) {
        output_.verbose(
            CALL_INFO, 1, 0,
            "Received PacketType::Register msg from %s\n\t- CoreId: %u\n",
            regReq->getSource().c_str(), regReq->getSourceId());
      }
      registerEv* regRet = static_cast<registerEv*>(regReq->clone());
      regRet->setPayload(core_->getCoreId(), core_->getStatus(),
                         core_->getCurrentContext());
      sstNoc_->send(regRet, 0);
      break;
    }
    default:
      break;
  }
  delete event;
}

uint64_t SimEngCoreWrapper::translateVAddr(uint64_t vaddr, uint64_t pid) {
  // std::cerr << "Translating " << std::hex << vaddr << std::dec << std::endl;
  uint64_t alignedVaddr = downAlign(vaddr, simeng::OS::PAGE_SIZE);
  if (fakeTLB_.find(alignedVaddr) != fakeTLB_.end()) {
    // std::cerr << "\tReturning " << std::hex
    //           << (vaddr & (simeng::OS::PAGE_SIZE - 1)) +
    //           fakeTLB_[alignedVaddr]
    //           << std::dec << std::endl;
    return (vaddr & (simeng::OS::PAGE_SIZE - 1)) + fakeTLB_[alignedVaddr];
  } else {
    transEv* translation = new transEv(getName(), core_->getCoreId());
    translation->setVirtualAddr(vaddr, pid);
    sstNoc_->send(translation, 0);

    uint64_t retVal = simeng::OS::masks::faults::pagetable::FAULT;
    retVal = retVal | simeng::OS::masks::faults::pagetable::PENDING;
    // std::cerr << "\tReturning " << std::hex << retVal << std::dec <<
    // std::endl;
    return retVal;
  }
}

void SimEngCoreWrapper::updateCoreDescInOS(simeng::OS::cpuContext ctx,
                                           uint16_t coreId,
                                           simeng::CoreStatus status,
                                           uint64_t ticks) {
  coreInfoEv* cInfoEv = new coreInfoEv(getName(), core_->getCoreId());
  cInfoEv->setPayload({coreId, status, ctx, ticks});
  sstNoc_->send(cInfoEv, 0);
}

void SimEngCoreWrapper::sendSyscall(simeng::OS::SyscallInfo info) {
  syscallInfoEv* sysInfo = new syscallInfoEv(getName(), core_->getCoreId());
  sysInfo->setPayload(info);
  sstNoc_->send(sysInfo, 0);
}

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
      // delimiting or escape behavior even with double quotes. e.g "arg1=1
      // arg2='"Hi"' arg3=2" will be parsed as std::vector<std::string>{arg1=1,
      // arg2="Hi", arg3=2}
      if (currChar == '\'' && escapeSingle) {
        escapeSingle = 0;
      }
      // If a portion of the argument string starts with a double quote (") and
      // we encounter another double quote, capture the substring enclosed by a
      // valid set of double quotes into an argument without producing any
      // delimiting or escape behavior even with single quotes. e.g "arg1=1
      // arg2="James' Car" arg3=2" will be parsed as
      // std::vector<std::string>{arg1=1, arg2=James' Car, arg3=2}
      else if (currChar == '\"' && escapeDouble) {
        escapeDouble = 0;
      } else {
        str += currChar;
      }
    } else if (currChar == ' ') {
      if (str != "") {
        args.push_back(str);
        str = "";
      }
    }
    // Check for escape character ("), this signals the algorithm to capture any
    // char inside a set of ("") without producing any delimiting or escape
    // behavior.
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
  if (escapeSingle || escapeDouble) {
    std::string err;
    output_.verbose(CALL_INFO, 1, 0, R"(
           Parsing failed: Invalid format - Please make sure all
           characters/strings are escaped properly within a set single or
           double quotes. To escape quotes use (\\\) instead of (\).\n
           )");
    std::cerr << "[SSTSimEng:SimEngCoreWrapper] Error occured at index "
              << index << " of the argument string - substring: "
              << "[ " << str << " ]" << std::endl;
    std::exit(EXIT_FAILURE);
  }
  args.push_back(str);
  return args;
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
}

// std::vector<uint64_t> SimEngCoreWrapper::splitHeapStr() {
//   std::vector<uint64_t> out;
//   std::string acc = "";
//   for (size_t a = 0; a < heapStr_.size(); a++) {
//     if (heapStr_[a] == ',') {
//       out.push_back(static_cast<uint64_t>(std::stoull(acc)));
//       acc = "";
//     } else {
//       acc += heapStr_[a];
//     }
//   }
//   out.push_back(static_cast<uint64_t>(std::stoull(acc)));
//   return out;
// }

// void SimEngCoreWrapper::initialiseHeapData() {
//   std::vector<uint8_t> initialHeapData;
//   std::vector<uint64_t> heapVals = splitHeapStr();
//   uint64_t heapSize = heapVals.size() * 8;
//   initialHeapData.resize(heapSize);
//   uint64_t* heap = reinterpret_cast<uint64_t*>(initialHeapData.data());
//   for (size_t x = 0; x < heapVals.size(); x++) {
//     heap[x] = heapVals[x];
//   }
//   // uint64_t heapStart = coreInstance_->getHeapStart();
//   // std::copy(initialHeapData.begin(), initialHeapData.end(),
//   //           coreInstance_->getProcessImage().get() + heapStart);
// }