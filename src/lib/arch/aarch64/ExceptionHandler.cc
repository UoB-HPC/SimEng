#include "simeng/arch/aarch64/ExceptionHandler.hh"

#include <iomanip>
#include <iostream>

#include "InstructionMetadata.hh"
#include "simeng/ArchitecturalRegisterFileSet.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** Helper constants for AArch64 general-purpose registers. */
static const Register R0 = {RegisterType::GENERAL, 0};
static const Register R1 = {RegisterType::GENERAL, 1};
static const Register R2 = {RegisterType::GENERAL, 2};
static const Register R3 = {RegisterType::GENERAL, 3};
static const Register R4 = {RegisterType::GENERAL, 4};
static const Register R5 = {RegisterType::GENERAL, 5};

ExceptionHandler::ExceptionHandler(const Core& core) : core_(core) {}

bool ExceptionHandler::tick() {
  // If an exception corresponding to a syscall was encountered and passed to
  // the simulated Operating System's syscall handler, conclude the syscall only
  // once the result has been returned
  if (invokingSycallHandler_) {
    if (!syscallReturned_) return false;
    return concludeSyscall();
  }

  // If no instruction with a generated exception has been registered return,
  // otherwise, handle the registered exception.
  if (instruction_ == nullptr)
    return false;
  else
    return handleException();
}

void ExceptionHandler::registerException(
    std::shared_ptr<simeng::Instruction> instruction) {
  instruction_ = std::static_pointer_cast<aarch64::Instruction>(instruction);
}

bool ExceptionHandler::handleException() {
  result_ = {};

  InstructionException exception = instruction_->getException();
  const auto& registerFileSet = core_.getArchitecturalRegisterFileSet();

  if (exception == InstructionException::SupervisorCall) {
    // Retrieve syscall ID held in register x8
    auto syscallId =
        registerFileSet.get({RegisterType::GENERAL, 8}).get<uint64_t>();

    simeng::OS::ProcessStateChange stateChange = {};
    switch (syscallId) {
      case 29:     // ioctl
      case 46:     // ftruncate
      case 48:     // faccessat
      case 56:     // openat
      case 57:     // close
      case 61:     // getdents64
      case 62:     // lseek
      case 63:     // rea
      case 64:     // write
      case 65:     // readv
      case 66:     // writev
      case 78:     // readlinkat
      case 79:     // newfstatat AKA fstatat
      case 80:     // fstat
      case 93:     // exit
      case 94:     // exit_group
      case 96:     // set_tid_address
      case 98:     // futex
      case 99:     // set_robust_list
      case 113:    // clock_gettime
      case 122:    // sched_setaffinity
      case 123:    // sched_getaffinity
      case 124:    // sched_yield
      case 131:    // tgkill
      case 134:    // rt_sigaction
      case 135:    // rt_sigprocmask
      case 165:    // getrusage
      case 169:    // gettimeofday
      case 178:    // gettid
      case 172:    // getpid
      case 174:    // getuid
      case 175:    // geteuid
      case 176:    // getgid
      case 177:    // getegid
      case 179:    // sysinfo
      case 210:    // shutdown
      case 214:    // brk
      case 215:    // munmap
      case 220:    // clone
      case 222:    // mmap
      case 226:    // mprotect
      case 233:    // madvise
      case 261:    // prlimit64
      case 278:    // getrandom
      case 293: {  // rseq
        core_.sendSyscall({syscallId,
                           core_.getCoreId(),
                           core_.getCurrentTID(),
                           {registerFileSet.get(R0), registerFileSet.get(R1),
                            registerFileSet.get(R2), registerFileSet.get(R3),
                            registerFileSet.get(R4), registerFileSet.get(R5)},
                           R0});
        invokingSycallHandler_ = true;
        return false;
      }
      case 160: {  // uname
        // Uname return can be core dependent, thus don't hand over to more
        // generic syscall handler.
        const uint64_t base = registerFileSet.get(R0).get<uint64_t>();
        const uint8_t len =
            65;  // Reserved length of each string field in Linux
        const char sysname[] = "Linux";
        const char nodename[] = "simeng.hpc.cs.bris.ac.uk";
        const char release[] = "4.14.0";
        const char version[] = "#1 SimEng Mon Apr 29 16:28:37 UTC 2019";
        const char machine[] = "aarch64";

        stateChange = {simeng::OS::ChangeType::REPLACEMENT,
                       {R0},
                       {0ull},
                       {{base, sizeof(sysname)},
                        {base + len, sizeof(nodename)},
                        {base + (len * 2), sizeof(release)},
                        {base + (len * 3), sizeof(version)},
                        {base + (len * 4), sizeof(machine)}},
                       {RegisterValue(sysname), RegisterValue(nodename),
                        RegisterValue(release), RegisterValue(version),
                        RegisterValue(machine)}};
        break;
      }
      default:
        printException();
        std::cout << "\n[SimEng:ExceptionHandler] Unrecognised syscall: "
                  << syscallId << std::endl;
        return fatal();
    }

    processSyscallResult({false, false, 0, 0, stateChange});
    return concludeSyscall();
  } else if (exception == InstructionException::StreamingModeUpdate ||
             exception == InstructionException::ZAregisterStatusUpdate ||
             exception == InstructionException::SMZAUpdate) {
    // Retrieve register file structure from architecture
    auto regFileStruct = SimInfo::getArchRegStruct();
    // Retrieve metadata from architecture
    auto metadata = instruction_->getMetadata();

    // Update SVCR value
    const uint64_t svcrBits = static_cast<uint64_t>(metadata.operands[0].svcr);
    const uint8_t imm = metadata.operands[1].imm;
    const uint64_t currSVCR = instruction_->getArchitecture().getSVCRval();
    uint64_t newSVCR = 0;

    if (imm == 0) {
      // Zero out relevant bits dictated by svcrBits
      const uint64_t mask = 0xFFFFFFFFFFFFFFFF ^ svcrBits;
      newSVCR = currSVCR & mask;
    } else if (imm == 1) {
      // Enable relevant bits, dictated by svcrBits
      const uint64_t mask = 0xFFFFFFFFFFFFFFFF & svcrBits;
      newSVCR = currSVCR | mask;
    } else {
      // Invalid instruction
      assert("SVCR Instruction invalid - Imm value can only be 0 or 1");
    }

    // Initialise vectors for all registers & values
    std::vector<Register> regs;
    std::vector<RegisterValue> regValues;

    // Add Vector/Predicate registers + 0 values (zeroed out on Streaming Mode
    // context switch)
    if (exception != InstructionException::ZAregisterStatusUpdate) {
      for (uint16_t i = 0; i < regFileStruct[RegisterType::VECTOR].quantity;
           i++) {
        regs.push_back({RegisterType::VECTOR, i});
        regValues.push_back(RegisterValue(0, 256));
        if (i < regFileStruct[RegisterType::PREDICATE].quantity) {
          regs.push_back({RegisterType::PREDICATE, i});
          regValues.push_back(RegisterValue(0, 32));
        }
      }
    }
    // Zero out ZA register (zeroed out on ZA-reg context switch)
    if (exception != InstructionException::StreamingModeUpdate) {
      for (uint16_t i = 0; i < regFileStruct[RegisterType::MATRIX].quantity;
           i++) {
        regs.push_back({RegisterType::MATRIX, i});
        regValues.push_back(RegisterValue(0, 256));
      }
    }
    // Update SVCR System Register
    regs.push_back({RegisterType::SYSTEM,
                    static_cast<uint16_t>(
                        instruction_->getArchitecture().getSystemRegisterTag(
                            ARM64_SYSREG_SVCR))});
    regValues.push_back(RegisterValue(newSVCR, 8));
    instruction_->getArchitecture().setSVCRval(newSVCR);

    simeng::OS::ProcessStateChange stateChange = {
        simeng::OS::ChangeType::REPLACEMENT, regs, regValues};
    processSyscallResult({false, false, 0, 0, stateChange});
    return concludeSyscall();
  }

  printException();
  return fatal();
}

void ExceptionHandler::processSyscallResult(
    const simeng::OS::SyscallResult syscallResult) {
  syscallResult_ = syscallResult;
  syscallReturned_ = true;
}

bool ExceptionHandler::concludeSyscall() {
  if (syscallResult_.fatal) {
    // If result was fatal, search through known exceptions to identify errors
    // or lacking support
    const auto& registerFileSet = core_.getArchitecturalRegisterFileSet();
    switch (syscallResult_.syscallId) {
      case 98: {  // futex
        // TODO: Functionality temporarily omitted as it is unused within
        // workloads regions of interest and not required for their simulation
        int op = registerFileSet.get(R1).get<int>();
        if (op != 129) {
          printException();
          std::cout << "\n[SimEng:ExceptionHandler] Unsupported arguments for "
                       "syscall: "
                    << syscallResult_.syscallId << std::endl;
        }
        break;
      }
      case 123: {  // sched_getaffinity
        int64_t bitmask =
            syscallResult_.stateChange.memoryAddressValues[0].get<int64_t>();
        // Currently, only a single CPU bitmask is supported
        if (bitmask != 1) {
          printException();
          std::cout << "[SimEng:SyscallHandler] Unexpected CPU affinity mask "
                       "returned in exception handler"
                    << std::endl;
        }
        break;
      }
      case 220: {
        std::cout << "[SimEng:SyscallHandler] Unsupported Flags for syscall: "
                  << syscallResult_.syscallId << std::endl;
      }
    }
    return fatal();
  }

  uint64_t nextInstructionAddress = instruction_->getInstructionAddress() + 4;
  result_ = {false, syscallResult_.idleAfterSyscall, nextInstructionAddress,
             syscallResult_.stateChange};

  resetState();
  return true;
}

const ExceptionResult& ExceptionHandler::getResult() const { return result_; }

void ExceptionHandler::printException() const {
  auto exception = instruction_->getException();
  std::cout << std::endl;
  std::cout << "[SimEng:ExceptionHandler] Encountered ";
  switch (exception) {
    case InstructionException::EncodingUnallocated:
      std::cout << "illegal instruction";
      break;
    case InstructionException::ExecutionNotYetImplemented:
      std::cout << "execution not-yet-implemented";
      break;
    case InstructionException::MisalignedPC:
      std::cout << "misaligned program counter";
      break;
    case InstructionException::DataAbort:
      std::cout << "data abort";
      break;
    case InstructionException::SupervisorCall:
      std::cout << "supervisor call";
      break;
    case InstructionException::HypervisorCall:
      std::cout << "hypervisor call";
      break;
    case InstructionException::SecureMonitorCall:
      std::cout << "secure monitor call";
      break;
    case InstructionException::NoAvailablePort:
      std::cout << "unsupported execution port";
      break;
    case InstructionException::UnmappedSysReg:
      std::cout << "unmapped system register";
      break;
    case InstructionException::StreamingModeUpdate:
      std::cout << "streaming mode update";
      break;
    case InstructionException::ZAregisterStatusUpdate:
      std::cout << "ZA register status update";
      break;
    case InstructionException::SMZAUpdate:
      std::cout << "streaming mode & ZA register status update";
      break;
    case InstructionException::ZAdisabled:
      std::cout << "ZA register access attempt when disabled";
      break;
    case InstructionException::SMdisabled:
      std::cout << "SME execution attempt when streaming mode disabled";
      break;
    default:
      std::cout << "unknown (id: " << static_cast<unsigned int>(exception)
                << ")";
  }
  std::cout << " exception" << std::endl;

  std::cout << "[SimEng:ExceptionHandler]   Generated by instruction:"
            << std::endl;
  std::cout << "[SimEng:ExceptionHandler]     0x" << std::hex
            << std::setfill('0') << std::setw(16)
            << instruction_->getInstructionAddress() << ": ";

  auto& metadata = instruction_->getMetadata();
  for (uint8_t byte : metadata.encoding) {
    std::cout << std::setfill('0') << std::setw(2)
              << static_cast<unsigned int>(byte) << " ";
  }
  std::cout << std::dec << "    ";
  if (exception == InstructionException::EncodingUnallocated) {
    std::cout << "<unknown>";
  } else {
    std::cout << metadata.mnemonic << " " << metadata.operandStr;
  }
  std::cout << std::endl;
  std::cout << "[SimEng:ExceptionHandler]       opcode ID: " << metadata.opcode
            << std::endl;
}

bool ExceptionHandler::fatal() {
  result_ = {true, false, 0, {}};
  resetState();
  return true;
}

void ExceptionHandler::resetState() {
  // Reset state of handler
  instruction_ = nullptr;
  syscallReturned_ = false;
  invokingSycallHandler_ = false;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
