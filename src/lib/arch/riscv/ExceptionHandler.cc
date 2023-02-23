#include "simeng/arch/riscv/ExceptionHandler.hh"

#include <iomanip>
#include <iostream>

#include "InstructionMetadata.hh"
#include "simeng/ArchitecturalRegisterFileSet.hh"

namespace simeng {
namespace arch {
namespace riscv {

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
  instruction_ = std::static_pointer_cast<riscv::Instruction>(instruction);
}

bool ExceptionHandler::handleException() {
  result_ = {};

  InstructionException exception = instruction_->getException();
  const auto& registerFileSet = core_.getArchitecturalRegisterFileSet();

  if (exception == InstructionException::SupervisorCall) {
    // Retrieve syscall ID held in register a7
    auto syscallId =
        registerFileSet.get({RegisterType::GENERAL, 17}).get<uint64_t>();

    simeng::OS::ProcessStateChange stateChange;
    switch (syscallId) {
      case 29:     // ioctl
      case 46:     // ftruncate
      case 48:     // faccessat
      case 56:     // openat
      case 57:     // close
      case 61:     // getdents64
      case 62:     // lseek
      case 63:     // read
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
      case 131:    // tgkill
      case 134:    // rt_sigaction
      case 135:    // rt_sigprocmask
      case 165:    // getrusage
      case 169:    // gettimeofday
      case 172:    // getpid
      case 174:    // getuid
      case 175:    // geteuid
      case 176:    // getgid
      case 177:    // getegid
      case 178:    // gettid
      case 179:    // sysinfo
      case 210:    // shutdown
      case 214:    // brk
      case 215:    // munmap
      case 222:    // mmap
      case 226:    // mprotect
      case 261:    // prlimit64
      case 278:    // getrandom
      case 293: {  // rseq
        core_.sendSyscall({syscallId,
                           0,
                           0,
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
        const char nodename[] = "fedora-riscv";
        const char release[] = "5.5.0-0.rc5.git0.1.1.riscv64.fc32.riscv64";
        const char version[] = "#1 SMP Mon Jan 6 17:31:22 UTC 2020";
        const char machine[] = "riscv64";
        const char domainname[] = "(none)";

        stateChange = {simeng::OS::ChangeType::REPLACEMENT,
                       {R0},
                       {0ull},
                       {{base, sizeof(sysname)},
                        {base + len, sizeof(nodename)},
                        {base + (len * 2), sizeof(release)},
                        {base + (len * 3), sizeof(version)},
                        {base + (len * 4), sizeof(machine)},
                        {base + (len * 5), sizeof(domainname)}},
                       {RegisterValue(sysname), RegisterValue(nodename),
                        RegisterValue(release), RegisterValue(version),
                        RegisterValue(machine), RegisterValue(domainname)}};
        break;
      }

      default:
        printException();
        std::cout << "\n[SimEng:ExceptionHandler] Unrecognised syscall: "
                  << syscallId << std::endl;
        return fatal();
    }

    processSyscallResult({false, 0, 0, stateChange});
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
    // If result was fatal, search through known exceptions to identify
    // errors or lacking support
    const auto& registerFileSet = core_.getArchitecturalRegisterFileSet();
    switch (syscallResult_.syscallId) {
      case 98: {  // futex
        // TODO: Functionality temporarily omitted as it is unused within
        // workloads regions of interest and not required for their
        // simulation
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
          std::cout << "Unexpected CPU affinity mask returned in exception "
                       "handler"
                    << std::endl;
        }
        break;
      }
    }
    return fatal();
  }

  uint64_t nextInstructionAddress = instruction_->getInstructionAddress() + 4;
  result_ = {false, nextInstructionAddress, syscallResult_.stateChange};

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
    default:
      std::cout << "unknown (id: " << static_cast<unsigned int>(exception)
                << ")";
  }
  std::cout << " exception\n";

  std::cout << "[SimEng:ExceptionHandler]  Generated by instruction: \n"
            << "[SimEng:ExceptionHandler]    0x" << std::hex
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
  std::cout << "[SimEng:ExceptionHandler]      opcode ID: " << metadata.opcode;
  std::cout << std::endl;
}

bool ExceptionHandler::fatal() {
  result_ = {true, 0, {}};
  resetState();
  return true;
}

void ExceptionHandler::resetState() {
  // Reset state of handler
  instruction_ = nullptr;
  syscallReturned_ = false;
  invokingSycallHandler_ = false;
}

}  // namespace riscv
}  // namespace arch
}  // namespace simeng
