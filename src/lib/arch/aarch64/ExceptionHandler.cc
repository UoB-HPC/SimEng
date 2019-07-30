#include "simeng/arch/aarch64/ExceptionHandler.hh"

#include <iomanip>
#include <iostream>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

ExceptionHandler::ExceptionHandler(
    const std::shared_ptr<simeng::Instruction>& instruction,
    const ArchitecturalRegisterFileSet& registerFileSet,
    MemoryInterface& memory, kernel::Linux& linux_)
    : instruction_(*static_cast<Instruction*>(instruction.get())),
      registerFileSet_(registerFileSet),
      memory_(memory),
      linux_(linux_) {
  resumeHandling_ = [this]() { return init(); };
}

bool ExceptionHandler::tick() { return resumeHandling_(); }

bool ExceptionHandler::init() {
  InstructionException exception = instruction_.getException();

  if (exception == InstructionException::SupervisorCall) {
    // Retrieve syscall ID held in register x8
    auto syscallId =
        registerFileSet_.get({RegisterType::GENERAL, 8}).get<uint64_t>();

    ProcessStateChange stateChange;
    switch (syscallId) {
      case 78: {  // readlinkat
        const auto pathnameAddress = registerFileSet_.get(R1).get<uint64_t>();

        // Copy string at `pathnameAddress`
        auto pathname = new char[kernel::Linux::LINUX_PATH_MAX];
        return readStringThen(pathname, pathnameAddress,
                              kernel::Linux::LINUX_PATH_MAX,
                              [this, pathname](auto length) {
                                // Pass the string `readLinkAt`, then destroy
                                // the buffer and resolve the handler.
                                readLinkAt({pathname, length});
                                delete[] pathname;
                                return true;
                              });
      }
      case 94: {  // exit_group
        auto exitCode = registerFileSet_.get(R0).get<uint64_t>();
        std::cout << "Received exit_group syscall: terminating with exit code "
                  << exitCode << std::endl;
        return fatal();
      }
      case 96: {  // set_tid_address
        uint64_t ptr = registerFileSet_.get(R0).get<uint64_t>();
        stateChange = {{R0}, {linux_.setTidAddress(ptr)}};
        break;
      }
      case 160: {  // uname
        const uint64_t base = registerFileSet_.get(R0).get<uint64_t>();
        const uint8_t len =
            65;  // Reserved length of each string field in Linux
        const char sysname[] = "Linux";
        const char nodename[] = "simeng.hpc.cs.bris.ac.uk";
        const char release[] = "0.0.0";
        const char version[] = "#1 SimEng Mon Apr 29 16:28:37 UTC 2019";
        const char machine[] = "aarch64";

        stateChange = {{R0},
                       {static_cast<uint64_t>(0)},
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
      case 174:  // getuid
        stateChange = {{R0}, {linux_.getuid()}};
        break;
      case 175:  // geteuid
        stateChange = {{R0}, {linux_.geteuid()}};
        break;
      case 176:  // getgid
        stateChange = {{R0}, {linux_.getgid()}};
        break;
      case 177:  // getegid
        stateChange = {{R0}, {linux_.getegid()}};
        break;
      case 214: {  // brk
        auto result = linux_.brk(registerFileSet_.get(R0).get<uint64_t>());
        stateChange = {{R0}, {static_cast<uint64_t>(result)}};
        break;
      }
      default:
        printException(instruction_);
        std::cout << "Unrecognised syscall" << std::endl;
        return fatal();
    }

    return concludeSyscall(stateChange);
  }

  printException(instruction_);
  return fatal();
}

bool ExceptionHandler::readStringThen(char* buffer, uint64_t address,
                                      int maxLength,
                                      std::function<bool(size_t length)> then,
                                      int offset) {
  if (maxLength <= 0) {
    return then(offset);
  }

  if (offset == -1) {
    // First call; trigger read for address 0
    memory_.requestRead({address + offset + 1, 1});
    resumeHandling_ = [=]() {
      return readStringThen(buffer, address, maxLength, then, offset + 1);
    };
    return false;
  }

  // Search completed memory requests for the needed data
  bool found = false;
  for (const auto& response : memory_.getCompletedReads()) {
    if (response.first.address == address + offset) {
      // TODO: Detect and handle any faults
      assert(response.second && "Memory read failed");
      buffer[offset] = response.second.get<char>();
      found = true;
      break;
    }
  }
  memory_.clearCompletedReads();

  if (!found) {
    // Leave this handler in place to call again
    return false;
  }

  if (buffer[offset] == '\0') {
    // End of string; call onwards
    return then(offset);
  }

  if (offset + 1 == maxLength) {
    // Reached max length; call onwards
    return then(maxLength);
  }

  // Queue up read for next character
  memory_.requestRead({address + offset + 1, 1});
  resumeHandling_ = [=]() {
    return readStringThen(buffer, address, maxLength, then, offset + 1);
  };
  return false;
}

void ExceptionHandler::readLinkAt(span<char> path) {
  if (path.size() == kernel::Linux::LINUX_PATH_MAX) {
    // TODO: Handle LINUX_PATH_MAX case
    std::cout << "Path exceeds LINUX_PATH_MAX" << std::endl;
    fatal();
    return;
  }

  const auto dirfd = registerFileSet_.get(R0).get<int64_t>();
  const auto bufAddress = registerFileSet_.get(R2).get<uint64_t>();
  const auto bufSize = registerFileSet_.get(R3).get<uint64_t>();

  char buffer[kernel::Linux::LINUX_PATH_MAX];
  auto result = linux_.readlinkat(dirfd, path.data(), buffer, bufSize);

  if (result < 0) {
    // TODO: Handle error case
    std::cout << "Error generated by readlinkat" << std::endl;
    fatal();
    return;
  }

  auto bytesCopied = static_cast<uint64_t>(result);

  ProcessStateChange stateChange = {{R0}, {result}};

  // Slice the returned path into <256-byte chunks for writing
  const char* bufPtr = buffer;
  for (size_t i = 0; i < bytesCopied; i += 256) {
    uint8_t size = std::min<uint64_t>(bytesCopied - i, 256ul);
    stateChange.memoryAddresses.push_back({bufAddress + i, size});
    stateChange.memoryAddressValues.push_back(RegisterValue(bufPtr, size));
  }

  concludeSyscall(stateChange);
}

bool ExceptionHandler::concludeSyscall(ProcessStateChange& stateChange) {
  uint64_t nextInstructionAddress = instruction_.getInstructionAddress() + 4;
  result_ = {false, nextInstructionAddress, stateChange};
  return true;
}

const ExceptionResult& ExceptionHandler::getResult() const { return result_; }

void ExceptionHandler::printException(const Instruction& insn) const {
  auto exception = insn.getException();
  std::cout << std::endl;
  std::cout << "Encountered ";
  switch (exception) {
    case InstructionException::EncodingUnallocated:
      std::cout << "illegal instruction";
      break;
    case InstructionException::ExecutionNotYetImplemented:
      std::cout << "execution not-yet-implemented";
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
    default:
      std::cout << "unknown (id: " << static_cast<unsigned int>(exception)
                << ")";
  }
  std::cout << " exception\n";

  std::cout << "  Generated by instruction: \n"
            << "    0x" << std::hex << std::setfill('0') << std::setw(16)
            << insn.getInstructionAddress() << ": ";

  auto& metadata = insn.getMetadata();
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
  std::cout << "\n      opcode ID: " << metadata.opcode;
  std::cout << std::endl;
}

bool ExceptionHandler::fatal() {
  result_ = {true, 0, {}};
  return true;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
