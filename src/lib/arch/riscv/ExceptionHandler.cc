#include "simeng/arch/riscv/ExceptionHandler.hh"

#include <iomanip>
#include <iostream>

#include "InstructionMetadata.hh"
#include "simeng/ArchitecturalRegisterFileSet.hh"

namespace simeng {
namespace arch {
namespace riscv {

ExceptionHandler::ExceptionHandler(
    const std::shared_ptr<simeng::Instruction>& instruction, const Core& core,
    MemoryInterface& memory, kernel::Linux& linux_)
    : instruction_(*static_cast<Instruction*>(instruction.get())),
      core(core),
      memory_(memory),
      linux_(linux_) {
  resumeHandling_ = [this]() { return init(); };
}

bool ExceptionHandler::tick() { return resumeHandling_(); }

bool ExceptionHandler::init() {
  InstructionException exception = instruction_.getException();
  const auto& registerFileSet = core.getArchitecturalRegisterFileSet();

  if (exception == InstructionException::SupervisorCall) {
    // Retrieve syscall ID held in register a7
    auto syscallId =
        registerFileSet.get({RegisterType::GENERAL, 17}).get<uint64_t>();

    ProcessStateChange stateChange;
    switch (syscallId) {
//      case 29: {  // ioctl
//        int64_t fd = registerFileSet.get(R0).get<int64_t>();
//        uint64_t request = registerFileSet.get(R1).get<uint64_t>();
//        uint64_t argp = registerFileSet.get(R2).get<uint64_t>();
//
//        std::vector<char> out;
//        int64_t retval = linux_.ioctl(fd, request, out);
//
//        assert(out.size() < 256 && "large ioctl() output not implemented");
//        uint8_t outSize = static_cast<uint8_t>(out.size());
//        stateChange = {ChangeType::REPLACEMENT, {R0}, {retval}};
//        stateChange.memoryAddresses.push_back({argp, outSize});
//        stateChange.memoryAddressValues.push_back(
//            RegisterValue(reinterpret_cast<const char*>(out.data()), outSize));
//        break;
//      }
//      case 56: {  // openat
//        int64_t dirfd = registerFileSet.get(R0).get<int64_t>();
//        uint64_t pathnamePtr = registerFileSet.get(R1).get<uint64_t>();
//        int64_t flags = registerFileSet.get(R2).get<int64_t>();
//        uint16_t mode = registerFileSet.get(R3).get<uint16_t>();
//
//        char* pathname = new char[kernel::Linux::LINUX_PATH_MAX];
//        return readStringThen(pathname, pathnamePtr,
//                              kernel::Linux::LINUX_PATH_MAX, [=](auto length) {
//                                // Invoke the kernel
//                                uint64_t retval =
//                                    linux_.openat(dirfd, pathname, flags, mode);
//                                ProcessStateChange stateChange = {
//                                    ChangeType::REPLACEMENT, {R0}, {retval}};
//                                delete[] pathname;
//                                return concludeSyscall(stateChange);
//                              });
//        break;
//      }
//      case 57: {  // close
//        int64_t fd = registerFileSet.get(R0).get<int64_t>();
//        stateChange = {ChangeType::REPLACEMENT, {R0}, {linux_.close(fd)}};
//        break;
//      }
//      case 62: {  // lseek
//        int64_t fd = registerFileSet.get(R0).get<int64_t>();
//        uint64_t offset = registerFileSet.get(R1).get<uint64_t>();
//        int64_t whence = registerFileSet.get(R2).get<uint64_t>();
//        stateChange = {
//            ChangeType::REPLACEMENT, {R0}, {linux_.lseek(fd, offset, whence)}};
//        break;
//      }
//      case 63: {  // read
//        int64_t fd = registerFileSet.get(R0).get<int64_t>();
//        uint64_t bufPtr = registerFileSet.get(R1).get<uint64_t>();
//        uint64_t count = registerFileSet.get(R2).get<uint64_t>();
//        return readBufferThen(bufPtr, count, [=]() {
//          int64_t totalRead = linux_.read(fd, dataBuffer.data(), count);
//          ProcessStateChange stateChange = {
//              ChangeType::REPLACEMENT, {R0}, {totalRead}};
//          // Check for failure
//          if (totalRead < 0) {
//            return concludeSyscall(stateChange);
//          }
//
//          int64_t bytesRemaining = totalRead;
//          // Get pointer and size of the buffer
//          uint64_t iDst = bufPtr;
//          uint64_t iLength = bytesRemaining;
//          if (iLength > bytesRemaining) {
//            iLength = bytesRemaining;
//          }
//          bytesRemaining -= iLength;
//
//          // Write data for this buffer in 128-byte chunks
//          auto iSrc = reinterpret_cast<const char*>(dataBuffer.data());
//          while (iLength > 0) {
//            uint8_t len = iLength > 128 ? 128 : static_cast<uint8_t>(iLength);
//            stateChange.memoryAddresses.push_back({iDst, len});
//            stateChange.memoryAddressValues.push_back({iSrc, len});
//            iDst += len;
//            iSrc += len;
//            iLength -= len;
//          }
//          return concludeSyscall(stateChange);
//        });
//      }
//      case 65: {  // readv
//        int64_t fd = registerFileSet.get(R0).get<int64_t>();
//        uint64_t iov = registerFileSet.get(R1).get<uint64_t>();
//        int64_t iovcnt = registerFileSet.get(R2).get<int64_t>();
//
//        // The pointer `iov` points to an array of structures that each contain
//        // a pointer to where the data should be written and the number of
//        // bytes to write.
//        //
//        // We're going to queue up two handlers:
//        // - First, read the iovec structures that describe each buffer.
//        // - Second, invoke the kernel to perform the read operation, and
//        //   generate memory write requests for each buffer.
//
//        // Create the second handler in the chain, which invokes the kernel and
//        // generates the memory write requests.
//        auto invokeKernel = [=]() {
//          // The iov structure has been read into `dataBuffer`
//          uint64_t* iovdata = reinterpret_cast<uint64_t*>(dataBuffer.data());
//
//          // Allocate buffers to hold the data read by the kernel
//          std::vector<std::vector<uint8_t>> buffers(iovcnt);
//          for (int64_t i = 0; i < iovcnt; i++) {
//            buffers[i].resize(iovdata[i * 2 + 1]);
//          }
//
//          // Build new iovec structures using pointers to `dataBuffer` data
//          std::vector<uint64_t> iovec(iovcnt * 2);
//          for (int64_t i = 0; i < iovcnt; i++) {
//            iovec[i * 2 + 0] = reinterpret_cast<uint64_t>(buffers[i].data());
//            iovec[i * 2 + 1] = iovdata[i * 2 + 1];
//          }
//
//          // Invoke the kernel
//          int64_t totalRead = linux_.readv(fd, iovec.data(), iovcnt);
//          ProcessStateChange stateChange = {
//              ChangeType::REPLACEMENT, {R0}, {totalRead}};
//
//          // Check for failure
//          if (totalRead < 0) {
//            return concludeSyscall(stateChange);
//          }
//
//          // Build list of memory write operations
//          int64_t bytesRemaining = totalRead;
//          for (int64_t i = 0; i < iovcnt; i++) {
//            // Get pointer and size of the buffer
//            uint64_t iDst = iovdata[i * 2 + 0];
//            uint64_t iLength = iovdata[i * 2 + 1];
//            if (iLength > bytesRemaining) {
//              iLength = bytesRemaining;
//            }
//            bytesRemaining -= iLength;
//
//            // Write data for this buffer in 128-byte chunks
//            auto iSrc = reinterpret_cast<const char*>(buffers[i].data());
//            while (iLength > 0) {
//              uint8_t len = iLength > 128 ? 128 : static_cast<uint8_t>(iLength);
//              stateChange.memoryAddresses.push_back({iDst, len});
//              stateChange.memoryAddressValues.push_back({iSrc, len});
//              iDst += len;
//              iSrc += len;
//              iLength -= len;
//            }
//          }
//
//          return concludeSyscall(stateChange);
//        };
//
//        // Run the buffer read to load the buffer structures, before invoking
//        // the kernel.
//        return readBufferThen(iov, iovcnt * 16, invokeKernel);
//      }
//      case 64: {  // write
//        int64_t fd = registerFileSet.get(R0).get<int64_t>();
//        uint64_t bufPtr = registerFileSet.get(R1).get<uint64_t>();
//        uint64_t count = registerFileSet.get(R2).get<uint64_t>();
//        return readBufferThen(bufPtr, count, [=]() {
//          int64_t retval = linux_.write(fd, dataBuffer.data(), count);
//          ProcessStateChange stateChange = {
//              ChangeType::REPLACEMENT, {R0}, {retval}};
//          return concludeSyscall(stateChange);
//        });
//      }
      case 66: {  // writev
        int64_t fd = registerFileSet.get(R0).get<int64_t>();
        uint64_t iov = registerFileSet.get(R1).get<uint64_t>();
        int64_t iovcnt = registerFileSet.get(R2).get<int64_t>();

        std::cout << fd << ":" << iov << ":" << iovcnt << std::endl;

        // The pointer `iov` points to an array of structures that each contain
        // a pointer to the data and the size of the data as an integer.
        //
        // We're going to queue up a chain of handlers:
        // - First, read the iovec structures that describe each buffer.
        // - Next, read the data for each buffer.
        // - Finally, invoke the kernel to perform the write operation.

        // Create the final handler in the chain, which invokes the kernel
        std::function<bool()> last = [=]() {
          // Rebuild the iovec structures using pointers to `dataBuffer` data
          uint64_t* iovdata = reinterpret_cast<uint64_t*>(dataBuffer.data());
          uint8_t* bufferPtr = dataBuffer.data() + iovcnt * 16;
          for (int64_t i = 0; i < iovcnt; i++) {
            iovdata[i * 2 + 0] = reinterpret_cast<uint64_t>(bufferPtr);

            // Get the length of this buffer and add it to the current pointer
            uint64_t len = iovdata[i * 2 + 1];
            bufferPtr += len;
          }

          // Invoke the kernel
          int64_t retval = linux_.writev(fd, dataBuffer.data(), iovcnt);
          ProcessStateChange stateChange = {
              ChangeType::REPLACEMENT, {R0}, {retval}};
          return concludeSyscall(stateChange);
        };

        // Build the chain of buffer loads backwards through the iov buffers
        for (int64_t i = iovcnt - 1; i >= 0; i--) {
          last = [=]() {
            uint64_t* iovdata = reinterpret_cast<uint64_t*>(dataBuffer.data());
            uint64_t ptr = iovdata[i * 2 + 0];
            uint64_t len = iovdata[i * 2 + 1];
            return readBufferThen(ptr, len, last);
          };
        }

        // Run the first buffer read to load the buffer structures, before
        // performing each of the buffer loads.
        return readBufferThen(iov, iovcnt * 16, last);
      }
//      case 78: {  // readlinkat
//        const auto pathnameAddress = registerFileSet.get(R1).get<uint64_t>();
//
//        // Copy string at `pathnameAddress`
//        auto pathname = new char[kernel::Linux::LINUX_PATH_MAX];
//        return readStringThen(pathname, pathnameAddress,
//                              kernel::Linux::LINUX_PATH_MAX,
//                              [this, pathname](auto length) {
//                                // Pass the string `readLinkAt`, then destroy
//                                // the buffer and resolve the handler.
//                                readLinkAt({pathname, length});
//                                delete[] pathname;
//                                return true;
//                              });
//      }
//      case 80: {  // fstat
//        int64_t fd = registerFileSet.get(R0).get<int64_t>();
//        uint64_t statbufPtr = registerFileSet.get(R1).get<uint64_t>();
//
//        kernel::stat statOut;
//        stateChange = {
//            ChangeType::REPLACEMENT, {R0}, {linux_.fstat(fd, statOut)}};
//        stateChange.memoryAddresses.push_back({statbufPtr, sizeof(statOut)});
//        stateChange.memoryAddressValues.push_back(statOut);
//        break;
//      }
//      case 94: {  // exit_group
//        auto exitCode = registerFileSet.get(R0).get<uint64_t>();
//        std::cout << "Received exit_group syscall: terminating with exit code "
//                  << exitCode << std::endl;
//        return fatal();
//      }
//      case 96: {  // set_tid_address
//        uint64_t ptr = registerFileSet.get(R0).get<uint64_t>();
//        stateChange = {
//            ChangeType::REPLACEMENT, {R0}, {linux_.setTidAddress(ptr)}};
//        break;
//      }
//      case 113: {  // clock_gettime
//        uint64_t clkId = registerFileSet.get(R0).get<uint64_t>();
//        uint64_t systemTimer = core.getSystemTimer();
//
//        uint64_t seconds;
//        uint64_t nanoseconds;
//        uint64_t retval =
//            linux_.clockGetTime(clkId, systemTimer, seconds, nanoseconds);
//        stateChange = {ChangeType::REPLACEMENT, {R0}, {retval}};
//
//        uint64_t timespecPtr = registerFileSet.get(R1).get<uint64_t>();
//        stateChange.memoryAddresses.push_back({timespecPtr, 8});
//        stateChange.memoryAddressValues.push_back(seconds);
//        stateChange.memoryAddresses.push_back({timespecPtr + 8, 8});
//        stateChange.memoryAddressValues.push_back(nanoseconds);
//        break;
//      }
      case 160: {  // uname
        const uint64_t base = registerFileSet.get(R0).get<uint64_t>();
        const uint8_t len =
            65;  // Reserved length of each string field in Linux
        const char sysname[] = "Linux";
        const char nodename[] = "simeng.hpc.cs.bris.ac.uk";
        const char release[] = "4.14.0";
        const char version[] = "#1 SimEng Mon Apr 29 16:28:37 UTC 2019";
        const char machine[] = "riscv64";

        stateChange = {ChangeType::REPLACEMENT,
                       {R0},
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
//      case 169: {  // gettimeofday
//        uint64_t tvPtr = registerFileSet.get(R0).get<uint64_t>();
//        uint64_t tzPtr = registerFileSet.get(R1).get<uint64_t>();
//        uint64_t systemTimer = core.getSystemTimer();
//
//        kernel::timeval tv;
//        kernel::timeval tz;
//        int64_t retval = linux_.gettimeofday(systemTimer, tvPtr ? &tv : nullptr,
//                                             tzPtr ? &tz : nullptr);
//        stateChange = {ChangeType::REPLACEMENT, {R0}, {retval}};
//        if (tvPtr) {
//          stateChange.memoryAddresses.push_back({tvPtr, 16});
//          stateChange.memoryAddressValues.push_back(tv);
//        }
//        if (tzPtr) {
//          stateChange.memoryAddresses.push_back({tzPtr, 16});
//          stateChange.memoryAddressValues.push_back(tz);
//        }
//        break;
//      }
      case 174:  // getuid
        stateChange = {ChangeType::REPLACEMENT, {R0}, {linux_.getuid()}};
        break;
      case 175:  // geteuid
        stateChange = {ChangeType::REPLACEMENT, {R0}, {linux_.geteuid()}};
        break;
      case 176:  // getgid
        stateChange = {ChangeType::REPLACEMENT, {R0}, {linux_.getgid()}};
        break;
      case 177:  // getegid
        stateChange = {ChangeType::REPLACEMENT, {R0}, {linux_.getegid()}};
        break;
      case 214: {  // brk
        auto result = linux_.brk(registerFileSet.get(R0).get<uint64_t>());
        stateChange = {
            ChangeType::REPLACEMENT, {R0}, {static_cast<uint64_t>(result)}};
        break;
      }
      default:
        printException(instruction_);
        std::cout << "Unrecognised syscall: " << syscallId << std::endl;
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
    if (response.target.address == address + offset) {
      // TODO: Detect and handle any faults
      assert(response.data && "Memory read failed");
      buffer[offset] = response.data.get<char>();
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

  const auto& registerFileSet = core.getArchitecturalRegisterFileSet();
  const auto dirfd = registerFileSet.get(R0).get<int64_t>();
  const auto bufAddress = registerFileSet.get(R2).get<uint64_t>();
  const auto bufSize = registerFileSet.get(R3).get<uint64_t>();

  char buffer[kernel::Linux::LINUX_PATH_MAX];
  auto result = linux_.readlinkat(dirfd, path.data(), buffer, bufSize);

  if (result < 0) {
    // TODO: Handle error case
    std::cout << "Error generated by readlinkat" << std::endl;
    fatal();
    return;
  }

  auto bytesCopied = static_cast<uint64_t>(result);

  ProcessStateChange stateChange = {ChangeType::REPLACEMENT, {R0}, {result}};

  // Slice the returned path into <256-byte chunks for writing
  const char* bufPtr = buffer;
  for (size_t i = 0; i < bytesCopied; i += 256) {
    uint8_t size = std::min<uint64_t>(bytesCopied - i, 256ul);
    stateChange.memoryAddresses.push_back({bufAddress + i, size});
    stateChange.memoryAddressValues.push_back(RegisterValue(bufPtr, size));
  }

  concludeSyscall(stateChange);
}

bool ExceptionHandler::readBufferThen(uint64_t ptr, uint64_t length,
                                      std::function<bool()> then,
                                      bool firstCall) {
  // If first call, trigger read for first entry and set self as handler
  if (firstCall) {
    if (length == 0) {
      return then();
    }

    // Request a read of up to 128 bytes
    uint64_t numBytes = std::min<uint64_t>(length, 128);
    memory_.requestRead({ptr, static_cast<uint8_t>(numBytes)},
                        instruction_.getSequenceId());
    resumeHandling_ = [=]() {
      return readBufferThen(ptr, length, then, false);
    };
  }

  // Check whether read has completed
  auto completedReads = memory_.getCompletedReads();
  auto response =
      std::find_if(completedReads.begin(), completedReads.end(),
                   [&](const MemoryReadResult& response) {
                     return response.requestId == instruction_.getSequenceId();
                   });
  if (response == completedReads.end()) {
    return false;
  }

  // Append data to buffer
  assert(response->data && "unhandled failed read in exception handler");
  uint8_t bytesRead = response->target.size;
  const uint8_t* data = response->data.getAsVector<uint8_t>();
  dataBuffer.insert(dataBuffer.end(), data, data + bytesRead);
  memory_.clearCompletedReads();

  // If there is more data, rerun this function for next chunk
  if (bytesRead < length) {
    return readBufferThen(ptr + bytesRead, length - bytesRead, then, true);
  }

  // All done - call onwards
  return then();
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
