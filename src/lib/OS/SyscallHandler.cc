#include "simeng/OS/SyscallHandler.hh"

#include <signal.h>

#include <algorithm>
#include <cstdint>
#include <ctime>

#include "simeng/OS/Constants.hh"
#include "simeng/OS/SimOS.hh"

namespace simeng {
namespace OS {

SyscallHandler::SyscallHandler(
    SimOS* OS, std::shared_ptr<simeng::memory::Mem> memory,
    std::function<void(const SyscallResult)> sendSyscallResultToCore)
    : OS_(OS),
      memory_(memory),
      sendSyscallResultToCore_(sendSyscallResultToCore) {
  // Define vector of all currently supported special file paths & files.
  supportedSpecialFiles_.insert(
      supportedSpecialFiles_.end(),
      {"/proc/cpuinfo", "proc/stat", "proc/self/maps", "maps",
       "/sys/devices/system/cpu", "/sys/devices/system/cpu/online", "core_id",
       "physical_package_id"});

  resumeHandling_ = [this]() { return handleSyscall(); };
}

std::shared_ptr<Port<std::unique_ptr<simeng::memory::MemPacket>>>
SyscallHandler::initMemPort() {
  memPort_ =
      std::make_shared<Port<std::unique_ptr<simeng::memory::MemPacket>>>();
  auto fn = [this](std::unique_ptr<simeng::memory::MemPacket> packet) -> void {
    if (packet->isRead()) {
      memRead_ = {{packet->vaddr_, packet->size_},
                  RegisterValue(packet->payload().data(), packet->size_),
                  packet->insnSeqId_};
    }
    if (packet->isWrite()) {
      OS_->informWriteResponse(std::move(packet));
    }
    reqMemAccess_ = false;
  };
  memPort_->registerReceiver(fn);
  return memPort_;
}

void SyscallHandler::receiveSyscall(SyscallInfo info) {
  syscallQueue_.push(info);
}

void SyscallHandler::tick() {
  if (reqMemAccess_) return;
  resumeHandling_();
}

void SyscallHandler::handleSyscall() {
  if (syscallQueue_.empty()) return;
  // Update currentInfo_
  if (currentInfo_.started) {
    return;
  }

  syscallQueue_.front().started = true;
  currentInfo_ = syscallQueue_.front();

  // std::cerr << currentInfo_.threadId << "| Starting Syscall "
  //           << currentInfo_.syscallId << std::endl;

  ProcessStateChange stateChange = {};

  switch (currentInfo_.syscallId) {
    case 29: {  // ioctl
      int64_t fd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t request = currentInfo_.registerArguments[1].get<uint64_t>();
      uint64_t argp = currentInfo_.registerArguments[2].get<uint64_t>();

      std::vector<char> out;
      int64_t retval = ioctl(fd, request, out);

      assert(out.size() < 256 &&
             "[SimEng:SyscallHandler] large ioctl() output not implemented");
      uint8_t outSize = static_cast<uint8_t>(out.size());
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
      stateChange.memoryAddresses.push_back({argp, outSize});
      stateChange.memoryAddressValues.push_back(
          RegisterValue(reinterpret_cast<const char*>(out.data()), outSize));
      break;
    }
    case 46: {  // ftruncate
      uint64_t fd = currentInfo_.registerArguments[0].get<uint64_t>();
      uint64_t length = currentInfo_.registerArguments[1].get<uint64_t>();
      stateChange = {
          ChangeType::REPLACEMENT, {currentInfo_.ret}, {ftruncate(fd, length)}};
      break;
    }
    case 48: {  // faccessat
      int64_t dfd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t filenamePtr = currentInfo_.registerArguments[1].get<uint64_t>();
      int64_t mode = currentInfo_.registerArguments[2].get<int64_t>();
      // flag component not used, although function definition includes it
      int64_t flag = 0;

      char* filename = (char*)malloc(PATH_MAX_LEN * sizeof(char));
      return readStringThen(
          filename, filenamePtr, PATH_MAX_LEN, [=](auto length) {
            // Invoke the kernel
            int64_t retval =
                faccessat(dfd, std::string(filename, length), mode, flag);
            ProcessStateChange stateChange = {
                ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
            concludeSyscall(stateChange);
            free(filename);
          });
      break;
    }
    case 56: {  // openat
      int64_t dirfd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t pathnamePtr = currentInfo_.registerArguments[1].get<uint64_t>();
      int64_t flags = currentInfo_.registerArguments[2].get<int64_t>();
      uint16_t mode = currentInfo_.registerArguments[3].get<uint16_t>();

      char* pathname = (char*)malloc(PATH_MAX_LEN * sizeof(char));
      return readStringThen(
          pathname, pathnamePtr, PATH_MAX_LEN, [=](auto length) {
            // Invoke the kernel
            uint64_t retval =
                openat(dirfd, std::string(pathname, length), flags, mode);
            ProcessStateChange stateChange = {
                ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
            concludeSyscall(stateChange);
            free(pathname);
          });
      break;
    }
    case 57: {  // close
      int64_t fd = currentInfo_.registerArguments[0].get<int64_t>();
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {close(fd)}};
      break;
    }
    case 61: {  // getdents64
      int64_t fd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t bufPtr = currentInfo_.registerArguments[1].get<uint64_t>();
      uint64_t count = currentInfo_.registerArguments[2].get<uint64_t>();

      return readBufferThen(bufPtr, count, [=]() {
        int64_t totalRead = getdents64(fd, dataBuffer_.data(), count);
        ProcessStateChange stateChange = {
            ChangeType::REPLACEMENT, {currentInfo_.ret}, {totalRead}};
        // Check for failure
        if (totalRead < 0) {
          return concludeSyscall(stateChange);
        }

        int64_t bytesRemaining = totalRead;
        // Get pointer and size of the buffer
        uint64_t iDst = bufPtr;
        uint64_t iLength = bytesRemaining;
        if (iLength > bytesRemaining) {
          iLength = bytesRemaining;
        }
        bytesRemaining -= iLength;
        // Write data for this buffer in 128-byte chunks
        auto iSrc = dataBuffer_.data();
        while (iLength > 0) {
          uint8_t len = iLength > 128 ? 128 : static_cast<uint8_t>(iLength);
          stateChange.memoryAddresses.push_back({iDst, len});
          stateChange.memoryAddressValues.push_back({iSrc, len});
          iDst += len;
          iSrc += len;
          iLength -= len;
        }
        concludeSyscall(stateChange);
      });
      break;
    }
    case 62: {  // lseek
      int64_t fd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t offset = currentInfo_.registerArguments[1].get<uint64_t>();
      int64_t whence = currentInfo_.registerArguments[2].get<uint64_t>();
      stateChange = {ChangeType::REPLACEMENT,
                     {currentInfo_.ret},
                     {lseek(fd, offset, whence)}};
      break;
    }
    case 63: {  // read
      int64_t fd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t bufPtr = currentInfo_.registerArguments[1].get<uint64_t>();
      uint64_t count = currentInfo_.registerArguments[2].get<uint64_t>();

      return readBufferThen(bufPtr, count, [=]() {
        int64_t totalRead = read(fd, dataBuffer_.data(), count);
        ProcessStateChange stateChange = {
            ChangeType::REPLACEMENT, {currentInfo_.ret}, {totalRead}};
        // Check for failure
        if (totalRead < 0) {
          return concludeSyscall(stateChange);
        }

        int64_t bytesRemaining = totalRead;
        // Get pointer and size of the buffer
        uint64_t iDst = bufPtr;
        uint64_t iLength = bytesRemaining;
        if (iLength > bytesRemaining) {
          iLength = bytesRemaining;
        }
        bytesRemaining -= iLength;

        // Write data for this buffer in 128-byte chunks
        auto iSrc = dataBuffer_.data();
        while (iLength > 0) {
          uint8_t len = iLength > 128 ? 128 : static_cast<uint8_t>(iLength);
          stateChange.memoryAddresses.push_back({iDst, len});
          stateChange.memoryAddressValues.push_back({iSrc, len});
          iDst += len;
          iSrc += len;
          iLength -= len;
        }
        concludeSyscall(stateChange);
      });
      break;
    }
    case 64: {  // write
      int64_t fd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t bufPtr = currentInfo_.registerArguments[1].get<uint64_t>();
      uint64_t count = currentInfo_.registerArguments[2].get<uint64_t>();

      return readBufferThen(bufPtr, count, [=]() {
        int64_t retval = write(fd, dataBuffer_.data(), count);
        ProcessStateChange stateChange = {
            ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
        concludeSyscall(stateChange);
      });
      break;
    }
    case 65: {  // readv
      int64_t fd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t iov = currentInfo_.registerArguments[1].get<uint64_t>();
      int64_t iovcnt = currentInfo_.registerArguments[2].get<int64_t>();

      // The pointer `iov` points to an array of structures that each contain
      // a pointer to where the data should be written and the number of
      // bytes to write.
      //
      // We're going to queue up two handlers:
      // - First, read the iovec structures that describe each buffer.
      // - Second, invoke the kernel to perform the read operation, and
      //   generate memory write requests for each buffer.

      // Create the second handler in the chain, which invokes the kernel and
      // generates the memory write requests.
      auto invokeKernel = [=]() {
        // The iov structure has been read into `dataBuffer_`
        uint64_t* iovdata = reinterpret_cast<uint64_t*>(dataBuffer_.data());

        // Allocate buffers to hold the data read by the kernel
        std::vector<std::vector<uint8_t>> buffers(iovcnt);
        for (int64_t i = 0; i < iovcnt; i++) {
          buffers[i].resize(iovdata[i * 2 + 1]);
        }

        // Build new iovec structures using pointers to `dataBuffer_` data
        std::vector<uint64_t> iovec(iovcnt * 2);
        for (int64_t i = 0; i < iovcnt; i++) {
          iovec[i * 2 + 0] = reinterpret_cast<uint64_t>(buffers[i].data());
          iovec[i * 2 + 1] = iovdata[i * 2 + 1];
        }

        // Invoke the kernel
        int64_t totalRead = readv(fd, iovec.data(), iovcnt);
        ProcessStateChange stateChange = {
            ChangeType::REPLACEMENT, {currentInfo_.ret}, {totalRead}};

        // Check for failure
        if (totalRead < 0) {
          return concludeSyscall(stateChange);
        }

        // Build list of memory write operations
        int64_t bytesRemaining = totalRead;
        for (int64_t i = 0; i < iovcnt; i++) {
          // Get pointer and size of the buffer
          uint64_t iDst = iovdata[i * 2 + 0];
          uint64_t iLength = iovdata[i * 2 + 1];
          if (iLength > bytesRemaining) {
            iLength = bytesRemaining;
          }
          bytesRemaining -= iLength;

          // Write data for this buffer in 128-byte chunks
          auto iSrc = reinterpret_cast<const char*>(buffers[i].data());
          while (iLength > 0) {
            uint8_t len = iLength > 128 ? 128 : static_cast<uint8_t>(iLength);
            stateChange.memoryAddresses.push_back({iDst, len});
            stateChange.memoryAddressValues.push_back({iSrc, len});
            iDst += len;
            iSrc += len;
            iLength -= len;
          }
        }

        concludeSyscall(stateChange);
      };

      // Run the buffer read to load the buffer structures, before invoking
      // the kernel.
      return readBufferThen(iov, iovcnt * 16, invokeKernel);
      break;
    }
    case 66: {  // writev
      int64_t fd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t iov = currentInfo_.registerArguments[1].get<uint64_t>();
      int64_t iovcnt = currentInfo_.registerArguments[2].get<int64_t>();

      // The pointer `iov` points to an array of structures that each contain
      // a pointer to the data and the size of the data as an integer.
      //
      // We're going to queue up a chain of handlers:
      // - First, read the iovec structures that describe each buffer.
      // - Next, read the data for each buffer.
      // - Finally, invoke the kernel to perform the write operation.

      // Create the final handler in the chain, which invokes the kernel
      std::function<void()> last = [=]() {
        // Check to see if the dataBuffer_ is empty due to an early conclusion
        // from a data abort fault on a virtual address translation within the
        // chain of buffer loads.
        if (dataBuffer_.size() == 0) return;

        // Rebuild the iovec structures using pointers to `dataBuffer_` data
        uint64_t* iovdata = reinterpret_cast<uint64_t*>(dataBuffer_.data());
        char* bufferPtr = dataBuffer_.data() + iovcnt * 16;
        for (int64_t i = 0; i < iovcnt; i++) {
          iovdata[i * 2 + 0] = reinterpret_cast<uint64_t>(bufferPtr);

          // Get the length of this buffer and add it to the current pointer
          uint64_t len = iovdata[i * 2 + 1];
          bufferPtr += len;
        }

        // Invoke the kernel
        int64_t retval = writev(fd, dataBuffer_.data(), iovcnt);
        ProcessStateChange stateChange = {
            ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
        concludeSyscall(stateChange);
      };

      // Build the chain of buffer loads backwards through the iov buffers
      for (int64_t i = iovcnt - 1; i >= 0; i--) {
        last = [=]() {
          uint64_t* iovdata = reinterpret_cast<uint64_t*>(dataBuffer_.data());
          uint64_t ptr = iovdata[i * 2 + 0];
          uint64_t len = iovdata[i * 2 + 1];

          return readBufferThen(ptr, len, last);
        };
      }

      // Run the first buffer read to load the buffer structures, before
      // performing each of the buffer loads.
      return readBufferThen(iov, iovcnt * 16, last);
      break;
    }
    case 78: {  // readlinkat
      const auto pathnameAddress =
          currentInfo_.registerArguments[1].get<uint64_t>();

      // Copy string at `pathnameAddress`
      char* pathname = (char*)malloc(PATH_MAX_LEN * sizeof(char));
      return readStringThen(pathname, pathnameAddress, PATH_MAX_LEN,
                            [=](auto length) {
                              // Pass the string `readLinkAt`, then destroy
                              // the buffer and resolve the handler.
                              readLinkAt(std::string(pathname, length), length);
                              free(pathname);
                              return;
                            });
      break;
    }
    case 79: {  // newfstatat AKA fstatat
      int64_t dfd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t filenamePtr = currentInfo_.registerArguments[1].get<uint64_t>();
      uint64_t statbufPtr = currentInfo_.registerArguments[2].get<uint64_t>();
      int64_t flag = currentInfo_.registerArguments[3].get<int64_t>();

      char* filename = (char*)malloc(PATH_MAX_LEN * sizeof(char));
      return readStringThen(
          filename, filenamePtr, PATH_MAX_LEN, [=](auto length) {
            // Invoke the kernel
            OS::stat statOut;
            uint64_t retval =
                newfstatat(dfd, std::string(filename, length), statOut, flag);
            ProcessStateChange stateChange = {
                ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
            stateChange.memoryAddresses.push_back(
                {statbufPtr, sizeof(statOut)});
            stateChange.memoryAddressValues.push_back(statOut);
            concludeSyscall(stateChange);
            free(filename);
          });
      break;
    }
    case 80: {  // fstat
      int64_t fd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t statbufPtr = currentInfo_.registerArguments[1].get<uint64_t>();

      OS::stat statOut;
      stateChange = {
          ChangeType::REPLACEMENT, {currentInfo_.ret}, {fstat(fd, statOut)}};
      stateChange.memoryAddresses.push_back({statbufPtr, sizeof(statOut)});
      stateChange.memoryAddressValues.push_back(statOut);
      break;
    }
    case 93: {  // exit
      auto exitCode = currentInfo_.registerArguments[0].get<uint64_t>();
      uint64_t tid = currentInfo_.threadId;
      // TODO: When `wait` is supported, return exitCode & 0xFF to parent
      // TODO: Call all functions registered with `atexit` and `on_exit`
      // TODO: Flush all open `stdio` streams when supported
      // TODO: Remove files created by `tmpfile` when supported
      OS_->terminateThread(tid);
      std::cout << "[SimEng:SyscallHandler] Received exit syscall on Thread "
                << tid << ". Terminating with exit code " << exitCode
                << std::endl;
      return concludeSyscall({}, false, true);
    }
    case 94: {  // exit_group
      auto exitCode = currentInfo_.registerArguments[0].get<uint64_t>();
      uint64_t tgid = OS_->getProcess(currentInfo_.threadId)->getTGID();
      // TODO: When `wait` is supported, return exitCode & 0xFF to parent
      // TODO: Call all functions registered with `atexit` and `on_exit`
      // TODO: Flush all open `stdio` streams when supported
      // TODO: Remove files created by `tmpfile` when supported
      OS_->terminateThreadGroup(tgid);
      std::cout << "[SimEng:SyscallHandler] Received exit_group syscall on "
                   "Thread Group "
                << tgid << ". Terminating with exit code " << exitCode
                << std::endl;
      return concludeSyscall({}, false, true);
    }
    case 96: {  // set_tid_address
      uint64_t ptr = currentInfo_.registerArguments[0].get<uint64_t>();
      stateChange = {
          ChangeType::REPLACEMENT, {currentInfo_.ret}, {setTidAddress(ptr)}};
      break;
    }
    case 98: {  // futex
      uint64_t addr = currentInfo_.registerArguments[0].get<uint64_t>();
      int32_t op = currentInfo_.registerArguments[1].get<int32_t>();
      uint32_t val = currentInfo_.registerArguments[2].get<uint32_t>();
      // TODO: Investigate values of the timespecPtr (4th arg) and usage with
      // current implementation of futex syscall.

      int syscallSupported = false;
      syscallSupported |= (op == syscalls::futex::futexop::SIMENG_FUTEX_WAKE);
      syscallSupported |= (op == syscalls::futex::futexop::SIMENG_FUTEX_WAIT);
      syscallSupported |=
          (op == syscalls::futex::futexop::SIMENG_FUTEX_WAKE_PRIVATE);
      syscallSupported |=
          (op == syscalls::futex::futexop::SIMENG_FUTEX_WAIT_PRIVATE);

      if (!syscallSupported) {
        std::cerr
            << "[SimEng:SyscallHandler] Arguments supplied to futex syscall "
               "not supported.\n"
            << "\tSupported Arguments:\n"
            << "\t\t futex_op:  FUTEX_WAIT, FUTEX_WAKE, FUTEX_WAKE_PRIVATE\n"
            << "\t\t const struct timespec *timeout: NULL\n"
            << "\t futex syscalls invoked with folowing arguments are not "
               "supported yet:\n"
            << "\t\tuint32_t val2\n"
            << "\t\tuint32_t *uaddr2\n"
            << "\t\tuint32_t val3" << std::endl;
        return concludeSyscall({}, true);
      }

      uint64_t paddr = OS_->handleVAddrTranslation(addr, currentInfo_.threadId);
      if (masks::faults::hasFault(paddr)) {
        std::cerr << "[SimEng:SyscallHandler] Fatal error occured during "
                     "virtual address translation in futex syscall: uaddr = "
                  << addr << std::endl;
        return concludeSyscall({}, true);
      }
      auto [putCoreToIdle, futexReturnValue] =
          futex(paddr, op, val, currentInfo_.threadId);
      // If the futex still relies on a memory access, do not conclude the
      // syscall until it has returned
      if (reqMemAccess_) return;
      return concludeSyscall(
          {ChangeType::REPLACEMENT, {currentInfo_.ret}, {futexReturnValue}},
          false, putCoreToIdle);
    }
    case 99: {  // set_robust_list
      // TODO: Functionality temporarily omitted as it is unused within
      // workloads regions of interest and not required for their simulation
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      break;
    }
    case 113: {  // clock_gettime
      uint64_t clkId = currentInfo_.registerArguments[0].get<uint64_t>();
      uint64_t systemTimer = OS_->getSystemTimer();

      uint64_t seconds;
      uint64_t nanoseconds;
      uint64_t retval = clockGetTime(clkId, systemTimer, seconds, nanoseconds);
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};

      uint64_t timespecPtr = currentInfo_.registerArguments[1].get<uint64_t>();
      stateChange.memoryAddresses.push_back({timespecPtr, 8});
      stateChange.memoryAddressValues.push_back(seconds);
      stateChange.memoryAddresses.push_back({timespecPtr + 8, 8});
      stateChange.memoryAddressValues.push_back(nanoseconds);
      break;
    }
    case 122: {  // sched_setaffinity
      pid_t pid = currentInfo_.registerArguments[0].get<pid_t>();
      size_t cpusetsize = currentInfo_.registerArguments[1].get<size_t>();
      uint64_t mask = currentInfo_.registerArguments[2].get<uint64_t>();

      int64_t retval = schedSetAffinity(pid, cpusetsize, mask);
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
      break;
    }
    case 123: {  // sched_getaffinity
      pid_t pid = currentInfo_.registerArguments[0].get<pid_t>();
      size_t cpusetsize = currentInfo_.registerArguments[1].get<size_t>();
      uint64_t mask = currentInfo_.registerArguments[2].get<uint64_t>();
      int64_t bitmask = schedGetAffinity(pid, cpusetsize, mask);
      // If returned bitmask is 0, assume an error
      if (bitmask > 0) {
        // Currently, only a single CPU bitmask is supported
        if (bitmask != 1) {
          return concludeSyscall({}, true);
        }
        uint64_t retval = static_cast<uint64_t>(bitmask);
        stateChange = {
            ChangeType::REPLACEMENT, {currentInfo_.ret}, {sizeof(retval)}};
        stateChange.memoryAddresses.push_back({mask, 8});
        stateChange.memoryAddressValues.push_back(bitmask);
      } else {
        stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {-1ll}};
      }
      break;
    }
    case 124: {  // sched_yield
      // Non args passed in
      // Have core go to idle after syscall, forcing the current Process to be
      // de-scheduled
      return concludeSyscall(
          {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}}, false, true);
    }
    case 131: {  // tgkill
      int tgid = currentInfo_.registerArguments[0].get<int>();
      int tid = currentInfo_.registerArguments[1].get<int>();
      int signal = currentInfo_.registerArguments[2].get<int>();
      int64_t retVal = 0;
      bool idleOnComplete = false;

      // Only support SIGABORT or no signal
      if (signal != SIGABRT || signal != 0) {
        retVal = -EINVAL;
      } else {
        auto proc = OS_->getProcess(tid);
        uint64_t procTgid = proc->getTGID();
        if (tgid == -1) {
          // Terminate all processes in thread group
          OS_->terminateThreadGroup(procTgid);
          std::cout << "[SimEng:SyscallHandler] Received tgkill syscall on "
                       "Thread Group "
                    << procTgid << ". Terminating with signal " << signal
                    << std::endl;
          idleOnComplete = true;
        } else {
          if (proc->getTGID() == tgid) {
            idleOnComplete = (proc->status_ == procStatus::executing);
            OS_->terminateThread(tid);
            std::cout
                << "[SimEng:SyscallHandler] Received tgkill syscall on Thread "
                << tid << " in Thread Group " << tgid
                << ". Terminating with signal " << signal << std::endl;
          } else {
            retVal = -ESRCH;
          }
        }
      }
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {retVal}};
      return concludeSyscall(stateChange, false, idleOnComplete);
    }
    case 134: {  // rt_sigaction
      // TODO: Implement syscall logic. Ignored for now as it's assumed the
      // current use of this syscall is to setup error handlers. Simualted
      // code is expected to work so no need for these handlers.
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      break;
    }
    case 135: {  // rt_sigprocmask
      // TODO: Implement syscall logic. Ignored for now as it's assumed the
      // current use of this syscall is to setup error handlers. Simualted
      // code is expected to work so no need for these handlers.
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      break;
    }
    case 165: {  // getrusage
      int who = currentInfo_.registerArguments[0].get<int>();
      uint64_t usagePtr = currentInfo_.registerArguments[1].get<uint64_t>();

      OS::rusage usageOut;
      stateChange = {ChangeType::REPLACEMENT,
                     {currentInfo_.ret},
                     {getrusage(who, usageOut)}};
      stateChange.memoryAddresses.push_back({usagePtr, sizeof(usageOut)});
      stateChange.memoryAddressValues.push_back(usageOut);
      break;
    }
    case 169: {  // gettimeofday
      uint64_t tvPtr = currentInfo_.registerArguments[0].get<uint64_t>();
      uint64_t tzPtr = currentInfo_.registerArguments[1].get<uint64_t>();
      uint64_t systemTimer = OS_->getSystemTimer();

      OS::timeval tv;
      OS::timeval tz;
      int64_t retval = gettimeofday(systemTimer, tvPtr ? &tv : nullptr,
                                    tzPtr ? &tz : nullptr);
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
      if (tvPtr) {
        stateChange.memoryAddresses.push_back({tvPtr, 16});
        stateChange.memoryAddressValues.push_back(tv);
      }
      if (tzPtr) {
        stateChange.memoryAddresses.push_back({tzPtr, 16});
        stateChange.memoryAddressValues.push_back(tz);
      }
      break;
    }
    case 172: {  // getpid
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {getpid()}};
      break;
    }
    case 174: {  // getuid
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {getuid()}};
      break;
    }
    case 175: {  // geteuid
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {geteuid()}};
      break;
    }
    case 176: {  // getgid
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {getgid()}};
      break;
    }
    case 177: {  // getegid
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {getegid()}};
      break;
    }
    case 178: {  // gettid
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {gettid()}};
      break;
    }
    case 179: {  // sysinfo
      // Sysinfo populates a sysinfo struct containing system information.
      // Currently, the majority of the sysinfo struct entries will be 0 for
      // SimEng's emulation of the syscall, therefore, we begin with a zero'ed
      // out std::array, `sysInfoVals`, to represent this struct. The mapping
      // between struct and `sysInfoVals` entries is as followed:
      //
      // {uptime, loads[0], loads[1], loads[2], totalram,
      // freeram, sharedram, bufferram, totalswap, freeswap,
      // procs,totalhigh, freehigh, mem_unit}
      //
      // (https://man7.org/linux/man-pages/man2/sysinfo.2.html has been used to
      // define the entries to be mapped and understand what they equate to.)
      //
      // Each entry is represented as an uint64_t value and later narrowed
      // implicity within the RegisterValue constructor where necessary.
      // `sysInfoValsSizes` is used to denote the sizes of each entry so that it
      // occupies the correct amount of memory after the syscall is concluded.

      uint64_t infoPtr = currentInfo_.registerArguments[0].get<uint64_t>();
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      std::array<uint64_t, 14> sysInfoVals;
      std::fill(sysInfoVals.begin(), sysInfoVals.end(), 0);
      std::array<uint8_t, 14> sysInfoValsSizes = {8, 8, 8, 8, 8, 8, 8,
                                                  8, 8, 8, 2, 8, 8, 4};
      // Populate those entries within the sysinfo struct which are currently
      // supported within SimEng
      sysInfoVals[0] = OS_->getSystemTimer() / 1e9;
      sysInfoVals[4] = memory_->getMemorySize();
      sysInfoVals[10] = OS_->getNumProcesses();
      // Add the sysinfo struct entries to stateChange in the correct order
      for (int val = 0; val < sysInfoVals.size(); val++) {
        uint8_t valSize = sysInfoValsSizes[val];
        stateChange.memoryAddresses.push_back({infoPtr, valSize});
        stateChange.memoryAddressValues.push_back({sysInfoVals[val], valSize});
        infoPtr += valSize;
      }
      break;
    }
    case 210: {  // shutdown
      // TODO: Functionality omitted - returns -38 (errno 38, function not
      // implemented) is to mimic the behaviour on isambard and avoid an
      // unrecognised syscall error
      stateChange = {ChangeType::REPLACEMENT,
                     {currentInfo_.ret},
                     {static_cast<int64_t>(-38)}};
      break;
    }
    case 214: {  // brk
      auto result = brk(currentInfo_.registerArguments[0].get<uint64_t>());
      stateChange = {ChangeType::REPLACEMENT,
                     {currentInfo_.ret},
                     {static_cast<uint64_t>(result)}};
      break;
    }
    case 215: {  // munmap
      uint64_t addr = currentInfo_.registerArguments[0].get<uint64_t>();
      size_t length = currentInfo_.registerArguments[1].get<size_t>();

      int64_t result = munmap(addr, length);
      // If successful, munmap returns the total number of bytes
      // unmapped. If the value is greater than 0, 0 is returned as specified
      // by the actual munmap specification. However, all negative values
      // returned by munmap are in accordance with the munmap specification,
      // so in case a negative value is returned it will remain the same.
      result = result >= 0 ? 0 : result;
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {result}};
      break;
    }
    case 220: {  // clone
      // Given this is the raw system call, the `fn` and `arg` arguments of the
      // `clone()` wrapper function are omitted
      uint64_t flags = currentInfo_.registerArguments[0].get<uint64_t>();
      uint64_t stackPtr = currentInfo_.registerArguments[1].get<uint64_t>();
      uint64_t parentTidPtr = currentInfo_.registerArguments[2].get<uint64_t>();
      uint64_t tls = currentInfo_.registerArguments[3].get<uint64_t>();
      uint64_t childTidPtr = currentInfo_.registerArguments[4].get<uint64_t>();

      int error = clone(flags, stackPtr, parentTidPtr, tls, childTidPtr);
      if (error < 0) {
        std::cout << "[SimEng:SyscallHandler] Error creating new thread via "
                     "clone syscall."
                  << std::endl;
        currentInfo_.started = false;
        stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {error}};
        break;
      }
      return;
    }
    case 222: {  // mmap
      uint64_t addr = currentInfo_.registerArguments[0].get<uint64_t>();
      size_t length = currentInfo_.registerArguments[1].get<size_t>();
      int prot = currentInfo_.registerArguments[2].get<int>();
      int flags = currentInfo_.registerArguments[3].get<int>();
      int fd = currentInfo_.registerArguments[4].get<int>();
      off_t offset = currentInfo_.registerArguments[5].get<off_t>();

      uint64_t result = mmap(addr, length, prot, flags, fd, offset);
      if (result <= 0) {
        stateChange = {ChangeType::REPLACEMENT,
                       {currentInfo_.ret},
                       {static_cast<int64_t>(-1)}};
      } else {
        stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {result}};
      }
      break;
    }
    case 226: {  // mprotect
      // mprotect is not supported
      // always return zero to indicate success
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      break;
    }
    case 233: {  // madvise
      // madvise is not supported
      // always return zero to indicate success
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      break;
    }
    case 235: {  // mbind
      // mbind is not supported due to all binaries being single threaded.
      // Always return zero to indicate success
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      break;
    }
    case 261: {  // prlimit64
      pid_t pid = currentInfo_.registerArguments[0].get<pid_t>();
      int resource = currentInfo_.registerArguments[1].get<int>();
      uint64_t newLimit = currentInfo_.registerArguments[2].get<uint64_t>();
      uint64_t oldLimit = currentInfo_.registerArguments[3].get<uint64_t>();
      int64_t retVal = 0;
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {retVal}};
      if (pid != 0) {
        // We only support changes to current process
        stateChange.modifiedRegisterValues[0] = -EPERM;
      } else {
        if (resource != RLIMIT_STACK) {
          std::cout << "[SimEng:SyscallHandler] Un-supported resource used in "
                       "prlimit64 syscall."
                    << std::endl;
          stateChange.modifiedRegisterValues[0] = -EINVAL;
        } else {
          if (newLimit) {
            // Update rlimit for Process
            uint64_t physAddr =
                OS_->handleVAddrTranslation(newLimit, currentInfo_.threadId);
            if (masks::faults::hasFault(physAddr)) {
              stateChange.modifiedRegisterValues[0] = -EFAULT;
            } else {
              rlimit newRlim;
              // If the read memory target does not equal the data required,
              // request it
              if (memRead_.target.vaddr != newLimit) {
                std::unique_ptr<simeng::memory::MemPacket> request =
                    simeng::memory::MemPacket::createReadRequest(
                        newLimit, sizeof(rlimit), currentInfo_.threadId, 0, 0);
                request->paddr_ = physAddr;
                reqMemAccess_ = true;
                memPort_->send(std::move(request));
                if (reqMemAccess_) return;
                return;
              }

              std::memcpy(&newRlim, memRead_.data.getAsVector<char>(),
                          sizeof(rlimit));
              OS_->getProcess(currentInfo_.threadId)->stackRlim_ = newRlim;
            }
          }
          if (oldLimit) {
            // Update rlimit struct pointed to by oldLimit
            // uint64_t physAddr =
            //     OS_->handleVAddrTranslation(oldLimit, currentInfo_.threadId);
            // if (masks::faults::hasFault(physAddr)) {
            //   stateChange.modifiedRegisterValues[0] = -EFAULT;
            // } else {
            rlimit rlim = OS_->getProcess(currentInfo_.threadId)->stackRlim_;
            std::vector<uint8_t> vec(sizeof(rlimit), '\0');
            std::memcpy(vec.data(), &rlim, sizeof(rlimit));
            // Write the new rlimit struct to memory
            for (size_t i = 0; i < sizeof(rlimit); i++) {
              stateChange.memoryAddresses.push_back({oldLimit + i, 1});
              stateChange.memoryAddressValues.push_back({vec[i], 1});
            }
            // std::unique_ptr<simeng::memory::MemPacket> request =
            //     simeng::memory::MemPacket::createWriteRequest(
            //         oldLimit, sizeof(rlimit), currentInfo_.threadId, 0, 0,
            //         vec);
            // request->paddr_ = physAddr;
            // memPort_->send(std::move(request));
            // }
          }
        }
      }

      break;
    }
    case 278: {  // getrandom
      // TODO: support flags argument

      // seed random numbers
      srand(clock());

      // Write <buflen> random bytes to buf
      uint64_t bufPtr = currentInfo_.registerArguments[0].get<uint64_t>();
      size_t buflen = currentInfo_.registerArguments[1].get<size_t>();

      char buf[buflen];
      for (size_t i = 0; i < buflen; i++) {
        buf[i] = (uint8_t)rand();
      }

      stateChange = {
          ChangeType::REPLACEMENT, {currentInfo_.ret}, {(uint64_t)buflen}};

      stateChange.memoryAddresses.push_back({bufPtr, (uint8_t)buflen});
      stateChange.memoryAddressValues.push_back(RegisterValue(buf, buflen));

      break;
    }
    case 293: {  // rseq
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      break;
    }

    default:
      break;
  }

  concludeSyscall(stateChange);
}

void SyscallHandler::readStringThen(char* buffer, uint64_t address,
                                    int maxLength,
                                    std::function<void(size_t length)> then) {
  if (maxLength <= 0) {
    return then(0);
  }

  // Translate the passed virtual address, `address + offset`
  uint64_t translatedAddr =
      OS_->handleVAddrTranslation(address, currentInfo_.threadId);

  // Don't process the syscall if the virtual address translation comes back
  // wih a DATA_ABORT or IGNORED fault. Given we read in a filename from
  // `translatedAddr`, both a DATA_ABORT and IGNORED fault will result in a
  // invalid filename and therefore, we cannot use it in further syscall
  // logic.
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(translatedAddr);
  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT ||
      faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    return concludeSyscall({}, true);
  } else {
    // Get a string from the simulation memory and within the passed buffer
    // If the read memory target does not equal the data required,
    // request it and resume the `readStringThen` call after its return
    if (memRead_.target.vaddr != address) {
      std::unique_ptr<simeng::memory::MemPacket> request =
          simeng::memory::MemPacket::createReadRequest(
              address, maxLength, currentInfo_.threadId, 0, 0);
      request->paddr_ = translatedAddr;
      reqMemAccess_ = true;
      memPort_->send(std::move(request));
      if (reqMemAccess_) {
        resumeHandling_ = [=]() {
          readStringThen(buffer, address, maxLength, then);
        };
        return;
      }
    }

    const char* data = memRead_.data.getAsVector<char>();

    for (int i = 0; i < memRead_.data.size(); i++) {
      buffer[i] = data[i];
      // End of string; call onwards
      if (buffer[i] == '\0') return then(i + 1);
    }

    // Reached max length; call onwards
    return then(maxLength);
  }
}

void SyscallHandler::resumeClone(int64_t tid) {
  if (tid > 0) {
    std::cout << "[SimEng:SyscallHandler] Clone syscall executed, new "
                 "thread created : TGID "
              << OS_->getProcess(tid)->getTGID() << ", TID " << tid
              << std::endl;
  } else {
    std::cout << "[SimEng:SyscallHandler] Error creating new thread via "
                 "clone syscall."
              << std::endl;
  }

  ProcessStateChange stateChange = {
      ChangeType::REPLACEMENT, {currentInfo_.ret}, {tid}};
  currentInfo_.started = false;
  return concludeSyscall(stateChange);
}

void SyscallHandler::readBufferThen(uint64_t ptr, uint64_t length,
                                    std::function<void()> then) {
  // If there's nothing to read, consider the read to be complete and call
  // onwards
  if (length == 0) {
    return then();
  }

  // Vector to hold data read from memory, will be inserted at the end of
  // dataBuffer_
  std::vector<char> data;

  // Translate the passed virtual address, `ptr`
  uint64_t translatedAddr =
      OS_->handleVAddrTranslation(ptr, currentInfo_.threadId);

  // Don't process the syscall if the virtual address translation comes back
  // wih a DATA_ABORT fault. If the address `translatedAddr` is not mapped, then
  // we cannot insert any data at the end of `dataBuffer_`.
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(translatedAddr);
  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT) {
    return concludeSyscall({}, true);
  } else if (faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    // If the translated address lies within the ignored region, read in
    // zero'ed out data of the correct length.
    data.resize(length);
    std::fill(data.begin(), data.end(), 0);
  } else {
    // Get data from the simulation memory and read into dataBuffer_
    // If the read memory target does not equal the data required,
    // request it and resume the `readBufferThen` call after its return
    if (memRead_.target.vaddr != ptr) {
      std::unique_ptr<simeng::memory::MemPacket> request =
          simeng::memory::MemPacket::createReadRequest(
              ptr, length, currentInfo_.threadId, 0, 0);
      request->paddr_ = translatedAddr;
      reqMemAccess_ = true;
      memPort_->send(std::move(request));
      if (reqMemAccess_) {
        resumeHandling_ = [=]() { readBufferThen(ptr, length, then); };
        return;
      }
    }

    const char* readData = memRead_.data.getAsVector<char>();
    data = std::vector<char>(readData, readData + memRead_.data.size());
  }
  dataBuffer_.insert(dataBuffer_.end(), data.begin(), data.begin() + length);

  // Read in data, call onwards
  return then();
}

void SyscallHandler::concludeSyscall(const ProcessStateChange& change,
                                     bool fatal, bool idleAftersycall) {
  currentInfo_.started = false;
  // std::cerr << currentInfo_.threadId << "| Syscall " <<
  // currentInfo_.syscallId
  //           << " results" << std::endl;
  // std::cerr << currentInfo_.threadId << "|\t fatal: " << fatal << std::endl;
  // std::cerr << currentInfo_.threadId
  //           << "|\t idleAftersycall: " << idleAftersycall << std::endl;
  sendSyscallResultToCore_({fatal, idleAftersycall, currentInfo_.syscallId,
                            currentInfo_.coreId, change});
  // Remove syscall from queue and reset handler to default state
  syscallQueue_.pop();
  dataBuffer_ = {};
  memRead_ = {{0, 0}, RegisterValue(), (uint64_t)-1};
  resumeHandling_ = [this]() { return handleSyscall(); };
}

void SyscallHandler::readLinkAt(std::string path, size_t length) {
  if (length == PATH_MAX_LEN) {
    // TODO: Handle PATH_MAX_LEN case
    std::cout << "[SimEng:SyscallHandler] Path exceeds PATH_MAX_LEN"
              << std::endl;
    return concludeSyscall({}, true);
  }

  const int64_t dirfd = currentInfo_.registerArguments[0].get<int64_t>();
  const uint64_t bufAddress = currentInfo_.registerArguments[2].get<uint64_t>();
  const uint64_t bufSize = currentInfo_.registerArguments[3].get<uint64_t>();

  char buffer[PATH_MAX_LEN];
  int64_t result = readlinkat(dirfd, path.data(), buffer, bufSize);

  if (result < 0) {
    // TODO: Handle error case
    std::cout << "[SimEng:SyscallHandler] Error generated by readlinkat"
              << std::endl;
    return concludeSyscall({}, true);
  }

  uint64_t bytesCopied = static_cast<uint64_t>(result);

  simeng::OS::ProcessStateChange stateChange = {
      simeng::OS::ChangeType::REPLACEMENT, {currentInfo_.ret}, {result}};

  // Slice the returned path into <256-byte chunks for writing
  const char* bufPtr = buffer;
  for (size_t i = 0; i < bytesCopied; i += 256) {
    uint8_t size = std::min<uint64_t>(bytesCopied - i, 256ul);
    stateChange.memoryAddresses.push_back({bufAddress + i, size});
    stateChange.memoryAddressValues.push_back(RegisterValue(bufPtr, size));
  }

  concludeSyscall(stateChange);
}

uint64_t SyscallHandler::getDirFd(int64_t dfd, std::string pathname) {
  // Resolve absolute path to target file
  char absolutePath[PATH_MAX_LEN];
  realpath(pathname.c_str(), absolutePath);

  int64_t dfd_temp = AT_FDCWD;
  if (dfd != -100) {
    dfd_temp = dfd;
    // If absolute path used then dfd is dis-regarded. Otherwise need to see
    // if fd exists for directory referenced
    if (strncmp(pathname.c_str(), absolutePath, strlen(absolutePath)) != 0) {
      auto entry =
          OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(dfd);
      if (!entry.isValid()) {
        return -1;
      }
      dfd_temp = entry.getFd();
    }
  }
  return dfd_temp;
}

std::string SyscallHandler::getSpecialFile(const std::string filename) {
  for (auto prefix : {"/dev/", "/proc/", "/sys/"}) {
    if (strncmp(filename.c_str(), prefix, strlen(prefix)) == 0) {
      for (int i = 0; i < supportedSpecialFiles_.size(); i++) {
        if (filename.find(supportedSpecialFiles_[i]) != std::string::npos) {
          std::cout << "[SimEng:SyscallHandler] Using Special File: "
                    << filename.c_str() << std::endl;
          // Hijack proc/self/maps and replace self with PID
          if (filename.find("proc/self/maps") != std::string::npos) {
            std::string newFileName = filename;
            std::string tgid = std::to_string(
                OS_->getProcess(currentInfo_.threadId)->getTGID());
            newFileName.replace(newFileName.find("self"), 4, tgid);
            return specialFilesDir_ + newFileName;
          }
          return specialFilesDir_ + filename;
        }
      }
      std::cout
          << "[SimEng:SyscallHandler] WARNING: unable to open unsupported "
             "special file: "
          << "'" << filename.c_str() << "'" << std::endl
          << "[SimEng:SyscallHandler]           allowing simulation to "
             "continue"
          << std::endl;
      break;
    }
  }
  return filename;
}

int64_t SyscallHandler::brk(uint64_t address) {
  return OS_->getProcess(currentInfo_.threadId)
      ->getMemRegion()
      .updateBrkRegion(address);
}

uint64_t SyscallHandler::clockGetTime(uint64_t clkId, uint64_t systemTimer,
                                      uint64_t& seconds,
                                      uint64_t& nanoseconds) {
  // TODO: Ideally this should get the system timer from the core directly
  // rather than having it passed as an argument.
  if (clkId == 0) {  // CLOCK_REALTIME
    seconds = systemTimer / 1e9;
    nanoseconds = systemTimer - (seconds * 1e9);
    return 0;
  } else if (clkId == 1) {  // CLOCK_MONOTONIC
    seconds = systemTimer / 1e9;
    nanoseconds = systemTimer - (seconds * 1e9);
    return 0;
  } else {
    assert(false &&
           "[SimEng:SyscallHandler] Unhandled clk_id in clock_gettime syscall");
    return -1;
  }
}

int64_t SyscallHandler::ftruncate(uint64_t fd, uint64_t length) {
  auto entry = OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();

  int64_t retval = ::ftruncate(hfd, length);
  return retval;
}

int64_t SyscallHandler::faccessat(int64_t dfd, const std::string& filename,
                                  int64_t mode, int64_t flag) {
  // Resolve absolute path to target file
  std::string new_pathname;

  // Alter special file path to point to SimEng one (if filename points to
  // special file)
  new_pathname = SyscallHandler::getSpecialFile(filename);

  // Get correct dirfd
  int64_t dirfd = SyscallHandler::getDirFd(dfd, filename);
  if (dirfd == -1) return EBADF;

  // Pass call through to host
  int64_t retval = ::faccessat(dirfd, new_pathname.c_str(), mode, flag);

  return retval;
}

int64_t SyscallHandler::close(int64_t fd) {
  // Don't close STDOUT or STDERR otherwise no SimEng output is given
  // afterwards. This includes final results given at the end of execution
  if (fd != STDERR_FILENO && fd != STDOUT_FILENO) {
    return OS_->getProcess(currentInfo_.threadId)->fdArray_->removeFDEntry(fd);
  }

  // Return success if STDOUT or STDERR is closed to allow execution to
  // proceed
  return 0;
}

int64_t SyscallHandler::newfstatat(int64_t dfd, const std::string& filename,
                                   stat& out, int64_t flag) {
  // Resolve absolute path to target file
  std::string new_pathname;

  // Alter special file path to point to SimEng one (if filename points to
  // special file)
  new_pathname = SyscallHandler::getSpecialFile(filename);

  // Get correct dirfd
  int64_t dirfd = SyscallHandler::getDirFd(dfd, filename);
  if (dirfd == -1) return EBADF;

  // Pass call through to host
  struct ::stat statbuf;
  int64_t retval = ::fstatat(dirfd, new_pathname.c_str(), &statbuf, flag);

  // Copy results to output struct
  out.dev = statbuf.st_dev;
  out.ino = statbuf.st_ino;
  out.mode = statbuf.st_mode;
  out.nlink = statbuf.st_nlink;
  out.uid = statbuf.st_uid;
  out.gid = statbuf.st_gid;
  out.rdev = statbuf.st_rdev;
  out.size = statbuf.st_size;
  out.blksize = statbuf.st_blksize;
  out.blocks = statbuf.st_blocks;

  // Mac and linux systems define the stat buff with the same format but
  // different names
#ifdef __MACH__
  out.atime = statbuf.st_atimespec.tv_sec;
  out.atimensec = statbuf.st_atimespec.tv_nsec;
  out.mtime = statbuf.st_mtimespec.tv_sec;
  out.mtimensec = statbuf.st_mtimespec.tv_nsec;
  out.ctime = statbuf.st_ctimespec.tv_sec;
  out.ctimensec = statbuf.st_ctimespec.tv_nsec;
#else
  out.atime = statbuf.st_atim.tv_sec;
  out.atimensec = statbuf.st_atim.tv_nsec;
  out.mtime = statbuf.st_mtim.tv_sec;
  out.mtimensec = statbuf.st_mtim.tv_nsec;
  out.ctime = statbuf.st_ctim.tv_sec;
  out.ctimensec = statbuf.st_ctim.tv_nsec;
#endif

  return retval;
}

int64_t SyscallHandler::fstat(int64_t fd, stat& out) {
  auto entry = OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();

  // Pass call through to host
  struct ::stat statbuf;
  int64_t retval = ::fstat(hfd, &statbuf);

  // Copy results to output struct
  out.dev = statbuf.st_dev;
  out.ino = statbuf.st_ino;
  out.mode = statbuf.st_mode;
  out.nlink = statbuf.st_nlink;
  out.uid = statbuf.st_uid;
  out.gid = statbuf.st_gid;
  out.rdev = statbuf.st_rdev;
  out.size = statbuf.st_size;
  out.blksize = statbuf.st_blksize;
  out.blocks = statbuf.st_blocks;
  out.atime = statbuf.st_atime;
  out.mtime = statbuf.st_mtime;
  out.ctime = statbuf.st_ctime;

  return retval;
}

// TODO: Current implementation will get whole SimEng resource usage stats,
// not just the usage stats of binary
int64_t SyscallHandler::getrusage(int64_t who, rusage& out) {
  // MacOS doesn't support the final enum RUSAGE_THREAD
#ifdef __MACH__
  if (!(who == 0 || who == -1)) {
    assert(false && "[SimEng:SyscallHandler] Un-recognised RUSAGE descriptor.");
    return -1;
  }
#else
  if (!(who == 0 || who == -1 || who == 1)) {
    assert(false && "[SimEng:SyscallHandler] Un-recognised RUSAGE descriptor.");
    return -1;
  }
#endif

  // Pass call through host
  struct ::rusage usage;
  int64_t retval = ::getrusage(who, &usage);

  // Copy results to output struct
  out.ru_utime = usage.ru_utime;
  out.ru_stime = usage.ru_stime;
  out.ru_maxrss = usage.ru_maxrss;
  out.ru_ixrss = usage.ru_ixrss;
  out.ru_idrss = usage.ru_idrss;
  out.ru_isrss = usage.ru_isrss;
  out.ru_minflt = usage.ru_minflt;
  out.ru_majflt = usage.ru_majflt;
  out.ru_nswap = usage.ru_nswap;
  out.ru_inblock = usage.ru_inblock;
  out.ru_oublock = usage.ru_oublock;
  out.ru_msgsnd = usage.ru_msgsnd;
  out.ru_msgrcv = usage.ru_msgrcv;
  out.ru_nsignals = usage.ru_nsignals;
  out.ru_nvcsw = usage.ru_nvcsw;
  out.ru_nivcsw = usage.ru_nivcsw;

  return retval;
}

int64_t SyscallHandler::getpid() const {
  // Given that the Thread Group ID (TGID) is equivalent to the Process ID
  // (PID), we can return the TGID instead
  return OS_->getProcess(currentInfo_.threadId)->getTGID();
}

int64_t SyscallHandler::getuid() const { return 0; }

int64_t SyscallHandler::geteuid() const { return 0; }

int64_t SyscallHandler::getgid() const { return 0; }

int64_t SyscallHandler::getegid() const { return 0; }

int64_t SyscallHandler::gettid() const {
  return OS_->getProcess(currentInfo_.threadId)->getTID();
}

int64_t SyscallHandler::gettimeofday(uint64_t systemTimer, timeval* tv,
                                     timeval* tz) {
  // TODO: Ideally this should get the system timer from the core directly
  // rather than having it passed as an argument.
  if (tv) {
    tv->tv_sec = systemTimer / 1e9;
    tv->tv_usec = (systemTimer - (tv->tv_sec * 1e9)) / 1e3;
  }
  if (tz) {
    tz->tv_sec = 0;
    tz->tv_usec = 0;
  }
  return 0;
}

int64_t SyscallHandler::ioctl(int64_t fd, uint64_t request,
                              std::vector<char>& out) {
  auto entry = OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();

  switch (request) {
    case 0x5401: {  // TCGETS
      struct ::termios hostResult;
      int64_t retval;
#ifdef __APPLE__
      retval = ::ioctl(hfd, TIOCGETA, &hostResult);
#else
      retval = ::ioctl(hfd, TCGETS, &hostResult);
#endif
      out.resize(sizeof(ktermios));
      ktermios& result = *reinterpret_cast<ktermios*>(out.data());
      result.c_iflag = hostResult.c_iflag;
      result.c_oflag = hostResult.c_oflag;
      result.c_cflag = hostResult.c_cflag;
      result.c_lflag = hostResult.c_lflag;
      // TODO: populate c_line and c_cc
      return retval;
    }
    case 0x5413:  // TIOCGWINSZ
      out.resize(sizeof(struct winsize));
      ::ioctl(hfd, TIOCGWINSZ, out.data());
      return 0;
    default:
      assert(false && "[SimEng:SyscallHandler] unimplemented ioctl request");
      return -1;
  }
}

uint64_t SyscallHandler::lseek(int64_t fd, uint64_t offset, int64_t whence) {
  auto entry = OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();
  return ::lseek(hfd, offset, whence);
}

int64_t SyscallHandler::munmap(uint64_t addr, size_t length) {
  return OS_->getProcess(currentInfo_.threadId)
      ->getMemRegion()
      .unmapRegion(addr, length);
}

int64_t SyscallHandler::clone(uint64_t flags, uint64_t stackPtr,
                              uint64_t parentTidPtr, uint64_t tls,
                              uint64_t childTidPtr) {
  // Check that required flags are present, if not trigger fatal error
  uint64_t reqFlags = syscalls::clone::flags::f_CLONE_VM |
                      syscalls::clone::flags::f_CLONE_FS |
                      syscalls::clone::flags::f_CLONE_FILES |
                      syscalls::clone::flags::f_CLONE_THREAD;
  if ((flags & reqFlags) != reqFlags) {
    std::cout << "[SimEng:SyscallHandler] One or more of the following flags "
                 "required for clone not provided :"
              << std::endl;
    std::cout << "\tCLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD"
              << std::endl;
    return -1;
  }
  // Must specify a child stack - won't support copy-on-write with parent
  if (stackPtr == 0) {
    std::cout << "[SimEng:SyscallHandler] Must provide a child stack address "
                 "to clone syscall."
              << std::endl;
    return -1;
  }

  OS_->cloneProcess(flags, parentTidPtr, stackPtr, tls, childTidPtr,
                    currentInfo_.threadId, currentInfo_.coreId,
                    currentInfo_.ret);

  return 0;
}

int64_t SyscallHandler::mmap(uint64_t addr, size_t length, int prot, int flags,
                             int fd, off_t offset) {
  auto process = OS_->getProcess(currentInfo_.threadId);
  HostFileMMap hostfile;

  if (fd > 0) {
    auto entry = process->fdArray_->getFDEntry(fd);
    if (!entry.isValid()) {
      std::cout << "[SimEng:SyscallHandler] Invalid virtual file descriptor "
                   "given to mmap"
                << std::endl;
      return -1;
    }
    hostfile = OS_->hfmmap_->mapfd(entry.getFd(), length, offset);
  }
  uint64_t ret =
      process->getMemRegion().mmapRegion(addr, length, prot, flags, hostfile);
  return ret;
}

int64_t SyscallHandler::openat(int64_t dfd, const std::string& filename,
                               int64_t flags, uint16_t mode) {
  std::string new_pathname;

  // Alter special file path to point to SimEng one (if filename points to
  // special file)
  new_pathname = SyscallHandler::getSpecialFile(filename);

  // Need to re-create flag input to correct values for host OS
  int64_t newFlags = 0;
  if (flags & 0x0) newFlags |= O_RDONLY;
  if (flags & 0x1) newFlags |= O_WRONLY;
  if (flags & 0x2) newFlags |= O_RDWR;
  if (flags & 0x400) newFlags |= O_APPEND;
  if (flags & 0x2000) newFlags |= O_ASYNC;
  if (flags & 0x80000) newFlags |= O_CLOEXEC;
  if (flags & 0x40) newFlags |= O_CREAT;
  if (flags & 0x10000) newFlags |= O_DIRECTORY;
  if (flags & 0x1000) newFlags |= O_DSYNC;
  if (flags & 0x80) newFlags |= O_EXCL;
  if (flags & 0x100) newFlags |= O_NOCTTY;
  if (flags & 0x20000) newFlags |= O_NOFOLLOW;
  if (flags & 0x800) newFlags |= O_NONBLOCK;  // O_NDELAY
  if (flags & 0x101000) newFlags |= O_SYNC;
  if (flags & 0x200) newFlags |= O_TRUNC;

#ifdef __MACH__
  // Apple only flags
  if (flags & 0x0010) newFlags |= O_SHLOCK;
  if (flags & 0x0020) newFlags |= O_EXLOCK;
  if (flags & 0x200000) newFlags |= O_SYMLINK;
#else
  // Linux only flags
  if (flags & 0x4000) newFlags |= O_DIRECT;
  if (flags & 0x0) newFlags |= O_LARGEFILE;
  if (flags & 0x40000) newFlags |= O_NOATIME;
  if (flags & 0x200000) newFlags |= O_PATH;
  if (flags & 0x410000) newFlags |= O_TMPFILE;
#endif

  // If Special File (or Special File Directory) is being opened then need to
  // set flags to O_RDONLY and O_CLOEXEC only.
  if (new_pathname != filename) {
    newFlags = O_RDONLY | O_CLOEXEC;
  }

  // Get correct dirfd
  int64_t dirfd = SyscallHandler::getDirFd(dfd, filename);
  if (dirfd == -1) return EBADF;

  auto proc = OS_->getProcess(currentInfo_.threadId);
  return proc->fdArray_->allocateFDEntry(dirfd, new_pathname.c_str(), newFlags,
                                         mode);
}

int64_t SyscallHandler::readlinkat(int64_t dirfd, const std::string& pathname,
                                   char* buf, size_t bufsize) const {
  auto process = OS_->getProcess(currentInfo_.threadId);
  if (pathname == "/proc/self/exe") {
    // Copy executable path to buffer
    // TODO: resolve path into canonical path
    std::strncpy(buf, process->getPath().c_str(), bufsize);
    return std::min(process->getPath().length(), bufsize);
  }

  // TODO: resolve symbolic link for other paths
  return -1;
}

int64_t SyscallHandler::getdents64(int64_t fd, void* buf, uint64_t count) {
  auto entry = OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();

  // Need alternative implementation as not all systems support the getdents64
  // syscall
  DIR* dir_stream = ::fdopendir(hfd);
  // Check for error
  if (dir_stream == NULL) return -1;

  // Keep a running count of the bytes read
  uint64_t bytesRead = 0;
  while (true) {
    // Get next dirent
    dirent* next_direct = ::readdir(dir_stream);
    // Check if end of directory
    if (next_direct == NULL) break;

    // Copy in readdir return and manipulate values for getdents64 usage
    linux_dirent64 result;
    result.d_ino = next_direct->d_ino;
#ifdef __MACH__
    result.d_off = next_direct->d_seekoff;
#else
    result.d_off = next_direct->d_off;
#endif
    std::string d_name = next_direct->d_name;
    result.d_type = next_direct->d_type;
    result.d_namlen = d_name.size();
    result.d_name = d_name.data();
    // Get size of struct before alignment
    // 20 = combined size of d_ino, d_off, d_reclen, d_type, and d_name's
    // null-terminator
    uint16_t structSize = 20 + result.d_namlen;
    result.d_reclen = alignToBoundary(structSize, 8);
    // Copy in all linux_dirent64 members to the buffer at the correct known
    // offsets from base `buf + bytesRead`
    std::memcpy((char*)buf + bytesRead, (void*)&result.d_ino, 8);
    std::memcpy((char*)buf + bytesRead + 8, (void*)&result.d_off, 8);
    std::memcpy((char*)buf + bytesRead + 16, (void*)&result.d_reclen, 2);
    std::memcpy((char*)buf + bytesRead + 18, (void*)&result.d_type, 1);
    std::memcpy((char*)buf + bytesRead + 19, result.d_name,
                result.d_namlen + 1);
    // Ensure bytes used to align struct to 8-byte boundary are zeroed out
    std::memset((char*)buf + bytesRead + structSize, '\0',
                (result.d_reclen - structSize));

    bytesRead += static_cast<uint64_t>(result.d_reclen);
  }
  // If more bytes have been read than the count arg, return count instead
  return std::min(count, bytesRead);
}

int64_t SyscallHandler::read(int64_t fd, void* buf, uint64_t count) {
  auto entry = OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();
  return ::read(hfd, buf, count);
}

int64_t SyscallHandler::readv(int64_t fd, const void* iovdata, int iovcnt) {
  auto entry = OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();
  return ::readv(hfd, reinterpret_cast<const struct iovec*>(iovdata), iovcnt);
}

int64_t SyscallHandler::schedGetAffinity(pid_t pid, size_t cpusetsize,
                                         uint64_t mask) {
  if (mask != 0 &&
      (pid == 0 || pid == OS_->getProcess(currentInfo_.threadId)->getTGID())) {
    // Always return a bit mask of 1 to represent 1 available CPU
    return 1;
  }
  return -1;
}

int64_t SyscallHandler::schedSetAffinity(pid_t pid, size_t cpusetsize,
                                         uint64_t mask) {
  // Currently, the bit mask can only be 1 so capture any error which would
  // occur but otherwise omit functionality
  if (mask == 0) return -EFAULT;
  uint64_t translatedAddr =
      OS_->handleVAddrTranslation(mask, currentInfo_.threadId);
  uint64_t faultCode = simeng::OS::masks::faults::getFaultCode(translatedAddr);
  if (faultCode == simeng::OS::masks::faults::pagetable::DATA_ABORT ||
      faultCode == simeng::OS::masks::faults::pagetable::IGNORED) {
    return -EFAULT;
  }
  if (pid != 0) return -ESRCH;
  if (cpusetsize == 0) return -EINVAL;
  return 0;
}

int64_t SyscallHandler::setTidAddress(uint64_t tidptr) {
  OS_->getProcess(currentInfo_.threadId)->clearChildTid_ = tidptr;
  return currentInfo_.threadId;
}

int64_t SyscallHandler::write(int64_t fd, const void* buf, uint64_t count) {
  auto entry = OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();
  return ::write(hfd, buf, count);
}

int64_t SyscallHandler::writev(int64_t fd, const void* iovdata, int iovcnt) {
  auto entry = OS_->getProcess(currentInfo_.threadId)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();
  return ::writev(hfd, reinterpret_cast<const struct iovec*>(iovdata), iovcnt);
}

std::pair<bool, long> SyscallHandler::futex(uint64_t uaddr, int futex_op,
                                            uint32_t val, uint64_t tid,
                                            const struct timespec* timeout,
                                            uint32_t uaddr2, uint32_t val3) {
  int wait = 0;
  int wake = 0;

  switch (futex_op) {
    case syscalls::futex::futexop::SIMENG_FUTEX_WAKE:
    case syscalls::futex::futexop::SIMENG_FUTEX_WAKE_PRIVATE:
      wake = 1;
      break;
    case syscalls::futex::futexop::SIMENG_FUTEX_WAIT:
    case syscalls::futex::futexop::SIMENG_FUTEX_WAIT_PRIVATE:
      wait = 1;
      break;
  }

  // Get the process associated with the thread id.
  auto process = OS_->getProcess(tid);
  uint64_t tgid = process->getTGID();

  // Iterator of the FutexInfo entry.
  auto ftableItr = futexTable_.find(tgid);

  if (wait) {
    // std::cerr << currentInfo_.threadId << "| \tFutex wait" << std::endl;
    // Atomically get the value at the address specified by the futex.
    // If the read memory target does not equal the data required,
    // request it and recall the `futex` call after its return
    if (memRead_.target.vaddr !=
        currentInfo_.registerArguments[0].get<uint64_t>()) {
      std::unique_ptr<simeng::memory::MemPacket> request =
          simeng::memory::MemPacket::createReadRequest(
              currentInfo_.registerArguments[0].get<uint64_t>(),
              sizeof(uint32_t), currentInfo_.threadId, 0, 0);
      request->paddr_ = uaddr;
      reqMemAccess_ = true;
      currentInfo_.started = false;
      memPort_->send(std::move(request));
      if (reqMemAccess_) return {false, -1};
    }
    uint32_t futexWord{};
    std::memcpy(&futexWord, memRead_.data.getAsVector<char>(),
                sizeof(uint32_t));
    // As per the linux futex specification, if the value of the futex word is
    // not equal to the value specified in the arguments, the syscall should
    // exit with a failure value (-1).
    // Source: https://man7.org/linux/man-pages/man2/futex.2.html
    if (val != futexWord) {
      std::cerr
          << "[SimEng:SyscallHandler]  Value of the futex word did not match "
             "with the value specified in the futex argument:\n"
          << "\tFutex word: " << futexWord << "\n"
          << "\tArgument value: " << val << std::endl;
      return {false, -1};
    }
    if (ftableItr == futexTable_.end()) {
      ftableItr = futexTable_.insert({tgid, std::list<FutexInfo>()}).first;
    }
    FutexInfo f(uaddr, process, FutexStatus::FUTEX_SLEEPING);
    ftableItr->second.push_back(f);
    // Set the process status to procStatus::sleeping so that it isn't
    // added to the waitingProcs_ queue.
    process->status_ = procStatus::sleeping;
    return {true, 0};
  }

  if (wake) {
    // std::cerr << currentInfo_.threadId << "| \tFutex wake" << std::endl;
    long procWokenUp = 0;
    // Variable denoting how many processes were woken up.
    if (ftableItr != futexTable_.end()) {
      size_t castedVal = static_cast<size_t>(val);
      size_t maxItr = std::min(castedVal, ftableItr->second.size());
      for (size_t t = 0; t < maxItr; t++) {
        auto futexInfo = ftableItr->second.front();
        // Awaken the process by changing the status to procStatus::waiting and
        // adding it to the waitingProcs_ queue.
        futexInfo.process->status_ = procStatus::waiting;
        OS_->addProcessToWaitQueue(futexInfo.process);
        ftableItr->second.pop_front();
        procWokenUp++;
      }
      // std::cerr << currentInfo_.threadId << "| \tWoke " << procWokenUp
      //           << " procs" << std::endl;
    }
    // procWokenUp should be be 0 if no processes were woken up.
    return {false, procWokenUp};
  }
  return {false, -1};
}

void SyscallHandler::removeFutexInfoList(uint64_t tgid) {
  auto itr = futexTable_.find(tgid);
  if (itr != futexTable_.end()) {
    futexTable_.erase(itr);
  }
}

void SyscallHandler::removeFutexInfo(uint64_t tgid, uint64_t tid) {
  auto tableitr = futexTable_.find(tgid);
  if (tableitr != futexTable_.end()) {
    auto list = tableitr->second;
    for (auto itr = list.begin(); itr != list.end(); itr++) {
      if (itr->process->getTID() == tid) {
        list.erase(itr);
        return;
      }
    }
  }
}

}  // namespace OS
}  // namespace simeng
