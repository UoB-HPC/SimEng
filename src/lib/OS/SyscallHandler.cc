#include "simeng/OS/SyscallHandler.hh"

#include "simeng/OS/SimOS.hh"

namespace simeng {
namespace OS {

SyscallHandler::SyscallHandler(SimOS* OS,
                               std::shared_ptr<simeng::memory::Mem> memory)
    : OS_(OS), memory_(memory) {
  // Define vector of all currently supported special file paths & files.
  supportedSpecialFiles_.insert(
      supportedSpecialFiles_.end(),
      {"/proc/cpuinfo", "proc/stat", "/sys/devices/system/cpu",
       "/sys/devices/system/cpu/online", "core_id", "physical_package_id"});
}

void SyscallHandler::receiveSyscall(SyscallInfo info) {
  syscallQueue_.push(info);
}

void SyscallHandler::tick() {
  if (!syscallQueue_.empty()) handleSyscall();
}

void SyscallHandler::handleSyscall() {
  // Update currentInfo_
  currentInfo_ = syscallQueue_.front();
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

      std::array<char, PATH_MAX_LEN> filename;
      return readStringThen(
          filename, filenamePtr, PATH_MAX_LEN, [&](auto length) {
            // Invoke the kernel
            int64_t retval = faccessat(
                dfd, std::string(filename.begin(), filename.end()), mode, flag);
            ProcessStateChange stateChange = {
                ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
            concludeSyscall(stateChange);
          });
      break;
    }
    case 56: {  // openat
      int64_t dirfd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t pathnamePtr = currentInfo_.registerArguments[1].get<uint64_t>();
      int64_t flags = currentInfo_.registerArguments[2].get<int64_t>();
      uint16_t mode = currentInfo_.registerArguments[3].get<uint16_t>();

      std::array<char, PATH_MAX_LEN> pathname;
      return readStringThen(
          pathname, pathnamePtr, PATH_MAX_LEN, [&](auto length) {
            // Invoke the kernel
            uint64_t retval =
                openat(dirfd, std::string(pathname.begin(), pathname.end()),
                       flags, mode);
            ProcessStateChange stateChange = {
                ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
            concludeSyscall(stateChange);
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
      std::array<char, PATH_MAX_LEN> pathname;
      return readStringThen(
          pathname, pathnameAddress, PATH_MAX_LEN, [&](auto length) {
            // Pass the string `readLinkAt`, then destroy
            // the buffer and resolve the handler.
            readLinkAt(std::string(pathname.begin(), pathname.end()), length);
            return;
          });
      break;
    }
    case 79: {  // newfstatat AKA fstatat
      int64_t dfd = currentInfo_.registerArguments[0].get<int64_t>();
      uint64_t filenamePtr = currentInfo_.registerArguments[1].get<uint64_t>();
      uint64_t statbufPtr = currentInfo_.registerArguments[2].get<uint64_t>();
      int64_t flag = currentInfo_.registerArguments[3].get<int64_t>();

      std::array<char, PATH_MAX_LEN> filename;
      return readStringThen(
          filename, filenamePtr, PATH_MAX_LEN, [&](auto length) {
            // Invoke the kernel
            OS::stat statOut;
            uint64_t retval =
                newfstatat(dfd, std::string(filename.begin(), filename.end()),
                           statOut, flag);
            ProcessStateChange stateChange = {
                ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
            stateChange.memoryAddresses.push_back(
                {statbufPtr, sizeof(statOut)});
            stateChange.memoryAddressValues.push_back(statOut);
            concludeSyscall(stateChange);
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
      // TODO: Functionality temporarily omitted as it is unused within
      // workloads regions of interest and not required for their simulation
      int op = currentInfo_.registerArguments[1].get<int>();
      if (op != 129) {
        return concludeSyscall({}, true);
      }
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {1ull}};
      break;
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
        uint64_t retval = (pid == 0) ? 1 : 0;
        stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {retval}};
        stateChange.memoryAddresses.push_back({mask, 1});
        stateChange.memoryAddressValues.push_back(bitmask);
      } else {
        stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {-1ll}};
      }
      break;
    }
    case 131: {  // tgkill
      // TODO: Functionality temporarily omitted since simeng only has a
      // single thread at the moment
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      break;
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
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
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
    case 235: {  // mbind
      // mbind is not supported due to all binaries being single threaded.
      // Always return zero to indicate success
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
      break;
    }
    case 261: {  // prlimit64
      // TODO: Functionality temporarily omitted as it is unused within
      // workloads regions of interest and not required for their simulation
      stateChange = {ChangeType::REPLACEMENT, {currentInfo_.ret}, {0ull}};
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

void SyscallHandler::readStringThen(std::array<char, PATH_MAX_LEN>& buffer,
                                    uint64_t address, int maxLength,
                                    std::function<void(size_t length)> then,
                                    int offset) {
  if (maxLength <= 0) {
    return then(offset);
  }

  // Translate the passed virtual address, `address + offset`
  uint64_t translatedAddr =
      OS_->handleVAddrTranslation(address + offset, currentInfo_.threadId);

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
    std::vector<char> data = memory_->getUntimedData(translatedAddr, maxLength);

    for (int i = 0; i < data.size(); i++) {
      buffer[i] = data[i];
      // End of string; call onwards
      if (buffer[i] == '\0') return then(i + 1);
    }

    // Reached max length; call onwards
    return then(maxLength);
  }
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
    data = memory_->getUntimedData(translatedAddr, length);
  }
  dataBuffer_.insert(dataBuffer_.end(), data.begin(), data.begin() + length);

  // Read in data, call onwards
  return then();
}

void SyscallHandler::concludeSyscall(const ProcessStateChange& change,
                                     bool fatal, bool idleAftersycall) {
  OS_->sendSyscallResult({fatal, idleAftersycall, currentInfo_.syscallId,
                          currentInfo_.coreId, change});
  // Remove syscall from queue and reset handler to default state
  syscallQueue_.pop();
  dataBuffer_ = {};
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

// TODO : update when supporting multi-process/thread
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
  if (mask != 0 && pid == 0) {
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
  if (pid != 0) return -ESRCH;
  if (cpusetsize == 0) return -EINVAL;
  return 0;
}

int64_t SyscallHandler::setTidAddress(uint64_t tidptr) {
  OS_->getProcess(currentInfo_.threadId)->clearChildTid_ = tidptr;
  return 0;
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

}  // namespace OS
}  // namespace simeng
