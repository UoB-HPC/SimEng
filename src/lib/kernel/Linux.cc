#include "simeng/kernel/Linux.hh"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/termios.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 8
#include <experimental/filesystem>
#else
#include <filesystem>
#endif
#include <iostream>

namespace simeng {
namespace kernel {

void Linux::createProcess(const LinuxProcess& process) {
  assert(process.isValid() && "Attempted to use an invalid process");
  assert(processStates_.size() == 0 && "Multiple processes not yet supported");
  // Can't use designated intialisers as is C++20
  // TODO remove comment after reviews
  processStates_.push_back({0,  // TODO: create unique PIDs
                            process.getPath(), process.getHeapStart(),
                            process.getHeapStart(),
                            process.getInitialStackPointer(),
                            process.getMmapStart(), process.getPageSize()});
  processStates_.back().fileDescriptorTable.push_back(STDIN_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDOUT_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDERR_FILENO);

  // Define vector of all currently supported special file paths & files.
  supportedSpecialFiles_.insert(
      supportedSpecialFiles_.end(),
      {"/proc/cpuinfo", "proc/stat", "/sys/devices/system/cpu",
       "/sys/devices/system/cpu/online", "core_id", "physical_package_id"});
}

int64_t Linux::getHostDirFD(int64_t vdfd) {
  // -100 = AT_FCWD on linux. Pass back AT_FDCWD for host platform e.g. -2 for
  // MAC
  if (vdfd == -100) {
    // Early return if requesting current working directory
    return AT_FDCWD;
  }

  if (vdfd < 0) {
    // Invalid virtual file descriptor
    return -1;
  } else {
    uint64_t unsignedVdfd = static_cast<uint64_t>(vdfd);
    if (unsignedVdfd < processStates_[0].fileDescriptorTable.size()) {
      // Within bounds of table. Entry will be -1 if invalid
      return processStates_[0].fileDescriptorTable[unsignedVdfd];
    } else {
      // Outside bounds of table
      return -1;
      // TODO potentially this should throw an error as per previous
      // implementation's assertion
    }
  }
}

std::string Linux::getSpecialFile(const std::string filename) {
  for (auto prefix : {"/dev/", "/proc/", "/sys/"}) {
    if (strncmp(filename.c_str(), prefix, strlen(prefix)) == 0) {
      for (size_t i = 0; i < supportedSpecialFiles_.size(); i++) {
        if (filename.find(supportedSpecialFiles_[i]) != std::string::npos) {
          std::cerr << "[SimEng:Linux] Using Special File: " << filename.c_str()
                    << std::endl;
          return specialFilesDir_ + filename;
        }
      }
      std::cerr << "[SimEng:Linux] WARNING: unable to open unsupported "
                   "special file: "
                << "'" << filename.c_str() << "'" << std::endl
                << "[SimEng:Linux]           allowing simulation to continue"
                << std::endl;
      break;
    }
  }
  return filename;
}

uint64_t Linux::getInitialStackPointer() const {
  assert(processStates_.size() > 0 &&
         "Attempted to retrieve a stack pointer before creating a process");

  return processStates_[0].initialStackPointer;
}

int64_t Linux::brk(uint64_t address) {
  assert(processStates_.size() > 0 &&
         "Attempted to move the program break before creating a process");

  auto& state = processStates_[0];
  // Move the break if it's within the heap region
  if (address > state.startBrk) {
    state.currentBrk = address;
  }
  return state.currentBrk;
}

uint64_t Linux::clockGetTime(uint64_t clkId, uint64_t systemTimer,
                             uint64_t& seconds, uint64_t& nanoseconds) {
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
    assert(false && "Unhandled clk_id in clock_gettime syscall");
    return -1;
  }
}

int64_t Linux::ftruncate(uint64_t fd, uint64_t length) {
  assert(fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }

  int64_t retval = ::ftruncate(hfd, length);
  return retval;
}

int64_t Linux::faccessat(int64_t dfd, const std::string& filename, int64_t mode,
                         int64_t flag) {
  // Resolve absolute path to target file
  std::string new_pathname;

  // Alter special file path to point to SimEng one (if filename points to
  // special file)
  new_pathname = Linux::getSpecialFile(filename);

  // Get host dirfd. May return -1 in case of no mapping, pass through to host
  // faccessat to deal with this
  int64_t hostDfd = Linux::getHostDirFD(dfd);

  // Pass call through to host
  int64_t retval = ::faccessat(hostDfd, new_pathname.c_str(), mode, flag);

  return retval;
}

int64_t Linux::close(int64_t vfd) {
  // Don't close STDOUT or STDERR otherwise no SimEng output is given
  // afterwards. This includes final results given at the end of execution
  if (vfd != STDERR_FILENO && vfd != STDOUT_FILENO) {
    assert(vfd >= 0 &&
           (size_t)vfd < processStates_[0].fileDescriptorTable.size());
    int64_t hfd = processStates_[0].fileDescriptorTable[vfd];
    if (hfd < 0) {
      // Early return, can't deallocate vfd that isn't in fileDescriptorTable
      return EBADF;
    }

    // Deallocate the virtual file descriptor
    assert(processStates_[0].freeFileDescriptors.count(vfd) == 0);
    processStates_[0].freeFileDescriptors.insert(vfd);
    processStates_[0].fileDescriptorTable[vfd] = -1;

    return ::close(hfd);
  }

  // Return success if STDOUT or STDERR is closed to allow execution to proceed
  return 0;
}

int64_t Linux::newfstatat(int64_t dfd, const std::string& filename, stat& out,
                          int64_t flag) {
  // Resolve absolute path to target file
  std::string new_pathname;

  // Alter special file path to point to SimEng one (if filename points to
  // special file)
  new_pathname = Linux::getSpecialFile(filename);

  // Get host dirfd. May return -1 in case of no mapping, pass through to host
  // fstatat to deal with this
  int64_t hostDfd = Linux::getHostDirFD(dfd);

  // Pass call through to host
  struct ::stat statbuf;
  int64_t retval = ::fstatat(hostDfd, new_pathname.c_str(), &statbuf, flag);

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

int64_t Linux::fstat(int64_t fd, stat& out) {
  assert(fd > 0 && (size_t)fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }

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

// TODO: Current implementation will get whole SimEng resource usage stats, not
// just the usage stats of binary
int64_t Linux::getrusage(int64_t who, rusage& out) {
  // MacOS doesn't support the final enum RUSAGE_THREAD
#ifdef __MACH__
  if (!(who == 0 || who == -1)) {
    assert(false && "Un-recognised RUSAGE descriptor.");
    return -1;
  }
#else
  if (!(who == 0 || who == -1 || who == 1)) {
    assert(false && "Un-recognised RUSAGE descriptor.");
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

int64_t Linux::getpid() const {
  assert(processStates_.size() > 0);
  return processStates_[0].pid;
}

int64_t Linux::getuid() const { return 0; }
int64_t Linux::geteuid() const { return 0; }
int64_t Linux::getgid() const { return 0; }
int64_t Linux::getegid() const { return 0; }
// TODO update for multithreaded processes
int64_t Linux::gettid() const { return 0; }

int64_t Linux::gettimeofday(uint64_t systemTimer, timeval* tv, timeval* tz) {
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

int64_t Linux::ioctl(int64_t fd, uint64_t request, std::vector<char>& out) {
  assert(fd > 0 && (size_t)fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }

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
      assert(false && "unimplemented ioctl request");
      return -1;
  }
}

uint64_t Linux::lseek(int64_t fd, uint64_t offset, int64_t whence) {
  assert(fd > 0 && (size_t)fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }
  return ::lseek(hfd, offset, whence);
}

int64_t Linux::munmap(uint64_t addr, size_t length) {
  LinuxProcessState* lps = &processStates_[0];
  if (addr % lps->pageSize != 0) {
    // addr must be a multiple of the process page size
    return -1;
  }
  // TODO i defined twice. Need to determine correct usage of second
  size_t i;
  vm_area_struct alloc;
  // Find addr in allocations
  for (i = 0; i < lps->contiguousAllocations.size(); i++) {
    alloc = lps->contiguousAllocations[i];
    if (alloc.vm_start == addr) {
      if ((alloc.vm_end - alloc.vm_start) < length) {
        // length must not be larger than the original allocation
        return -1;
      }
      if (i != 0) {
        lps->contiguousAllocations[i - 1].vm_next =
            lps->contiguousAllocations[i].vm_next;
      }
      lps->contiguousAllocations.erase(lps->contiguousAllocations.begin() + i);
      return 0;
    }
  }

  // TODO check redefinition of i is correct
  for (size_t j = 0; j < lps->nonContiguousAllocations.size(); j++) {
    alloc = lps->nonContiguousAllocations[j];
    if (alloc.vm_start == addr) {
      if ((alloc.vm_end - alloc.vm_start) < length) {
        // length must not be larger than the original allocation
        return -1;
      }
      lps->nonContiguousAllocations.erase(
          lps->nonContiguousAllocations.begin() + j);
      return 0;
    }
  }
  // Not an error if the indicated range does no contain any mapped pages
  return 0;
}

uint64_t Linux::mmap(uint64_t addr, size_t length, [[maybe_unused]] int prot,
                     [[maybe_unused]] int flags, [[maybe_unused]] int fd,
                     [[maybe_unused]] off_t offset) {
  LinuxProcessState* lps = &processStates_[0];
  std::shared_ptr<struct vm_area_struct> newAlloc(new vm_area_struct);
  if (addr == 0) {  // Kernel decides allocation
    if (lps->contiguousAllocations.size() > 1) {
      // Determine if the new allocation can fit between existing allocations,
      // append to end of allocations if not
      for (auto& alloc : lps->contiguousAllocations) {
        if (alloc.vm_next != NULL &&
            (alloc.vm_next->vm_start - alloc.vm_end) >= length) {
          newAlloc->vm_start = alloc.vm_end;
          // Re-link contiguous allocation to include new allocation
          newAlloc->vm_next = alloc.vm_next;
          alloc.vm_next = newAlloc;
        }
      }
      if (newAlloc->vm_start == 0) {
        newAlloc->vm_start = lps->contiguousAllocations.back().vm_end;
        lps->contiguousAllocations.back().vm_next = newAlloc;
      }
    } else if (lps->contiguousAllocations.size() > 0) {
      // Append allocation to end of list and link first entry to new
      // allocation
      newAlloc->vm_start = lps->contiguousAllocations[0].vm_end;
      lps->contiguousAllocations[0].vm_next = newAlloc;
    } else {
      // If no allocation exists, allocate to start of the mmap region
      newAlloc->vm_start = lps->mmapRegion;
    }
    // The end of the allocation must be rounded up to the nearest page size
    newAlloc->vm_end =
        alignToBoundary(newAlloc->vm_start + length, lps->pageSize);
    lps->contiguousAllocations.push_back(*newAlloc);
  } else {  // Use hint to provide allocation
    return 0;
  }
  return newAlloc->vm_start;
}

int64_t Linux::openat(int64_t dfd, const std::string& pathname, int64_t flags,
                      uint16_t mode) {
  // Alter special file path to point to SimEng one (if filename points to
  // special file)
  std::string new_pathname = Linux::getSpecialFile(pathname);

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
  if (new_pathname != pathname) {
    newFlags = O_RDONLY | O_CLOEXEC;
  }

  // Get host dirfd. May return -1 in case of no mapping, pass through to host
  // openat to deal with this
  int64_t hDfd = Linux::getHostDirFD(dfd);

  // Pass call through to host
  int64_t hostFd = ::openat(hDfd, new_pathname.c_str(), newFlags, mode);
  if (hostFd < 0) {
    // An error occurred, pass this back to userspace don't allocate virtual
    // file descriptor
    // TODO possibly need to set errno for simulated program so that it can be
    // handled correctly?? This may be relevant throughout
    return hostFd;
  }

  LinuxProcessState& processState = processStates_[0];

  // Allocate virtual file descriptor and map to host file descriptor
  int64_t vfd;
  if (!processState.freeFileDescriptors.empty()) {
    // Take virtual descriptor from free pool
    auto first = processState.freeFileDescriptors.begin();
    vfd = processState.freeFileDescriptors.extract(first).value();
    processState.fileDescriptorTable[vfd] = hostFd;
  } else {
    // Extend file descriptor table for a new virtual descriptor
    vfd = processState.fileDescriptorTable.size();
    processState.fileDescriptorTable.push_back(hostFd);
  }

  return vfd;
}

int64_t Linux::readlinkat(int64_t dirfd, const std::string& pathname, char* buf,
                          size_t bufsize) const {
  const auto& processState = processStates_[0];
  if (pathname == "/proc/self/exe") {
    // Resolve absolute path
    char absolutePath[LINUX_PATH_MAX];
    char* output = realpath(processState.path.c_str(), absolutePath);
    if (output == nullptr) {
      // Something went wrong
      std::cerr << "[SimEng:readlinkat] realpath failed with errno = " << errno
                << std::endl;
      exit(EXIT_FAILURE);
    }

    // Copy executable path to buffer
    std::strncpy(buf, absolutePath, bufsize);

    return std::min(std::strlen(absolutePath), bufsize);
  }

  // TODO: resolve symbolic link for other paths - get hostfd then pass to real
  // readlinkat
  return -1;
}

int64_t Linux::getdents64(int64_t fd, void* buf, uint64_t count) {
  assert(fd > 0 && (size_t)fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }

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

int64_t Linux::read(int64_t fd, void* buf, uint64_t count) {
  assert(fd > 0 && (size_t)fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }
  return ::read(hfd, buf, count);
}

int64_t Linux::readv(int64_t fd, const void* iovdata, int iovcnt) {
  assert(fd > 0 && (size_t)fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }
  return ::readv(hfd, reinterpret_cast<const struct iovec*>(iovdata), iovcnt);
}

int64_t Linux::schedGetAffinity(pid_t pid, size_t cpusetsize, uint64_t mask) {
  if (mask != 0 && pid == 0) {
    // Always return a bit mask of 1 to represent 1 available CPU
    return 1;
  }
  return -1;
}

int64_t Linux::schedSetAffinity(pid_t pid, size_t cpusetsize, uint64_t mask) {
  // Currently, the bit mask can only be 1 so capture any error which would
  // occur but otherwise omit functionality
  if (mask == 0) return -EFAULT;
  if (pid != 0) return -ESRCH;
  if (cpusetsize == 0) return -EINVAL;
  return 0;
}
int64_t Linux::setTidAddress(uint64_t tidptr) {
  assert(processStates_.size() > 0);
  processStates_[0].clearChildTid = tidptr;
  return processStates_[0].pid;
}

int64_t Linux::write(int64_t fd, const void* buf, uint64_t count) {
  assert(fd > 0 && (size_t)fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }
  return ::write(hfd, buf, count);
}

int64_t Linux::writev(int64_t fd, const void* iovdata, int iovcnt) {
  assert(fd > 0 && (size_t)fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }
  return ::writev(hfd, reinterpret_cast<const struct iovec*>(iovdata), iovcnt);
}

}  // namespace kernel
}  // namespace simeng
