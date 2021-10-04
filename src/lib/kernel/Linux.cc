#include "simeng/kernel/Linux.hh"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <cassert>
#include <cstring>
#include <iostream>

namespace simeng {
namespace kernel {

void Linux::createProcess(const LinuxProcess& process) {
  assert(process.isValid() && "Attempted to use an invalid process");
  assert(processStates_.size() == 0 && "Multiple processes not yet supported");
  processStates_.push_back({.pid = 0,  // TODO: create unique PIDs
                            .path = process.getPath(),
                            .startBrk = process.getHeapStart(),
                            .currentBrk = process.getHeapStart(),
                            .initialStackPointer = process.getStackPointer(),
                            .mmapRegion = process.getMmapStart(),
                            .pageSize = process.getPageSize()});
  processStates_.back().fileDescriptorTable.push_back(STDIN_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDOUT_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDERR_FILENO);

  // Define special file path replacement paths
  specialPathTranslations_.insert(
      {"/sys/devices/system/cpu/online", specialFilesDir_ + "online"});
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
  char absolutePath[LINUX_PATH_MAX];
  realpath(filename.c_str(), absolutePath);

  // Setup variable to record if an alternative path is available for use
  bool altPath = false;

  // Check if path may be a special file, bail out if it is
  // TODO: Add support for special files
  for (auto prefix : {"/dev/", "/proc/", "/sys/"}) {
    if (strncmp(absolutePath, prefix, strlen(prefix)) == 0) {
      std::cerr << "ERROR: attempted to return information on a special file: "
                << "'" << absolutePath << "'" << std::endl;
      exit(1);
    }
  }

  int64_t dfd_temp = AT_FDCWD;
  // Pass syscall through to host
  if (dfd != -100) {
    dfd_temp = dfd;
    // If absolute path used then dfd is dis-regarded.
    // Otherwise, a dirfd != AT_FDCWD isn't currently supported for relative
    // paths.
    if (strlen(filename.c_str()) != strlen(absolutePath)) {
      assert("Unsupported dirfd argument in fstatat syscall");
      return EBADF;
    }
  }

  int64_t retval = ::faccessat(dfd_temp, filename.c_str(), mode, flag);

  return retval;
}

int64_t Linux::close(int64_t fd) {
  assert(fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }

  // Deallocate the virtual file descriptor
  assert(processStates_[0].freeFileDescriptors.count(fd) == 0);
  processStates_[0].freeFileDescriptors.insert(fd);
  processStates_[0].fileDescriptorTable[fd] = -1;

  return ::close(hfd);
}

int64_t Linux::newfstatat(int64_t dfd, const std::string& filename, stat& out,
                          int64_t flag) {
  // Resolve absolute path to target file
  char absolutePath[LINUX_PATH_MAX];
  realpath(filename.c_str(), absolutePath);

  // Check if path may be a special file, bail out if it is
  // TODO: Add support for special files
  for (auto prefix : {"/dev/", "/proc/", "/sys/"}) {
    if (strncmp(absolutePath, prefix, strlen(prefix)) == 0) {
      std::cerr << "ERROR: attempted to return information on a special file: "
                << "'" << absolutePath << "'" << std::endl;
      exit(1);
    }
  }

  // Pass call through to host
  assert(dfd == -100 && "Unsupported dirfd argument in fstatat syscall");
  struct ::stat statbuf;
  int64_t retval = ::fstatat(AT_FDCWD, filename.c_str(), &statbuf, flag);

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

int64_t Linux::fstat(int64_t fd, stat& out) {
  assert(fd < processStates_[0].fileDescriptorTable.size());
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
  if (!(who == 0 || who == -1)) {
    assert(false && "Un-recognised RUSAGE descriptor.");
    return -1;
  }

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
  assert(fd < processStates_[0].fileDescriptorTable.size());
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
  assert(fd < processStates_[0].fileDescriptorTable.size());
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
  int i;
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

  for (int i = 0; i < lps->nonContiguousAllocations.size(); i++) {
    alloc = lps->nonContiguousAllocations[i];
    if (alloc.vm_start == addr) {
      if ((alloc.vm_end - alloc.vm_start) < length) {
        // length must not be larger than the original allocation
        return -1;
      }
      lps->nonContiguousAllocations.erase(
          lps->nonContiguousAllocations.begin() + i);
      return 0;
    }
  }
  // Not an error if the indicated range does no contain any mapped pages
  return 0;
}

uint64_t Linux::mmap(uint64_t addr, size_t length, int prot, int flags, int fd,
                     off_t offset) {
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
      // Append allocation to end of list and link first entry to new allocation
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

int64_t Linux::openat(int64_t dirfd, const std::string& pathname, int64_t flags,
                      uint16_t mode) {
  // Resolve absolute path to target file
  char absolutePath[LINUX_PATH_MAX];
  realpath(pathname.c_str(), absolutePath);
  // Setup variable to record if an alternative path is available for use
  bool altPath = false;

  // Check if path may be a special file
  for (auto prefix : {"/dev", "/proc", "/sys"}) {
    if (strncmp(absolutePath, prefix, strlen(prefix)) == 0) {
      // Check if there's an assigned replacement path
      if (specialPathTranslations_.find(pathname) !=
          specialPathTranslations_.end()) {
        altPath = true;
        break;
      } else {
        std::cerr << "-- WARNING: unable to open unsupported special file: "
                  << "'" << pathname.c_str() << "'" << std::endl
                  << "--          allowing simulation to continue" << std::endl;
        break;
      }
    }
  }

  // Need to re-create flag input to correct values for host OS
  int64_t newFlags = 0;
  if (flags & 0x0) newFlags |= O_RDONLY;
  if (flags & 0x1) newFlags |= O_WRONLY;
  if (flags & 0x2) newFlags |= O_RDWR;
  if (flags & 0x400) newFlags |= O_APPEND;
  if (flags & 0x2000) newFlags |= O_ASYNC;
  if (flags & 0x80000) newFlags |= O_CLOEXEC;
  if (flags & 0x40) newFlags |= O_CREAT;
  // if (flags & 0x4000) newFlags |= O_DIRECT;
  if (flags & 0x10000) newFlags |= O_DIRECTORY;
  if (flags & 0x1000) newFlags |= O_DSYNC;
  if (flags & 0x80) newFlags |= O_EXCL;
  // if (flags & 0x0) newFlags |= O_LARGEFILE;
  // if (flags & 0x40000) newFlags |= O_NOATIME;
  if (flags & 0x100) newFlags |= O_NOCTTY;
  if (flags & 0x20000) newFlags |= O_NOFOLLOW;
  if (flags & 0x800) newFlags |= O_NONBLOCK;  // O_NDELAY
  // if (flags & 0x200000) newFlags |= O_PATH;
  if (flags & 0x101000) newFlags |= O_SYNC;
  // if (flags & 0x410000) newFlags |= O_TMPFILE;
  if (flags & 0x200) newFlags |= O_TRUNC;

  // Pass syscall through to host
  assert(dirfd == -100 && "unsupported dirfd argument in openat syscall");
  // Use path replacement for pathname argument of openat, if chosen
  const char* newPathname =
      altPath ? specialPathTranslations_[pathname].c_str() : pathname.c_str();
  int64_t hfd = ::openat(AT_FDCWD, newPathname, newFlags, mode);
  if (hfd < 0) {
    return hfd;
  }

  LinuxProcessState& processState = processStates_[0];

  // Allocate virtual file descriptor and map to host file descriptor
  int64_t vfd;
  if (!processState.freeFileDescriptors.empty()) {
    // Take virtual descriptor from free pool
    auto first = processState.freeFileDescriptors.begin();
    vfd = processState.freeFileDescriptors.extract(first).value();
    processState.fileDescriptorTable[vfd] = hfd;
  } else {
    // Extend file descriptor table for a new virtual descriptor
    vfd = processState.fileDescriptorTable.size();
    processState.fileDescriptorTable.push_back(hfd);
  }

  return vfd;
}

int64_t Linux::readlinkat(int64_t dirfd, const std::string& pathname, char* buf,
                          size_t bufsize) const {
  const auto& processState = processStates_[0];
  if (pathname == "/proc/self/exe") {
    // Copy executable path to buffer
    // TODO: resolve path into canonical path
    std::strncpy(buf, processState.path.c_str(), bufsize);

    return std::min(processState.path.length(), bufsize);
  }

  // TODO: resolve symbolic link for other paths
  return -1;
}

int64_t Linux::read(int64_t fd, void* buf, uint64_t count) {
  assert(fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }
  return ::read(hfd, buf, count);
}

int64_t Linux::readv(int64_t fd, const void* iovdata, int iovcnt) {
  assert(fd < processStates_[0].fileDescriptorTable.size());
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
  assert(fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }
  return ::write(hfd, buf, count);
}

int64_t Linux::writev(int64_t fd, const void* iovdata, int iovcnt) {
  assert(fd < processStates_[0].fileDescriptorTable.size());
  int64_t hfd = processStates_[0].fileDescriptorTable[fd];
  if (hfd < 0) {
    return EBADF;
  }
  return ::writev(hfd, reinterpret_cast<const struct iovec*>(iovdata), iovcnt);
}

}  // namespace kernel
}  // namespace simeng
