#include "simeng/kernel/Linux.hh"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
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
                            .initialStackPointer = process.getStackPointer()});
  processStates_.back().fileDescriptorTable.push_back(STDIN_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDOUT_FILENO);
  processStates_.back().fileDescriptorTable.push_back(STDERR_FILENO);
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
  if (clkId == CLOCK_REALTIME) {
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

int64_t Linux::openat(int64_t dirfd, const std::string& pathname, int64_t flags,
                      uint16_t mode) {
  // Resolve absolute path to target file
  char absolutePath[LINUX_PATH_MAX];
  realpath(pathname.c_str(), absolutePath);

  // Check if path may be a special file, bail out if it is
  // TODO: Add support for special files
  for (auto prefix : {"/dev/", "/proc/", "/sys/"}) {
    if (strncmp(absolutePath, prefix, strlen(prefix)) == 0) {
      std::cerr << "ERROR: attempted to open special file: "
                << "'" << absolutePath << "'" << std::endl;
      exit(1);
    }
  }

  // Pass syscall through to host
  assert(dirfd == -100 && "unsupported dirfd argument in openat syscall");
  int64_t hfd = ::openat(AT_FDCWD, pathname.c_str(), flags, mode);
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

int64_t Linux::readlinkat(int64_t dirfd, const std::string pathname, char* buf,
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
