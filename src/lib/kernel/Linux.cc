#include "simeng/kernel/Linux.hh"

#include <sys/ioctl.h>
#include <sys/uio.h>
#include <algorithm>
#include <cassert>
#include <cstring>

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
  assert(fd == 1 && "unimplemented ioctl fd");
  switch (request) {
    case 0x5413:  // TIOCGWINSZ
      out.resize(sizeof(struct winsize));
      ::ioctl(fd, TIOCGWINSZ, out.data());
      return 0;
    default:
      assert(false && "unimplemented ioctl request");
      return -1;
  }
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

int64_t Linux::setTidAddress(uint64_t tidptr) {
  assert(processStates_.size() > 0);
  processStates_[0].clearChildTid = tidptr;
  return processStates_[0].pid;
}

uint64_t Linux::writev(int64_t fd, void* iovdata, int iovcnt) {
  assert(fd == 1 && "unimplemented writev fd");
  return ::writev(fd, reinterpret_cast<const struct iovec*>(iovdata), iovcnt);
}

}  // namespace kernel
}  // namespace simeng
