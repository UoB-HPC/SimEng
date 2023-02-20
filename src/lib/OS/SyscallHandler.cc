#include "simeng/OS/SyscallHandler.hh"

#include "simeng/OS/SimOS.hh"
namespace simeng {
namespace OS {

SyscallHandler::SyscallHandler(SimOS* os) : os_(os) {
  // Define vector of all currently supported special file paths & files.
  supportedSpecialFiles_.insert(
      supportedSpecialFiles_.end(),
      {"/proc/cpuinfo", "proc/stat", "/sys/devices/system/cpu",
       "/sys/devices/system/cpu/online", "core_id", "physical_package_id"});
}

// TODO : update when supporting multi-process/thread
uint64_t SyscallHandler::getDirFd(int64_t dfd, std::string pathname) {
  // Resolve absolute path to target file
  char absolutePath[PATH_MAX_LEN];
  realpath(pathname.c_str(), absolutePath);

  int64_t dfd_temp = AT_FDCWD;
  if (dfd != -100) {
    dfd_temp = dfd;
    // If absolute path used then dfd is dis-regarded. Otherwise need to see if
    // fd exists for directory referenced
    if (strncmp(pathname.c_str(), absolutePath, strlen(absolutePath)) != 0) {
      auto entry = os_->getProcess(0)->fdArray_->getFDEntry(dfd);
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
          std::cerr << "[SimEng:SyscallHandler] Using Special File: "
                    << filename.c_str() << std::endl;
          return specialFilesDir_ + filename;
        }
      }
      std::cerr
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
  return os_->getProcess(0)->getMemRegion().updateBrkRegion(address);
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
    assert(false && "Unhandled clk_id in clock_gettime syscall");
    return -1;
  }
}

int64_t SyscallHandler::ftruncate(uint64_t fd, uint64_t length) {
  auto entry = os_->getProcess(0)->fdArray_->getFDEntry(fd);
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
    return os_->getProcess(0)->fdArray_->removeFDEntry(fd);
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
  auto entry = os_->getProcess(0)->fdArray_->getFDEntry(fd);
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

int64_t SyscallHandler::getpid() const {
  // TODO : Needs to be properly implemented once multi-thread supported
  return 0;
}

int64_t SyscallHandler::getuid() const { return 0; }
int64_t SyscallHandler::geteuid() const { return 0; }
int64_t SyscallHandler::getgid() const { return 0; }
int64_t SyscallHandler::getegid() const { return 0; }
// TODO update for multithreaded processes
int64_t SyscallHandler::gettid() const { return 0; }

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
  auto entry = os_->getProcess(0)->fdArray_->getFDEntry(fd);
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
      assert(false && "unimplemented ioctl request");
      return -1;
  }
}

uint64_t SyscallHandler::lseek(int64_t fd, uint64_t offset, int64_t whence) {
  auto entry = os_->getProcess(0)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();
  return ::lseek(hfd, offset, whence);
}

int64_t SyscallHandler::munmap(uint64_t addr, size_t length) {
  return os_->getProcess(0)->getMemRegion().unmapRegion(addr, length);
}

int64_t SyscallHandler::mmap(uint64_t addr, size_t length, int prot, int flags,
                             int fd, off_t offset) {
  auto process = os_->getProcess(0);
  HostFileMMap hostfile;

  if (fd > 0) {
    auto entry = process->fdArray_->getFDEntry(fd);
    if (!entry.isValid()) {
      std::cerr << "[SimEng:SyscallHandler] Invalid virtual file descriptor "
                   "given to mmap"
                << std::endl;
      return -1;
    }
    hostfile = os_->hfmmap_->mapfd(entry.getFd(), length, offset);
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

  auto proc = os_->getProcess(0);
  return proc->fdArray_->allocateFDEntry(dirfd, new_pathname.c_str(), newFlags,
                                         mode);
}

int64_t SyscallHandler::readlinkat(int64_t dirfd, const std::string& pathname,
                                   char* buf, size_t bufsize) const {
  auto process = os_->getProcess(0);
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
  auto entry = os_->getProcess(0)->fdArray_->getFDEntry(fd);
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
  auto entry = os_->getProcess(0)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();
  return ::read(hfd, buf, count);
}

int64_t SyscallHandler::readv(int64_t fd, const void* iovdata, int iovcnt) {
  auto entry = os_->getProcess(0)->fdArray_->getFDEntry(fd);
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
  os_->getProcess(0)->clearChildTid = tidptr;
  return 0;
}

int64_t SyscallHandler::write(int64_t fd, const void* buf, uint64_t count) {
  auto entry = os_->getProcess(0)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();
  return ::write(hfd, buf, count);
}

int64_t SyscallHandler::writev(int64_t fd, const void* iovdata, int iovcnt) {
  auto entry = os_->getProcess(0)->fdArray_->getFDEntry(fd);
  if (!entry.isValid()) {
    return EBADF;
  }
  int64_t hfd = entry.getFd();
  return ::writev(hfd, reinterpret_cast<const struct iovec*>(iovdata), iovcnt);
}

}  // namespace OS
}  // namespace simeng
