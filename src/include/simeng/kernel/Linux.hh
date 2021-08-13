#pragma once

#include <memory>
#include <set>
#include <unordered_map>

#include "simeng/kernel/LinuxProcess.hh"
#include "simeng/version.hh"

namespace simeng {
namespace kernel {

/** Fixed-width definition of `timeval`.
 * Defined by Linux kernel in include/uapi/asm-generic/stat.h */
struct stat {
  uint64_t dev;       // offset =   0
  uint64_t ino;       // offset =   8
  uint32_t mode;      // offset =  16
  uint32_t nlink;     // offset =  20
  uint32_t uid;       // offset =  24
  uint32_t gid;       // offset =  28
  uint64_t rdev;      // offset =  32
  uint64_t padding1;  // offset =  40
  int64_t size;       // offset =  48
  int32_t blksize;    // offset =  56
  uint32_t padding2;  // offset =  60
  int64_t blocks;     // offset =  64
  int64_t atime;      // offset =  72
  uint64_t padding3;  // offset =  80
  int64_t mtime;      // offset =  88
  uint64_t padding4;  // offset =  96
  int64_t ctime;      // offset = 104
  uint64_t padding5;  // offset = 112
  uint32_t padding6;  // offset = 116
  uint32_t padding7;  // offset = 124
};

/** Fixed-width definition of `termios`.
 * Defined by Linux kernel in `include/uapi/asm-generic/termbits.h` */
struct ktermios {
  uint32_t c_iflag;  // input mode flags
  uint32_t c_oflag;  // output mode flags
  uint32_t c_cflag;  // control mode flags
  uint32_t c_lflag;  // local mode flags
  uint8_t c_line;    // line discipline
  uint8_t c_cc[19];  // control characters
};

/** Fixed-width definition of `timeval` (from `<sys/time.h>`). */
struct timeval {
  int64_t tv_sec;   // seconds
  int64_t tv_usec;  // microseconds
};

/** Struct to hold information about a contiguous virtual memory area. */
struct vm_area_struct {
  /** The address representing the end of the memory allocation. */
  uint64_t vm_end = 0;
  /** The address representing the start of the memory allocation. */
  uint64_t vm_start = 0;
  /** The next allocation in the contiguous list. */
  std::shared_ptr<struct vm_area_struct> vm_next = NULL;
};

/** A state container for a Linux process. */
struct LinuxProcessState {
  /** The process ID. */
  int64_t pid;
  /** The path of the executable that created this process. */
  std::string path;
  /** The address of the start of the heap. */
  uint64_t startBrk;
  /** The address of the current end of heap. */
  uint64_t currentBrk;
  /** The initial stack pointer. */
  uint64_t initialStackPointer;
  /** The address of the start of the mmap region. */
  uint64_t mmapRegion;
  /** The page size of the process memory. */
  uint64_t pageSize;
  /** Contiguous memory allocations from the mmap system call. */
  std::vector<vm_area_struct> contiguousAllocations;
  /** Non-Contiguous memory allocations from the mmap system call. */
  std::vector<vm_area_struct> nonContiguousAllocations;

  // Thread state
  // TODO: Support multiple threads per process
  /** The clear_child_tid value. */
  uint64_t clearChildTid = 0;

  /** The virtual file descriptor mapping table. */
  std::vector<int64_t> fileDescriptorTable;
  /** Set of deallocated virtual file descriptors available for reuse. */
  std::set<int64_t> freeFileDescriptors;
};

/** A Linux kernel syscall emulation implementation, which mimics the responses
   to Linux system calls. */
class Linux {
 public:
  /** Create a new Linux process running above this kernel. */
  void createProcess(const LinuxProcess& process);

  /** Retrieve the initial stack pointer. */
  uint64_t getInitialStackPointer() const;

  /** brk syscall: change data segment size. Sets the program break to
   * `addr` if reasonable, and returns the program break. */
  int64_t brk(uint64_t addr);

  /** clock_gettime syscall: get the time of specified clock `clkId`, using
   * the system timer `systemTimer` (with nanosecond accuracy). Returns 0 on
   * success, and puts the retrieved time in the `seconds` and `nanoseconds`
   * arguments. */
  uint64_t clockGetTime(uint64_t clkId, uint64_t systemTimer, uint64_t& seconds,
                        uint64_t& nanoseconds);

  /** ftruncate syscall: truncate a file to an exact size. */
  int64_t ftruncate(uint64_t fd, uint64_t length);

  /** close syscall: close a file descriptor. */
  int64_t close(int64_t fd);

  /** newfstatat syscall: get file status; AKA fstatat. */
  int64_t newfstatat(int64_t dfd, const std::string& filename, stat& out,
                     int64_t flag);

  /** fstat syscall: get file status. */
  int64_t fstat(int64_t fd, stat& out);

  /** getpid syscall: get the process owner's process ID. */
  int64_t getpid() const;
  /** getuid syscall: get the process owner's user ID. */
  int64_t getuid() const;
  /** geteuid syscall: get the process owner's effective user ID. */
  int64_t geteuid() const;
  /** getgid syscall: get the process owner's group ID. */
  int64_t getgid() const;
  /** getegid syscall: get the process owner's effective group ID. */
  int64_t getegid() const;

  /** gettimeofday syscall: get the current time, using the system timer
   * `systemTimer` (with nanosecond accuracy). Returns 0 on success, and puts
   * the seconds and microsconds elapsed since the Epoch in `tv`, while setting
   * the elements of `tz` to 0. */
  int64_t gettimeofday(uint64_t systemTimer, timeval* tv, timeval* tz);

  /** ioctl syscall: control device. */
  int64_t ioctl(int64_t fd, uint64_t request, std::vector<char>& out);

  /** lseek syscall: reposition read/write file offset. */
  uint64_t lseek(int64_t fd, uint64_t offset, int64_t whence);

  /** munmap syscall: deletes the mappings for the specified address range. */
  int64_t munmap(uint64_t addr, size_t length);

  /** mmap syscall: map files or devices into memory. */
  uint64_t mmap(uint64_t addr, size_t length, int prot, int flags, int fd,
                off_t offset);

  /** openat syscall: open/create a file. */
  int64_t openat(int64_t dirfd, const std::string& path, int64_t flags,
                 uint16_t mode);

  /** readlinkat syscall: read value of a symbolic link. */
  int64_t readlinkat(int64_t dirfd, const std::string pathname, char* buf,
                     size_t bufsize) const;

  /** get a process's CPU affinity mask. */
  int64_t schedGetAffinity(pid_t pid, size_t cpusetsize, uint64_t mask);

  /** set a process's CPU affinity mask. */
  int64_t schedSetAffinity(pid_t pid, size_t cpusetsize, uint64_t mask);

  /** set_tid_address syscall: set clear_child_tid value for calling thread. */
  int64_t setTidAddress(uint64_t tidptr);

  /** read syscall: read buffer from a file. */
  int64_t read(int64_t fd, void* buf, uint64_t count);

  /** readv syscall: read buffers from a file. */
  int64_t readv(int64_t fd, const void* iovdata, int iovcnt);

  /** write syscall: write buffer to a file. */
  int64_t write(int64_t fd, const void* buf, uint64_t count);

  /** writev syscall: write buffers to a file. */
  int64_t writev(int64_t fd, const void* iovdata, int iovcnt);

  /** The maximum size of a filesystem path. */
  static const size_t LINUX_PATH_MAX = 4096;

 private:
  /** The state of the user-space processes running above the kernel. */
  std::vector<LinuxProcessState> processStates_;

  /** Translation between special files paths and simeng replacement files. */
  std::unordered_map<std::string, const std::string> specialPathTranslations_;

  /** Path to the root of the replacement special files. */
  const std::string specialFilesDir_ =
      SIMENG_SOURCE_DIR "/src/lib/kernel/specialFiles/";
};

}  // namespace kernel
}  // namespace simeng
