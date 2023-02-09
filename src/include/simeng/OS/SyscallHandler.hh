#pragma once

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
#include <iostream>
#include <memory>
#include <queue>
#include <set>
#include <unordered_map>
#include <vector>

#include "simeng/Elf.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/OS/Process.hh"
#include "simeng/version.hh"

static constexpr uint16_t PATH_MAX_LEN = 4096;

namespace simeng {
namespace OS {

// Forward delare everything needed for SimOS
class SimOS;

/** Fixed-width definition of `stat`.
 * Defined by Linux kernel in include/uapi/asm-generic/stat.h */
struct stat {
  uint64_t dev;        // offset =   0
  uint64_t ino;        // offset =   8
  uint32_t mode;       // offset =  16
  uint32_t nlink;      // offset =  20
  uint32_t uid;        // offset =  24
  uint32_t gid;        // offset =  28
  uint64_t rdev;       // offset =  32
  uint64_t padding1;   // offset =  40
  int64_t size;        // offset =  48
  int32_t blksize;     // offset =  56
  uint32_t padding2;   // offset =  60
  int64_t blocks;      // offset =  64
  int64_t atime;       // offset =  72
  uint64_t atimensec;  // offset =  80
  int64_t mtime;       // offset =  88
  uint64_t mtimensec;  // offset =  96
  int64_t ctime;       // offset = 104
  uint64_t ctimensec;  // offset = 112
  uint32_t padding3;   // offset = 116
  uint32_t padding4;   // offset = 124
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

/** Fixed-width definition of 'rusage' (from <sys/resource.h>). */
struct rusage {
  struct ::timeval ru_utime;  // user CPU time used
  struct ::timeval ru_stime;  // system CPU time used
  int64_t ru_maxrss;          // maximum resident set size
  int64_t ru_ixrss;           // integral shared memory size
  int64_t ru_idrss;           // integral unshared data size
  int64_t ru_isrss;           // integral unshared stack size
  int64_t ru_minflt;          // page reclaims (soft page faults)
  int64_t ru_majflt;          // page faults (hard page faults)
  int64_t ru_nswap;           // swaps
  int64_t ru_inblock;         // block input operations
  int64_t ru_oublock;         // block output operations
  int64_t ru_msgsnd;          // IPC messages sent
  int64_t ru_msgrcv;          // IPC messages received
  int64_t ru_nsignals;        // signals received
  int64_t ru_nvcsw;           // voluntary context switches
  int64_t ru_nivcsw;          // involuntary context switches
};

/** Definition of the structure used in getdents64. Required as not defined on
 * some systems. */
struct linux_dirent64 {
  uint64_t d_ino;     // 64-bit inode number
  uint64_t d_off;     // 64-bit offset to next structure
  uint16_t d_reclen;  // Size of this dirent
  uint16_t d_namlen;  // Size of the filename
  uint8_t d_type;     // File type
  char* d_name;       // Filename (null-terminated)
};

/** The types of changes that can be made to values within the process state. */
enum class ChangeType { REPLACEMENT, INCREMENT, DECREMENT };

/** A structure describing a set of changes to the process state. */
struct ProcessStateChange {
  /** Type of changes to be made */
  ChangeType type;
  /** Registers to modify */
  std::vector<Register> modifiedRegisters;
  /** Values to set modified registers to */
  std::vector<RegisterValue> modifiedRegisterValues;
  /** Memory address/width pairs to modify */
  std::vector<MemoryAccessTarget> memoryAddresses;
  /** Values to write to memory */
  std::vector<RegisterValue> memoryAddressValues;
};

/** The result from a handled syscall. */
struct SyscallResult {
  /** Whether execution should halt. */
  bool fatal;
  /** Id of the syscall to aid exception handler processing. */
  uint64_t syscallId;
  // The unique ID of the core associated with the syscall
  uint64_t coreId;
  /** Any changes to apply to the process state. */
  ProcessStateChange stateChange;
};

/** A struct to hold information used as arguments to a syscall. */
struct SyscallInfo {
  // The ID of the syscall
  uint64_t syscallId;
  // The unique sequenceID of the instructions triggering the syscall
  uint64_t seqId;
  // The unique ID of the core associated with the syscall
  uint64_t coreId;
  // The unique ID of the process associated with the syscall
  uint64_t processId;
  // The register values used a parameters to the envoked syscall
  RegisterValue R0;
  RegisterValue R1;
  RegisterValue R2;
  RegisterValue R3;
  RegisterValue R4;
  RegisterValue R5;
  // The register to return the success code to
  Register ret;
};

/** A Linux kernel syscall emulation implementation, which mimics the responses
   to Linux system calls. */
class SyscallHandler {
 public:
  /** Create new SyscallHandler object. */
  SyscallHandler(
      const std::unordered_map<uint64_t, std::shared_ptr<Process>>& processes,
      std::shared_ptr<MemoryInterface> memory,
      std::function<void(simeng::OS::SyscallResult)> returnSyscall,
      std::function<uint64_t()> getSystemTime);

  /** Tick the syscall handler to carry out any oustanding syscalls. */
  void tick();

  /** Initialise the processing of the syscall at the front of the syscallQueue_
   * queue. */
  void initSyscall();

  /** Add the incoming syscall to the syscallQueue_ queue for later processing.
   */
  void receiveSyscall(const SyscallInfo info);

  /** Once the syscall is deemed complete, conclude its execution by
   * constructing a SyscallResult and supplying it to the returnSyscall_
   * function. */
  void concludeSyscall(ProcessStateChange change, bool fatal = false);

  /** Attempt to read a string of max length `maxLength` from address `address`
   * into the supplied buffer, starting from character `offset`. An offset of
   * `-1` (default) will queue a read operation for the first character.
   *
   * This function will repeatedly set itself as the handler for the next cycle
   * until it either reads a null character or reaches the maximum length, at
   * which point it will call `then`, supplying the length of the read string.
   */
  void readStringThen(char* buffer, uint64_t address, int maxLength,
                      std::function<void(size_t length)> then, int offset = -1);

  /** Read `length` bytes of data from `ptr`, and then call `then`.
   *
   * This function will repeatedly set itself as the handler for the next cycle
   * until it has read `length` bytes of data. The data may be read in chunks if
   * it is larger than can be read in a single memory request. The data will be
   * appended to the member vector `dataBuffer`.
   */
  void readBufferThen(uint64_t ptr, uint64_t length, std::function<void()> then,
                      bool firstCall = true);

  /** Performs a readlinkat syscall using the path supplied. */
  void readLinkAt(span<char> path);

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

  /** faccessat syscall: checks whether the calling process can access the
   * file 'pathname'. */
  int64_t faccessat(int64_t dfd, const std::string& filename, int64_t mode,
                    int64_t flag);

  /** close syscall: close a file descriptor. */
  int64_t close(int64_t fd);

  /** newfstatat syscall: get file status; AKA fstatat. */
  int64_t newfstatat(int64_t dfd, const std::string& filename, stat& out,
                     int64_t flag);

  /** fstat syscall: get file status. */
  int64_t fstat(int64_t fd, stat& out);

  /** getrusage syscall: get recource usage measures for Who*/
  int64_t getrusage(int64_t who, rusage& out);

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
  /** gettid syscall: get the process owner's thread ID. */
  int64_t gettid() const;

  /** gettimeofday syscall: get the current time, using the system timer
   * `systemTimer` (with nanosecond accuracy). Returns 0 on success, and puts
   * the seconds and microsconds elapsed since the Epoch in `tv`, while
   * setting the elements of `tz` to 0. */
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
  int64_t readlinkat(int64_t dirfd, const std::string& pathname, char* buf,
                     size_t bufsize) const;

  /** get a process's CPU affinity mask. */
  int64_t schedGetAffinity(pid_t pid, size_t cpusetsize, uint64_t mask);

  /** set a process's CPU affinity mask. */
  int64_t schedSetAffinity(pid_t pid, size_t cpusetsize, uint64_t mask);

  /** set_tid_address syscall: set clear_child_tid value for calling thread.
   */
  int64_t setTidAddress(uint64_t tidptr);

  /** getdents64 syscall: read several linux_dirent structures from directory
   * referred to by open file into a buffer. */
  int64_t getdents64(int64_t fd, void* buf, uint64_t count);

  /** read syscall: read buffer from a file. */
  int64_t read(int64_t fd, void* buf, uint64_t count);

  /** readv syscall: read buffers from a file. */
  int64_t readv(int64_t fd, const void* iovdata, int iovcnt);

  /** write syscall: write buffer to a file. */
  int64_t write(int64_t fd, const void* buf, uint64_t count);

  /** writev syscall: write buffers to a file. */
  int64_t writev(int64_t fd, const void* iovdata, int iovcnt);

 private:
  /** Resturn correct Dirfd depending on given pathname abd dirfd given to
   * syscall. */
  uint64_t getDirFd(int64_t dfd, std::string pathname);

  /** If the given filepath points to a special file, the filepath is replaced
   * to point to the SimEng equivalent. */
  std::string getSpecialFile(const std::string filename);

  /** The user-space processes running above the kernel. */
  const std::unordered_map<uint64_t, std::shared_ptr<Process>>& processes_;

  /** A memory interface to the system memory. */
  std::shared_ptr<MemoryInterface> memory_;

  /** A callback function to send a syscall result back to a core through the
   * SimOS class. */
  std::function<void(simeng::OS::SyscallResult)> returnSyscall_;

  /** A callback function to get the system time from the SimOS class. */
  std::function<uint64_t()> getSystemTime_;

  /** A queue to hold all outstanding syscalls. */
  std::queue<const SyscallInfo> syscallQueue_;

  /** A function to call to resume handling an exception. */
  std::function<void()> resumeHandling_;

  /** Path to the root of the replacement special files. */
  const std::string specialFilesDir_ = SIMENG_BUILD_DIR "/specialFiles";

  /** Vector of all currently supported special file paths & files.*/
  std::vector<std::string> supportedSpecialFiles_;

  /** A data buffer used for reading data from memory. */
  std::vector<uint8_t> dataBuffer_;
};

}  // namespace OS
}  // namespace simeng
