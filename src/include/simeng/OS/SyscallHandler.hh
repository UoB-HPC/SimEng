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
#include <cstdint>
#include <cstring>
#include <iostream>
#include <list>
#include <memory>
#include <queue>
#include <set>
#include <unordered_map>
#include <vector>

#include "simeng/Elf.hh"
#include "simeng/OS/Process.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/memory/Mem.hh"
#include "simeng/memory/MemRequests.hh"
#include "simeng/version.hh"

static constexpr uint16_t PATH_MAX_LEN = 4096;

namespace simeng {
namespace OS {

/** Enum representing the status of a process that has invoked the futex
 * syscall. */
enum class FutexStatus : uint8_t { FUTEX_SLEEPING, FUTEX_AWAKE };

/** This struct stores all information required to perform the futex syscall.*/
struct FutexInfo {
  /** This is the address in memory where the futex word is stored. */
  uint64_t faddr = 0;

  /** This is the process which invoked the futex syscall. */
  std::shared_ptr<Process> process = nullptr;

  /** This is the status of the process after a futex syscall has been
   * performed. */
  FutexStatus status = FutexStatus::FUTEX_SLEEPING;

  /** Default constructor for the FutexInfo struct. */
  FutexInfo() {}

  /** Default copy constructor for FutexInfo. */
  FutexInfo(const FutexInfo& res) = default;

  /** Default move constructor for FutexInfo to enable copy elision
   * whenever it is possible. */
  FutexInfo(FutexInfo&& res) = default;

  /** Default copy assignment operator for FutexInfo. */
  FutexInfo& operator=(const FutexInfo& res) = default;

  /** Default move assignment operator for FutexInfo to enable copy
   * elision whenever it is possible. */
  FutexInfo& operator=(FutexInfo&& res) = default;

  /** This constructor creates the FutexInfo struct with specific values. */
  FutexInfo(uint32_t uaddr, std::shared_ptr<Process> proc, FutexStatus sts)
      : faddr(uaddr), process(proc), status(sts) {}
};

// Forward declare SimOS to resolve the circular dependency.
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
  std::vector<memory::MemoryAccessTarget> memoryAddresses;

  /** Values to write to memory */
  std::vector<RegisterValue> memoryAddressValues;

  /** Default copy constructor for ProcessStateChange. */
  ProcessStateChange(const ProcessStateChange& res) = default;

  /** Default move constructor for ProcessStateChange to enable copy elision
   * whenever it is possible. */
  ProcessStateChange(ProcessStateChange&& res) = default;

  /** Default copy assignment operator for ProcessStateChange. */
  ProcessStateChange& operator=(const ProcessStateChange& res) = default;

  /** Default move assignment operator for ProcessStateChange to enable copy
   * elision whenever it is possible. */
  ProcessStateChange& operator=(ProcessStateChange&& res) = default;
};

/** This result from a handled syscall. */
struct SyscallResult {
  /** Indicates whether the outcome of the syscall is fatal for the associated
   * core and it should therefore halt. */
  bool fatal = false;

  /** Indicates whether the receiving core should go into an idle state after
   * the syscall has concluded and all state changes have been processed. */
  bool idleAfterSyscall = false;

  /** Id of the syscall to aid exception handler processing. */
  uint64_t syscallId = 0;

  /** The unique ID of the core associated with the syscall. */
  uint64_t coreId = 0;

  /** Any changes to apply to the process state. */
  ProcessStateChange stateChange = {};

  /** Default copy constructor for SyscallResult. */
  SyscallResult(const SyscallResult& res) = default;

  /** Default move constructor for SyscallResult to enable copy elision whenever
   * it is possible. */
  SyscallResult(SyscallResult&& res) = default;

  /** Default copy assignment operator for SyscallResult. */
  SyscallResult& operator=(const SyscallResult& res) = default;

  /** Default move assignment operator for SyscallResult to enable copy elision
   * whenever it is possible. */
  SyscallResult& operator=(SyscallResult&& res) = default;
};

/** A struct to hold information used as arguments to a syscall. */
struct SyscallInfo {
  /** The ID of the syscall. */
  uint64_t syscallId = 0;

  /** The unique ID of the core associated with the syscall. */
  uint64_t coreId = 0;

  /** The unique ID of the process associated with the syscall. Default value is
   * 1 as this is the lowest TID available. */
  uint64_t threadId = 1;

  /** The register values used as parameters to the invoked syscall. */
  std::array<RegisterValue, 6> registerArguments = {};

  /** The register which will be updated with the return value of the processed
   * syscall. */
  Register ret = {0, 0};

  /** Default copy constructor for SyscallInfo. */
  SyscallInfo(const SyscallInfo& info) = default;

  /** Default move constructor for SyscallInfo to enable copy elision whenever
   * it is possible. */
  SyscallInfo(SyscallInfo&& info) = default;

  /** Default copy assignment operator for SyscallInfo. */
  SyscallInfo& operator=(const SyscallInfo& info) = default;

  /** Default move assignment operator for SyscallInfo to enable copy elision
   * whenever it is possible. */
  SyscallInfo& operator=(SyscallInfo&& info) = default;
};

/** A Linux kernel syscall emulation implementation, which mimics the responses
   to Linux system calls. */
class SyscallHandler {
 public:
  /** Create new SyscallHandler object. */
  SyscallHandler(SimOS* OS, std::shared_ptr<simeng::memory::Mem> memory);

  /** Tick the syscall handler to carry out any oustanding syscalls. */
  void tick();

  /** Function used to process the syscall at the front of the syscallQueue_
   * queue. */
  void handleSyscall();

  /** This function receives a SyscallInfo struct from the a Core and adds it to
   * syscallQueue_ so it can be processed. */
  void receiveSyscall(SyscallInfo info);

  /** Once the syscall is complete, conclude its execution by
   * constructing a SyscallResult and supplying it to the returnSyscall_
   * function. */
  void concludeSyscall(const ProcessStateChange& change, bool fatal = false,
                       bool idleAftersycall = false);

  /** Attempt to read a string of max length `maxLength` from address `address`
   * into the supplied buffer, starting from character `offset`. */
  void readStringThen(std::array<char, PATH_MAX_LEN>& buffer, uint64_t address,
                      int maxLength, std::function<void(size_t length)> then,
                      int offset = 0);

  /** Read `length` bytes of data from `ptr`, and then call `then`. */
  void readBufferThen(uint64_t ptr, uint64_t length,
                      std::function<void()> then);

  /** Performs a readlinkat syscall using the path supplied. The length of the
   * supplied path is held in the `length` parameter. */
  void readLinkAt(std::string path, size_t length);

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

  /** clone syscall: creates a new thread of the calling process. */
  int64_t clone(uint64_t flags, uint64_t stackPtr, uint64_t parentTidPtr,
                uint64_t tls, uint64_t childTidPtr);

  /** mmap syscall: map files or devices into memory. */
  int64_t mmap(uint64_t addr, size_t length, int prot, int flags, int fd,
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

  /** futex syscall: Mutex like thread scheduling in the user space.
   * This method returns a pair<bool, long>. The 'bool' signifies whether the
   * core status should set to idle after the syscall result has been received
   * by the core and 'long' specifies the syscall return value. */
  std::pair<bool, long> futex(uint64_t uaddr, int futex_op, uint32_t val,
                              uint64_t tid,
                              const struct timespec* timeout = nullptr,
                              uint32_t uaddr2 = 0, uint32_t val3 = 0);

  /** Method to remove all FutexInfo structs associated with a tgid. */
  void removeFutexInfoList(uint64_t tgid);

  /** Method to remove a FutexInfo struct containing process with TID = 'tid'
   * and TGID = 'tgid' */
  void removeFutexInfo(uint64_t tgid, uint64_t tid);

 private:
  /** Returns the correct dirFd depending on the pathname and dirFd given to
   * syscall. */
  uint64_t getDirFd(int64_t dfd, std::string pathname);

  /** If the given filepath points to a special file, the filepath is replaced
   * to point to the SimEng equivalent. */
  std::string getSpecialFile(const std::string filename);

  /** Pointer reference to SimOS object. */
  SimOS* OS_ = nullptr;

  /** A shared pointer to the simulation memory. */
  std::shared_ptr<simeng::memory::Mem> memory_;

  /** A queue to hold all outstanding syscalls. */
  std::queue<SyscallInfo> syscallQueue_;

  /** The SyscallInfo of the syscall currently being handled. */
  SyscallInfo currentInfo_ = {};

  /** Vector of all currently supported special file paths & files.*/
  std::vector<std::string> supportedSpecialFiles_;

  /** A data buffer used for reading data from memory. */
  std::vector<char> dataBuffer_;

  /** Unordered map used to keep track of all processes sleeping on a futex. */
  std::unordered_map<uint64_t, std::list<FutexInfo>> futexTable_;
};

}  // namespace OS
}  // namespace simeng
