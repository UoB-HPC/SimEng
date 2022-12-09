#pragma once

#include <memory>
#include <set>
#include <unordered_map>
#include <vector>

#include "simeng/CoreInstance.hh"
#include "simeng/Elf.hh"
#include "simeng/kernel/LinuxProcess.hh"
#include "simeng/version.hh"
#include "yaml-cpp/yaml.h"

namespace simeng {
namespace kernel {

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

/** A simple, lightweight Operating System kernel based on Linux to emulate
 * syscalls and manage process execution. */
class SimOS {
 public:
  /** Construct a SimOS object. */
  SimOS(const std::vector<std::string>& commandLine, YAML::Node config);

  /** Execute the target workload through SimEng. */
  double execute();

  /** Create the desired amount of Core's. */
  void createCores(const uint64_t numCores);

  /** Create a new Linux process running above this kernel. */
  /// EDIT
  void createProcess(const LinuxProcess& process);

  /** Retrieve the initial stack pointer. */
  /// EDIT
  uint64_t getInitialStackPointer() const;

  /** The maximum size of a filesystem path. */
  static const size_t LINUX_PATH_MAX = 4096;

 protected:
  /** The state of the user-space processes running above the kernel. */
  std::vector<LinuxProcessState> processStates_;

  /** Translation between special files paths and simeng replacement files. */
  std::unordered_map<std::string, const std::string> specialPathTranslations_;

  /** Path to the root of the replacement special files. */
  const std::string specialFilesDir_ = SIMENG_BUILD_DIR "/specialFiles";

  /** Vector of all currently supported special file paths & files.*/
  std::vector<std::string> supportedSpecialFiles_;

 private:
  /** The list of available CPU cores*/
  std::vector<CoreInstance> cores_;

  /** The list of active processes. */
  std::vector<std::shared_ptr<LinuxProcess>> processes_;
};
}  // namespace kernel
}  // namespace simeng