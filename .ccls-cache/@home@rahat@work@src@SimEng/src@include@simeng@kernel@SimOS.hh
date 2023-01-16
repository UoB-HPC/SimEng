#pragma once

#include <string>
#include <tuple>
#include <vector>

#include "simeng/Config.hh"
#include "simeng/CoreInstance.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/kernel/SyscallHandler.hh"
#include "simeng/memory/SimpleMem.hh"
#include "simeng/span.hh"

// Forward declare RegressionTest class so that it can be declared a friend.
class RegressionTest;

namespace simeng {
namespace kernel {

// Program used when no executable is provided; counts down from
// 1024*1024, with an independent `orr` at the start of each branch.
static uint32_t hex_[8] = {
    0x320C03E0,  // orr w0, wzr, #1048576
    0x320003E1,  // orr w0, wzr, #1
    0x71000400,  // subs w0, w0, #1
    0x54FFFFC1,  // b.ne -8
                 // .exit:
    0xD2800000,  // mov x0, #0
    0xD2800BC8,  // mov x8, #94
    0xD4000001,  // svc #0
};

/** A simple, lightweight Operating System kernel based on Linux to emulate
 * syscalls and manage process execution. */
class SimOS {
 public:
  /** Construct a SimOS object. */
  SimOS(int argc, char** argv, std::shared_ptr<simeng::memory::Mem> mem);

  /** Get pointer to process with specified PID. */
  std::shared_ptr<Process> getProcess() const;

  /** Get user defined config, executable, and executable args. */
  std::tuple<std::string, std::vector<std::string>> getParsedArgv() const {
    return {executablePath_, executableArgs_};
  };

  /** Get shared_ptr to syscallHandler instance. */
  std::shared_ptr<SyscallHandler> getSyscallHandler() const {
    return syscallHandler_;
  }

  /** Set up friend class with RegressionTest to enable exclusive access to
   * protected functions. */
  friend class ::RegressionTest;

 private:
  /** Create the initial SimOS Process running above this kernel from command
   * line arguments.
   * Empty command line arguments denote the usage of hardcoded instructions
   * held in the hex_ array.*/
  void createInitialProcess();

  /** Construct the special file directory. */
  void createSpecialFileDirectory() const;

  /** Update the initial process to a pre-defined one.
   * Should be used EXCLUSIVELY by the test suite. */
  void setInitialProcess(std::shared_ptr<Process> proc) {
    processes_.emplace(processes_.begin(), proc);
  }

  /** The path of user defined Executable. */
  std::string executablePath_ = DEFAULT_STR;

  /** The runtime arguments of the user defined executable. */
  std::vector<std::string> executableArgs_ = {};

  /** The list of user-space processes running above the kernel. */
  std::vector<std::shared_ptr<Process>> processes_ = {};

  /** Reference to the global memory pointer */
  std::shared_ptr<simeng::memory::Mem> memory_ = nullptr;

  /** SyscallHandler Object to process all syscalls. */
  std::shared_ptr<SyscallHandler> syscallHandler_;
};

}  // namespace kernel
}  // namespace simeng