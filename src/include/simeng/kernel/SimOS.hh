#pragma once

#include <string>
#include <tuple>
#include <vector>

#include "simeng/CoreInstance.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/kernel/SyscallHandler.hh"
#include "simeng/span.hh"

#define DEFAULT_STR "Default"

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

  /** Create the initial SimOS Process running above this kernel from command
   * line arguments.
   * Empty command line arguments denote the usage of hardcoded instructions
   * held in the hex_ array.*/
  void createInitialProcess();

  /** Get pointer to process with specified PID. */
  std::shared_ptr<Process> getProcess();

  /** Get user defined config, executable, and executable args. */
  std::tuple<YAML::Node&, std::string, std::vector<std::string>>
  getParsedArgv() {
    return {config_, executablePath_, executableArgs_};
  };

  /** SyscallHandler Object to process all syscalls. */
  SyscallHandler syscallHandler_;

 private:
  /** Construct the special file directory. */
  void createSpecialFileDirectory();

  /** The user defined Config File describing the modelled core to be created.*/
  YAML::Node config_;

  /** The path of user defined Executable. */
  std::string executablePath_ = DEFAULT_STR;

  /** The runtime arguments of the user defined executable. */
  std::vector<std::string> executableArgs_ = {};

  /** The list of user-space processes running above the kernel. */
  std::vector<std::shared_ptr<Process>> processes_;

  /** Reference to the global memory pointer */
  std::shared_ptr<simeng::memory::Mem> memory_ = nullptr;
};

}  // namespace kernel
}  // namespace simeng