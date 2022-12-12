#pragma once

#include <string>
#include <tuple>
#include <vector>

#include "simeng/kernel/SyscallHandler.hh"

#define DEFAULT_PATH "Default"

namespace simeng {
namespace kernel {

/** A simple, lightweight Operating System kernel based on Linux to emulate
 * syscalls and manage process execution. */
class SimOS {
 public:
  /** Construct a SimOS object. */
  SimOS(int argc, char** argv);

  /** Get user defined config, executable, and executable args. */
  std::tuple<std::string, std::string, std::vector<std::string>>
  getParsedArgv() {
    return {configFilePath_, executablePath_, executableArgs_};
  };

  /** Create a new Linux process running above this kernel. */
  /// EDIT
  void createProcess(const LinuxProcess& process);

  /** Retrieve the initial stack pointer. */
  /// EDIT
  uint64_t getInitialStackPointer() const;

  /** SyscallHandler Object to process all syscalls. */
  SyscallHandler syscalls_;

  /** The maximum size of a filesystem path. */
  static const size_t LINUX_PATH_MAX = 4096;

 private:
  /** The path of user defined Config File.*/
  std::string configFilePath_ = DEFAULT_PATH;

  /** The path of user defined Executable. */
  std::string executablePath_ = DEFAULT_PATH;

  /** The runtime arguments of the user defined executable. */
  std::vector<std::string> executableArgs_ = {};

  /** The list of active processes. */
  std::vector<std::shared_ptr<LinuxProcess>> processes_;

  /** The state of the user-space processes running above the kernel. */
  std::vector<LinuxProcessState> processStates_;
};

}  // namespace kernel
}  // namespace simeng