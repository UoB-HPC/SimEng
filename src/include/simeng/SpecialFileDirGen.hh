#pragma once

#include <fstream>
#include <string>

#include "simeng/config/SimInfo.hh"
#include "simeng/version.hh"

namespace simeng {
class SpecialFileDirGen {
 public:
  /** Construct a SpecialFileDirGen class by reading in the YAML file and
   * running it through checks and formatting. */
  SpecialFileDirGen();

  /** Removes all files inside the '/src.lib/kernel/specialFiles' directory. */
  void RemoveExistingSFDir();

  /** Creates necessary file structure to support needed special files inside
   * the '/src.lib/kernel/specialFiles' directory. */
  void GenerateSFDir();

 private:
  /** Path to the root of the SimEng special files directory. */
  const std::string specialFilesDir_ = SIMENG_BUILD_DIR "/specialFiles";

  /** Values declared in YAML config file needed to create the Special Files
   * Directory tree. */
  uint64_t core_count;
  uint64_t smt;
  uint64_t socket_count;
  float bogoMIPS;
  std::string features;
  std::string cpu_implementer;
  uint64_t cpu_architecture;
  std::string cpu_variant;
  std::string cpu_part;
  uint64_t cpu_revision;
  uint64_t package_count;

};  // namespace SpecialFilesDirGen

}  // namespace simeng