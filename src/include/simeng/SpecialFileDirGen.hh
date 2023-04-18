#pragma once

#include <fstream>
#include <string>

#include "simeng/SimInfo.hh"
#include "simeng/version.hh"

namespace simeng {

/** Path to the root of the SimEng special files directory. */
static const std::string specialFilesDir_ = SIMENG_BUILD_DIR "/specialFiles";
class SpecialFileDirGen {
 public:
  /** Construct a SpecialFileDirGen class by reading in the YAML file and
   * running it through checks and formatting. */
  SpecialFileDirGen();

  /** Removes all files inside the 'simeng/build/specialFiles' directory. */
  void RemoveExistingSFDir();

  /** Creates necessary file structure to support needed special files inside
   * the 'simeng/build/specialFiles' directory. */
  void GenerateSFDir();

 private:
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