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
  uint64_t coreCount_;
  uint64_t smt_;
  uint64_t socketCount_;
  float bogoMIPS_;
  std::string features_;
  std::string cpuImplementer_;
  uint64_t cpuArchitecture_;
  std::string cpuVariant_;
  std::string cpuPart_;
  uint64_t cpuRevision_;
  uint64_t packageCount_;

};  // namespace SpecialFilesDirGen

}  // namespace simeng