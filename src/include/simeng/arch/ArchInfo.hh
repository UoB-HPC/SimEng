#pragma once

#include <vector>

#include "capstone/capstone.h"
#include "simeng/RegisterFileSet.hh"
#include "simeng/config/yaml/ryml.hh"

namespace simeng {
namespace arch {

/** A class to hold and generate architecture specific configuration options. */
class ArchInfo {
 public:
  virtual ~ArchInfo(){};

  /** Get the set of system register enums currently supported. */
  virtual std::vector<uint64_t> getSysRegEnums(ryml::ConstNodeRef config) = 0;

  /** Get the structure of the architecture register fileset(s). */
  virtual std::vector<simeng::RegisterFileStructure> getArchRegStruct(
      ryml::ConstNodeRef config) = 0;
};

}  // namespace arch
}  // namespace simeng