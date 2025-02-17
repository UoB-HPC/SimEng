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
  virtual const std::vector<uint64_t>& getSysRegEnums() const = 0;

  /** Get the structure of the architecture register fileset(s). */
  virtual const std::vector<simeng::RegisterFileStructure>& getArchRegStruct()
      const = 0;

  /** Get the structure of the physical register fileset(s) as defined in the
   * simulation configuration. */
  virtual const std::vector<simeng::RegisterFileStructure>& getPhysRegStruct()
      const = 0;

  /** Get the quantities of the physical register in each fileset as defined in
   * the simulation configuration. */
  virtual const std::vector<uint16_t>& getPhysRegQuantities() const = 0;
};

}  // namespace arch
}  // namespace simeng