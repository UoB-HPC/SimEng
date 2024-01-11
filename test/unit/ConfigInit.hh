#pragma once

#include "simeng/config/SimInfo.hh"
#include "simeng/version.hh"

namespace simeng {

// This small class' purpose is to initialise the SimInfo config before the
// initialisation of a test class
class ConfigInit {
 public:
  ConfigInit(config::ISA isa, std::string configAdditions) {
    config::SimInfo::generateDefault(isa, true);
    config::SimInfo::addToConfig(configAdditions);
  }
};

}  // namespace simeng