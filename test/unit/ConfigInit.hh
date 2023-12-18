#pragma once

#include "simeng/config/SimInfo.hh"
#include "simeng/version.hh"

namespace simeng {

// This small class' purpose is to initialise the SimInfo config before the
// initialisation of a test class
class ConfigInit {
 public:
  ConfigInit(config::ISA isa) {
    if (isa == config::ISA::AArch64) {
      config::SimInfo::setConfig(SIMENG_SOURCE_DIR "/configs/a64fx.yaml");
    } else if (isa == config::ISA::RV64) {
      config::SimInfo::setConfig(SIMENG_SOURCE_DIR "/configs/DEMO_RISCV.yaml");
    }
  }

  ConfigInit(std::string configAdditions) {
    config::SimInfo::addToConfig(configAdditions);
    config::SimInfo::reBuild();
  }
};

}  // namespace simeng