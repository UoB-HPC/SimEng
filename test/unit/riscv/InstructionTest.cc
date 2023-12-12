#include "../MockArchitecture.hh"
#include "gmock/gmock.h"
#include "simeng/ModelConfig.hh"
#include "simeng/arch/riscv/Instruction.hh"
#include "simeng/version.hh"

namespace simeng {
namespace arch {
namespace riscv {

// TODO: Implement instruction unit tests once InstructionMetadata.hh has been
// moved to include/simeng

// AArch64 Instruction Tests
class RiscVInstructionTest : public testing::Test {
 public:
  RiscVInstructionTest() {}

 protected:
  const std::string configPath = SIMENG_SOURCE_DIR "/configs/DEMO_RISCV.yaml";
  YAML::Node config;

  MockArchitecture arch;
  //   InstructionMetadata metadata;
  InstructionException exception;
};

}  // namespace riscv
}  // namespace arch
}  // namespace simeng