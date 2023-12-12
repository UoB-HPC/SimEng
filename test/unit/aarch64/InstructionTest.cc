#include "../MockArchitecture.hh"
#include "gmock/gmock.h"
#include "simeng/ModelConfig.hh"
#include "simeng/arch/aarch64/Instruction.hh"
#include "simeng/version.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

// TODO: Implement instruction unit tests once InstructionMetadata.hh has been
// moved to include/simeng

// AArch64 Instruction Tests
class AArch64InstructionTest : public testing::Test {
 public:
  AArch64InstructionTest() {}

 protected:
  const std::string configPath = SIMENG_SOURCE_DIR "/configs/a64fx.yaml";
  YAML::Node config;

  MockArchitecture arch;
  //   InstructionMetadata metadata;
  MicroOpInfo uopInfo;
  InstructionException exception;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng