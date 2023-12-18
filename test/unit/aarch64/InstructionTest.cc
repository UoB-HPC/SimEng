#include "../ConfigInit.hh"
#include "../MockArchitecture.hh"
#include "gmock/gmock.h"
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
  ConfigInit configInit = ConfigInit(config::ISA::AArch64);

  MockArchitecture arch;
  //   InstructionMetadata metadata;
  MicroOpInfo uopInfo;
  InstructionException exception;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng