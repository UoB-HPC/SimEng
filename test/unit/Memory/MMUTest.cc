#include "../MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/memory/SimpleMem.hh"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Field;
using ::testing::Return;
using ::testing::SetArgReferee;

namespace simeng {
namespace memory {

class MemoryMMUTest : public testing::Test {
 public:
  MemoryMMUTest()
      : memory(std::make_shared<memory::SimpleMem>(1024)),
        mmu(memory::MMU(fn)),
        connection(),
        uop(new MockInstruction),
        uopPtr(uop) {
    uopPtr->setInstructionAddress(0);

    // Set up MMU->Memory connection
    port1 = mmu.initPort();
    port2 = memory->initPort();
    connection.connect(port1, port2);
  }

 protected:
  VAddrTranslator fn = [](uint64_t vaddr, uint64_t pid) -> uint64_t {
    return vaddr;
  };

  std::shared_ptr<memory::SimpleMem> memory;
  memory::MMU mmu;

  simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>> connection;
  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      port1;
  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      port2;

  MockInstruction* uop;
  std::shared_ptr<Instruction> uopPtr;
};

TEST_F(MemoryMMUTest, reqInsnReadTarget) {}

TEST_F(MemoryMMUTest, reqReadAligned) {}
TEST_F(MemoryMMUTest, reqReadUnAligned) {}
TEST_F(MemoryMMUTest, reqReadMultiPacketAligned) {}
TEST_F(MemoryMMUTest, reqReadMultiPacketUnAligned) {}

TEST_F(MemoryMMUTest, reqWriteAligned_Insn) {}
TEST_F(MemoryMMUTest, reqWriteUnAligned_Insn) {}
TEST_F(MemoryMMUTest, reqWriteMultiPacketAligned_Insn) {}
TEST_F(MemoryMMUTest, reqWriteMultiPacketUnAligned_Insn) {}

TEST_F(MemoryMMUTest, reqWriteAligned_Target) {}
TEST_F(MemoryMMUTest, reqWriteUnAligned_Target) {}

TEST_F(MemoryMMUTest, exclusiveReqsExceedBandwidth) {}
TEST_F(MemoryMMUTest, nonExclusiveReqsExceedBandwidth) {}

TEST_F(MemoryMMUTest, MultiInsnExclusiveReqsDontExceedBandwidth) {}
TEST_F(MemoryMMUTest, MultiInsnExclusiveReqsExceedBandwidth) {}

TEST_F(MemoryMMUTest, MultiInsnNonExclusiveReqsDontExceedBandwidth) {}
TEST_F(MemoryMMUTest, MultiInsnNonExclusiveReqsExceedBandwidth) {}

}  // namespace memory
}  // namespace simeng
