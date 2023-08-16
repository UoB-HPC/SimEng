#include "../MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/memory/SimpleMem.hh"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Field;
using ::testing::Property;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SetArgReferee;

namespace simeng {
namespace memory {

class MMUTest : public testing::Test {
 public:
  MMUTest()
      : memory(std::make_shared<memory::SimpleMem>(8192)),
        connection(),
        uop(new MockInstruction),
        uop2(new MockInstruction),
        uop3(new MockInstruction),
        uop4(new MockInstruction),
        uopPtr(uop),
        uopPtr2(uop2),
        uopPtr3(uop3),
        uopPtr4(uop4) {
    uopPtr->setInstructionAddress(0);
    uopPtr->setSequenceId(0);
    uopPtr->setInstructionId(0);
    uopPtr2->setInstructionAddress(0x4);
    uopPtr2->setSequenceId(1);
    uopPtr2->setInstructionId(1);
    uopPtr3->setInstructionAddress(0x8);
    uopPtr3->setSequenceId(2);
    uopPtr3->setInstructionId(2);
    uopPtr4->setInstructionAddress(0xC);
    uopPtr4->setSequenceId(3);
    uopPtr4->setInstructionId(3);

    // Setup port in memory
    port2 = memory->initMemPort();

    // Populate memory with data to read
    memory->sendUntimedData(
        {0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,
         0xb,  0xc,  0xd,  0xe,  0xf,  0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
         0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
        0x1000, 32);
    memory->sendUntimedData({0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}, 0xfd, 8);
    memory->sendUntimedData({0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}, 0x1fd, 8);
    memory->sendUntimedData({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
                            0x2fd, 8);
  }

 protected:
  VAddrTranslator fn = [](uint64_t vaddr, uint64_t pid) -> uint64_t {
    return vaddr;
  };

  // Set the default config with a parameterised Exclusive config option
  void setConfig(bool isExclusive = true) {
    std::string configStr =
        "{Core: {Simulation-Mode: outoforder}, Memory-Hierarchy: "
        "{Cache-Line-Width: 256}, LSQ-Memory-Interface: {Exclusive: " +
        (isExclusive ? std::string("True") : std::string("False")) +
        ", Load-Bandwidth: 24, Store-Bandwidth: 24, "
        "Permitted-Requests-Per-Cycle: 5, Permitted-Loads-Per-Cycle: 5, "
        "Permitted-Stores-Per-Cycle: 5}}";
    config::SimInfo::addToConfig(configStr);

    mmu = std::make_shared<memory::MMU>(fn);

    // Set up MMU->Memory connection
    port1 = mmu->initPort();
    connection.connect(port1, port2);
  }

  // Zero out a region of memory
  void resetMemory(uint64_t addr, uint64_t numBytes) {
    memory->sendUntimedData(std::vector<char>(numBytes, '\0'), addr, numBytes);
  }

  std::shared_ptr<memory::SimpleMem> memory;
  std::shared_ptr<memory::MMU> mmu;

  PortMediator<std::unique_ptr<memory::MemPacket>> connection;
  std::shared_ptr<Port<std::unique_ptr<memory::MemPacket>>> port1;
  std::shared_ptr<Port<std::unique_ptr<memory::MemPacket>>> port2;

  MockInstruction* uop;
  MockInstruction* uop2;
  MockInstruction* uop3;
  MockInstruction* uop4;
  std::shared_ptr<Instruction> uopPtr;
  std::shared_ptr<Instruction> uopPtr2;
  std::shared_ptr<Instruction> uopPtr3;
  std::shared_ptr<Instruction> uopPtr4;
};

// A test to ensure instructions can be successfully read from memory
TEST_F(MMUTest, reqInsnReadTarget) {
  setConfig();
  memory::MemoryAccessTarget target = {0x1000, 8};
  mmu->requestInstrRead(target);
  span<memory::MemoryReadResult> insnReads = mmu->getCompletedInstrReads();

  EXPECT_EQ(insnReads.size(), 1);
  EXPECT_EQ(insnReads[0].data.get<uint64_t>(), 0x0706050403020100);
}

// A test to ensure an aligned data read is carried out successfully
TEST_F(MMUTest, reqReadAligned) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> target = {{0x1000, 8}};
  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100))};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));

  EXPECT_CALL(*uop, supplyData(0x1000, Property(&RegisterValue::get<uint64_t>,
                                                data[0].get<uint64_t>())))
      .Times(1);

  mmu->requestRead(uopPtr);
  mmu->tick();
}
// A test to ensure an aligned data read is carried out successfully
TEST_F(MMUTest, reqReadUnAligned) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> target = {{0xfd, 8}};
  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100))};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));

  EXPECT_CALL(*uop, supplyData(0xfd, Property(&RegisterValue::get<uint64_t>,
                                              data[0].get<uint64_t>())))
      .Times(1);

  mmu->requestRead(uopPtr);
  mmu->tick();
}
// A test to ensure multiple aligned data reads are carried out successfully
TEST_F(MMUTest, reqReadMultiPacketAligned) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> target = {
      {0x1000, 8}, {0x1008, 8}, {0x1010, 8}};
  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100)),
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908)),
      RegisterValue(static_cast<uint64_t>(0x1716151413121110))};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));

  EXPECT_CALL(*uop, supplyData(0x1000, Property(&RegisterValue::get<uint64_t>,
                                                data[0].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1008, Property(&RegisterValue::get<uint64_t>,
                                                data[1].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1010, Property(&RegisterValue::get<uint64_t>,
                                                data[2].get<uint64_t>())))
      .Times(1);

  mmu->requestRead(uopPtr);
  mmu->tick();
}
// A test to ensure multiple unaligned data reads are carried out successfully
TEST_F(MMUTest, reqReadMultiPacketUnAligned) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> target = {
      {0xfd, 8}, {0x1fd, 8}, {0x2fd, 8}};
  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100)),
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908)),
      RegisterValue(static_cast<uint64_t>(0x1716151413121110))};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));

  EXPECT_CALL(*uop, supplyData(0xfd, Property(&RegisterValue::get<uint64_t>,
                                              data[0].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1fd, Property(&RegisterValue::get<uint64_t>,
                                               data[1].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x2fd, Property(&RegisterValue::get<uint64_t>,
                                               data[2].get<uint64_t>())))
      .Times(1);

  mmu->requestRead(uopPtr);
  mmu->tick();
}

// A test to ensure aligned an data write from an instruction is carried out
// successfully
TEST_F(MMUTest, reqWriteAligned_Insn) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> target = {{0x600, 8}};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));

  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100))};

  mmu->requestWrite(uopPtr, data);
  mmu->tick();

  EXPECT_EQ(memory->getUntimedData(0x600, 8),
            std::vector<char>({0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}));
  // Cleanup memory
  resetMemory(0x600, 8);
}
// A test to ensure an unaligned data write from an instruction is carried out
// successfully
TEST_F(MMUTest, reqWriteUnAligned_Insn) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> target = {{0x4fd, 8}};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));

  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100))};

  mmu->requestWrite(uopPtr, data);
  mmu->tick();

  EXPECT_EQ(memory->getUntimedData(0x4fd, 8),
            std::vector<char>({0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}));
  // Cleanup memory
  resetMemory(0x4fd, 8);
}
// A test to ensure multiple aligned data writes from an instruction are carried
// out successfully
TEST_F(MMUTest, reqWriteMultiPacketAligned_Insn) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> target = {
      {0x600, 8}, {0x608, 8}, {0x610, 8}};
  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100)),
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908)),
      RegisterValue(static_cast<uint64_t>(0x1716151413121110))};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));

  mmu->requestWrite(uopPtr, data);
  mmu->tick();

  EXPECT_EQ(
      memory->getUntimedData(0x600, 24),
      std::vector<char>({0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                         0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}));
  // Cleanup memory
  resetMemory(0x600, 24);
}
// A test to ensure multiple unaligned data writes from an instruction are
// carried out successfully
TEST_F(MMUTest, reqWriteMultiPacketUnAligned_Insn) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> target = {
      {0x4fd, 8}, {0x5fd, 8}, {0x6fd, 8}};
  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100)),
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908)),
      RegisterValue(static_cast<uint64_t>(0x1716151413121110))};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(target));

  mmu->requestWrite(uopPtr, data);
  mmu->tick();

  EXPECT_EQ(memory->getUntimedData(0x4fd, 8),
            std::vector<char>({0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}));
  EXPECT_EQ(memory->getUntimedData(0x5fd, 8),
            std::vector<char>({0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}));
  EXPECT_EQ(
      memory->getUntimedData(0x6fd, 8),
      std::vector<char>({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}));
  // Cleanup memory
  resetMemory(0x4fd, 8);
  resetMemory(0x5fd, 8);
  resetMemory(0x6fd, 8);
}

// A test to ensure an aligned data writes from a single MemoryAccessTarget is
// carried out successfully
TEST_F(MMUTest, reqWriteAligned_Target) {
  setConfig();
  memory::MemoryAccessTarget target = {0x600, 8};

  RegisterValue data = RegisterValue(static_cast<uint64_t>(0x1716151413121110));
  mmu->requestWrite(target, data);

  EXPECT_EQ(
      memory->getUntimedData(0x600, 8),
      std::vector<char>({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}));
  // Cleanup memory
  resetMemory(0x600, 8);
}
// A test to ensure an unaligned data writes from a single MemoryAccessTarget is
// carried out successfully
TEST_F(MMUTest, reqWriteUnAligned_Target) {
  setConfig();
  memory::MemoryAccessTarget target = {0x4fd, 8};

  RegisterValue data = RegisterValue(static_cast<uint64_t>(0x1716151413121110));

  mmu->requestWrite(target, data);
  mmu->tick();

  EXPECT_EQ(
      memory->getUntimedData(0x4fd, 8),
      std::vector<char>({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}));
  // Cleanup memory
  resetMemory(0x4fd, 8);
}

// A test to ensure an exclusive MMU will delay process of memory accesses due
// to bandwith constraints
TEST_F(MMUTest, exclusiveReqsExceedBandwidth) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> readTarget = {
      {0x1000, 8}, {0x1008, 8}, {0x1010, 8}, {0x1018, 8}};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(readTarget));

  std::vector<memory::MemoryAccessTarget> writeTarget = {
      {0x600, 8}, {0x608, 8}, {0x610, 8}, {0x618, 8}};
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(writeTarget));
  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100)),
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908)),
      RegisterValue(static_cast<uint64_t>(0x1716151413121110)),
      RegisterValue(static_cast<uint64_t>(0x1f1e1d1c1b1a1918))};

  // Due to the exclusivity of the MMU, only a single access type should be able
  // to be requested at a time
  EXPECT_EQ(mmu->requestRead(uopPtr), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr2, data), false);
  // It will take two ticks for all the load packets to be sent off to memory
  // and return
  mmu->tick();
  EXPECT_CALL(*uop, supplyData(0x1000, Property(&RegisterValue::get<uint64_t>,
                                                data[0].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1008, Property(&RegisterValue::get<uint64_t>,
                                                data[1].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1010, Property(&RegisterValue::get<uint64_t>,
                                                data[2].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1018, Property(&RegisterValue::get<uint64_t>,
                                                data[3].get<uint64_t>())))
      .Times(1);
  mmu->tick();

  EXPECT_EQ(mmu->requestWrite(uopPtr2, data), true);
  // It will take two ticks for the store to fully write its data. All the data
  // from store uop and half the data from store uop2 will be processed in the
  // first cycle. The remaining data in store uop2 will be processed in the
  // second cycle
  mmu->tick();
  EXPECT_EQ(memory->getUntimedData(0x600, 32),
            std::vector<char>({0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                               0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                               0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0}));
  mmu->tick();
  EXPECT_EQ(
      memory->getUntimedData(0x600, 32),
      std::vector<char>({0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                         0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}));
  // Cleanup memory
  resetMemory(0x600, 32);
}
// A test to ensure a non-exclusive MMU will delay process of memory accesses
// due to bandwith constraints
TEST_F(MMUTest, nonExclusiveReqsExceedBandwidth) {
  setConfig(false);
  std::vector<memory::MemoryAccessTarget> readTarget = {
      {0x1000, 8}, {0x1008, 8}, {0x1010, 8}, {0x1018, 8}};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(readTarget));

  std::vector<memory::MemoryAccessTarget> writeTarget = {
      {0x600, 8}, {0x608, 8}, {0x610, 8}, {0x618, 8}};
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(writeTarget));
  std::vector<RegisterValue> data = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100)),
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908)),
      RegisterValue(static_cast<uint64_t>(0x1716151413121110)),
      RegisterValue(static_cast<uint64_t>(0x1f1e1d1c1b1a1918))};

  // Due to the non-exclusivity of the MMU, both access types should be able
  // to be requested at a time
  EXPECT_EQ(mmu->requestRead(uopPtr), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr2, data), true);
  // It will take two ticks for all the load packets to be sent off to memory
  // and return.
  // It will also take two ticks for the store to fully write its data. All the
  // data from store uop and half the data from store uop2 will be processed in
  // the first cycle. The remaining data in store uop2 will be processed in the
  // second cycle
  mmu->tick();
  EXPECT_CALL(*uop, supplyData(0x1000, Property(&RegisterValue::get<uint64_t>,
                                                data[0].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1008, Property(&RegisterValue::get<uint64_t>,
                                                data[1].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1010, Property(&RegisterValue::get<uint64_t>,
                                                data[2].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1018, Property(&RegisterValue::get<uint64_t>,
                                                data[3].get<uint64_t>())))
      .Times(1);
  EXPECT_EQ(memory->getUntimedData(0x600, 32),
            std::vector<char>({0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                               0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                               0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0}));
  mmu->tick();
  EXPECT_EQ(
      memory->getUntimedData(0x600, 32),
      std::vector<char>({0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                         0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}));
  // Cleanup memory
  resetMemory(0x600, 32);
}

// A test to ensure an exclusive MMU will not delay the processing of memory
// accesses from multiple instructions as the bandwidth restriction is not
// exceeded
TEST_F(MMUTest, MultiInsnExclusiveReqsDontExceedBandwidth) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> readTargetA = {{0x1000, 8}};
  std::vector<memory::MemoryAccessTarget> readTargetB = {{0x1008, 8}};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(readTargetA));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(readTargetB));

  std::vector<memory::MemoryAccessTarget> writeTargetA = {{0x600, 8}};
  std::vector<memory::MemoryAccessTarget> writeTargetB = {{0x608, 8}};
  ON_CALL(*uop3, getGeneratedAddresses())
      .WillByDefault(ReturnRef(writeTargetA));
  ON_CALL(*uop4, getGeneratedAddresses())
      .WillByDefault(ReturnRef(writeTargetB));
  std::vector<RegisterValue> dataA = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100))};
  std::vector<RegisterValue> dataB = {
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908))};

  // Due to the exclusivity of the MMU, only a single access type should be able
  // to be requested at a time
  EXPECT_EQ(mmu->requestRead(uopPtr), true);
  EXPECT_EQ(mmu->requestRead(uopPtr2), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr3, dataA), false);
  EXPECT_EQ(mmu->requestWrite(uopPtr4, dataB), false);

  // It will take one tick for all the load packets, from both uops, to be sent
  // off to memory and return
  EXPECT_CALL(*uop, supplyData(0x1000, Property(&RegisterValue::get<uint64_t>,
                                                dataA[0].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop2, supplyData(0x1008, Property(&RegisterValue::get<uint64_t>,
                                                 dataB[0].get<uint64_t>())))
      .Times(1);
  mmu->tick();

  // It will take one tick for the store uops to fully write their data
  EXPECT_EQ(mmu->requestWrite(uopPtr3, dataA), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr4, dataB), true);
  mmu->tick();
  EXPECT_EQ(memory->getUntimedData(0x600, 16),
            std::vector<char>({0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
                               0xa, 0xb, 0xc, 0xd, 0xe, 0xf}));
  // Cleanup memory
  resetMemory(0x600, 16);
}
// A test to ensure an exclusive MMU will delay the processing of memory
// accesses from multiple instructions as the bandwidth restriction is exceeded
TEST_F(MMUTest, MultiInsnExclusiveReqsExceedBandwidth) {
  setConfig();
  std::vector<memory::MemoryAccessTarget> readTargetA = {{0x1000, 8},
                                                         {0x1008, 8}};
  std::vector<memory::MemoryAccessTarget> readTargetB = {{0x1010, 8},
                                                         {0x1018, 8}};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(readTargetA));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(readTargetB));

  std::vector<memory::MemoryAccessTarget> writeTargetA = {{0x600, 8},
                                                          {0x608, 8}};
  std::vector<memory::MemoryAccessTarget> writeTargetB = {{0x610, 8},
                                                          {0x618, 8}};
  ON_CALL(*uop3, getGeneratedAddresses())
      .WillByDefault(ReturnRef(writeTargetA));
  ON_CALL(*uop4, getGeneratedAddresses())
      .WillByDefault(ReturnRef(writeTargetB));
  std::vector<RegisterValue> dataA = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100)),
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908))};
  std::vector<RegisterValue> dataB = {
      RegisterValue(static_cast<uint64_t>(0x1716151413121110)),
      RegisterValue(static_cast<uint64_t>(0x1f1e1d1c1b1a1918))};

  // Due to the exclusivity of the MMU, only a single access type should be able
  // to be requested at a time
  EXPECT_EQ(mmu->requestRead(uopPtr), true);
  EXPECT_EQ(mmu->requestRead(uopPtr2), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr3, dataA), false);
  EXPECT_EQ(mmu->requestWrite(uopPtr4, dataB), false);
  // It will take one tick for all the load packets of uop to be sent off to
  // memory and return. The first packet of uop2 will also be processed this
  // cycle but uop2 must wait for its 2nd packet to get processed next cycle
  // before completing
  EXPECT_CALL(*uop, supplyData(0x1000, Property(&RegisterValue::get<uint64_t>,
                                                dataA[0].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1008, Property(&RegisterValue::get<uint64_t>,
                                                dataA[1].get<uint64_t>())))
      .Times(1);
  mmu->tick();

  // Due to uop2 (load) still being active, the store uops shouldn't be
  // able to be registered again
  EXPECT_EQ(mmu->requestWrite(uopPtr3, dataA), false);
  EXPECT_EQ(mmu->requestWrite(uopPtr4, dataB), false);
  // Process the 2nd load packet of uop2 and supply all the read data
  EXPECT_CALL(*uop2, supplyData(0x1010, Property(&RegisterValue::get<uint64_t>,
                                                 dataB[0].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop2, supplyData(0x1018, Property(&RegisterValue::get<uint64_t>,
                                                 dataB[1].get<uint64_t>())))
      .Times(1);
  mmu->tick();

  EXPECT_EQ(mmu->requestWrite(uopPtr3, dataA), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr4, dataB), true);
  // It will take two ticks for the store to fully write its data. All the data
  // from store uop and half the data from store uop2 will be processed in the
  // first cycle. The remaining data in store uop2 will be processed in the
  // second cycle
  mmu->tick();
  EXPECT_EQ(memory->getUntimedData(0x600, 32),
            std::vector<char>({0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                               0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                               0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0}));
  mmu->tick();
  EXPECT_EQ(
      memory->getUntimedData(0x600, 32),
      std::vector<char>({0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                         0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}));
  // Cleanup memory
  resetMemory(0x600, 32);
}

// A test to ensure a non-exclusive MMU will not delay the processing of memory
// accesses from multiple instructions as the bandwidth restriction is not
// exceeded
TEST_F(MMUTest, MultiInsnNonExclusiveReqsDontExceedBandwidth) {
  setConfig(false);
  std::vector<memory::MemoryAccessTarget> readTargetA = {{0x1000, 8}};
  std::vector<memory::MemoryAccessTarget> readTargetB = {{0x1008, 8}};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(readTargetA));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(readTargetB));

  std::vector<memory::MemoryAccessTarget> writeTargetA = {{0x600, 8}};
  std::vector<memory::MemoryAccessTarget> writeTargetB = {{0x608, 8}};
  ON_CALL(*uop3, getGeneratedAddresses())
      .WillByDefault(ReturnRef(writeTargetA));
  ON_CALL(*uop4, getGeneratedAddresses())
      .WillByDefault(ReturnRef(writeTargetB));
  std::vector<RegisterValue> dataA = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100))};
  std::vector<RegisterValue> dataB = {
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908))};

  // Due to the non-exclusivity of the MMU, both access types should be able
  // to be requested at a time
  EXPECT_EQ(mmu->requestRead(uopPtr), true);
  EXPECT_EQ(mmu->requestRead(uopPtr2), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr3, dataA), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr4, dataB), true);

  // It will take one tick for all the load packets, from both uops, to be sent
  // off to memory and return. All the data to be stored by uops 3/4 will also
  // be processed
  EXPECT_CALL(*uop, supplyData(0x1000, Property(&RegisterValue::get<uint64_t>,
                                                dataA[0].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop2, supplyData(0x1008, Property(&RegisterValue::get<uint64_t>,
                                                 dataB[0].get<uint64_t>())))
      .Times(1);
  mmu->tick();
  EXPECT_EQ(memory->getUntimedData(0x600, 16),
            std::vector<char>({0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9,
                               0xa, 0xb, 0xc, 0xd, 0xe, 0xf}));
  // Cleanup memory
  resetMemory(0x600, 16);
}
// A test to ensure a non-exclusive MMU will delay the processing of memory
// accesses from multiple instructions as the bandwidth restriction is exceeded
TEST_F(MMUTest, MultiInsnNonExclusiveReqsExceedBandwidth) {
  setConfig(false);
  std::vector<memory::MemoryAccessTarget> readTargetA = {{0x1000, 8},
                                                         {0x1008, 8}};
  std::vector<memory::MemoryAccessTarget> readTargetB = {{0x1010, 8},
                                                         {0x1018, 8}};
  ON_CALL(*uop, getGeneratedAddresses()).WillByDefault(ReturnRef(readTargetA));
  ON_CALL(*uop2, getGeneratedAddresses()).WillByDefault(ReturnRef(readTargetB));

  std::vector<memory::MemoryAccessTarget> writeTargetA = {{0x600, 8},
                                                          {0x608, 8}};
  std::vector<memory::MemoryAccessTarget> writeTargetB = {{0x610, 8},
                                                          {0x618, 8}};
  ON_CALL(*uop3, getGeneratedAddresses())
      .WillByDefault(ReturnRef(writeTargetA));
  ON_CALL(*uop4, getGeneratedAddresses())
      .WillByDefault(ReturnRef(writeTargetB));
  std::vector<RegisterValue> dataA = {
      RegisterValue(static_cast<uint64_t>(0x0706050403020100)),
      RegisterValue(static_cast<uint64_t>(0x0f0e0d0c0b0a0908))};
  std::vector<RegisterValue> dataB = {
      RegisterValue(static_cast<uint64_t>(0x1716151413121110)),
      RegisterValue(static_cast<uint64_t>(0x1f1e1d1c1b1a1918))};

  // Due to the non-exclusivity of the MMU, both access types should be able
  // to be requested at a time
  EXPECT_EQ(mmu->requestRead(uopPtr), true);
  EXPECT_EQ(mmu->requestRead(uopPtr2), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr3, dataA), true);
  EXPECT_EQ(mmu->requestWrite(uopPtr4, dataB), true);

  // It will take one tick for all the load packets of uop to be sent off to
  // memory and return. The first packet of uop2 will also be processed this
  // cycle but uop2 must wait for its 2nd packet to get processed next cycle
  // before completing.
  // The data packets from store uop3 will be written and so will half the
  // packets from store uop 4
  EXPECT_CALL(*uop, supplyData(0x1000, Property(&RegisterValue::get<uint64_t>,
                                                dataA[0].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop, supplyData(0x1008, Property(&RegisterValue::get<uint64_t>,
                                                dataA[1].get<uint64_t>())))
      .Times(1);
  EXPECT_CALL(*uop2, supplyData(0x1010, Property(&RegisterValue::get<uint64_t>,
                                                 dataB[0].get<uint64_t>())))
      .Times(1);
  mmu->tick();
  EXPECT_EQ(memory->getUntimedData(0x600, 32),
            std::vector<char>({0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                               0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                               0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0,  0x0}));

  // Process the 2nd load packet of uop2 and supply all the read data as well as
  // write the remainder of the store uops data. Also process the last packet in
  // store uop 4
  EXPECT_CALL(*uop2, supplyData(0x1018, Property(&RegisterValue::get<uint64_t>,
                                                 dataB[1].get<uint64_t>())))
      .Times(1);
  mmu->tick();
  EXPECT_EQ(
      memory->getUntimedData(0x600, 32),
      std::vector<char>({0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
                         0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                         0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}));
  // Cleanup memory
  resetMemory(0x600, 32);
}

}  // namespace memory
}  // namespace simeng
