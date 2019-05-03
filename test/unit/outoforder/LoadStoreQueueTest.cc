#include "../MockInstruction.hh"
#include "Instruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "outoforder/LoadStoreQueue.hh"

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Property;
using ::testing::Return;

namespace simeng {
namespace outoforder {

class LoadStoreQueueTest : public testing::Test {
 public:
  LoadStoreQueueTest()
      : addresses({{0, 1}}),
        data({static_cast<uint8_t>(1)}),
        memory{},
        splitQueue(maxLoads, maxStores, memory),
        combinedQueue(maxCombinedSpace, memory),
        loadUop(new MockInstruction),
        storeUop(new MockInstruction),
        loadUopPtr(loadUop),
        storeUopPtr(storeUop) {
    // Set up sensible return values for the load uop
    ON_CALL(*loadUop, isLoad()).WillByDefault(Return(true));
    ON_CALL(*loadUop, getGeneratedAddresses()).WillByDefault(Return(addresses));

    // Set up sensible return values for the store uop
    ON_CALL(*storeUop, isStore()).WillByDefault(Return(true));
    ON_CALL(*storeUop, getGeneratedAddresses())
        .WillByDefault(Return(addresses));
    ON_CALL(*storeUop, getData()).WillByDefault(Return(data));
  }

 protected:
  const uint8_t maxLoads = 32;
  const uint8_t maxStores = 32;
  const uint8_t maxCombinedSpace = 64;

  std::vector<std::pair<uint64_t, uint8_t>> addresses;
  std::vector<RegisterValue> data;

  char memory[1024];

  LoadStoreQueue splitQueue;
  LoadStoreQueue combinedQueue;

  MockInstruction* loadUop;
  MockInstruction* storeUop;

  std::shared_ptr<Instruction> loadUopPtr;
  std::shared_ptr<MockInstruction> storeUopPtr;
};

// Tests that a load can be added to a split queue, without reducing the
// available space for stores
TEST_F(LoadStoreQueueTest, SplitAddLoad) {
  splitQueue.addLoad(loadUopPtr);

  EXPECT_EQ(splitQueue.getLoadQueueSpace(), maxLoads - 1);
  EXPECT_EQ(splitQueue.getStoreQueueSpace(), maxStores);
}

// Tests that a load can be added to a combined queue, and it also reduces the
// available space for stores
TEST_F(LoadStoreQueueTest, CombinedAddLoad) {
  combinedQueue.addLoad(loadUopPtr);

  EXPECT_EQ(combinedQueue.getLoadQueueSpace(), maxCombinedSpace - 1);
  EXPECT_EQ(combinedQueue.getStoreQueueSpace(), maxCombinedSpace - 1);
  EXPECT_EQ(combinedQueue.getTotalSpace(), maxCombinedSpace - 1);
}

// Tests that a store can be added to a split queue, without reducing the
// available space for loads
TEST_F(LoadStoreQueueTest, SplitAddStore) {
  splitQueue.addStore(storeUopPtr);

  EXPECT_EQ(splitQueue.getLoadQueueSpace(), maxLoads);
  EXPECT_EQ(splitQueue.getStoreQueueSpace(), maxStores - 1);
}

// Tests that a store can be added to a combined queue, and it also reduces the
// available space for loads
TEST_F(LoadStoreQueueTest, CombinedAddStore) {
  combinedQueue.addStore(storeUopPtr);

  EXPECT_EQ(combinedQueue.getLoadQueueSpace(), maxCombinedSpace - 1);
  EXPECT_EQ(combinedQueue.getStoreQueueSpace(), maxCombinedSpace - 1);
  EXPECT_EQ(combinedQueue.getTotalSpace(), maxCombinedSpace - 1);
}

// Tests that a split queue can purge flushed load instructions
TEST_F(LoadStoreQueueTest, SplitPurgeFlushedLoad) {
  splitQueue.addLoad(loadUopPtr);

  loadUop->setFlushed();
  splitQueue.purgeFlushed();

  EXPECT_EQ(splitQueue.getLoadQueueSpace(), maxLoads);
}

// Tests that a split queue can purge flushed store instructions
TEST_F(LoadStoreQueueTest, SplitPurgeFlushedStore) {
  splitQueue.addStore(storeUopPtr);

  storeUop->setFlushed();
  splitQueue.purgeFlushed();

  EXPECT_EQ(splitQueue.getStoreQueueSpace(), maxStores);
}

// Tests that a combined queue can purge flushed load instructions
TEST_F(LoadStoreQueueTest, CombinedPurgeFlushedLoad) {
  combinedQueue.addLoad(loadUopPtr);

  loadUop->setFlushed();
  combinedQueue.purgeFlushed();

  EXPECT_EQ(combinedQueue.getLoadQueueSpace(), maxCombinedSpace);
}

// Tests that a combined queue can purge flushed store instructions
TEST_F(LoadStoreQueueTest, CombinedPurgeFlushedStore) {
  combinedQueue.addStore(storeUopPtr);

  storeUop->setFlushed();
  combinedQueue.purgeFlushed();

  EXPECT_EQ(combinedQueue.getStoreQueueSpace(), maxCombinedSpace);
}

// Tests that a split queue can perform a load
TEST_F(LoadStoreQueueTest, SplitLoad) {
  memory[0] = 1;

  EXPECT_CALL(*loadUop, getGeneratedAddresses()).Times(AtLeast(1));

  splitQueue.addLoad(loadUopPtr);

  // Check that the request reads the correct value from memory (a single byte
  // of value `memory[0]`)
  // TODO: Replace with check for call over memory interface in future?
  EXPECT_CALL(*loadUop,
              supplyData(0, Property(&RegisterValue::get<uint8_t>, memory[0])))
      .Times(1);

  splitQueue.startLoad(loadUopPtr);
}

// Tests that a combined queue can perform a load
TEST_F(LoadStoreQueueTest, CombinedLoad) {
  memory[0] = 1;

  EXPECT_CALL(*loadUop, getGeneratedAddresses()).Times(AtLeast(1));

  combinedQueue.addLoad(loadUopPtr);

  // Check that the request reads the correct value from memory (a single byte
  // of value `memory[0]`)
  // TODO: Replace with check for call over memory interface in future?
  EXPECT_CALL(*loadUop,
              supplyData(0, Property(&RegisterValue::get<uint8_t>, memory[0])))
      .Times(1);

  combinedQueue.startLoad(loadUopPtr);
}

// Tests that a split queue can perform a store
TEST_F(LoadStoreQueueTest, SplitStore) {
  EXPECT_CALL(*storeUop, getGeneratedAddresses()).Times(AtLeast(1));
  EXPECT_CALL(*storeUop, getData()).Times(AtLeast(1));

  combinedQueue.addStore(storeUopPtr);
  storeUopPtr->setCommitReady();
  combinedQueue.commitStore(storeUopPtr);

  // TODO: Replace with check for call over memory interface in future?
  EXPECT_EQ(memory[0], 1);
  // Check the store was removed
  EXPECT_EQ(splitQueue.getStoreQueueSpace(), maxStores);
}

}  // namespace outoforder
}  // namespace simeng
