#include "../MockInstruction.hh"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Instruction.hh"
#include "simeng/pipeline/RegisterAliasTable.hh"

namespace simeng {
namespace pipeline {

class RegisterAliasTableTest : public testing::Test {
 public:
  RegisterAliasTableTest() : rat({{8, architecturalCount}}, {physicalCount}) {}

 protected:
  const uint16_t architecturalCount = 32;
  const uint16_t physicalCount = 64;

  Register reg = {0, 0};
  RegisterAliasTable rat;
};

// Tests that the RAT allocates default physical registers for architectural
// registers
TEST_F(RegisterAliasTableTest, Default) {
  EXPECT_EQ(rat.freeRegistersAvailable(0), physicalCount - architecturalCount);
}

// Tests that the RAT correctly reports that registers can be allocated when it
// has enough free registers available
TEST_F(RegisterAliasTableTest, CanAllocate) {
  auto freeRegisters = rat.freeRegistersAvailable(0);
  EXPECT_TRUE(rat.canAllocate(0, freeRegisters));
}

// Tests that the RAT reports that registers cannot be allocated when it doesn't
// have enough free registers
TEST_F(RegisterAliasTableTest, CanNotAllocate) {
  auto freeRegisters = rat.freeRegistersAvailable(0);
  EXPECT_FALSE(rat.canAllocate(0, freeRegisters + 1));
}

// Tests that a new physical register can be allocated without freeing the old
// mapping, and future mappings reflect the allocation
TEST_F(RegisterAliasTableTest, Allocate) {
  auto initialFreeRegisters = rat.freeRegistersAvailable(0);

  auto oldMapping = rat.getMapping(reg);
  auto newMapping = rat.allocate(reg);

  // Check the mapping changed
  EXPECT_NE(oldMapping, newMapping);
  // Check the mapping is reflected in future calls
  EXPECT_EQ(newMapping, rat.getMapping(reg));

  // Check that the old register isn't yet freed
  EXPECT_EQ(rat.freeRegistersAvailable(0), initialFreeRegisters - 1);
}

// Tests that a new physical register can be allocated without affecting the
// availability of registers for other register files
TEST_F(RegisterAliasTableTest, AllocateIndependent) {
  auto multiRAT =
      RegisterAliasTable({{8, architecturalCount}, {8, architecturalCount}},
                         {physicalCount, physicalCount});
  auto initialFreeRegisters1 = multiRAT.freeRegistersAvailable(1);

  multiRAT.allocate(reg);

  // Check that the same number of physical registers are still available
  EXPECT_EQ(multiRAT.freeRegistersAvailable(1), initialFreeRegisters1);
}

// Tests that a physical register can be committed, freeing the old mapping
TEST_F(RegisterAliasTableTest, Commit) {
  auto initialFreeRegisters = rat.freeRegistersAvailable(0);
  auto mapping = rat.allocate(reg);
  rat.commit(mapping);

  EXPECT_EQ(rat.freeRegistersAvailable(0), initialFreeRegisters);
}

// Tests that an allocation may be rewound, restoring the old mapping and
// freeing the allocated register
TEST_F(RegisterAliasTableTest, Rewind) {
  auto initialFreeRegisters = rat.freeRegistersAvailable(0);
  auto oldMapping = rat.getMapping(reg);
  auto newMapping = rat.allocate(reg);
  rat.rewind(newMapping);

  // Check that the old mapping is once again available
  EXPECT_EQ(rat.getMapping(reg), oldMapping);
  // Check that the new allocation was freed
  EXPECT_EQ(rat.freeRegistersAvailable(0), initialFreeRegisters);
}

}  // namespace pipeline
}  // namespace simeng
