#include "TestFriends.hh"
#include "gtest/gtest.h"
#include "simeng/kernel/PageTable.hh"

using namespace simeng::kernel;
using namespace TestFriends;

namespace {

TEST(PageTableTest, CreateMappingSmallerThanPageSize) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  pTable->createMapping(0, 0, 250);
  std::shared_ptr<std::map<uint64_t, simeng::kernel::PTEntry*>> table =
      pTbfrnd->getTable();
  auto itr = table->find(0);

  ASSERT_EQ(table->size(), 1);
  ASSERT_NE(itr, table->end());
  ASSERT_EQ(itr->second->endVAddr, 4096);
}

TEST(PageTableTest, CreateMappingEqualToPageSize) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  pTable->createMapping(0, 0, 4096);
  std::shared_ptr<std::map<uint64_t, simeng::kernel::PTEntry*>> table =
      pTbfrnd->getTable();
  auto itr = table->find(0);

  ASSERT_EQ(table->size(), 1);
  ASSERT_NE(itr, table->end());
  ASSERT_EQ(itr->second->endVAddr, 4096);
}

TEST(PageTableTest, CreateMappingGreaterThanPageSize) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  pTable->createMapping(0, 0, 4096 * 3);
  std::shared_ptr<std::map<uint64_t, simeng::kernel::PTEntry*>> table =
      pTbfrnd->getTable();

  ASSERT_EQ(table->size(), 3);

  auto itr = table->find(0);
  ASSERT_NE(itr, table->end());
  ASSERT_EQ(itr->second->baseVAddr, 0);
  ASSERT_EQ(itr->second->basePhyAddr, 0);
  ASSERT_EQ(itr->second->endVAddr, 4096);

  itr = table->find(4096);
  ASSERT_NE(itr, table->end());
  ASSERT_EQ(itr->second->baseVAddr, 4096);
  ASSERT_EQ(itr->second->basePhyAddr, 4096);
  ASSERT_EQ(itr->second->endVAddr, 4096 * 2);

  itr = table->find(4096 * 2);
  ASSERT_NE(itr, table->end());
  ASSERT_EQ(itr->second->baseVAddr, 4096 * 2);
  ASSERT_EQ(itr->second->basePhyAddr, 4096 * 2);
  ASSERT_EQ(itr->second->endVAddr, 4096 * 3);
}

}  // namespace
