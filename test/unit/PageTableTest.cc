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

TEST(PageTableTest, TranslateVaddr) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  pTable->createMapping(0, 4096, 4096);
  std::shared_ptr<std::map<uint64_t, simeng::kernel::PTEntry*>> table =
      pTbfrnd->getTable();

  ASSERT_EQ(table->size(), 1);
  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(10);
  ASSERT_EQ(pAddrWOffset, 4096 + 10);

  // End address are not inclusive in a range equal to pageSize number bytes
  // because we index from 0. This means 4096 is the start of a new page in the
  // page table. Hence the mapping should fail with a value of ~0.
  pAddrWOffset = pTable->translate(4096);
  ASSERT_EQ(pAddrWOffset, ~(uint64_t)0);
}

TEST(PageTableTest, TranslateOnRangeLargerThanPage) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // Map vaddr range [0, 12,288) -> paddr [4096, 16,384)
  pTable->createMapping(0, 4096, 4096 * 3);
  std::shared_ptr<std::map<uint64_t, simeng::kernel::PTEntry*>> table =
      pTbfrnd->getTable();

  ASSERT_EQ(table->size(), 3);
  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(10);
  ASSERT_EQ(pAddrWOffset, 4096 + 10);

  pAddrWOffset = pTable->translate(5183);
  // 5183 would lie in a range greater than first page in the ptable i.e [0,
  // 4096) It must lie in the second range i.e [4096, 8192) if vaddr 0 is mapped
  // to 4096, and we defined a continous range of 3 pages. Then 5183 should live
  // in the second page starting at address 8192. Mask to get the lower 12 bits.
  ASSERT_EQ(pAddrWOffset, 8192 + (5183 & 0xFFF));
}

TEST(PageTableTest, TranslateVaddrWithSameOffset) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // Map range vaddr [0, 4096) -> paddr [4096, 8192)
  pTable->createMapping(0, 4096, 4096);

  // Map range vaddr [4096, 12,288) -> paddr [8192, 16384)
  pTable->createMapping(4096, 4096 * 2, 4096 * 2);
  std::shared_ptr<std::map<uint64_t, simeng::kernel::PTEntry*>> table =
      pTbfrnd->getTable();

  ASSERT_EQ(table->size(), 3);
  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(4097);
  ASSERT_EQ(pAddrWOffset, 8193);

  uint16_t mask = 0xFFF;
  uint64_t vaddr1 = 3152;
  uint64_t vaddr2 = 7248;

  ASSERT_EQ(vaddr1 & mask, vaddr2 & mask);

  pAddrWOffset = pTable->translate(vaddr1);
  ASSERT_EQ(pAddrWOffset, 7248);

  pAddrWOffset = pTable->translate(vaddr2);
  ASSERT_EQ(pAddrWOffset, 11344);
}

TEST(PageTableTest, DeleteMapping) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // Map vaddr range [0, 12,288) -> paddr [4096, 16,384)
  pTable->createMapping(0, 4096, 4096);
  std::shared_ptr<std::map<uint64_t, simeng::kernel::PTEntry*>> table =
      pTbfrnd->getTable();

  ASSERT_EQ(table->size(), 1);
  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(10);
  ASSERT_EQ(pAddrWOffset, 4096 + 10);

  pTable->deleteMapping(0, 4096);

  ASSERT_EQ(table->size(), 0);

  pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, ~(uint64_t)0);
}

/*
 * Todo:
 * 1) Write more tests for deleting Mappings.
 * 2) Write tests for creating mappings smaller or greater than pageSize but not
 * size aligned. 3) Write tests for deleting mapping smaller or greater than
 * pageSize but not page aligned. 4) Write tests for deleting mappings of size
 * greater than the original mapping.
 */

}  // namespace
