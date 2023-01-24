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
  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();
  auto itr = table.find(0);

  ASSERT_EQ(table.size(), 1);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 0);
}

TEST(PageTableTest, CreateMappingEqualToPageSize) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);
  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();

  pTable->createMapping(0, 0, 4096);
  table = pTbfrnd->getTable();

  auto itr = table.find(0);
  ASSERT_EQ(table.size(), 1);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 0);
}

TEST(PageTableTest, CreateMappingGreaterThanPageSize) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  pTable->createMapping(0, 0, 4096 * 3);
  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();

  ASSERT_EQ(table.size(), 3);

  auto itr = table.find(0);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 0);

  itr = table.find(4096);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 4096);

  itr = table.find(4096 * 2);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 4096 * 2);
}

TEST(PageTableTest, CreateMappingOverExistingMapping) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // map [0, 12288) -> [0, 12288)
  pTable->createMapping(0, 0, 4096 * 3);
  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();

  ASSERT_EQ(table.size(), 3);

  auto itr = table.find(0);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 0);

  itr = table.find(4096);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 4096);

  itr = table.find(4096 * 2);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 4096 * 2);

  // try to now map [4096, 8192) -> [8192, 12288)
  uint64_t retVal = pTable->createMapping(4096, 8192, 4096);
  ASSERT_EQ(retVal,
            masks::faults::pagetable::fault | masks::faults::pagetable::map);
}

TEST(PageTableTest, TranslateVaddr) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  pTable->createMapping(0, 4096, 4096);
  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();

  ASSERT_EQ(table.size(), 1);
  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(10);
  ASSERT_EQ(pAddrWOffset, 4096 + 10);

  // End address are not inclusive in a range equal to pageSize number bytes
  // because we index from 0. This means 4096 is the start of a new page in the
  // page table. Hence the mapping should fail with a value of ~0.
  pAddrWOffset = pTable->translate(4096);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::fault |
                              masks::faults::pagetable::translate);
}

TEST(PageTableTest, TranslateOnRangeLargerThanPage) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // Map vaddr range [0, 12,288) -> paddr [4096, 16,384)
  pTable->createMapping(0, 4096, 4096 * 3);

  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 3);
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
  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();

  ASSERT_EQ(table.size(), 3);
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

  pTable->createMapping(0, 4096, 4096);

  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 1);

  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(10);
  ASSERT_EQ(pAddrWOffset, 4096 + 10);

  uint64_t retVal = pTable->deleteMapping(0, 4096);
  ASSERT_EQ(retVal, 0);

  table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 0);

  pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::fault |
                              masks::faults::pagetable::translate);
}

TEST(PageTableTest, DeleteMappingGreaterThanExistingMapping) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // Map vaddr range [0, 12,288) -> paddr [4096, 16,384)
  pTable->createMapping(0, 4096, 4096 * 3);

  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 3);

  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(45);
  ASSERT_EQ(pAddrWOffset, 4096 + 45);

  // Try to delete a mapping greater than size of mapping.
  uint64_t retVal = pTable->deleteMapping(0, 4096 * 4);
  ASSERT_EQ(retVal,
            masks::faults::pagetable::fault | masks::faults::pagetable::unmap);

  table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 3);
}

TEST(PageTableTest, DeleteMappingAtUnalignedAddr) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // Map vaddr range [0, 4096) -> paddr [4096, 8192)
  pTable->createMapping(0, 4096, 4096);

  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 1);

  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(45);
  ASSERT_EQ(pAddrWOffset, 4096 + 45);

  // This will delete the page assosciate in which the addr resides.
  uint64_t retVal = pTable->deleteMapping(1024, 4096);
  ASSERT_EQ(retVal, 0);

  pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::fault |
                              masks::faults::pagetable::translate);

  table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 0);
}

TEST(PageTableTest, DeleteMappingAtUnalignedSizes) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // Map vaddr range [0, 8192) -> paddr [4096, 12288)
  pTable->createMapping(0, 4096, 4096 * 2);

  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 2);

  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  // This should delete the first mapping i.e [0, 12288) -> [4096, 8192)
  uint64_t retVal = pTable->deleteMapping(1024, 3456);
  ASSERT_EQ(retVal, 0);

  pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::fault |
                              masks::faults::pagetable::translate);

  table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 1);
}

TEST(PageTableTest, DeleteMappingInBetweenTwoPages) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // Map vaddr range [0, 12288) -> paddr [4096, 16384)
  pTable->createMapping(0, 4096, 4096 * 3);

  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 3);

  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(4098);
  ASSERT_EQ(pAddrWOffset, 8192 + (0xFFF & 4098));

  pAddrWOffset = pTable->translate(8199);
  ASSERT_EQ(pAddrWOffset, 12288 + (0xFFF & 8199));

  // This should delete the first mapping i.e [0, 4096) -> [4096, 8192)
  uint64_t retVal = pTable->deleteMapping(4096, 4096);
  ASSERT_EQ(retVal, 0);

  pAddrWOffset = pTable->translate(4098);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::fault |
                              masks::faults::pagetable::translate);

  table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 2);
}

TEST(PageTableTest, DeleteNonExistentMapping) {
  PageTable* pTable = new PageTable();
  PTFriend* pTbfrnd = new PTFriend(pTable);

  // Map vaddr range [0, 12288) -> paddr [4096, 16384)
  pTable->createMapping(0, 4096, 4096);

  std::map<uint64_t, uint64_t> table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 1);

  uint64_t pAddrWOffset = pTable->translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable->translate(4098);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::fault |
                              masks::faults::pagetable::translate);

  // This should delete the first mapping i.e [0, 4096) -> [4096, 8192)
  uint64_t retVal = pTable->deleteMapping(4096, 4096);
  ASSERT_EQ(retVal,
            masks::faults::pagetable::fault | masks::faults::pagetable::unmap);

  table = pTbfrnd->getTable();
  ASSERT_EQ(table.size(), 1);
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
