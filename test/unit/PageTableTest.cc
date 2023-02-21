#include "gtest/gtest.h"
#include "simeng/OS/PageTable.hh"

using namespace simeng::OS;

namespace {

TEST(PageTableTest, CreateMappingSmallerThanPageSize) {
  PageTable pTable = PageTable();

  pTable.createMapping(0, 0, 250);
  std::map<uint64_t, uint64_t> table = pTable.getTable();
  auto itr = table.find(0);

  ASSERT_EQ(table.size(), 1);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 0);
}

TEST(PageTableTest, CreateMappingEqualToPageSize) {
  PageTable pTable = PageTable();
  std::map<uint64_t, uint64_t> table;

  pTable.createMapping(0, 0, 4096);
  table = pTable.getTable();

  auto itr = table.find(0);
  ASSERT_EQ(table.size(), 1);
  ASSERT_NE(itr, table.end());
  ASSERT_EQ(itr->second, 0);
}

TEST(PageTableTest, CreateMappingGreaterThanPageSize) {
  PageTable pTable = PageTable();

  pTable.createMapping(0, 0, 4096 * 3);
  std::map<uint64_t, uint64_t> table = pTable.getTable();

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
  PageTable pTable = PageTable();

  // map [0, 12288) -> [0, 12288)
  pTable.createMapping(0, 0, 4096 * 3);
  std::map<uint64_t, uint64_t> table = pTable.getTable();

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
  uint64_t retVal = pTable.createMapping(4096, 8192, 4096);
  ASSERT_EQ(retVal,
            masks::faults::pagetable::FAULT | masks::faults::pagetable::MAP);
}

TEST(PageTableTest, TranslateVaddr) {
  PageTable pTable = PageTable();

  pTable.createMapping(0, 4096, 4096);
  std::map<uint64_t, uint64_t> table = pTable.getTable();

  ASSERT_EQ(table.size(), 1);
  uint64_t pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable.translate(10);
  ASSERT_EQ(pAddrWOffset, 4096 + 10);

  // End addresses are not inclusive in a mapped range, therefore, in this test
  // case the address 4096 is not mapped (0 to 4095 is). Hence, the translation
  // should fail.
  pAddrWOffset = pTable.translate(4096);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::FAULT |
                              masks::faults::pagetable::TRANSLATE);
}

TEST(PageTableTest, TranslateOnRangeLargerThanPage) {
  PageTable pTable = PageTable();

  // Map vaddr range [0, 12288) -> paddr [4096, 16384)
  pTable.createMapping(0, 4096, 4096 * 3);

  std::map<uint64_t, uint64_t> table = pTable.getTable();
  ASSERT_EQ(table.size(), 3);
  uint64_t pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable.translate(10);
  ASSERT_EQ(pAddrWOffset, 4096 + 10);

  pAddrWOffset = pTable.translate(5183);
  // Address 5183 would lie in a range greater than the first page in the ptable
  // i.e. [0, 4096). It must therefore lie on the second page of [4096, 8192).
  // With vaddr 0 mapping to paddr 4096, we have that vaddr 5183 is mapped to
  // 8192 + (5183 - 4096) = 9279.

  ASSERT_EQ(pAddrWOffset, 8192 + (5183 - 4096));
}

TEST(PageTableTest, TranslateVaddrWithSameOffset) {
  PageTable pTable = PageTable();

  // Map range vaddr [0, 4096) -> paddr [4096, 8192)
  pTable.createMapping(0, 4096, 4096);

  // Map range vaddr [4096, 12288) -> paddr [8192, 16384)
  pTable.createMapping(4096, 4096 * 2, 4096 * 2);
  std::map<uint64_t, uint64_t> table = pTable.getTable();

  ASSERT_EQ(table.size(), 3);
  uint64_t pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable.translate(4097);
  ASSERT_EQ(pAddrWOffset, 8193);

  uint16_t mask = 0xFFF;
  uint64_t vaddr1 = 3152;
  uint64_t vaddr2 = 7248;

  ASSERT_EQ(vaddr1 & mask, vaddr2 & mask);

  pAddrWOffset = pTable.translate(vaddr1);
  ASSERT_EQ(pAddrWOffset, 7248);

  pAddrWOffset = pTable.translate(vaddr2);
  ASSERT_EQ(pAddrWOffset, 11344);
}

TEST(PageTableTest, DeleteMapping) {
  PageTable pTable = PageTable();

  pTable.createMapping(0, 4096, 4096);

  std::map<uint64_t, uint64_t> table = pTable.getTable();
  ASSERT_EQ(table.size(), 1);

  uint64_t pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable.translate(10);
  ASSERT_EQ(pAddrWOffset, 4096 + 10);

  uint64_t retVal = pTable.deleteMapping(0, 4096);
  ASSERT_EQ(retVal, 0);

  table = pTable.getTable();
  ASSERT_EQ(table.size(), 0);

  pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::FAULT |
                              masks::faults::pagetable::TRANSLATE);
}

TEST(PageTableTest, DeleteMappingGreaterThanExistingMapping) {
  PageTable pTable = PageTable();

  // Map vaddr range [0, 12288) -> paddr [4096, 16384)
  pTable.createMapping(0, 4096, 4096 * 3);

  std::map<uint64_t, uint64_t> table = pTable.getTable();
  ASSERT_EQ(table.size(), 3);

  uint64_t pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable.translate(45);
  ASSERT_EQ(pAddrWOffset, 4096 + 45);

  // Try to delete a mapping greater than size of mapping.
  uint64_t retVal = pTable.deleteMapping(0, 4096 * 4);
  ASSERT_EQ(retVal,
            masks::faults::pagetable::FAULT | masks::faults::pagetable::UNMAP);

  table = pTable.getTable();
  ASSERT_EQ(table.size(), 3);
}

TEST(PageTableTest, DeleteMappingAtUnalignedAddr) {
  PageTable pTable = PageTable();

  // Map vaddr range [0, 4096) -> paddr [4096, 8192)
  pTable.createMapping(0, 4096, 4096);

  std::map<uint64_t, uint64_t> table = pTable.getTable();
  ASSERT_EQ(table.size(), 1);

  uint64_t pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable.translate(45);
  ASSERT_EQ(pAddrWOffset, 4096 + 45);

  // This will delete the page assosciate in which the addr resides.
  uint64_t retVal = pTable.deleteMapping(1024, 4096);
  ASSERT_EQ(retVal, 0);

  pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::FAULT |
                              masks::faults::pagetable::TRANSLATE);

  table = pTable.getTable();
  ASSERT_EQ(table.size(), 0);
}

TEST(PageTableTest, DeleteMappingAtUnalignedSizes) {
  PageTable pTable = PageTable();

  // Map vaddr range [0, 8192) -> paddr [4096, 12288)
  pTable.createMapping(0, 4096, 4096 * 2);

  std::map<uint64_t, uint64_t> table = pTable.getTable();
  ASSERT_EQ(table.size(), 2);

  uint64_t pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  // This should delete the first mapping i.e [0, 12288) -> [4096, 8192)
  uint64_t retVal = pTable.deleteMapping(1024, 3456);
  ASSERT_EQ(retVal, 0);

  pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::FAULT |
                              masks::faults::pagetable::TRANSLATE);

  table = pTable.getTable();
  ASSERT_EQ(table.size(), 1);
}

TEST(PageTableTest, DeleteMappingInBetweenTwoPages) {
  PageTable pTable = PageTable();

  // Map vaddr range [0, 12288) -> paddr [4096, 16384)
  pTable.createMapping(0, 4096, 4096 * 3);

  std::map<uint64_t, uint64_t> table = pTable.getTable();
  ASSERT_EQ(table.size(), 3);

  uint64_t pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable.translate(4098);
  ASSERT_EQ(pAddrWOffset, 8192 + (0xFFF & 4098));

  pAddrWOffset = pTable.translate(8199);
  ASSERT_EQ(pAddrWOffset, 12288 + (0xFFF & 8199));

  // This should delete the first mapping i.e [0, 4096) -> [4096, 8192)
  uint64_t retVal = pTable.deleteMapping(4096, 4096);
  ASSERT_EQ(retVal, 0);

  pAddrWOffset = pTable.translate(4098);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::FAULT |
                              masks::faults::pagetable::TRANSLATE);

  table = pTable.getTable();
  ASSERT_EQ(table.size(), 2);
}

TEST(PageTableTest, DeleteNonExistentMapping) {
  PageTable pTable = PageTable();

  // Map vaddr range [0, 12288) -> paddr [4096, 16384)
  pTable.createMapping(0, 4096, 4096);

  std::map<uint64_t, uint64_t> table = pTable.getTable();
  ASSERT_EQ(table.size(), 1);

  uint64_t pAddrWOffset = pTable.translate(0);
  ASSERT_EQ(pAddrWOffset, 4096);

  pAddrWOffset = pTable.translate(4098);
  ASSERT_EQ(pAddrWOffset, masks::faults::pagetable::FAULT |
                              masks::faults::pagetable::TRANSLATE);

  // This should delete the first mapping i.e [0, 4096) -> [4096, 8192)
  uint64_t retVal = pTable.deleteMapping(4096, 4096);
  ASSERT_EQ(retVal,
            masks::faults::pagetable::FAULT | masks::faults::pagetable::UNMAP);

  table = pTable.getTable();
  ASSERT_EQ(table.size(), 1);
}

}  // namespace
