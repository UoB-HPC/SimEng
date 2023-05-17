#include <cstdint>
#include <iostream>

#include "gtest/gtest.h"
#include "simeng/Port.hh"
#include "simeng/memory/hierarchy/Replacement.hh"

namespace {

using namespace simeng;
using namespace simeng::memory;
using namespace simeng::memory::hierarchy;

TEST(LRUTest, GetInvalidClineFirst) {
  LRU lru = LRU(1024, 4);
  uint16_t cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 0);
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 1);
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 2);
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 3);

  cline = lru.findReplacement(2);
  ASSERT_EQ(cline, 0);
  cline = lru.findReplacement(2);
  ASSERT_EQ(cline, 1);
  cline = lru.findReplacement(2);
  ASSERT_EQ(cline, 2);
  cline = lru.findReplacement(2);
  ASSERT_EQ(cline, 3);
}

TEST(LRUTest, ReplaceValidCline) {
  LRU lru = LRU(1024, 4);
  lru.findReplacement(0);
  lru.findReplacement(0);
  lru.findReplacement(0);
  lru.findReplacement(0);
  uint16_t cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 0);
}

TEST(LRUTest, CycleThroughValidClines) {
  LRU lru = LRU(1024, 4);
  lru.findReplacement(0);
  lru.findReplacement(0);
  lru.findReplacement(0);
  lru.findReplacement(0);
  uint16_t cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 0);
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 1);
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 2);
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 3);
}

TEST(LRUTest, UpdateCline1) {
  LRU lru = LRU(1024, 4);
  uint16_t cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 0);
  lru.updateUsage(0, 1);
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 2);
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 3);
  ASSERT_EQ(std::string("0->1->2->3").compare(lru.serialiseSet(0)), 0);
}

TEST(LRUTest, UpdateCline2) {
  LRU lru = LRU(1024, 4);
  uint16_t cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 0);
  lru.updateUsage(0, 1);
  lru.updateUsage(0, 2);
  ASSERT_EQ(std::string("3->0->1->2"), lru.serialiseSet(0));
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 3);
  ASSERT_EQ(std::string("0->1->2->3").compare(lru.serialiseSet(0)), 0);
}

TEST(LRUTest, UpdateCline3) {
  LRU lru = LRU(1024, 4);
  uint16_t cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 0);
  lru.updateUsage(0, 1);
  lru.updateUsage(0, 1);
  ASSERT_EQ(std::string("2->3->0->1"), lru.serialiseSet(0));
  cline = lru.findReplacement(0);
  ASSERT_EQ(cline, 2);
  ASSERT_EQ(std::string("3->0->1->2").compare(lru.serialiseSet(0)), 0);
}

}  // namespace
