#include <array>
#include <bitset>
#include <cstdint>
#include <iostream>
#include <memory>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "simeng/Port.hh"
#include "simeng/memory/SimpleMem.hh"
#include "simeng/memory/hierarchy/SetAssosciativeCache.hh"
#include "simeng/memory/hierarchy/TagSchemes.hh"

using namespace simeng::memory::hierarchy;

namespace {

TEST(TagSchemePIPT, Test1) {
  // auto pipt = std::make_unique<PIPT>(1024 * 16, 4, 4);
}

}  // namespace
