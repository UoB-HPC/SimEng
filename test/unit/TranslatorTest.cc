#include "gtest/gtest.h"
#include "simeng/Translator.hh"

namespace simeng {

// Test that multiple regions can be created
TEST(TranslatorTest, AddRegions) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  // Add new region mappings and ensure their return values are correct
  EXPECT_EQ(address_translator->add_mapping({0, 500}, {1600, 2100}), true);
  EXPECT_EQ(address_translator->get_mapping(0), Translation({1600, true}));
  EXPECT_EQ(address_translator->get_mapping(250), Translation({1850, true}));
  EXPECT_EQ(address_translator->get_mapping(499), Translation({2099, true}));

  EXPECT_EQ(address_translator->add_mapping({500, 1000}, {1100, 1600}), true);
  EXPECT_EQ(address_translator->get_mapping(500), Translation({1100, true}));
  EXPECT_EQ(address_translator->get_mapping(750), Translation({1350, true}));
  EXPECT_EQ(address_translator->get_mapping(999), Translation({1599, true}));

  EXPECT_EQ(address_translator->add_mapping({1500, 2000}, {100, 600}), true);
  EXPECT_EQ(address_translator->get_mapping(1500), Translation({100, true}));
  EXPECT_EQ(address_translator->get_mapping(1750), Translation({350, true}));
  EXPECT_EQ(address_translator->get_mapping(1999), Translation({599, true}));

  EXPECT_EQ(address_translator->add_mapping({1000, 1500}, {600, 1100}), true);
  EXPECT_EQ(address_translator->get_mapping(1000), Translation({600, true}));
  EXPECT_EQ(address_translator->get_mapping(1250), Translation({850, true}));
  EXPECT_EQ(address_translator->get_mapping(1499), Translation({1099, true}));

  EXPECT_EQ(address_translator->add_mapping({2000, 2001}, {2100, 2101}), true);
  EXPECT_EQ(address_translator->get_mapping(2000), Translation({2100, true}));
}

// Test that translating under, over, and on a region boundary returns correctly
TEST(TranslatorTest, TranslateAtBoundary) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  EXPECT_EQ(address_translator->add_mapping({400, 500}, {2000, 2100}), true);
  EXPECT_EQ(address_translator->get_mapping(350), Translation({0, false}));
  EXPECT_EQ(address_translator->get_mapping(399), Translation({0, false}));
  EXPECT_EQ(address_translator->get_mapping(400), Translation({2000, true}));
  EXPECT_EQ(address_translator->get_mapping(401), Translation({2001, true}));
  EXPECT_EQ(address_translator->get_mapping(450), Translation({2050, true}));
  EXPECT_EQ(address_translator->get_mapping(499), Translation({2099, true}));
  EXPECT_EQ(address_translator->get_mapping(500), Translation({0, false}));
  EXPECT_EQ(address_translator->get_mapping(501), Translation({0, false}));
  EXPECT_EQ(address_translator->get_mapping(550), Translation({0, false}));
}

// Test incorrect addition of regions fails due to overlap
TEST(TranslatorTest, OverlappedAddedRegions) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  // Create region to overlap on
  EXPECT_EQ(address_translator->add_mapping({100, 200}, {1000, 1100}), true);
  // Test that equivalent regions are rejected
  EXPECT_EQ(address_translator->add_mapping({100, 200}, {2000, 2100}), false);
  EXPECT_EQ(address_translator->add_mapping({0, 100}, {1000, 1100}), false);
  EXPECT_EQ(address_translator->add_mapping({100, 200}, {1000, 1100}), false);
  // Test that regions that contain a previously mapped boundary are rejected
  EXPECT_EQ(address_translator->add_mapping({0, 100}, {950, 1050}), false);
  EXPECT_EQ(address_translator->add_mapping({0, 100}, {1050, 1150}), false);
  EXPECT_EQ(address_translator->add_mapping({50, 150}, {2000, 2100}), false);
  EXPECT_EQ(address_translator->add_mapping({150, 250}, {2000, 2100}), false);

  EXPECT_EQ(address_translator->add_mapping({100, 101}, {1100, 1101}), false);
  EXPECT_EQ(address_translator->add_mapping({200, 201}, {1000, 1001}), false);
}

// Test incorrect addition of regions fails due to differing sizes
TEST(TranslatorTest, DifferentlySizedAddedRegions) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  EXPECT_EQ(address_translator->add_mapping({100, 200}, {1000, 2000}), false);
  EXPECT_EQ(address_translator->add_mapping({1000, 2000}, {100, 200}), false);
}

// Test incorrect addition of regions fails due to invalid regions
TEST(TranslatorTest, InvalidAddedRegions) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  // Failure as start of region is greater than end
  EXPECT_EQ(address_translator->add_mapping({200, 100}, {1000, 2000}), false);
  EXPECT_EQ(address_translator->add_mapping({1000, 2000}, {200, 100}), false);
  EXPECT_EQ(address_translator->add_mapping({200, 100}, {2000, 1000}), false);

  // Failure as start of region is equal to end
  EXPECT_EQ(address_translator->add_mapping({100, 100}, {1000, 1000}), false);
}

// Test that regions can be updated
TEST(TranslatorTest, UpdateRegions) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  // Expand added regions
  EXPECT_EQ(address_translator->add_mapping({0, 50}, {160, 210}), true);
  EXPECT_EQ(address_translator->update_mapping({0, 50}, {0, 500}, {1600, 2100}),
            true);
  EXPECT_EQ(address_translator->get_mapping(0), Translation({1600, true}));
  EXPECT_EQ(address_translator->get_mapping(250), Translation({1850, true}));
  EXPECT_EQ(address_translator->get_mapping(499), Translation({2099, true}));

  EXPECT_EQ(address_translator->add_mapping({550, 600}, {110, 160}), true);
  EXPECT_EQ(address_translator->update_mapping({550, 600}, {1500, 2000},
                                               {1100, 1600}),
            true);
  EXPECT_EQ(address_translator->get_mapping(1500), Translation({1100, true}));
  EXPECT_EQ(address_translator->get_mapping(1750), Translation({1350, true}));
  EXPECT_EQ(address_translator->get_mapping(1999), Translation({1599, true}));

  EXPECT_EQ(address_translator->add_mapping({600, 650}, {10, 60}), true);
  EXPECT_EQ(
      address_translator->update_mapping({600, 650}, {1000, 1500}, {600, 1100}),
      true);
  EXPECT_EQ(address_translator->get_mapping(1000), Translation({600, true}));
  EXPECT_EQ(address_translator->get_mapping(1250), Translation({850, true}));
  EXPECT_EQ(address_translator->get_mapping(1499), Translation({1099, true}));

  // Use same region as previous before update
  EXPECT_EQ(address_translator->add_mapping({600, 650}, {10, 60}), true);
  EXPECT_EQ(
      address_translator->update_mapping({600, 650}, {500, 1000}, {100, 600}),
      true);
  EXPECT_EQ(address_translator->get_mapping(500), Translation({100, true}));
  EXPECT_EQ(address_translator->get_mapping(750), Translation({350, true}));
  EXPECT_EQ(address_translator->get_mapping(999), Translation({599, true}));

  // Use an equivalent region in update
  EXPECT_EQ(address_translator->add_mapping({2000, 2050}, {3000, 3050}), true);
  EXPECT_EQ(address_translator->update_mapping({2000, 2050}, {2000, 2050},
                                               {4000, 4050}),
            true);
  EXPECT_EQ(address_translator->get_mapping(2000), Translation({4000, true}));
  EXPECT_EQ(address_translator->get_mapping(2025), Translation({4025, true}));
  EXPECT_EQ(address_translator->get_mapping(2049), Translation({4049, true}));

  EXPECT_EQ(address_translator->add_mapping({3000, 3050}, {2100, 2150}), true);
  EXPECT_EQ(address_translator->update_mapping({3000, 3050}, {4000, 4050},
                                               {2100, 2150}),
            true);
  EXPECT_EQ(address_translator->get_mapping(4000), Translation({2100, true}));
  EXPECT_EQ(address_translator->get_mapping(4025), Translation({2125, true}));
  EXPECT_EQ(address_translator->get_mapping(4049), Translation({2149, true}));
}

// Test incorrect update of regions fails due to overlap
TEST(TranslatorTest, OverlappedUpdatedRegions) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  // Create regions to overlap on
  EXPECT_EQ(address_translator->add_mapping({100, 200}, {1000, 1100}), true);
  EXPECT_EQ(address_translator->add_mapping({200, 300}, {1100, 1200}), true);

  // Test for equivalence
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {100, 200}, {1100, 1200}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {200, 300}, {1000, 1100}),
      false);

  // Test for crossing boundary
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {50, 150}, {1100, 1200}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {150, 250}, {1100, 1200}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {200, 300}, {950, 1050}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {200, 300}, {1050, 1150}),
      false);

  // Test for shrinking region to fit inside a prior region
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {101, 199}, {1101, 1199}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {149, 150}, {1049, 1050}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {201, 299}, {1001, 1099}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {249, 250}, {1049, 1050}),
      false);

  // Test for expanding region to encapsulate a prior region
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {99, 200}, {1099, 1200}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {50, 250}, {1050, 1250}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {199, 300}, {999, 1100}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({200, 300}, {150, 350}, {950, 1150}),
      false);
}

// Test incorrect update of regions fails due to differing sizes
TEST(TranslatorTest, DifferentlySizedUpdatedRegions) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  // Create regions to update
  EXPECT_EQ(address_translator->add_mapping({100, 200}, {1000, 1100}), true);

  EXPECT_EQ(
      address_translator->update_mapping({100, 200}, {100, 199}, {1000, 1100}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({100, 200}, {100, 200}, {1000, 1099}),
      false);
}

// Test incorrect update of regions fails due to invalid regions
TEST(TranslatorTest, InvalidUpdatedRegions) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  // Create regions to update
  EXPECT_EQ(address_translator->add_mapping({100, 200}, {1000, 1100}), true);

  // Failure as start of region is greater than end
  EXPECT_EQ(
      address_translator->update_mapping({100, 200}, {200, 100}, {1000, 1100}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({100, 200}, {100, 200}, {1100, 1000}),
      false);
  EXPECT_EQ(
      address_translator->update_mapping({100, 200}, {200, 100}, {1100, 1000}),
      false);

  // Failure as start of region is equal to end
  EXPECT_EQ(
      address_translator->update_mapping({100, 200}, {100, 100}, {1000, 1000}),
      false);
}

// Test incorrect update of regions fails due to orignal doesn't exist
TEST(TranslatorTest, NonExistentOriginalUpdatedRegions) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();

  EXPECT_EQ(
      address_translator->update_mapping({100, 200}, {300, 400}, {1000, 1100}),
      false);
}

// Test that disabling the translator does no translations
TEST(TranslatorTest, DisableTranslator) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();

  address_translator->disable_translation();

  // Add new region
  EXPECT_EQ(address_translator->add_mapping({0, 500}, {1600, 2100}), true);
  EXPECT_EQ(address_translator->get_mapping(0), Translation({0, true}));
  EXPECT_EQ(address_translator->get_mapping(250), Translation({250, true}));
  EXPECT_EQ(address_translator->get_mapping(499), Translation({499, true}));

  // Add and update a region
  EXPECT_EQ(address_translator->add_mapping({0, 50}, {160, 210}), true);
  EXPECT_EQ(
      address_translator->update_mapping({0, 50}, {500, 1000}, {2100, 2600}),
      true);
  EXPECT_EQ(address_translator->get_mapping(500), Translation({500, true}));
  EXPECT_EQ(address_translator->get_mapping(750), Translation({750, true}));
  EXPECT_EQ(address_translator->get_mapping(999), Translation({999, true}));

  // Get mapping with no region added
  EXPECT_EQ(address_translator->get_mapping(12345), Translation({12345, true}));
  EXPECT_EQ(address_translator->get_mapping(67890), Translation({67890, true}));
}

// Test mmap allocations
TEST(TranslatorTest, MmapAllocation) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  address_translator->setPageSize(100);
  address_translator->setInitialMmapRegion(1000, 2000);

  // Mmap regions
  EXPECT_EQ(address_translator->mmap_allocation(100), 1000);
  EXPECT_EQ(address_translator->get_mapping(1000), Translation({2000, true}));
  EXPECT_EQ(address_translator->get_mapping(1099), Translation({2099, true}));
  EXPECT_EQ(address_translator->mmap_allocation(100), 1100);
  EXPECT_EQ(address_translator->get_mapping(1100), Translation({2100, true}));
  EXPECT_EQ(address_translator->get_mapping(1199), Translation({2199, true}));
  EXPECT_EQ(address_translator->mmap_allocation(200), 1200);
  EXPECT_EQ(address_translator->get_mapping(1200), Translation({2200, true}));
  EXPECT_EQ(address_translator->get_mapping(1399), Translation({2399, true}));
  EXPECT_EQ(address_translator->mmap_allocation(100), 1400);
  EXPECT_EQ(address_translator->get_mapping(1400), Translation({2400, true}));
  EXPECT_EQ(address_translator->get_mapping(1499), Translation({2499, true}));

  // Deallocate region and ensure mapped memory is erased
  EXPECT_EQ(address_translator->munmap_deallocation(1200, 200), 0);
  EXPECT_EQ(address_translator->get_mapping(1200), Translation({0, false}));
  EXPECT_EQ(address_translator->get_mapping(1399), Translation({0, false}));

  // Ensure deallocated region is reused
  EXPECT_EQ(address_translator->mmap_allocation(100), 1200);
  EXPECT_EQ(address_translator->get_mapping(1200), Translation({2200, true}));
  EXPECT_EQ(address_translator->get_mapping(1299), Translation({2299, true}));
  EXPECT_EQ(address_translator->mmap_allocation(100), 1300);
  EXPECT_EQ(address_translator->get_mapping(1300), Translation({2300, true}));
  EXPECT_EQ(address_translator->get_mapping(1399), Translation({2399, true}));
  EXPECT_EQ(address_translator->mmap_allocation(100), 1500);
  EXPECT_EQ(address_translator->get_mapping(1500), Translation({2500, true}));
  EXPECT_EQ(address_translator->get_mapping(1599), Translation({2599, true}));
}

// Test registering a previously mapped allocation
TEST(TranslatorTest, RegisterAllocation) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  address_translator->setPageSize(100);
  address_translator->setInitialMmapRegion(1000, 2000);

  // Add regions to be latter registered as mmap allocations
  EXPECT_EQ(address_translator->add_mapping({1000, 1100}, {2000, 2100}), true);
  EXPECT_EQ(address_translator->add_mapping({1200, 1300}, {2200, 2300}), true);
  EXPECT_EQ(address_translator->add_mapping({1300, 1400}, {2300, 2400}), true);
  EXPECT_EQ(address_translator->add_mapping({1400, 1500}, {2400, 2500}), true);

  // Register allocations
  EXPECT_EQ(address_translator->register_allocation(1000, 100, {2000, 2100}),
            true);
  EXPECT_EQ(address_translator->register_allocation(1200, 100, {2200, 2300}),
            true);
  EXPECT_EQ(address_translator->register_allocation(1300, 100, {2300, 2400}),
            true);
  EXPECT_EQ(address_translator->register_allocation(1400, 100, {2400, 2500}),
            true);

  // Ensure new allocations interect with recently registered allocations
  // correctly
  EXPECT_EQ(address_translator->mmap_allocation(100), 1100);
  EXPECT_EQ(address_translator->get_mapping(1100), Translation({2100, true}));
  EXPECT_EQ(address_translator->get_mapping(1199), Translation({2199, true}));
  EXPECT_EQ(address_translator->mmap_allocation(100), 1500);
  EXPECT_EQ(address_translator->get_mapping(1500), Translation({2500, true}));
  EXPECT_EQ(address_translator->get_mapping(1599), Translation({2599, true}));

  // Ensure register allocation can be correctly deallocated
  EXPECT_EQ(address_translator->munmap_deallocation(1300, 100), 0);
  EXPECT_EQ(address_translator->get_mapping(1300), Translation({0, false}));
  EXPECT_EQ(address_translator->get_mapping(1399), Translation({0, false}));

  // Ensure deallocated region is reused
  EXPECT_EQ(address_translator->mmap_allocation(100), 1300);
  EXPECT_EQ(address_translator->get_mapping(1300), Translation({2300, true}));
  EXPECT_EQ(address_translator->get_mapping(1399), Translation({2399, true}));
  EXPECT_EQ(address_translator->mmap_allocation(100), 1600);
  EXPECT_EQ(address_translator->get_mapping(1600), Translation({2600, true}));
  EXPECT_EQ(address_translator->get_mapping(1699), Translation({2699, true}));
}

// Test invalid register allocations
TEST(TranslatorTest, InvalidRegisterAllocation) {
  // Create instance of translator
  std::unique_ptr<simeng::Translator> address_translator =
      std::make_unique<simeng::Translator>();
  address_translator->setPageSize(100);
  address_translator->setInitialMmapRegion(1000, 2000);

  EXPECT_EQ(address_translator->add_mapping({1000, 1100}, {2000, 2100}), true);
  EXPECT_EQ(address_translator->add_mapping({2000, 2100}, {3000, 3100}), true);

  // Ensure failure if a unmapped memory region is supplied
  EXPECT_EQ(address_translator->register_allocation(1000, 100, {2000, 4100}),
            false);
  EXPECT_EQ(address_translator->register_allocation(1000, 100, {1000, 2100}),
            false);
  EXPECT_EQ(address_translator->register_allocation(1000, 100, {1000, 4100}),
            false);

  // Ensure failure if allocation has already been registered
  EXPECT_EQ(address_translator->register_allocation(1000, 100, {2000, 2100}),
            true);
  EXPECT_EQ(address_translator->register_allocation(1000, 100, {2000, 2100}),
            false);

  // Ensure failure if process region described doesn't exist
  EXPECT_EQ(address_translator->register_allocation(500, 100, {2000, 2100}),
            false);
  EXPECT_EQ(address_translator->register_allocation(1000, 50, {2000, 2100}),
            false);
  EXPECT_EQ(address_translator->register_allocation(500, 50, {2000, 2100}),
            false);

  // Ensure failure if memory region supplied has already been assigned to
  // another registered allocation
  EXPECT_EQ(address_translator->register_allocation(2000, 100, {2000, 2100}),
            false);
  EXPECT_EQ(address_translator->register_allocation(2000, 100, {3000, 3100}),
            true);
}

}  // namespace simeng
