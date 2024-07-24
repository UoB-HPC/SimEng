#pragma once

#include <assert.h>

#include <queue>
#include <stack>

#include "simeng/OperandBypassMap.hh"
#include "simeng/arch/aarch64/InstructionGroups.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

/** A simple class to hold the permitted operand bypass model and easily find
   the bypass latency between two instructions. */
class A64fxBypassMap : public OperandBypassMap {
 public:
  A64fxBypassMap() {
    // Fill out bypass map structure
    // Integer Operation
    bypassMap_[InstructionGroups::INT] = {
        {std::nullopt,
         {{{InstructionGroups::INT, InstructionGroups::LOAD,
            InstructionGroups::STORE_ADDRESS},
           1}}},
        {nzcv_,
         {{{InstructionGroups::INT}, 1},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           7},
          {{InstructionGroups::PREDICATE}, 6}}}};
    // Integer Load
    bypassMap_[InstructionGroups::LOAD_INT] = {
        {std::nullopt,
         {{{InstructionGroups::INT, InstructionGroups::LOAD,
            InstructionGroups::STORE_ADDRESS},
           0}}}};
    // FP Scalar Load
    bypassMap_[InstructionGroups::LOAD_SCALAR] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           0}}}};
    // FP Vector Load
    bypassMap_[InstructionGroups::LOAD_VECTOR] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           0}}}};
    // SVE Load
    bypassMap_[InstructionGroups::LOAD_SVE] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           0}}}};
    // Predicate Load
    bypassMap_[InstructionGroups::LOAD] = {
        {pred_,
         {{{InstructionGroups::LOAD_SCALAR, InstructionGroups::LOAD_VECTOR,
            InstructionGroups::LOAD_SVE,
            InstructionGroups::STORE_ADDRESS_SCALAR,
            InstructionGroups::STORE_ADDRESS_VECTOR,
            InstructionGroups::STORE_ADDRESS_SVE},
           0},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           3},
          {{InstructionGroups::PREDICATE}, 1}}}};
    // Predicate Operation
    bypassMap_[InstructionGroups::PREDICATE] = {
        {std::nullopt,
         {{{InstructionGroups::LOAD_SCALAR, InstructionGroups::LOAD_VECTOR,
            InstructionGroups::LOAD_SVE,
            InstructionGroups::STORE_ADDRESS_SCALAR,
            InstructionGroups::STORE_ADDRESS_VECTOR,
            InstructionGroups::STORE_ADDRESS_SVE},
           1},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           3},
          {{InstructionGroups::PREDICATE}, 0}}},
        {nzcv_,
         {{{InstructionGroups::INT}, 6},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           8},
          {{InstructionGroups::PREDICATE}, 7}}}};
    // FP Operation
    bypassMap_[InstructionGroups::FP] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           0}}},
        {nzcv_,
         {{{InstructionGroups::INT}, 5},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           0},
          {{InstructionGroups::PREDICATE}, 6}}}};
    // SVE Operation
    bypassMap_[InstructionGroups::SVE] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           0}}},
        {nzcv_,
         {{{InstructionGroups::INT}, 5},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           0},
          {{InstructionGroups::PREDICATE}, 6}}}};
    // SVE Compare Operation
    bypassMap_[InstructionGroups::SVE_SIMPLE_CMP] = {
        {pred_,
         {{{InstructionGroups::LOAD_SCALAR, InstructionGroups::LOAD_VECTOR,
            InstructionGroups::LOAD_SVE,
            InstructionGroups::STORE_ADDRESS_SCALAR,
            InstructionGroups::STORE_ADDRESS_VECTOR,
            InstructionGroups::STORE_ADDRESS_SVE},
           2},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           1},
          {{InstructionGroups::PREDICATE}, 2}}},
        {nzcv_,
         {{{InstructionGroups::INT}, 9},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           11},
          {{InstructionGroups::PREDICATE}, 10}}}};
  }

  /** Given the instruction groups of the producer instruction and consumer
   * instruction, plus the forwarded operand's register type, the
   * bypass latency in cycles is returned.
   * If no bypass is permitted, then -1 is returned. */
  int64_t getBypassLatency(const uint16_t producerGroup,
                           const uint16_t consumerGroup,
                           const uint8_t regType) override {
    // If producer or consumer group is NONE, then no bypass can occur.
    if (producerGroup == InstructionGroups::NONE ||
        consumerGroup == InstructionGroups::NONE)
      return -1;

    // Get all valid groups for Producer and Consumer - i.e. their current group
    // and all parent groups
    std::stack<uint16_t> producerGroups;
    std::stack<uint16_t> consumerGroups;
    // Look in cache for producer group stack
    if (groupHierarchyCache_.find(producerGroup) !=
        groupHierarchyCache_.end()) {
      producerGroups = groupHierarchyCache_.at(producerGroup);
    } else {
      // No cache entry present, find groups manually
      [[maybe_unused]] bool pathPresent = findGroupParents(
          InstructionGroups::ALL, &producerGroups, producerGroup);
      assert(pathPresent && "Invalid producer group.");
      // Add found groups to cache
      groupHierarchyCache_[producerGroup] = producerGroups;
    }
    // Look in cache for consumer group stack
    if (groupHierarchyCache_.find(consumerGroup) !=
        groupHierarchyCache_.end()) {
      consumerGroups = groupHierarchyCache_.at(consumerGroup);
    } else {
      // No cache entry present, find groups manually
      [[maybe_unused]] bool pathPresent = findGroupParents(
          InstructionGroups::ALL, &consumerGroups, consumerGroup);
      assert(pathPresent && "Invalid consumer group.");
      // Add found groups to cache
      groupHierarchyCache_[consumerGroup] = consumerGroups;
    }

    // Starting with lowest level group, see if the producer is in the bypass
    // map
    bool found = false;
    while (!producerGroups.empty()) {
      if (bypassMap_.find(producerGroups.top()) != bypassMap_.end()) {
        found = true;
        break;
      }
      // Check SCALAR group against FP counterpart (excluding LD or STR)
      else if ((producerGroups.top() >= InstructionGroups::SCALAR &&
                producerGroups.top() <=
                    InstructionGroups::SCALAR_DIV_OR_SQRT)) {
        // Group is SCALAR - see if is in the bypassMap
        if (bypassMap_.find(producerGroups.top() - (InstructionGroups::SCALAR -
                                                    InstructionGroups::FP)) !=
            bypassMap_.end()) {
          found = true;
          break;
        }
      }
      // Check VECTOR group against FP counterpart (excluding LD or STR)
      else if (producerGroups.top() >= InstructionGroups::VECTOR &&
               producerGroups.top() <= InstructionGroups::VECTOR_DIV_OR_SQRT) {
        // Group is SCALAR - see if is in the bypassMap
        if (bypassMap_.find(producerGroups.top() - (InstructionGroups::VECTOR -
                                                    InstructionGroups::FP)) !=
            bypassMap_.end()) {
          found = true;
          break;
        }
      }

      else {
        producerGroups.pop();
      }
    }

    if (found) {
      auto& mapEntry = bypassMap_.at(producerGroups.top());
      assert(mapEntry.size() > 0 && "Bypass map entry is empty.");

      // Identify which vector of bypassConsumers we are concerned with by
      // seeing if we need to consider the operand register type
      std::vector<bypassConsumer> bypassConsumerVec = {};
      for (auto& regConsumersPair : mapEntry) {
        if (regConsumersPair.first.has_value() &&
            regConsumersPair.first.value() == regType) {
          // Found the register condition. Track vector and end search
          bypassConsumerVec = regConsumersPair.second;
          break;
        } else {
          // Optional reg type has no value so no register condition required.
          // Keep track this vector and loop through the rest of the mapEntry
          // values to ensure there isn't a missed register type match
          bypassConsumerVec = regConsumersPair.second;
        }
      }
      // If no vector is empty (as no register conditions were met),
      // bypass is not permitted
      if (bypassConsumerVec.size() == 0) return -1;

      // Starting with lowest level consumer group (`consumerGroup` argument),
      // see if a bypass latency is available
      while (!consumerGroups.empty()) {
        for (bypassConsumer& consumer : bypassConsumerVec) {
          if (std::find(consumer.groups.begin(), consumer.groups.end(),
                        consumerGroups.top()) != consumer.groups.end()) {
            // Group match found, return bypass latency
            return consumer.latency;
          }
          // Check SCALAR group against FP counterpart (excluding LD or STR)
          else if ((consumerGroups.top() >= InstructionGroups::SCALAR &&
                    consumerGroups.top() <=
                        InstructionGroups::SCALAR_DIV_OR_SQRT)) {
            if (std::find(consumer.groups.begin(), consumer.groups.end(),
                          consumerGroups.top() - (InstructionGroups::SCALAR -
                                                  InstructionGroups::FP)) !=
                consumer.groups.end()) {
              // Group match found, return bypass latency
              return consumer.latency;
            }
          }
          // Check VECTOR group against FP counterpart (excluding LD or STR)
          else if (consumerGroups.top() >= InstructionGroups::VECTOR &&
                   consumerGroups.top() <=
                       InstructionGroups::VECTOR_DIV_OR_SQRT) {
            if (std::find(consumer.groups.begin(), consumer.groups.end(),
                          consumerGroups.top() - (InstructionGroups::VECTOR -
                                                  InstructionGroups::FP)) !=
                consumer.groups.end()) {
              // Group match found, return bypass latency
              return consumer.latency;
            }
          }
        }
        // No group match, pop current top and move onto next consumer group
        consumerGroups.pop();
      }
    }

    // If no entry in bypassMap found, operand forwarding is not allowed
    return -1;
  }

 private:
  /** Recursivly find all instruction group parents for a given group using
   * depth first search.
   * Returns true if a path was formed, false otherwise. */
  bool findGroupParents(const uint16_t rootGroup,
                        std::stack<uint16_t>* pathToGroup,
                        const uint16_t targetGroup) const {
    pathToGroup->push(rootGroup);
    if (rootGroup == targetGroup) {
      return true;
    }

    if (groupInheritance_.find(rootGroup) != groupInheritance_.end()) {
      // If children exist, iterate over them all recursively
      auto& rootGroupChildren = groupInheritance_.at(rootGroup);
      for (auto& child : rootGroupChildren) {
        // Child is target group
        if (findGroupParents(child, pathToGroup, targetGroup)) return true;
      }
    }

    // Target group not found, pop group from path stack
    pathToGroup->pop();
    return false;
  }

  /** A constant representation of the NZCV AArch64 register type. */
  const uint8_t nzcv_ = 3;

  /** A constant representation of the predicate AArch64 register type. */
  const uint8_t pred_ = 2;

  /** Map which caches previously completed group inheritance searches.
   * Key = lowest level group in search
   * Value = in order vector of group hierarchy */
  std::unordered_map<uint16_t, std::stack<uint16_t>> groupHierarchyCache_;
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng