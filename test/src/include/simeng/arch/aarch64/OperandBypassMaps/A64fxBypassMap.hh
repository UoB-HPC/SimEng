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
  bool print = false;

 public:
  A64fxBypassMap() {
    // Fill out bypass map structure
    // Integer Operation
    bypassMap_[InstructionGroups::INT] = {
        {std::nullopt,
         {{{InstructionGroups::INT, InstructionGroups::LOAD,
            InstructionGroups::STORE_ADDRESS_INT,
            InstructionGroups::STORE_ADDRESS_SCALAR,
            InstructionGroups::STORE_ADDRESS_VECTOR,
            InstructionGroups::STORE_ADDRESS_SVE,
            InstructionGroups::STORE_ADDRESS_SME},
           1},
          {{InstructionGroups::STORE_DATA_INT}, 1}}},
        {nzcv_,
         {{{InstructionGroups::INT}, 1},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           7},
          {{InstructionGroups::PREDICATE}, 6},
          {{InstructionGroups::BRANCH}, 0}}}};
    // bypassMap_[InstructionGroups::STORE_DATA_INT] = {
    //     {std::nullopt,
    //      {{{InstructionGroups::INT, InstructionGroups::BRANCH}, 0}}},
    // };
    // bypassMap_[InstructionGroups::BRANCH] = {
    //     {std::nullopt,
    //      {{{InstructionGroups::INT, InstructionGroups::STORE_DATA_INT,
    //         InstructionGroups::LOAD},
    //        0}}},
    // };
    // Integer cvt
    // bypassMap_[InstructionGroups::INT_SIMPLE_ARTH_NOSHIFT] = {
    //     {std::nullopt, {{{InstructionGroups::FP_SIMPLE_CVT}, 3}}}};
    // Integer Load
    bypassMap_[InstructionGroups::LOAD_INT] = {
        {std::nullopt,
         {{{InstructionGroups::INT, InstructionGroups::LOAD,
            InstructionGroups::STORE_DATA_INT,
            InstructionGroups::STORE_ADDRESS_INT,
            InstructionGroups::STORE_ADDRESS_SCALAR,
            InstructionGroups::STORE_ADDRESS_VECTOR,
            InstructionGroups::STORE_ADDRESS_SVE,
            InstructionGroups::STORE_ADDRESS_SME},
           1}}}};
    // FP Scalar Load
    bypassMap_[InstructionGroups::LOAD_SCALAR] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::LOAD, InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           1}}}};
    // FP Vector Load
    bypassMap_[InstructionGroups::LOAD_VECTOR] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::LOAD, InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           1}}}};
    // SVE Load
    bypassMap_[InstructionGroups::LOAD_SVE] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::LOAD, InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           1}}}};
    // Predicate Load
    // bypassMap_[InstructionGroups::LOAD] = {
    //     {pred_,
    //      {{{InstructionGroups::LOAD_SCALAR, InstructionGroups::LOAD_VECTOR,
    //         InstructionGroups::LOAD_SVE,
    //         InstructionGroups::STORE_ADDRESS_SCALAR,
    //         InstructionGroups::STORE_ADDRESS_VECTOR,
    //         InstructionGroups::STORE_ADDRESS_SVE},
    //        0},
    //       {{InstructionGroups::SVE, InstructionGroups::FP,
    //         InstructionGroups::STORE_DATA_SCALAR,
    //         InstructionGroups::STORE_DATA_VECTOR,
    //         InstructionGroups::STORE_DATA_SVE},
    //        3},
    //       {{InstructionGroups::PREDICATE}, 1}}}};
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
          {{InstructionGroups::PREDICATE}, 7},
          {{InstructionGroups::BRANCH}, 0}}}};
    // FP Operation
    bypassMap_[InstructionGroups::FP] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           1}}},
        {nzcv_,
         {{{InstructionGroups::INT}, 5},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           1},
          {{InstructionGroups::PREDICATE}, 6},
          {{InstructionGroups::BRANCH}, 0}}}};
    // FP cvt
    // bypassMap_[InstructionGroups::FP_SIMPLE_ARTH_NOSHIFT] = {
    //     {std::nullopt, {{{InstructionGroups::INT_SIMPLE_CVT}, 1}}}};
    // SVE Operation
    bypassMap_[InstructionGroups::SVE] = {
        {std::nullopt,
         {{{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           1}}},
        {nzcv_,
         {{{InstructionGroups::INT}, 5},
          {{InstructionGroups::SVE, InstructionGroups::FP,
            InstructionGroups::STORE_DATA_SCALAR,
            InstructionGroups::STORE_DATA_VECTOR,
            InstructionGroups::STORE_DATA_SVE},
           1},
          {{InstructionGroups::PREDICATE}, 6},
          {{InstructionGroups::BRANCH}, 0}}}};
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
          {{InstructionGroups::PREDICATE}, 10},
          {{InstructionGroups::BRANCH}, 0}}}};
  }

  /** Given the instruction groups of the producer instruction and consumer
   * instruction, plus the forwarded operand's register type, the
   * bypass latency in cycles is returned.
   * If no bypass is permitted, then -1 is returned. */
  int64_t getBypassLatency(const uint16_t producerGroup,
                           const uint16_t consumerGroup,
                           const uint8_t regType) override {
    if (print)
      std::cerr << groupNames_[producerGroup] << " to "
                << groupNames_[consumerGroup] << " on reg type "
                << unsigned(regType) << std::endl;
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
      if (print) {
        std::cerr << "\tGH for producer " << groupNames_[producerGroup]
                  << std::endl;
        auto tmpStk = groupHierarchyCache_[producerGroup];
        while (tmpStk.size()) {
          std::cerr << "\t\t" << groupNames_[tmpStk.top()] << std::endl;
          tmpStk.pop();
        }
      }
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
      if (print) {
        std::cerr << "\tGH for consumer " << groupNames_[consumerGroup]
                  << std::endl;
        auto tmpStk = groupHierarchyCache_[consumerGroup];
        while (tmpStk.size()) {
          std::cerr << "\t\t" << groupNames_[tmpStk.top()] << std::endl;
          tmpStk.pop();
        }
      }
    }

    // Starting with lowest level group, see if the producer is in the bypass
    // map
    bool found = false;
    while (!producerGroups.empty() && (found == false)) {
      if (bypassMap_.find(producerGroups.top()) != bypassMap_.end()) {
        found = true;
        if (print)
          std::cerr << "\tBypass entry for "
                    << groupNames_[producerGroups.top()] << std::endl;
      }
      // Check SCALAR group against FP counterpart (excluding LD or STR)
      else if ((producerGroups.top() >= InstructionGroups::SCALAR &&
                producerGroups.top() <=
                    InstructionGroups::SCALAR_DIV_OR_SQRT)) {
        // Group is SCALAR - see if FP counterpart is in the bypassMap
        uint16_t fpGroup = producerGroups.top() -
                           (InstructionGroups::SCALAR - InstructionGroups::FP);
        if (bypassMap_.find(fpGroup) != bypassMap_.end()) {
          found = true;
          producerGroups.pop();
          producerGroups.push(fpGroup);
        }
      }
      // Check VECTOR group against FP counterpart (excluding LD or STR)
      else if (producerGroups.top() >= InstructionGroups::VECTOR &&
               producerGroups.top() <= InstructionGroups::VECTOR_DIV_OR_SQRT) {
        // Group is VECTOR - see if FP counterpart is in the bypassMap
        uint16_t fpGroup = producerGroups.top() -
                           (InstructionGroups::VECTOR - InstructionGroups::FP);
        if (bypassMap_.find(fpGroup) != bypassMap_.end()) {
          producerGroups.pop();
          producerGroups.push(fpGroup);
          found = true;
        }
      }

      if (found == false) {
        if (print)
          std::cerr << "\tNo bypass entry for "
                    << groupNames_[producerGroups.top()] << std::endl;
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
        } else if (!regConsumersPair.first.has_value()) {
          // Optional reg type has no value so no register condition required.
          // Keep track this vector and loop through the rest of the mapEntry
          // values to ensure there isn't a missed register type match
          bypassConsumerVec = regConsumersPair.second;
        }
      }
      // If no vector is empty (as no register conditions were met),
      // bypass is not permitted
      if (bypassConsumerVec.size() == 0) {
        // if (print)
        std::cerr << "\tNo register (" << unsigned(regType) << ") entry for "
                  << groupNames_[producerGroups.top()] << std::endl;
        return -1;
      } else if (print) {
        std::cerr << "\tGenerated consumer vec on " << unsigned(regType)
                  << std::endl;
        for (const auto& grps : bypassConsumerVec) {
          for (const auto& grp : grps.groups) {
            std::cerr << "\t\t" << groupNames_[grp] << std::endl;
          }
        }
      }

      // Starting with lowest level consumer group (`consumerGroup` argument),
      // see if a bypass latency is available
      while (!consumerGroups.empty()) {
        for (bypassConsumer& consumer : bypassConsumerVec) {
          if (std::find(consumer.groups.begin(), consumer.groups.end(),
                        consumerGroups.top()) != consumer.groups.end()) {
            // Group match found, return bypass latency
            if (print)
              std::cerr << "\tmatching entry for " << groupNames_[consumerGroup]
                        << " with " << groupNames_[producerGroup] << " with "
                        << consumer.latency << std::endl;
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
              if (print)
                std::cerr << "\tmatching entry for "
                          << groupNames_[consumerGroup] << " with "
                          << groupNames_[producerGroup] << " with "
                          << consumer.latency << std::endl;
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
              if (print)
                std::cerr << "\tmatching entry for "
                          << groupNames_[consumerGroup] << " with "
                          << groupNames_[producerGroup] << " with "
                          << consumer.latency << std::endl;
              return consumer.latency;
            }
          }
        }
        // No group match, pop current top and move onto next consumer group
        consumerGroups.pop();
      }
    }

    // If no entry in bypassMap found, operand forwarding is not allowed
    if (print)
      std::cerr << "\tNo matching entry for " << groupNames_[consumerGroup]
                << " with " << groupNames_[producerGroup] << std::endl;
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

    if (groupInheritance.find(rootGroup) != groupInheritance.end()) {
      // If children exist, iterate over them all recursively
      auto& rootGroupChildren = groupInheritance.at(rootGroup);
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

  std::vector<std::string> groupNames_ = {"INT",
                                          "INT_SIMPLE",
                                          "INT_SIMPLE_ARTH",
                                          "INT_SIMPLE_ARTH_NOSHIFT",
                                          "INT_SIMPLE_LOGICAL",
                                          "INT_SIMPLE_LOGICAL_NOSHIFT",
                                          "INT_SIMPLE_CMP",
                                          "INT_SIMPLE_CVT",
                                          "INT_MUL",
                                          "INT_DIV_OR_SQRT",
                                          "LOAD_INT",
                                          "STORE_ADDRESS_INT",
                                          "STORE_DATA_INT",
                                          "STORE_INT",
                                          "FP",
                                          "FP_SIMPLE",
                                          "FP_SIMPLE_ARTH",
                                          "FP_SIMPLE_ARTH_NOSHIFT",
                                          "FP_SIMPLE_LOGICAL",
                                          "FP_SIMPLE_LOGICAL_NOSHIFT",
                                          "FP_SIMPLE_CMP",
                                          "FP_SIMPLE_CVT",
                                          "FP_MUL",
                                          "FP_DIV_OR_SQRT",
                                          "SCALAR",
                                          "SCALAR_SIMPLE",
                                          "SCALAR_SIMPLE_ARTH",
                                          "SCALAR_SIMPLE_ARTH_NOSHIFT",
                                          "SCALAR_SIMPLE_LOGICAL",
                                          "SCALAR_SIMPLE_LOGICAL_NOSHIFT",
                                          "SCALAR_SIMPLE_CMP",
                                          "SCALAR_SIMPLE_CVT",
                                          "SCALAR_MUL",
                                          "SCALAR_DIV_OR_SQRT",
                                          "LOAD_SCALAR",
                                          "STORE_ADDRESS_SCALAR",
                                          "STORE_DATA_SCALAR",
                                          "STORE_SCALAR",
                                          "VECTOR",
                                          "VECTOR_SIMPLE",
                                          "VECTOR_SIMPLE_ARTH",
                                          "VECTOR_SIMPLE_ARTH_NOSHIFT",
                                          "VECTOR_SIMPLE_LOGICAL",
                                          "VECTOR_SIMPLE_LOGICAL_NOSHIFT",
                                          "VECTOR_SIMPLE_CMP",
                                          "VECTOR_SIMPLE_CVT",
                                          "VECTOR_MUL",
                                          "VECTOR_DIV_OR_SQRT",
                                          "LOAD_VECTOR",
                                          "STORE_ADDRESS_VECTOR",
                                          "STORE_DATA_VECTOR",
                                          "STORE_VECTOR",
                                          "SVE",
                                          "SVE_SIMPLE",
                                          "SVE_SIMPLE_ARTH",
                                          "SVE_SIMPLE_ARTH_NOSHIFT",
                                          "SVE_SIMPLE_LOGICAL",
                                          "SVE_SIMPLE_LOGICAL_NOSHIFT",
                                          "SVE_SIMPLE_CMP",
                                          "SVE_SIMPLE_CVT",
                                          "SVE_MUL",
                                          "SVE_DIV_OR_SQRT",
                                          "LOAD_SVE",
                                          "STORE_ADDRESS_SVE",
                                          "STORE_DATA_SVE",
                                          "STORE_SVE",
                                          "PREDICATE",
                                          "LOAD",
                                          "STORE_ADDRESS",
                                          "STORE_DATA",
                                          "STORE",
                                          "BRANCH",
                                          "SME",
                                          "SME_SIMPLE",
                                          "SME_SIMPLE_ARTH",
                                          "SME_SIMPLE_ARTH_NOSHIFT",
                                          "SME_SIMPLE_LOGICAL",
                                          "SME_SIMPLE_LOGICAL_NOSHIFT",
                                          "SME_SIMPLE_CMP",
                                          "SME_SIMPLE_CVT",
                                          "SME_MUL",
                                          "SME_DIV_OR_SQRT",
                                          "LOAD_SME",
                                          "STORE_ADDRESS_SME",
                                          "STORE_DATA_SME",
                                          "STORE_SME",
                                          "ALL",
                                          "NONE"};
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
