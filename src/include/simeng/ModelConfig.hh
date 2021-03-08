#pragma once

#include <math.h>

#include <algorithm>
#include <cassert>
#include <climits>
#include <fstream>
#include <iostream>
#include <map>
#include <string>

#include "simeng/arch/aarch64/Instruction.hh"
#include "yaml-cpp/yaml.h"

#define DEFAULT_CONFIG \
  ("{Core: {                                                \
   Simulation-Mode: inorderpipelined, Clock-Frequency: 2.5, \
   Fetch-Block-Alignment-Bits: 5                            \
   }, Register-Set: {                                       \
   GeneralPurpose-Count: 154, FloatingPoint/SVE-Count: 90,  \
   Conditional-Count: 128                                   \
   }, Pipeline-Widths: {                                    \
   Commit: 4, Dispatch-Rate: 4, FrontEnd: 4,                \
   LSQ-Completion: 2                                        \
   }, Queue-Sizes: {                                        \
   ROB: 180, Load: 64, Store: 36                            \
   }, Branch-Predictor: {                                   \
   BTB-bitlength: 16                                        \
   }, L1-Cache: {                                           \
   GeneralPurpose-Latency: 4, FloatingPoint-Latency: 4,     \
   SVE-Latency: 11, Bandwidth: 32,                          \
   Permitted-Requests-Per-Cycle: 2,                         \
   Permitted-Loads-Per-Cycle: 2,                            \
   Permitted-Stores-Per-Cycle: 1                            \
   }, Ports: {                                              \
   '0': {Portname: Port 0, Instruction-Support:             \
   [{Compulsory: [0], Optional: [1, 2]},                    \
   {Compulsory: [4], Optional: [1, 2, 3]}]},                \
   '1': {Portname: Port 1, Instruction-Support:             \
   [{Compulsory: [0], Optional: [1, 2, 3]},                 \
   {Compulsory: [4], Optional: [1, 2, 3]}]},                \
   '2': {Portname: Port 2, Instruction-Support:             \
   [{Compulsory: [0], Optional: [1, 2]},                    \
   {Compulsory: [7]}]},                                     \
   '3': {Portname: Port 4, Instruction-Support:             \
   [{Compulsory: [5], Optional: [1, 4]}]},                  \
   '4': {Portname: Port 5, Instruction-Support:             \
   [{Compulsory: [5], Optional: [1, 4]}]},                  \
   '5': {Portname: Port 3, Instruction-Support:             \
   [{Compulsory: [6], Optional: [1, 4]}]}                   \
   }, Reservation-Stations: {                               \
   '0': {Size: 60,                                          \
   Ports: [0, 1, 2, 3, 4, 5]}                               \
   }, Execution-Units: {                                    \
   '0': {Pipelined: true, Blocking-Group: 0},               \
   '1': {Pipelined: true, Blocking-Group: 0},               \
   '2': {Pipelined: true, Blocking-Group: 0},               \
   '3': {Pipelined: true, Blocking-Group: 0},               \
   '4': {Pipelined: true, Blocking-Group: 0},               \
   '5': {Pipelined: true, Blocking-Group: 0}                \
   }                                                        \
   }")

namespace simeng {
std::vector<std::string> groupOptions = {"ARITHMETIC", "SHIFT",  "MULTIPLY",
                                         "DIVIDE",     "ASIMD",  "LOAD",
                                         "STORE",      "BRANCH", "PREDICATE"};
std::vector<std::string> groupOptionsWithNone = {
    "ARITHMETIC", "SHIFT", "MULTIPLY", "DIVIDE",    "ASIMD",
    "LOAD",       "STORE", "BRANCH",   "PREDICATE", "NONE"};
struct GroupMapping {
  uint8_t arth = simeng::arch::aarch64::InstructionGroups::ARITHMETIC;
  uint8_t shft = simeng::arch::aarch64::InstructionGroups::SHIFT;
  uint8_t mul = simeng::arch::aarch64::InstructionGroups::MULTIPLY;
  uint8_t div = simeng::arch::aarch64::InstructionGroups::DIVIDE;
  uint8_t simd = simeng::arch::aarch64::InstructionGroups::ASIMD;
  uint8_t ld = simeng::arch::aarch64::InstructionGroups::LOAD;
  uint8_t st = simeng::arch::aarch64::InstructionGroups::STORE;
  uint8_t br = simeng::arch::aarch64::InstructionGroups::BRANCH;
  uint8_t pred = simeng::arch::aarch64::InstructionGroups::PREDICATE;
};

std::map<std::string, uint8_t> group_mapping = {
    {"ARITHMETIC", simeng::arch::aarch64::InstructionGroups::ARITHMETIC},
    {"SHIFT", simeng::arch::aarch64::InstructionGroups::SHIFT},
    {"MULTIPLY", simeng::arch::aarch64::InstructionGroups::MULTIPLY},
    {"DIVIDE", simeng::arch::aarch64::InstructionGroups::DIVIDE},
    {"ASIMD", simeng::arch::aarch64::InstructionGroups::ASIMD},
    {"LOAD", simeng::arch::aarch64::InstructionGroups::LOAD},
    {"STORE", simeng::arch::aarch64::InstructionGroups::STORE},
    {"BRANCH", simeng::arch::aarch64::InstructionGroups::BRANCH},
    {"PREDICATE", simeng::arch::aarch64::InstructionGroups::PREDICATE}};

namespace ExpectedValue {
const uint8_t Integer = 0;
const uint8_t UInteger = 1;
const uint8_t Float = 2;
const uint8_t String = 3;
const uint8_t Bool = 4;
}  // namespace ExpectedValue

std::map<uint8_t, std::string> invalid_type_map = {
    {ExpectedValue::Integer, " must be of type integer"},
    {ExpectedValue::UInteger, " must be of type unsigned integer"},
    {ExpectedValue::Float, " must be of type float"},
    {ExpectedValue::String, " must be of type string"},
    {ExpectedValue::Bool, " must be of type bool"}};

/** A class to correctly validate and format the provided
 * configuration YAML file. */
class ModelConfig {
 public:
  /** Construct a ModelConfig class by reading in the YAML file and
   * running it through checks and formatting. */
  ModelConfig(std::string path);

  /** Return the checked and formatted config file. */
  YAML::Node getConfigFile();

 private:
  /** If using a base config file, inherit and overwite values form
   * the base file. */
  void inherit();

  /** Validate all required fields are filled with an approriate
   * value. */
  void validate();

  /** Given a node, value requirements, and possibly a deafult value,
   * validate the value held within the node. All methods perform, at
   * least, an existance and "read as type" check with the latter
   * reading the value as the given type within a try catch
   * expressions. */
  // Set of values requirement, no default value
  template <typename T>
  int nodeChecker(YAML::Node node, std::string field,
                  const std::vector<T>& value_set, uint8_t expected);
  // Set of values requirement, with default value
  template <typename T>
  int nodeChecker(YAML::Node node, std::string field,
                  const std::vector<T>& value_set, uint8_t expected,
                  T default_value);
  // Pair of inclusive bounds requirement, no default value
  template <typename T>
  int nodeChecker(YAML::Node node, std::string field,
                  const std::pair<T, T>& bounds, uint8_t expected);
  // Pair of inclusive bounds requirement, with default value
  template <typename T>
  int nodeChecker(YAML::Node node, std::string field,
                  const std::pair<T, T>& bounds, uint8_t expected,
                  T default_value);

  /** Given a set of values (value_set), ensure the supplied node is on of these
   * options. */
  template <typename T>
  int setChecker(YAML::Node node, std::string field,
                 const std::vector<T>& value_set, uint8_t expected) {
    // Ensure node value can be read as specified type
    try {
      T node_value = node.as<T>();
      // Check if a set of expected options has been defined
      if (value_set.size()) {
        // Ensure values lies within the defined options
        if (!(std::find(value_set.begin(), value_set.end(), node_value) !=
              value_set.end())) {
          invalid_ << "\t- " << field << " value \"" << node_value
                   << "\" is not in the valid set {";
          for (int i = 0; i < value_set.size(); i++) {
            invalid_ << value_set[i];
            if (i != value_set.size() - 1) invalid_ << ", ";
          }
          invalid_ << "}\n";
          return 0;
        }
      }
    } catch (...) {
      invalid_ << "\t- " << field << invalid_type_map[expected] << "\n";
      return 0;
    }
    return 1;
  }

  /** Given a set of bounds (bounds) ensure the supplied node is betwene these
   * value inclusively. */
  template <typename T>
  int boundChecker(YAML::Node node, std::string field,
                   const std::pair<T, T>& bounds, uint8_t expected) {
    // Ensure node value can be read as specified type
    try {
      T node_value = node.as<T>();
      // Extract bounds from bounds pair
      T lower_bound = bounds.first;
      T upper_bound = bounds.second;
      assert(lower_bound <= upper_bound &&
             "Defined lower bound of config option is not equal or "
             "less than defined upper bound");

      // Ensure value lies within the defined bounds
      if (lower_bound > node_value || node_value > upper_bound) {
        invalid_ << "\t- " << field
                 << " must conform to the inclusive bounds of " << lower_bound
                 << " and " << upper_bound << "\n";
        return 0;
      }
    } catch (...) {
      invalid_ << "\t- " << field << invalid_type_map[expected] << "\n";
      return 0;
    }
    return 1;
  }

  /** The YAML formatted config file. */
  YAML::Node configFile_;

  /** A string stream containing information about missing config
   * fields. */
  std::ostringstream missing_;

  /** A string stream containing information about invalid values. */
  std::ostringstream invalid_;
};  // namespace ModelConfig

}  // namespace simeng