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

#define DEFAULT_CONFIG                                                         \
  ("{Core: {Simulation-Mode: outoforder, Clock-Frequency: 2.5, "               \
   "Fetch-Block-Size: 32}, Register-Set: {GeneralPurpose-Count: "              \
   "154, FloatingPoint/SVE-Count: 90, Predicate-Count: 17, "                   \
   "Conditional-Count: 128}, Pipeline-Widths: {Commit: 4, Dispatch-Rate: 4, "  \
   "FrontEnd: 4, LSQ-Completion: 2}, Queue-Sizes: {ROB: 180, Load: 64, "       \
   "Store: 36}, Branch-Predictor: {BTB-bitlength: 16}, L1-Cache: "             \
   "{GeneralPurpose-Latency: 4, FloatingPoint-Latency: 4, SVE-Latency: 1, "    \
   "Bandwidth: 32, Permitted-Requests-Per-Cycle: 2, "                          \
   "Permitted-Loads-Per-Cycle: 2, Permitted-Stores-Per-Cycle: 1}, Ports: "     \
   "{'0': {Portname: Port 0, Instruction-Support: [0, 1, 7, 10, 16, 17]}, "    \
   "'1': {Portname: Port 1, Instruction-Support: [0, 1, 7, 8, 10, 16, 17]}, "  \
   "'2': {Portname: Port 2, Instruction-Support: [1, 7, 56]}, '3': "           \
   "{Portname: Port 4, Instruction-Support: [46]}, '4': {Portname: Port 5, "   \
   "Instruction-Support: [46]}, '5': {Portname: Port 3, Instruction-Support: " \
   "[51]}}, Reservation-Stations: {'0': {Size: 60, Ports: [0, 1, 2, 3, 4, "    \
   "5]}}, Execution-Units: {'0': {Pipelined: true}, '1': {Pipelined: true}, "  \
   "'2': {Pipelined: true}, '3': {Pipelined: true}, '4': {Pipelined: true}, "  \
   "'5': {Pipelined: true}}}")

namespace simeng {
std::vector<std::string> groupOptions = {"INT",
                                         "INT_SIMPLE",
                                         "INT_ARTH",
                                         "INT_ARTH_NOSHIFT",
                                         "INT_LOGICAL",
                                         "INT_LOGICAL_NOSHIFT",
                                         "INT_CMP",
                                         "INT_CVT",
                                         "INT_MUL",
                                         "INT_DIV_OR_SQRT",
                                         "LOAD_INT",
                                         "STORE_INT",
                                         "FP",
                                         "FP_SIMPLE",
                                         "FP_ARTH",
                                         "FP_ARTH_NOSHIFT",
                                         "FP_LOGICAL",
                                         "FP_LOGICAL_NOSHIFT",
                                         "FP_CMP",
                                         "FP_CVT",
                                         "FP_MUL",
                                         "FP_DIV_OR_SQRT",
                                         "SCALAR",
                                         "SCALAR_SIMPLE",
                                         "SCALAR_ARTH",
                                         "SCALAR_ARTH_NOSHIFT",
                                         "SCALAR_LOGICAL",
                                         "SCALAR_LOGICAL_NOSHIFT",
                                         "SCALAR_CMP",
                                         "SCALAR_CVT",
                                         "SCALAR_MUL",
                                         "SCALAR_DIV_OR_SQRT",
                                         "LOAD_FLOAT",
                                         "STORE_FLOAT",
                                         "VECTOR",
                                         "VECTOR_SIMPLE",
                                         "VECTOR_ARTH",
                                         "VECTOR_ARTH_NOSHIFT",
                                         "VECTOR_LOGICAL",
                                         "VECTOR_LOGICAL_NOSHIFT",
                                         "VECTOR_CMP",
                                         "VECTOR_CVT",
                                         "VECTOR_MUL",
                                         "VECTOR_DIV_OR_SQRT",
                                         "LOAD_VECTOR",
                                         "STORE_VECTOR",
                                         "SVE",
                                         "SVE_SIMPLE",
                                         "SVE_ARTH",
                                         "SVE_ARTH_NOSHIFT",
                                         "SVE_LOGICAL",
                                         "SVE_LOGICAL_NOSHIFT",
                                         "SVE_CMP",
                                         "SVE_CVT",
                                         "SVE_MUL",
                                         "SVE_DIV_OR_SQRT",
                                         "LOAD_SVE",
                                         "STORE_SVE",
                                         "PREDICATE",
                                         "LOAD",
                                         "STORE",
                                         "BRANCH"};

std::map<std::string, uint16_t> group_mapping = {
    {"INT", simeng::arch::aarch64::InstructionGroups::INT},
    {"INT_SIMPLE", simeng::arch::aarch64::InstructionGroups::INT_SIMPLE},
    {"INT_ARTH", simeng::arch::aarch64::InstructionGroups::INT_ARTH},
    {"INT_ARTH_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::INT_ARTH_NOSHIFT},
    {"INT_LOGICAL", simeng::arch::aarch64::InstructionGroups::INT_LOGICAL},
    {"INT_LOGICAL_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::INT_LOGICAL_NOSHIFT},
    {"INT_CMP", simeng::arch::aarch64::InstructionGroups::INT_CMP},
    {"INT_CVT", simeng::arch::aarch64::InstructionGroups::INT_CVT},
    {"INT_MUL", simeng::arch::aarch64::InstructionGroups::INT_MUL},
    {"INT_DIV_OR_SQRT",
     simeng::arch::aarch64::InstructionGroups::INT_DIV_OR_SQRT},
    {"LOAD_INT", simeng::arch::aarch64::InstructionGroups::LOAD_INT},
    {"STORE_INT", simeng::arch::aarch64::InstructionGroups::STORE_INT},
    {"FP", simeng::arch::aarch64::InstructionGroups::FP},
    {"FP_SIMPLE", simeng::arch::aarch64::InstructionGroups::FP_SIMPLE},
    {"FP_ARTH", simeng::arch::aarch64::InstructionGroups::FP_ARTH},
    {"FP_ARTH_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::FP_ARTH_NOSHIFT},
    {"FP_LOGICAL", simeng::arch::aarch64::InstructionGroups::FP_LOGICAL},
    {"FP_LOGICAL_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::FP_LOGICAL_NOSHIFT},
    {"FP_CMP", simeng::arch::aarch64::InstructionGroups::FP_CMP},
    {"FP_CVT", simeng::arch::aarch64::InstructionGroups::FP_CVT},
    {"FP_MUL", simeng::arch::aarch64::InstructionGroups::FP_MUL},
    {"FP_DIV_OR_SQRT",
     simeng::arch::aarch64::InstructionGroups::FP_DIV_OR_SQRT},
    {"SCALAR", simeng::arch::aarch64::InstructionGroups::SCALAR},
    {"SCALAR_SIMPLE", simeng::arch::aarch64::InstructionGroups::SCALAR_SIMPLE},
    {"SCALAR_ARTH", simeng::arch::aarch64::InstructionGroups::SCALAR_ARTH},
    {"SCALAR_ARTH_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::SCALAR_ARTH_NOSHIFT},
    {"SCALAR_LOGICAL",
     simeng::arch::aarch64::InstructionGroups::SCALAR_LOGICAL},
    {"SCALAR_LOGICAL_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::SCALAR_LOGICAL_NOSHIFT},
    {"SCALAR_CMP", simeng::arch::aarch64::InstructionGroups::SCALAR_CMP},
    {"SCALAR_CVT", simeng::arch::aarch64::InstructionGroups::SCALAR_CVT},
    {"SCALAR_MUL", simeng::arch::aarch64::InstructionGroups::SCALAR_MUL},
    {"SCALAR_DIV_OR_SQRT",
     simeng::arch::aarch64::InstructionGroups::SCALAR_DIV_OR_SQRT},
    {"LOAD_FLOAT", simeng::arch::aarch64::InstructionGroups::LOAD_FLOAT},
    {"STORE_FLOAT", simeng::arch::aarch64::InstructionGroups::STORE_FLOAT},
    {"VECTOR", simeng::arch::aarch64::InstructionGroups::VECTOR},
    {"VECTOR_SIMPLE", simeng::arch::aarch64::InstructionGroups::VECTOR_SIMPLE},
    {"VECTOR_ARTH", simeng::arch::aarch64::InstructionGroups::VECTOR_ARTH},
    {"VECTOR_ARTH_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::VECTOR_ARTH_NOSHIFT},
    {"VECTOR_LOGICAL",
     simeng::arch::aarch64::InstructionGroups::VECTOR_LOGICAL},
    {"VECTOR_LOGICAL_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::VECTOR_LOGICAL_NOSHIFT},
    {"VECTOR_CMP", simeng::arch::aarch64::InstructionGroups::VECTOR_CMP},
    {"VECTOR_CVT", simeng::arch::aarch64::InstructionGroups::VECTOR_CVT},
    {"VECTOR_MUL", simeng::arch::aarch64::InstructionGroups::VECTOR_MUL},
    {"VECTOR_DIV_OR_SQRT",
     simeng::arch::aarch64::InstructionGroups::VECTOR_DIV_OR_SQRT},
    {"LOAD_VECTOR", simeng::arch::aarch64::InstructionGroups::LOAD_VECTOR},
    {"STORE_VECTOR", simeng::arch::aarch64::InstructionGroups::STORE_VECTOR},
    {"SVE", simeng::arch::aarch64::InstructionGroups::SVE},
    {"SVE_SIMPLE", simeng::arch::aarch64::InstructionGroups::SVE_SIMPLE},
    {"SVE_ARTH", simeng::arch::aarch64::InstructionGroups::SVE_ARTH},
    {"SVE_ARTH_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::SVE_ARTH_NOSHIFT},
    {"SVE_LOGICAL", simeng::arch::aarch64::InstructionGroups::SVE_LOGICAL},
    {"SVE_LOGICAL_NOSHIFT",
     simeng::arch::aarch64::InstructionGroups::SVE_LOGICAL_NOSHIFT},
    {"SVE_CMP", simeng::arch::aarch64::InstructionGroups::SVE_CMP},
    {"SVE_CVT", simeng::arch::aarch64::InstructionGroups::SVE_CVT},
    {"SVE_MUL", simeng::arch::aarch64::InstructionGroups::SVE_MUL},
    {"SVE_DIV_OR_SQRT",
     simeng::arch::aarch64::InstructionGroups::SVE_DIV_OR_SQRT},
    {"LOAD_SVE", simeng::arch::aarch64::InstructionGroups::LOAD_SVE},
    {"STORE_SVE", simeng::arch::aarch64::InstructionGroups::STORE_SVE},
    {"PREDICATE", simeng::arch::aarch64::InstructionGroups::PREDICATE},
    {"LOAD", simeng::arch::aarch64::InstructionGroups::LOAD},
    {"STORE", simeng::arch::aarch64::InstructionGroups::STORE},
    {"BRANCH", simeng::arch::aarch64::InstructionGroups::BRANCH},
};

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

  /** Given a set of values (value_set), ensure the supplied node is on of
   * these options. */
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