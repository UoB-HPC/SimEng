#pragma once

#include <math.h>

#include <algorithm>
#include <cassert>
#include <climits>
#include <fstream>
#include <iostream>
#include <queue>
#include <string>
#include <unordered_map>

#include "simeng/arch/aarch64/InstructionGroups.hh"
#include "yaml-cpp/yaml.h"

namespace simeng {

namespace ExpectedValue {
const uint8_t Integer = 0;
const uint8_t UInteger = 1;
const uint8_t Float = 2;
const uint8_t String = 3;
const uint8_t Bool = 4;
}  // namespace ExpectedValue

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
  /** If using a base config file, inherit and overwrite values form
   * the base file. */
  void inherit();

  /** Validate all required fields are filled with an appropriate
   * value. */
  void validate();

  /** From a pre-defined vector of instruction group strings, instantiate an
   * ISA specific mapping between the instruction group strings and the
   * relevant instruction group variables. */
  void createGroupMapping();

  /** Given a node, value requirements, and possibly a default value,
   * validate the value held within the node. All methods perform, at
   * least, an existence and "read as type" check with the latter
   * reading the value as the given type within a try catch
   * expressions. */
  // Set of values requirement, no default value
  template <typename T>
  int nodeChecker(const YAML::Node& node, const std::string& field,
                  const std::vector<T>& value_set, uint8_t expected);
  // Set of values requirement, with default value
  template <typename T>
  int nodeChecker(YAML::Node node, const std::string& field,
                  const std::vector<T>& value_set, uint8_t expected,
                  T default_value);
  // Pair of inclusive bounds requirement, no default value
  template <typename T>
  int nodeChecker(const YAML::Node& node, const std::string& field,
                  const std::pair<T, T>& bounds, uint8_t expected);
  // Pair of inclusive bounds requirement, with default value
  template <typename T>
  int nodeChecker(YAML::Node node, const std::string& field,
                  const std::pair<T, T>& bounds, uint8_t expected,
                  const T& default_value);

  /** Given a set of values (value_set), ensure the supplied node is one of
   * these options. */
  template <typename T>
  int setChecker(YAML::Node node, const std::string& field,
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
      invalid_ << "\t- " << field << invalidTypeMap_[expected] << "\n";
      return 0;
    }
    return 1;
  }

  /** Given a set of bounds (bounds) ensure the supplied node is between
   * these value inclusively. */
  template <typename T>
  int boundChecker(YAML::Node node, const std::string& field,
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
      invalid_ << "\t- " << field << invalidTypeMap_[expected] << "\n";
      return 0;
    }
    return 1;
  }

  /** The YAML formatted config file. */
  YAML::Node configFile_;

  /** The ISA specific vector of instruction group strings for matching
   * against user inputted groups. */
  std::vector<std::string> groupOptions_;

  /** ISA specific mapping between the defined instruction strings and the
   * instruction group variables. */
  std::unordered_map<std::string, uint16_t> groupMapping_;

  /** A mapping between the expected data type and the error message if a
   * field cannot be read as the expected type. */
  std::unordered_map<uint8_t, std::string> invalidTypeMap_ = {
      {ExpectedValue::Integer, " must be of type integer"},
      {ExpectedValue::UInteger, " must be of type unsigned integer"},
      {ExpectedValue::Float, " must be of type float"},
      {ExpectedValue::String, " must be of type string"},
      {ExpectedValue::Bool, " must be of type bool"}};

  /** A string stream containing information about missing config
   * fields. */
  std::ostringstream missing_;

  /** A string stream containing information about invalid values. */
  std::ostringstream invalid_;
};  // namespace ModelConfig

}  // namespace simeng