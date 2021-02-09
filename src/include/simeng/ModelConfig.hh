#pragma once

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <map>
#include <string>

#include "simeng/arch/aarch64/Instruction.hh"
#include "yaml-cpp/yaml.h"

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

/** A class to correctly validate and format the provided configuration YAML
 * file. */
class ModelConfig {
 public:
  /** Construct a ModelConfig class by reading in the YAML file and running it
   * through checks and formatting. */
  ModelConfig(std::string path);

  /** Return the checked and formatted config file. */
  YAML::Node getConfigFile();

 private:
  /** If using a base config file, inherit and overwite values form the base
   * file. */
  void inherit();

  /** Validate all required fields are filled with an approriate value. */
  void validate();

  /** Given a node, value requirements, and an "allow_default" value,
   * validate the value held within the node. All methods perform, at least, an
   * existance and "read as type" check with the latter reading the value as the
   * given type within a try catch expressions. */
  /** For the string type, a "value_set" can be given to ensure the provided
   * node value is within the set. An empty value_set disables the matching
   * requirement. */
  int nodeChecker(YAML::Node node, std::string field,
                  std::vector<std::string> value_set,
                  bool allow_default = false, std::string default_value = "");
  /** For the bool type, only an existance and type check is performed. */
  int nodeChecker(YAML::Node node, std::string field,
                  bool allow_default = false, bool default_value = false);
  /** For integer types, either a match against a given set ("value_set") of
   * values or adherence to a defined inclusive bounds must be fulfilled as an
   * additional requirement (controlled by the "bounds" parameter). When chosen,
   * an empty value_set disables the matching requirement. An additional
   * "expected" parameter is used to supply a value from the ExpectedValue
   * namespace as to correctly format outputs. */
  template <typename T = int>
  int nodeChecker(YAML::Node node, std::string field, std::vector<T> value_set,
                  bool bounds, uint8_t expected, bool allow_default = false,
                  T default_value = 0);

  /** The YAML formatted config file. */
  YAML::Node configFile;

  /** The string containing information about missing config fields. */
  std::string missing;

  /** The string containing information about invalid values. */
  std::string invalid;
};  // namespace ModelConfig

}  // namespace simeng