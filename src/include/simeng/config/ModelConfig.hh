#pragma once

#include <math.h>

#include <algorithm>
#include <cassert>
#include <climits>
#include <fstream>
#include <iostream>
#include <queue>
#include <sstream>
#include <string>
#include <unordered_map>
#include <variant>

#include "simeng/config/Expectations.hh"
#include "simeng/config/yaml/ryml.hh"

namespace simeng {
namespace config {

// Forward declaration for SimInfo.
class SimInfo;

/** A class to correctly validate and format the provided
 * configuration YAML file. */
class ModelConfig {
 public:
  /** Construct a ModelConfig class by reading in the YAML file and
   * run it through validation and formatting. */
  ModelConfig(std::string path);

  /** Default constructor which creates a default configuration file. */
  ModelConfig();

  /** A getter function to retrieve the validated and formatted config file. */
  ryml::Tree getConfig();

  /** Re-generate the default config file based on the passed isa. */
  void reGenerateDefault(std::string isa);

  /** Append/replace config options within the held config file. */
  void addConfigOptions(std::string config);

  void recursivePrint(ryml::NodeRef node, int depth = 0) {
    for (ryml::NodeRef chld : node.children()) {
      for (int i = 0; i < depth; i++) std::cerr << "\t";
      if (chld.is_map()) {
        std::cerr << chld.key() << ": " << std::endl;
        recursivePrint(chld, depth + 1);
      } else if (chld.is_seq()) {
        std::cerr << chld.key() << ": " << std::endl;
        for (int i = 0; i < chld.num_children(); i++) {
          for (int i = 0; i < depth + 1; i++) std::cerr << "\t";
          std::cerr << "- " << chld[i].val() << std::endl;
        }
      } else {
        std::cerr << chld.key() << ": " << chld.val() << std::endl;
      }
    }
  }

 private:
  /** A utility function to construct a default config file and pass it through
   * validation and post-validation logic. */
  void generateDefault();

  /** Construct a default config file within `configTree_` from the default
   * value information held within `expectations`. A `root_id` is supplied as an
   * index for adding new config options to the `configTree` ryml::Tree. */
  void constructDefault(expectationNode expectations, size_t root_id);

  /** A utility function to recursively iterate over the passed NodeRef and its
   * children and add them to the held config file `configTree_`. A `id` is
   * supplied as an index for adding new config options to the `configTree`
   * ryml::Tree. */
  void recursiveAdd(ryml::NodeRef node, size_t id);

  /** Create the expectationNode tree-like structure `expectations_` which holds
   * all expectations on the values of passed/created config files. */
  void setExpectations(bool isDefault = false);

  /** A utility function to recursively iterate over all instances of
   * expectationNode in `expectations` and the values within the config file,
   * calling expectationNode validate functionality on each associated config
   * option. A `hierarchyString` is used for printouts concerning errored
   * validation. */
  void recursiveValidate(expectationNode expectation, ryml::NodeRef node,
                         std::string hierarchyString = "");

  /** A set of formatting and checks performed on the config file after its
   * validation is complete. */
  void postValidation();

  /** From a pre-defined vector of instruction group strings, instantiate an
   * ISA specific mapping between the instruction group strings and the
   * relevant instruction group namespace numbers. */
  void createGroupMapping();

  /** A representation of the YAML config file passed to the simulation or a
   * config file constructed from pre-defined default values. */
  ryml::Tree configTree_;

  /** The ISA currently being simulated. Various config options rely on the
   * knowledge of the ISA under simulation thus a variable is used to keep track
   * of its value. */
  std::string ISA_ = "AArch64";

  /** Whether the config file was created from default values. */
  bool isDefault_ = true;

  /** The first node of the tree-like structure containing the expectations of
   * all config options used within the simulation. */
  expectationNode expectations_ = expectationNode();

  /** The ISA specific vector of instruction group strings for matching
   * against user inputted groups. */
  std::vector<std::string> groupOptions_;

  /** ISA specific mapping between the defined instruction strings and the
   * instruction group variables. */
  std::unordered_map<std::string, uint16_t> groupMapping_;

  /** A string stream containing information about missing config
   * fields. */
  std::ostringstream missing_;

  /** A string stream containing information about invalid values. */
  std::ostringstream invalid_;
};  // namespace ModelConfig

}  // namespace config
}  // namespace simeng