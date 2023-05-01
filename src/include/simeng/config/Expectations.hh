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

#include "simeng/config/yaml/ryml.hh"

#define DEFAULT_CONFIG                                                         \
  ("{Core: {ISA: AArch64, Simulation-Mode: inorderpipelined, "                 \
   "Clock-Frequency: 2.5, Timer-Frequency: 100, Micro-Operations: True, "      \
   "Vector-Length: 512, Streaming-Vector-Length: 512}, Fetch: "                \
   "{Fetch-Block-Size: 32, Loop-Buffer-Size: 64, Loop-Detection-Threshold: "   \
   "4}, Process-Image: {Heap-Size: 10485760, Stack-Size: 1048576}, "           \
   "Register-Set: {GeneralPurpose-Count: 154, FloatingPoint/SVE-Count: 90, "   \
   "Predicate-Count: 17, Conditional-Count: 128, Matrix-Count: 2}, "           \
   "Pipeline-Widths: {Commit: 4, FrontEnd: 4, LSQ-Completion: 2}, "            \
   "Queue-Sizes: {ROB: 180, Load: 64, Store: 36}, Branch-Predictor: "          \
   "{BTB-Tag-Bits: 11, Saturating-Count-Bits: 2, Global-History-Length: 10, "  \
   "RAS-entries: 5, Fallback-Static-Predictor: 2}, L1-Data-Memory: "           \
   "{Interface-Type: Flat}, L1-Instruction-Memory: {Interface-Type: Flat}, "   \
   "LSQ-L1-Interface: {Access-Latency: 4, Exclusive: False, Load-Bandwidth: "  \
   "32, Store-Bandwidth: 16, Permitted-Requests-Per-Cycle: 2, "                \
   "Permitted-Loads-Per-Cycle: 2, Permitted-Stores-Per-Cycle: 1}, Ports: "     \
   "{'0': {Portname: Port 0, Instruction-Group-Support: [1, 8, 14]}, '1': "    \
   "{Portname: Port 1, Instruction-Group-Support: [0, 14]}, '2': {Portname: "  \
   "Port 2, Instruction-Group-Support: [1, 8, 71]}, '3': {Portname: Port 4, "  \
   "Instruction-Group-Support: [67]}, '4': {Portname: Port 5, "                \
   "Instruction-Group-Support: [67]}, '5': {Portname: Port 3, "                \
   "Instruction-Group-Support: [70]}}, Reservation-Stations: {'0': {Size: "    \
   "60, Dispatch-Rate: 4, Ports: [0, 1, 2, 3, 4, 5]}}, Execution-Units: "      \
   "{'0': {Pipelined: true}, '1': {Pipelined: true}, '2': {Pipelined: true}, " \
   "'3': {Pipelined:true}, '4': {Pipelined: true}, '5': {Pipelined: true}}, "  \
   "CPU-Info: {Generate-Special-Dir: false, Core-Count: 1, Socket-Count: 1, "  \
   "SMT: 1, BogoMIPS: 200.00, Features: fp asimd evtstrm atomics cpuid, "      \
   "CPU-Implementer: 0x0, CPU-Architecture: 0, CPU-Variant: 0x0, CPU-Part: "   \
   "0x0, CPU-Revision: 0, Package-Count: 1}}")

namespace simeng {
namespace config {

/** An enum containing all supported data types that can be expected of a config
 * option. */
enum ExpectedType { Bool, Float, Integer, String, UInteger, Valueless };

/** A class to hold the expectations of a specific config option. Each class
 * is considered to be one node of a tree-like structure which maps onto the
 * hierarchical YAML structure of the passed/generated config file. Each node
 * can contain any number of children, each of which is another instance of the
 * `expectationNode` class for another config option. The expectation placed on
 * each config option can be defined as a type, a set of values to which it must
 * belong, and a set of bounds it must lie between. A default value is also
 * expected for the sake of default construction and generation of default
 * config files. The values of such expectations are held within a
 * `std::variant` which can hold one of the expected data types equivalent to
 * that held in the `ExpectedType` enum. */
class expectationNode {
  using dataTypeVariant =
      std::variant<bool, float, int64_t, std::string, uint64_t>;

 public:
  expectationNode(){};

  ~expectationNode(){};

  /** A templated function to allow for the creation of an `expectationNode`
   * instance. The instance created is one with a value and a key. A key,
   * default value, type, and a flag denoting whether the node is optional are
   * provided to the underlying constructor. */
  template <typename T, bool optional = false>
  expectationNode create(std::string key, T defaultValue) {
    dataTypeVariant defValVariant = defaultValue;
    ExpectedType type = static_cast<ExpectedType>(defValVariant.index());
    // The instance created must have a value so ensure the passed type reflects
    // requirement
    if (type == ExpectedType::Valueless) {
      std::cerr << "[SimEng:ModelConfig] Cannot create a node with a default "
                   "value and an expected "
                   "type of `Valueless`"
                << std::endl;
      exit(1);
    }
    expectationNode node = expectationNode(key, type, optional);
    node.setDefaultValue(defValVariant);
    return node;
  }

  /** A templated function to allow for the creation of an `expectationNode`
   * instance. The instance created is one with only a key. A key and a flag
   * denoting whether the node is optional are provided to the underlying
   * constructor. */
  template <bool optional = false>
  expectationNode create(std::string key) {
    expectationNode node =
        expectationNode(key, ExpectedType::Valueless, optional);
    return node;
  }

  /** A getter function to retrieve the key of a node. */
  std::string getKey() const { return nodeKey_; }

  /** A getter function to retrieve the held default value of a node. */
  template <typename T>
  T getDefault() const {
    return getByType<T>(defaultValue_);
  }

  /** A getter function to retrieve the value type of a node. */
  ExpectedType getType() const { return type_; }

  /** A getter function to retrieve the child expectationNode instances of this
   * node. */
  std::vector<expectationNode> getChildren() const { return nodeChildren_; }

  /** A getter function to retrieve whether the expectations should be applied
   * to a sequence of config values. */
  bool isSequence() const { return isSequence_; }

  /** A getter function to retrieve whether the node is wild. */
  bool isWild() const { return isWild_; }

  /** A utility function used by the class to get a value from a `std::variant`
   * with error handling if the passed type is not currently stored. */
  template <typename T>
  T getByType(const dataTypeVariant& variant) const {
    // Value existence check
    if (variant.valueless_by_exception()) {
      std::cerr << "[SimEng:ModelConfig] No value in passed variant within "
                   "expectationNode with key "
                << nodeKey_ << std::endl;
      exit(1);
    }
    // Value type check
    if (!std::holds_alternative<T>(variant)) {
      std::cerr << "[SimEng:ModelConfig] Value of given type not held in "
                   "variant within expectationNode with key "
                << nodeKey_ << ". Variant holds a "
                << typeToString(variant.index())
                << " and the expected type of this node is "
                << typeToString(type_) << "." << std::endl;
      exit(1);
    }
    return std::get<T>(variant);
  }

  /** A utility function for converting the type held in dataTypeVariant or the
   * value of type_ into a string via an index. */
  std::string typeToString(size_t index) const {
    switch (index) {
      case 0:
        return "bool";
      case 1:
        return "float";
      case 2:
        return "integer";
      case 3:
        return "string";
      case 4:
        return "unsigned integer";
    }
    return "unknown";
  }

  /** Setter function to set the default value for this node's associated config
   * option. */
  void setDefaultValue(dataTypeVariant var) { defaultValue_ = var; }

  /** Setter function to set the expected bounds for this node's associated
   * config option. */
  template <typename T>
  void setValueBounds(T lower, T upper) {
    definedBounds_ = true;
    expectedBounds_.first = lower;
    expectedBounds_.second = upper;
  }

  /** Setter function to set the expected set of values for this node's
   * associated config option. */
  template <typename T>
  void setValueSet(std::vector<T> set) {
    definedSet_ = true;
    for (const T s : set) {
      dataTypeVariant dtv = s;
      expectedSet_.push_back(dtv);
    }
  }

  /** Add a child node to the vector of children within this node. */
  void addChild(expectationNode chld) { nodeChildren_.push_back(chld); }

  /** A setter function which denotes this node's expectations should be applied
   * to a sequence of config values. */
  void setAsSequence() { isSequence_ = true; }

  /** An intermediary function which sets the expectations that the passed
   * config option should be checked against. */
  std::string validateConfigNode(ryml::NodeRef node) {
    // If the node is a wild, then only a key will exist in the validation
    // check
    if (isWild_) {
      std::string retStr = "Success";
      if (!node.has_key()) {
        retStr = "has no key";
      }
      return retStr;
    } else {
      // Continue to validate the passed config option based on the held
      // expected type
      switch (type_) {
        case ExpectedType::Bool:
          return validateConfigNodeWithType<bool>(node);
        case ExpectedType::Float:
          return validateConfigNodeWithType<float>(node);
        case ExpectedType::Integer:
          return validateConfigNodeWithType<int64_t>(node);
        case ExpectedType::String:
          return validateConfigNodeWithType<std::string>(node);
        case ExpectedType::UInteger:
          return validateConfigNodeWithType<uint64_t>(node);
        case ExpectedType::Valueless: {
          // If the node has no value, then only a key will exist in the
          // validation check
          std::string retStr = "Success";
          if (!node.has_key() && !isOptional_) {
            retStr = "has no key";
          }
          return retStr;
        }
      }
    }
  }

  /** A function to validate a passed config option against held expectations.
   */
  template <typename T>
  std::string validateConfigNodeWithType(ryml::NodeRef node) {
    std::string retStr = "Success";
    // Value existence check
    if (!node.has_val()) {
      // If the node is optional, fill in the missing config value with held
      // default value
      if (isOptional_) {
        node << getByType<T>(defaultValue_);
      } else {
        retStr = "has no value";
        return retStr;
      }
    }

    // Read as check
    T nodeVal;
    node >> nodeVal;

    if (definedSet_) {
      // Check for value in set
      bool foundInSet = false;
      for (int i = 0; i < expectedSet_.size(); i++) {
        if (getByType<T>(expectedSet_[i]) == nodeVal) {
          foundInSet = true;
          break;
        }
      }
      if (!foundInSet) {
        node >> retStr;
        retStr += " not in set";
      }
    }

    if (definedBounds_) {
      // Check for value between bounds
      if (getByType<T>(expectedBounds_.first) > nodeVal ||
          getByType<T>(expectedBounds_.second) < nodeVal) {
        node >> retStr;
        retStr = " not in bounds";
      }
    }

    return retStr;
  }

  /** Search through the held children to find a node with the key `childKey`.
   * If no `childKey` can be found, then it is considered to be fatal for the
   * simulation. However, if a wild node is present within the children,
   * then return said child. */
  expectationNode& operator[](std::string childKey) {
    int wildIndex = -1;
    // Search children for childKey and record latest wildcard children
    for (size_t chld = 0; chld < nodeChildren_.size(); chld++) {
      if (nodeChildren_[chld].getKey() == childKey)
        return nodeChildren_[chld];
      else if (nodeChildren_[chld].getKey() == "*")
        wildIndex = chld;
    }

    // If no child was found but a wild node exists, return the wild child node
    if (wildIndex != -1) return nodeChildren_[wildIndex];

    std::cerr
        << "[SimEng:ModelConfig] Tried to access a config node that does not "
           "exist, namely \""
        << childKey << "\" in parent node \"" << nodeKey_ << "\"" << std::endl;
    exit(1);
  }

 private:
  /** Constructor for expectationNode instances. */
  expectationNode(std::string key, ExpectedType type, bool optional)
      : nodeKey_(key), type_(type), isOptional_(optional) {
    if (nodeKey_ == "*") isWild_ = true;
  }

  /** The key of this node used for indexing the tree-like expectationNode
   * structure. */
  std::string nodeKey_ = "INVALID";

  /** The expected value type this node places on it associated config option.
   */
  ExpectedType type_ = ExpectedType::Valueless;

  /** Whether the config option associated with this node is optional. */
  bool isOptional_ = false;

  /** Whether the config option associated with this node is a sequence. If
   * true, then the config values lower in the YAML hierarchy from the
   * associated config option are a sequence of values (a set of values with no
   * key). All values are validated against this node's expectations. */
  bool isSequence_ = false;

  /** Whether this instance of expectationNode is wild. If true, then when
   * indexing this instance of expectationNode, any passed key will match. This
   * is primarily used when one config option has many "child" values or YAML
   * structures which follow the same pattern. */
  bool isWild_ = false;

  /** The default value for the associated config option. */
  dataTypeVariant defaultValue_;

  /** Whether a value set has been defined as part of the expectation for the
   * associated config option. */
  bool definedSet_ = false;

  /** The set of values the associated config option is expected to belong to.
   */
  std::vector<dataTypeVariant> expectedSet_;

  /** Whether a value bounds have been defined as part of the expectation for
   * the associated config option. */
  bool definedBounds_ = false;

  /** The value bounds the associated config option is expected to lie between.
   */
  std::pair<dataTypeVariant, dataTypeVariant> expectedBounds_;

  /** The instances of expectationNode's held within this node. Considered to be
   * the children of this node. */
  std::vector<expectationNode> nodeChildren_;
};

}  // namespace config
}  // namespace simeng