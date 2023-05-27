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
#include <type_traits>
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

/** An enum containing all supported data types that can be expected of a
 * config option. */
enum class ExpectedType {
  Bool,
  Double,
  Float,
  Integer,
  String,
  UInteger,
  Valueless
};

/** String to represent a wildcard node key. */
const std::string wildcard = "*";

/** A struct to hold whether the validation was an error and an accompanying
 * outcome message. */
struct ValidationResult {
  bool errored;
  std::string message;
};

/** A class to hold the expectations of a specific config option. Each class
 * is considered to be one node of a tree-like structure which maps onto the
 * hierarchical YAML structure of the passed/generated config file. Each node
 * can contain any number of children, each of which is another instance of the
 * `ExpectationNode` class for another config option. The expectation placed on
 * each config option can be defined as a type, a set of values to which it must
 * belong, and a set of bounds it must lie between. A default value is also
 * expected for the sake of default construction and generation of default
 * config files. The values of such expectations are held within a
 * `std::variant` which can hold one of the expected data types equivalent to
 * that held in the `ExpectedType` enum. */
class ExpectationNode {
 public:
  using DataTypeVariant =
      std::variant<bool, double, float, int64_t, std::string, uint64_t>;

  /** A templated struct to store a boolean value denoting whether a passed
   * typename T belongs to one types represented in ExpectedType. */
  template <typename T>
  struct is_expected_type
      : std::integral_constant<bool, std::is_same<bool, T>::value ||
                                         std::is_same<double, T>::value ||
                                         std::is_same<float, T>::value ||
                                         std::is_same<int64_t, T>::value ||
                                         std::is_same<std::string, T>::value ||
                                         std::is_same<uint64_t, T>::value> {};

  /** A templated function to allow for the creation of an `ExpectationNode`
   * instance. The instance created is one with a value and a key. A default
   * value, key, type, and a bool denoting whether the node is optional are
   * provided to the underlying constructor. */
  template <typename T>
  static ExpectationNode createExpectation(T defaultValue, std::string key,
                                           bool optional = false) {
    // Ensure templated type is of an expected type
    static_assert(is_expected_type<T>::value &&
                  "[SimEng:ModelConfig] Unexpected type given to "
                  "ExpectationNode::create");
    DataTypeVariant defValVariant = defaultValue;
    ExpectedType type = static_cast<ExpectedType>(defValVariant.index());
    ExpectationNode node = ExpectationNode(key, type, optional);
    node.setDefaultValue(defValVariant);
    return node;
  }

  /** A templated function to allow for the creation of an `ExpectationNode`
   * instance with a key but no associated value. A key and a bool denoting
   * whether the node is optional are provided to the underlying constructor. */
  static ExpectationNode createExpectation(std::string key,
                                           bool optional = false) {
    ExpectationNode node =
        ExpectationNode(key, ExpectedType::Valueless, optional);
    return node;
  }

  /** Constructor for ExpectationNode instances. */
  ExpectationNode(std::string key, ExpectedType type, bool optional)
      : nodeKey_(key), type_(type), isOptional_(optional) {
    if (nodeKey_ == wildcard) isWild_ = true;
  }

  ExpectationNode(){};

  ~ExpectationNode(){};

  /** A getter function to retrieve the key of a node. */
  std::string getKey() const { return nodeKey_; }

  /** A getter function to retrieve the held default value of a node. */
  template <typename T>
  T getDefault() const {
    return getByType<T>(defaultValue_);
  }

  /** A getter function to retrieve the value type of a node. */
  ExpectedType getType() const { return type_; }

  /** A getter function to retrieve the child ExpectationNode instances of this
   * node. */
  std::vector<ExpectationNode> getChildren() const { return nodeChildren_; }

  /** A getter function to retrieve whether the expectations should be applied
   * to a sequence of config values. */
  bool isSequence() const { return isSequence_; }

  /** A getter function to retrieve whether the node is wild. */
  bool isWild() const { return isWild_; }

  /** A utility function used by the class to get a value from a `std::variant`
   * with error handling if the passed type is not currently stored. */
  template <typename T>
  T getByType(const DataTypeVariant& variant) const {
    // Ensure templated type is of an expected type
    static_assert(is_expected_type<T>::value &&
                  "[SimEng:ModelConfig] Unexpected type given to "
                  "ExpectationNode::getByType");

    // Value existence check
    if (variant.valueless_by_exception()) {
      std::cerr << "[SimEng:ModelConfig] No value in passed variant within "
                   "ExpectationNode with key "
                << nodeKey_ << std::endl;
      exit(1);
    }
    // Value type check
    if (!std::holds_alternative<T>(variant)) {
      std::cerr << "[SimEng:ModelConfig] A value of given type not held in "
                   "variant within ExpectationNode with key "
                << nodeKey_ << ". Variant holds a "
                << typeToString(variant.index())
                << " and the expected type of this node is "
                << typeToString(static_cast<size_t>(type_)) << "." << std::endl;
      exit(1);
    }
    return std::get<T>(variant);
  }

  /** A utility function for converting the type held in DataTypeVariant or the
   * value of type_ into a string via an index. */
  std::string typeToString(size_t index) const {
    switch (index) {
      case static_cast<size_t>(ExpectedType::Bool):
        return "bool";
      case static_cast<size_t>(ExpectedType::Double):
        return "double";
      case static_cast<size_t>(ExpectedType::Float):
        return "float";
      case static_cast<size_t>(ExpectedType::Integer):
        return "integer";
      case static_cast<size_t>(ExpectedType::String):
        return "string";
      case static_cast<size_t>(ExpectedType::UInteger):
        return "unsigned integer";
    }
    return "unknown";
  }

  /** Setter function to set the default value for this node's associated config
   * option. */
  void setDefaultValue(DataTypeVariant var) { defaultValue_ = var; }

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
      DataTypeVariant dtv = s;
      expectedSet_.push_back(dtv);
    }
  }

  /** Add a child node to the vector of children within this node. */
  void addChild(ExpectationNode chld) {
    // Ensure that if the new child is wild, one does not already exist in this
    // instance's children
    if (chld.getKey() == wildcard) {
      if (hasWild_) {
        std::cerr << "[SimEng:ModelConfig] Attempted to add multiple wild "
                     "nodes to the same ExpectationNode instance of key "
                  << nodeKey_ << std::endl;
        exit(1);
      }
      hasWild_ = true;
    }
    nodeChildren_.push_back(chld);
  }

  /** A setter function which denotes this node's expectations should be applied
   * to a sequence of config values. */
  void setAsSequence() { isSequence_ = true; }

  /** An intermediary function which sets the expectations that the passed
   * config option should be checked against. */
  ValidationResult validateConfigNode(ryml::NodeRef node) {
    // If the node is a wild, then only a key will exist in the validation
    // check
    if (isWild_) {
      if (!node.has_key()) {
        return {true, "has no key"};
      }
      return {false, "Success"};
    } else {
      // Continue to validate the passed config option based on the held
      // expected type
      switch (type_) {
        case ExpectedType::Bool:
          return validateConfigNodeWithType<bool>(node);
        case ExpectedType::Double:
          return validateConfigNodeWithType<double>(node);
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
          if (!node.has_key() && !isOptional_) {
            return {true, "has no key"};
          }
          return {false, "Success"};
        }
      }
    }
  }

  /** A function to validate a passed config option against held expectations.
   */
  template <typename T>
  ValidationResult validateConfigNodeWithType(ryml::NodeRef node) {
    // Value existence check
    if (!node.has_val()) {
      // If the node is optional, fill in the missing config
      // value with held default value
      if (isOptional_) {
        // If the node is a sequence, add the default value to a new child
        if (isSequence_) {
          node |= ryml::SEQ;
          node = node.append_child() << getByType<T>(defaultValue_);
        } else {
          node << getByType<T>(defaultValue_);
        }
      } else {
        return {true, "has no value"};
      }
    }

    // Read as check
    T nodeVal;
    node >> nodeVal;

    std::ostringstream retStr;

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
        // Construct a human readable output denoted expected set failure
        retStr << nodeVal << " not in set {";
        for (int i = 0; i < expectedSet_.size(); i++) {
          retStr << getByType<T>(expectedSet_[i]);
          if (i < expectedSet_.size() - 1) retStr << ", ";
        }
        retStr << "}";
        return {true, retStr.str()};
      }
    }

    if (definedBounds_) {
      // Check for value between bounds
      if (getByType<T>(expectedBounds_.first) > nodeVal ||
          getByType<T>(expectedBounds_.second) < nodeVal) {
        // Construct a human readable output denoted expected bounds failure
        retStr << nodeVal << " not in the bounds {"
               << getByType<T>(expectedBounds_.first) << " to "
               << getByType<T>(expectedBounds_.second) << "}";
        return {true, retStr.str()};
      }
    }

    return {false, "Success"};
  }

  /** Search through the held children to find a node with the key `childKey`.
   * If no `childKey` can be found, then it is considered to be fatal for the
   * simulation. However, if a wild node is present within the children,
   * then return said child. */
  ExpectationNode& operator[](std::string childKey) {
    int wildIndex = -1;
    // Search children for childKey and record latest wildcard children
    for (size_t chld = 0; chld < nodeChildren_.size(); chld++) {
      if (nodeChildren_[chld].getKey() == childKey)
        return nodeChildren_[chld];
      else if (nodeChildren_[chld].getKey() == wildcard)
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
  /** The key of this node used for indexing the tree-like ExpectationNode
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

  /** Whether this instance of ExpectationNode is wild. If true, then when
   * indexing this instance of ExpectationNode, any passed key will match. This
   * is primarily used when one config option has many "child" values or YAML
   * structures which follow the same pattern. */
  bool isWild_ = false;

  /** Whether this instance of ExpectationNode has a child node which is wild.
   * Each parent node can only have one wild node in its children. */
  bool hasWild_ = false;

  /** The default value for the associated config option. */
  DataTypeVariant defaultValue_;

  /** Whether a value set has been defined as part of the expectation for the
   * associated config option. */
  bool definedSet_ = false;

  /** The set of values the associated config option is expected to belong to.
   */
  std::vector<DataTypeVariant> expectedSet_;

  /** Whether a value bounds have been defined as part of the expectation for
   * the associated config option. */
  bool definedBounds_ = false;

  /** The value bounds the associated config option is expected to lie between.
   */
  std::pair<DataTypeVariant, DataTypeVariant> expectedBounds_;

  /** The instances of ExpectationNode's held within this node. Considered to be
   * the children of this node. */
  std::vector<ExpectationNode> nodeChildren_;
};

}  // namespace config
}  // namespace simeng