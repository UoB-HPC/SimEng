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

namespace simeng {
namespace config {

/** An enum containing all supported data types that can be expected of a
 * config option.
 * NOTE: The index of the ExpectedType enum matches that of
 * ExpectationNode::DataTypeVariant.
 */
enum class ExpectedType {
  Bool,
  Double,
  Float,
  Integer8,
  Integer16,
  Integer32,
  Integer64,
  String,
  UInteger8,
  UInteger16,
  UInteger32,
  UInteger64,
  Valueless
};

/** The string used to represent a wildcard node as described in the comment
 * above class ExpectationNode. */
const std::string wildcard = "*";

/** A struct to hold whether the validation was valid and an accompanying
 * outcome message. */
struct ValidationResult {
  bool valid;
  std::string message;
};

/** A class to hold the expectations of a specific config option. Each instance
 * is considered to be one node of a tree-like structure which maps onto the
 * hierarchical YAML structure of the passed/generated config file. Each node
 * can contain any number of children, each of which is another instance of the
 * `ExpectationNode` class for another config option. The expectation placed on
 * each config option can be defined as a type, a set of values to which it must
 * belong, and a set of bounds it must lie between. A default value is also
 * expected for the sake of default construction and generation of default
 * config files. The values of such expectations are held within a
 * `std::variant` which can hold one of the expected data types equivalent to
 * that held in the `ExpectedType` enum.
 *
 * The notion of a wildcard node is implemented to allow for expectations to
 * be placed on a set of nodes. Rather than specifing the specific node name
 * string, a wildcard string variable can be used to denote any possible node
 * name. An example is given below:
 *
 *                  |--["child_0"]-["value_node_A"]
 * ["parent_node"]--|--["child_1"]-["value_node_B"]
 *                  |--["child_2"]-["value_node_C"]
 *
 * can be represented by
 *
 *                             |--["value_node_A"]
 * ["parent_node"]-[wildcard]--|--["value_node_B"]
 *                             |--["value_node_C"]
 */
class ExpectationNode {
 public:
  /** NOTE: The index of the ExpectedType enum matches that of
   * ExpectationNode::DataTypeVariant.
   */
  using DataTypeVariant =
      std::variant<bool, double, float, int8_t, int16_t, int32_t, int64_t,
                   std::string, uint8_t, uint16_t, uint32_t, uint64_t>;

  /** A templated struct to store a boolean value denoting whether a passed
   * typename T belongs to one types represented in ExpectedType. */
  template <typename T>
  struct is_expected_type
      : std::integral_constant<bool, std::is_same<bool, T>::value ||
                                         std::is_same<double, T>::value ||
                                         std::is_same<float, T>::value ||
                                         std::is_same<int8_t, T>::value ||
                                         std::is_same<int16_t, T>::value ||
                                         std::is_same<int32_t, T>::value ||
                                         std::is_same<int64_t, T>::value ||
                                         std::is_same<std::string, T>::value ||
                                         std::is_same<uint8_t, T>::value ||
                                         std::is_same<uint16_t, T>::value ||
                                         std::is_same<uint32_t, T>::value ||
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
                  "[SimEng:ExpectationNode] Unexpected type given to "
                  "ExpectationNode::createExpectation");
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

  /** Default constructor. Used primarily to provide a root node for populated
   * ExpectationNode instances to be added to. */
  ExpectationNode(){};

  ~ExpectationNode(){};

  /** A getter function to retrieve the key of a node. */
  std::string getKey() const { return nodeKey_; }

  /** A setter function to create the hierarchy key of this node, prefixed by
   * the key sent from a parent node. */
  void setHierarchyKey(std::string hKey) {
    // If a non-blank key is passed, prefix this instances hierarchyKey_ with it
    if (hKey != "") hierarchyKey_ = hKey + ":" + nodeKey_;
    // Don't consider "INVALID" node keys when constructing a hierarchyKey_
    else if (nodeKey_ != "INVALID")
      hierarchyKey_ = nodeKey_;
  }

  /** A getter function to retrieve the held default value of a node. */
  template <typename T>
  T getDefault() const {
    return getByType<T>(defaultValue_);
  }

  /** A getter function to retrieve the value type of a node. */
  ExpectedType getType() const { return type_; }

  /** A getter function to retrieve the child ExpectationNode instances of this
   * node. */
  const std::vector<ExpectationNode>& getChildren() const {
    return nodeChildren_;
  }

  /** A getter function to retrieve whether the expectations should be applied
   * to a sequence of config values. */
  bool isSequence() const { return isSequence_; }

  /** A getter function to retrieve whether the node is a wildcard. */
  bool isWildcard() const { return isWildcard_; }

  /** Setter function to set the expected bounds for this node's associated
   * config option. */
  template <typename T>
  void setValueBounds(T lower, T upper) {
    // Value type check
    DataTypeVariant valCheck = lower;
    if (valCheck.index() != static_cast<size_t>(type_)) {
      std::cerr
          << "[SimEng:ExpectationNode] The data type of the passed "
             "value bounds used in setValueBounds() does not match that held "
             "within the ExpectationNode with key "
          << hierarchyKey_ << ". Passed bounds are of type "
          << typeToString(valCheck.index())
          << " and the expected type of this node is "
          << typeToString(static_cast<size_t>(type_)) << "." << std::endl;
      exit(1);
    }
    // Ensure an expectation set hasn't already been defined for this node
    if (definedSet_) {
      std::cerr
          << "[SimEng:ExpectationNode] Invalid call of setValueBounds() for "
             "the ExpectationNode with key "
          << hierarchyKey_ << " as a value set has already been defined."
          << std::endl;
      exit(1);
    }

    definedBounds_ = true;
    expectedBounds_.first = lower;
    expectedBounds_.second = upper;
  }

  /** Setter function to set the expected set of values for this node's
   * associated config option. */
  template <typename T>
  void setValueSet(std::vector<T> set) {
    // Value type check
    if (set.size()) {
      T val = set[0];
      DataTypeVariant valCheck = val;
      if (valCheck.index() != static_cast<size_t>(type_)) {
        std::cerr << "[SimEng:ExpectationNode] The data type of the passed "
                     "vector used in setValueSet() does not match that held "
                     "within the ExpectationNode with key "
                  << hierarchyKey_ << ". Passed vector elements are of type "
                  << typeToString(valCheck.index())
                  << " and the expected type of this node is "
                  << typeToString(static_cast<size_t>(type_)) << "."
                  << std::endl;
        exit(1);
      }
    }
    // Ensure expectation bounds haven't already been defined for this node
    if (definedBounds_) {
      std::cerr << "[SimEng:ExpectationNode] Invalid call of setValueSet() for "
                   "the ExpectationNode with key "
                << hierarchyKey_
                << " as value bounds have already been defined." << std::endl;
      exit(1);
    }

    definedSet_ = true;
    for (const T& s : set) {
      DataTypeVariant dtv = s;
      expectedSet_.push_back(dtv);
    }
  }

  /** A setter function which denotes this node's expectations should be applied
   * to a sequence of config values. */
  void setAsSequence() { isSequence_ = true; }

  /** Add a child node to the vector of children within this node. */
  void addChild(ExpectationNode child) {
    // Ensure that if the new child is a wildcard node, one does not already
    // exist in this instance's children
    if (child.getKey() == wildcard) {
      if (hasWildcard_) {
        std::cerr
            << "[SimEng:ExpectationNode] Attempted to add multiple wildcard "
               "nodes to the same ExpectationNode instance of key "
            << hierarchyKey_ << std::endl;
        exit(1);
      }
      hasWildcard_ = true;
    }
    nodeChildren_.push_back(child);

    // Set hierarchy key of child
    nodeChildren_.back().setHierarchyKey(hierarchyKey_);
  }

  /** An intermediary function which sets the expectations that the passed
   * config option should be checked against. */
  ValidationResult validateConfigNode(ryml::NodeRef node) const {
    // If the node is a wildcard, then only a key will exist in the validation
    // check
    if (isWildcard_) {
      if (!node.has_key()) {
        return {false, "has no key"};
      }
      return {true, "Success"};
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
        case ExpectedType::Integer8:
          return validateConfigNodeWithType<int8_t>(node);
        case ExpectedType::Integer16:
          return validateConfigNodeWithType<int16_t>(node);
        case ExpectedType::Integer32:
          return validateConfigNodeWithType<int32_t>(node);
        case ExpectedType::Integer64:
          return validateConfigNodeWithType<int64_t>(node);
        case ExpectedType::String:
          return validateConfigNodeWithType<std::string>(node);
        case ExpectedType::UInteger8:
          return validateConfigNodeWithType<uint8_t>(node);
        case ExpectedType::UInteger16:
          return validateConfigNodeWithType<uint16_t>(node);
        case ExpectedType::UInteger32:
          return validateConfigNodeWithType<uint32_t>(node);
        case ExpectedType::UInteger64:
          return validateConfigNodeWithType<uint64_t>(node);
        case ExpectedType::Valueless: {
          // If the node has no value, then only a key will exist in the
          // validation check
          if (!node.has_key() && !isOptional_) {
            return {false, "has no key"};
          }
          return {true, "Success"};
        }
        default:
          std::cerr << "[SimEng:validateConfigNode] Unexpected ExpectedType"
                    << std::endl;

          exit(-1);
      }
    }
  }

  /** Search through the held children to find a node with the key `childKey`.
   * If no `childKey` can be found, then it is considered to be fatal for the
   * simulation. However, if a wildcard node is present within the children,
   * then return said child. */
  ExpectationNode& operator[](std::string childKey) {
    int wildcardIndex = -1;
    // Search children for childKey and record latest wildcard children
    for (size_t child = 0; child < nodeChildren_.size(); child++) {
      if (nodeChildren_[child].getKey() == childKey)
        return nodeChildren_[child];
      else if (nodeChildren_[child].getKey() == wildcard)
        wildcardIndex = child;
    }

    // If no child was found but a wildcard node exists, return the wildcard
    // child node
    if (wildcardIndex != -1) return nodeChildren_[wildcardIndex];

    std::cerr << "[SimEng:ExpectationNode] Tried to access a config node that "
                 "does not exist, namely \""
              << childKey << "\" in parent node \"" << nodeKey_ << "\""
              << std::endl;
    exit(1);
  }

 private:
  /** Constructor for ExpectationNode instances. */
  ExpectationNode(std::string key, ExpectedType type, bool optional)
      : nodeKey_(key), type_(type), isOptional_(optional) {
    if (nodeKey_ == wildcard) isWildcard_ = true;
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
      case static_cast<size_t>(ExpectedType::Integer8):
        return "8-bit integer";
      case static_cast<size_t>(ExpectedType::Integer16):
        return "16-bit integer";
      case static_cast<size_t>(ExpectedType::Integer32):
        return "32-bit integer";
      case static_cast<size_t>(ExpectedType::Integer64):
        return "64-bit integer";
      case static_cast<size_t>(ExpectedType::String):
        return "string";
      case static_cast<size_t>(ExpectedType::UInteger8):
        return "8-bit unsigned integer";
      case static_cast<size_t>(ExpectedType::UInteger16):
        return "16-bit unsigned integer";
      case static_cast<size_t>(ExpectedType::UInteger32):
        return "32-bit unsigned integer";
      case static_cast<size_t>(ExpectedType::UInteger64):
        return "64-bit unsigned integer";
    }
    return "unknown";
  }

  /** Setter function to set the default value for this node's associated config
   * option. */
  void setDefaultValue(DataTypeVariant var) {
    if (var.index() != static_cast<size_t>(type_)) {
      std::cerr
          << "[SimEng:ExpectationNode] A DataTypeVariant used to set the "
             "default value is not of type held within the ExpectationNode "
             "with key "
          << hierarchyKey_ << ". Variant holds a " << typeToString(var.index())
          << " and the expected type of this node is "
          << typeToString(static_cast<size_t>(type_)) << "." << std::endl;
      exit(1);
    }
    defaultValue_ = var;
  }

  /** A utility function used by the class to get a value from a `std::variant`
   * with error handling if the passed type is not currently stored. */
  template <typename T>
  T getByType(const DataTypeVariant& variant) const {
    // Ensure templated type is of an expected type
    static_assert(is_expected_type<T>::value &&
                  "[SimEng:ExpectationNode] Unexpected type given to "
                  "ExpectationNode::getByType");

    // Value existence check
    if (variant.valueless_by_exception()) {
      std::cerr << "[SimEng:ExpectationNode] No value in passed "
                   "DataTypeVariant within ExpectationNode with key "
                << hierarchyKey_ << std::endl;
      exit(1);
    }
    // Value type check
    if (!std::holds_alternative<T>(variant)) {
      std::cerr << "[SimEng:ExpectationNode] A value of given type not held in "
                   "variant within ExpectationNode with key "
                << hierarchyKey_ << ". Variant holds a "
                << typeToString(variant.index())
                << " and the expected type of this node is "
                << typeToString(static_cast<size_t>(type_)) << "." << std::endl;
      exit(1);
    }
    return std::get<T>(variant);
  }

  /** A function to validate a passed config option against held expectations.
   */
  template <typename T>
  ValidationResult validateConfigNodeWithType(ryml::NodeRef node) const {
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
          node << getDefault<T>();
        }
      } else {
        return {false, "has no value"};
      }
    }

    // Read as check
    T nodeVal = node.as<T>();

    std::ostringstream retStr;

    if (definedSet_) {
      // Check for value in set
      bool foundInSet = false;
      for (size_t i = 0; i < expectedSet_.size(); i++) {
        if (getByType<T>(expectedSet_[i]) == nodeVal) {
          foundInSet = true;
          break;
        }
      }
      if (!foundInSet) {
        // Construct a human-readable output denoted expected set failure
        retStr << nodeVal << " not in set {";
        for (size_t i = 0; i < expectedSet_.size(); i++) {
          retStr << getByType<T>(expectedSet_[i]);
          if (i < expectedSet_.size() - 1) retStr << ", ";
        }
        retStr << "}";
        return {false, retStr.str()};
      }
    }

    if (definedBounds_) {
      // Check for value between bounds
      if (getByType<T>(expectedBounds_.first) > nodeVal ||
          getByType<T>(expectedBounds_.second) < nodeVal) {
        // Construct a human-readable output denoted expected bounds failure
        retStr << nodeVal << " not in the bounds {"
               << getByType<T>(expectedBounds_.first) << " to "
               << getByType<T>(expectedBounds_.second) << "}";
        return {false, retStr.str()};
      }
    }

    return {true, "Success"};
  }

  /** The key of this node used for indexing the tree-like ExpectationNode
   * structure. */
  std::string nodeKey_ = "INVALID";

  /** The cumulatively constructed key of all connected nodes which came before
   * this instance. Primarily used for improved debugging when an errored
   * ExceptionNode instance is encountered. */
  std::string hierarchyKey_ = "";

  /** The expected value type this node places on it associated config option.
   */
  ExpectedType type_ = ExpectedType::Valueless;

  /** Whether the config option associated with this node is optional. */
  bool isOptional_ = false;

  /** Whether the config option associated with this node is a sequence. A
   * sequence is defined by a named config option having many values, for
   * example the below Instruction-Group-Support option is a sequence,
   *
   * Instruction-Group-Support:
   * - INT_SIMPLE
   * - INT_MUL
   * - STORE_DATA
   *
   * In this instance, the expectations set for the named node are applied to
   * all the values lower in the YAML hierarchy rather than just a single value.
   */
  bool isSequence_ = false;

  /** Whether this instance of ExpectationNode is a wildcard as described in the
   * comment above class ExpectationNode. */
  bool isWildcard_ = false;

  /** Whether this instance of ExpectationNode has a child node which is a
   * wildcard. Each parent node can only have one wildcard node in its children.
   */
  bool hasWildcard_ = false;

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
  // TODO needs initialisation in case validation called before setting. Unsure
  // whether this is a good solution
  std::pair<DataTypeVariant, DataTypeVariant> expectedBounds_ = {0, 0};

  /** The instances of ExpectationNodes held within this node. Considered to be
   * the children of this node. */
  std::vector<ExpectationNode> nodeChildren_;
};

}  // namespace config
}  // namespace simeng