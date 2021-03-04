#include "simeng/ModelConfig.hh"

namespace simeng {

ModelConfig::ModelConfig(std::string path) {
  // Ensure the file exists
  std::ifstream file(path);
  if (!file.is_open()) {
    std::cerr << "Could not read/parse " << path << std::endl;
    exit(1);
  }
  file.close();

  // Read in the config file
  configFile = YAML::LoadFile(path);

  // Check if the config file inherits values from a base config
  inherit();

  // Validate the inputted config file
  validate();
}

YAML::Node ModelConfig::getConfigFile() { return configFile; }

void ModelConfig::inherit() {
  // Check if the config file includes a inheritted file
  if (!configFile["Inherit-From"]) {
    return;
  } else {
    // TODO: Merge files
  }
  return;
}

void ModelConfig::validate() {
  // Loop through expected fields and ensure a valid value exists
  std::vector<std::string> subFields;
  std::string root = "";
  // Core
  root = "Core";
  subFields = {"Simulation-Mode", "Clock-Frequency", "Fetch-Block-Size"};
  nodeChecker(configFile[root][subFields[0]], subFields[0],
              {"emulation", "inorderpipelined", "outoforder"});
  nodeChecker<float>(configFile[root][subFields[1]], subFields[1], {0.f, 10.f},
                     true, ExpectedValue::Float);
  if (nodeChecker<uint16_t>(configFile[root][subFields[2]], subFields[2],
                            {4, UINT16_MAX}, true, ExpectedValue::UInteger)) {
    uint16_t block_size = configFile[root][subFields[2]].as<uint16_t>();
    // Ensure ftech block size is a power of 2
    if ((block_size & (block_size - 1)) == 0) {
      uint8_t alignment_bits = log2(block_size);
      configFile[root]["Fetch-Block-Alignment-Bits"] = unsigned(alignment_bits);
    } else {
      invalid += "\t- Fetch-Block-Size must be a power of 2\n";
    }
  }
  subFields.clear();

  // Branch-Predictor
  root = "Branch-Predictor";
  subFields = {"BTB-bitlength"};
  nodeChecker<uint8_t>(configFile[root][subFields[0]], subFields[0],
                       {1, UINT8_MAX}, true, ExpectedValue::UInteger);
  subFields.clear();

  // L1-Cache
  root = "L1-Cache";
  subFields = {"GeneralPurpose-Latency",
               "FloatingPoint-Latency",
               "SVE-Latency",
               "Bandwidth",
               "Permitted-Requests-Per-Cycle",
               "Permitted-Loads-Per-Cycle",
               "Permitted-Stores-Per-Cycle"};
  nodeChecker<uint16_t>(configFile[root][subFields[0]], subFields[0],
                        {1, UINT16_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<uint16_t>(configFile[root][subFields[1]], subFields[1],
                        {1, UINT16_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<uint16_t>(configFile[root][subFields[2]], subFields[2],
                        {1, UINT16_MAX}, true, ExpectedValue::UInteger, true,
                        1);
  nodeChecker<uint8_t>(configFile[root][subFields[3]], subFields[3],
                       {1, UINT8_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<uint8_t>(configFile[root][subFields[4]], subFields[4],
                       {1, UINT8_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<uint8_t>(configFile[root][subFields[5]], subFields[5],
                       {1, UINT8_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<uint8_t>(configFile[root][subFields[6]], subFields[6],
                       {1, UINT8_MAX}, true, ExpectedValue::UInteger);
  subFields.clear();

  // Ports
  std::vector<std::string> portNames;
  root = "Ports";
  size_t num_ports = configFile[root].size();
  if (!num_ports) {
    missing += ("\t- " + root + "\n");
  }
  for (size_t i = 0; i < num_ports; i++) {
    YAML::Node port_node = configFile[root][i];
    // Get port number into a string format
    char port_msg[10];
    sprintf(port_msg, "Port %zu ", i);
    std::string port_num = std::string(port_msg);
    // Check for existance of Portname field and record name
    if (nodeChecker(port_node["Portname"], port_num + "Portname",
                    std::vector<std::string>{})) {
      std::string name = port_node["Portname"].as<std::string>();
      // Ensure port name is unique
      if (std::find(portNames.begin(), portNames.end(), name) ==
          portNames.end()) {
        portNames.push_back(name);
      } else {
        invalid += ("\t- " + port_num + "name \"" + name + "\" already used\n");
      }
    }
    // Check for existance of Instruction-Support field
    if (!(port_node["Instruction-Support"].IsDefined()) ||
        port_node["Instruction-Support"].IsNull()) {
      missing += ("\t- " + port_num + "Instruction-Support\n");
      continue;
    }
    for (size_t j = 0; j < port_node["Instruction-Support"].size(); j++) {
      YAML::Node group = port_node["Instruction-Support"][j];
      // Get group number into a string format
      char group_msg[10];
      sprintf(group_msg, "Group %zu ", j);
      std::string group_num = std::string(group_msg);
      // Check for existance of Compulsory field
      if (!(group["Compulsory"].IsDefined()) || group["Compulsory"].IsNull()) {
        missing += ("\t- " + port_num + group_num + "Compulsory\n");
      }
      for (size_t k = 0; k < group["Compulsory"].size(); k++) {
        if (nodeChecker(group["Compulsory"][k],
                        port_num + group_num + "Compulsory", groupOptions)) {
          configFile["Ports"][i]["Instruction-Support"][j]["Compulsory"][k] =
              unsigned(group_mapping[group["Compulsory"][k].as<std::string>()]);
        }
      }
      // If optional instruction identifiers are defined within the group
      for (size_t k = 0; k < group["Optional"].size(); k++) {
        if (nodeChecker(group["Optional"][k], port_num + group_num + "Optional",
                        groupOptions)) {
          configFile["Ports"][i]["Instruction-Support"][j]["Optional"][k] =
              unsigned(group_mapping[group["Optional"][k].as<std::string>()]);
        }
      }
    }
  }

  // Reservation-Stations
  root = "Reservation-Stations";
  size_t num_rs = configFile[root].size();
  if (!num_rs) {
    missing += ("\t- " + root + "\n");
  }
  for (size_t i = 0; i < num_rs; i++) {
    YAML::Node rs = configFile[root][i];
    // Get rs number into a string format
    char rs_msg[25];
    sprintf(rs_msg, "Reservation Station %zu ", i);
    std::string rs_num = std::string(rs_msg);
    nodeChecker<uint16_t>(rs["Size"], rs_num + "Size", {1, UINT16_MAX}, true,
                          ExpectedValue::UInteger);
    // Check for existance of Ports field
    if (!(rs["Ports"].IsDefined()) || rs["Ports"].IsNull()) {
      missing += ("\t- " + rs_num + "Ports\n");
      continue;
    }
    for (size_t j = 0; j < rs["Ports"].size(); j++) {
      YAML::Node port_node = rs["Ports"][j];
      // Get port index into a string format
      char port_msg[25];
      sprintf(port_msg, "Port %zu ", j);
      std::string port_num = std::string(port_msg);
      if (nodeChecker(port_node, rs_num + port_num, portNames)) {
        // Change port name to port index
        for (uint8_t k = 0; k < portNames.size(); k++) {
          if (port_node.as<std::string>() == portNames[k]) {
            configFile["Reservation-Stations"][i]["Ports"][j] = unsigned(k);
            break;
          }
        }
      }
    }
  }

  // Register-Set
  root = "Register-Set";
  subFields = {"GeneralPurpose-Count", "FloatingPoint/SVE-Count",
               "Predicate-Count", "Conditional-Count"};
  nodeChecker<uint16_t>(configFile[root][subFields[0]], subFields[0],
                        {32, UINT16_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<uint16_t>(configFile[root][subFields[1]], subFields[1],
                        {32, UINT16_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<uint16_t>(configFile[root][subFields[2]], subFields[2],
                        {17, UINT16_MAX}, true, ExpectedValue::UInteger, true,
                        17);
  nodeChecker<uint16_t>(configFile[root][subFields[3]], subFields[3],
                        {1, UINT16_MAX}, true, ExpectedValue::UInteger);
  subFields.clear();

  // Queue-Sizes
  root = "Queue-Sizes";
  subFields = {"ROB", "Load", "Store"};
  nodeChecker<unsigned int>(configFile[root][subFields[0]], subFields[0],
                            {1, UINT_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile[root][subFields[1]], subFields[1],
                            {1, UINT_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile[root][subFields[2]], subFields[2],
                            {1, UINT_MAX}, true, ExpectedValue::UInteger);
  subFields.clear();

  // Pipeline-Widths
  root = "Pipeline-Widths";
  subFields = {"Commit", "Dispatch-Rate", "FrontEnd", "LSQ-Completion"};
  nodeChecker<unsigned int>(configFile[root][subFields[0]], subFields[0],
                            {1, UINT_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile[root][subFields[1]], subFields[1],
                            {1, UINT_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile[root][subFields[2]], subFields[2],
                            {1, UINT_MAX}, true, ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile[root][subFields[3]], subFields[3],
                            {1, UINT_MAX}, true, ExpectedValue::UInteger);
  subFields.clear();

  // Execution-Units
  root = "Execution-Units";
  subFields = {"Pipelined", "Blocking-Group"};
  size_t num_units = configFile[root].size();
  if (!num_units) {
    missing += ("\t- " + root + "\n");
  } else if (num_ports != num_units) {
    invalid +=
        "\t- Number of issue ports and execution units should be equal\n";
  }
  for (size_t i = 0; i < num_units; i++) {
    char msg[50];
    sprintf(msg, "Execution Unit %zu ", i);
    nodeChecker(configFile[root][i][subFields[0]],
                (std::string(msg) + subFields[0]));
    if (nodeChecker(configFile[root][i][subFields[1]],
                    (std::string(msg) + subFields[1]), groupOptionsWithNone)) {
      // Map EU Blocking-Group to integer value
      YAML::Node group = configFile[root][i][subFields[1]];
      group = (group.as<std::string>() != "NONE")
                  ? (1 << group_mapping[group.as<std::string>()])
                  : 0;
    }
  }
  subFields.clear();

  // Print all missing fields
  if (missing.length()) {
    std::cerr << "The following fields are missing from the provided "
                 "configuration file:\n"
              << missing << std::endl;
  }
  // Print all invalid values
  if (invalid.length()) {
    std::cerr
        << "The following values are invalid for their associated field:\n"
        << invalid << std::endl;
  }
  if (missing.length() || invalid.length()) exit(1);
  return;
}

int ModelConfig::nodeChecker(YAML::Node node, std::string field,
                             std::vector<std::string> value_set,
                             bool allow_default, std::string default_value) {
  // Check for the existance of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    if (allow_default) {
      node = default_value;
      return 1;
    }
    missing += ("\t- " + field + "\n");
    return 0;
  }

  // Ensure node value can be read as specified type
  try {
    std::string node_value = node.as<std::string>();
    // Ensure values lies within the defined options
    if (value_set.size() && !(std::find(value_set.begin(), value_set.end(),
                                        node_value) != value_set.end())) {
      invalid += ("\t- " + field + " value \"" + node_value +
                  "\" is not in valid set {");
      for (int i = 0; i < value_set.size(); i++) {
        invalid += value_set[i];
        if (i != value_set.size() - 1) invalid += ", ";
      }
      invalid += "}\n";
      return 0;
    }
  } catch (...) {
    invalid += ("\t- " + field + " must be of type string\n");
    return 0;
  }
  return 1;
}

int ModelConfig::nodeChecker(YAML::Node node, std::string field,
                             bool allow_default, bool default_value) {
  // Check for the existance of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    if (allow_default) {
      node = default_value;
      return 1;
    }
    missing += ("\t- " + field + "\n");
    return 0;
  }

  // Ensure node value can be read as specified type
  try {
    bool node_value = node.as<bool>();
  } catch (...) {
    invalid += ("\t- " + field + " must be of type bool\n");
    return 0;
  }
  return 1;
}

template <typename T>
int ModelConfig::nodeChecker(YAML::Node node, std::string field,
                             std::vector<T> value_set, bool bounds,
                             uint8_t expected, bool allow_default,
                             T default_value) {
  // Check for the existance of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    if (allow_default) {
      node = default_value;
      return 1;
    }
    missing += ("\t- " + field + "\n");
    return 0;
  }

  // Ensure node value can be read as specified type
  try {
    T node_value = node.as<T>();
    if (bounds) {
      // Extract bounds from value_set vector
      assert(value_set.size() == 2 &&
             "Defined bound vector for config option requires 2 values");
      T lower_bound = value_set[0];
      T upper_bound = value_set[1];
      assert(lower_bound <= upper_bound &&
             "Defined lower bound of config option is not equal or "
             "less than defined upper bound");

      // Ensure value lies within the defined bounds
      if (lower_bound > node_value || node_value > upper_bound) {
        invalid +=
            ("\t- " + field + " must conform to the inclusive bounds of ");
        char err[50];
        if (expected == ExpectedValue::Integer ||
            expected == ExpectedValue::UInteger) {
          sprintf(err, "%d and %d\n", lower_bound, upper_bound);
          invalid += err;
        } else if (expected == ExpectedValue::Float) {
          sprintf(err, "%.1f and %.1f\n", lower_bound, upper_bound);
          invalid += err;
        } else {
          invalid += "#cannot print bounds#";
        }
        return 0;
      }
    } else {
      // Ensure values lies within the defined options
      assert(value_set.size() && "Defined value set of config option is empty");
      if (!(std::find(value_set.begin(), value_set.end(), node_value) !=
            value_set.end())) {
        char msg[50];
        try {
          if (expected == ExpectedValue::Integer ||
              expected == ExpectedValue::UInteger) {
            sprintf(msg, "\t- %s value \"%d\" is not in valid set {",
                    field.c_str(), node_value);
          } else if (expected == ExpectedValue::Float) {
            sprintf(msg, "\t- %s value \"%.1f\" is not in valid set {",
                    field.c_str(), node_value);
          } else {
            sprintf(msg, "\t- %s value is not in valid set {", field.c_str());
          }
        } catch (...) {
          sprintf(msg, "\t- %s value is not in valid set {", field.c_str());
        }
        invalid += std::string(msg);
        for (int i = 0; i < value_set.size(); i++) {
          char err[25];
          if (expected == ExpectedValue::Integer ||
              expected == ExpectedValue::UInteger) {
            sprintf(err, "%d", value_set[i]);
            invalid += err;
          } else if (expected == ExpectedValue::Float) {
            sprintf(err, "%.1f", value_set[i]);
            invalid += err;
          } else {
            invalid += "#unreadable#";
          }
          if (i != value_set.size() - 1) invalid += ", ";
        }
        invalid += "}\n";
        return 0;
      }
    }
  } catch (...) {
    invalid += ("\t- " + field + invalid_type_map[expected] + "\n");
    return 0;
  }
  return 1;
}

}  // namespace simeng
