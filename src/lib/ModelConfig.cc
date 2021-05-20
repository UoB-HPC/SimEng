#include "simeng/ModelConfig.hh"

namespace simeng {

ModelConfig::ModelConfig(std::string path) {
  // Ensure the file exists
  std::ifstream file(path);
  if (!file.is_open()) {
    std::cerr << "Could not read " << path << std::endl;
    exit(1);
  }
  file.close();

  // Read in the config file
  configFile_ = YAML::LoadFile(path);

  // Check if the config file inherits values from a base config
  inherit();

  // Validate the inputted config file
  validate();
}

YAML::Node ModelConfig::getConfigFile() { return configFile_; }

void ModelConfig::inherit() {
  // Check if the config file includes a inheritted file
  if (!configFile_["Inherit-From"]) {
    return;
  } else {
    std::cerr << "Config inheritance not yet supported" << std::endl;
    exit(1);
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
  nodeChecker<std::string>(configFile_[root][subFields[0]], subFields[0],
                           {"emulation", "inorderpipelined", "outoforder"},
                           ExpectedValue::String);
  nodeChecker<float>(configFile_[root][subFields[1]], subFields[1],
                     std::make_pair(0.f, 10.f), ExpectedValue::Float);
  if (nodeChecker<uint16_t>(configFile_[root][subFields[2]], subFields[2],
                            std::make_pair(4, UINT16_MAX),
                            ExpectedValue::UInteger)) {
    uint16_t block_size = configFile_[root][subFields[2]].as<uint16_t>();
    // Ensure ftech block size is a power of 2
    if ((block_size & (block_size - 1)) == 0) {
      uint8_t alignment_bits = log2(block_size);
      configFile_[root]["Fetch-Block-Alignment-Bits"] =
          unsigned(alignment_bits);
    } else {
      invalid_ << "\t- Fetch-Block-Size must be a power of 2\n";
    }
  }
  subFields.clear();

  // Branch-Predictor
  root = "Branch-Predictor";
  subFields = {"BTB-bitlength"};
  nodeChecker<uint8_t>(configFile_[root][subFields[0]], subFields[0],
                       std::make_pair(1, UINT8_MAX), ExpectedValue::UInteger);
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
  nodeChecker<uint16_t>(configFile_[root][subFields[0]], subFields[0],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger);
  nodeChecker<uint16_t>(configFile_[root][subFields[1]], subFields[1],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger);
  nodeChecker<uint16_t>(configFile_[root][subFields[2]], subFields[2],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger,
                        1);
  nodeChecker<uint8_t>(configFile_[root][subFields[3]], subFields[3],
                       std::make_pair(1, UINT8_MAX), ExpectedValue::UInteger);
  nodeChecker<uint8_t>(configFile_[root][subFields[4]], subFields[4],
                       std::make_pair(1, UINT8_MAX), ExpectedValue::UInteger);
  nodeChecker<uint8_t>(configFile_[root][subFields[5]], subFields[5],
                       std::make_pair(1, UINT8_MAX), ExpectedValue::UInteger);
  nodeChecker<uint8_t>(configFile_[root][subFields[6]], subFields[6],
                       std::make_pair(1, UINT8_MAX), ExpectedValue::UInteger);
  subFields.clear();

  // Ports
  std::vector<std::string> portNames;
  std::map<std::string, bool> portLinked;
  root = "Ports";
  size_t num_ports = configFile_[root].size();
  if (!num_ports) {
    missing_ << "\t- " << root << "\n";
  }
  for (size_t i = 0; i < num_ports; i++) {
    YAML::Node port_node = configFile_[root][i];
    // Get port number into a string format
    char port_msg[10];
    sprintf(port_msg, "Port %zu ", i);
    std::string port_num = std::string(port_msg);
    // Check for existance of Portname field and record name
    if (nodeChecker<std::string>(port_node["Portname"], port_num + "Portname",
                                 std::vector<std::string>{},
                                 ExpectedValue::String)) {
      std::string name = port_node["Portname"].as<std::string>();
      // Ensure port name is unique
      if (std::find(portNames.begin(), portNames.end(), name) ==
          portNames.end()) {
        portNames.push_back(name);
        portLinked.insert({name, false});
      } else {
        invalid_ << "\t- " << port_num << "name \"" << name
                 << "\" already used\n";
      }
    }
    // Check for existance of Instruction-Support field
    if (!(port_node["Instruction-Support"].IsDefined()) ||
        port_node["Instruction-Support"].IsNull()) {
      missing_ << "\t- " << port_num << "Instruction-Support\n";
      continue;
    }
    for (size_t j = 0; j < port_node["Instruction-Support"].size(); j++) {
      YAML::Node group = port_node["Instruction-Support"][j];
      // Get group number into a string format
      char group_msg[10];
      sprintf(group_msg, "Group %zu ", j);
      std::string group_num = std::string(group_msg);
      // Check for existance of instruction group
      if (nodeChecker<std::string>(port_node["Instruction-Support"][j],
                                   port_num + group_num, groupOptions,
                                   ExpectedValue::String)) {
        configFile_["Ports"][i]["Instruction-Support"][j] =
            unsigned(group_mapping[port_node["Instruction-Support"][j]
                                       .as<std::string>()]);
      }
    }
  }

  // Reservation-Stations
  root = "Reservation-Stations";
  size_t num_rs = configFile_[root].size();
  if (!num_rs) {
    missing_ << "\t- " << root << "\n";
  }
  for (size_t i = 0; i < num_rs; i++) {
    YAML::Node rs = configFile_[root][i];
    // Get rs number into a string format
    char rs_msg[25];
    sprintf(rs_msg, "Reservation Station %zu ", i);
    std::string rs_num = std::string(rs_msg);
    nodeChecker<uint16_t>(rs["Size"], rs_num + "Size",
                          std::make_pair(1, UINT16_MAX),
                          ExpectedValue::UInteger);
    // Check for existance of Ports field
    if (!(rs["Ports"].IsDefined()) || rs["Ports"].IsNull()) {
      missing_ << "\t- " << rs_num << "Ports\n";
      continue;
    }
    for (size_t j = 0; j < rs["Ports"].size(); j++) {
      YAML::Node port_node = rs["Ports"][j];
      // Get port index into a string format
      char port_msg[25];
      sprintf(port_msg, "Port %zu ", j);
      std::string port_num = std::string(port_msg);
      if (nodeChecker<std::string>(port_node, rs_num + port_num + "Portname",
                                   portNames, ExpectedValue::String)) {
        // Change port name to port index
        for (uint8_t k = 0; k < portNames.size(); k++) {
          if (port_node.as<std::string>() == portNames[k]) {
            configFile_["Reservation-Stations"][i]["Ports"][j] = unsigned(k);
            portLinked[portNames[k]] = true;
            break;
          }
        }
      }
    }
  }
  // Ensure all ports have an associated reservation station
  for (auto& port : portLinked) {
    if (!port.second) {
      missing_ << "\t- " << port.first
               << " has no associated reservation station\n";
    }
  }

  // Register-Set
  root = "Register-Set";
  subFields = {"GeneralPurpose-Count", "FloatingPoint/SVE-Count",
               "Predicate-Count", "Conditional-Count"};
  nodeChecker<uint16_t>(configFile_[root][subFields[0]], subFields[0],
                        std::make_pair(32, UINT16_MAX),
                        ExpectedValue::UInteger);
  nodeChecker<uint16_t>(configFile_[root][subFields[1]], subFields[1],
                        std::make_pair(32, UINT16_MAX),
                        ExpectedValue::UInteger);
  nodeChecker<uint16_t>(configFile_[root][subFields[2]], subFields[2],
                        std::make_pair(17, UINT16_MAX), ExpectedValue::UInteger,
                        17);
  nodeChecker<uint16_t>(configFile_[root][subFields[3]], subFields[3],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger);
  subFields.clear();

  // Queue-Sizes
  root = "Queue-Sizes";
  subFields = {"ROB", "Load", "Store"};
  nodeChecker<unsigned int>(configFile_[root][subFields[0]], subFields[0],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile_[root][subFields[1]], subFields[1],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile_[root][subFields[2]], subFields[2],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger);
  subFields.clear();

  // Pipeline-Widths
  root = "Pipeline-Widths";
  subFields = {"Commit", "Dispatch-Rate", "FrontEnd", "LSQ-Completion"};
  nodeChecker<unsigned int>(configFile_[root][subFields[0]], subFields[0],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile_[root][subFields[1]], subFields[1],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile_[root][subFields[2]], subFields[2],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger);
  nodeChecker<unsigned int>(configFile_[root][subFields[3]], subFields[3],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger);
  subFields.clear();

  // Execution-Units
  root = "Execution-Units";
  subFields = {"Pipelined", "Blocking-Groups"};
  size_t num_units = configFile_[root].size();
  if (!num_units) {
    missing_ << "\t- " << root << "\n";
  } else if (num_ports != num_units) {
    invalid_
        << "\t- Number of issue ports and execution units should be equal\n";
  }
  for (size_t i = 0; i < num_units; i++) {
    char euNum[50];
    sprintf(euNum, "Execution Unit %zu ", i);
    YAML::Node euNode = configFile_[root][i];
    nodeChecker<bool>(configFile_[root][i][subFields[0]],
                      (std::string(euNum) + subFields[0]),
                      std::make_pair(false, true), ExpectedValue::Bool);
    if (euNode[subFields[1]].IsDefined() && !(euNode[subFields[1]].IsNull())) {
      for (size_t j = 0; j < euNode[subFields[1]].size(); j++) {
        char bgNum[50];
        sprintf(bgNum, "Blocking group %zu", j);
        if (nodeChecker<std::string>(configFile_[root][i][subFields[1]][j],
                                     (std::string(euNum) + std::string(bgNum)),
                                     groupOptions, ExpectedValue::String)) {
          YAML::Node group = euNode[subFields[1]][j];
          // Map EU Blocking-Group to integer value
          configFile_["Execution-Units"][i]["Blocking-Groups"][j] =
              group_mapping[group.as<std::string>()];
        }
      }
    }
  }
  subFields.clear();

  // Latencies
  root = "Latencies";
  subFields = {"Instruction-Group", "Execution-Latency",
               "Execution-Throughput"};
  size_t num_groups = configFile_[root].size();
  for (size_t i = 0; i < num_groups; i++) {
    char latNum[50];
    sprintf(latNum, "Latency group %zu ", i);
    YAML::Node latNode = configFile_[root][i];
    if (nodeChecker<std::string>(latNode[subFields[0]],
                                 (std::string(latNum) + subFields[0]),
                                 groupOptions, ExpectedValue::String)) {
      // Map latency Instruction-Group to integer value
      configFile_["Latencies"][i]["Instruction-Group"] =
          group_mapping[latNode[subFields[0]].as<std::string>()];
    }
    nodeChecker<uint16_t>(
        latNode[subFields[1]], (std::string(latNum) + subFields[1]),
        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger);
    nodeChecker<uint16_t>(
        latNode[subFields[2]], (std::string(latNum) + subFields[2]),
        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger);
  }
  subFields.clear();

  std::string missingStr = missing_.str();
  std::string invalidStr = invalid_.str();
  // Print all missing fields
  if (missingStr.length()) {
    std::cerr << "The following fields are missing from the provided "
                 "configuration file:\n"
              << missingStr << std::endl;
  }
  // Print all invalid values
  if (invalidStr.length()) {
    std::cerr
        << "The following values are invalid for their associated field:\n"
        << invalidStr << std::endl;
  }
  if (missingStr.length() || invalidStr.length()) exit(1);
  return;
}

template <typename T>
int ModelConfig::nodeChecker(YAML::Node node, std::string field,
                             const std::vector<T>& value_set,
                             uint8_t expected) {
  // Check for the existance of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    missing_ << "\t- " << field << "\n";
    return 0;
  }

  return setChecker(node, field, value_set, expected);
}

template <typename T>
int ModelConfig::nodeChecker(YAML::Node node, std::string field,
                             const std::vector<T>& value_set, uint8_t expected,
                             T default_value) {
  // Check for the existance of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    node = default_value;
    return 1;
  }

  return setChecker(node, field, value_set, expected);
}

template <typename T>
int ModelConfig::nodeChecker(YAML::Node node, std::string field,
                             const std::pair<T, T>& bounds, uint8_t expected) {
  // Check for the existance of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    missing_ << "\t- " << field << "\n";
    return 0;
  }

  return boundChecker(node, field, bounds, expected);
}

template <typename T>
int ModelConfig::nodeChecker(YAML::Node node, std::string field,
                             const std::pair<T, T>& bounds, uint8_t expected,
                             T default_value) {
  // Check for the existance of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    node = default_value;
    return 1;
  }

  return boundChecker(node, field, bounds, expected);
}

}  // namespace simeng
