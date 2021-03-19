#include "simeng/ModelConfig.hh"

#include <math.h>

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

  // Generate groupOptions_ and groupMapping_
  createGroupMapping();

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
  subFields = {"Simulation-Mode", "Clock-Frequency", "Timer-Frequency",
               "Micro-Operations", "Vector-Length"};
  nodeChecker<std::string>(configFile_[root][subFields[0]], subFields[0],
                           {"emulation", "inorderpipelined", "outoforder"},
                           ExpectedValue::String);
  nodeChecker<float>(configFile_[root][subFields[1]], subFields[1],
                     std::make_pair(0.f, 10.f), ExpectedValue::Float);
  nodeChecker<uint32_t>(configFile_[root][subFields[2]], subFields[2],
                        std::make_pair(1, UINT32_MAX), ExpectedValue::UInteger,
                        100);
  nodeChecker<bool>(configFile_[root][subFields[3]], subFields[3],
                    std::make_pair(false, true), ExpectedValue::Bool, false);
  nodeChecker<uint16_t>(configFile_[root][subFields[4]], subFields[4],
                        {128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280,
                         1408, 1536, 1664, 1792, 1920, 2048},
                        ExpectedValue::UInteger, 512);
  subFields.clear();

  // Fetch
  root = "Fetch";
  subFields = {"Fetch-Block-Size", "Loop-Buffer-Size",
               "Loop-Detection-Threshold"};
  if (nodeChecker<uint16_t>(configFile_[root][subFields[0]], subFields[0],
                            std::make_pair(4, UINT16_MAX),
                            ExpectedValue::UInteger)) {
    uint16_t block_size = configFile_[root][subFields[0]].as<uint16_t>();
    // Ensure fetch block size is a power of 2
    if ((block_size & (block_size - 1)) == 0) {
      uint8_t alignment_bits = log2(block_size);
      configFile_[root]["Fetch-Block-Alignment-Bits"] =
          unsigned(alignment_bits);
    } else {
      invalid_ << "\t- Fetch-Block-Size must be a power of 2\n";
    }
  }
  nodeChecker<uint16_t>(configFile_[root][subFields[1]], subFields[1],
                        std::make_pair(0, UINT16_MAX), ExpectedValue::UInteger);
  nodeChecker<uint16_t>(configFile_[root][subFields[2]], subFields[2],
                        std::make_pair(0, UINT16_MAX), ExpectedValue::UInteger);
  subFields.clear();

  // Process-Image
  root = "Process-Image";
  subFields = {"Heap-Size", "Stack-Size"};
  // Default heap size is 1024 * 1024 * 10 = 10MiB
  nodeChecker<uint64_t>(configFile_[root][subFields[0]], subFields[0],
                        std::make_pair(1, UINT64_MAX), ExpectedValue::UInteger,
                        10485760);
  // Default stack size is 1024 * 1024 = 1MiB
  nodeChecker<uint64_t>(configFile_[root][subFields[1]], subFields[1],
                        std::make_pair(1, UINT64_MAX), ExpectedValue::UInteger,
                        1048576);
  subFields.clear();

  // Branch-Predictor
  root = "Branch-Predictor";
  subFields = {"BTB-Tag-Bits", "Saturating-Count-Bits", "Global-History-Length",
               "RAS-entries", "Fallback-Static-Predictor"};
  nodeChecker<uint64_t>(configFile_[root][subFields[0]], subFields[0],
                        std::make_pair(1, UINT64_MAX), ExpectedValue::UInteger);
  nodeChecker<uint64_t>(configFile_[root][subFields[2]], subFields[2],
                        std::make_pair(0, 64), ExpectedValue::UInteger);
  nodeChecker<uint64_t>(configFile_[root][subFields[3]], subFields[3],
                        std::make_pair(1, UINT64_MAX), ExpectedValue::UInteger);
  if (nodeChecker<std::string>(
          configFile_[root][subFields[4]], subFields[4],
          std::vector<std::string>{"Always-Taken", "Always-Not-Taken"},
          ExpectedValue::String)) {
    // If the Saturating-Count-Bits option is valid, set fallback static
    // prediction to weakest value of the specific direction (i.e weakly taken
    // or weakly not-taken)
    if (nodeChecker<uint64_t>(configFile_[root][subFields[1]], subFields[1],
                              std::make_pair(1, UINT64_MAX),
                              ExpectedValue::UInteger)) {
      // Calculate saturation counter boundary between weakly taken and
      // not-taken. `(2 ^ num_sat_cnt_bits) / 2` gives the weakly taken state
      // value
      uint16_t weaklyTaken =
          std::pow(2, (configFile_[root][subFields[1]].as<uint64_t>() - 1));
      // Swap Fallback-Static-Predictor scheme out for equivalent saturating
      // counter value
      configFile_[root][subFields[4]] =
          (configFile_[root][subFields[4]].as<std::string>() == "Always-Taken")
              ? weaklyTaken
              : (weaklyTaken - 1);
    }
  }
  subFields.clear();

  // L1-Cache
  root = "L1-Cache";
  subFields = {"Access-Latency",
               "Exclusive",
               "Load-Bandwidth",
               "Store-Bandwidth",
               "Permitted-Requests-Per-Cycle",
               "Permitted-Loads-Per-Cycle",
               "Permitted-Stores-Per-Cycle"};
  nodeChecker<uint16_t>(configFile_[root][subFields[0]], subFields[0],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger,
                        1);
  nodeChecker<bool>(configFile_[root][subFields[1]], subFields[1],
                    std::vector<bool>{true, false}, ExpectedValue::Bool, false);
  nodeChecker<uint16_t>(configFile_[root][subFields[2]], subFields[2],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger,
                        UINT16_MAX);
  nodeChecker<uint16_t>(configFile_[root][subFields[3]], subFields[3],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger,
                        UINT16_MAX);
  nodeChecker<uint16_t>(configFile_[root][subFields[4]], subFields[4],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger,
                        UINT16_MAX);
  nodeChecker<uint16_t>(configFile_[root][subFields[5]], subFields[5],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger,
                        UINT16_MAX);
  nodeChecker<uint16_t>(configFile_[root][subFields[6]], subFields[6],
                        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger,
                        UINT16_MAX);
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
    // Check for existence of Portname field and record name
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
    // Check for existence of Instruction-Support field
    if (!(port_node["Instruction-Support"].IsDefined()) ||
        port_node["Instruction-Support"].IsNull()) {
      missing_ << "\t- " << port_num << "Instruction-Support\n";
      continue;
    }
    uint16_t groupIndex = 0;
    uint16_t opcodeIndex = 0;
    for (size_t j = 0; j < port_node["Instruction-Support"].size(); j++) {
      YAML::Node group = port_node["Instruction-Support"][j];
      // Get group number into a string format
      char group_msg[10];
      sprintf(group_msg, "Group %zu ", j);
      std::string group_num = std::string(group_msg);
      // Check for existance of instruction group
      if (group.as<std::string>()[0] == '~') {
        // Extract opcode and store in config option
        uint16_t opcode = std::stoi(
            group.as<std::string>().substr(1, group.as<std::string>().size()));
        configFile_["Ports"][i]["Instruction-Opcode-Support"][opcodeIndex] =
            opcode;
        // Ensure opcode is between the bounds of 0 and Capstones'
        // AArch64_INSTRUCTION_LIST_END
        boundChecker(
            configFile_["Ports"][i]["Instruction-Opcode-Support"][opcodeIndex],
            port_num + group_num, std::make_pair(0, 4516),
            ExpectedValue::UInteger);
        opcodeIndex++;
      } else if (nodeChecker<std::string>(group, port_num + group_num,
                                          groupOptions_,
                                          ExpectedValue::String)) {
        configFile_["Ports"][i]["Instruction-Group-Support"][groupIndex] =
            unsigned(groupMapping_[group.as<std::string>()]);
        groupIndex++;
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
    // Check for existence of Ports field
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
                      std::vector<bool>{false, true}, ExpectedValue::Bool);
    if (euNode[subFields[1]].IsDefined() && !(euNode[subFields[1]].IsNull())) {
      // Compile set of blocking groups into a queue
      std::queue<uint16_t> blockingGroups;
      for (size_t j = 0; j < euNode[subFields[1]].size(); j++) {
        char bgNum[50];
        sprintf(bgNum, "Blocking group %zu", j);
        if (nodeChecker<std::string>(configFile_[root][i][subFields[1]][j],
                                     (std::string(euNum) + std::string(bgNum)),
                                     groupOptions_, ExpectedValue::String)) {
          uint16_t mappedGroup =
              groupMapping_[euNode[subFields[1]][j].as<std::string>()];
          blockingGroups.push(mappedGroup);
          configFile_["Execution-Units"][i]["Blocking-Groups"][j] = mappedGroup;
        }
      }
      // Expand set of blocking groups to include those that inherit from the
      // user defined set
      uint16_t config_index =
          configFile_["Execution-Units"][i]["Blocking-Groups"].size();
      while (blockingGroups.size()) {
        // Determine if there's any inheritance
        if (arch::aarch64::groupInheritance.find(blockingGroups.front()) !=
            arch::aarch64::groupInheritance.end()) {
          std::vector<uint16_t> inheritedGroups =
              arch::aarch64::groupInheritance.at(blockingGroups.front());
          for (int k = 0; k < inheritedGroups.size(); k++) {
            blockingGroups.push(inheritedGroups[k]);
            configFile_["Execution-Units"][i]["Blocking-Groups"][config_index] =
                inheritedGroups[k];
            config_index++;
          }
        }
        blockingGroups.pop();
      }
    }
  }
  subFields.clear();

  // Latencies
  root = "Latencies";
  subFields = {"Instruction-Groups", "Execution-Latency",
               "Execution-Throughput"};
  for (size_t i = 0; i < configFile_[root].size(); i++) {
    char latNum[50];
    sprintf(latNum, "Latency group %zu ", i);
    YAML::Node latNode = configFile_[root][i];
    YAML::Node grpNode = latNode[subFields[0]];
    if (grpNode.IsDefined() && !(grpNode.IsNull())) {
      uint16_t groupIndex = 0;
      uint16_t opcodeIndex = 0;
      for (size_t j = 0; j < grpNode.size(); j++) {
        char grpNum[50];
        sprintf(grpNum, "Instruction group %zu ", j);
        // Determine whether the value is an opcode or an instruction-group
        // value
        if (grpNode[j].as<std::string>()[0] == '~') {
          // Extract opcode and store in config option
          uint16_t opcode = std::stoi(grpNode[j].as<std::string>().substr(
              1, grpNode[j].as<std::string>().size()));
          configFile_[root][i]["Instruction-Opcode"][opcodeIndex] = opcode;
          // Ensure opcode is between the bounds of 0 and Capstones'
          // AArch64_INSTRUCTION_LIST_END
          boundChecker(configFile_[root][i]["Instruction-Opcode"][opcodeIndex],
                       (std::string(latNum) + std::string(grpNum)),
                       std::make_pair(0, 4516), ExpectedValue::UInteger);
          opcodeIndex++;
        } else if (nodeChecker<std::string>(
                       grpNode[j], (std::string(latNum) + std::string(grpNum)),
                       groupOptions_, ExpectedValue::String)) {
          // Map latency Instruction-Group to integer value
          configFile_[root][i]["Instruction-Group"][groupIndex] =
              groupMapping_[grpNode[j].as<std::string>()];
          groupIndex++;
        }
      }
    } else {
      missing_ << "\t- " << (std::string(latNum) + subFields[0]) << "\n";
    }
    nodeChecker<uint16_t>(
        latNode[subFields[1]], (std::string(latNum) + subFields[1]),
        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger);
    nodeChecker<uint16_t>(
        latNode[subFields[2]], (std::string(latNum) + subFields[2]),
        std::make_pair(1, UINT16_MAX), ExpectedValue::UInteger);
  }
  subFields.clear();

  // CPU-Info
  root = "CPU-Info";
  subFields = {"Generate-Special-Dir",
               "Core-Count",
               "Socket-Count",
               "SMT",
               "BogoMIPS",
               "Features",
               "CPU-Implementer",
               "CPU-Architecture",
               "CPU-Variant",
               "CPU-Part",
               "CPU-Revision",
               "Package-Count"};
  nodeChecker<std::string>(configFile_[root][subFields[0]], subFields[0],
                           {"T", "F", ""}, ExpectedValue::String, "F");
  nodeChecker<unsigned int>(configFile_[root][subFields[1]], subFields[1],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger, 1);
  nodeChecker<unsigned int>(configFile_[root][subFields[2]], subFields[2],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger, 1);
  nodeChecker<unsigned int>(configFile_[root][subFields[3]], subFields[3],
                            std::make_pair(1, UINT_MAX),
                            ExpectedValue::UInteger, 1);
  nodeChecker<float>(configFile_[root][subFields[4]], subFields[4],
                     std::make_pair(0.0f, std::numeric_limits<float>::max()),
                     ExpectedValue::Float, 0.0f);
  nodeChecker<std::string>(configFile_[root][subFields[5]], subFields[5],
                           std::vector<std::string>(), ExpectedValue::String,
                           "");
  nodeChecker<std::string>(configFile_[root][subFields[6]], subFields[6],  //
                           std::vector<std::string>(), ExpectedValue::String,
                           "0x0");
  nodeChecker<unsigned int>(configFile_[root][subFields[7]], subFields[7],
                            std::make_pair(0, UINT_MAX),
                            ExpectedValue::UInteger, 0);
  nodeChecker<std::string>(configFile_[root][subFields[8]], subFields[8],  //
                           std::vector<std::string>(), ExpectedValue::String,
                           "0x0");
  nodeChecker<std::string>(configFile_[root][subFields[9]], subFields[9],  //
                           std::vector<std::string>(), ExpectedValue::String,
                           "0x0");
  nodeChecker<unsigned int>(configFile_[root][subFields[10]], subFields[10],
                            std::make_pair(0, UINT_MAX),
                            ExpectedValue::UInteger, 0x0);
  if (nodeChecker<unsigned int>(configFile_[root][subFields[11]], subFields[11],
                                std::make_pair(1, UINT_MAX),
                                ExpectedValue::UInteger, 1)) {
    uint64_t package_count = configFile_[root][subFields[11]].as<uint64_t>();
    uint64_t core_count = configFile_[root][subFields[1]].as<uint64_t>();
    // Ensure package_count size is a less than or equal to the core count, and
    // that the core count can be divided by the package count
    if (!((package_count <= core_count) && (core_count % package_count == 0))) {
      invalid_
          << "\t- Package-Count must be a Less-than or equal to Core-Count, "
             "and Core-Count must be divisible by Package-Count.";
    }
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

void ModelConfig::createGroupMapping() {
  groupOptions_ = {"INT",
                   "INT_SIMPLE",
                   "INT_SIMPLE_ARTH",
                   "INT_SIMPLE_ARTH_NOSHIFT",
                   "INT_SIMPLE_LOGICAL",
                   "INT_SIMPLE_LOGICAL_NOSHIFT",
                   "INT_SIMPLE_CMP",
                   "INT_SIMPLE_CVT",
                   "INT_MUL",
                   "INT_DIV_OR_SQRT",
                   "LOAD_INT",
                   "STORE_ADDRESS_INT",
                   "STORE_DATA_INT",
                   "STORE_INT",
                   "FP",
                   "FP_SIMPLE",
                   "FP_SIMPLE_ARTH",
                   "FP_SIMPLE_ARTH_NOSHIFT",
                   "FP_SIMPLE_LOGICAL",
                   "FP_SIMPLE_LOGICAL_NOSHIFT",
                   "FP_SIMPLE_CMP",
                   "FP_SIMPLE_CVT",
                   "FP_MUL",
                   "FP_DIV_OR_SQRT",
                   "SCALAR",
                   "SCALAR_SIMPLE",
                   "SCALAR_SIMPLE_ARTH",
                   "SCALAR_SIMPLE_ARTH_NOSHIFT",
                   "SCALAR_SIMPLE_LOGICAL",
                   "SCALAR_SIMPLE_LOGICAL_NOSHIFT",
                   "SCALAR_SIMPLE_CMP",
                   "SCALAR_SIMPLE_CVT",
                   "SCALAR_MUL",
                   "SCALAR_DIV_OR_SQRT",
                   "LOAD_SCALAR",
                   "STORE_ADDRESS_SCALAR",
                   "STORE_DATA_SCALAR",
                   "STORE_SCALAR",
                   "VECTOR",
                   "VECTOR_SIMPLE",
                   "VECTOR_SIMPLE_ARTH",
                   "VECTOR_SIMPLE_ARTH_NOSHIFT",
                   "VECTOR_SIMPLE_LOGICAL",
                   "VECTOR_SIMPLE_LOGICAL_NOSHIFT",
                   "VECTOR_SIMPLE_CMP",
                   "VECTOR_SIMPLE_CVT",
                   "VECTOR_MUL",
                   "VECTOR_DIV_OR_SQRT",
                   "LOAD_VECTOR",
                   "STORE_ADDRESS_VECTOR",
                   "STORE_DATA_VECTOR",
                   "STORE_VECTOR",
                   "SVE",
                   "SVE_SIMPLE",
                   "SVE_SIMPLE_ARTH",
                   "SVE_SIMPLE_ARTH_NOSHIFT",
                   "SVE_SIMPLE_LOGICAL",
                   "SVE_SIMPLE_LOGICAL_NOSHIFT",
                   "SVE_SIMPLE_CMP",
                   "SVE_SIMPLE_CVT",
                   "SVE_MUL",
                   "SVE_DIV_OR_SQRT",
                   "LOAD_SVE",
                   "STORE_ADDRESS_SVE",
                   "STORE_DATA_SVE",
                   "STORE_SVE",
                   "PREDICATE",
                   "LOAD",
                   "STORE_ADDRESS",
                   "STORE_DATA",
                   "STORE",
                   "BRANCH"};
  // AARCH64 instruction group namespace contains a set of contiguous assigned
  // uint16_t start from 0. Therefore the index of each groupOptions_ entry is
  // also its aarch64::InstructionGroups value (assuming groupOptions_ is
  // ordered exactly as aarch64::InstructionGroups is).
  for (int grp = 0; grp < groupOptions_.size(); grp++) {
    groupMapping_[groupOptions_[grp]] = grp;
  }
}

template <typename T>
int ModelConfig::nodeChecker(const YAML::Node& node, const std::string& field,
                             const std::vector<T>& value_set,
                             uint8_t expected) {
  // Check for the existence of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    missing_ << "\t- " << field << "\n";
    return 0;
  }

  return setChecker(node, field, value_set, expected);
}

template <typename T>
int ModelConfig::nodeChecker(YAML::Node node, const std::string& field,
                             const std::vector<T>& value_set, uint8_t expected,
                             T default_value) {
  // Check for the existence of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    node = default_value;
    return 1;
  }

  return setChecker(node, field, value_set, expected);
}

template <typename T>
int ModelConfig::nodeChecker(const YAML::Node& node, const std::string& field,
                             const std::pair<T, T>& bounds, uint8_t expected) {
  // Check for the existence of the given node
  if (!(node.IsDefined()) || node.IsNull()) {
    missing_ << "\t- " << field << "\n";
    return 0;
  }

  return boundChecker(node, field, bounds, expected);
}

template <typename T>
int ModelConfig::nodeChecker(YAML::Node node, const std::string& field,
                             const std::pair<T, T>& bounds, uint8_t expected,
<<<<<<< HEAD
                             const T& default_value) {
  // Check for the existance of the given node
=======
                             T default_value) {
  // Check for the existence of the given node
>>>>>>> 142bda6 (Typo corrections)
  if (!(node.IsDefined()) || node.IsNull()) {
    node = default_value;
    return 1;
  }

  return boundChecker(node, field, bounds, expected);
}

}  // namespace simeng
