#define RYML_SINGLE_HDR_DEFINE_NOW
#include "simeng/config/ModelConfig.hh"

#include <cmath>

#include "arch/aarch64/InstructionMetadata.hh"
#include "arch/riscv/InstructionMetadata.hh"
#include "simeng/config/SimInfo.hh"

namespace simeng {
namespace config {

/** RISC-V opcodes. Each opcode represents a unique RISC-V operation. */
namespace RISCVOpcode {
#define GET_INSTRINFO_ENUM
#include "RISCVGenInstrInfo.inc"
}  // namespace RISCVOpcode

/** AArch64 opcodes. Each opcode represents a unique AArch64 operation. */
namespace AARCH64Opcode {
#define GET_INSTRINFO_ENUM
#include "AArch64GenInstrInfo.inc"
}  // namespace AARCH64Opcode

ModelConfig::ModelConfig(std::string path) {
  // Reset ryml::Tree used to represent the config file
  configTree_.clear();
  configTree_.rootref() |= ryml::MAP;
  isDefault_ = false;

  std::ifstream file(path, std::ios::binary);
  // Check for file existence
  if (!file.is_open()) {
    std::cerr << "[SimEng:ModelConfig] Could not read " << path << std::endl;
    exit(1);
  }
  // Read in the contents of the file and create a ryml:Tree from it
  std::stringstream buffer;
  buffer << file.rdbuf();
  configTree_ = ryml::parse_in_arena(ryml::to_csubstr(buffer.str()));
  file.close();

  // Set the expectations of the config file and validate the config values
  // within the passed config file
  setExpectations();
  recursiveValidate(expectations_, configTree_.rootref());
  postValidation();

  std::string missingStr = missing_.str();
  std::string invalidStr = invalid_.str();
  // Print all missing fields
  if (missingStr.length()) {
    std::cerr << "[SimEng:ModelConfig] The following fields are missing from "
                 "the provided "
                 "configuration file:\n"
              << missingStr << std::endl;
  }
  // Print all invalid values
  if (invalidStr.length()) {
    std::cerr << "[SimEng:ModelConfig] The following values are invalid for "
                 "their associated field:\n"
              << invalidStr << std::endl;
  }
  // Stop execution if the config file didn't pass checks
  if (missingStr.length() || invalidStr.length()) exit(1);
  return;
}

ModelConfig::ModelConfig() {
  // Generate the default config file
  generateDefault();
}

void ModelConfig::reGenerateDefault(ISA isa) {
  // Only re-generate the default config file if it hasn't already been
  // generated for the specified ISA
  if (ISA_ == isa && isDefault_) return;

  ISA_ = isa;
  generateDefault();
}

void ModelConfig::generateDefault() {
  // Reset ryml::Tree used to represent the config file
  configTree_.clear();
  configTree_.rootref() |= ryml::MAP;
  isDefault_ = true;

  // Set the expectations for the default config file, construct it, and
  // validate it to ensure correctness for the simulation
  setExpectations(true);
  constructDefault(expectations_, configTree_.root_id());
  recursiveValidate(expectations_, configTree_.rootref());
  postValidation();
}

void ModelConfig::constructDefault(expectationNode expectations,
                                   size_t root_id) {
  // Iterate over the expectations supplied
  for (const auto& chld : expectations.getChildren()) {
    std::string key = chld.getKey();
    ExpectedType type = chld.getType();
    // If the key is a wildcard ("*"), then change it to be an appropriate value
    // in the resultant config file and its type to be valueless
    if (key == "*") {
      key = "0";
      type = ExpectedType::Valueless;
    }
    // Create the ryml::NodeRef representing a config option
    ryml::NodeRef node = configTree_.ref(root_id).append_child()
                         << ryml::key(key);
    // If the expectation is a sequence, then add an additional ryml::NodeRef as
    // a child to the former to act as the sequence of values when read in later
    if (chld.isSequence()) {
      node |= ryml::SEQ;
      node = configTree_.ref(node.id()).append_child();
    }
    // Set the value of the ryml::NodeRef based on the type. A valueless
    // expectation informs that an additional level of the YAML hierarchy is
    // required, thus call constructDefault again with the new ryml::NodeRef's
    // id as the root id
    switch (type) {
      case ExpectedType::Bool:
        node << chld.getDefault<bool>();
        break;
      case ExpectedType::Float:
        node << chld.getDefault<float>();
        break;
      case ExpectedType::Integer:
        node << chld.getDefault<int64_t>();
        break;
      case ExpectedType::String:
        node << chld.getDefault<std::string>();
        break;
      case ExpectedType::UInteger:
        node << chld.getDefault<uint64_t>();
        break;
      case ExpectedType::Valueless:
        node |= ryml::MAP;
        constructDefault(expectations[key], node.id());
        break;
    }
  }
}

void ModelConfig::addConfigOptions(std::string config) {
  // Construct a temporary ryml:Tree so that the values held in the passed
  // config string can be appropriately extracted
  ryml::Tree tree = ryml::parse_in_arena(ryml::to_csubstr(config));

  // Add/replace the passed config options in `configTree_` and re-run
  // validation/checks
  recursiveAdd(tree.rootref(), configTree_.root_id());
  recursiveValidate(expectations_, configTree_.rootref());
  postValidation();
}

void ModelConfig::recursiveAdd(ryml::NodeRef node, size_t id) {
  // Iterate over the config options supplied
  for (ryml::NodeRef chld : node.children()) {
    ryml::NodeRef ref;
    // If the config option doesn't already exists, add it. Otherwise get the
    // reference to it
    if (!configTree_.ref(id).has_child(chld.key())) {
      ref = configTree_.ref(id).append_child() << chld.key();
      // Set any appropriate ryml::NodeRef types
      if (chld.is_map()) {
        ref |= ryml::MAP;
      }
      if (chld.is_seq()) {
        ref |= ryml::SEQ;
      }
    } else {
      ref = configTree_.ref(id)[chld.key()];
    }
    if (chld.is_map()) {
      // If the config option had children, iterate through them.
      recursiveAdd(chld, ref.id());
    } else if (chld.is_seq()) {
      // If the config option is a sequence, then add the sequence of values
      // held within the config option (its children) as children to the current
      // ryml::Tree node identified by `id`
      ref.clear_children();
      for (size_t entry = 0; entry < chld.num_children(); entry++) {
        ref.append_child();
        ref[entry] << chld[entry].val();
      }
    } else {
      // If the config option is neither a map nor a sequence, simply add its
      // value to the ryml::Tree node reference
      ref << chld.val();
    }
  }
}

void ModelConfig::setExpectations(bool isDefault) {
  // Reset expectations
  expectations_ = {};

  // Core
  expectations_.addChild(expectations_.create("Core"));

  expectations_["Core"].addChild(
      expectations_.create<std::string>("ISA", "AArch64"));
  expectations_["Core"]["ISA"].setValueSet(
      std::vector<std::string>{"AArch64", "rv64"});

  // Early check on [Core][ISA] as its value is needed to inform the
  // expectations of other config options
  if (!isDefault) {
    std::string result = expectations_["Core"]["ISA"].validateConfigNode(
        configTree_["Core"]["ISA"]);
    std::string ISA;
    configTree_["Core"]["ISA"] >> ISA;
    if (result != "Success") {
      std::cerr << "[SimEng:ModelConfig] Invalid ISA value of \"" << ISA
                << "\" passed in config file due to \"" << result
                << "\" error. Cannot continue with config validation. Exiting."
                << std::endl;
      exit(1);
    }
    // Set ISA_
    if (ISA == "AArch64") {
      ISA_ = ISA::AArch64;
    } else if ("rv64") {
      ISA_ = ISA::RV64;
    }
  }
  createGroupMapping();

  expectations_["Core"].addChild(
      expectations_.create<std::string>("Simulation-Mode", "emulation"));
  expectations_["Core"]["Simulation-Mode"].setValueSet(
      std::vector<std::string>{"emulation", "inorderpipelined", "outoforder"});

  expectations_["Core"].addChild(expectations_.create("Clock-Frequency", 1.f));
  expectations_["Core"]["Clock-Frequency"].setValueBounds(0.f, 10.f);

  expectations_["Core"].addChild(
      expectations_.create<uint64_t>("Timer-Frequency", 100));
  expectations_["Core"]["Timer-Frequency"].setValueBounds<uint64_t>(1,
                                                                    UINT64_MAX);

  expectations_["Core"].addChild(
      expectations_.create("Micro-Operations", false));
  expectations_["Core"]["Micro-Operations"].setValueSet(
      std::vector{false, true});

  if (ISA_ == ISA::AArch64) {
    expectations_["Core"].addChild(
        expectations_.create<uint64_t, true>("Vector-Length", 512));
    expectations_["Core"]["Vector-Length"].setValueSet(
        std::vector<uint64_t>{128, 256, 384, 512, 640, 768, 896, 1024, 1152,
                              1280, 1408, 1536, 1664, 1792, 1920, 2048});

    expectations_["Core"].addChild(
        expectations_.create<uint64_t, true>("Streaming-Vector-Length", 512));
    expectations_["Core"]["Streaming-Vector-Length"].setValueSet(
        std::vector<uint64_t>{128, 256, 384, 512, 640, 768, 896, 1024, 1152,
                              1280, 1408, 1536, 1664, 1792, 1920, 2048});
  }

  // Fetch
  expectations_.addChild(expectations_.create("Fetch"));

  expectations_["Fetch"].addChild(
      expectations_.create<uint64_t>("Fetch-Block-Size", 32));
  expectations_["Fetch"]["Fetch-Block-Size"].setValueSet(std::vector<uint64_t>{
      4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096, 8192, 16384, 32768, 65536});

  expectations_["Fetch"].addChild(
      expectations_.create<uint64_t>("Loop-Buffer-Size", 32));
  expectations_["Fetch"]["Loop-Buffer-Size"].setValueBounds<uint64_t>(
      0, UINT16_MAX);

  expectations_["Fetch"].addChild(
      expectations_.create<uint64_t>("Loop-Detection-Threshold", 5));
  expectations_["Fetch"]["Loop-Detection-Threshold"].setValueBounds<uint64_t>(
      0, UINT16_MAX);

  // Process-Image
  expectations_.addChild(expectations_.create("Process-Image"));

  expectations_["Process-Image"].addChild(
      expectations_.create<uint64_t>("Heap-Size", 100000));
  expectations_["Process-Image"]["Heap-Size"].setValueBounds<uint64_t>(
      1, UINT64_MAX);

  expectations_["Process-Image"].addChild(
      expectations_.create<uint64_t>("Stack-Size", 100000));
  expectations_["Process-Image"]["Stack-Size"].setValueBounds<uint64_t>(
      1, UINT64_MAX);

  // Register-Set
  expectations_.addChild(expectations_.create("Register-Set"));
  if (ISA_ == ISA::AArch64) {
    expectations_["Register-Set"].addChild(
        expectations_.create<uint64_t>("GeneralPurpose-Count", 32));
    expectations_["Register-Set"]["GeneralPurpose-Count"]
        .setValueBounds<uint64_t>(32, UINT16_MAX);

    expectations_["Register-Set"].addChild(
        expectations_.create<uint64_t>("FloatingPoint/SVE-Count", 32));
    expectations_["Register-Set"]["FloatingPoint/SVE-Count"]
        .setValueBounds<uint64_t>(32, UINT16_MAX);

    expectations_["Register-Set"].addChild(
        expectations_.create<uint64_t, true>("Predicate-Count", 17));
    expectations_["Register-Set"]["Predicate-Count"].setValueBounds<uint64_t>(
        17, UINT16_MAX);

    expectations_["Register-Set"].addChild(
        expectations_.create<uint64_t>("Conditional-Count", 1));
    expectations_["Register-Set"]["Conditional-Count"].setValueBounds<uint64_t>(
        1, UINT16_MAX);

    expectations_["Register-Set"].addChild(
        expectations_.create<uint64_t, true>("Matrix-Count", 1));
    expectations_["Register-Set"]["Matrix-Count"].setValueBounds<uint64_t>(
        1, UINT16_MAX);
  } else if (ISA_ == ISA::RV64) {
    expectations_["Register-Set"].addChild(
        expectations_.create<uint64_t>("GeneralPurpose-Count", 32));
    expectations_["Register-Set"]["GeneralPurpose-Count"]
        .setValueBounds<uint64_t>(32, UINT16_MAX);

    expectations_["Register-Set"].addChild(
        expectations_.create<uint64_t>("FloatingPoint-Count", 32));
    expectations_["Register-Set"]["FloatingPoint-Count"]
        .setValueBounds<uint64_t>(32, UINT16_MAX);
  }

  // Pipeline-Widths
  expectations_.addChild(expectations_.create("Pipeline-Widths"));

  expectations_["Pipeline-Widths"].addChild(
      expectations_.create<uint64_t>("Commit", 1));
  expectations_["Pipeline-Widths"]["Commit"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["Pipeline-Widths"].addChild(
      expectations_.create<uint64_t>("FrontEnd", 1));
  expectations_["Pipeline-Widths"]["FrontEnd"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["Pipeline-Widths"].addChild(
      expectations_.create<uint64_t>("LSQ-Completion", 1));
  expectations_["Pipeline-Widths"]["LSQ-Completion"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  // Queue-Sizes
  expectations_.addChild(expectations_.create("Queue-Sizes"));

  expectations_["Queue-Sizes"].addChild(
      expectations_.create<uint64_t>("ROB", 32));
  expectations_["Queue-Sizes"]["ROB"].setValueBounds<uint64_t>(1, UINT16_MAX);

  expectations_["Queue-Sizes"].addChild(
      expectations_.create<uint64_t>("Load", 16));
  expectations_["Queue-Sizes"]["Load"].setValueBounds<uint64_t>(1, UINT16_MAX);

  expectations_["Queue-Sizes"].addChild(
      expectations_.create<uint64_t>("Store", 16));
  expectations_["Queue-Sizes"]["Store"].setValueBounds<uint64_t>(1, UINT16_MAX);

  // Branch-Predictor
  expectations_.addChild(expectations_.create("Branch-Predictor"));

  expectations_["Branch-Predictor"].addChild(
      expectations_.create<uint64_t>("BTB-Tag-Bits", 8));
  expectations_["Branch-Predictor"]["BTB-Tag-Bits"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["Branch-Predictor"].addChild(
      expectations_.create<uint64_t>("Saturating-Count-Bits", 2));
  expectations_["Branch-Predictor"]["Saturating-Count-Bits"]
      .setValueBounds<uint64_t>(1, 64);

  expectations_["Branch-Predictor"].addChild(
      expectations_.create<uint64_t>("Global-History-Length", 8));
  expectations_["Branch-Predictor"]["Global-History-Length"]
      .setValueBounds<uint64_t>(1, UINT16_MAX);

  expectations_["Branch-Predictor"].addChild(
      expectations_.create<uint64_t>("RAS-entries", 8));
  expectations_["Branch-Predictor"]["RAS-entries"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["Branch-Predictor"].addChild(expectations_.create<std::string>(
      "Fallback-Static-Predictor", "Always-Taken"));
  expectations_["Branch-Predictor"]["Fallback-Static-Predictor"].setValueSet(
      std::vector<std::string>{"Always-Taken", "Always-Not-Taken"});

  // L1-Data-Memory
  expectations_.addChild(expectations_.create("L1-Data-Memory"));

  expectations_["L1-Data-Memory"].addChild(
      expectations_.create<std::string>("Interface-Type", "Flat"));
  expectations_["L1-Data-Memory"]["Interface-Type"].setValueSet(
      std::vector<std::string>{"Flat", "Fixed", "External"});

  // L1-Instruction-Memory
  expectations_.addChild(expectations_.create("L1-Instruction-Memory"));

  expectations_["L1-Instruction-Memory"].addChild(
      expectations_.create<std::string>("Interface-Type", "Flat"));
  expectations_["L1-Instruction-Memory"]["Interface-Type"].setValueSet(
      std::vector<std::string>{"Flat", "Fixed", "External"});

  // LSQ-L1-Interface
  expectations_.addChild(expectations_.create("LSQ-L1-Interface"));

  expectations_["LSQ-L1-Interface"].addChild(
      expectations_.create<uint64_t>("Access-Latency", 4));
  expectations_["LSQ-L1-Interface"]["Access-Latency"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["LSQ-L1-Interface"].addChild(
      expectations_.create("Exclusive", false));
  expectations_["LSQ-L1-Interface"]["Exclusive"].setValueSet(
      std::vector{false, true});

  expectations_["LSQ-L1-Interface"].addChild(
      expectations_.create<uint64_t>("Load-Bandwidth", 32));
  expectations_["LSQ-L1-Interface"]["Load-Bandwidth"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["LSQ-L1-Interface"].addChild(
      expectations_.create<uint64_t>("Store-Bandwidth", 32));
  expectations_["LSQ-L1-Interface"]["Store-Bandwidth"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["LSQ-L1-Interface"].addChild(
      expectations_.create<uint64_t>("Permitted-Requests-Per-Cycle", 1));
  expectations_["LSQ-L1-Interface"]["Permitted-Requests-Per-Cycle"]
      .setValueBounds<uint64_t>(1, UINT16_MAX);

  expectations_["LSQ-L1-Interface"].addChild(
      expectations_.create<uint64_t>("Permitted-Loads-Per-Cycle", 1));
  expectations_["LSQ-L1-Interface"]["Permitted-Loads-Per-Cycle"]
      .setValueBounds<uint64_t>(1, UINT16_MAX);

  expectations_["LSQ-L1-Interface"].addChild(
      expectations_.create<uint64_t>("Permitted-Stores-Per-Cycle", 1));
  expectations_["LSQ-L1-Interface"]["Permitted-Stores-Per-Cycle"]
      .setValueBounds<uint64_t>(1, UINT16_MAX);

  // Ports
  expectations_.addChild(expectations_.create("Ports"));
  expectations_["Ports"].addChild(expectations_.create<uint64_t>("*", 0));

  expectations_["Ports"]["*"].addChild(
      expectations_.create<std::string>("Portname", "0"));

  expectations_["Ports"]["*"].addChild(expectations_.create<std::string, true>(
      "Instruction-Group-Support", "ALL"));
  expectations_["Ports"]["*"]["Instruction-Group-Support"].setValueSet(
      groupOptions_);
  expectations_["Ports"]["*"]["Instruction-Group-Support"].setAsSequence();

  // Get the upper bound of what the opcode value can be based on the ISA
  uint64_t maxOpcode = 0;
  if (ISA_ == ISA::AArch64) {
    maxOpcode = arch::aarch64::Opcode::AArch64_INSTRUCTION_LIST_END;
  } else if (ISA_ == ISA::RV64) {
    maxOpcode = arch::riscv::Opcode::RISCV_INSTRUCTION_LIST_END;
  }
  expectations_["Ports"]["*"].addChild(expectations_.create<uint64_t, true>(
      "Instruction-Opcode-Support", maxOpcode));
  expectations_["Ports"]["*"]["Instruction-Opcode-Support"]
      .setValueBounds<uint64_t>(0, maxOpcode);
  expectations_["Ports"]["*"]["Instruction-Opcode-Support"].setAsSequence();

  // Early check on [Ports][*][Portname] as the values are needed to inform
  // the expectations of the [Reservation-Stations][*][Ports] values
  std::vector<std::string> portnames = {"0"};
  if (!isDefault) {
    portnames = {};
    // An index value used in case of error
    uint16_t idx = 0;
    // Get all portnames defined in the config file and ensure they are unique
    for (ryml::NodeRef chld : configTree_["Ports"]) {
      std::string result =
          expectations_["Ports"]["*"]["Portname"].validateConfigNode(
              chld["Portname"]);
      std::string portname;
      chld["Portname"] >> portname;
      if (result == "Success") {
        if (std::find(portnames.begin(), portnames.end(), portname) ==
            portnames.end()) {
          portnames.push_back(portname);
        } else {
          invalid_ << "\t- duplicate portname \"" << portname << "\"\n";
        }
      } else {
        std::cerr
            << "[SimEng:ModelConfig] Invalid portname for port " << idx
            << ", namely \"" << portname
            << "\", passed in config file due to \"" << result
            << "\" error. Cannot continue with config validation. Exiting."
            << std::endl;
        exit(1);
      }
      idx++;
    }
  }

  // Reservation-Stations
  expectations_.addChild(expectations_.create("Reservation-Stations"));
  expectations_["Reservation-Stations"].addChild(
      expectations_.create<uint64_t>("*", 0));

  expectations_["Reservation-Stations"]["*"].addChild(
      expectations_.create<uint64_t>("Size", 32));
  expectations_["Reservation-Stations"]["*"]["Size"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["Reservation-Stations"]["*"].addChild(
      expectations_.create<uint64_t>("Dispatch-Rate", 4));
  expectations_["Reservation-Stations"]["*"]["Dispatch-Rate"]
      .setValueBounds<uint64_t>(1, UINT16_MAX);

  expectations_["Reservation-Stations"]["*"].addChild(
      expectations_.create<std::string>("Ports", "0"));
  expectations_["Reservation-Stations"]["*"]["Ports"].setValueSet(portnames);
  expectations_["Reservation-Stations"]["*"]["Ports"].setAsSequence();

  // Execution-Units
  expectations_.addChild(expectations_.create("Execution-Units"));
  expectations_["Execution-Units"].addChild(
      expectations_.create<uint64_t>("*", 0));

  expectations_["Execution-Units"]["*"].addChild(
      expectations_.create("Pipelined", true));
  expectations_["Execution-Units"]["*"]["Pipelined"].setValueSet(
      std::vector{false, true});

  expectations_["Execution-Units"]["*"].addChild(
      expectations_.create<std::string, true>("Blocking-Groups", "NONE"));
  expectations_["Execution-Units"]["*"]["Blocking-Groups"].setValueSet(
      groupOptions_);
  expectations_["Execution-Units"]["*"]["Blocking-Groups"].setAsSequence();

  // Latencies
  expectations_.addChild(expectations_.create<true>("Latencies"));
  expectations_["Latencies"].addChild(expectations_.create<uint64_t>("*", 0));

  expectations_["Latencies"]["*"].addChild(
      expectations_.create<std::string, true>("Instruction-Groups", "NONE"));
  expectations_["Latencies"]["*"]["Instruction-Groups"].setValueSet(
      groupOptions_);
  expectations_["Latencies"]["*"]["Instruction-Groups"].setAsSequence();

  expectations_["Latencies"]["*"].addChild(
      expectations_.create<uint64_t, true>("Instruction-Opcodes", maxOpcode));
  expectations_["Latencies"]["*"]["Instruction-Opcodes"]
      .setValueBounds<uint64_t>(0, maxOpcode);
  expectations_["Latencies"]["*"]["Instruction-Opcodes"].setAsSequence();

  expectations_["Latencies"]["*"].addChild(
      expectations_.create<uint64_t>("Execution-Latency", 1));
  expectations_["Latencies"]["*"]["Execution-Latency"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["Latencies"]["*"].addChild(
      expectations_.create<uint64_t, true>("Execution-Throughput", 1));
  expectations_["Latencies"]["*"]["Execution-Throughput"]
      .setValueBounds<uint64_t>(1, UINT16_MAX);

  // CPU-Info
  expectations_.addChild(expectations_.create("CPU-Info"));

  expectations_["CPU-Info"].addChild(
      expectations_.create<bool, true>("Generate-Special-Dir", false));
  expectations_["CPU-Info"]["Generate-Special-Dir"].setValueSet(
      std::vector{false, true});

  expectations_["CPU-Info"].addChild(
      expectations_.create<uint64_t, true>("Core-Count", 1));
  expectations_["CPU-Info"]["Core-Count"].setValueBounds<uint64_t>(1,
                                                                   UINT16_MAX);

  expectations_["CPU-Info"].addChild(
      expectations_.create<uint64_t, true>("Socket-Count", 1));
  expectations_["CPU-Info"]["Socket-Count"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["CPU-Info"].addChild(
      expectations_.create<uint64_t, true>("SMT", 1));
  expectations_["CPU-Info"]["SMT"].setValueBounds<uint64_t>(1, UINT16_MAX);

  expectations_["CPU-Info"].addChild(
      expectations_.create<float, true>("BogoMIPS", 0.f));
  expectations_["CPU-Info"]["BogoMIPS"].setValueBounds(
      0.f, std::numeric_limits<float>::max());

  expectations_["CPU-Info"].addChild(
      expectations_.create<std::string, true>("Features", ""));

  expectations_["CPU-Info"].addChild(
      expectations_.create<std::string, true>("CPU-Implementer", "0x0"));

  expectations_["CPU-Info"].addChild(
      expectations_.create<uint64_t, true>("CPU-Architecture", 0));
  expectations_["CPU-Info"]["CPU-Architecture"].setValueBounds<uint64_t>(
      0, UINT16_MAX);

  expectations_["CPU-Info"].addChild(
      expectations_.create<std::string, true>("CPU-Variant", "0x0"));

  expectations_["CPU-Info"].addChild(
      expectations_.create<std::string, true>("CPU-Part", "0x0"));

  expectations_["CPU-Info"].addChild(
      expectations_.create<uint64_t, true>("CPU-Revision", 0));
  expectations_["CPU-Info"]["CPU-Revision"].setValueBounds<uint64_t>(
      0, UINT16_MAX);

  expectations_["CPU-Info"].addChild(
      expectations_.create<uint64_t, true>("Package-Count", 1));
  expectations_["CPU-Info"]["Package-Count"].setValueBounds<uint64_t>(
      1, UINT16_MAX);
}

void ModelConfig::recursiveValidate(expectationNode expectation,
                                    ryml::NodeRef node,
                                    std::string hierarchyString) {
  // Iterate over passed expectations
  for (auto& chld : expectation.getChildren()) {
    std::string nodeKey = chld.getKey();
    // If the expectation is a wildcard, then iterate over the associated
    // children in the config option using the same expectation(s)
    if (nodeKey == "*") {
      for (ryml::NodeRef rymlChld : node) {
        // An index value used in case of error
        std::string idx =
            std::string(rymlChld.key().data(), rymlChld.key().size());
        std::string result = chld.validateConfigNode(rymlChld);
        if (result != "Success")
          invalid_ << "\t- " << hierarchyString + idx + " " + result + "\n";
        recursiveValidate(chld, rymlChld, hierarchyString + idx + ":");
      }
    } else if (node.has_child(ryml::to_csubstr(nodeKey))) {
      // If the config file contains the key of the expectation node, get
      // it
      ryml::NodeRef rymlChld = node[ryml::to_csubstr(nodeKey)];
      if (chld.isSequence()) {
        // If the expectation node is a sequence, then treat the ryml::NodeRef
        // as a parent and validate all its children against the expectation
        // node
        int idx = 0;
        for (ryml::NodeRef grndChld : rymlChld) {
          std::string result = chld.validateConfigNode(grndChld);
          if (result != "Success")
            invalid_ << "\t- "
                     << hierarchyString + ":" + nodeKey + ":" +
                            std::to_string(idx) + " " + result + "\n";
          idx++;
        }
      } else {
        // If the expectation node is not a sequence, validate the config
        // option against the current expectations and if it has children,
        // validate those recursively
        std::string result = chld.validateConfigNode(rymlChld);
        if (result != "Success")
          invalid_ << "\t- " << hierarchyString + nodeKey + " " + result + "\n";
        if (chld.getChildren().size()) {
          recursiveValidate(chld, rymlChld, hierarchyString + nodeKey + ":");
        }
      }
    } else {
      // If the config file doesn't contain the key of the expectation node,
      // create is as a child to the config ryml::NodeRef supplied. If the
      // config option is optional, a default value will be injected,
      // otherwise the validation will fail
      ryml::NodeRef rymlChld = node.append_child() << ryml::key(nodeKey);
      // Set the new ryml::NodeRef to be a sequence and give it a child node
      if (chld.isSequence()) {
        rymlChld |= ryml::SEQ;
        rymlChld = rymlChld.append_child();
      }
      std::string result = chld.validateConfigNode(rymlChld);
      if (result != "Success")
        invalid_ << "\t- " << hierarchyString + nodeKey + " " + result + "\n";
    }
  }
}

void ModelConfig::postValidation() {
  // Ensure package_count size is a less than or equal to the core count,
  // and that the core count can be divided by the package count
  uint64_t packageCount;
  configTree_["CPU-Info"]["Package-Count"] >> packageCount;
  uint64_t coreCount;
  configTree_["CPU-Info"]["Core-Count"] >> coreCount;
  if (!((packageCount <= coreCount) && (coreCount % packageCount == 0))) {
    invalid_ << "\t- Package-Count must be a Less-than or equal to Core-Count, "
                "and Core-Count must be divisible by Package-Count.";
  }

  // Convert all instruction group strings to their corresponding group
  // numbers into another config option
  for (ryml::NodeRef node : configTree_["Ports"]) {
    // Clear or create a new Instruction-Group-Support-Nums config option
    if (node.has_child("Instruction-Group-Support-Nums")) {
      node["Instruction-Group-Support-Nums"].clear_children();
    } else {
      node.append_child() << ryml::key("Instruction-Group-Support-Nums") |=
          ryml::SEQ;
    }
    // Read in each group and place its corresponding group number into the
    // new config option
    for (ryml::NodeRef chld : node["Instruction-Group-Support"]) {
      std::string groupStr;
      chld >> groupStr;
      node["Instruction-Group-Support-Nums"].append_child()
          << groupMapping_[groupStr];
    }
  }
  for (ryml::NodeRef node : configTree_["Execution-Units"]) {
    // Clear or create a new Blocking-Group-Nums config option
    if (node.has_child("Blocking-Group-Nums")) {
      node["Blocking-Group-Nums"].clear_children();
    } else {
      node.append_child() << ryml::key("Blocking-Group-Nums") |= ryml::SEQ;
    }
    // Read in each group and place its corresponding group number into the
    // new config option
    for (ryml::NodeRef chld : node["Blocking-Groups"]) {
      std::string groupStr;
      chld >> groupStr;
      node["Blocking-Group-Nums"].append_child() << groupMapping_[groupStr];
    }
  }
  for (ryml::NodeRef node : configTree_["Latencies"]) {
    // Clear or create a new Instruction-Group-Nums config option
    if (node.has_child("Instruction-Group-Nums")) {
      node["Instruction-Group-Nums"].clear_children();
    } else {
      node.append_child() << ryml::key("Instruction-Group-Nums") |= ryml::SEQ;
    }
    // Read in each group and place its corresponding group number into the
    // new config option
    for (ryml::NodeRef chld : node["Instruction-Groups"]) {
      std::string groupStr;
      chld >> groupStr;
      node["Instruction-Group-Nums"].append_child() << groupMapping_[groupStr];
    }
  }

  // Ensure all execution ports have an associated reservation station and
  // convert port strings to their associated port indexes
  std::vector<std::string> portnames;
  std::unordered_map<std::string, uint16_t> portIndexes;
  uint16_t idx = 0;
  // Read all available port names.
  for (ryml::NodeRef node : configTree_["Ports"]) {
    std::string portname;
    node["Portname"] >> portname;
    portnames.push_back(portname);
    portIndexes[portname] = idx++;
  }
  // Iterate over all [Reservation-Stations][Ports] children
  for (ryml::NodeRef node : configTree_["Reservation-Stations"]) {
    // Clear or create a new Port-Nums config option
    if (node.has_child("Port-Nums")) {
      node["Port-Nums"].clear_children();
    } else {
      node.append_child() << ryml::key("Port-Nums") |= ryml::SEQ;
    }
    for (int i = 0; i < node["Ports"].num_children(); i++) {
      std::string portname;
      node["Ports"][i] >> portname;
      std::vector<std::string>::iterator itr =
          std::find(portnames.begin(), portnames.end(), portname);
      // If a port is yet to be marked as linked, remove it from portnames
      if (itr != portnames.end()) {
        portnames.erase(itr);
      }
      // Place the port's corresponding index into the new config option
      node["Port-Nums"].append_child() << portIndexes[portname];
    }
  }
  // Record any unlinked port names
  for (const auto& prt : portnames)
    invalid_ << "\t- " << prt << " has no associated reservation station\n";
}

ryml::Tree ModelConfig::getConfig() { return configTree_; }

void ModelConfig::createGroupMapping() {
  if (ISA_ == ISA::AArch64) {
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
                     "BRANCH",
                     "SME",
                     "SME_SIMPLE",
                     "SME_SIMPLE_ARTH",
                     "SME_SIMPLE_ARTH_NOSHIFT",
                     "SME_SIMPLE_LOGICAL",
                     "SME_SIMPLE_LOGICAL_NOSHIFT",
                     "SME_SIMPLE_CMP",
                     "SME_SIMPLE_CVT",
                     "SME_MUL",
                     "SME_DIV_OR_SQRT",
                     "LOAD_SME",
                     "STORE_ADDRESS_SME",
                     "STORE_DATA_SME",
                     "STORE_SME",
                     "ALL",
                     "NONE"};
  } else if (ISA_ == ISA::RV64) {
    groupOptions_ = {"INT",
                     "INT_SIMPLE",
                     "INT_SIMPLE_ARTH",
                     "INT_SIMPLE_CMP",
                     "INT_SIMPLE_LOGICAL",
                     "INT_SIMPLE_SHIFT",
                     "INT_MUL",
                     "INT_DIV",
                     "LOAD_INT",
                     "STORE_INT",
                     "LOAD",
                     "STORE",
                     "BRANCH",
                     "ALL",
                     "NONE"};
  }
  // ISA instruction group namespaces contain a set of contiguous assigned
  // uint16_t starting from 0. Therefore, the index of each groupOptions_
  // entry is also its <isa>::InstructionGroups value (assuming groupOptions_
  // is ordered exactly as <isa>::InstructionGroups is).
  for (int grp = 0; grp < groupOptions_.size(); grp++) {
    groupMapping_[groupOptions_[grp]] = grp;
  }
}

}  // namespace config
}  // namespace simeng
