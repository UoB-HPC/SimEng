#define RYML_SINGLE_HDR_DEFINE_NOW
#include "simeng/config/ModelConfig.hh"

#include <cmath>

#include "arch/aarch64/InstructionMetadata.hh"
#include "arch/riscv/InstructionMetadata.hh"

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
  validate();
}

ModelConfig::ModelConfig() {
  // Generate the default config file
  generateDefault();
}

void ModelConfig::validate() {
  missing_.clear();
  invalid_.clear();

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
}

void ModelConfig::reGenerateDefault(ISA isa, bool force) {
  // Only re-generate the default config file if it hasn't already been
  // generated for the specified ISA
  if (!force && (isa_ == isa && isDefault_)) return;
  isa_ = isa;
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
  validate();
}

void ModelConfig::constructDefault(ExpectationNode expectations,
                                   size_t root_id) {
  // Iterate over the expectations supplied
  for (const auto& child : expectations.getChildren()) {
    std::string key = child.getKey();
    ExpectedType type = child.getType();
    // If the key is a wildcard, then change it to be an appropriate value
    // in the resultant config file and its type to be valueless
    if (key == wildcard) {
      key = "0";
      type = ExpectedType::Valueless;
    }
    // Create the ryml::NodeRef representing a config option
    ryml::NodeRef node = configTree_.ref(root_id).append_child()
                         << ryml::key(key);
    // If the expectation is a sequence, then add an additional ryml::NodeRef as
    // a child to the former to act as the sequence of values when read in later
    if (child.isSequence()) {
      node |= ryml::SEQ;
      node = configTree_.ref(node.id()).append_child();
    }
    // Set the value of the ryml::NodeRef based on the type. A valueless
    // expectation informs that an additional level of the YAML hierarchy is
    // required, thus call constructDefault again with the new ryml::NodeRef's
    // id as the root id
    switch (type) {
      case ExpectedType::Bool:
        node << child.getDefault<bool>();
        break;
      case ExpectedType::Double:
        node << child.getDefault<double>();
        break;
      case ExpectedType::Float:
        node << child.getDefault<float>();
        break;
      case ExpectedType::Integer8:
        node << child.getDefault<int8_t>();
        break;
      case ExpectedType::Integer16:
        node << child.getDefault<int16_t>();
        break;
      case ExpectedType::Integer32:
        node << child.getDefault<int32_t>();
        break;
      case ExpectedType::Integer64:
        node << child.getDefault<int64_t>();
        break;
      case ExpectedType::String:
        node << child.getDefault<std::string>();
        break;
      case ExpectedType::UInteger8:
        node << child.getDefault<uint8_t>();
        break;
      case ExpectedType::UInteger16:
        node << child.getDefault<uint16_t>();
        break;
      case ExpectedType::UInteger32:
        node << child.getDefault<uint32_t>();
        break;
      case ExpectedType::UInteger64:
        node << child.getDefault<uint64_t>();
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
  setExpectations();

  // If the config additions result in a smaller config tree then errors can
  // occur where node ids are greater than the size of the ryml::Tree. To
  // combat this, a new tree is created to reassign node ids such that none are
  // greater than the size of the ryml::Tree
  ryml::Tree tmp;
  // Copy all config values over to a temporary tree
  tmp.rootref() |= ryml::MAP;
  tmp.duplicate_children(&configTree_, configTree_.root_id(), tmp.root_id(),
                         -1);
  // Clear configTree_ and copy config values back over but with new assigned
  // node ids
  configTree_.clear();
  configTree_.rootref() |= ryml::MAP;
  configTree_.duplicate_children(&tmp, tmp.root_id(), tmp.root_id(), -1);

  validate();
}

void ModelConfig::recursiveAdd(ryml::NodeRef node, size_t id) {
  // Iterate over the config options supplied
  for (ryml::NodeRef child : node.children()) {
    ryml::NodeRef ref;
    // If the config option doesn't already exists, add it. Otherwise get the
    // reference to it
    if (!configTree_.ref(id).has_child(child.key())) {
      std::string key = std::string(child.key().data(), child.key().size());
      ref = configTree_.ref(id).append_child() << ryml::key(key);
      // Set any appropriate ryml::NodeRef types
      if (child.is_map()) {
        ref |= ryml::MAP;
      }
      if (child.is_seq()) {
        ref |= ryml::SEQ;
      }
    } else {
      ref = configTree_.ref(id)[child.key()];
    }
    if (child.is_map()) {
      // If the config option had children, iterate through them.
      recursiveAdd(child, ref.id());
    } else if (child.is_seq()) {
      // If the config option is a sequence, then add the sequence of values
      // held within the config option (its children) as children to the current
      // ryml::Tree node identified by `id`
      ref.clear_children();
      for (size_t entry = 0; entry < child.num_children(); entry++) {
        ref.append_child();
        ref[entry] << child[entry].val();
      }
    } else {
      // If the config option is neither a map nor a sequence, simply add its
      // value to the ryml::Tree node reference
      ref << child.val();
    }
  }
}

void ModelConfig::setExpectations(bool isDefault) {
  // Reset expectations
  expectations_ = {};

  // Core
  expectations_.addChild(ExpectationNode::createExpectation("Core"));

  if (isa_ == ISA::AArch64)
    expectations_["Core"].addChild(
        ExpectationNode::createExpectation<std::string>("AArch64", "ISA"));
  else if (isa_ == ISA::RV64)
    expectations_["Core"].addChild(
        ExpectationNode::createExpectation<std::string>("rv64", "ISA"));
  expectations_["Core"]["ISA"].setValueSet(
      std::vector<std::string>{"AArch64", "rv64"});

  // Early check on [Core][ISA] as its value is needed to inform the
  // expectations of other config options
  if (!isDefault) {
    // Ensure the key "Core" exists before querying the associated YAML node
    if (configTree_.rootref().has_child(ryml::to_csubstr("Core"))) {
      // Ensure the key "Core:ISA" exists before querying the associated YAML
      // node
      if (configTree_["Core"].has_child(ryml::to_csubstr("ISA"))) {
        ValidationResult result =
            expectations_["Core"]["ISA"].validateConfigNode(
                configTree_["Core"]["ISA"]);
        std::string ISA = configTree_["Core"]["ISA"].as<std::string>();
        if (!result.valid) {
          std::cerr
              << "[SimEng:ModelConfig] Invalid ISA value of \"" << ISA
              << "\" passed in config file due to \"" << result.message
              << "\" error. Cannot continue with config validation. Exiting."
              << std::endl;
          exit(1);
        }
        // Set isa_
        if (ISA == "AArch64") {
          isa_ = ISA::AArch64;
        } else if (ISA == "rv64") {
          isa_ = ISA::RV64;
        }
      } else {
        std::cerr
            << "[SimEng:ModelConfig] Attempted to access config key "
               "\"Core:ISA\" but it doesn't exist. Cannot continue with config "
               "validation. Exiting."
            << std::endl;
        exit(1);
      }
    } else {
      std::cerr << "[SimEng:ModelConfig] Attempted to access config key "
                   "\"Core\" but it doesn't exist. Cannot continue with config "
                   "validation. Exiting."
                << std::endl;
      exit(1);
    }
  }
  createGroupMapping();

  if (isa_ == ISA::RV64) {
    expectations_["Core"].addChild(
        ExpectationNode::createExpectation<bool>(false, "Compressed"));
    expectations_["Core"]["Compressed"].setValueSet(std::vector{false, true});
  }

  expectations_["Core"].addChild(
      ExpectationNode::createExpectation<std::string>("emulation",
                                                      "Simulation-Mode"));
  expectations_["Core"]["Simulation-Mode"].setValueSet(
      std::vector<std::string>{"emulation", "inorderpipelined", "outoforder"});

  const float clockFreqUpperBound = 10.f;
  expectations_["Core"].addChild(
      ExpectationNode::createExpectation<float>(1.f, "Clock-Frequency-GHz"));
  expectations_["Core"]["Clock-Frequency-GHz"].setValueBounds(
      0.001f, clockFreqUpperBound);

  // Early check on ["Core"]["Clock-Frequency-GHz"] as values are needed to
  // inform the expected lower bound of the ["Core"]["Timer-Frequency-MHz"]
  // value
  uint64_t tFreqUpperBound = clockFreqUpperBound * 1000;
  if (!isDefault) {
    // Ensure the key "Core" exists before querying the associated YAML node
    if (configTree_.rootref().has_child(ryml::to_csubstr("Core"))) {
      // Ensure the key "Core:Clock-Frequency-GHz" exists before querying the
      // associated YAML node
      if (configTree_["Core"].has_child(
              ryml::to_csubstr("Clock-Frequency-GHz"))) {
        ValidationResult result =
            expectations_["Core"]["Clock-Frequency-GHz"].validateConfigNode(
                configTree_["Core"]["Clock-Frequency-GHz"]);
        float clockFreq =
            configTree_["Core"]["Clock-Frequency-GHz"].as<float>();
        if (!result.valid) {
          std::cerr
              << "[SimEng:ModelConfig] Invalid Clock-Frequency-GHz value of \""
              << clockFreq << "\" passed in config file due to \""
              << result.message
              << "\" error. Cannot continue with config validation. Exiting."
              << std::endl;
          exit(1);
        }

        tFreqUpperBound = clockFreq * 1000;
      } else {
        std::cerr << "[SimEng:ModelConfig] Attempted to access config key "
                     "\"Core:Clock-Frequency-GHz\" but it doesn't exist. "
                     "Cannot continue with config "
                     "validation. Exiting."
                  << std::endl;
        exit(1);
      }
    } else {
      std::cerr << "[SimEng:ModelConfig] Attempted to access config key "
                   "\"Core\" but it doesn't exist. Cannot continue with config "
                   "validation. Exiting."
                << std::endl;
      exit(1);
    }
  }

  expectations_["Core"].addChild(
      ExpectationNode::createExpectation<uint32_t>(100, "Timer-Frequency-MHz"));
  expectations_["Core"]["Timer-Frequency-MHz"].setValueBounds<uint32_t>(
      1, tFreqUpperBound);

  expectations_["Core"].addChild(ExpectationNode::createExpectation<bool>(
      false, "Micro-Operations", true));
  expectations_["Core"]["Micro-Operations"].setValueSet(
      std::vector{false, true});

  if (isa_ == ISA::AArch64) {
    expectations_["Core"].addChild(ExpectationNode::createExpectation<uint64_t>(
        128, "Vector-Length", true));
    expectations_["Core"]["Vector-Length"].setValueSet(
        std::vector<uint64_t>{128, 256, 384, 512, 640, 768, 896, 1024, 1152,
                              1280, 1408, 1536, 1664, 1792, 1920, 2048});

    expectations_["Core"].addChild(ExpectationNode::createExpectation<uint64_t>(
        128, "Streaming-Vector-Length", true));
    expectations_["Core"]["Streaming-Vector-Length"].setValueSet(
        std::vector<uint64_t>{128, 256, 512, 1024, 2048});
  }

  // Fetch
  expectations_.addChild(ExpectationNode::createExpectation("Fetch"));

  expectations_["Fetch"].addChild(
      ExpectationNode::createExpectation<uint16_t>(32, "Fetch-Block-Size"));
  expectations_["Fetch"]["Fetch-Block-Size"].setValueSet(std::vector<uint16_t>{
      4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768});

  expectations_["Fetch"].addChild(
      ExpectationNode::createExpectation<uint16_t>(32, "Loop-Buffer-Size"));
  expectations_["Fetch"]["Loop-Buffer-Size"].setValueBounds<uint16_t>(
      0, UINT16_MAX);

  expectations_["Fetch"].addChild(ExpectationNode::createExpectation<uint16_t>(
      5, "Loop-Detection-Threshold"));
  expectations_["Fetch"]["Loop-Detection-Threshold"].setValueBounds<uint16_t>(
      0, UINT16_MAX);

  // Process-Image
  expectations_.addChild(ExpectationNode::createExpectation("Process-Image"));

  expectations_["Process-Image"].addChild(
      ExpectationNode::createExpectation<uint64_t>(100000, "Heap-Size"));
  expectations_["Process-Image"]["Heap-Size"].setValueBounds<uint64_t>(
      1, UINT64_MAX);

  expectations_["Process-Image"].addChild(
      ExpectationNode::createExpectation<uint64_t>(100000, "Stack-Size"));
  expectations_["Process-Image"]["Stack-Size"].setValueBounds<uint64_t>(
      1, UINT64_MAX);

  // Register-Set
  expectations_.addChild(ExpectationNode::createExpectation("Register-Set"));
  if (isa_ == ISA::AArch64) {
    // TODO: Reduce to 32 once renaming issue has been sorted. Also replace in
    // ConfigTest.
    expectations_["Register-Set"].addChild(
        ExpectationNode::createExpectation<uint16_t>(38,
                                                     "GeneralPurpose-Count"));
    expectations_["Register-Set"]["GeneralPurpose-Count"]
        .setValueBounds<uint16_t>(38, UINT16_MAX);

    // TODO: Reduce to 32 once renaming issue has been sorted. Also replace in
    // ConfigTest.
    expectations_["Register-Set"].addChild(
        ExpectationNode::createExpectation<uint16_t>(
            38, "FloatingPoint/SVE-Count"));
    expectations_["Register-Set"]["FloatingPoint/SVE-Count"]
        .setValueBounds<uint16_t>(38, UINT16_MAX);

    expectations_["Register-Set"].addChild(
        ExpectationNode::createExpectation<uint16_t>(17, "Predicate-Count",
                                                     true));
    expectations_["Register-Set"]["Predicate-Count"].setValueBounds<uint16_t>(
        17, UINT16_MAX);

    expectations_["Register-Set"].addChild(
        ExpectationNode::createExpectation<uint16_t>(1, "Conditional-Count"));
    expectations_["Register-Set"]["Conditional-Count"].setValueBounds<uint16_t>(
        1, UINT16_MAX);

    expectations_["Register-Set"].addChild(
        ExpectationNode::createExpectation<uint16_t>(1, "Matrix-Count", true));
    expectations_["Register-Set"]["Matrix-Count"].setValueBounds<uint16_t>(
        1, UINT16_MAX);
  } else if (isa_ == ISA::RV64) {
    // TODO: Reduce to 32 once renaming issue has been sorted. Also replace in
    // ConfigTest.
    expectations_["Register-Set"].addChild(
        ExpectationNode::createExpectation<uint16_t>(38,
                                                     "GeneralPurpose-Count"));
    // TODO: Reduce to 32 once renaming issue has been sorted
    expectations_["Register-Set"]["GeneralPurpose-Count"]
        .setValueBounds<uint16_t>(38, UINT16_MAX);

    // TODO: Reduce to 32 once renaming issue has been sorted. Also replace in
    // ConfigTest.
    expectations_["Register-Set"].addChild(
        ExpectationNode::createExpectation<uint16_t>(38,
                                                     "FloatingPoint-Count"));
    // TODO: Reduce to 32 once renaming issue has been sorted
    expectations_["Register-Set"]["FloatingPoint-Count"]
        .setValueBounds<uint16_t>(38, UINT16_MAX);
  }

  // Pipeline-Widths
  expectations_.addChild(ExpectationNode::createExpectation("Pipeline-Widths"));

  expectations_["Pipeline-Widths"].addChild(
      ExpectationNode::createExpectation<uint16_t>(1, "Commit"));
  expectations_["Pipeline-Widths"]["Commit"].setValueBounds<uint16_t>(
      1, UINT16_MAX);

  expectations_["Pipeline-Widths"].addChild(
      ExpectationNode::createExpectation<uint16_t>(1, "FrontEnd"));
  expectations_["Pipeline-Widths"]["FrontEnd"].setValueBounds<uint16_t>(
      1, UINT16_MAX);

  expectations_["Pipeline-Widths"].addChild(
      ExpectationNode::createExpectation<uint16_t>(1, "LSQ-Completion"));
  expectations_["Pipeline-Widths"]["LSQ-Completion"].setValueBounds<uint16_t>(
      1, UINT16_MAX);

  // Queue-Sizes
  expectations_.addChild(ExpectationNode::createExpectation("Queue-Sizes"));

  expectations_["Queue-Sizes"].addChild(
      ExpectationNode::createExpectation<uint32_t>(32, "ROB"));
  expectations_["Queue-Sizes"]["ROB"].setValueBounds<uint32_t>(1, UINT32_MAX);

  expectations_["Queue-Sizes"].addChild(
      ExpectationNode::createExpectation<uint32_t>(16, "Load"));
  expectations_["Queue-Sizes"]["Load"].setValueBounds<uint32_t>(1, UINT32_MAX);

  expectations_["Queue-Sizes"].addChild(
      ExpectationNode::createExpectation<uint32_t>(16, "Store"));
  expectations_["Queue-Sizes"]["Store"].setValueBounds<uint32_t>(1, UINT32_MAX);

  // Branch-Predictor
  expectations_.addChild(
      ExpectationNode::createExpectation("Branch-Predictor"));

  expectations_["Branch-Predictor"].addChild(
      ExpectationNode::createExpectation<std::string>("Perceptron", "Type"));
  expectations_["Branch-Predictor"]["Type"].setValueSet(
      std::vector<std::string>{"Generic", "Perceptron"});

  expectations_["Branch-Predictor"].addChild(
      ExpectationNode::createExpectation<uint8_t>(8, "BTB-Tag-Bits"));
  expectations_["Branch-Predictor"]["BTB-Tag-Bits"].setValueBounds<uint8_t>(1,
                                                                            64);

  expectations_["Branch-Predictor"].addChild(
      ExpectationNode::createExpectation<uint16_t>(8, "Global-History-Length"));
  expectations_["Branch-Predictor"]["Global-History-Length"]
      .setValueBounds<uint16_t>(1, 32);

  expectations_["Branch-Predictor"].addChild(
      ExpectationNode::createExpectation<uint16_t>(8, "RAS-entries"));
  expectations_["Branch-Predictor"]["RAS-entries"].setValueBounds<uint16_t>(
      1, UINT16_MAX);

  // The saturating counter bits and the fallback predictor
  // are relevant to the GenericPredictor only
  if (!isDefault) {
    // Ensure the key "Branch-Predictor" exists before querying the associated
    // YAML node
    if (configTree_.rootref().has_child(ryml::to_csubstr("Branch-Predictor"))) {
      // Ensure the key "Branch-Predictor:Type" exists before querying the
      // associated YAML node
      if (configTree_["Branch-Predictor"].has_child(ryml::to_csubstr("Type"))) {
        if (configTree_["Branch-Predictor"]["Type"].as<std::string>() ==
            "Generic") {
          expectations_["Branch-Predictor"].addChild(
              ExpectationNode::createExpectation<uint8_t>(
                  2, "Saturating-Count-Bits"));
          expectations_["Branch-Predictor"]["Saturating-Count-Bits"]
              .setValueBounds<uint8_t>(1, 64);

          expectations_["Branch-Predictor"].addChild(
              ExpectationNode::createExpectation<std::string>(
                  "Always-Taken", "Fallback-Static-Predictor"));
          expectations_["Branch-Predictor"]["Fallback-Static-Predictor"]
              .setValueSet(
                  std::vector<std::string>{"Always-Taken", "Always-Not-Taken"});
        }
      } else {
        std::cerr << "[SimEng:ModelConfig] Attempted to access config key "
                     "\"Branch-Predictor:Type\" but it doesn't exist. "
                     "Cannot continue with config "
                     "validation. Exiting."
                  << std::endl;
        exit(1);
      }
    } else {
      std::cerr << "[SimEng:ModelConfig] Attempted to access config key "
                   "\"Branch-Predictor\" but it doesn't exist. Cannot continue "
                   "with config "
                   "validation. Exiting."
                << std::endl;
      exit(1);
    }
  }

  // L1-Data-Memory
  expectations_.addChild(ExpectationNode::createExpectation("L1-Data-Memory"));

  expectations_["L1-Data-Memory"].addChild(
      ExpectationNode::createExpectation<std::string>("Flat",
                                                      "Interface-Type"));
  expectations_["L1-Data-Memory"]["Interface-Type"].setValueSet(
      std::vector<std::string>{"Flat", "Fixed", "External"});

  // L1-Instruction-Memory
  expectations_.addChild(
      ExpectationNode::createExpectation("L1-Instruction-Memory"));

  expectations_["L1-Instruction-Memory"].addChild(
      ExpectationNode::createExpectation<std::string>("Flat",
                                                      "Interface-Type"));
  expectations_["L1-Instruction-Memory"]["Interface-Type"].setValueSet(
      std::vector<std::string>{"Flat", "Fixed", "External"});

  // LSQ-L1-Interface
  expectations_.addChild(
      ExpectationNode::createExpectation("LSQ-L1-Interface"));

  expectations_["LSQ-L1-Interface"].addChild(
      ExpectationNode::createExpectation<uint64_t>(4, "Access-Latency"));
  expectations_["LSQ-L1-Interface"]["Access-Latency"].setValueBounds<uint64_t>(
      1, UINT16_MAX);

  expectations_["LSQ-L1-Interface"].addChild(
      ExpectationNode::createExpectation<bool>(false, "Exclusive"));
  expectations_["LSQ-L1-Interface"]["Exclusive"].setValueSet(
      std::vector{false, true});

  expectations_["LSQ-L1-Interface"].addChild(
      ExpectationNode::createExpectation<uint16_t>(32, "Load-Bandwidth"));

  expectations_["LSQ-L1-Interface"].addChild(
      ExpectationNode::createExpectation<uint16_t>(32, "Store-Bandwidth"));

  // AArch64 requires a vector length of at least 128, requiring a minimum of 16
  // byte load/store bandwidths
  // For RV64, the the minimum required load/store bandwidth is 8 bytes
  if (isa_ == ISA::AArch64) {
    expectations_["LSQ-L1-Interface"]["Load-Bandwidth"]
        .setValueBounds<uint16_t>(16, UINT16_MAX);
    expectations_["LSQ-L1-Interface"]["Store-Bandwidth"]
        .setValueBounds<uint16_t>(16, UINT16_MAX);
  } else if (isa_ == ISA::RV64) {
    expectations_["LSQ-L1-Interface"]["Store-Bandwidth"]
        .setValueBounds<uint16_t>(8, UINT16_MAX);
    expectations_["LSQ-L1-Interface"]["Load-Bandwidth"]
        .setValueBounds<uint16_t>(8, UINT16_MAX);
  }

  expectations_["LSQ-L1-Interface"].addChild(
      ExpectationNode::createExpectation<uint16_t>(
          1, "Permitted-Requests-Per-Cycle"));
  expectations_["LSQ-L1-Interface"]["Permitted-Requests-Per-Cycle"]
      .setValueBounds<uint16_t>(1, UINT16_MAX);

  expectations_["LSQ-L1-Interface"].addChild(
      ExpectationNode::createExpectation<uint16_t>(
          1, "Permitted-Loads-Per-Cycle"));
  expectations_["LSQ-L1-Interface"]["Permitted-Loads-Per-Cycle"]
      .setValueBounds<uint16_t>(1, UINT16_MAX);

  expectations_["LSQ-L1-Interface"].addChild(
      ExpectationNode::createExpectation<uint16_t>(
          1, "Permitted-Stores-Per-Cycle"));
  expectations_["LSQ-L1-Interface"]["Permitted-Stores-Per-Cycle"]
      .setValueBounds<uint16_t>(1, UINT16_MAX);

  // Ports
  expectations_.addChild(ExpectationNode::createExpectation("Ports"));
  expectations_["Ports"].addChild(
      ExpectationNode::createExpectation<uint16_t>(0, wildcard));

  expectations_["Ports"][wildcard].addChild(
      ExpectationNode::createExpectation<std::string>("0", "Portname"));

  expectations_["Ports"][wildcard].addChild(
      ExpectationNode::createExpectation<std::string>(
          "ALL", "Instruction-Group-Support", true));
  expectations_["Ports"][wildcard]["Instruction-Group-Support"].setValueSet(
      groupOptions_);
  expectations_["Ports"][wildcard]["Instruction-Group-Support"].setAsSequence();

  // Get the upper bound of what the opcode value can be based on the ISA
  uint16_t maxOpcode = 0;
  if (isa_ == ISA::AArch64) {
    maxOpcode = arch::aarch64::Opcode::AArch64_INSTRUCTION_LIST_END;
  } else if (isa_ == ISA::RV64) {
    maxOpcode = arch::riscv::Opcode::RISCV_INSTRUCTION_LIST_END;
  }
  expectations_["Ports"][wildcard].addChild(
      ExpectationNode::createExpectation<uint16_t>(
          maxOpcode, "Instruction-Opcode-Support", true));
  expectations_["Ports"][wildcard]["Instruction-Opcode-Support"]
      .setValueBounds<uint16_t>(0, maxOpcode);
  expectations_["Ports"][wildcard]["Instruction-Opcode-Support"]
      .setAsSequence();

  // Early check on [Ports][*][Portname] as the values are needed to inform
  // the expectations of the [Reservation-Stations][*][Ports] values
  std::vector<std::string> portnames = {"0"};
  if (!isDefault) {
    portnames = {};
    // An index value used in case of error
    uint16_t idx = 0;
    // Get all portnames defined in the config file and ensure they are unique
    if (configTree_.rootref().has_child(ryml::to_csubstr("Ports"))) {
      for (ryml::NodeRef child : configTree_["Ports"]) {
        ValidationResult result =
            expectations_["Ports"][wildcard]["Portname"].validateConfigNode(
                child["Portname"]);
        std::string portname = child["Portname"].as<std::string>();
        if (result.valid) {
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
              << "\", passed in config file due to \"" << result.message
              << "\" error. Cannot continue with config validation. Exiting."
              << std::endl;
          exit(1);
        }
        idx++;
      }
    }
  }

  // Reservation-Stations
  expectations_.addChild(
      ExpectationNode::createExpectation("Reservation-Stations"));
  expectations_["Reservation-Stations"].addChild(
      ExpectationNode::createExpectation<uint16_t>(0, wildcard));

  expectations_["Reservation-Stations"][wildcard].addChild(
      ExpectationNode::createExpectation<uint32_t>(32, "Size"));
  expectations_["Reservation-Stations"][wildcard]["Size"]
      .setValueBounds<uint32_t>(1, UINT32_MAX);

  expectations_["Reservation-Stations"][wildcard].addChild(
      ExpectationNode::createExpectation<uint16_t>(4, "Dispatch-Rate"));
  expectations_["Reservation-Stations"][wildcard]["Dispatch-Rate"]
      .setValueBounds<uint16_t>(1, UINT16_MAX);

  expectations_["Reservation-Stations"][wildcard].addChild(
      ExpectationNode::createExpectation<std::string>("0", "Ports"));
  expectations_["Reservation-Stations"][wildcard]["Ports"].setValueSet(
      portnames);
  expectations_["Reservation-Stations"][wildcard]["Ports"].setAsSequence();

  // Execution-Units
  expectations_.addChild(ExpectationNode::createExpectation("Execution-Units"));
  expectations_["Execution-Units"].addChild(
      ExpectationNode::createExpectation<uint16_t>(0, wildcard));

  expectations_["Execution-Units"][wildcard].addChild(
      ExpectationNode::createExpectation<bool>(true, "Pipelined"));
  expectations_["Execution-Units"][wildcard]["Pipelined"].setValueSet(
      std::vector{false, true});

  expectations_["Execution-Units"][wildcard].addChild(
      ExpectationNode::createExpectation<std::string>("NONE", "Blocking-Groups",
                                                      true));
  expectations_["Execution-Units"][wildcard]["Blocking-Groups"].setValueSet(
      groupOptions_);
  expectations_["Execution-Units"][wildcard]["Blocking-Groups"].setAsSequence();

  // Latencies
  expectations_.addChild(ExpectationNode::createExpectation("Latencies", true));
  expectations_["Latencies"].addChild(
      ExpectationNode::createExpectation<uint16_t>(0, wildcard));

  expectations_["Latencies"][wildcard].addChild(
      ExpectationNode::createExpectation<std::string>(
          "NONE", "Instruction-Groups", true));
  expectations_["Latencies"][wildcard]["Instruction-Groups"].setValueSet(
      groupOptions_);
  expectations_["Latencies"][wildcard]["Instruction-Groups"].setAsSequence();

  expectations_["Latencies"][wildcard].addChild(
      ExpectationNode::createExpectation<uint16_t>(
          maxOpcode, "Instruction-Opcodes", true));
  expectations_["Latencies"][wildcard]["Instruction-Opcodes"]
      .setValueBounds<uint16_t>(0, maxOpcode);
  expectations_["Latencies"][wildcard]["Instruction-Opcodes"].setAsSequence();

  expectations_["Latencies"][wildcard].addChild(
      ExpectationNode::createExpectation<uint16_t>(1, "Execution-Latency"));
  expectations_["Latencies"][wildcard]["Execution-Latency"]
      .setValueBounds<uint16_t>(1, UINT16_MAX);

  expectations_["Latencies"][wildcard].addChild(
      ExpectationNode::createExpectation<uint16_t>(1, "Execution-Throughput",
                                                   true));
  expectations_["Latencies"][wildcard]["Execution-Throughput"]
      .setValueBounds<uint16_t>(1, UINT16_MAX);

  // CPU-Info
  expectations_.addChild(ExpectationNode::createExpectation("CPU-Info"));

  expectations_["CPU-Info"].addChild(ExpectationNode::createExpectation<bool>(
      true, "Generate-Special-Dir", true));
  expectations_["CPU-Info"]["Generate-Special-Dir"].setValueSet(
      std::vector{false, true});

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<std::string>(
          defaultSpecialFilePath_, "Special-File-Dir-Path", true));

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<uint64_t>(1, "Core-Count", true));
  expectations_["CPU-Info"]["Core-Count"].setValueBounds<uint64_t>(1,
                                                                   UINT16_MAX);

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<uint64_t>(1, "Socket-Count", true));
  expectations_["CPU-Info"]["Socket-Count"].setValueSet<uint64_t>({1});

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<uint64_t>(1, "SMT", true));
  expectations_["CPU-Info"]["SMT"].setValueSet<uint64_t>({1});

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<float>(0.f, "BogoMIPS", true));
  expectations_["CPU-Info"]["BogoMIPS"].setValueBounds(
      0.f, std::numeric_limits<float>::max());

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<std::string>("", "Features", true));

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<std::string>("0x0", "CPU-Implementer",
                                                      true));

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<uint64_t>(0, "CPU-Architecture",
                                                   true));
  expectations_["CPU-Info"]["CPU-Architecture"].setValueBounds<uint64_t>(
      0, UINT16_MAX);

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<std::string>("0x0", "CPU-Variant",
                                                      true));

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<std::string>("0x0", "CPU-Part", true));

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<uint64_t>(0, "CPU-Revision", true));
  expectations_["CPU-Info"]["CPU-Revision"].setValueBounds<uint64_t>(
      0, UINT16_MAX);

  expectations_["CPU-Info"].addChild(
      ExpectationNode::createExpectation<uint64_t>(1, "Package-Count", true));
  expectations_["CPU-Info"]["Package-Count"].setValueBounds<uint64_t>(
      1, UINT16_MAX);
}

void ModelConfig::recursiveValidate(ExpectationNode expectation,
                                    ryml::NodeRef node,
                                    std::string hierarchyString) {
  // Iterate over passed expectations
  for (auto& child : expectation.getChildren()) {
    std::string nodeKey = child.getKey();
    // If the expectation is a wildcard, then iterate over the associated
    // children in the config option using the same expectation(s)
    if (nodeKey == wildcard) {
      for (ryml::NodeRef rymlChild : node) {
        // An index value used in case of error
        std::string idx =
            std::string(rymlChild.key().data(), rymlChild.key().size());
        ValidationResult result = child.validateConfigNode(rymlChild);
        if (!result.valid)
          invalid_ << "\t- "
                   << hierarchyString + idx + " " + result.message + "\n";
        recursiveValidate(child, rymlChild, hierarchyString + idx + ":");
      }
    } else if (node.has_child(ryml::to_csubstr(nodeKey))) {
      // If the config file contains the key of the expectation node, get
      // it
      ryml::NodeRef rymlChild = node[ryml::to_csubstr(nodeKey)];
      if (child.isSequence()) {
        // If the expectation node is a sequence, then treat the ryml::NodeRef
        // as a parent and validate all its children against the expectation
        // node
        int idx = 0;
        for (ryml::NodeRef grndchild : rymlChild) {
          ValidationResult result = child.validateConfigNode(grndchild);
          if (!result.valid)
            invalid_ << "\t- "
                     << hierarchyString + nodeKey + ":" + std::to_string(idx) +
                            " " + result.message + "\n";
          idx++;
        }
      } else {
        // If the expectation node is not a sequence, validate the config
        // option against the current expectations and if it has children,
        // validate those recursively
        ValidationResult result = child.validateConfigNode(rymlChild);
        if (!result.valid)
          invalid_ << "\t- "
                   << hierarchyString + nodeKey + " " + result.message + "\n";
        if (child.getChildren().size()) {
          recursiveValidate(child, rymlChild, hierarchyString + nodeKey + ":");
        }
      }
    } else {
      // If the config file doesn't contain the key of the expectation node,
      // create it as a child to the config ryml::NodeRef supplied. If the
      // config option is optional, a default value will be injected,
      // otherwise the validation will fail
      ryml::NodeRef rymlChild = node.append_child() << ryml::key(nodeKey);
      ValidationResult result = child.validateConfigNode(rymlChild);
      if (!result.valid)
        invalid_ << "\t- "
                 << hierarchyString + nodeKey + " " + result.message + "\n";
    }
  }
}

void ModelConfig::postValidation() {
  // Ensure package_count size is a less than or equal to the core count,
  // and that the core count can be divided by the package count
  uint64_t packageCount =
      configTree_["CPU-Info"]["Package-Count"].as<uint64_t>();
  uint64_t coreCount = configTree_["CPU-Info"]["Core-Count"].as<uint64_t>();
  if (!((packageCount <= coreCount) && (coreCount % packageCount == 0))) {
    invalid_ << "\t- Package-Count must be a Less-than or equal to Core-Count, "
                "and Core-Count must be divisible by Package-Count\n";
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
    for (ryml::NodeRef child : node["Instruction-Group-Support"]) {
      ryml::NodeRef newChild =
          node["Instruction-Group-Support-Nums"].append_child();
      newChild << groupMapping_[child.as<std::string>()];
    }
  }
  for (ryml::NodeRef node : configTree_["Execution-Units"]) {
    // Clear or create a new Blocking-Group-Nums config option
    if (node.has_child("Blocking-Group-Nums")) {
      node["Blocking-Group-Nums"].clear_children();
    } else {
      node.append_child() << ryml::key("Blocking-Group-Nums") |= ryml::SEQ;
    }
    // Read in each bloacking group and place its corresponding group number
    // into the new config option.
    std::queue<uint16_t> blockingGroups;
    for (ryml::NodeRef child : node["Blocking-Groups"]) {
      uint16_t parentGroup = groupMapping_[child.as<std::string>()];
      blockingGroups.push(parentGroup);
      node["Blocking-Group-Nums"].append_child() << parentGroup;
    }
    // Expand the set of blocking groups to include those that inherit from the
    // user defined set
    std::unordered_map<uint16_t, std::vector<uint16_t>> groupInheritance;
    if (isa_ == ISA::AArch64) {
      groupInheritance = arch::aarch64::groupInheritance_;
    } else if (isa_ == ISA::RV64) {
      groupInheritance = arch::riscv::groupInheritance_;
    }
    while (blockingGroups.size()) {
      // Determine if there's any inheritance
      if (groupInheritance.find(blockingGroups.front()) !=
          groupInheritance.end()) {
        std::vector<uint16_t> inheritedGroups =
            groupInheritance.at(blockingGroups.front());
        for (size_t k = 0; k < inheritedGroups.size(); k++) {
          blockingGroups.push(inheritedGroups[k]);
          node["Blocking-Group-Nums"].append_child() << inheritedGroups[k];
        }
      }
      blockingGroups.pop();
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
    for (ryml::NodeRef child : node["Instruction-Groups"]) {
      node["Instruction-Group-Nums"].append_child()
          << groupMapping_[child.as<std::string>()];
    }
  }

  // Ensure all execution ports have an associated reservation station and
  // convert port strings to their associated port indexes
  if (configTree_["Ports"].num_children() !=
      configTree_["Execution-Units"].num_children()) {
    invalid_ << "\t- The number of execution units ("
             << configTree_["Execution-Units"].num_children()
             << ") must match the number of ports ("
             << configTree_["Ports"].num_children() << ")\n";
  }
  std::vector<std::string> portnames;
  std::unordered_map<std::string, uint16_t> portIndexes;
  uint16_t idx = 0;
  // Read all available port names.
  for (ryml::NodeRef node : configTree_["Ports"]) {
    std::string portname = node["Portname"].as<std::string>();
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
    for (size_t i = 0; i < node["Ports"].num_children(); i++) {
      std::string portname = node["Ports"][i].as<std::string>();
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

  // Ensure that given special file directory exists iff auto-generation is
  // False
  if (!configTree_["CPU-Info"]["Generate-Special-Dir"].as<bool>() &&
      !std::ifstream(
           configTree_["CPU-Info"]["Special-File-Dir-Path"].as<std::string>())
           .good()) {
    invalid_
        << "\t- Special File Directory '"
        << configTree_["CPU-Info"]["Special-File-Dir-Path"].as<std::string>()
        << "' does not exist\n";
  }

  // Ensure the L1-[Data|Instruction]-Memory:Interface-Type restrictions are
  // enforced
  std::string simMode =
      configTree_["Core"]["Simulation-Mode"].as<std::string>();
  // Currently, only outoforder core types can use non-Flat L1-Data-Memory
  // interfaces
  if (simMode != "outoforder") {
    std::string l1dType =
        configTree_["L1-Data-Memory"]["Interface-Type"].as<std::string>();
    if (l1dType != "Flat")
      invalid_ << "\t- Only a Flat L1-Data-Memory Interface-Type may be used "
                  "with the "
               << simMode << " Simulation-Mode. Interface-Type used is "
               << l1dType << "\n";
  }

  // Currently, only a Flat L1-Instruction-Memory:Interface-Type is supported
  std::string l1iType =
      configTree_["L1-Instruction-Memory"]["Interface-Type"].as<std::string>();
  if (l1iType != "Flat")
    invalid_ << "\t- Only a 'Flat' L1-Instruction-Memory Interface-Type is "
                "supported. Interface-Type used is "
             << l1iType << "\n";

  if (isa_ == ISA::AArch64) {
    // Ensure LSQ-L1-Interface Load/Store Bandwidth is large enough to
    // accomodate a full vector load of the specified Vector-Length parameter
    if (configTree_["Core"]["Vector-Length"].as<uint16_t>() / 8 >
        configTree_["LSQ-L1-Interface"]["Load-Bandwidth"].as<uint16_t>()) {
      invalid_
          << "\t- Load-Bandwidth (bytes) must be greater than Vector-Length "
             "(bits). "
             "The current Load-Bandwidth is set to "
          << configTree_["LSQ-L1-Interface"]["Load-Bandwidth"].as<uint16_t>()
          << " bytes, when it must be at least "
          << configTree_["Core"]["Vector-Length"].as<uint16_t>() / 8 << "\n";
    }
    if (configTree_["Core"]["Vector-Length"].as<uint16_t>() / 8 >
        configTree_["LSQ-L1-Interface"]["Store-Bandwidth"].as<uint16_t>()) {
      invalid_
          << "\t- Store-Bandwidth (bytes) must be greater than Vector-Length "
             "(bits). "
             "The current Store-Bandwidth is set to "
          << configTree_["LSQ-L1-Interface"]["Store-Bandwidth"].as<uint16_t>()
          << " bytes, when it must be at least "
          << configTree_["Core"]["Vector-Length"].as<uint16_t>() / 8 << "\n";
    }
    // Ensure LSQ-L1-Interface Load/Store Bandwidth is also large enough to
    // accomodate a full vector load of the specified Streaming-Vector-Length
    // parameter when streaming mode is enabled
    if (configTree_["Core"]["Streaming-Vector-Length"].as<uint16_t>() / 8 >
        configTree_["LSQ-L1-Interface"]["Load-Bandwidth"].as<uint16_t>()) {
      invalid_
          << "\t- Load-Bandwidth (bytes) must be greater than "
             "Streaming-Vector-Length (bits). "
             "The current Load-Bandwidth is set to "
          << configTree_["LSQ-L1-Interface"]["Load-Bandwidth"].as<uint16_t>()
          << " bytes, when it must be at least "
          << configTree_["Core"]["Streaming-Vector-Length"].as<uint16_t>() / 8
          << "\n";
    }
    if (configTree_["Core"]["Streaming-Vector-Length"].as<uint16_t>() / 8 >
        configTree_["LSQ-L1-Interface"]["Store-Bandwidth"].as<uint16_t>()) {
      invalid_
          << "\t- Store-Bandwidth (bytes) must be greater than "
             "Streaming-Vector-Length (bits). "
             "The current Store-Bandwidth is set to "
          << configTree_["LSQ-L1-Interface"]["Store-Bandwidth"].as<uint16_t>()
          << " bytes, when it must be at least "
          << configTree_["Core"]["Streaming-Vector-Length"].as<uint16_t>() / 8
          << "\n";
    }
  }
}

ryml::Tree ModelConfig::getConfig() { return configTree_; }

void ModelConfig::createGroupMapping() {
  if (isa_ == ISA::AArch64) {
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
  } else if (isa_ == ISA::RV64) {
    groupOptions_ = {"INT",
                     "INT_SIMPLE",
                     "INT_SIMPLE_ARTH",
                     "INT_SIMPLE_CMP",
                     "INT_SIMPLE_LOGICAL",
                     "INT_SIMPLE_SHIFT",
                     "INT_MUL",
                     "INT_DIV_OR_SQRT",
                     "LOAD_INT",
                     "STORE_INT",
                     "FLOAT",
                     "FLOAT_SIMPLE",
                     "FLOAT_SIMPLE_ARTH",
                     "FLOAT_SIMPLE_CMP",
                     "FLOAT_SIMPLE_LOGICAL",
                     "FLOAT_SIMPLE_CVT",
                     "FLOAT_MUL",
                     "FLOAT_DIV_OR_SQRT",
                     "LOAD_FLOAT",
                     "STORE_FLOAT",
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
  for (size_t grp = 0; grp < groupOptions_.size(); grp++) {
    groupMapping_[groupOptions_[grp]] = grp;
  }
}

}  // namespace config
}  // namespace simeng
