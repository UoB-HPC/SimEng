#pragma once
#include <memory>
#include <string>

#include "simeng/ModelConfig.hh"
#include "yaml-cpp/yaml.h"

#define DEFAULT_STR "Default"

/** A Config class to hold a single instance of a global config file. */
class Config {
 public:
  /** Gets the current Config file. */
  static YAML::Node& get() { return getInstance()->getYAMLConfig(); }

  /** Update the config via a filepath to load from. */
  static void set(std::string path) { getInstance()->makeConfig(path); }

  /** Update the config to a provided YAML::Node. */
  static void set(YAML::Node newConfig) {
    getInstance()->makeConfig(newConfig);
  }

  /** Update the config via a provided char* input. */
  static void set(const char* configStr) {
    getInstance()->makeConfig(configStr);
  }

  /** Returns if the DEFAULT_CONFIG is in use. */
  static bool isDefault() { return getInstance()->isDefault_; }

  /** Get the filepath of the config file. */
  static std::string getPath() { return getInstance()->path_; }

 private:
#define DEFAULT_CONFIG                                                         \
  ("{Core: {ISA: AArch64, Simulation-Mode: inorderpipelined, "                 \
   "Clock-Frequency: 2.5, Timer-Frequency: 100, Micro-Operations: True, "      \
   "Vector-Length: 512, Streaming-Vector-Length: 512}, Fetch: "                \
   "{Fetch-Block-Size: 32, Loop-Buffer-Size: 64, Loop-Detection-Threshold: "   \
   "4}, Process-Image: {Heap-Size: 10485760, Stack-Size: 1048576, Mmap-Size: " \
   "10485760}, Simulation-Memory: {Size: 104857600}, Register-Set: "           \
   "{GeneralPurpose-Count: 154, FloatingPoint/SVE-Count: 90, "                 \
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

  /** Constructor of a Config object. */
  Config() { config_ = YAML::Load(DEFAULT_CONFIG); }

  /** Creates a new config file from ModelConfig using a filepath. */
  void makeConfig(std::string path) {
    config_ = simeng::ModelConfig(path).getConfigFile();
    isDefault_ = false;
    path_ = path;
  };

  /** Creates a new config file from ModelConfig using a filepath. */
  void makeConfig(const char* configStr) {
    config_ = YAML::Load(configStr);
    isDefault_ = false;
    path_ = "Custom Config";
  };

  /** Creates a new config file from a provided YAML::Node. */
  void makeConfig(YAML::Node newConfig) {
    config_ = newConfig;
    isDefault_ = false;
    path_ = "Custom Config";
  };

  /** Internal getter of config_. */
  YAML::Node& getYAMLConfig() { return config_; }

  /** Gets the static instance of the Config class. */
  static std::unique_ptr<Config>& getInstance() {
    static std::unique_ptr<Config> cfgClass = nullptr;
    if (cfgClass == nullptr) {
      cfgClass = std::unique_ptr<Config>(new Config());
    }
    return cfgClass;
  }

  /** The global config file for this simulation. */
  YAML::Node config_;

  /** The file path of the config file being used. */
  std::string path_ = DEFAULT_STR;

  /** Bool to hold if DEFAULT_CONFIG is in use. */
  bool isDefault_ = true;

 public:
  /** Gets the current Config file. */
  static YAML::Node& get() { return getInstance()->getYAMLConfig(); }

  /** Update the config via a filepath to load from. */
  static void set(std::string path) { getInstance()->makeConfig(path); }

  /** Update the config to a provided YAML::Node. */
  static void set(YAML::Node newConfig) {
    getInstance()->makeConfig(newConfig);
  }

  /** Update the config via a provided char* input. */
  static void set(const char* configStr) {
    getInstance()->makeConfig(configStr);
  }

  /** Returns if the DEFAULT_CONFIG is in use. */
  static bool isDefault() { return getInstance()->isDefault_; }

  /** Get the filepath of the config file. */
  static std::string getPath() { return getInstance()->path_; }
};
