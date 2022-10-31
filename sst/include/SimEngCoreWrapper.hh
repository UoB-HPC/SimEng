// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on
#include <sst/core/component.h>
#include <sst/core/eli/elementinfo.h>
#include <sst/core/interfaces/stdMem.h>

#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "SimEngMemInterface.hh"
#include "simeng/Core.hh"
#include "simeng/CoreInstance.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/version.hh"

using namespace SST;
using namespace SST::Interfaces;
using namespace SST::SSTSimEng;
using namespace simeng;

namespace SST {

namespace SSTSimEng {

/**
 * A Wrapper class registered as a custom SST::Component to participate in an
 * SST simulation. The SimEng core as well as componets/interfaces from SST
 * required to ensure a succesful integration are instantiated and configured in
 * this class as well. This class acts as the point of main contact for clock
 * ticks recieved from SST and hence is also responsible for ticking the SimEng
 * core and other classes assosciated to it.
 */
class SimEngCoreWrapper : public SST::Component {
 public:
  SimEngCoreWrapper(SST::ComponentId_t id, SST::Params& params);
  ~SimEngCoreWrapper();

  /** SST lifecycle methods (in-order of invocation) overriden from
   * SST::Component. */

  /**
   * This is the init lifecycle method present in all SST::Components.
   * Here it is overriden to include init calls to all other SST::Components
   * which are contained inside SimEngCoreWrapper. It is neccessary to call all
   * lifecycle methods for SST::Component(s).
   */
  void init(unsigned int phase);

  /**
   * This is the setup lifecycle method present in all SST::Components.
   * Here it is overriden to include setup calls to all other SST::Components
   * which are contained inside SimEngCoreWrapper. It is neccessary to call all
   * lifecycle methods for SST::Component(s).
   */
  void setup();

  /**
   * This is the finish lifecycle method present in all SST::Components.
   * Here it is overriden to finish statistics about the SimEng simulation.
   */
  void finish();

  /**
   * The clockTick is a method present in all SST::Components. This fuction
   * is called everytime the SST clock ticks. The current clock cycle is passed
   * as an argument by SST. The SimEng core ticks in this method.
   */
  bool clockTick(SST::Cycle_t currentCycle);

  /**
   * This handle event method is registered to StandardMem interface. This
   * method is called everytime a memory request is forwarded by the interface.
   * This function acts as a callback and invokes SimEngMemHandler on the memory
   * requests.
   */
  void handleMemoryEvent(StandardMem::Request* memEvent);

  /**
   * SST supplied MACRO used to register custom SST:Components with
   * the SST Core.
   */
  SST_ELI_REGISTER_COMPONENT(SimEngCoreWrapper, "sstsimeng", "simengcore",
                             SST_ELI_ELEMENT_VERSION(1, 0, 0),
                             "SimEng core wrapper for SST",
                             COMPONENT_CATEGORY_PROCESSOR)

  /**
   * SST supplied MACRO used to document all parameters needed by
   * a custom SST:Component.
   */
  SST_ELI_DOCUMENT_PARAMS(
      {"simeng_config_path",
       "Value which specifies the path to SimEng YAML model config file. "
       "(string)",
       ""},
      {"executable_path",
       "Value which specifies the path to executable binary to be run by "
       "SimEng. (string)",
       ""},
      {"executable_args",
       "Value which specifies the argument to be passed to the executable "
       "binary. (string)",
       ""},
      {"clock", "Value which specifies clock rate of the SST clock. (string)",
       ""},
      {"max_addr_memory",
       "Value which specifies the maximum address that memory can access. "
       "(int)",
       ""},
      {"cache_line_width",
       "Value which specifies the width of the cache line in bytes. (int)", ""},
      {"source",
       "Value which specifies the string of instructions to be assembled by "
       "LLVM and executed by SimEng (if any). (string)",
       ""},
      {"assemble_with_source",
       "Value which indicates whether to assemble the instructions supplied "
       "through the source parameter using LLVM. (boolean)",
       "false"},
      {"heap",
       "Value which specifies comma separated uint64_t values used to populate "
       "the heap. This parameter will only be used if "
       "assemble_with_source=true. (string)",
       ""},
      {"debug",
       "Value which enables output statistics that can be parsed by the "
       "testing framework. (boolean)",
       "false"})

 private:
  /** Method used to assemble SimEng core. */
  void fabricateSimEngCore();

  /** Method to split the passed executable argument's string into a vector of
   * individual arguments. */
  std::vector<std::string> splitArgs(std::string argString);

  /** This method trims any leading or trailing spaces in a string. */
  std::string trimSpaces(std::string argsStr);

  /** This method splits the comma separated heap string into a vector of
   * uint32_t values. */
  std::vector<uint64_t> splitHeapStr();

  // SST properties
  /**
   * SST defined output class used to output information to standard output.
   * This class has in-built method for different levels of severity and can
   * also be configured to output information like line-number and filename.
   */
  SST::Output output_;

  /**
   * SST clock for the component register with the custom component
   * during instantiation using the registerClock method provided
   * by SST.
   */
  TimeConverter* clock_;

  /**
   * SST::Interfaces::StandardMem interface responsible for converting
   * SST::StandardMem::Request(s) into SST memory events to be passed
   * down the memory heirarchy.
   */
  StandardMem* sstMem_;

  // SimEng properties
  /** Reference to the CoreInstance class responsible for creating the core to
   * be simulated. */
  std::unique_ptr<simeng::CoreInstance> coreInstance_;

  /** Reference to SimEng core. */
  std::shared_ptr<simeng::Core> core_;

  /** Path to the YAML configuration file for SimEng. */
  std::string simengConfigPath_;

  /** Path to the executable binary to be simulated by SimEng. */
  std::string executablePath_;

  /** Arguments to be passed to executable binary. */
  std::vector<std::string> executableArgs_;

  /** The cache line width for SST. */
  uint64_t cacheLineWidth_;

  /** Maximum address availbale to SimEng for memory purposes. */
  uint64_t maxAddrMemory_;

  /** Reference to the process memory used in SimEng. */
  std::shared_ptr<char> processMemory_;

  /** Reference to SimEng instruction memory. */
  std::shared_ptr<simeng::MemoryInterface> instructionMemory_;

  /** Reference to SimEngMemInterface used for interfacing with SST. */
  std::shared_ptr<SimEngMemInterface> dataMemory_;

  /** Number of clock iterations. */
  int iterations_;

  /** Start time of simulation. */
  std::chrono::high_resolution_clock::time_point startTime_;

  /** Reference to memory request handler class defined in SimEngMemInterface.
   */
  SimEngMemInterface::SimEngMemHandlers* handlers_;

  /** String which holds source instructions to be assembled. (if any)*/
  std::string source_;

  /** Boolean which indicates whether or not to assemble by source. */
  bool assembleWithSource_ = false;

  /** Heap contents as string. */
  std::string heapStr_;

  /** Variable to enable parseable print debug statements in test mode. */
  bool debug_ = false;
};

}  // namespace SSTSimEng

}  // namespace SST
