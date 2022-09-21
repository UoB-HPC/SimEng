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

#include "SimengMemInterface.hh"
#include "simeng/Core.hh"
#include "simeng/CoreInstance.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/version.hh"

using namespace SST;
using namespace SST::Interfaces;
using namespace SST::SSTSimeng;
using namespace simeng;

namespace SST {

namespace SSTSimeng {

/**
 * A Wrapper class registered as a custom SST::Component to participate in an
 * SST simulation. The SimEng core as well as componets/interfaces from SST
 * required to ensure a succesful integration are instantiated and configured in
 * this class as well. This class acts as the point of main contact for clock
 * ticks recieved from SST and hence is also responsible for ticking the SimEng
 * core and other classes assosciated to it.
 */
class SimengCoreWrapper : public SST::Component {
 public:
  SimengCoreWrapper(SST::ComponentId_t id, SST::Params& params);
  ~SimengCoreWrapper();

  /** SST lifecycle methods (in-order of invocation) overriden from
   * SST::Component. */

  /**
   * This is the init lifecycle method present in all SST::Components.
   * Here it is overriden to include init calls to all other SST::Components
   * which are contained inside SimengCoreWrapper. It is neccessary call all
   * lifecycle methods for SST::Component(s).
   */
  void init(unsigned int phase);

  /**
   * This is the setup lifecycle method present in all SST::Components.
   * Here it is overriden to include setup calls to all other SST::Components
   * which are contained inside SimengCoreWrapper. It is neccessary call all
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
   * This handle event method is registered to StandardMem interface is called
   * everytime a memory request is forwarded by the interface. This functions
   * acts a callback and invokes SimengMemHandlers on the memory request.
   */
  void handleEvent(StandardMem::Request* ev);

  /**
   * SST supplied MACRO used to register custom SST:Components with
   * the SST Core.
   */
  SST_ELI_REGISTER_COMPONENT(SimengCoreWrapper, "sstsimeng", "simengcore",
                             SST_ELI_ELEMENT_VERSION(1, 0, 0),
                             "Simeng core wrapper for SST",
                             COMPONENT_CATEGORY_PROCESSOR)

  /**
   * SST supplied MACRO used to document all parameters needed by
   * a custom SST:Component.
   */
  SST_ELI_DOCUMENT_PARAMS(
      {"simeng_config_path", "Path to SimEng YAML model config file (string)",
       ""},
      {"executable_path",
       "Path to executable binary to be run by SimEng (string)", ""},
      {"executable_args",
       "argument to be passed to the executable binary (string)", ""},
      {"clock", "Clock rate of the SST clock (string)", ""},
      {"max_addr_memory", "Maximum address that memory can access (int)"}, )

 private:
  /** Method used to assemble SimEng core. */
  void fabricateSimengCore();

  /** Method to split the passed executable argument's string into a vector of
   * individual arguments. */
  std::vector<std::string> splitArgs(std::string argString);

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
   * SST::Interfaces::StandardMem interface responsible for convering
   * SST::StandardMem::Request(s) into SST memory events to be passed
   * down the memory heirarchy.
   */
  StandardMem* mem_;

  // Simeng properties
  /** Reference to the CoreInstance class responsible for creating the core to
   * be simulated. */
  std::unique_ptr<simeng::CoreInstance> coreInstance_;

  /** Reference to SimEng core. */
  std::shared_ptr<simeng::Core> core_;

  /** Path to the YAML configuration file for SimEng. */
  std::string configPath_;

  /** Path to the executable binary to be simulated by SimEng. */
  std::string executablePath_;

  /** Arguments to be passed to executable binary. */
  std::vector<std::string> executableArgs_;

  /** The cache line width for SST. */
  uint64_t cacheLineWidth_;

  /** Maximum address availbale to SimEng for memory purposes. */
  uint64_t maxAddrMemory_;

  /** Reference to the SimEng LinuxProcess. */
  std::shared_ptr<simeng::kernel::LinuxProcess> process_;

  /** Reference to the process memory used in SimEng. */
  std::shared_ptr<char> processMemory_;

  /** Reference to SimEng instruction memory. */
  std::shared_ptr<simeng::MemoryInterface> instructionMemory_;

  /** Reference to SimengMemInterface used for interfacing with SST. */
  std::shared_ptr<SimengMemInterface> dataMemory_;

  /** Number of clock iterations. */
  int iterations_;

  /** Start time of simulation. */
  std::chrono::high_resolution_clock::time_point startTime_;

  /** Reference to memory request handler class defined in SimengMemInterface.
   */
  SimengMemInterface::SimengMemHandlers* handlers_;
};

}  // namespace SSTSimeng

}  // namespace SST
