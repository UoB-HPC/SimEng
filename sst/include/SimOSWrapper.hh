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
#include "SimEngNOC.hh"
#include "simeng/Core.hh"
#include "simeng/CoreInstance.hh"
#include "simeng/OS/SimOS.hh"
#include "simeng/config/SimInfo.hh"
#include "simeng/memory/MMU.hh"
#include "simeng/version.hh"

using namespace SST;
using namespace SST::Interfaces;
using namespace SST::SSTSimEng;
using namespace simeng;

namespace SST {

namespace SSTSimEng {

// Program used when no executable is provided; counts down from
// 1024*1024, with an independent `orr` at the start of each branch.
static uint32_t hex_[8] = {
    0x320C03E0,  // orr w0, wzr, #1048576
    0x320003E1,  // orr w0, wzr, #1
    0x71000400,  // subs w0, w0, #1
    0x54FFFFC1,  // b.ne -8
                 // .exit:
    0xD2800000,  // mov x0, #0
    0xD2800BC8,  // mov x8, #94
    0xD4000001,  // svc #0
};

/**
 * A Wrapper for the SimOS class, registered as a custom SST::Component to
 * participate in an SST simulation. The SimOS class as well as
 * componets/interfaces from SST required to ensure a succesful integration are
 * instantiated and configured in this class as well. This class acts as the
 * point of main contact for clock ticks received from SST and hence is also
 * responsible for ticking the SimEng operating system, cores, and other classes
 * assosciated to it.
 */
class SimOSWrapper : public SST::Component {
 public:
  SimOSWrapper(SST::ComponentId_t id, SST::Params& params);
  ~SimOSWrapper();

  /** SST lifecycle methods (in-order of invocation) overriden from
   * SST::Component. */

  /**
   * This is the init lifecycle method present in all SST::Components.
   * Here it is overriden to include init calls to all other SST::Components
   * which are contained inside SimOSWrapper. It is neccessary to call all
   * lifecycle methods for SST::Component(s).
   */
  void init(unsigned int phase);

  /**
   * This is the setup lifecycle method present in all SST::Components.
   * Here it is overriden to include setup calls to all other SST::Components
   * which are contained inside SimOSWrapper. It is neccessary to call all
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

  /** This handle event method is registered as a callback function with the NOC
   * subcomponent. This method is called everytime the NOC receives a request
   * from the network. */
  void handleNetworkEvent(SST::Event* netEvent);

  /**
   * SST supplied MACRO used to register custom SST:Components with
   * the SST Core.
   */
  SST_ELI_REGISTER_COMPONENT(SimOSWrapper, "sstsimeng", "simos",
                             SST_ELI_ELEMENT_VERSION(1, 0, 0),
                             "SimEng Operating System wrapper for SST",
                             COMPONENT_CATEGORY_PROCESSOR)

  /**
   * SST supplied MACRO used to document all parameters needed by
   * a custom SST:Component.
   */
  SST_ELI_DOCUMENT_PARAMS(
      {"num_cores",
       "Value which specifies the number of SimEng cores defined within the "
       "simulation. "
       "(int)",
       ""},
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
      {"debug",
       "Value which enables output statistics that can be parsed by the "
       "testing framework. (boolean)",
       "false"})

  SST_ELI_DOCUMENT_PORTS()

  SST_ELI_DOCUMENT_SUBCOMPONENT_SLOTS(
      {"DataInterface",
       "Interface between the core and the SST memory backend for data "
       "requests",
       "SST::SSTSimEng::SimEngMemInterface"},
      {"InstrInterface",
       "Interface between the core and the SST memory backend for instruction "
       "requests",
       "SST::SSTSimEng::SimEngMemInterface"},
      {"NOC", "Network On Chip (NOC) interface", "SST::SSTSimEng::SimEngNOC"})

 private:
  void fabricateSimOS();

  /** Construct the special file directory. */
  void createSpecialFileDirectory() const;

  /** Receive a network packet from the network. */
  void receiveFromNOC(simengNetEv pckt);

  /** This method trims any leading or trailing spaces in a string. */
  std::string trimSpaces(std::string argsStr);

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
   * SST::Interfaces::StandardMem interface responsible for converting
   * SST::StandardMem::Request(s) into SST memory events to be passed
   * down the memory heirarchy.
   */
  StandardMem* dataInterface_;

  /**
   * SST::Interfaces::StandardMem interface responsible for converting
   * SST::StandardMem::Request(s) into SST memory events to be passed
   * down the memory heirarchy.
   */
  StandardMem* instrInterface_;

  /** Reference to SimEngMemInterface used for interfacing with SST. */
  std::shared_ptr<SimEngMemInterface> memInterface_;

  /** Reference to memory request handler class defined in SimEngMemInterface.
   */
  SimEngMemInterface::SimEngMemHandlers* handlers_;

  /** SST::SSTSimEng::nocAPI api responsible for interfacing with the
   * SST::SSTSimEng::SimEngNOC network interface controller SubComponent.
   * SST::SSTSimEng::simengNetEv network events will be sent through the
   * SimEngNOC.
   */
  //   nocAPI* sstNoc_;

  /** The cache line width for SST. */
  uint64_t cacheLineWidth_;

  /** Maximum address available to SimEng for memory purposes. */
  uint64_t maxAddrMemory_;

  /** Number of clock iterations. */
  int iterations_;

  /** Start time of simulation. */
  std::chrono::high_resolution_clock::time_point startTime_;

  /** The number of cores connect over the NOC. */
  uint16_t numCores_ = 0;

  /** Variable to enable parseable print debug statements in test mode. */
  bool debug_ = false;

  // SimEng properties
  /** The total number of times the SimOS class has been ticked. */
  uint64_t ticks_ = 0;

  /** Path to the executable binary to be simulated by SimEng. */
  std::string executablePath_ = DEFAULT_STR;

  /** Arguments to be passed to executable binary. */
  std::vector<std::string> executableArgs_ = {};

  /** Path to the YAML configuration file for SimEng. */
  std::string simengConfigPath_;

  std::unique_ptr<simeng::OS::SimOS> simOS_;

  std::shared_ptr<simeng::memory::MMU> mmu_;

  std::shared_ptr<
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>>
      connection_ = std::make_shared<
          simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>>();

  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      mmuPort_;

  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      memPort_;

  std::unique_ptr<simeng::CoreInstance> coreInstance_;

  std::shared_ptr<simeng::Core> core_;

  /** Indicates if all processes have completed or a core has halted due to an
   * exception. */
  bool halted_ = false;

  /** The value of the next TID value that should be assigned to a process on
   * instantiation. */
  uint64_t nextFreeTID_ = 1;

  /** Reference to the PageFrameAllocator object.  */
  simeng::OS::PageFrameAllocator pageFrameAllocator_;
};

}  // namespace SSTSimEng

}  // namespace SST
