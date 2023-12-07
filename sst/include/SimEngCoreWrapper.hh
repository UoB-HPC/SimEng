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
 * required to ensure a succesful integration are instantiated and configured
 in
 * this class as well. This class acts as the point of main contact for clock
 * ticks received from SST and hence is also responsible for ticking the
 SimEng
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
   * which are contained inside SimEngCoreWrapper. It is neccessary to call
   all
   * lifecycle methods for SST::Component(s).
   */
  void init(unsigned int phase);

  /**
   * This is the setup lifecycle method present in all SST::Components.
   * Here it is overriden to include setup calls to all other SST::Components
   * which are contained inside SimEngCoreWrapper. It is neccessary to call
   all
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
   * is called everytime the SST clock ticks. The current clock cycle is
   passed
   * as an argument by SST. The SimEng core ticks in this method.
   */
  bool clockTick(SST::Cycle_t currentCycle);

  /**
   * This handle event method is registered to StandardMem interface. This
   * method is called everytime a memory request is forwarded by the
   interface.
   * This function acts as a callback and invokes SimEngMemHandler on the
   memory
   * requests.
   */
  void handleMemoryEvent(StandardMem::Request* memEvent);

  /** This handle event method is registered as a callback function with the
  NOC
   * subcomponent. This method is called everytime the NOC receives a request
   * from the network. */
  void handleNetworkEvent(SST::Event* netEvent);

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
      {"clock", "Value which specifies clock rate of the SST clock. (string)",
       ""},
      {"max_addr_memory",
       "Value which specifies the maximum address that memory can access. "
       "(int)",
       ""},
      {"cache_line_width",
       "Value which specifies the width of the cache line in bytes. (int)", ""},
      //   {"source",
      //    "Value which specifies the string of instructions to be assembled "
      //    "by "
      //    "LLVM and executed by SimEng (if any). (string)",
      //    ""},
      //   {"assemble_with_source",
      //    "Value which indicates whether to assemble the instructions "
      //    "supplied "
      //    "through the source parameter using LLVM. (boolean)",
      //    "false"},
      //   {"heap",
      //    "Value which specifies comma separated uint64_t values used to "
      //    "populate "
      //    "the heap. This parameter will only be used if "
      //    "assemble_with_source=true. (string)",
      //    ""},
      {"debug",
       "Value which enables output statistics that can be parsed by the "
       "testing framework. (boolean)",
       "false"})

  SST_ELI_DOCUMENT_STATISTICS(
      {"cycles", "Number of elapsed cycled", "cycles", 1},
      {"retired", "Number of retired instructions", "count", 1},
      {"ipc", "Average instructions executed per cycles", "count", 1},
      {"flushes", "Number of pipeline flushed", "count", 1},
      {"fetch_fetchStalls",
       "Number of stalls in the fetch unit due to a lack of instructions",
       "count", 1},
      {"decode_earlyFlushes",
       "Number of pipeline flushes due to early misprediction detection",
       "count", 1},
      {"rename_allocationStalls",
       "Number of frontend pipeline stalls due to a lack of physical registers "
       "used in the renaming scheme",
       "count", 1},
      {"rename_robStalls",
       "Number of frontend pipeline stalls due to a lack of free entries in "
       "the reorder buffer",
       "count", 1},
      {"rename_lqStalls",
       "Number of frontend pipeline stalls due to a lack of free entries in "
       "the load queue",
       "count", 1},
      {"rename_sqStalls",
       "Number of frontend pipeline stalls due to a lack of free entries in "
       "the store queue",
       "count", 1},
      {"dispatch_rsStalls",
       "Number of frontend pipeline stalls due to a lack of resources in a "
       "reservation station",
       "count", 1},
      {"issue_frontendStalls",
       "Enumeration of all pipeline stalls caused by a lack of instructions "
       "being fed from the frontend of the pipeline",
       "count", 1},
      {"issue_backendStalls",
       "Enumeration of all pipeline stalls caused by a lack of resources in "
       "the backend of the pipeline",
       "count", 1},
      {"issue_portBusyStalls",
       "Number of instances a instruction could not be issued as their "
       "associated execution unit was busy undergoing a blocking operation",
       "count", 1},
      {"branch_executed", "Number of branches executed", "count", 1},
      {"branch_mispredict", "Number of branches mispredicted", "count", 1},
      {"branch_missrate", "Branch missrate", "count", 1},
      {"lsq_loadViolations",
       "Number of loads which violate the ordering of load-store execution",
       "count", 1},
      {"idle_ticks",
       "Number of ticks in which a core has no active thread to execute",
       "count", 1},
      {"context_switches", "Number of context switches a core undergoes",
       "count", 1},
      {"rob_numLoadsRetired", "Number of loads retired", "count", 1},
      {"rob_numStoresRetired", "Number of stores retired", "count", 1},
      {"mmu_numInsnReads", "Number of instruction reads handled by the MMU",
       "count", 1},
      {"mmu_numDataReads", "Number of data reads handled by the MMU", "count",
       1},
      {"mmu_numDataWrites", "Number of data writes handled by the MMU", "count",
       1},
      {"duration", "Host time elapsed during simulation", "milliseconds", 1},
      {"frequency", "Frequency that the simualted core was ticked by the host",
       "kHz", 1},
      {"mips", "Millions of instructions executed per second of host time",
       "count", 1})

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
  /** Method used to assemble SimEng core. */
  void fabricateSimEngCore();

  uint64_t translateVAddr(uint64_t vaddr, uint64_t pid);

  void updateCoreDescInOS(simeng::OS::cpuContext ctx, uint16_t coreId,
                          simeng::CoreStatus status, uint64_t ticks);

  void sendSyscall(simeng::OS::SyscallInfo info);

  /** Method to split the passed executable argument's string into a vector
  of
   * individual arguments. */
  std::vector<std::string> splitArgs(std::string argString);

  /** This method trims any leading or trailing spaces in a string. */
  std::string trimSpaces(std::string argsStr);

  /** This method splits the comma separated heap string into a vector of
   * uint32_t values. */
  //   std::vector<uint64_t> splitHeapStr();

  /** Initialises heap data specified by the testing framework. */
  //   void initialiseHeapData();

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

  /** SST::SSTSimEng::nocAPI api responsible for interfacing with the
   * SST::SSTSimEng::SimEngNOC network interface controller SubComponent.
   * SST::SSTSimEng::simengNetEv network events will be sent through the
   * SimEngNOC.
   */
  nocAPI* sstNoc_;

  /** Reference to SimEngMemInterface used for interfacing with SST. */
  std::shared_ptr<SimEngMemInterface> memInterface_;

  /** Reference to memory request handler class defined in SimEngMemInterface.
   */
  SimEngMemInterface::SimEngMemHandlers* handlers_;

  std::map<std::string, Statistic<uint64_t>*> statsU64 = {
      {"cycles", registerStatistic<uint64_t>("cycles")},
      {"retired", registerStatistic<uint64_t>("retired")},
      {"flushes", registerStatistic<uint64_t>("flushes")},
      {"fetch_fetchStalls", registerStatistic<uint64_t>("fetch_fetchStalls")},
      {"decode_earlyFlushes",
       registerStatistic<uint64_t>("decode_earlyFlushes")},
      {"rename_allocationStalls",
       registerStatistic<uint64_t>("rename_allocationStalls")},
      {"rename_robStalls", registerStatistic<uint64_t>("rename_robStalls")},
      {"rename_lqStalls", registerStatistic<uint64_t>("rename_lqStalls")},
      {"rename_sqStalls", registerStatistic<uint64_t>("rename_sqStalls")},
      {"dispatch_rsStalls", registerStatistic<uint64_t>("dispatch_rsStalls")},
      {"issue_frontendStalls",
       registerStatistic<uint64_t>("issue_frontendStalls")},
      {"issue_backendStalls",
       registerStatistic<uint64_t>("issue_backendStalls")},
      {"issue_portBusyStalls",
       registerStatistic<uint64_t>("issue_portBusyStalls")},
      {"branch_executed", registerStatistic<uint64_t>("branch_executed")},
      {"branch_mispredict", registerStatistic<uint64_t>("branch_mispredict")},
      {"lsq_loadViolations", registerStatistic<uint64_t>("lsq_loadViolations")},
      {"idle_ticks", registerStatistic<uint64_t>("idle_ticks")},
      {"context_switches", registerStatistic<uint64_t>("context_switches")},
      {"rob_numLoadsRetired",
       registerStatistic<uint64_t>("rob_numLoadsRetired")},
      {"rob_numStoresRetired",
       registerStatistic<uint64_t>("rob_numStoresRetired")},
      {"mmu_numInsnReads", registerStatistic<uint64_t>("mmu_numInsnReads")},
      {"mmu_numDataReads", registerStatistic<uint64_t>("mmu_numDataReads")},
      {"mmu_numDataWrites", registerStatistic<uint64_t>("mmu_numDataWrites")},
      {"duration", registerStatistic<uint64_t>("duration")}};

  std::map<std::string, Statistic<float>*> statsF32 = {
      {"ipc", registerStatistic<float>("ipc")},
      {"branch_missrate", registerStatistic<float>("branch_missrate")},
      {"frequency", registerStatistic<float>("frequency")},
      {"mips", registerStatistic<float>("mips")}};

  // SimEng properties
  /** Reference to the CoreInstance class responsible for creating the core
  to
   * be simulated. */
  std::unique_ptr<simeng::CoreInstance> coreInstance_;

  /** Reference to SimEng core. */
  std::shared_ptr<simeng::Core> core_;

  std::shared_ptr<simeng::memory::MMU> mmu_;

  std::map<uint64_t, uint64_t> fakeTLB_;

  std::vector<uint64_t> pendingTranslation_;

  std::shared_ptr<
      simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>>
      connection_ = std::make_shared<
          simeng::PortMediator<std::unique_ptr<simeng::memory::MemPacket>>>();

  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      mmuPort_;

  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      memPort_;

  /** Path to the YAML configuration file for SimEng. */
  std::string simengConfigPath_;

  /** The cache line width for SST. */
  uint64_t cacheLineWidth_;

  /** Maximum address availbale to SimEng for memory purposes. */
  uint64_t maxAddrMemory_;

  /** Number of clock iterations. */
  int iterations_;

  /** Start time of simulation. */
  std::chrono::high_resolution_clock::time_point startTime_;

  /** String which holds source instructions to be assembled. (if any)*/
  //   std::string source_;

  /** Boolean which indicates whether or not to assemble by source. */
  //   bool assembleWithSource_ = false;

  /** Heap contents as string. */
  //   std::string heapStr_;

  /** Variable to enable parseable print debug statements in test mode. */
  bool debug_ = false;

  /** Path to A64fx model config. */
  const std::string a64fxConfigPath_ =
      std::string(SIMENG_BUILD_DIR) +
      "/simeng-configs/sst-cores/a64fx-sst.yaml";

  std::chrono::high_resolution_clock::time_point intervalStart_;
};  // namespace SSTSimEng

}  // namespace SSTSimEng

}  // namespace SST
