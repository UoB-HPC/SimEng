// DO NOT MOVE FROM TOP OF FILE
#include <sst/core/sst_config.h>
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
#include "simeng/AlwaysNotTakenPredictor.hh"
#include "simeng/BTBPredictor.hh"
#include "simeng/BTB_BWTPredictor.hh"
#include "simeng/Core.hh"
#include "simeng/Elf.hh"
#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/FlatMemoryInterface.hh"
#include "simeng/MemoryInterface.hh"
#include "simeng/ModelConfig.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"
#include "simeng/arch/aarch64/MicroDecoder.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/models/emulation/Core.hh"
#include "simeng/models/inorder/Core.hh"
#include "simeng/models/outoforder/Core.hh"
#include "simeng/pipeline/A64FXPortAllocator.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"
#include "simeng/version.hh"

using namespace SST;
using namespace SST::Interfaces;
using namespace SST::SSTSimeng;
using namespace simeng;

namespace SST {

namespace SSTSimeng {

class SimengCoreWrapper : public SST::Component {
 public:
  SimengCoreWrapper(SST::ComponentId_t id, SST::Params& params);
  ~SimengCoreWrapper();

  /** SST lifecycle methods (in-order of invocation) overriden from
   * SST::Component */

  /**
   * This is the init lifecycle method present in all SST::Components.
   * Here it is overriden to include init calls to all other SST::Components
   * which are contained inside SimengCoreWrapper. It is neccessary call all
   * lifecycle methods for SST::Component(s)
   */
  void init(unsigned int phase);

  /**
   * This is the setup lifecycle method present in all SST::Components.
   * Here it is overriden to include setup calls to all other SST::Components
   * which are contained inside SimengCoreWrapper. It is neccessary call all
   * lifecycle methods for SST::Component(s)
   */
  void setup();

  /**
   * This is the finish lifecycle method present in all SST::Components.
   * Here it is overriden to finish statistics about the SimEng simulation.
   */
  void finish();

  /**
   * The clockTick is a method present in all SST::Components. This fuction
   * is called everytime the SST clock ticks. The current clock cylce is passed
   * as an argument by SST. The SimEng core ticks in this method.
   */
  bool clockTick(SST::Cycle_t currentCycle);

  /**
   * This handle event method is registered to StandardMem interface is called
   * everytime a memory request is forwarded by the interface. This functions
   * acts a callback and invokes SimengMemHandlers on the memory request.
   */
  void handleEvent(StandardMem::Request* ev);

  SST_ELI_REGISTER_COMPONENT(SimengCoreWrapper, "sstsimeng", "simengcore",
                             SST_ELI_ELEMENT_VERSION(1, 0, 0),
                             "Simeng core wrapper for SST",
                             COMPONENT_CATEGORY_PROCESSOR)

  SST_ELI_DOCUMENT_PARAMS(
      {"config_path", "Path to Simeng YAML config file (string)", ""},
      {"executable_path",
       "Path to executable binary to be run by SimEng (string)", ""},
      {"executable_args",
       "argument to be passed to the executable binary (string)", ""},
      {"clock", "Clock rate of the SST clock (string)", ""},
      {"max_addr_memory", "Maximum address that memory can access (int)"}, )

 private:
  // SST properties
  SST::Output output;
  TimeConverter* clock;
  StandardMem* mem;

  // Simeng properties
  std::unique_ptr<simeng::Core> core;
  std::string config_path;
  std::string executable_path;
  std::string executable_args;
  uint64_t cache_line_width;
  uint64_t max_addr_memory;
  std::unique_ptr<simeng::kernel::LinuxProcess> process;
  std::unique_ptr<simeng::kernel::Linux> kernel;
  char* process_memory;
  std::unique_ptr<simeng::arch::Architecture> arch;
  std::unique_ptr<simeng::MemoryInterface> instruction_memory;
  std::unique_ptr<simeng::BranchPredictor> predictor;
  std::unique_ptr<simeng::pipeline::PortAllocator> port_allocator;
  std::unique_ptr<SimengMemInterface> data_memory;
  int iterations;
  int vitrual_counter;
  double timer_modulo;
  int size;
  std::chrono::high_resolution_clock::time_point start_time;

  SimengMemInterface::SimengMemHandlers* handlers;
  /** Method used to assemble SimEng core. */
  void fabricateSimengCore();
};

}  // namespace SSTSimeng

}  // namespace SST
