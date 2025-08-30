// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
// ReSharper disable once CppMissingIncludeGuard
#include <sst/core/sst_config.h>
// clang-format on
#pragma once

#include <sst/core/component.h>
#include <sst/core/eli/elementinfo.h>
#include <sst/core/interfaces/stdMem.h>

#include "OffloadingEvent.hh"
#include "SimEngCoreWrapper.hh"
#include "SimEngMemInterface.hh"
#include "simeng/Accelerator.hh"
#include "simeng/AcceleratorInstance.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"

using namespace SST;
using namespace SST::SSTSimEng;
using namespace SST::Interfaces;
using namespace simeng;

namespace SST {
namespace SSTSimEng {

/**
 * A Wrapper class registered as a custom SST::Component to participate in an
 * SST simulation. The SimEng accelerator as well as componets/interfaces from
 * SST required to ensure a successful integration are instantiated and
 * configured in this class as well. This class acts as the point of main
 * contact for clock ticks received from SST and hence is also responsible for
 * ticking the SimEng accelerator and other classes associated to it.
 */
class SimEngAcceleratorWrapper : public Component {
  /** Debugging level (a higher level also includes all info from lower levels).
   */
  enum class DebugLevel {
    None = 0,
    Offloading = 1,
    Memory = 2,
  };

 public:
  /** The init phase at which the accelerator will be fabricated. */
  static constexpr unsigned int LAST_INIT_PHASE =
      SimEngCoreWrapper::LAST_INIT_PHASE + 1;

  SimEngAcceleratorWrapper(ComponentId_t id, const Params& params);
  ~SimEngAcceleratorWrapper() override;

  /** SST lifecycle methods (in-order of invocation) overridden from
   * SST::Component. */

  /**
   * This is the init lifecycle method present in all SST::Components.
   * Here it is overridden to include init calls to all other SST::Components
   * which are contained inside SimEngCoreWrapper. It is necessary to call all
   * lifecycle methods for SST::Component(s).
   */
  void init(unsigned int phase) override;

  /**
   * This is the setup lifecycle method present in all SST::Components.
   * Here it is overridden to include setup calls to all other SST::Components
   * which are contained inside SimEngCoreWrapper. It is necessary to call all
   * lifecycle methods for SST::Component(s).
   */
  void setup() override;

  /**
   * This is the finish lifecycle method present in all SST::Components.
   * Here it is overridden to finish statistics about the SimEng simulation.
   */
  void finish() override;

  /**
   * The clockTick is a method present in all SST::Components. This function
   * is called everytime the SST clock ticks. The current clock cycle is passed
   * as an argument by SST. The SimEng core ticks in this method.
   */
  bool clockTick(Cycle_t currentCycle);

  /**
   * This handle event method is registered to the link connected to a SimEng
   * core. This method is called every time an event arrives from the core.
   */
  void handleCoreEvent(Event* ev);

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
  SST_ELI_REGISTER_COMPONENT(SimEngAcceleratorWrapper, "sstsimeng",
                             "simengaccelerator",
                             SST_ELI_ELEMENT_VERSION(1, 0, 0),
                             "SimEng accelerator wrapper for SST",
                             COMPONENT_CATEGORY_PROCESSOR)

  /**
   * SST supplied MACRO used to document all parameters needed by
   * a custom SST:Component.
   */
  SST_ELI_DOCUMENT_PARAMS(
      {"simeng_config_path",
       "Value which specifies the path to SimEng YAML accelerator model config "
       "file. (string)",
       ""},
      {"clock", "Value which specifies clock rate of the SST clock. (string)",
       ""},
      {"max_addr_memory",
       "Value which specifies the maximum address that memory can access. "
       "Should be the same as on the core. (int)",
       ""},
      {"cache_line_width",
       "Value which specifies the width of the cache line in bytes. "
       "Should be the same as on the core. (int)",
       ""},
      {"debug",
       "Value which enables output statistics that can be parsed by the "
       "testing framework. (boolean)",
       "false"},
      {"debug_level",
       "Debugging level (a higher level also includes all info from lower "
       "levels): 0[None], 1[Offloading traffic], 2[Memory requests] (uint)",
       "0 if debug = FALSE, 2 if debug = TRUE and debug_level unset"})

  SST_ELI_DOCUMENT_PORTS({"core_link",
                          "Port that connects the accelerator to a core, "
                          "or a NoC router if there is more than one.",
                          {"simeng.OffloadingEvent"}})

 private:
  /** Method used to assemble SimEng core. */
  void fabricateSimEngAccelerator();

  /** A handler function used for sending OffloadingEvents to the core. */
  [[nodiscard]] bool sendOffloadingEvent(
      const OffloadingEvent::packet_t& packet) const;

  /** A handler function used for receiving OffloadingEvents from the core. */
  [[nodiscard]] std::optional<OffloadingEvent::packet_t> recvOffloadingEvent()
      const;

  // SST properties
  /**
   * SST defined output class used to output information to standard output.
   * This class has in-built method for different levels of severity and can
   * also be configured to output information like line-number and filename.
   */
  Output output_;

  /**
   * SST clock for the component registered with the custom component
   * during instantiation using the registerClock method provided
   * by SST.
   */
  TimeConverter* clock_;

  /**
   * SST::Interfaces::StandardMem interface responsible for converting
   * SST::StandardMem::Request(s) into SST memory events to be passed
   * down the memory hierarchy.
   */
  StandardMem* sstMem_;

  // SimEng properties
  /** AcceleratorInstance object responsible for creating the accelerator to
   * be simulated. */
  std::unique_ptr<AcceleratorInstance> acceleratorInstance_;

  /** SimEng accelerator instance. */
  std::shared_ptr<Accelerator> accelerator_;

  /** Port Allocator for the accelerator. */
  std::unique_ptr<pipeline::BalancedPortAllocator> portAllocator_;

  /** An SST::Link between a SimEng core and the accelerator. */
  Link* coreLink_;

  /** SimEngMemInterface instance used for interfacing with SST. */
  std::shared_ptr<SimEngMemInterface> dataMemory_;

  /** Pointer to memory request handler class defined in SimEngMemInterface. */
  SimEngMemInterface::SimEngMemHandlers* handlers_;

  /** Path to the YAML configuration file for the SimEng accelerator. */
  std::string simengConfigPath_;

  /** The cache line width for SST. */
  uint64_t cacheLineWidth_;

  /** Maximum address available to SimEng for memory purposes. */
  uint64_t maxAddrMemory_;

  /** Flag for additional debug printing. */
  bool debug_ = false;

  /** Specifies debug verbosity. */
  DebugLevel debugLevel_ = DebugLevel::None;
};

}  // namespace SSTSimEng
}  // namespace SST
