// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include <sst/core/component.h>
#include <sst/core/eli/elementinfo.h>
#include <sst/core/event.h>
#include <sst/core/interfaces/simpleNetwork.h>
#include <sst/core/interfaces/stdMem.h>
#include <sst/core/link.h>
#include <sst/core/timeConverter.h>

namespace SST {

namespace SSTSimEng {

/** A custom SST::Event to handle the network events to/from the SimEngNIC
 * component. */
class networkEvent : public SST::Event {
 public:
  networkEvent() : Event() {}
};

/** A custom SST::SubComponent to handle the API for the SimEngNIC component. */
class nicAPI : public SST::SubComponent {
 public:
  // Register NIC API SubComponent
  SST_ELI_REGISTER_SUBCOMPONENT_API(SST::SSTSimEng::nicAPI)

  nicAPI(SST::ComponentId_t id, SST::Params& params) : SubComponent(id) {}
  ~nicAPI() {}

  /** SST Init lifecycle method. */
  virtual void init(unsigned int phase) = 0;

  /** SST Setup lifecycle method. */
  virtual void setup() = 0;

  /** Set the handler which processes notifications from the network interface
   * which denotes a new request had been recieved from the network. */
  virtual void setRecvNotifyHandler(Event::HandlerBase* handler) = 0;

  /** Send a request, of the form networkEvent, into the network targetting the
   * port `dest`. */
  virtual void send(networkEvent* netEv, int dest) = 0;
};

/**
 * A inherritted class of the nicAPI SST::SubComponent that implements the
 * on-chip communication between SimEng cores.
 */
class SimEngNIC : public nicAPI {
 public:
  /** Register SimEng NIC SubComponent deriving from the nicAPI class. */
  SST_ELI_REGISTER_SUBCOMPONENT_DERIVED(
      SimEngNIC, "sstsimeng", "SimEngNIC", SST_ELI_ELEMENT_VERSION(1, 0, 0),
      "SimEng NIC for inter-core communication", SST::SSTSimEng::nicAPI)

  /** Register the parameters of the SimEngNIC SubComponent. */
  SST_ELI_DOCUMENT_PARAMS(
      {"clock", "Value which specifies clock rate of the SST clock. (string)",
       ""})

  /** Register the ports. */
  SST_ELI_DOCUMENT_PORTS({"network",
                          "Port to network",
                          {"SimEngNIC.networkEvent"}})

  /** Register the SubComponent slots. */
  SST_ELI_DOCUMENT_SUBCOMPONENT_SLOTS(
      {"interface", "SimpleNetwork interface to the linked network",
       "SST::Interfaces::SimpleNetwork"})

  SimEngNIC(ComponentId_t id, Params& params);
  ~SimEngNIC();

  /** SST Init lifecycle method. */
  void init(unsigned int phase) override;

  /** SST Setup lifecycle method. */
  void setup() override;

  /** Set the handler which processes notifications from the network interface
   * which denotes a new request had been recieved from the network. */
  void setRecvNotifyHandler(Event::HandlerBase* handler) override;

  /** Send a request, of the form networkEvent, into the network targetting the
   * port `dest`. */
  void send(networkEvent* netEv, int dest) override;

  /** Callback function for handling the notification from the network that a
   * request is available. The function is passed an int, `virtualNetwork`,
   * representing the virtual network id. Returns a bool which informs the
   * interface whether to keep the handler alive. */
  bool recvNotify(int vn);

  /** Clock tick function to implement per cycle logic. Triggered by the SST
   * clock ticks. */
  bool clockTick(SST::Cycle_t currentCycle);

 protected:
  /** SST output object. */
  SST::Output output_;

  /** SST::SimpleNetwork interface to the linked network. */
  SST::Interfaces::SimpleNetwork* interface_;
};

}  // namespace SSTSimEng
}  // namespace SST