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

#include <queue>

namespace SST {

namespace SSTSimEng {

/** A custom SST::Event to handle the network events to/from the SimEngNOC
 * component. */
class simengNetEv : public SST::Event {
 public:
  simengNetEv(std::string name) : Event(), srcDevice(name) {}
  simengNetEv() : Event() {}

  /** Get the name of the source device. */
  std::string getSource() { return srcDevice; }

  /** Overrides the base class clone() which clones the event in for the case of
   * a broadcast. */
  virtual Event* clone(void) override {
    simengNetEv* ev = new simengNetEv(*this);
    return ev;
  }

  /** Override of base class event serializer. */
  void serialize_order(SST::Core::Serialization::serializer& ser) override {
    Event::serialize_order(ser);
    ser& srcDevice;
  }

  /** Implements SimEngNOC serialization. */
  ImplementSerializable(SST::SSTSimEng::simengNetEv);

 private:
  /** Name of the source device that sent the event. */
  std::string srcDevice;
};

/** A custom SST::SubComponent to handle the API for the SimEngNOC component. */
class nocAPI : public SST::SubComponent {
 public:
  // Register NOC API SubComponent
  SST_ELI_REGISTER_SUBCOMPONENT_API(SST::SSTSimEng::nocAPI)

  nocAPI(SST::ComponentId_t id, SST::Params& params) : SubComponent(id) {}
  virtual ~nocAPI() {}

  /** SST Init lifecycle method. */
  virtual void init(unsigned int phase) {}

  /** SST Setup lifecycle method. */
  virtual void setup() {}

  /** Set the handler which processes notifications from the network interface
   * which denotes a new request had been recieved from the network. */
  virtual void setRecvNotifyHandler(Event::HandlerBase* handler) = 0;

  /** Send a request, of the form simengNetEv, into the network targetting the
   * port `dest`. */
  virtual void send(simengNetEv* netEv, int dest) = 0;
};

/**
 * A inherritted class of the nocAPI SST::SubComponent that implements the
 * on-chip communication between SimEng cores.
 */
class SimEngNOC : public nocAPI {
 public:
  /** Register SimEng NOC SubComponent deriving from the nocAPI class. */
  SST_ELI_REGISTER_SUBCOMPONENT_DERIVED(
      SimEngNOC, "sstsimeng", "SimEngNOC", SST_ELI_ELEMENT_VERSION(1, 0, 0),
      "SimEng NOC for inter-core communication", SST::SSTSimEng::nocAPI)

  /** Register the parameters of the SimEngNOC SubComponent. */
  SST_ELI_DOCUMENT_PARAMS(
      {"clock", "Value which specifies clock rate of the SST clock. (string)",
       ""})

  /** Register the ports. */
  SST_ELI_DOCUMENT_PORTS({"network",
                          "Port to network",
                          {"SimEngNOC.simengNetEv"}})

  /** Register the SubComponent slots. */
  SST_ELI_DOCUMENT_SUBCOMPONENT_SLOTS(
      {"interface", "SimpleNetwork interface to the linked network",
       "SST::Interfaces::SimpleNetwork"})

  SimEngNOC(ComponentId_t id, Params& params);
  virtual ~SimEngNOC();

  /** SST Init lifecycle method. */
  virtual void init(unsigned int phase);

  /** SST Setup lifecycle method. */
  virtual void setup();

  /** Set the handler which processes notifications from the network interface
   * which denotes a new request had been recieved from the network. */
  void setRecvNotifyHandler(Event::HandlerBase* handler) override;

  /** Send a request, of the form simengNetEv, into the network targetting the
   * port `dest`. */
  void send(simengNetEv* netEv, int dest) override;

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

  /** Queue to buffer network requests to be sent to the interface_. */
  std::queue<SST::Interfaces::SimpleNetwork::Request*> sendQueue_;

  /** A callback function to handle signals that a message is
   * ready to be recieved by the NOC from the network. */
  SST::Event::HandlerBase* recvNotifyHandler_ = nullptr;

  /** Whether the NOC has sent its initial broadcast. */
  bool initBroadcastSent_ = false;
};

}  // namespace SSTSimEng
}  // namespace SST