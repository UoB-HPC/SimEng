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

#include "simeng/arch/Architecture.hh"

namespace SST {

namespace SSTSimEng {
enum class PacketType { Empty, Syscall };

/** A custom SST::Event to handle the network events to/from the SimEngNOC
 * component. */
class simengNetEv : public SST::Event {
 public:
  /** Get the name of the source device. */
  std::string getSource() { return srcDevice_; }

  /** Get the type of the network event. */
  PacketType getType() { return type_; }

  /** Override of base class event serializer. */
  void serialize_order(SST::Core::Serialization::serializer& ser) override {
    Event::serialize_order(ser);
    ser& srcDevice_;
    ser& type_;
  }

 protected:
  simengNetEv(std::string name, PacketType type)
      : Event(), srcDevice_(name), type_(type) {}

  /** Default constructor needed for serilisation. */
  simengNetEv() {}

  /** Name of the source device that sent the event. */
  std::string srcDevice_;

  /** The type of the packet which helps identify what the paylod is. */
  PacketType type_;

  ImplementSerializable(SST::SSTSimEng::simengNetEv);
};

/** Class to represent a network event which has no payload. Primarily used to
 * establish an initial connection between NOC endpoints. */
class emptyEv : public SST::SSTSimEng::simengNetEv {
 public:
  emptyEv(std::string name) : simengNetEv(name, PacketType::Empty) {}

  emptyEv() : simengNetEv() {}

  /** Overrides the base class clone() which clones the event in for the case
   * of a broadcast. */
  virtual Event* clone(void) override {
    emptyEv* ev = new emptyEv(*this);
    return ev;
  }

  /** Override of base class event serializer. */
  void serialize_order(SST::Core::Serialization::serializer& ser) override {
    simengNetEv::serialize_order(ser);
  }

 private:
  ImplementSerializable(SST::SSTSimEng::emptyEv);
};

/** Class to represent a network event which communicates the outcome of a
 * syscall handled by the SST::SSTSimEng::SimOSWrapper component. */
class syscallEv : public simengNetEv {
 public:
  syscallEv(std::string name) : simengNetEv(name, PacketType::Syscall) {}

  syscallEv() : simengNetEv() {}

  /** Set the payload to be delivered. */
  void setPayload(simeng::arch::ProcessStateChange stateChange) {
    changeType_ = stateChange.type;
    for (size_t i = 0; i < stateChange.modifiedRegisters.size(); i++) {
      simeng::Register reg = stateChange.modifiedRegisters[i];
      regTypes_.push_back(reg.type);
      regTags_.push_back(reg.tag);

      simeng::RegisterValue regVal = stateChange.modifiedRegisterValues[i];
      regSizes_.push_back(regVal.size());
      regValues_.push_back({});
      regValues_[i].assign(regVal.getAsVector<char>(),
                           regVal.getAsVector<char>() + regVal.size());
    }
    for (size_t i = 0; i < stateChange.memoryAddresses.size(); i++) {
      simeng::MemoryAccessTarget memTarget = stateChange.memoryAddresses[i];
      memTargetAddrs_.push_back(memTarget.address);
      memTargetSizes_.push_back(memTarget.size);

      simeng::RegisterValue memVal = stateChange.memoryAddressValues[i];
      assert(memTargetSizes_[i] == memVal.size() &&
             "In syscallEv payload, mismatch between a stateChange's "
             "memoryAddress and memoryAddressValue sizes");
      memTargetValues_.push_back({});
      memTargetValues_[i].assign(memVal.getAsVector<char>(),
                                 memVal.getAsVector<char>() + memVal.size());
    }
  }

  /** Get the payload. */
  simeng::arch::ProcessStateChange getPayload() {
    simeng::arch::ProcessStateChange stateChange = {
        changeType_, {}, {}, {}, {}};
    for (size_t i = 0; i < regTypes_.size(); i++) {
      stateChange.modifiedRegisters.push_back({regTypes_[i], regTags_[i]});
      stateChange.modifiedRegisterValues.push_back(
          {regValues_[i].data(), (uint16_t)regSizes_[i]});
    }
    for (size_t i = 0; i < memTargetAddrs_.size(); i++) {
      stateChange.memoryAddresses.push_back(
          {memTargetAddrs_[i], (uint8_t)memTargetSizes_[i]});
      stateChange.memoryAddressValues.push_back(
          {memTargetValues_[i].data(), (uint16_t)memTargetSizes_[i]});
    }
    return stateChange;
  }

  /** Overrides the base class clone() which clones the event in for the case
   * of a broadcast. */
  virtual Event* clone(void) override {
    syscallEv* ev = new syscallEv(*this);
    return ev;
  }

  /** Override of base class event serializer. */
  void serialize_order(SST::Core::Serialization::serializer& ser) override {
    simengNetEv::serialize_order(ser);
    ser& changeType_;
    ser& regTypes_;
    ser& regTags_;
    ser& regSizes_;
    ser& regValues_;
    ser& memTargetAddrs_;
    ser& memTargetSizes_;
    ser& memTargetValues_;
  }

 private:
  /** The state change type. */
  simeng::arch::ChangeType changeType_;

  /** The types of the registers to be changed. */
  std::vector<uint8_t> regTypes_;

  /** The tags of the registers to be changed. */
  std::vector<uint16_t> regTags_;

  /** The sizes, in bytes, of the selected registers. */
  std::vector<size_t> regSizes_;

  /** The values to change the selected registers with. */
  std::vector<std::vector<char>> regValues_;

  /** The memory addresses to be changed. */
  std::vector<uint64_t> memTargetAddrs_;

  /** The sizes, in bytes, of the memory target values. */
  std::vector<uint8_t> memTargetSizes_;

  /** The values to change the selected memory addresses with. */
  std::vector<std::vector<char>> memTargetValues_;

  ImplementSerializable(SST::SSTSimEng::syscallEv);
};

/** A custom SST::SubComponent to handle the API for the SimEngNOC component.
 */
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

  /** Retrieve the number of devices that can be communicated with over the
   * network. */
  const uint16_t getNumDevices() const;

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

  /** The number of other devices on the network that can be communicated with.
   */
  uint16_t numDevices_ = 0;
};

}  // namespace SSTSimEng
}  // namespace SST