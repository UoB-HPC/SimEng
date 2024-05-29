#include "SimEngNOC.hh"

using namespace SST;
using namespace SST::SSTSimEng;

SimEngNOC::SimEngNOC(ComponentId_t id, Params& params) : nocAPI(id, params) {
  output_.init("[SSTSimEng:SimEngNOC] " + getName() + ":@p:@l ", 999, 0,
               SST::Output::STDOUT);
  clock_ = registerClock(
      params.find<std::string>("clock", "1GHz"),
      new SST::Clock::Handler<SimEngNOC>(this, &SimEngNOC::clockTick));
  // Args for merlin.linkcontrol (which inherits from
  // SST::Interfaces::SimpleNetwork) is just the number of virtual netwroks, set
  // to 1 here
  interface_ = loadUserSubComponent<SST::Interfaces::SimpleNetwork>(
      "interface", SST::ComponentInfo::SHARE_NONE, 1);

  interface_->setNotifyOnReceive(
      new SST::Interfaces::SimpleNetwork::Handler<SimEngNOC>(
          this, &SimEngNOC::recvNotify));
}

SimEngNOC::~SimEngNOC() {}

void SimEngNOC::init(unsigned int phase) {
  interface_->init(phase);

  // Send an initial broadcast if the network interface has been initialised and
  // the broadcast hasn't been sent
  if (interface_->isNetworkInitialized()) {
    if (!initBroadcastSent_) {
      initBroadcastSent_ = true;
      emptyEv* ev = new emptyEv(getName(), -1);
      // Create a network request for init data
      SST::Interfaces::SimpleNetwork::Request* req =
          new SST::Interfaces::SimpleNetwork::Request();
      req->dest = SST::Interfaces::SimpleNetwork::INIT_BROADCAST_ADDR;
      req->src = interface_->getEndpointID();
      // output_.verbose(CALL_INFO, 1, 0, "Endpoint net id is %lld\n",
      //                 interface_->getEndpointID());
      req->givePayload(ev);
      // Send network request over interface
      interface_->sendInitData(req);
    }
  }

  // Check for init data from the network interface
  while (SST::Interfaces::SimpleNetwork::Request* req =
             interface_->recvInitData()) {
    // simengNetEv* ev = static_cast<simengNetEv*>(req->takePayload());
    // output_.verbose(CALL_INFO, 1, 0, "%s received init msg from %s\n",
    //                 getName().c_str(), ev->getSource().c_str());
    numDevices_++;
  }
}

void SimEngNOC::setup() {
  if (recvNotifyHandler_ == nullptr) {
    output_.fatal(CALL_INFO, -1,
                  "%s, Error: SimEngNOC uses a callback function that notifies "
                  "it that a request is ready to be processed within the "
                  "network interface. The callback function has not been "
                  "registered through setRecvNotifyHandler(...)\n",
                  getName().c_str());
  }
}

void SimEngNOC::setRecvNotifyHandler(Event::HandlerBase* handler) {
  recvNotifyHandler_ = handler;
}

void SimEngNOC::send(simengNetEv* ev, int dest) {
  enumeratedComms_[ev->getType()]->addData(1);
  // Bundle the passed network event into a network request and send to the
  // passed dest Node ID
  SST::Interfaces::SimpleNetwork::Request* req =
      new SST::Interfaces::SimpleNetwork::Request();
  req->dest = dest;
  req->src = interface_->getEndpointID();
  // if (ev->getType() == PacketType::Translate) {
  //   output_.verbose(CALL_INFO, 2, 0, "Adding request to queue %s\n",
  //                   ev->toString());
  // }
  req->givePayload(ev);
  sendQueue_.push(req);
}

bool SimEngNOC::recvNotify(int vn) {
  // output_.verbose(CALL_INFO, 1, 0, "Got netEvent");
  // On notification, pass the network request onto the message handler
  SST::Interfaces::SimpleNetwork::Request* req = interface_->recv(0);
  if (req != nullptr) {
    // simengNetEv* ev2 = static_cast<simengNetEv*>(req->inspectPayload());
    // if (ev2->getType() == PacketType::Translate) {
    //   transEv* translationReq = static_cast<transEv*>(req->inspectPayload());
    //   if (translationReq->getVirtualAddr() == 0x10102464c4500) {
    //     std::cerr << "RECV TRANS FOR VADDR " << std::hex
    //               << translationReq->getVirtualAddr() << std::dec
    //               << " INTO NETWORK QUEUE" << std::endl;
    //   }
    // }
    simengNetEv* ev = static_cast<simengNetEv*>(req->takePayload());
    (*recvNotifyHandler_)(ev);
    delete req;
  }
  return true;
}

bool SimEngNOC::clockTick(SST::Cycle_t current_cycle) {
  // output_.verbose(CALL_INFO, 1, 0, "tick %llu\n", current_cycle);
  // Sequentially iterate over to-be-sent network requests and send them to the
  // interface_
  while (!sendQueue_.empty()) {
    // simengNetEv* ev =
    //     static_cast<simengNetEv*>(sendQueue_.front()->inspectPayload());
    // if (ev->getType() == PacketType::Translate) {
    //   transEv* translationReq =
    //       static_cast<transEv*>(sendQueue_.front()->inspectPayload());
    //   if (translationReq->getVirtualAddr() == 0x10102464c4500) {
    //     std::cerr << current_cycle << " ADDED TRANS FOR VADDR " << std::hex
    //               << translationReq->getVirtualAddr() << std::dec
    //               << " INTO NETWORK QUEUE" << std::endl;
    //     sendQueue_.front()->setTraceType(
    //         SST::Interfaces::SimpleNetwork::Request::TraceType::FULL);
    //   }
    // }
    // Only send requests if there's enough bandwidth
    if (interface_->spaceToSend(0, 512) &&
        interface_->send(sendQueue_.front(), 0)) {
      // output_.verbose(CALL_INFO, 1, 0, "Sending packet to endpoint %lld\n",
      //                 sendQueue_.front()->dest);
      // if (ev->getType() == PacketType::Translate) {
      //   transEv* translationReq =
      //       static_cast<transEv*>(sendQueue_.front()->inspectPayload());
      //   if (translationReq->getVirtualAddr() == 0x10102464c4500) {
      //     std::cerr << current_cycle << " SENT TRANS FOR VADDR " << std::hex
      //               << translationReq->getVirtualAddr() << std::dec
      //               << " INTO NETWORK QUEUE" << std::endl;
      //   }
      // }
      sendQueue_.pop();
    } else {
      // if (ev->getType() == PacketType::Translate) {
      //   transEv* translationReq =
      //       static_cast<transEv*>(sendQueue_.front()->inspectPayload());
      //   if (translationReq->getVirtualAddr() == 0x10102464c4500) {
      //     std::cerr << current_cycle << " NOT SENT TRANS FOR VADDR " <<
      //     std::hex
      //               << translationReq->getVirtualAddr() << std::dec
      //               << " INTO NETWORK QUEUE AS "
      //               << interface_->spaceToSend(0, 512) << std::endl;
      //   }
      // }
      break;
    }
  }
  // Return false to signal the component should continue to be ticked
  return false;
}

const uint16_t SimEngNOC::getNumDevices() const { return numDevices_; }

const int64_t SimEngNOC::getEndpointId() const {
  return interface_->getEndpointID();
}