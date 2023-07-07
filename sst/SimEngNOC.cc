// #include "SimEngNOC.hh"

// using namespace SST;
// using namespace SST::SSTSimEng;

// SimEngNOC::SimEngNOC(ComponentId_t id, Params& params) : nocAPI(id, params) {
//   output_.init("[SSTSimEng:SimEngNOC] " + getName() + ":@p:@l ", 999, 0,
//                SST::Output::STDOUT);
//   clock_ = registerClock(
//       params.find<std::string>("clock", "1GHz"),
//       new SST::Clock::Handler<SimEngNOC>(this, &SimEngNOC::clockTick));
//   // Args for merlin.linkcontrol (which inherits from
//   // SST::Interfaces::SimpleNetwork) is just the number of virtual netwroks,
//   set
//   // to 1 here
//   interface_ = loadUserSubComponent<SST::Interfaces::SimpleNetwork>(
//       "interface", SST::ComponentInfo::SHARE_NONE, 1);

//   interface_->setNotifyOnReceive(
//       new SST::Interfaces::SimpleNetwork::Handler<SimEngNOC>(
//           this, &SimEngNOC::recvNotify));
// }

// SimEngNOC::~SimEngNOC() {}

// void SimEngNOC::init(unsigned int phase) {
//   interface_->init(phase);

//   // Send an initial broadcast if the network interface has been initialised
//   and
//   // the broadcast hasn't been sent
//   if (interface_->isNetworkInitialized()) {
//     if (!initBroadcastSent_) {
//       initBroadcastSent_ = true;
//       emptyEv* ev = new emptyEv(getName());
//       // Create a network request for init data
//       SST::Interfaces::SimpleNetwork::Request* req =
//           new SST::Interfaces::SimpleNetwork::Request();
//       req->dest = SST::Interfaces::SimpleNetwork::INIT_BROADCAST_ADDR;
//       req->src = interface_->getEndpointID();
//       output_.verbose(CALL_INFO, 1, 0, "Endpoint net id is %lld\n",
//                       interface_->getEndpointID());
//       req->givePayload(ev);
//       // Send network request over interface
//       interface_->sendInitData(req);
//     }
//   }

//   // Check for init data from the network interface
//   while (SST::Interfaces::SimpleNetwork::Request* req =
//              interface_->recvInitData()) {
//     simengNetEv* ev = static_cast<simengNetEv*>(req->takePayload());
//     output_.verbose(CALL_INFO, 1, 0, "%s received init msg from %s\n",
//                     getName().c_str(), ev->getSource().c_str());
//     numDevices_++;
//   }
// }

// void SimEngNOC::setup() {
//   if (recvNotifyHandler_ == nullptr) {
//     output_.fatal(CALL_INFO, -1,
//                   "%s, Error: SimEngNOC uses a callback function that
//                   notifies " "it that a request is ready to be processed
//                   within the " "network interface. The callback function has
//                   not been " "registered through
//                   setRecvNotifyHandler(...)\n", getName().c_str());
//   }
// }

// void SimEngNOC::setRecvNotifyHandler(Event::HandlerBase* handler) {
//   recvNotifyHandler_ = handler;
// }

// void SimEngNOC::send(simengNetEv* ev, int dest) {
//   // Bundle the passed network event into a network request and send to the
//   // passed dest Node ID
//   SST::Interfaces::SimpleNetwork::Request* req =
//       new SST::Interfaces::SimpleNetwork::Request();
//   req->dest = dest;
//   req->src = interface_->getEndpointID();
//   req->givePayload(ev);
//   sendQueue_.push(req);
// }

// bool SimEngNOC::recvNotify(int vn) {
//   output_.verbose(CALL_INFO, 1, 0, "Got netEvent");
//   // On notification, pass the network request onto the message handler
//   SST::Interfaces::SimpleNetwork::Request* req = interface_->recv(0);
//   if (req != nullptr) {
//     simengNetEv* ev = static_cast<simengNetEv*>(req->takePayload());
//     (*recvNotifyHandler_)(ev);
//     delete req;
//   }
//   return true;
// }

// bool SimEngNOC::clockTick(SST::Cycle_t currentCycle) {
//   // Sequentially iterate over to-be-sent network requests and send them to
//   the
//   // interface_
//   while (!sendQueue_.empty()) {
//     // Only send requests if there's enough bandwidth
//     if (interface_->spaceToSend(0, 512) &&
//         interface_->send(sendQueue_.front(), 0)) {
//       output_.verbose(CALL_INFO, 1, 0, "Sending packet to endpoint %lld\n",
//                       sendQueue_.front()->dest);
//       sendQueue_.pop();
//     } else {
//       break;
//     }
//   }
//   // Return false to signal the component should continue to be ticked
//   return false;
// }

// const uint16_t SimEngNOC::getNumDevices() const { return numDevices_; }