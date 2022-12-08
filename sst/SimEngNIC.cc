// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include "SimEngNIC.hh"

using namespace SST;
using namespace SST::SSTSimEng;

SimEngNIC::SimEngNIC(SST::ComponentId_t id, SST::Params& params)
    : nicAPI(id, params) {
  output_.init("[SSTSimEng:SimEngNIC] " + getName() + ":@p:@l ", 999, 0,
               SST::Output::STDOUT);
  registerClock(
      params.find<std::string>("clock", "1GHz"),
      new SST::Clock::Handler<SimEngNIC>(this, &SimEngNIC::clockTick));
  // Args for merlin.linkcontrol (which inherets from
  // SST::Interfaces::SimpleNetwork) is just the number of virtual netwroks, set
  // to 1 here
  interface_ = loadUserSubComponent<SST::Interfaces::SimpleNetwork>(
      "interface", SST::ComponentInfo::SHARE_NONE, 1);
}

void SimEngNIC::init(unsigned int phase) {}

void SimEngNIC::setup() {}

void SimEngNIC::setRecvNotifyHandler(Event::HandlerBase* handler) {}

void SimEngNIC::send(networkEvent* netEv, int dest) {}

bool SimEngNIC::recvNotify(int vn) { return true; }

bool SimEngNIC::clockTick(SST::Cycle_t currentCycle) { return false; }