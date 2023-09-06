#include "simeng/pipeline_hi/LoadStoreQueue.hh"

#include <array>
#include <cassert>
#include <cstring>
#include <iostream>

namespace simeng {
namespace pipeline_hi {

/** Check whether requests `a` and `b` overlap. */
bool requestsOverlap(MemoryAccessTarget a, MemoryAccessTarget b) {
  // Check whether one region ends before the other begins, implying no overlap,
  // and negate
  return !(a.address + a.size <= b.address || b.address + b.size <= a.address);
}

LoadStoreQueue::LoadStoreQueue(
    unsigned int maxCombinedSpace, MemoryInterface& memory,
    span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
    std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
    bool exclusive, uint16_t loadBandwidth, uint16_t storeBandwidth,
    uint16_t permittedRequests, uint16_t permittedLoads,
    uint16_t permittedStores)
    : completionSlots_(completionSlots),
      forwardOperands_(forwardOperands),
      maxCombinedSpace_(maxCombinedSpace),
      combined_(true),
      memory_(memory),
      exclusive_(exclusive),
      loadBandwidth_(loadBandwidth),
      storeBandwidth_(storeBandwidth),
      totalLimit_(permittedRequests),
      // Set per-cycle limits for each request type
      reqLimits_{permittedLoads, permittedStores} {};

LoadStoreQueue::LoadStoreQueue(
    unsigned int maxLoadQueueSpace, unsigned int maxStoreQueueSpace,
    MemoryInterface& memory,
    span<PipelineBuffer<std::shared_ptr<Instruction>>> completionSlots,
    std::function<void(span<Register>, span<RegisterValue>)> forwardOperands,
    bool exclusive, uint16_t loadBandwidth, uint16_t storeBandwidth,
    uint16_t permittedRequests, uint16_t permittedLoads,
    uint16_t permittedStores)
    : completionSlots_(completionSlots),
      forwardOperands_(forwardOperands),
      maxLoadQueueSpace_(maxLoadQueueSpace),
      maxStoreQueueSpace_(maxStoreQueueSpace),
      combined_(false),
      memory_(memory),
      exclusive_(exclusive),
      loadBandwidth_(loadBandwidth),
      storeBandwidth_(storeBandwidth),
      totalLimit_(permittedRequests),
      // Set per-cycle limits for each request type
      reqLimits_{permittedLoads, permittedStores} {};

unsigned int LoadStoreQueue::getLoadQueueSpace() const {
  if (combined_) {
    return getCombinedSpace();
  } else {
    return getLoadQueueSplitSpace();
  }
}
unsigned int LoadStoreQueue::getStoreQueueSpace() const {
  if (combined_) {
    return getCombinedSpace();
  } else {
    return getStoreQueueSplitSpace();
  }
}
unsigned int LoadStoreQueue::getTotalSpace() const {
  if (combined_) {
    return getCombinedSpace();
  } else {
    return getLoadQueueSplitSpace() + getStoreQueueSplitSpace();
  }
}

unsigned int LoadStoreQueue::getLoadQueueSplitSpace() const {
  return maxLoadQueueSpace_ - loadQueue_.size();
}
unsigned int LoadStoreQueue::getStoreQueueSplitSpace() const {
  return maxStoreQueueSpace_ - storeQueue_.size();
}
unsigned int LoadStoreQueue::getCombinedSpace() const {
  return maxCombinedSpace_ - loadQueue_.size() - storeQueue_.size();
}

bool isMisAligned(uint64_t addr, uint8_t sz) {
  if(((addr & 0x1) && sz==2) || ((addr & 0x3) && sz==4)) {
    return true;
  }
  return false;
}

void LoadStoreQueue::addLoad(const std::shared_ptr<Instruction>& insn) {

  const auto& addresses = insn->getGeneratedAddresses();

  assert(addresses.size()==1 && "Expecting only 1 address in load request");
  // Do something to split into multiple requests if alignment is required for case like crossing 4 byte boundary.

  loadQueue_.push_back(insn);
  uint64_t add_tick = 1;
  bool isMisAlign = false;
  if (isMisAligned(addresses[0].address, addresses[0].size)) {
    add_tick+=1;
    isMisAlign=true;
  }
  requestQueue_.push_back({{}, {}, insn, LOAD, (tickCounter_+add_tick) + insn->getLSQLatency(), isMisAlign});
  // Submit request write to memory interface early as the architectural state
  // considers the store to be retired and thus its operation complete

  for (size_t i = 0; i < addresses.size(); i++) {
    //memory_.requestWrite(addresses[i], data[i]);
    // Still add addresses to requestQueue_ to ensure contention of resources is
    // correctly simulated
    requestQueue_.back().reqAddresses.push(addresses[i]);
  }

  //loadQueue_.push_back(insn);
  //startLoad(insn);
}

void LoadStoreQueue::addStore(const std::shared_ptr<Instruction>& insn) {

  const auto& addresses = insn->getGeneratedAddresses();
  span<const simeng::RegisterValue> data = insn->getData();

  assert(addresses.size()==1 && "Expecting only 1 address in store request");
  // Do something to split into multiple requests if alignment is required for case like crossing 4 byte boundary.

  storeQueue_.push_back({insn, data});

  uint64_t add_tick = 1;
  bool isMisAlign = false;
  if (isMisAligned(addresses[0].address, addresses[0].size)) {
    add_tick+=1;
    isMisAlign = true;
  }

  requestQueue_.push_back({{}, {}, insn, STORE, (tickCounter_+add_tick) + insn->getLSQLatency(), isMisAlign});
  // Submit request write to memory interface early as the architectural state
  // considers the store to be retired and thus its operation complete

  for (size_t i = 0; i < addresses.size(); i++) {
    //memory_.requestWrite(addresses[i], data[i]);
    // Still add addresses to requestQueue_ to ensure contention of resources is
    // correctly simulated
    requestQueue_.back().reqAddresses.push(addresses[i]);
    requestQueue_.back().data.push(data[i]);
  }
  //storeQueue_.push_back({insn, {}});
  //supplyStoreData(insn);
  //commitStore(insn);
}

void LoadStoreQueue::startLoad(const std::shared_ptr<Instruction>& insn) {
  return;
}

void LoadStoreQueue::supplyStoreData(const std::shared_ptr<Instruction>& insn) {
  return;
}

bool LoadStoreQueue::commitStore(const std::shared_ptr<Instruction>& uop) {

  if (storeQueue_.front().first == uop) {
    storeQueue_.pop_front();
  } else {
    assert(false && "The commited store is not the one in the front of the storeQueue_");
  }
  return true;
}

void LoadStoreQueue::commitLoad(const std::shared_ptr<Instruction>& uop) {

  if (loadQueue_.front() == uop) {
    loadQueue_.pop_front();
  } else {
    assert(false && "The commited store is not the one in the front of the loadQueue_");
  }
  return;
}

void LoadStoreQueue::purgeFlushed() {

  return;

}

bool LoadStoreQueue::isBusy() const {
  // TODO: This is just to allow only 1 outstanding request to be used for SST integeration.
  //if (activeMisAlignedOpr() || loadQueue_.size()>=1 || storeQueue_.size()>=1) {
  if (activeMisAlignedOpr() || (loadQueue_.size()+storeQueue_.size())>=2) {
    return true;
  }
  return false;
}

void LoadStoreQueue::tick() {
  tickCounter_++;

  //Request at the front of the queue should be sent to memory first
  //Ensure its scheduled after necessary tick
  if (requestQueue_.size() > 0) {
    requestEntry1& oldestreq = requestQueue_.front();
    if (tickCounter_ >= oldestreq.reqtick) {
      if(oldestreq.type == LOAD) {
        memory_.requestRead(oldestreq.reqAddresses.front(), (uint64_t) busReqId);
        oldestreq.reqAddresses.pop();
        if (oldestreq.reqAddresses.size() == 0) { // All requests sent
          requestQueue_.pop_front();
        }
        requestedLoads_.emplace(busReqId, oldestreq.insn);
        numLoads++;
        latencyLoads_.emplace(busReqId, tickCounter_);
        busReqId++;
      } else if(oldestreq.type == STORE) {
        memory_.requestWrite(oldestreq.reqAddresses.front(), oldestreq.data.front());
        oldestreq.reqAddresses.pop();
        oldestreq.data.pop();
        if (oldestreq.reqAddresses.size() == 0) { // All requests sent
          requestQueue_.pop_front();
          //Verify same instruction. and remove from the storeQueue_ as well
          //storeQueue_.pop_front();//No need
        }
      } else {
        assert(false && "Unknown request type to be scheduled to memory");
      }
    }
  }

  //processResponse();
}

void LoadStoreQueue::processResponse() {
  // Process completed read requests
  for (const auto& response : memory_.getCompletedReads()) {
    const auto& address = response.target.address;
    const auto& data = response.data;

    // TODO: Detect and handle non-fatal faults (e.g. page fault)

    // Find instruction that requested the memory read
    const auto& itr = requestedLoads_.find(response.requestId);
    if (itr == requestedLoads_.end()) {
      continue;
    } else {
      requestedLoads_.erase(response.requestId);
      uint32_t ldLatency = ((tickCounter_ + 1) - latencyLoads_.at(response.requestId));
      if (ldLatency > maxLdLatency) {
        maxLdLatency = ldLatency;
      }
      if (ldLatency < minLdLatency) {
        minLdLatency = ldLatency;
      }
      totalLdLatency += ldLatency;
      //std::cout << std::dec << "Total Ld latency: " << totalLdLatency << ", numLoads: " << numLoads  << std::endl;
      latencyLoads_.erase(response.requestId);
    }
    // Supply data to the instruction and execute if it is ready
    const auto& load = itr->second;
    load->supplyData(address, data);
    if (load->hasAllData()) {
      // This load has completed
      load->execute();
      /*if (load->isStoreData()) {
        supplyStoreData(load);
      }*/
      completedLoads_.push(load);
    }
  }
  memory_.clearCompletedReads();

  // Pop from the front of the completed loads queue and send to writeback
  size_t count = 0;
  while (completedLoads_.size() > 0 && count < completionSlots_.size()) {
    const auto& insn = completedLoads_.front();

    // Don't process load instruction if it has been flushed
    if (insn->isFlushed()) {
      completedLoads_.pop();
      continue;
    }

    // Forward the results
    // forwardOperands_(insn->getDestinationRegisters(), insn->getResults());

    completionSlots_[count].getTailSlots()[0] = std::move(insn);

    completedLoads_.pop();

    count++;
  }
}

std::shared_ptr<Instruction> LoadStoreQueue::getViolatingLoad() const {
  return violatingLoad_;
}

//Clean up is required!
bool LoadStoreQueue::activeMisAlignedOpr() const {
  //if the front of the request queue has a misaligned request that is not yet being sent to the bus then its better to halt LSU taking new requests.
  // if(storeQueue_.size() > 0 && activeMisAlignedStore) {
  //   return true;
  // }
  return (requestQueue_.size() > 0 && requestQueue_.front().isMisAligned && ((requestQueue_.front().reqtick-tickCounter_)==1));
}

bool LoadStoreQueue::isCombined() const { return combined_; }

}  // namespace pipeline_hi
}  // namespace simeng
