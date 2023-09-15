// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include "SimEngMemInterface.hh"

#include <iostream>

#include "simeng/memory/MemPacket.hh"

using namespace SST::SSTSimEng;

SimEngMemInterface::SimEngMemInterface(StandardMem* dataMem,
                                       StandardMem* instrMem, uint64_t cl,
                                       uint64_t max_addr, bool debug)
    : simeng::memory::Mem() {
  this->dataMem_ = dataMem;
  this->instrMem_ = instrMem;
  this->cacheLineWidth_ = cl;
  this->maxAddrMemory_ = max_addr;
  this->debug_ = debug;
};

size_t SimEngMemInterface::getMemorySize() { return maxAddrMemory_ + 1; }

void SimEngMemInterface::requestAccess(
    std::unique_ptr<simeng::memory::MemPacket>& pkt) {
  if (pkt->ignore()) {
    // std::cerr << "IGNORE: " << pkt->vaddr_ << ":" << pkt->paddr_ <<
    // std::endl;
    handleIgnoredRequest(pkt);
    if (pkt->isFromSystem())
      sysPort_->send(std::move(pkt));
    else
      memPort_->send(std::move(pkt));
  } else if (pkt->isRequest() && pkt->isRead()) {
    // std::cerr << "READ: " << pkt->vaddr_ << ":" << pkt->paddr_ << std::endl;
    handleReadRequest(pkt);
    return;
  } else if (pkt->isRequest() && pkt->isWrite()) {
    // std::cerr << "WRITE: " << pkt->vaddr_ << ":" << pkt->paddr_ << std::endl;
    handleWriteRequest(pkt);
    return;
  } else {
    std::cerr << "[SimEng:SimEngMemInterface] Invalid MemPacket type for "
                 "requesting access to memory. Requests to memory should "
                 "either be of "
                 "type READ_REQUEST or WRITE_REQUEST."
              << std::endl;
    pkt->markAsFaulty();
    if (pkt->isFromSystem())
      sysPort_->send(std::move(pkt));
    else
      memPort_->send(std::move(pkt));
  }
}

void SimEngMemInterface::sendUntimedData(std::vector<char> data, uint64_t addr,
                                         size_t size) {
  std::cerr << "[SimEng:SimEngMemInterface] Attempted to send untimed data "
               "which is unsupported outside of the init() and complete() "
               "stages of an SST simulation. Exiting..."
            << std::endl;
  exit(1);
}

std::vector<char> SimEngMemInterface::getUntimedData(uint64_t paddr,
                                                     size_t size) {
  std::cerr << "[SimEng:SimEngMemInterface] Attempted to get untimed data "
               "which is unsupported outside of the init() and complete() "
               "stages of an SST simulation. Exiting..."
            << std::endl;
  exit(1);
}

void SimEngMemInterface::handleIgnoredRequest(
    std::unique_ptr<simeng::memory::MemPacket>& pkt) {
  if (pkt->isRead()) {
    pkt->turnIntoReadResponse(std::vector<char>(pkt->size_, '\0'));
  } else {
    pkt->turnIntoWriteResponse();
  }
}

void SimEngMemInterface::handleReadRequest(
    std::unique_ptr<simeng::memory::MemPacket>& pkt) {
  uint64_t pAddrStart = pkt->paddr_;
  uint64_t vAddrStart = pkt->vaddr_;
  uint64_t size = pkt->size_;
  uint64_t pAddrEnd = pAddrStart + size - 1;

  AggregateReadRequest* aggrReq = new AggregateReadRequest(pkt);
  std::vector<StandardMem::Request*> requests =
      makeSSTRequests<AggregateReadRequest>(aggrReq, pAddrStart, pAddrEnd,
                                            vAddrStart, size);
  // SST output data parsed by the testing framework.
  // Format:
  // [SSTSimEng:SSTDebug] MemRead-read-<type=request|response>-<request ID>
  // -cycle-<cycle count>-split-<number of requests>
  // if (debug_) {
  //   std::cout << "[SSTSimEng:SSTDebug] MemRead"
  //             << "-read-request-" << aggrReq->id_ << "-cycle-" <<
  //             tickCounter_
  //             << "-split-" << requests.size() << std::endl;
  // }
  if (aggrReq->pkt_->isInstrRead()) {
    for (StandardMem::Request* req : requests) {
      // std::cerr << req->getString() << std::endl;
      instrMem_->send(req);
    }
  } else {
    for (StandardMem::Request* req : requests) {
      // std::cerr << req->getString() << std::endl;
      // std::cerr << "Sent MemPacket from insn " << aggrReq->pkt_->insnSeqId_
      //           << ":" << req->getString() << std::endl;
      dataMem_->send(req);
    }
  }
}

void SimEngMemInterface::handleWriteRequest(
    std::unique_ptr<simeng::memory::MemPacket>& pkt) {
  uint64_t pAddrStart = pkt->paddr_;
  uint64_t vAddrStart = pkt->vaddr_;
  uint64_t size = pkt->size_;
  uint64_t pAddrEnd = pAddrStart + size - 1;

  AggregateWriteRequest* aggrReq = new AggregateWriteRequest(pkt);
  std::vector<StandardMem::Request*> requests =
      makeSSTRequests<AggregateWriteRequest>(aggrReq, pAddrStart, pAddrEnd,
                                             vAddrStart, size);
  // if (debug_) {
  //   std::cout << "[SSTSimEng:SSTDebug] MemWrite"
  //             << "-write-request-" << aggrReq->id_ << "-cycle-" <<
  //             tickCounter_
  //             << "-split-" << requests.size() << std::endl;
  // }

  for (StandardMem::Request* req : requests) {
    // std::cerr << req->getString() << std::endl;
    dataMem_->send(req);
  }
}

std::shared_ptr<Port<std::unique_ptr<simeng::memory::MemPacket>>>
SimEngMemInterface::initMemPort() {
  memPort_ =
      std::make_shared<Port<std::unique_ptr<simeng::memory::MemPacket>>>();
  auto fn = [this](std::unique_ptr<simeng::memory::MemPacket> packet) -> void {
    this->requestAccess(packet);
  };
  memPort_->registerReceiver(fn);
  return memPort_;
}

std::shared_ptr<Port<std::unique_ptr<simeng::memory::MemPacket>>>
SimEngMemInterface::initSystemPort() {
  sysPort_ =
      std::make_shared<Port<std::unique_ptr<simeng::memory::MemPacket>>>();
  auto fn = [this](std::unique_ptr<simeng::memory::MemPacket> packet) -> void {
    packet->markAsFromSystem();
    this->requestAccess(packet);
  };
  sysPort_->registerReceiver(fn);
  return sysPort_;
}

template <typename T,
          typename std::enable_if<std::is_base_of<
              SimEngMemInterface::SimEngMemoryRequest, T>::value>::type*>
std::vector<StandardMem::Request*> SimEngMemInterface::makeSSTRequests(
    T* aggrReq, uint64_t pAddrStart, uint64_t pAddrEnd, uint64_t vAddrStart,
    uint64_t size) {
  /*
      Here we check if the memory request spans multiple cache lines.
      i.e from the start address to the end of the cache line there isn't
      enough space to store data or the data to read continues to succeeding
      cache lines. To handle this case the request addresses are divided as
      follows:
          1) pAddrStart to end of first cache-line.
          2) Start of second cache-line to addrEnd.
      Note: addrEnd can be multiple cache-lines ahead of pAddrStart

      |   cache-line 1   |   cache-line 2   |
      |         |        |        |         |
      |         |        |        |         |
      |         |        |        |         |
      |         V        |        V         |
      |     pAddrStart    |     pAddrEnd      |
      |          <--------------->          |
      |             Request size            |
      |------------------|------------------|
  */
  if (requestSpansMultipleCacheLines(pAddrStart, pAddrEnd)) {
    std::vector<StandardMem::Request*> reqs;
    uint64_t cacheLineEndAddr =
        nearestCacheLineEnd(pAddrStart) * cacheLineWidth_;
    uint64_t firstFragmentSize = cacheLineEndAddr - pAddrStart;
    uint64_t secondFragmentSize = size - firstFragmentSize;
    std::vector<StandardMem::Request*> rvec1 = splitAggregatedRequest(
        aggrReq, pAddrStart, vAddrStart, firstFragmentSize);
    std::vector<StandardMem::Request*> rvec2 = splitAggregatedRequest(
        aggrReq, cacheLineEndAddr,
        (vAddrStart + (cacheLineEndAddr - pAddrStart)), secondFragmentSize);
    reqs.insert(reqs.end(), rvec1.begin(), rvec1.end());
    reqs.insert(reqs.end(), rvec2.begin(), rvec2.end());
    return reqs;
  }
  return splitAggregatedRequest(aggrReq, pAddrStart, vAddrStart, size);
}

std::vector<StandardMem::Request*> SimEngMemInterface::splitAggregatedRequest(
    AggregateWriteRequest* aggrReq, uint64_t pAddrStart, uint64_t vAddrStart,
    uint64_t size) {
  std::vector<StandardMem::Request*> requests;
  uint64_t dataIndex = 0;
  // Determine the number of cache-lines needed to store the data in the write
  // request
  int numCacheLinesNeeded = getNumCacheLinesNeeded(size);
  /*
      This check here increments the data index to a value indexing the portion
     of data which succeeds the portion data already copied incase the request
     spans multiple cache-lines. In reference to the diagram above, this check
     will succeed only for cache-line 2.
  */
  if (pAddrStart > aggrReq->pkt_->paddr_) {
    dataIndex += pAddrStart - aggrReq->pkt_->paddr_;
  }
  // Loop used to divide a write request from SimEng based on cache-line size.
  for (int x = 0; x < numCacheLinesNeeded; x++) {
    uint64_t currReqSize = size;
    if (size > cacheLineWidth_) {
      size -= cacheLineWidth_;
      currReqSize = cacheLineWidth_;
    }
    // SST write requests accept uint8_t vectors as data.
    std::vector<uint8_t> payload;
    payload.resize(currReqSize);

    // Fill the payload vector currReqSize number of bytes starting
    // and inclusive of the dataIndex.
    const char* data = aggrReq->data_.getAsVector<char>();
    memcpy((void*)&payload[0], &(data[dataIndex]), currReqSize);
    uint32_t flags = 0;
    if (aggrReq->pkt_->isUntimed()) {
      flags = 2;
    }
    StandardMem::Request* writeReq;
    // The underlying class of the StandardMem::Request pointer depends on
    // whether the access is atomic
    if (aggrReq->pkt_->isAtomic()) {
      writeReq = new StandardMem::StoreConditional(pAddrStart, currReqSize,
                                                   payload, flags);
    } else {
      writeReq = new StandardMem::Write(pAddrStart, currReqSize, payload, false,
                                        flags);
    }

    aggrReq->aggregateCount_++;
    dataIndex += currReqSize;
    pAddrStart += currReqSize;
    vAddrStart += currReqSize;
    requests.push_back(writeReq);
    aggregationMap_.insert({writeReq->getID(), aggrReq});
  }
  return requests;
}

std::vector<StandardMem::Request*> SimEngMemInterface::splitAggregatedRequest(
    AggregateReadRequest* aggrReq, uint64_t pAddrStart, uint64_t vAddrStart,
    uint64_t size) {
  std::vector<StandardMem::Request*> requests;
  // Get the number of cache-lines needed to read the data requested by the
  // read request.
  int numCacheLinesNeeded = getNumCacheLinesNeeded(size);

  // Loop used to divide a read request from SimEng based on cache-line size.
  for (int x = 0; x < numCacheLinesNeeded; x++) {
    uint64_t currReqSize = size;
    if (size > cacheLineWidth_) {
      size -= cacheLineWidth_;
      currReqSize = cacheLineWidth_;
    }

    StandardMem::Request* readReq;
    // The underlying class of the StandardMem::Request pointer depends on
    // whether the access is atomic
    if (aggrReq->pkt_->isAtomic())
      readReq = new StandardMem::LoadLink(pAddrStart, currReqSize);
    else
      readReq = new StandardMem::Read(pAddrStart, currReqSize);

    // Increase the aggregate count to denote the number SST requests a read
    // request from SimEng was split into.
    aggrReq->aggregateCount_++;
    pAddrStart += currReqSize;
    vAddrStart += currReqSize;
    requests.push_back(readReq);
    /*
    Insert a key-value pair of SST request id and AggregatedReadRequest
    reference in the aggregation map. These key-value pairs will later be
    used to store read response data received from SST. This models a
    many-to-one relation between multiple SST requests and a SimEng read
    request.
    */
    aggregationMap_.insert({readReq->getID(), aggrReq});
  }
  return requests;
}

void SimEngMemInterface::tick() { tickCounter_++; }

void SimEngMemInterface::aggregatedReadResponses(
    AggregateReadRequest* aggrReq) {
  if (aggrReq->aggregateCount_ != 0) return;
  std::vector<char> mergedData;
  // Loop through the ordered map and merge the data in order inside the
  // mergedData vector. Also remove entries from the aggregation_map as we
  // loop through each SST Request id.
  for (auto itr = aggrReq->responseMap_.begin();
       itr != aggrReq->responseMap_.end(); itr++) {
    mergedData.insert(mergedData.end(), itr->second.begin(), itr->second.end());
    aggregationMap_.erase(itr->first);
  }
  // Send the completed read request back to SimEng via the
  // completed_read_requests queue.
  uint64_t resp = 0;
  for (int x = mergedData.size() - 1; x >= 0; x--) {
    resp = (resp << 8) | static_cast<uint8_t>(mergedData[x]);
  }
  // SST output data parsed by the testing framework.
  // Format:
  // [SSTSimEng:SSTDebug] MemRead-read-<type=request|response>-<request ID>
  // -cycle-<cycle count>-data-<value>
  // uint64_t id = aggrReq->id_;
  // if (debug_) {
  //   std::cout << "[SSTSimEng:SSTDebug] MemRead"
  //             << "-read-response-" << id << "-cycle-" << tickCounter_
  //             << "-data-" << resp << std::endl;
  // }

  aggrReq->pkt_->turnIntoReadResponse(mergedData);
  if (aggrReq->pkt_->isFromSystem())
    sysPort_->send(std::move(aggrReq->pkt_));
  else
    memPort_->send(std::move(aggrReq->pkt_));

  // const char* char_data = reinterpret_cast<const char*>(&mergedData[0]);

  // completedReadRequests_.push_back(
  //     {aggrReq->target,
  //      RegisterValue(char_data, uint16_t(unsigned(aggrReq->target.size))),
  //      aggrReq->id_});

  // Cleanup
  aggrReq->responseMap_.clear();
  delete aggrReq;
}

void SimEngMemInterface::aggregatedWriteResponses(
    AggregateWriteRequest* aggrReq) {
  if (aggrReq->aggregateCount_ != 0) return;
  uint64_t id = aggrReq->id_;
  // if (debug_) {
  //   std::cout << "[SSTSimEng:SSTDebug] MemWrite"
  //             << "-write-response-" << id << "-cycle-" << tickCounter_
  //             << "-failed-" << aggrReq->pkt_->hasFailed() << std::endl;
  // }
  aggrReq->pkt_->turnIntoWriteResponse();
  if (aggrReq->pkt_->isFromSystem())
    sysPort_->send(std::move(aggrReq->pkt_));
  else
    memPort_->send(std::move(aggrReq->pkt_));

  // Cleanup
  delete aggrReq;
}

void SimEngMemInterface::SimEngMemHandlers::handle(StandardMem::ReadResp* rsp) {
  uint64_t id = rsp->getID();
  auto data = rsp->data;
  delete rsp;

  // Upon receiving a response from SST the aggregation_map is used to
  // retrieve the AggregatedReadRequest the received SST response is a part
  // of.
  auto itr = memInterface_.aggregationMap_.find(id);
  if (itr == memInterface_.aggregationMap_.end()) return;
  /*
      After succesful retrieval of AggregatedReadRequest from aggregation_map
     the response data is stored inside the AggregatedReadRequest in an
     ordered map. It is neccesary to maintain order in which the orginal read
     request from SimEng was split into otherwise garbage values will be
     obtained upon merging. An ordered map is used here because
     SST::StandardMem::Request ids are generated using an atomic incrementing
     couter. Reference - "interfaces/stdMem.(hh/cc)" (SST-Core)
  */
  SimEngMemInterface::AggregateReadRequest* aggrReq =
      reinterpret_cast<SimEngMemInterface::AggregateReadRequest*>(itr->second);
  aggrReq->responseMap_.insert({id, data});
  /*
      Decrement aggregateCount as we keep on receiving responses from SST.
      If all responses have been received aggregate all responses and send
      data back to SimEng.
  */
  if (--aggrReq->aggregateCount_ <= 0) {
    memInterface_.aggregatedReadResponses(aggrReq);
  }
}

void SimEngMemInterface::SimEngMemHandlers::handle(
    StandardMem::WriteResp* rsp) {
  uint64_t id = rsp->getID();
  // std::cout << "HANDLE " << id << std::endl;
  delete rsp;

  auto itr = memInterface_.aggregationMap_.find(id);
  if (itr == memInterface_.aggregationMap_.end()) {
    // std::cerr << "\tNo aggr req" << std::endl;
    return;
  }

  SimEngMemInterface::AggregateWriteRequest* aggrReq =
      reinterpret_cast<SimEngMemInterface::AggregateWriteRequest*>(itr->second);
  // Record a failure
  if (rsp->getFail()) aggrReq->pkt_->markAsFailed();

  if (--aggrReq->aggregateCount_ <= 0) {
    memInterface_.aggregatedWriteResponses(aggrReq);
    // } else {
    //   std::cerr << "\t" << aggrReq->aggregateCount_ << " left" << std::endl;
  }
}

int SimEngMemInterface::getNumCacheLinesNeeded(uint64_t size) const {
  if (size < cacheLineWidth_) return 1;
  if (size % cacheLineWidth_ == 0) return size / cacheLineWidth_;
  return (size / cacheLineWidth_) + 1;
}
bool SimEngMemInterface::unsignedOverflow_(uint64_t a, uint64_t b) const {
  return (a + b) < a || (a + b) < b;
};
bool SimEngMemInterface::requestSpansMultipleCacheLines(
    uint64_t addrStart, uint64_t addrEnd) const {
  uint64_t lineDiff =
      (addrEnd / cacheLineWidth_) - (addrStart / cacheLineWidth_);
  return lineDiff > 0;
};
uint64_t SimEngMemInterface::nearestCacheLineEnd(uint64_t addrStart) const {
  return (addrStart / cacheLineWidth_) + 1;
};