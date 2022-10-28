// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include "SimEngMemInterface.hh"

#include <iostream>

using namespace SST::SSTSimEng;

SimEngMemInterface::SimEngMemInterface(StandardMem* mem, uint64_t cl,
                                       uint64_t max_addr, bool debug)
    : simeng::MemoryInterface() {
  this->sstMem_ = mem;
  this->cacheLineWidth_ = cl;
  this->maxAddrMemory_ = max_addr;
  this->debug_ = debug;
};

void SimEngMemInterface::sendProcessImageToSST(char* image, uint64_t size) {
  std::vector<uint8_t> data;
  data.reserve(size);

  for (uint64_t i = 0; i < size; i++) {
    data.push_back((uint8_t)image[i]);
  }

  StandardMem::Request* req = new StandardMem::Write(0, data.size(), data);
  sstMem_->sendUntimedData(req);
  return;
};

template <typename T,
          typename std::enable_if<std::is_base_of<
              SimEngMemInterface::SimEngMemoryRequest, T>::value>::type*>
std::vector<StandardMem::Request*> SimEngMemInterface::makeSSTRequests(
    T* aggrReq, uint64_t addrStart, uint64_t addrEnd, uint64_t size) {
  /*
      Here we check if the memory request spans multiple cache lines.
      i.e from the start address to the end of the cache line there isn't
      enough space to store data or the data to read continues to succeeding
      cache lines. To handle this case the request addresses are divided as
      follows:
          1) addrStart to end of first cache-line.
          2) Start of second cache-line to addrEnd.
      Note: addrEnd can be multiple cache-lines ahead of addrStart

      |   cache-line 1   |   cache-line 2   |
      |         |        |        |         |
      |         |        |        |         |
      |         |        |        |         |
      |         V        |        V         |
      |     addrStart    |     addrEnd      |
      |          <--------------->          |
      |             Request size            |
      |------------------|------------------|
  */
  if (requestSpansMultipleCacheLines(addrStart, addrEnd)) {
    std::vector<StandardMem::Request*> reqs;
    uint64_t cacheLineEndAddr =
        nearestCacheLineEnd(addrStart) * cacheLineWidth_;
    uint64_t firstFragmentSize = cacheLineEndAddr - addrStart;
    uint64_t secondFragmentSize = size - firstFragmentSize;
    std::vector<StandardMem::Request*> rvec1 =
        splitAggregatedRequest(aggrReq, addrStart, firstFragmentSize);
    std::vector<StandardMem::Request*> rvec2 =
        splitAggregatedRequest(aggrReq, cacheLineEndAddr, secondFragmentSize);
    reqs.insert(reqs.end(), rvec1.begin(), rvec1.end());
    reqs.insert(reqs.end(), rvec2.begin(), rvec2.end());
    return reqs;
  }
  return splitAggregatedRequest(aggrReq, addrStart, size);
}

std::vector<StandardMem::Request*> SimEngMemInterface::splitAggregatedRequest(
    AggregateWriteRequest* aggrReq, uint64_t addrStart, uint64_t size) {
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
  if (addrStart > aggrReq->target.address) {
    dataIndex += addrStart - aggrReq->target.address;
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
    const char* data = aggrReq->data.getAsVector<char>();
    memcpy((void*)&payload[0], &(data[dataIndex]), currReqSize);
    StandardMem::Request* writeReq =
        new StandardMem::Write(addrStart, currReqSize, payload);

    dataIndex += currReqSize;
    addrStart += currReqSize;
    requests.push_back(writeReq);
  }
  return requests;
}

std::vector<StandardMem::Request*> SimEngMemInterface::splitAggregatedRequest(
    AggregateReadRequest* aggrReq, uint64_t addrStart, uint64_t size) {
  std::vector<StandardMem::Request*> requests;
  // Get the number of cache-lines needed to read the data requested by the read
  // request.
  int numCacheLinesNeeded = getNumCacheLinesNeeded(size);

  // Loop used to divide a read request from SimEng based on cache-line size.
  for (int x = 0; x < numCacheLinesNeeded; x++) {
    uint64_t currReqSize = size;
    if (size > cacheLineWidth_) {
      size -= cacheLineWidth_;
      currReqSize = cacheLineWidth_;
    }

    StandardMem::Request* readReq =
        new StandardMem::Read(addrStart, currReqSize);

    // Increase the aggregate count to denote the number SST requests a read
    // request from SimEng was split into.
    aggrReq->aggregateCount_++;
    addrStart += currReqSize;
    requests.push_back(readReq);
    /*
    Insert a key-value pair of SST request id and AggregatedReadRequest
    reference in the aggregation map. These key-value pairs will later be
    used to store read response data recieved from SST. This models a
    many-to-one relation between multiple SST requests and a SimEng read
    request.
    */
    aggregationMap_.insert({readReq->getID(), aggrReq});
  }
  return requests;
}

void SimEngMemInterface::requestRead(const MemoryAccessTarget& target,
                                     uint64_t requestId) {
  uint64_t addrStart = target.address;
  uint64_t size = unsigned(target.size);
  uint64_t addrEnd = addrStart + size - 1;
  /*
      Check if address is greater than max memory address or overflows.
      This often happens on wrongly speculated branches leading to
      large values. In this case we queue an empty register value
      which signals an exception. However, wrongly speculated branches
      lead to a pipeline flush after which execution continues.
  */
  if (addrEnd > maxAddrMemory_ || unsignedOverflow_(addrStart, size)) {
    completedReadRequests_.push_back({target, RegisterValue(), requestId});
    return;
  }

  AggregateReadRequest* aggrReq = new AggregateReadRequest(target, requestId);
  std::vector<StandardMem::Request*> requests =
      makeSSTRequests<AggregateReadRequest>(aggrReq, addrStart, addrEnd, size);
  // SST output data parsed by the testing framework.
  // Format:
  // [SSTSimEng:SSTDebug] MemRead-read-<type=request|response>-<request ID>
  // -cycle-<cycle count>-split-<number of requests>
  if (debug_) {
    std::cout << "[SSTSimEng:SSTDebug] MemRead"
              << "-read-request-" << requestId << "-cycle-" << tickCounter_
              << "-split-" << requests.size() << std::endl;
  }
  for (StandardMem::Request* req : requests) {
    sstMem_->send(req);
  }
}

void SimEngMemInterface::requestWrite(const MemoryAccessTarget& target,
                                      const RegisterValue& data) {
  uint64_t addrStart = target.address;
  uint64_t size = unsigned(target.size);
  uint64_t addrEnd = addrStart + size - 1;

  AggregateWriteRequest* aggrReq = new AggregateWriteRequest(target, data);
  std::vector<StandardMem::Request*> requests =
      makeSSTRequests<AggregateWriteRequest>(aggrReq, addrStart, addrEnd, size);

  for (StandardMem::Request* req : requests) {
    sstMem_->send(req);
  }
}

void SimEngMemInterface::tick() { tickCounter_++; }

void SimEngMemInterface::clearCompletedReads() {
  completedReadRequests_.clear();
}

bool SimEngMemInterface::hasPendingRequests() const {
  return aggregationMap_.size() > 0;
};

const span<MemoryReadResult> SimEngMemInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completedReadRequests_.data()),
          completedReadRequests_.size()};
};

void SimEngMemInterface::aggregatedReadResponses(
    AggregateReadRequest* aggrReq) {
  if (aggrReq->aggregateCount_ != 0) return;
  std::vector<uint8_t> mergedData;
  // Loop through the ordered map and merge the data in order inside the
  // mergedData vector. Also remove entries from the aggregation_map as we loop
  // through each SST Request id.
  for (auto itr = aggrReq->responseMap_.begin();
       itr != aggrReq->responseMap_.end(); itr++) {
    mergedData.insert(mergedData.end(), itr->second.begin(), itr->second.end());
    aggregationMap_.erase(itr->first);
  }
  // Send the completed read request back to SimEng via the
  // completed_read_requests queue.
  uint64_t resp = 0;
  for (int x = mergedData.size() - 1; x >= 0; x--) {
    resp = (resp << 8) | mergedData[x];
  }
  // SST output data parsed by the testing framework.
  // Format:
  // [SSTSimEng:SSTDebug] MemRead-read-<type=request|response>-<request ID>
  // -cycle-<cycle count>-data-<value>
  uint64_t id = aggrReq->id_;
  if (debug_) {
    std::cout << "[SSTSimEng:SSTDebug] MemRead"
              << "-read-response-" << id << "-cycle-" << tickCounter_
              << "-data-" << resp << std::endl;
  }

  const char* char_data = reinterpret_cast<const char*>(&mergedData[0]);
  completedReadRequests_.push_back(
      {aggrReq->target,
       RegisterValue(char_data, uint16_t(unsigned(aggrReq->target.size))),
       aggrReq->id_});

  // Cleanup
  aggrReq->responseMap_.clear();
  delete aggrReq;
}

void SimEngMemInterface::SimEngMemHandlers::handle(
    StandardMem::WriteResp* rsp) {
  delete rsp;
}

void SimEngMemInterface::SimEngMemHandlers::handle(StandardMem::ReadResp* rsp) {
  uint64_t id = rsp->getID();
  auto data = rsp->data;
  delete rsp;

  // Upon recieving a response from SST the aggregation_map is used to retrieve
  // the AggregatedReadRequest the recieved SST response is a part of.
  auto itr = memInterface_.aggregationMap_.find(id);
  if (itr == memInterface_.aggregationMap_.end()) return;
  /*
      After succesful retrieval of AggregatedReadRequest from aggregation_map
     the response data is stored inside the AggregatedReadRequest in an ordered
     map. It is neccesary to maintain order in which the orginal read request
     from SimEng was split into otherwise garbage values will be obtained upon
     merging. An ordered map is used here because SST::StandardMem::Request ids
     are generated using an atomic incrementing couter. Reference -
     "interfaces/stdMem.(hh/cc)" (SST-Core)
  */
  SimEngMemInterface::AggregateReadRequest* aggrReq = itr->second;
  aggrReq->responseMap_.insert({id, data});
  /*
      Decrement aggregateCount as we keep on recieving responses from SST.
      If all responses have been recieved aggregate all responses and send
      data back to SimEng.
  */
  if (--aggrReq->aggregateCount_ <= 0) {
    memInterface_.aggregatedReadResponses(aggrReq);
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