// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on

#include "SimengMemInterface.hh"

#include <iostream>

using namespace SST::SSTSimeng;

SimengMemInterface::SimengMemInterface(StandardMem* mem, uint64_t cl,
                                       uint64_t max_addr, SST::Output* out)
    : simeng::MemoryInterface() {
  this->mem_ = mem;
  this->clw_ = cl;
  this->max_addr_memory_ = max_addr;
  this->output_ = out;
};

void SimengMemInterface::sendProcessImageToSST(const span<char> image) {
  std::vector<uint8_t> data;
  data.reserve(image.size());

  for (size_t i = 0; i < image.size(); i++) {
    data.push_back((uint8_t)image[i]);
  }

  StandardMem::Request* req = new StandardMem::Write(0, data.size(), data);
  mem_->sendUntimedData(req);
  return;
};

template <
    typename T,
    typename std::enable_if<std::is_base_of<
        SimengMemInterface::SimengMemoryRequest, T>::value>::type* = nullptr>
std::vector<StandardMem::Request*> SimengMemInterface::makeSSTRequests(
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
    uint64_t cacheLineEndAddr = nearestCacheLineEnd(addrStart) * clw_;
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

std::vector<StandardMem::Request*> SimengMemInterface::splitAggregatedRequest(
    AggregateWriteRequest* aggrReq, uint64_t addrStart, uint64_t size) {
  std::vector<StandardMem::Request*> requests;
  uint64_t dataIndex = 0;
  std::vector<uint64_t> req_ids;
  // Determine the number of cache-lines needed to store the data in the write
  // request
  int cacheLinesNeeded = getCacheLinesNeeded(size);
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
  for (int x = 0; x < cacheLinesNeeded; x++) {
    uint64_t currReqSize = size;
    if (size > clw_) {
      size -= clw_;
      currReqSize = clw_;
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

std::vector<StandardMem::Request*> SimengMemInterface::splitAggregatedRequest(
    AggregateReadRequest* aggrReq, uint64_t addrStart, uint64_t size) {
  std::vector<StandardMem::Request*> requests;
  std::vector<uint64_t> req_ids;
  // Get the number of cache-lines needed to read the data requested by the read
  // request.
  int cacheLinesNeeded = getCacheLinesNeeded(size);

  // Loop used to divide a read request from SimEng based on cache-line size.
  for (int x = 0; x < cacheLinesNeeded; x++) {
    uint64_t currReqSize = size;
    if (size > clw_) {
      size -= clw_;
      currReqSize = clw_;
    }

    StandardMem::Request* readReq =
        new StandardMem::Read(addrStart, currReqSize);

    // Increase the aggregate count to denote the number SST requests a read
    // request from SimEng was split into.
    aggrReq->aggregateCount++;
    addrStart += currReqSize;
    req_ids.push_back(readReq->getID());
    requests.push_back(readReq);
  }
  for (uint64_t id : req_ids) {
    /*
        Insert a key-value pair of SST request id and AggregatedReadRequest
       reference in the aggregation map. These key-value pairs will later be
       used to store read response data recieved from SST. This models a
       many-to-one relation between multiple SST requests and a SimEng read
       request.
    */
    aggregation_map_.insert({id, aggrReq});
  }
  req_ids.clear();
  return requests;
}

void SimengMemInterface::requestRead(const MemoryAccessTarget& target,
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
  if (addrEnd > max_addr_memory_ || unsignedOverflow_(addrStart, size)) {
    completed_read_requests_.push_back({target, RegisterValue(), requestId});
    return;
  }

  AggregateReadRequest* aggrReq = new AggregateReadRequest(target, requestId);
  std::vector<StandardMem::Request*> requests =
      makeSSTRequests<AggregateReadRequest>(aggrReq, addrStart, addrEnd, size);
  for (StandardMem::Request* req : requests) {
    mem_->send(req);
  }
}

void SimengMemInterface::requestWrite(const MemoryAccessTarget& target,
                                      const RegisterValue& data) {
  uint64_t addrStart = target.address;
  uint64_t size = unsigned(target.size);
  uint64_t addrEnd = addrStart + size - 1;

  AggregateWriteRequest* aggrReq = new AggregateWriteRequest(target, data);
  std::vector<StandardMem::Request*> requests =
      makeSSTRequests<AggregateWriteRequest>(aggrReq, addrStart, addrEnd, size);
  for (StandardMem::Request* req : requests) {
    mem_->send(req);
  }
}

void SimengMemInterface::tick() { tickCounter_++; }

void SimengMemInterface::clearCompletedReads() {
  completed_read_requests_.clear();
}

bool SimengMemInterface::hasPendingRequests() const {
  return completed_read_requests_.size() > 0;
};

const span<MemoryReadResult> SimengMemInterface::getCompletedReads() const {
  return {const_cast<MemoryReadResult*>(completed_read_requests_.data()),
          completed_read_requests_.size()};
};

void SimengMemInterface::aggregatedReadResponses(
    AggregateReadRequest* aggrReq) {
  if (aggrReq->aggregateCount != 0) return;
  std::vector<uint8_t> mergedData;
  // Loop through the ordered map and merge the data in order inside the
  // mergedData vector. Also remove entries from the aggregation_map as we loop
  // through each SST Request id.
  for (auto itr = aggrReq->response_map.begin();
       itr != aggrReq->response_map.end(); itr++) {
    mergedData.insert(mergedData.end(), itr->second.begin(), itr->second.end());
    aggregation_map_.erase(itr->first);
  }
  // Send the completed read request back to SimEng via the
  // completed_read_requests queue.
  const char* char_data = reinterpret_cast<const char*>(&mergedData[0]);
  completed_read_requests_.push_back(
      {aggrReq->target,
       RegisterValue(char_data, uint16_t(unsigned(aggrReq->target.size))),
       aggrReq->id});

  // Cleanup
  aggrReq->response_map.clear();
  delete aggrReq;
}

void SimengMemInterface::SimengMemHandlers::handle(
    StandardMem::WriteResp* rsp) {
  delete rsp;
}

void SimengMemInterface::SimengMemHandlers::handle(StandardMem::ReadResp* rsp) {
  uint64_t id = rsp->getID();
  auto data = rsp->data;
  delete rsp;

  // Upon recieving a response from SST the aggregation_map is used to retrieve
  // the AggregatedReadRequest the recieved SST response is a part of.
  auto itr = mem_interface_.aggregation_map_.find(id);
  if (itr == mem_interface_.aggregation_map_.end()) return;
  /*
      After succesful retrieval of AggregatedReadRequest from aggregation_map
     the response data is stored inside the AggregatedReadRequest in an ordered
     map. It is neccesary to maintain order in which the orginal read request
     from SimEng was split into otherwise garbage values will be obtained upon
     merging. An ordered map is used here because SST::StandardMem::Request ids
     are generated using an atomic incrementing couter. Reference -
     "interfaces/stdMem.(hh/cc)" (SST-Core)
  */
  SimengMemInterface::AggregateReadRequest* aggrReq = itr->second;
  aggrReq->response_map.insert({id, data});
  /*
      Decrement aggregateCount as we keep on recieving responses from SST.
      If all responses have been recieved aggregate all responses and send
      data back to SimEng.
  */
  if (--aggrReq->aggregateCount <= 0) {
    mem_interface_.aggregatedReadResponses(aggrReq);
  }
}

int SimengMemInterface::getCacheLinesNeeded(uint64_t size) {
  if (size < clw_) return 1;
  if (size % clw_ == 0) return size / clw_;
  return (size / clw_) + 1;
}
bool SimengMemInterface::unsignedOverflow_(uint64_t a, uint64_t b) const {
  return (a + b) < a || (a + b) < b;
};
bool SimengMemInterface::requestSpansMultipleCacheLines(uint64_t addrStart,
                                                        uint64_t addrEnd) {
  uint64_t lineDiff = (addrEnd / clw_) - (addrStart / clw_);
  return lineDiff > 0;
};
uint64_t SimengMemInterface::nearestCacheLineEnd(uint64_t addrStart) {
  return (addrStart / clw_) + 1;
};