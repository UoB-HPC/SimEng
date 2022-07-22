#include <sst/core/sst_config.h>
#include "SimengMemInterface.hh"

#include <iostream>

using namespace SST::SSTSimeng;

SimengMemInterface::SimengMemInterface(StandardMem* mem, uint64_t cl, uint64_t max_addr, SST::Output* out): simeng::MemoryInterface() {
    this->mem = mem;
    this->clw= cl;
    this->max_addr_memory = max_addr;
    this->output = out;
};

void SimengMemInterface::sendProcessImageToSST(const span<char> image) {
    std::vector<uint8_t> data;
    data.reserve(image.size());

    for (size_t i = 0; i < image.size(); i++) {
        data.push_back((uint8_t)image[i]);
    }

    StandardMem::Request* req = new StandardMem::Write(0, data.size(), data);
    mem->sendUntimedData(req);
    return;
};

// std::vector<StandardMem::Request*> SimengMemInterface::makeSSTRequests(SSTSimengMemReq* sstReq) { 
//     std::vector<StandardMem::Request*> requests;
//     uint64_t addrStart = sstReq->target.address;
//     uint64_t size = unsigned(sstReq->target.size);
//     uint64_t addrEnd = addrStart + size;
    
//     if (addrEnd > max_addr_memory || unsignedOverflow_(addrStart, size)) {
//         completed_read_requests.push_back({sstReq->target, RegisterValue(), sstReq->id});
//         return requests;
//     }

//     if (requestSpansMultipleCacheLines(addrStart, addrEnd)) {
//         std::vector<StandardMem::Request*> reqs;
//         uint64_t cacheLineEndAddr = nearestCacheLineEnd(addrStart) * clw;
//         uint64_t firstFragmentSize = cacheLineEndAddr - addrStart;
//         uint64_t secondFragmentSize = size - firstFragmentSize;
//         std::vector<StandardMem::Request*> rvec1 = divideAggregatedReq(sstReq, addrStart, firstFragmentSize);
//         std::vector<StandardMem::Request*> rvec2 = divideAggregatedReq(sstReq, cacheLineEndAddr, secondFragmentSize);
//         reqs.insert(reqs.end(), rvec1.begin(), rvec1.end());
//         reqs.insert(reqs.end(), rvec2.begin(), rvec2.end());
//         return reqs;
//     }
//     return divideAggregatedReq(sstReq, addrStart, size);
// }

template<typename T, typename std::enable_if<std::is_base_of<SimengMemInterface::SimengMemoryRequest, T>::value>::type* = nullptr>
std::vector<StandardMem::Request*> SimengMemInterface::makeSSTRequests(T* aggrReq, 
    uint64_t addrStart, uint64_t addrEnd, uint64_t size)
{    
    if (requestSpansMultipleCacheLines(addrStart, addrEnd)) {
        std::vector<StandardMem::Request*> reqs;
        uint64_t cacheLineEndAddr = nearestCacheLineEnd(addrStart) * clw;
        uint64_t firstFragmentSize = cacheLineEndAddr - addrStart;
        uint64_t secondFragmentSize = size - firstFragmentSize;
        std::vector<StandardMem::Request*> rvec1 = splitAggregatedRequest(aggrReq, addrStart, firstFragmentSize);
        std::vector<StandardMem::Request*> rvec2 = splitAggregatedRequest(aggrReq, cacheLineEndAddr, secondFragmentSize);
        reqs.insert(reqs.end(), rvec1.begin(), rvec1.end());
        reqs.insert(reqs.end(), rvec2.begin(), rvec2.end());
        return reqs;
    }
    return splitAggregatedRequest(aggrReq, addrStart, size);
}

// std::vector<StandardMem::Request*> SimengMemInterface::makeSSTRequests(AggregateReadRequest* aggrReq) { 
//     std::vector<StandardMem::Request*> requests;
//     uint64_t addrStart = sstReq->target.address;
//     uint64_t size = unsigned(sstReq->target.size);
//     uint64_t addrEnd = addrStart + size;
    
//     if (addrEnd > max_addr_memory || unsignedOverflow_(addrStart, size)) {
//         completed_read_requests.push_back({sstReq->target, RegisterValue(), sstReq->id});
//         return requests;
//     }

//     if (requestSpansMultipleCacheLines(addrStart, addrEnd)) {
//         std::vector<StandardMem::Request*> reqs;
//         uint64_t cacheLineEndAddr = nearestCacheLineEnd(addrStart) * clw;
//         uint64_t firstFragmentSize = cacheLineEndAddr - addrStart;
//         uint64_t secondFragmentSize = size - firstFragmentSize;
//         std::vector<StandardMem::Request*> rvec1 = divideAggregatedReq(sstReq, addrStart, firstFragmentSize);
//         std::vector<StandardMem::Request*> rvec2 = divideAggregatedReq(sstReq, cacheLineEndAddr, secondFragmentSize);
//         reqs.insert(reqs.end(), rvec1.begin(), rvec1.end());
//         reqs.insert(reqs.end(), rvec2.begin(), rvec2.end());
//         return reqs;
//     }
//     return divideAggregatedReq(sstReq, addrStart, size);
// }
std::vector<StandardMem::Request*> SimengMemInterface::splitAggregatedRequest(
    SimengMemoryRequest* aggrReq, uint64_t addrStart, uint64_t size)
{
    output->fatal(CALL_INFO, -1,
        "splitAggregatedRequest should not be called with an instance of the base class (SimengMemoryRequest)"
    );
    return std::vector<StandardMem::Request*>();
}

std::vector<StandardMem::Request*> SimengMemInterface::splitAggregatedRequest(
    AggregateWriteRequest* aggrReq, uint64_t addrStart, uint64_t size)
{
    std::vector<StandardMem::Request*> requests;
    uint64_t dataIndex = 0;
    std::vector<uint64_t> req_ids;
    int cacheLinesNeeded = getCacheLinesNeeded(size);
    if (addrStart > aggrReq->target.address) {
        dataIndex += addrStart - aggrReq->target.address;
    }

    for (int x = 0; x < cacheLinesNeeded; x++) {
        uint64_t currReqSize = size;
        if (size > clw) {
            size -= clw;
            currReqSize = clw;
        }
        
        std::vector<uint8_t> payload;
        payload.resize(currReqSize);

        const char* data = aggrReq->data.getAsVector<char>();
        memcpy((void*)&payload[0],  &(data[dataIndex]), currReqSize);
        StandardMem::Request* writeReq = new StandardMem::Write(addrStart, currReqSize, payload); 

        dataIndex += currReqSize;
        addrStart += currReqSize;
        requests.push_back(writeReq);
    }
    return requests;
}

std::vector<StandardMem::Request*> SimengMemInterface::splitAggregatedRequest(
    AggregateReadRequest* aggrReq, uint64_t addrStart, uint64_t size)
{
    std::vector<StandardMem::Request*> requests;
    std::vector<uint64_t> req_ids;
    int cacheLinesNeeded = getCacheLinesNeeded(size);

    for (int x = 0; x < cacheLinesNeeded; x++) {
        uint64_t currReqSize = size;
        if (size > clw) {
            size -= clw;
            currReqSize = clw;
        }

        StandardMem::Request* readReq = new StandardMem::Read(addrStart, currReqSize);

        aggrReq->aggregateCount++;
        addrStart += currReqSize;
        req_ids.push_back(readReq->getID());
        requests.push_back(readReq);
    }
    for (uint64_t id: req_ids) {
        aggregation_map.insert({id, aggrReq});
    }
    req_ids.clear();
    return requests;
}

// std::vector<StandardMem::Request*> SimengMemInterface::divideAggregatedReq(SSTSimengMemReq* sstReq, 
//     uint64_t addrStart, uint64_t size) 
// {
//     std::vector<StandardMem::Request*> requests;
//     uint64_t dataIndex = 0;
//     std::vector<uint64_t> req_ids;
//     int cacheLinesNeeded = size > clw ? (size / clw) + 1 : 1;
//     if (addrStart > sstReq->target.address) {
//         dataIndex += addrStart - sstReq->target.address;
//     }
//     for (int x = 0; x < cacheLinesNeeded; x++) {
//         uint64_t currReqSize = size;
//         if (size > clw) {
//             size -= clw;
//             currReqSize = clw;
//         }
//         StandardMem::Request* req;
//         if (sstReq->req_type == WRITE) {
//             std::vector<uint8_t> payload;
//             payload.resize(currReqSize);
//             const char* data = sstReq->data.getAsVector<char>();
//             memcpy((void*)&payload[0],  &(data[dataIndex]), currReqSize);
//             req = new StandardMem::Write(addrStart, currReqSize, payload); 
//             dataIndex += currReqSize;
//         } else {
//             req = new StandardMem::Read(addrStart, currReqSize);
//         }
//         sstReq->aggregateCount++;
//         req_ids.push_back(req->getID());
//         requests.push_back(req);
//         addrStart += currReqSize;
//     }
//     sstReq->req_ids.insert(sstReq->req_ids.end(), req_ids.begin(), req_ids.end());
//     for (uint64_t id: req_ids) {
//         aggregation_map.insert({id, sstReq});
//     }
//     return requests;
// }

void SimengMemInterface::requestRead(const MemoryAccessTarget& target, uint64_t requestId) {
    uint64_t addrStart = target.address;
    uint64_t size = unsigned(target.size);
    uint64_t addrEnd = addrStart + size;
    
    if (addrEnd > max_addr_memory || unsignedOverflow_(addrStart, size)) {
        completed_read_requests.push_back({target, RegisterValue(), requestId});
        return;
    }

    AggregateReadRequest* aggrReq = new AggregateReadRequest(target, requestId);
    std::vector<StandardMem::Request*> requests = makeSSTRequests<AggregateReadRequest>(aggrReq, addrStart, addrEnd, size);
    for (StandardMem::Request* req : requests) {
        mem->send(req);
    }
}

void SimengMemInterface::requestWrite(const MemoryAccessTarget& target, const RegisterValue& data) {
    uint64_t addrStart = target.address;
    uint64_t size = unsigned(target.size);
    uint64_t addrEnd = addrStart + size;

    AggregateWriteRequest* aggrReq = new AggregateWriteRequest(target, data);
    std::vector<StandardMem::Request*> requests = makeSSTRequests<AggregateWriteRequest>(aggrReq, addrStart, addrEnd, size);
    for (StandardMem::Request* req : requests) {
        mem->send(req);
    }
}

void SimengMemInterface::tick() {
    tickCounter++;
}

void SimengMemInterface::clearCompletedReads() {
    completed_read_requests.clear();
}

bool SimengMemInterface::hasPendingRequests() const {
    return completed_read_requests.size() > 0;
};

const span<MemoryReadResult> SimengMemInterface::getCompletedReads() const {
    return {const_cast<MemoryReadResult*>(completed_read_requests.data()),
        completed_read_requests.size()};
};

void SimengMemInterface::aggregatedReadResponses(AggregateReadRequest* aggrReq) {
    if (aggrReq->aggregateCount != 0) return;
    std::vector<uint8_t> mergedData;
    for (auto itr = aggrReq->response_map.begin(); itr != aggrReq->response_map.end(); itr++)
    {
        mergedData.insert(mergedData.end(), itr->second.begin(), itr->second.end());
        aggregation_map.erase(itr->first);
    }

    // for (uint64_t id: aggrReq->req_ids) {
    //     auto itr = read_response_data.find(id);
    //     if (itr != read_response_data.end()) {
    //         mergedData.insert(mergedData.end(), itr->second.begin(), itr->second.end());
    //     }
    // }

    // Simeng memory is just a big chunch of chars
    const char* char_data = reinterpret_cast<const char*>(&mergedData[0]);
    completed_read_requests.push_back({
        aggrReq->target,
        RegisterValue(char_data, uint16_t(unsigned(aggrReq->target.size))),
        aggrReq->id
    });

    // Erase responses and request entries, this is a part of cleanup
    // for (uint64_t id: aggrReq->req_ids) {
    //     read_response_data.erase(id);
    //     aggregation_map.erase(id);
    // }

    aggrReq->response_map.clear();
    delete aggrReq;
}

void SimengMemInterface::SimengMemHandlers::handle(StandardMem::WriteResp* rsp) {
    // uint64_t id = rsp->getID();
    delete rsp;

    // auto itr = mem_interface.aggregation_map.find(id);
    // if (itr == mem_interface.aggregation_map.end()) return;
    
    // SimengMemInterface::SSTSimengMemReq* aggrReq = itr->second;
    // mem_interface.aggregation_map.erase(id);

    // // delete Aggregated request once all responses have been handled.
    // if (--aggrReq->aggregateCount <= 0) delete aggrReq;
}

void SimengMemInterface::SimengMemHandlers::handle(StandardMem::ReadResp* rsp) {
    uint64_t id = rsp->getID();
    auto data = rsp->data;
    delete rsp;

    auto itr = mem_interface.aggregation_map.find(id);
    if (itr == mem_interface.aggregation_map.end()) return;

    SimengMemInterface::AggregateReadRequest* aggrReq = itr->second;
    aggrReq->response_map.insert({id, data});
    if (--aggrReq->aggregateCount <= 0) {
        mem_interface.aggregatedReadResponses(aggrReq);
    }
}