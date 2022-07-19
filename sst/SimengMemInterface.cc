// #ifndef SIMENG_ENABLE_SST

#include <sst/core/sst_config.h>
#include "SimengMemInterface.hh"

#include <vector>

using namespace SST::Interfaces;
using namespace simeng;

std::vector<StandardMem::Request*> SimengMemInterface::makeSSTRequests(SSTSimengMemReq* sstReq) { 
    // Add logic for unaligned read/write access.

    std::vector<StandardMem::Request*> requests;
    uint64_t addrStart = sstReq->target.address;
    // size * 32/64 (or whatever the ISA specifies)
    uint64_t addrEnd = addrStart + sstReq->target.size;
    uint64_t size = sstReq->target.size;
    uint64_t dataIndex = 0;
    std::vector<uint64_t> req_ids;
    // Error in logic +1 not needed always, only for memory sizes lower than clw
    int cacheLinesNeeded = ((addrEnd - addrStart) / clw) + 1;
    for (int x = 0; x < cacheLinesNeeded; x++) {
        uint64_t currReqSize = size;
        if (size > clw) {
            size -= clw;
            currReqSize = clw;
        }
        StandardMem::Request* req;
        if (sstReq->req_type == WRITE) {
            std::vector<uint8_t> payload;
            // Number of bytes / 8 = payloadSize
            payload.resize(currReqSize);
            const char* data = sstReq->data.getAsVector<char>();
            memcpy((void*)&payload[0],  &(data[dataIndex]), currReqSize);
            req = new StandardMem::Write(addrStart, currReqSize, payload); 
            dataIndex += currReqSize;
        } else {
            req = new StandardMem::Read(addrStart, currReqSize);
        }
        sstReq->aggregateCount++;
        req_ids.push_back(req->getID());
        requests.push_back(req);
        addrStart += currReqSize;
    }
    sstReq->req_ids = req_ids;
    for (uint64_t id: sstReq->req_ids) {
        aggregation_map.insert({id, sstReq});
    }
    return requests;
}

void SimengMemInterface::requestRead(const MemoryAccessTarget& target, uint64_t requestId) {
    SSTSimengMemReq* sstReq = new SSTSimengMemReq(target, requestId);
    std::vector<StandardMem::Request*> requests = makeSSTRequests(sstReq);
    for (StandardMem::Request* req : requests) {
        mem->send(req);
    }
}

void SimengMemInterface::requestWrite(const MemoryAccessTarget& target, const RegisterValue& data) {
    SSTSimengMemReq* sstReq = new SSTSimengMemReq(target, data);
    std::vector<StandardMem::Request*> requests = makeSSTRequests(sstReq);
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

void SimengMemInterface::handleCompletedReadRequest(SSTSimengMemReq* aggrReq) {
    if (aggrReq->aggregateCount != 0) return;
    std::vector<uint8_t> mergedData;
    for (uint64_t id: aggrReq->req_ids) {
        auto itr = read_response_data.find(id);
        if (itr != read_response_data.end()) {
            mergedData.insert(mergedData.end(), itr->second.begin(), itr->second.end());
        }
    }
    // Simeng memory is just a big chunch of chars
    const char* char_data = reinterpret_cast<const char*>(&mergedData[0]);
    completed_read_requests.push_back({
        aggrReq->target,
        RegisterValue(char_data, aggrReq->target.size),
        aggrReq->id
    });
       
    // Erase responses and request entries, this is a part of cleanup
    for (uint64_t id: aggrReq->req_ids) {
        read_response_data.erase(id);
        aggregation_map.erase(id);
    }
    delete aggrReq;
}

void SimengMemInterface::SimengMemHandlers::handle(StandardMem::WriteResp* rsp) {
    uint64_t id = rsp->getID();
    auto itr = memIface.aggregation_map.find(id);
     SimengMemInterface::SSTSimengMemReq* aggrReq;
    if (itr != memIface.aggregation_map.end()) {
        aggrReq = itr->second;
        // Erase entry from aggregation map 
        memIface.aggregation_map.erase(id);
    } 
    if (--aggrReq->aggregateCount <= 0) {
        // delete Aggregated request once all responses have been handled.
        delete aggrReq;
    }
    // Delete WriteResp from SST and SSTSimengMemReq
    delete rsp;
    return;
}

void SimengMemInterface::SimengMemHandlers::handle(StandardMem::ReadResp* rsp) {
    uint64_t id = rsp->getID();
    auto itr = memIface.aggregation_map.find(id);
    SimengMemInterface::SSTSimengMemReq* aggrReq;
    if (itr != memIface.aggregation_map.end()) {
        aggrReq = itr->second;
    } else {
        return;
    }
    if (--aggrReq->aggregateCount <= 0) {
        memIface.handleCompletedReadRequest(aggrReq);
        delete rsp;
        return;
    }
    memIface.read_response_data.insert({id, rsp->data});
    delete rsp;
}

// #endif