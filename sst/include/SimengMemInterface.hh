
#include <sst/core/sst_config.h>
#include <sst/core/interfaces/stdMem.h>
#include <sst/core/eli/elementinfo.h>

#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <set>
#include <type_traits>

#include  "simeng/MemoryInterface.hh"
#include "simeng/span.hh"

using namespace simeng;
using namespace SST::Interfaces;

namespace SST {

namespace SSTSimeng {

class SimengMemInterface: public MemoryInterface {
    public:
        SimengMemInterface(StandardMem* mem, uint64_t cl, uint64_t max_addr, SST::Output* out);
        void sendProcessImageToSST(const span<char> image);
        void requestRead(const MemoryAccessTarget& target,
                    uint64_t requestId = 0);
        void requestWrite(const MemoryAccessTarget& target,
                                    const RegisterValue& data);
        const span<MemoryReadResult> getCompletedReads() const;
        void clearCompletedReads();
        bool hasPendingRequests() const;
        void tick();

        
        class SimengMemHandlers : public StandardMem::RequestHandler {
            friend class SimengMemInterface;
            public:
                SimengMemHandlers(SimengMemInterface& interface, SST::Output* out):StandardMem::RequestHandler(out), mem_interface(interface) {}
                ~SimengMemHandlers() {}
                void handle(StandardMem::ReadResp* resp) override;
                void handle(StandardMem::WriteResp* resp) override;
                SimengMemInterface& mem_interface;
        };

        // This struct represents a memory request from SimEng, It is used as base struct for
        // AggregateWriteRequest and AggregateReadRequest.
        struct SimengMemoryRequest {
            const MemoryAccessTarget target;

            SimengMemoryRequest(): target(MemoryAccessTarget()) {};
            SimengMemoryRequest(const MemoryAccessTarget& target): target(target) {};
        };

        /*
            Structs AggregatedWriteRequest and AggregatedReadRequest are used to store
            information regarding the multiple SST::StandardMem::Request (Read or Write) a memory
            request from SimEng is split into if its size is greater than the cache line width.
            These structs are also used to represent SimEng requests which aren't split for ease of 
            implementation.
        */
        struct AggregateWriteRequest: public SimengMemoryRequest {
            const RegisterValue data;

            AggregateWriteRequest(): SimengMemoryRequest(), data(RegisterValue()) {};
            AggregateWriteRequest(const MemoryAccessTarget& target, const RegisterValue& data):
                SimengMemoryRequest(target), data(data) {};
        };

        struct AggregateReadRequest: public SimengMemoryRequest {
            const uint64_t id;
            std::map<uint64_t, std::vector<uint8_t>> response_map;
            int aggregateCount = 0;

            AggregateReadRequest(): SimengMemoryRequest(), id(0) {};
            AggregateReadRequest(const MemoryAccessTarget& target, const uint64_t id):
                SimengMemoryRequest(target), id(id) {}
        };
        
    private:
        SST::Output* output;
        StandardMem* mem;

        uint64_t tickCounter = 0;
        uint64_t clw;
        uint64_t max_addr_memory;
        
        std::vector<MemoryReadResult> completed_read_requests;
        /*
            This map is used to store unique ids of SST::StandardMem:Read requests and their corresponding
            AggregatedReadRequest as key-value pairs (In some cases SimengMemoryRequest has to be divided
            into multiple SST::StandardMem:Request(s) if the SimengMemoryRequest size > cache line width).
            i.e the unique ids of multiple read requests and their correspong aggregatedReadRequest are stored 
            in a many-to-one fashion. An entry from this map is removed when a response for 
            SST::StandardMem::Read request is recieved and recorded. The response holds the same unique id as
            the request.
            No such key-value pairs are maintained for AggregatedWriteRequest(s) even if they are split into multiple
            SST::StandardMem::Write requests as their responses do not need to be aggregated.
        */
        std::unordered_map<uint64_t, AggregateReadRequest*> aggregation_map;

        // This method only accepts structs derived from the SimengMemoryRequest struct as the value for aggrReq.
        template<typename T, typename std::enable_if<std::is_base_of<SimengMemoryRequest, T>::value>::type* = nullptr>
        std::vector<StandardMem::Request*> makeSSTRequests(T* aggrReq,  uint64_t addrStart, uint64_t addrEnd, uint64_t size);
        /*
            These overloaded methods handle AggregatedWriteRequest, AggregatedReadRequest and SimengMemoryRequest
            as values for aggrReq. Any struct dervied from SimengMemoryRequest will require an overloaded definition
            and implementation. Dervided structs with no corresponding overloaded method will be passed to
            splitAggregatedRequest(SimengMemoryRequest* aggrReq, ....) causing an error.
            Any instantiations of base struct (SimengMemoryRequest) passed to splitAggregatedRequest will also cause errors.
        */
        std::vector<StandardMem::Request*> splitAggregatedRequest(AggregateWriteRequest* aggrReq, uint64_t addrStart, uint64_t size);
        std::vector<StandardMem::Request*> splitAggregatedRequest(AggregateReadRequest* aggrReq, uint64_t addrStart, uint64_t size);
        std::vector<StandardMem::Request*> splitAggregatedRequest(SimengMemoryRequest* aggrReq, uint64_t addrStart, uint64_t size);

        void aggregatedReadResponses(AggregateReadRequest* aggrReq);
        int getCacheLinesNeeded(int size);
        bool unsignedOverflow_(uint64_t a, uint64_t b) const;
        bool requestSpansMultipleCacheLines(uint64_t addrStart, uint64_t addrEnd);
        uint64_t nearestCacheLineEnd(uint64_t addrStart);
};

}; // namespace SSTSimeng

}; // namespace SST
