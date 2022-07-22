
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
                virtual void requestRead(const MemoryAccessTarget& target,
                           uint64_t requestId = 0);
                virtual void requestWrite(const MemoryAccessTarget& target,
                                            const RegisterValue& data);
                virtual const span<MemoryReadResult> getCompletedReads() const;
                virtual void clearCompletedReads();
                virtual bool hasPendingRequests() const;
                virtual void tick();

                class SimengMemHandlers : public StandardMem::RequestHandler {
                    friend class SimengMemInterface;
                    public:
                        SimengMemHandlers(SimengMemInterface& interface, SST::Output* out):StandardMem::RequestHandler(out), mem_interface(interface) {}
                        virtual ~SimengMemHandlers() {}
                        virtual void handle(StandardMem::ReadResp* resp) override;
                        virtual void handle(StandardMem::WriteResp* resp) override;
                        SimengMemInterface& mem_interface;
                };

                struct SimengMemoryRequest {
                    const MemoryAccessTarget target;

                    SimengMemoryRequest(): target(MemoryAccessTarget()) {};
                    SimengMemoryRequest(const MemoryAccessTarget& target): target(target) {};
                };

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



                // struct SSTSimengMemReq {
                //     const uint64_t id;
                //     const MemoryAccessTarget target;
                //     MemoryRequestType req_type;
                //     const RegisterValue data;
                //     std::vector<uint64_t> req_ids;
                //     int aggregateCount;
                    
                //     SSTSimengMemReq(): target(MemoryAccessTarget()), data(RegisterValue()), id(0) {}

                //     SSTSimengMemReq(const MemoryAccessTarget& target, uint64_t requestId): id(requestId), data(RegisterValue()), target(target) {
                //         req_type = READ;
                //         aggregateCount =  0;
                //     };

                //     SSTSimengMemReq(const MemoryAccessTarget& target, const RegisterValue& data): id(0), target(target), data(data) {
                //         req_type = WRITE;
                //         aggregateCount = 0;
                //     };
                // };
                
            private:
                SST::Output* output;
                StandardMem* mem;

                uint64_t tickCounter = 0;
                uint64_t clw;
                uint64_t max_addr_memory;
                
                std::vector<MemoryReadResult> completed_read_requests;
                std::unordered_map<uint64_t, AggregateReadRequest*> aggregation_map;

                template<typename T, typename std::enable_if<std::is_base_of<SimengMemoryRequest, T>::value>::type* = nullptr>
                std::vector<StandardMem::Request*> makeSSTRequests(T* aggrReq,  uint64_t addrStart, uint64_t addrEnd, uint64_t size);
                void aggregatedReadResponses(AggregateReadRequest* aggrReq);


                // std::vector<StandardMem::Request*> makeSSTRequests(SSTSimengMemReq* sstReq);

                std::vector<StandardMem::Request*> splitAggregatedRequest(AggregateWriteRequest* aggrReq, uint64_t addrStart, uint64_t size);
                std::vector<StandardMem::Request*> splitAggregatedRequest(AggregateReadRequest* aggrReq, uint64_t addrStart, uint64_t size);
                std::vector<StandardMem::Request*> splitAggregatedRequest(SimengMemoryRequest* aggrReq, uint64_t addrStart, uint64_t size);

                // std::vector<StandardMem::Write*> splitWriteRequest(SSTSimengMemReq* sstReq, uint64_t addrStart, uint64_t size);
                // std::vector<StandardMem::Read*> splitReadRequest(SSTSimengMemReq* sstReq, uint64_t addrStart, uint64_t size);
                int getCacheLinesNeeded(int size) {
                    if (size < clw) return 1;
                    if (size % clw == 0) return size / clw;
                    return (size / clw) + 1;
                }

                bool unsignedOverflow_(uint64_t a, uint64_t b) const {
                    return (a + b) < a || (a + b) < b;
                };
                bool requestSpansMultipleCacheLines(uint64_t addrStart, uint64_t addrEnd) {
                    return (addrStart / clw) < (addrEnd / clw) && (addrEnd % clw != 0);
                };
                uint64_t nearestCacheLineEnd(uint64_t addrStart) {
                    return (addrStart / clw) + 1;
                };
        };
    };
};