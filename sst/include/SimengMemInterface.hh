#ifdef SIMENG_ENABLE_SST
#include <sst/core/sst_config.h>
#include <sst/core/interfaces/stdMem.h>

#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <set>

#include  "simeng/MemoryInterface.hh"
#include "simeng/span.hh"

using namespace simeng;
using namespace SST::Interfaces;

namespace SST {
    namespace SSTSimeng {
        class SimengMemInterface: public MemoryInterface {
            public:
                SimengMemInterface(StandardMem* mem, uint64_t cl);
                
                void hello();
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
                        SimengMemHandlers(SimengMemInterface& memIface, SST::Output* out):StandardMem::RequestHandler(out), memIface(memIface) {}
                        virtual ~SimengMemHandlers() {}
                        virtual void handle(StandardMem::ReadResp* resp) override;
                        virtual void handle(StandardMem::WriteResp* resp) override;
                        SimengMemInterface& memIface;
                };

                enum MemoryRequestType {
                    READ, WRITE
                };

                struct SSTSimengMemReq {
                    const uint64_t id;
                    const MemoryAccessTarget target;
                    MemoryRequestType req_type;
                    const RegisterValue data;
                    std::vector<uint64_t> req_ids;
                    int aggregateCount;
                    
                    SSTSimengMemReq(): target(MemoryAccessTarget()), data(RegisterValue()), id(0) {}

                    SSTSimengMemReq(const MemoryAccessTarget& target, uint64_t requestId): id(requestId), data(RegisterValue()), target(target) {
                        req_type = READ;
                        aggregateCount =  0;
                    };

                    SSTSimengMemReq(const MemoryAccessTarget& target, const RegisterValue& data): id(0), target(target), data(data) {
                        req_type = WRITE;
                        aggregateCount = 0;
                    };
                };
            private:
                uint64_t tickCounter = 0;
                std::vector<MemoryReadResult> completed_read_requests;
                std::unordered_map<uint64_t, std::vector<uint8_t>> read_response_data;
                std::unordered_multimap<uint64_t, SSTSimengMemReq*> aggregation_map;
                StandardMem* mem;
                uint64_t clw;
                void handleCompletedReadRequest(SSTSimengMemReq* aggrReq);
                std::vector<StandardMem::Request*> makeSSTRequests(SSTSimengMemReq* sstReq);
        };
    };
};
#endif