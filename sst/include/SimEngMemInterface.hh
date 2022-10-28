// clang-format off
// DO NOT MOVE FROM TOP OF FILE - https://github.com/sstsimulator/sst-core/issues/865
#include <sst/core/sst_config.h>
// clang-format on
#include <sst/core/eli/elementinfo.h>
#include <sst/core/interfaces/stdMem.h>

#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <type_traits>
#include <vector>

#include "simeng/MemoryInterface.hh"
#include "simeng/span.hh"

using namespace simeng;
using namespace SST::Interfaces;

namespace SST {

namespace SSTSimEng {

/** A memory interface used by SimEng to communicate with SST's memory model. */
class SimEngMemInterface : public MemoryInterface {
 public:
  SimEngMemInterface(StandardMem* mem, uint64_t cl, uint64_t max_addr,
                     bool debug);
  /** Send SimEng's processImage to SST memory backend during `init` lifecycle
   * phase of SST. */
  void sendProcessImageToSST(char* image, uint64_t size);

  /**
   * Construct an AggregatedReadRequest and use it to generate
   * SST::StandardMem::Read request(s). These request(s) are then sent to SST.
   */
  void requestRead(const MemoryAccessTarget& target, uint64_t requestId = 0);

  /**
   * Construct an AggregatedWriteRequest and use it to generate
   * SST::StandardMem::Write request(s). These request(s) are then sent to SST.
   */
  void requestWrite(const MemoryAccessTarget& target,
                    const RegisterValue& data);

  /** Retrieve all completed read requests. */
  const span<MemoryReadResult> getCompletedReads() const;

  /** Clear the completed reads. */
  void clearCompletedReads();

  /** Returns true if there are any oustanding memory requests. */
  bool hasPendingRequests() const;

  /**
   * Tick the memory interface to process SimEng related tasks. Since all memory
   * operations are handled by SST this method is only used increment
   * `tickCounter`.
   */
  void tick();

  /**
   * An instance of `SimEngMemHandlers` is registered to an instance of
   * SST::StandardMem and is used to handle Read and Write response. The same
   * instance of SST::StandardMem is passed to `SimEngMemHandlers` to access
   * private variables needed to handle responses correctly. Defining
   * `SimEngMemHandlers` as a friend class gives it access to all private
   * variables defined in `SimEngMemInterface`.
   */
  class SimEngMemHandlers : public StandardMem::RequestHandler {
    friend class SimEngMemInterface;

   public:
    SimEngMemHandlers(SimEngMemInterface& interface, SST::Output* out)
        : StandardMem::RequestHandler(out), memInterface_(interface) {}

    ~SimEngMemHandlers() {}

    /**
     * Overloaded instance of handle method to handle read request responses
     * overriden to aggregate responses and send them back to SimEng.
     */
    void handle(StandardMem::ReadResp* resp) override;

    /**
     * Overloaded instance of handle method to handle write request responses
     * overriden to delete the incoming responses as SimEng does not have any
     * use for it.
     */
    void handle(StandardMem::WriteResp* resp) override;

    /** Reference to SimEngMemInterface used for interfacing with SST. */
    SimEngMemInterface& memInterface_;
  };

  /**
   * This struct represents a memory request from SimEng. It is used as base
   * struct for AggregateWriteRequest and AggregateReadRequest.
   */
  struct SimEngMemoryRequest {
    /** MemoryAccessTarget from SimEng memory instruction. */
    const MemoryAccessTarget target;

    SimEngMemoryRequest() : target(MemoryAccessTarget()){};
    SimEngMemoryRequest(const MemoryAccessTarget& target) : target(target){};
  };

  /**
   * Struct AggregatedWriteRequest is used to store information regarding
   * the multiple SST::StandardMem::Request (Write) a memory request from SimEng
   * is split into. This happens if its size is greater than the cache line
   * width. These structs are also used to represent SimEng write requests which
   * aren't split for ease of implementation.
   */
  struct AggregateWriteRequest : public SimEngMemoryRequest {
    /** RegisterValue (write data) from SimEng memory instruction. */
    const RegisterValue data;

    AggregateWriteRequest() : SimEngMemoryRequest(), data(RegisterValue()){};
    AggregateWriteRequest(const MemoryAccessTarget& target,
                          const RegisterValue& data)
        : SimEngMemoryRequest(target), data(data){};
  };

  /**
   * Struct AggregatedReadRequest is used to store information regarding
   * the multiple SST::StandardMem::Request (Read) a memory request from SimEng
   * is split into. This happens if its size is greater than the cache line
   * width. These structs are also used to represent SimEng read requests which
   * aren't split for ease of implementation.
   */
  struct AggregateReadRequest : public SimEngMemoryRequest {
    /** Unique identifier of each AggregatedReadRequest copied from SimEng read
     * request. */
    const uint64_t id_;
    /**
     * This response map is used to store all responses of SST read request,
     * this aggregated read request was split into. An ordered map is used to
     * record and maintain the order to split responses.
     */
    std::map<uint64_t, std::vector<uint8_t>> responseMap_;
    /** Total number of SST request the SimEng memory request was split into. */
    int aggregateCount_ = 0;

    AggregateReadRequest() : SimEngMemoryRequest(), id_(0){};
    AggregateReadRequest(const MemoryAccessTarget& target, const uint64_t id)
        : SimEngMemoryRequest(target), id_(id) {}
  };

 private:
  /**
   * SST::Interfaces::StandardMem interface responsible for converting
   * SST::StandardMem::Request(s) into SST memory events to be passed
   * down the memory heirarchy.
   */
  StandardMem* sstMem_;

  /** Counter for clock ticks. */
  uint64_t tickCounter_ = 0;

  /** The cache line width specified by SST config.py. */
  uint64_t cacheLineWidth_;

  /** Maximum address available for memory purposes. */
  uint64_t maxAddrMemory_;

  /** A vector containing all completed read requests. */
  std::vector<MemoryReadResult> completedReadRequests_;

  /**
   * This map is used to store unique ids of SST::StandardMem::Read requests and
   * their corresponding AggregateReadRequest as key-value pairs (In some cases
   * SimEngMemoryRequest has to be divided into multiple
   * SST::StandardMem::Request(s) if the SimEngMemoryRequest size > cache line
   * width). That is, the unique ids of multiple read requests and their
   * corresponding aggregatedReadRequest are stored in a many-to-one fashion.
   * An entry from this map is removed when a response for
   * SST::StandardMem::Read request is recieved and recorded. The response holds
   * the same unique id as the request. No such key-value pairs are maintained
   * for AggregatedWriteRequest(s) even if they are split into multiple
   * SST::StandardMem::Write requests as their responses do not need to be
   * aggregated.
   */
  std::unordered_map<uint64_t, AggregateReadRequest*> aggregationMap_;

  /** This method only accepts structs derived from the SimEngMemoryRequest
   * struct as the value for aggrReq. */
  template <typename T, typename std::enable_if<std::is_base_of<
                            SimEngMemoryRequest, T>::value>::type* = nullptr>
  std::vector<StandardMem::Request*> makeSSTRequests(T* aggrReq,
                                                     uint64_t addrStart,
                                                     uint64_t addrEnd,
                                                     uint64_t size);

  /** The overloaded instance of splitAggregatedRequest is used to split an
   * AggregatedWriteRequest into multiple SST write requests.
   */
  std::vector<StandardMem::Request*> splitAggregatedRequest(
      AggregateWriteRequest* aggrReq, uint64_t addrStart, uint64_t size);

  /** The overloaded instance of splitAggregatedRequest is used to split an
   * AggregatedReadRequest into multiple SST read requests.
   */
  std::vector<StandardMem::Request*> splitAggregatedRequest(
      AggregateReadRequest* aggrReq, uint64_t addrStart, uint64_t size);

  /** This method is used to aggregate responses from multiple read request into
   * one response. */
  void aggregatedReadResponses(AggregateReadRequest* aggrReq);

  /** Get the number of cache lines needed incase the size of a memory request
   * is larger than cache line width.
   */
  int getNumCacheLinesNeeded(uint64_t size) const;
  bool unsignedOverflow_(uint64_t a, uint64_t b) const;

  /**
   * Check to see if a request spans multiple cache lines. This method
   * identifies the case when the start and end address of the request do not
   * lie on the same cache line. This can even happen if the size of the memory
   * request is less than cache line width.
   */
  bool requestSpansMultipleCacheLines(uint64_t addrStart,
                                      uint64_t addrEnd) const;

  /**
   * This method is used to find the end address of the cache line specified by
   * the start address of the memory request. This method is used when a memory
   * request spans multiple cache lines.
   */
  uint64_t nearestCacheLineEnd(uint64_t addrStart) const;

  /** Variable to enable parseable print debug statements in test mode. */
  bool debug_ = false;
};

};  // namespace SSTSimEng

};  // namespace SST
