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

#include "simeng/memory/Mem.hh"
#include "simeng/span.hh"

using namespace simeng;
using namespace SST::Interfaces;

namespace SST {

namespace SSTSimEng {

/** A memory interface used by SimEng to communicate with SST's memory model. */
class SimEngMemInterface : public simeng::memory::Mem {
 public:
  SimEngMemInterface(StandardMem* dataMem, StandardMem* instrMem, uint64_t cl,
                     uint64_t max_addr, bool debug);

  /** This method requests access to memory for both read and write requests. */
  void requestAccess(std::unique_ptr<simeng::memory::MemPacket>& pkt) override;

  /** This method returns the size of memory. */
  size_t getMemorySize() override;

  /** This method writes data to memory without incurring any latency.  */
  void sendUntimedData(std::vector<char> data, uint64_t addr,
                       size_t size) override;

  /** This method reads data from memory without incurring any latency. */
  std::vector<char> getUntimedData(uint64_t paddr, size_t size) override;

  void handleIgnoredRequest(
      std::unique_ptr<simeng::memory::MemPacket>& pkt) override;

  /** Function used to initialise a Port used for bidirection communication. */
  std::shared_ptr<Port<std::unique_ptr<simeng::memory::MemPacket>>>
  initMemPort() override;

  std::shared_ptr<Port<std::unique_ptr<simeng::memory::MemPacket>>>
  initSystemPort() override;

  /**
   * Tick the memory interface to process SimEng related tasks.
   */
  void tick() override;

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
    const uint64_t id_;
    std::unique_ptr<simeng::memory::MemPacket> pkt_;
    /** Total number of SST request the SimEng memory request was split into. */
    int aggregateCount_ = 0;

    SimEngMemoryRequest() : id_(0){};
    SimEngMemoryRequest(std::unique_ptr<simeng::memory::MemPacket>& pkt)
        : id_(pkt->id_), pkt_(std::move(pkt)){};
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
    const simeng::RegisterValue data_;

    AggregateWriteRequest() : SimEngMemoryRequest(), data_(RegisterValue()){};
    AggregateWriteRequest(std::unique_ptr<simeng::memory::MemPacket>& pkt)
        : SimEngMemoryRequest(pkt),
          data_(RegisterValue(pkt_->payload().data(), pkt_->size_)){};
  };

  /**
   * Struct AggregatedReadRequest is used to store information regarding
   * the multiple SST::StandardMem::Request (Read) a memory request from SimEng
   * is split into. This happens if its size is greater than the cache line
   * width. These structs are also used to represent SimEng read requests which
   * aren't split for ease of implementation.
   */
  struct AggregateReadRequest : public SimEngMemoryRequest {
    /**
     * This response map is used to store all responses of SST read request,
     * this aggregated read request was split into. An ordered map is used to
     * record and maintain the order to split responses.
     */
    std::map<uint64_t, std::vector<uint8_t>> responseMap_;

    AggregateReadRequest() : SimEngMemoryRequest(){};
    AggregateReadRequest(std::unique_ptr<simeng::memory::MemPacket>& pkt)
        : SimEngMemoryRequest(pkt) {}
  };

 private:
  /**
   * Construct an AggregatedReadRequest and use it to generate
   * SST::StandardMem::Read request(s). These request(s) are then sent to SST.
   */
  void handleReadRequest(std::unique_ptr<simeng::memory::MemPacket>& req);

  /**
   * Construct an AggregatedWriteRequest and use it to generate
   * SST::StandardMem::Write request(s). These request(s) are then sent to SST.
   */
  void handleWriteRequest(std::unique_ptr<simeng::memory::MemPacket>& req);

  /** This method only accepts structs derived from the SimEngMemoryRequest
   * struct as the value for aggrReq. */
  template <typename T, typename std::enable_if<std::is_base_of<
                            SimEngMemoryRequest, T>::value>::type* = nullptr>
  std::vector<StandardMem::Request*> makeSSTRequests(T* aggrReq,
                                                     uint64_t pAddrStart,
                                                     uint64_t pAddrEnd,
                                                     uint64_t vAddrStart,
                                                     uint64_t size);

  /** The overloaded instance of splitAggregatedRequest is used to split an
   * AggregatedWriteRequest into multiple SST write requests.
   */
  std::vector<StandardMem::Request*> splitAggregatedRequest(
      AggregateWriteRequest* aggrReq, uint64_t pAddrStart, uint64_t vAddrStart,
      uint64_t size);

  /** The overloaded instance of splitAggregatedRequest is used to split an
   * AggregatedReadRequest into multiple SST read requests.
   */
  std::vector<StandardMem::Request*> splitAggregatedRequest(
      AggregateReadRequest* aggrReq, uint64_t pAddrStart, uint64_t vAddrStart,
      uint64_t size);

  /** This method is used to aggregate responses from multiple read request into
   * one response. */
  void aggregatedReadResponses(AggregateReadRequest* aggrReq);

  void aggregatedWriteResponses(AggregateWriteRequest* aggrReq);

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

  /**
   * SST::Interfaces::StandardMem interface responsible for converting
   * SST::StandardMem::Request(s) into SST memory events to be passed
   * down the memory heirarchy.
   */
  StandardMem* dataMem_;

  /**
   * SST::Interfaces::StandardMem interface responsible for converting
   * SST::StandardMem::Request(s) into SST memory events to be passed
   * down the memory heirarchy.
   */
  StandardMem* instrMem_;

  /** Port used for communication with other classes. */
  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      memPort_ = nullptr;

  std::shared_ptr<simeng::Port<std::unique_ptr<simeng::memory::MemPacket>>>
      sysPort_ = nullptr;

  /** Counter for clock ticks. */
  uint64_t tickCounter_ = 0;

  /** The cache line width specified by SST config.py. */
  uint64_t cacheLineWidth_;

  /** Maximum address available for memory purposes. */
  uint64_t maxAddrMemory_;

  /**
   * This map is used to store unique ids of SST::StandardMem::Read requests and
   * their corresponding AggregateReadRequest as key-value pairs (In some cases
   * SimEngMemoryRequest has to be divided into multiple
   * SST::StandardMem::Request(s) if the SimEngMemoryRequest size > cache line
   * width). That is, the unique ids of multiple read requests and their
   * corresponding aggregatedReadRequest are stored in a many-to-one fashion.
   * An entry from this map is removed when a response for
   * SST::StandardMem::Read request is received and recorded. The response holds
   * the same unique id as the request. No such key-value pairs are maintained
   * for AggregatedWriteRequest(s) even if they are split into multiple
   * SST::StandardMem::Write requests as their responses do not need to be
   * aggregated.
   */
  std::unordered_map<uint64_t, SimEngMemoryRequest*> aggregationMap_;

  /** Variable to enable parseable print debug statements in test mode. */
  bool debug_ = false;
};

};  // namespace SSTSimEng

};  // namespace SST
