#ifndef _H_SST_L1L2_PRFETCHER
#define _H_SST_L1L2_PRFETCHER

#include <sst/core/component.h>
#include <sst/core/eli/elementinfo.h>
#include <sst/core/event.h>
#include <sst/core/interfaces/stdMem.h>
#include <sst/core/link.h>
#include <sst/core/sst_types.h>
#include <sst/core/timeConverter.h>
#include <sst/elements/memHierarchy/cacheListener.h>
#include <sst/elements/memHierarchy/memEvent.h>

#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace SST;
using namespace SST::MemHierarchy;

namespace SST {

namespace SSTSimEng {

class ControlEvent : public SST::Event {
 public:
  ControlEvent(bool clearPFQ) : SST::Event(), clearPFQ_(clearPFQ) {}

  bool shouldClearPFQ() const { return clearPFQ_; }

 private:
  bool clearPFQ_;

  ControlEvent() {}  // For serialization only

 public:
  void serialize_order(SST::Core::Serialization::serializer& ser) override {
    Event::serialize_order(ser);
    ser & clearPFQ_;
  }

  ImplementSerializable(ControlEvent);
};

struct pfqEntry {
  Addr pAddr = 0;
  Addr vAddr = 0;

  std::pair<Addr, Addr> directionalPredcitedAddresses = {0, 0};

  Addr predictedAddress = 0;

  Addr l1Distance = 0;
  Addr l2Distance = 0;

  Addr lastPrefetch = 0;

  Addr offset = 0;

  bool comparing = true;
  bool ascending = false;
  bool atMaxL1Distance = false;
  bool atMaxL2Distance = false;

  uint16_t hitCount = 0;
  bool l2Paused = false;

  int64_t lruRank = -1;
};

class L1L2Prefetcher : public SST::Component {
 public:
  L1L2Prefetcher(SST::ComponentId_t id, SST::Params& params);
  ~L1L2Prefetcher();

  /**
   * This is the init lifecycle method present in all SST::Components.
   * Here it is overriden to include init calls to all other SST::Components
   * which are contained inside SimOSWrapper. It is neccessary to call all
   * lifecycle methods for SST::Component(s).
   */
  void init(unsigned int phase);

  /**
   * This is the setup lifecycle method present in all SST::Components.
   * Here it is overriden to include setup calls to all other SST::Components
   * which are contained inside SimOSWrapper. It is neccessary to call all
   * lifecycle methods for SST::Component(s).
   */
  void setup();

  /**
   * This is the finish lifecycle method present in all SST::Components.
   * Here it is overriden to finish statistics about the SimEng simulation.
   */
  void finish();

  /**
   * The clockTick is a method present in all SST::Components. This fuction
   * is called everytime the SST clock ticks. The current clock cycle is passed
   * as an argument by SST. The SimEng core ticks in this method.
   */
  bool clockTick(SST::Cycle_t currentCycle);

  /**
   * SST supplied MACRO used to register custom SST:Components with
   * the SST Core.
   */
  SST_ELI_REGISTER_COMPONENT(
      L1L2Prefetcher, "sstsimeng", "l1l2prefetcher",
      SST_ELI_ELEMENT_VERSION(1, 0, 0),
      "Prefetcher that sends requests to multiple caches simultaneously",
      COMPONENT_CATEGORY_MEMORY)

  /**
   * SST supplied MACRO used to document all parameters needed by
   * a custom SST:Component.
   */
  SST_ELI_DOCUMENT_PARAMS(
      {"verbose", "Controls the verbosity of the SSTSimEng component", "0"},
      {"cache_line_size",
       "Size of the cache line the prefetcher is attached to", "256"},
      {"pfq_size", "Size of the PFQ table", "16"})

  SST_ELI_DOCUMENT_PORTS({"from_prefetch_link_%(port)d",
                          "Link to a prefetcher shim",
                          {"sstsimeng.NotifyEvent", "sstsimeng.PrefetchEvent"}},
                         {"from_cache_link_%(port)d",
                          "Link to a cache listener",
                          {"sstsimeng.CacheListenerEvent"}},
                         {"from_core_link",
                          "Link to a processor component",
                          {"sstsimeng.ControlEvent",
                           "sstsimeng.PrefetchEvent"}})

  SST_ELI_DOCUMENT_STATISTICS(
      {"l1_prefetches_issued", "Number of l1 prefetch requests issued",
       "prefetches", 1},
      {"l2_prefetches_issued", "Number of l2 prefetch requests issued",
       "prefetches", 1},
      {"pfq_evictions", "Number of entry evictions from the PFQ.", "prefetches",
       1},
      {"cancelled_by_history", "Number of entry evictions from the PFQ.",
       "prefetches", 1},
      {"pfq_clears", "Number of PFQ clear due to TLB miss.", "prefetches", 1},
      {"pfq_entry_reset", "Number of entry resets from the PFQ.", "prefetches",
       1},
      {"pfq_entry_restart", "Number of entry restarts from the PFQ.",
       "prefetches", 1},
      {"pfq_entry_pause", "Number of entry pauses from the PFQ.", "prefetches",
       1})

 private:
  Output* output;
  uint32_t verbosity;
  Addr clSize;
  size_t pfqSize;
  uint8_t numFetchAhead;
  Addr initialDistance;
  Addr maxL1Distance;
  Addr maxL2Distance;
  std::deque<pfqEntry>* pfq;
  std::deque<Addr>* addrHistory = {};
  size_t addrHistoryLength;
  uint64_t contL2Hits = 0;
  bool pauseL2 = false;

  /**
   * SST clock for the component register with the custom component
   * during instantiation using the registerClock method provided
   * by SST.
   */
  TimeConverter* clock_;

  void handleFromPrefetchEvent(Event* ev);
  void handleFromCacheEvent(Event* ev);
  void handleFromProcessorEvent(Event* ev);
  void processShimEvent(Addr vaddr, Addr paddr, Addr insnPtr, bool wasMiss,
                        bool fromL2);
  void generatePrefetches(std::deque<pfqEntry>::iterator itr);
  void sendL1Prefetch(Addr pAddr, Addr vAddr, size_t size);
  void sendL2Prefetch(Addr pAddr, Addr vAddr, size_t size);

  void incLRURankings();
  void trimPFQ();

  std::vector<Link*> fromPRF_links;
  std::vector<Link*> fromCache_links;
  Link* fromCore_link;

  std::unordered_map<uint32_t, uint32_t> portIdMappings;

  std::deque<Addr> pageHistory = {};

  Statistic<uint64_t>* statL1PrefetchEventsIssued;
  Statistic<uint64_t>* statL2PrefetchEventsIssued;
  Statistic<uint64_t>* statPFQEvictions;
  Statistic<uint64_t>* statHistCancelled;
  Statistic<uint64_t>* statPRFClears;
  Statistic<uint64_t>* statPFQResets;
  Statistic<uint64_t>* statPFQRestarts;
  Statistic<uint64_t>* statPFQPauses;
};

}  // namespace SSTSimEng

}  // namespace SST
#endif
