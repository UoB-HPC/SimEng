#ifndef _H_SST_OFFSET_PREFETCH
#define _H_SST_OFFSET_PREFETCH

#include <sst/core/component.h>
#include <sst/core/event.h>
#include <sst/core/link.h>
#include <sst/core/sst_types.h>
#include <sst/core/timeConverter.h>
#include <sst/elements/memHierarchy/cacheListener.h>
#include <sst/elements/memHierarchy/memEvent.h>

#include <vector>

using namespace SST;
using namespace SST::MemHierarchy;
using namespace std;

namespace SST {
namespace Cassini {

class OffsetPrefetch : public SST::MemHierarchy::CacheListener {
 public:
  OffsetPrefetch(ComponentId_t id, Params& params);
  ~OffsetPrefetch();

  void notifyAccess(const CacheListenerNotification& notify);
  void registerResponseCallback(Event::HandlerBase* handler);
  void printStats(Output& out);

  SST_ELI_REGISTER_SUBCOMPONENT_DERIVED(OffsetPrefetch, "cassini",
                                        "OffsetPrefetch",
                                        SST_ELI_ELEMENT_VERSION(1, 0, 0),
                                        "Offset Prefetcher",
                                        SST::MemHierarchy::CacheListener)

  SST_ELI_DOCUMENT_PARAMS(
      {"cache_line_size",
       "Size of the cache line the prefetcher is attached to", "64"},
      {"offset",
       "Offset of which cache-line to prefetch. I.e. an access to line X with "
       "offset D would prefetch line X+D.",
       "1"})

  SST_ELI_DOCUMENT_STATISTICS(
      {"prefetches_issued", "Number of prefetch requests issued", "prefetches",
       1},
      {"miss_events_processed", "Number of cache misses received", "misses", 2},
      {"hit_events_processed", "Number of cache hits received", "hits", 2})

 private:
  std::vector<Event::HandlerBase*> registeredCallbacks;
  uint64_t blockSize;
  uint64_t offset;

  Statistic<uint64_t>* statPrefetchEventsIssued;
  Statistic<uint64_t>* statMissEventsProcessed;
  Statistic<uint64_t>* statHitEventsProcessed;
};

}  // namespace Cassini
}  // namespace SST

#endif
