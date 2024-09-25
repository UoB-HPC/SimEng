#ifndef _H_SST_PERCEPTRON_FILTERING_PREFETCH
#define _H_SST_PERCEPTRON_FILTERING_PREFETCH

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

class PerceptronFilteringPrefetch : public SST::MemHierarchy::CacheListener {
 public:
  PerceptronFilteringPrefetch(ComponentId_t id, Params& params);
  ~PerceptronFilteringPrefetch();

  void notifyAccess(const CacheListenerNotification& notify);
  void registerResponseCallback(Event::HandlerBase* handler);
  void printStats(Output& out);

  SST_ELI_REGISTER_SUBCOMPONENT_DERIVED(PerceptronFilteringPrefetch, "cassini",
                                        "PerceptronFilteringPrefetch",
                                        SST_ELI_ELEMENT_VERSION(1, 0, 0),
                                        "Perceptron-Based Prefetch Filtering",
                                        SST::MemHierarchy::CacheListener)

  SST_ELI_DOCUMENT_PARAMS(
      //   {"cache_line_size", "Size of the cache line the prefetcher is attached to", "64"},
      //   {"aggressiveness", "Number of consecutive blocks to prefetch", "1"}
  )

  SST_ELI_DOCUMENT_STATISTICS(
      //   {"prefetches_issued", "Number of prefetch requests issued", "prefetches", 1},
      //   {"miss_events_processed", "Number of cache misses received", "misses", 2},
      //   {"hit_events_processed", "Number of cache hits received", "hits", 2}
  )

 private:
  //   std::vector<Event::HandlerBase*> registeredCallbacks;
  //   uint64_t blockSize;
  //   uint64_t aggressiveness;

  //   Statistic<uint64_t>* statPrefetchEventsIssued;
  //   Statistic<uint64_t>* statMissEventsProcessed;
  //   Statistic<uint64_t>* statHitEventsProcessed;
};

}  // namespace Cassini
}  // namespace SST

#endif
