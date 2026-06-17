#ifndef _H_SST_LISTENER
#define _H_SST_LISTENER

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

namespace SST {
namespace SSTSimEng {

class Listener : public SST::MemHierarchy::CacheListener {
 public:
  Listener(ComponentId_t id, Params& params);
  ~Listener();

  void notifyAccess(const MemHierarchy::CacheListenerNotification& notify);
  void printStats(Output& UNUSED(out)) {}

  SST_ELI_REGISTER_SUBCOMPONENT(Listener, "sstsimeng", "Listener",
                                SST_ELI_ELEMENT_VERSION(1, 0, 0),
                                "Cache listener",
                                SST::MemHierarchy::CacheListener)

  SST_ELI_DOCUMENT_PARAMS({"verbose", "Controls the verbosity of the component",
                           "0"})

  SST_ELI_DOCUMENT_STATISTICS()

  SST_ELI_DOCUMENT_PORTS()

 private:
  Output* output;
  uint32_t verbosity;
};

}  // namespace SSTSimEng

}  // namespace SST
#endif
