#ifndef _H_SST_PREFETCHER_SHIM
#define _H_SST_PREFETCHER_SHIM

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

class NotifyEvent : public SST::Event {
 public:
  NotifyEvent(const uint32_t reqSize, const Addr tAddr, const Addr pAddr,
              const Addr vAddr, const Addr iPtr, NotifyAccessType accessT,
              NotifyResultType resultT, uint32_t sId, bool fromL2)
      : SST::Event(),
        size(reqSize),
        targAddr(tAddr),
        physAddr(pAddr),
        virtAddr(vAddr),
        instPtr(iPtr),
        access(accessT),
        result(resultT),
        srcId(sId),
        isL2(fromL2) {}

  uint32_t getSize() const { return size; }
  Addr getTargetAddress() const { return targAddr; }
  Addr getPhysicalAddress() const { return physAddr; }
  Addr getVirtualAddress() const { return virtAddr; }
  Addr getInstructionPointer() const { return instPtr; }
  NotifyAccessType getAccessType() const { return access; }
  NotifyResultType getResultType() const { return result; }
  uint32_t getSrcId() const { return srcId; }
  bool getIsL2() const { return isL2; }

 private:
  uint32_t size;
  Addr targAddr;
  Addr physAddr;
  Addr virtAddr;
  Addr instPtr;
  NotifyAccessType access;
  NotifyResultType result;
  uint32_t srcId;
  bool isL2;

  NotifyEvent() {}  // For serialization only

 public:
  void serialize_order(SST::Core::Serialization::serializer& ser) override {
    Event::serialize_order(ser);
    ser & size;
    ser & targAddr;
    ser & physAddr;
    ser & virtAddr;
    ser & instPtr;
    ser & access;
    ser & result;
    ser & srcId;
    ser & isL2;
  }

  ImplementSerializable(NotifyEvent);
};

class PrefetchEvent : public SST::Event {
 public:
  PrefetchEvent(const uint32_t reqSize, const Addr paddr, const Addr vaddr)
      : SST::Event(), size(reqSize), pAddr(paddr), vAddr(vaddr) {}

  uint32_t getSize() const { return size; }
  Addr getPAddr() const { return pAddr; }
  Addr getVAddr() const { return vAddr; }

 private:
  uint32_t size;
  Addr pAddr;
  Addr vAddr;

  PrefetchEvent() {}  // For serialization only

 public:
  void serialize_order(SST::Core::Serialization::serializer& ser) override {
    Event::serialize_order(ser);
    ser & size;
    ser & pAddr;
    ser & vAddr;
  }

  ImplementSerializable(PrefetchEvent);
};

class PrefetcherShim : public SST::MemHierarchy::CacheListener {
 public:
  PrefetcherShim(ComponentId_t id, Params& params);
  ~PrefetcherShim();

  void notifyAccess(const CacheListenerNotification& notify);
  void registerResponseCallback(Event::HandlerBase* handler);
  void printStats(Output& out);

  SST_ELI_REGISTER_SUBCOMPONENT(PrefetcherShim, "sstsimeng", "PrefetcherShim",
                                SST_ELI_ELEMENT_VERSION(1, 0, 0),
                                "Prefetcher Shim that forwards cache events",
                                SST::MemHierarchy::CacheListener)

  SST_ELI_DOCUMENT_PARAMS(
      {"should_forward",
       "Controls where a notified access from the connected Cache is forwarded "
       "over the prefetcher link",
       "true"},
      {"is_l2", "Whether the shim is connected to an L2 cache", "false"})

  SST_ELI_DOCUMENT_STATISTICS()

  SST_ELI_DOCUMENT_PORTS({"to_prefetcher_link",
                          "Link to a prefetcher",
                          {"sstsimeng.NotifyEvent", "sstsimeng.PrefetchEvent"}})

 private:
  Output* output;
  uint32_t verbosity;
  bool shouldForward;
  bool isL2;
  std::vector<Event::HandlerBase*> registeredCallbacks;

  void recvPrefetchRequest(Event* ev);

  Link* toPrefetcher;
  Link* fromPrefetcher;
};

}  // namespace SSTSimEng

}  // namespace SST
#endif
