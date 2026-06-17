#ifndef _H_SST_FORWARD_LISTENER
#define _H_SST_FORWARD_LISTENER

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

class CacheListenerEvent : public SST::Event {
 public:
  CacheListenerEvent(const MemHierarchy::Addr tAddr,
                     const MemHierarchy::Addr pAddr,
                     const MemHierarchy::Addr vAddr,
                     const MemHierarchy::Addr iPtr, const uint32_t reqSize,
                     MemHierarchy::NotifyAccessType accessT,
                     MemHierarchy::NotifyResultType resultT, bool l2)
      : SST::Event(),
        size(reqSize),
        targAddr(tAddr),
        physAddr(pAddr),
        virtAddr(vAddr),
        instPtr(iPtr),
        access(accessT),
        result(resultT),
        fromL2(l2) {}

  MemHierarchy::Addr getTargetAddress() const { return targAddr; }
  MemHierarchy::Addr getPhysicalAddress() const { return physAddr; }
  MemHierarchy::Addr getVirtualAddress() const { return virtAddr; }
  MemHierarchy::Addr getInstructionPointer() const { return instPtr; }
  MemHierarchy::NotifyAccessType getAccessType() const { return access; }
  MemHierarchy::NotifyResultType getResultType() const { return result; }
  uint32_t getSize() const { return size; }
  bool isFromL2() const { return fromL2; }

 private:
  uint32_t size;
  MemHierarchy::Addr targAddr;
  MemHierarchy::Addr physAddr;
  MemHierarchy::Addr virtAddr;
  MemHierarchy::Addr instPtr;
  MemHierarchy::NotifyAccessType access;
  MemHierarchy::NotifyResultType result;
  bool fromL2;

  CacheListenerEvent() {}  // For serialization only

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
    ser & fromL2;
  }

  ImplementSerializable(CacheListenerEvent);
};

class ForwardListener : public SST::MemHierarchy::CacheListener {
 public:
  ForwardListener(ComponentId_t id, Params& params);
  ~ForwardListener();

  void notifyAccess(const MemHierarchy::CacheListenerNotification& notify);
  void registerResponseCallback(Event::HandlerBase* handler) { delete handler; }
  void printStats(Output& UNUSED(out)) {}

  SST_ELI_REGISTER_SUBCOMPONENT(
      ForwardListener, "sstsimeng", "ForwardListener",
      SST_ELI_ELEMENT_VERSION(1, 0, 0),
      "Cache listener which forwards event over set link",
      SST::MemHierarchy::CacheListener)

  SST_ELI_DOCUMENT_PARAMS({"verbose", "Controls the verbosity of the component",
                           "0"},
                          {"only_misses", "Only forward miss events", "false"},
                          {"is_l2", "Listens to L2 Cache", "false"})

  SST_ELI_DOCUMENT_STATISTICS(
      {"read_miss", "Number of read misses", "listener", 1},
      {"read_hit", "Number of read hits", "listener", 1},
      {"write_miss", "Number of write misses.", "listener", 1},
      {"write_hit", "Number of write hits", "listener", 1},
      {"prf_miss", "Number of prefetch misses", "listener", 1},
      {"prf_hit", "Number of prefetch hit", "listener", 1})

  SST_ELI_DOCUMENT_PORTS({"forward_link",
                          "Link to forward access over",
                          {"sstsimeng.CacheListenerEvent"}})

 private:
  Output* output;
  uint32_t verbosity;
  bool onlyMisses;
  bool isL2 = false;

  void recvLinkEvent(Event* ev) { delete ev; }

  Link* forwardLink;

  Statistic<uint64_t>* readMiss;
  Statistic<uint64_t>* readHit;
  Statistic<uint64_t>* writeMiss;
  Statistic<uint64_t>* writeHit;
  Statistic<uint64_t>* prfMiss;
  Statistic<uint64_t>* prfHit;
};

}  // namespace SSTSimEng

}  // namespace SST
#endif
