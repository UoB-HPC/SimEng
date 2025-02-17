#pragma once

#include "simeng/RegisterValue.hh"
#include "simeng/memory/MemoryAccessTarget.hh"

namespace simeng {

namespace memory {

/** A structure used for the result of memory read operations. */
struct MemoryReadResult {
  /** The memory access that was requested. */
  MemoryAccessTarget target;
  /** The data returned by the request. */
  RegisterValue data;
  /** The request identifier provided by the requester. */
  uint64_t requestId;
};

}  // namespace memory
}  // namespace simeng