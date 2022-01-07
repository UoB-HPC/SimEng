#pragma once

namespace simeng {
namespace arch {
namespace aarch64 {

/** A aarch64 custom decoder for splitting appropriate macro-ops into micro-ops.
 */
class MicroDecoder {
 public:
  /** Construct a micro decoder for splitting relevant instructons. */
  MicroDecoder();
};

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
