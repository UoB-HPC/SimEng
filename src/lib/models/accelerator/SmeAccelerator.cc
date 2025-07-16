#include "simeng/models/accelerator/SmeAccelerator.hh"

namespace simeng {
namespace models {
namespace accelerator {

SmeAccelerator::SmeAccelerator(send_fn_t send_fn, receive_fn_t receive_fn,
                               const bool pipelined,
                               const std::vector<uint16_t>& blockingGroups)
    : Accelerator(std::move(send_fn), std::move(receive_fn)),
      executeUnit_(
          *input_, *output_, [](auto, auto) {},
          [](auto&) {
            // TODO: Implement loads
            assert(false && "Unimplemented");
          },
          [](auto&) {
            // TODO: Implement stores
            assert(false && "Unimplemented");
          },
          [this](const auto& insn) { this->output_->getTailSlots()[0] = insn; },
          pipelined, blockingGroups) {}

void SmeAccelerator::tickImpl() { executeUnit_.tick(); }

}  // namespace accelerator
}  // namespace models
}  // namespace simeng
