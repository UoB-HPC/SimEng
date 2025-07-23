#include "simeng/models/accelerator/SmeAccelerator.hh"

#include "simeng/arch/aarch64/Architecture.hh"

namespace simeng {
namespace models {
namespace accelerator {

SmeAccelerator::SmeAccelerator(const id_t id, send_fn_t send_fn,
                               receive_fn_t receive_fn, const bool pipelined,
                               const std::vector<uint16_t>& blockingGroups)
    : Accelerator(id, std::move(send_fn), std::move(receive_fn)),
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

bool SmeAccelerator::shouldAccelerate(
    const std::shared_ptr<Instruction>& insn) {
  // NOLINTBEGIN(*-pro-type-static-cast-downcast)
  const auto& aarch_insn =
      *static_cast<arch::aarch64::Instruction*>(insn.get());
  // NOLINTEND(*-pro-type-static-cast-downcast)

  const auto& arch = aarch_insn.getArchitecture();
  if (!arch.isStreamingModeEnabled() && !arch.isZARegisterEnabled())
    return false;

  const auto src = insn->getSourceRegisters();
  const auto dst = insn->getDestinationRegisters();

  return std::find_if(src.begin(), src.end(), isSmeRegister) != src.end() ||
         std::find_if(dst.begin(), dst.end(), isSmeRegister) != dst.end();
}

void SmeAccelerator::tickImpl() { executeUnit_.tick(); }

bool SmeAccelerator::isSmeRegister(const Register& reg) {
  switch (reg.type) {
    case arch::aarch64::RegisterType::VECTOR:
    case arch::aarch64::RegisterType::MATRIX:
    case arch::aarch64::RegisterType::TABLE:
      return true;
    default:
      return false;
  }
}

}  // namespace accelerator
}  // namespace models
}  // namespace simeng
