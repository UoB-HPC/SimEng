#pragma once

#include "simeng/Accelerator.hh"
#include "simeng/Instruction.hh"
#include "simeng/pipeline/noc/NocGateway.hh"

namespace simeng {
namespace config {

struct OffloadingLogic {
  /** An alias for a function that determines which accelerator (if any)
   * should an instruction be diverted to. It returns the ID of the accelerator,
   * with a value of 0 indicating that the instruction should not be offloaded.
   */
  using instruction_filter =
      std::function<Accelerator::id_t(const Instruction&)>;

  /** The type of the NoC gateway used offloading instructions. */
  using gateway_t = Accelerator::gateway_t;

  /** An alias for a function that decides whether an offloaded instruction is
   * ready to be sent to the associated accelerator. */
  using is_ready_t = std::function<bool(const Instruction&)>;

  /** An alias for a function which checks whether the specified register
   * is present on an accelerator and should be ignored on the core. */
  using register_filter = std::function<bool(const Register&)>;

  /** A function handle that determines whether an instruction should be
   * diverted to an accelerator. */
  instruction_filter filter_;

  /** A function for sending packets over the NoC. It takes a reference
   * to the packet and returns whether it has been successfully sent. */
  gateway_t::send_fn_t send_;

  /** A function for receiving packets from the NoC. Returns the latest
   * packet received from the network, if there are any. */
  gateway_t::receive_fn_t receive_;

  /** Creates a default offloading logic object -- it never offloads, and both
   * sending and receiving always fail. */
  OffloadingLogic()
      : filter_([](const auto&) { return Accelerator::NO_ACCELERATOR; }),
        send_([](const auto&) { return false; }),
        receive_([] {
          return std::optional<NocPacket<AcceleratorPacket>>();
        }) {}

  /** Creates an offloading logic object based on provided parameters. */
  OffloadingLogic(
      instruction_filter filter,
      std::unordered_map<Accelerator::id_t, is_ready_t> isReadyVTable,
      std::unordered_map<Accelerator::id_t, register_filter> operandFilterVTable,
      gateway_t::send_fn_t send, gateway_t::receive_fn_t receive)
      : filter_(std::move(filter)),
        send_(std::move(send)),
        receive_(std::move(receive)),
        isReadyVTable_(std::move(isReadyVTable)),
        operandFilterVTable_(std::move(operandFilterVTable)) {}

  /** Checks if an instruction is ready to be sent to the associated
   * accelerator. */
  bool isInstructionReady(const Accelerator::id_t accelerator,
                          const Instruction& insn) const {
    const auto iter = isReadyVTable_.find(accelerator);
    assert(iter != isReadyVTable_.end() &&
           "Cannot check instruction readiness: unknown accelerator ID");
    const auto& isReady = iter->second;
    return isReady(insn);
  }

  /** Checks whether `reg` is present on an accelerator and should be ignored
   * on the core. */
  bool isRegisterOffloaded(const Accelerator::id_t accelerator,
                          const Register& reg) const {
    const auto iter = operandFilterVTable_.find(accelerator);
    assert(iter != operandFilterVTable_.end() &&
           "Cannot check operand: unknown accelerator ID");
    const auto& operandCheck = iter->second;
    return operandCheck(reg);
  }

 private:
  /** A mapping from accelerator ID to a function which checks if an
   * instruction is ready to be sent to the associated accelerator. */
  std::unordered_map<Accelerator::id_t, is_ready_t> isReadyVTable_;

  /** A mapping from accelerator ID to a function which checks whether
   * a register is present on an accelerator and should be ignored on the core.
   */
  std::unordered_map<Accelerator::id_t, register_filter> operandFilterVTable_;
};

}  // namespace config
}  // namespace simeng
