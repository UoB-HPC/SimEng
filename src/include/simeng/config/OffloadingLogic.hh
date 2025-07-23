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
      std::function<Accelerator::id_t(const std::shared_ptr<Instruction>&)>;

  /** The type of the NoC gateway used offloading instructions. */
  using gateway_t = pipeline::noc::NocGateway<std::shared_ptr<Instruction>,
                                              AcceleratorPacket>;

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
          return std::optional<pipeline::noc::NocPacket<AcceleratorPacket>>();
        }) {}

  /** Creates an offloading logic object based on provided parameters. */
  OffloadingLogic(instruction_filter filter, gateway_t::send_fn_t send,
                  gateway_t::receive_fn_t receive)
      : filter_(std::move(filter)),
        send_(std::move(send)),
        receive_(std::move(receive)) {}
};

}  // namespace config
}  // namespace simeng
