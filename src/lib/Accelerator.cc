#include "simeng/Accelerator.hh"

namespace simeng {

AcceleratorPacket::AcceleratorPacket(pipeline::noc::OffloadingPayload payload)
    : payload_(std::move(payload)) {}

pipeline::noc::OffloadingPayload AcceleratorPacket::into() {
  return std::move(payload_);
}

Accelerator::Accelerator(const id_t id, gateway_t::send_fn_t send_fn,
                         gateway_t::receive_fn_t receive_fn)
    : input_(std::make_shared<pipeline_buffer_t>(1, nullptr)),
      output_(std::make_shared<pipeline_buffer_t>(1, nullptr)),
      gateway_(std::move(send_fn), std::move(receive_fn)),
      id_(id) {}

void Accelerator::tick() {
  using namespace pipeline::noc;

  if (!input_->isStalled()) {
    // The accelerator is not stalling the in-bound queue
    auto payload = gateway_.tickInbound();
    if (payload.has_value()) {
      auto [id, type, seq, insn] = std::move(payload.value());
      switch (type) {
        case OffloadingPayloadType::Schedule: {
          assert(insn != nullptr &&
                 "Cannot schedule instruction that does not exist");
          const auto* ptr = insn.get();
          assert(insnMeta_.find(ptr) == insnMeta_.end() &&
                 "Same instruction instance already in flight");
          insnMeta_[ptr] = {id, seq};
          auto mapped = mapIncoming(std::move(insn));
          coreSeqToAccSeq_[seq] = mapped;
          input_->getTailSlots()[0] = std::move(mapped);
          break;
        }
        case OffloadingPayloadType::CommitRequest: {
          assert(coreSeqToAccSeq_.find(seq) != coreSeqToAccSeq_.end() &&
                 "Cannot commit: unknown instruction sequence ID");

          break;
        }
        case OffloadingPayloadType::CommitResponse: {
          assert(
              false &&
              "Cannot send commit responses from the core to the accelerator");
        }
        case OffloadingPayloadType::Flush: {
          assert(coreSeqToAccSeq_.find(seq) != coreSeqToAccSeq_.end() &&
                 "Cannot flush: unknown instruction sequence ID");
          lowestFlushedId_ = coreSeqToAccSeq_[seq]->getInstructionId();
          break;
        }
      }
    }

    // TODO: Tick the gateway even if stalling
    //       (maybe part the gateway's internal pipeline can tick?)
  }

  // TODO: What if the gateway needs to stall?
  std::optional<OffloadingPayload> outbound = {};
  auto output = std::move(output_->getHeadSlots()[0]);
  if (output != nullptr) {
    output = mapOutgoing(std::move(output));
    const auto* ptr = output.get();
    assert(insnMeta_.find(ptr) != insnMeta_.end() &&
           "Unknown instruction pointer");
    const auto [id, seq] = insnMeta_[ptr];
    insnMeta_.erase(ptr);
    output->setSequenceId(seq);
    coreSeqToAccSeq_.erase(seq);
    outbound = OffloadingPayload::confirmCommit(id, std::move(output));
  }
  gateway_.tickOutbound(std::move(outbound));

  tickImpl();

  // Purge flushed
  lowestFlushedId_ = {};
}

Accelerator::id_t Accelerator::getId() const noexcept { return id_; }

std::shared_ptr<Instruction> Accelerator::mapIncoming(
    std::shared_ptr<Instruction> insn) {
  return insn;
}

std::shared_ptr<Instruction> Accelerator::mapOutgoing(
    std::shared_ptr<Instruction> insn) {
  return insn;
}

}  // namespace simeng