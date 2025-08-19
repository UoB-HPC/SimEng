#include "simeng/Accelerator.hh"

namespace simeng {

AcceleratorPacket::AcceleratorPacket(OffloadingPayload payload)
    : payload_(std::move(payload)) {}

OffloadingPayload AcceleratorPacket::into() { return std::move(payload_); }

Accelerator::Accelerator(const id_t id, gateway_t::send_fn_t send_fn,
                         gateway_t::receive_fn_t receive_fn)
    : input_(std::make_shared<pipeline_buffer_t>(1, nullptr)),
      output_(std::make_shared<pipeline_buffer_t>(1, nullptr)),
      gateway_(std::move(send_fn), std::move(receive_fn)),
      id_(id) {}

void Accelerator::tick() {
  if (!input_->isStalled()) {
    // The accelerator is not stalling the in-bound queue
    // TODO: Make receiving packets non-blocking
    auto payload = gateway_.tickInbound();
    if (payload.has_value()) {
      const auto id = payload.value().id_;
      switch (payload.value().type_) {
        case OffloadingPayload::Type::Schedule: {
          if (flushing_.has_value()) {
            // Drain incoming instructions until flush is finalized
            break;
          }

          auto insn = std::move(payload.value().insn_);
          const auto seq = insn->getSequenceId();
          assert(insn != nullptr &&
                 "Cannot schedule instruction that does not exist");
          const auto* ptr = insn.get();
          assert(insnMeta_.find(ptr) == insnMeta_.end() &&
                 "Same instruction instance already in flight");
          insnMeta_[ptr] = {id, seq};
          mapIncoming(insn);
          // coreSeqToAccInsn_[seq] = insn;
          input_->getTailSlots()[0] = std::move(insn);
          break;
        }
        case OffloadingPayload::Type::Commit: {
          assert(
              false &&
              "Cannot send commit responses from the core to the accelerator");
        }
        case OffloadingPayload::Type::Flush: {
          assert(false &&
                 "The core cannot request flushes from the accelerator");
        }
        case OffloadingPayload::Type::Flushed: {
          assert(flushing_.has_value() &&
                 "Cannot finalize flush: no flush in progress");
          assert(id >= flushing_.value() &&
                 "Cannot finalize flush: invalid payload ID");
          if (id > flushing_.value()) {
            // Skip stale flushes
            break;
          }

          // Purge insnMeta_
          std::vector<uint64_t> flushed;
          for (auto it = insnMeta_.begin(); it != insnMeta_.end();) {
            if (it->second.first >= id) {
              flushed.push_back(it->second.second);
              it = insnMeta_.erase(it);
            } else {
              ++it;
            }
          }

          // // Purge coreSeqToAccInsn_
          // for (const auto seq : flushed) {
          //   coreSeqToAccInsn_.erase(seq);
          // }

          flushing_.reset();
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
    mapOutgoing(output);
    const auto* ptr = output.get();
    assert(insnMeta_.find(ptr) != insnMeta_.end() &&
           "Unknown instruction pointer");
    const auto [id, seq] = insnMeta_[ptr];
    insnMeta_.erase(ptr);
    output->setSequenceId(seq);
    // coreSeqToAccInsn_.erase(seq);
    outbound = OffloadingPayload::commit(id, std::move(output));
  }
  gateway_.tickOutbound(std::move(outbound));

  tickImpl();
}

void Accelerator::flush(const std::shared_ptr<Instruction>& flushAfter) {
  assert(insnMeta_.find(flushAfter.get()) != insnMeta_.end() &&
         "Cannot flush: unknown instruction");
  const auto id = insnMeta_[flushAfter.get()].first;
  if (!flushing_.has_value() || id < flushing_.value()) {
    flushing_ = id;
    // TODO Just enqueue instead of ticking the whole gateway
    gateway_.tickOutbound(payload_t::flush(id));
  }

  input_->fill(nullptr);
  input_->stall(false);
}

Accelerator::id_t Accelerator::getId() const noexcept { return id_; }

void Accelerator::mapIncoming(std::shared_ptr<Instruction>& insn) {}

void Accelerator::mapOutgoing(std::shared_ptr<Instruction>& insn) {}

}  // namespace simeng
