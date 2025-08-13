#include "simeng/models/accelerator/SmeAccelerator.hh"

#include "arch/aarch64/InstructionMetadata.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/branchpredictors/AlwaysNotTakenPredictor.hh"

namespace simeng {
namespace models {
namespace accelerator {

SmeAccelerator::SmeAccelerator(const id_t id, send_fn_t send_fn,
                               receive_fn_t receive_fn,
                               memory::MemoryInterface& dataMemory,
                               pipeline::PortAllocator& portAllocator,
                               const ryml::ConstNodeRef config)
    : Accelerator(id, std::move(send_fn), std::move(receive_fn)),
      registerFileSet_(config::SimInfo::getPhysRegStruct()),
      physicalRegisterStructures_(config::SimInfo::getPhysRegStruct()),
      physicalRegisterQuantities_(config::SimInfo::getPhysRegQuantities()),
      registerAliasTable_(config::SimInfo::getArchRegStruct(),
                          physicalRegisterQuantities_),
      renameToDispatchBuffer_(input_->getWidth(), nullptr),
      issuePorts_(config["Execution-Units"].num_children(), {1, nullptr}),
      completionSlots_(
          config["Execution-Units"].num_children() +
              config["Pipeline-Widths"]["LSQ-Completion"].as<uint16_t>(),
          {1, nullptr}),
      renameUnit_(*input_, renameToDispatchBuffer_, reorderBuffer_,
                  registerAliasTable_, loadStoreQueue_,
                  physicalRegisterStructures_.size()),
      dispatchIssueUnit_(renameToDispatchBuffer_, issuePorts_, registerFileSet_,
                         portAllocator, physicalRegisterQuantities_),
      writebackUnit_(
          completionSlots_, registerFileSet_,
          [this](auto insnId) { reorderBuffer_.commitMicroOps(insnId); }),
      reorderBuffer_(
          config["Queue-Sizes"]["ROB"].as<uint32_t>(), registerAliasTable_,
          loadStoreQueue_, [this](const auto&) {}, [this](auto) {},
          branchPredictor_, 0, 0),
      loadStoreQueue_(
          config["Queue-Sizes"]["Load"].as<uint32_t>(),
          config["Queue-Sizes"]["Store"].as<uint32_t>(), dataMemory,
          {completionSlots_.data() + config["Execution-Units"].num_children(),
           config["Pipeline-Widths"]["LSQ-Completion"].as<uint16_t>()},
          [this](auto regs, auto values) {
            dispatchIssueUnit_.forwardOperands(regs, values);
          },
          [](const auto& uop) { uop->setCommitReady(); },
          config["LSQ-L1-Interface"]["Exclusive"].as<bool>(),
          config["LSQ-L1-Interface"]["Load-Bandwidth"].as<uint16_t>(),
          config["LSQ-L1-Interface"]["Store-Bandwidth"].as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Requests-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Loads-Per-Cycle"]
              .as<uint16_t>(),
          config["LSQ-L1-Interface"]["Permitted-Stores-Per-Cycle"]
              .as<uint16_t>()),
      portAllocator_(portAllocator),
      commitWidth_(output_->getWidth())
{
  for (size_t i = 0; i < config["Execution-Units"].num_children(); i++) {
    // Create vector of blocking groups
    std::vector<uint16_t> blockingGroups = {};
    for (ryml::ConstNodeRef grp :
         config["Execution-Units"][i]["Blocking-Group-Nums"]) {
      blockingGroups.push_back(grp.as<uint16_t>());
    }
    executionUnits_.emplace_back(
        issuePorts_[i], completionSlots_[i],
        [this](auto regs, auto values) {
          dispatchIssueUnit_.forwardOperands(regs, values);
        },
        [this](const auto& uop) { loadStoreQueue_.startLoad(uop); },
        [this](const auto& uop) { loadStoreQueue_.supplyStoreData(uop); },
        [](const auto& uop) { uop->setCommitReady(); },
        config["Execution-Units"][i]["Pipelined"].as<bool>(), blockingGroups);
  }

  // Provide reservation size getter to A64FX port allocator
  portAllocator.setRSSizeGetter([this](std::vector<uint32_t>& sizeVec) {
    dispatchIssueUnit_.getRSSizes(sizeVec);
  });
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
bool SmeAccelerator::shouldAccelerate(const Instruction& insn) {
  using namespace arch::aarch64;

  // NOLINTBEGIN(*-pro-type-static-cast-downcast)
  const auto& aarch_insn =
      *static_cast<const arch::aarch64::Instruction*>(&insn);
  // NOLINTEND(*-pro-type-static-cast-downcast)

  const auto& arch = aarch_insn.getArchitecture();
  if (!arch.isStreamingModeEnabled() && !arch.isZARegisterEnabled())
    return false;

  const auto src = insn.getSourceRegisters();
  const auto dst = insn.getDestinationRegisters();

  const bool usesSmeRegs =
      std::find_if(dst.begin(), dst.end(), isSmeRegister) != dst.end() ||
      std::find_if(src.begin(), src.end(), isSmeRegister) != src.end();
  if (!usesSmeRegs) return false;

  return true;
}

bool SmeAccelerator::isInstructionReady(const Instruction& insn) {
  const auto& srcs = insn.getSourceRegisters();
  for (size_t i = 0; i < srcs.size(); i++) {
    if (!isOperandOffloaded(srcs[i]) &&
        !insn.isOperandReady(static_cast<int>(i))) {
      return false;
    }
  }
  return true;
}

bool SmeAccelerator::isOperandOffloaded(const Register& reg) {
  return isSmeRegister(reg);
}

void SmeAccelerator::tickImpl() {
  // Tick port allocators internal functionality at start of cycle
  portAllocator_.tick();

  // Writeback must be ticked at start of cycle, to ensure decode reads the
  // correct values
  writebackUnit_.tick();

  // Tick units
  renameUnit_.tick();
  dispatchIssueUnit_.tick();
  for (auto& eu : executionUnits_) {
    // Tick each execution unit
    eu.tick();
  }

  loadStoreQueue_.tick();

  // Late tick for the dispatch/issue unit to issue newly ready uops
  dispatchIssueUnit_.issue();

  // Tick buffers
  // Each unit must have wiped the entries at the head of the buffer after use,
  // as these will now loop around and become the tail.
  renameToDispatchBuffer_.tick();
  for (auto& issuePort : issuePorts_) {
    issuePort.tick();
  }
  for (auto& completionSlot : completionSlots_) {
    completionSlot.tick();
  }

  // Commit instructions from ROB
  if (!output_->isStalled()) {
    const auto commited = reorderBuffer_.commit(commitWidth_);
    assert(commited <= output_->getWidth() &&
           "Commited more instructions than the NoC gateway can handle");
    assert(commited <= insns_.size() &&
           "Commited more instructions than the current buffer size");

    // Send the commited instructions to the NoC gateway
    // We rely on the assumption that the instructions in the `insn_` queue is
    // in program order
    for (uint16_t slot = 0; slot < output_->getWidth(); ++slot) {
      output_->getTailSlots()[slot] = nullptr;
      if (slot < commited) {
        auto insn = insns_[0];
        output_->getTailSlots()[slot] = std::move(insn);
        insns_.pop_front();
      }
    }
  }

  input_->tick();
  output_->tick();
}

std::shared_ptr<Instruction> SmeAccelerator::mapIncoming(
    std::shared_ptr<Instruction> insn) {
  insn->markAccelerated();
  insns_.push_back(insn);
  return insn;
}

bool SmeAccelerator::isSmeRegister(const Register& reg) {
  switch (reg.type) {
    // TODO: Enable vector registers on the accelerator
    //       (why does this break stuff?)
    // case arch::aarch64::RegisterType::VECTOR:
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
