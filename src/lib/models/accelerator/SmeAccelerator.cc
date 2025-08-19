#include "simeng/models/accelerator/SmeAccelerator.hh"

#include "arch/aarch64/InstructionMetadata.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/branchpredictors/AlwaysNotTakenPredictor.hh"

namespace simeng {
namespace models {
namespace accelerator {

using namespace arch;

SmeAccelerator::SmeAccelerator(const id_t id, gateway_t::send_fn_t send_fn,
                               gateway_t::receive_fn_t receive_fn,
                               memory::MemoryInterface& dataMemory,
                               pipeline::PortAllocator& portAllocator,
                               const ryml::ConstNodeRef config)
    : Accelerator(id, std::move(send_fn), std::move(receive_fn)),
      registerFileSet_(config::SimInfo::getPhysRegStruct()),
      physicalRegisterStructures_(config::SimInfo::getPhysRegStruct()),
      physicalRegisterQuantities_(config::SimInfo::getPhysRegQuantities()),
      registerAliasTable_(config::SimInfo::getArchRegStruct(),
                          physicalRegisterQuantities_),
      mappedRegisterFileSet_(registerFileSet_, registerAliasTable_),
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
          loadStoreQueue_, [this](const auto& insn) { raiseException(insn); },
          [](auto) {}, branchPredictor_, 0, 0),
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
      commitWidth_(output_->getWidth()) {
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
  const auto& aarch_insn = *static_cast<const aarch64::Instruction*>(&insn);
  // NOLINTEND(*-pro-type-static-cast-downcast)

  // SMSTART/SMSTOP
  const auto& metadata = aarch_insn.getMetadata();
  switch (metadata.opcode) {
    case Opcode::AArch64_MSR:
      if (metadata.operands[0].sysop.reg.sysreg == AARCH64_SYSREG_SVCR) {
        return true;
      }
      break;
    case Opcode::AArch64_MSRpstatesvcrImm1:
      return true;
    default:
      break;
  }

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
    if (!isRegisterOffloaded(srcs[i]) &&
        !insn.isOperandReady(static_cast<int>(i))) {
      return false;
    }
  }
  return true;
}

bool SmeAccelerator::isRegisterOffloaded(const Register& reg) {
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
  unsigned int commited = 0;
  if (!output_->isStalled()) {
    commited = reorderBuffer_.commit(commitWidth_);
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
        output_->getTailSlots()[slot] = insns_[slot];
      }
    }
  }

  input_->tick();
  output_->tick();

  if (exceptionInsn_.has_value()) {
    handleException();
  } else {
    flushIfNeeded();
  }

  for (unsigned int i = 0; i < commited; i++) {
    insns_.pop_front();
  }
}

void SmeAccelerator::mapIncoming(std::shared_ptr<Instruction>& insn) {
  insn->markAccelerated();
  insns_.push_back(insn);
}

bool SmeAccelerator::isSmeRegister(const Register& reg) {
  switch (reg.type) {
    // TODO: Enable vector registers on the accelerator
    //       (why does this break stuff?)
    // case aarch64::RegisterType::VECTOR:
    case aarch64::RegisterType::MATRIX:
    case aarch64::RegisterType::TABLE:
      return true;
    default:
      return false;
  }
}

void SmeAccelerator::flushIfNeeded() {
  // Check for flush

  // lowestInsnId
  std::optional<uint64_t> flush{};
  for (const auto& eu : executionUnits_) {
    if (eu.shouldFlush()) {
      if (!flush.has_value() || eu.getFlushInsnId() < flush.value()) {
        flush = eu.getFlushInsnId();
      }
    }
  }
  if (flush.has_value() || reorderBuffer_.shouldFlush()) {
    // Flush was requested in an out-of-order stage.
    // Update PC and wipe in-order buffers (Fetch/Decode, Decode/Rename,
    // Rename/Dispatch)

    if (reorderBuffer_.shouldFlush()) {
      if (!flush.has_value() ||
          reorderBuffer_.getFlushInsnId() < flush.value()) {
        flush = reorderBuffer_.getFlushInsnId();
      }
    }
    assert(flush.has_value());
    this->flush(flush.value());
  }
}

void SmeAccelerator::raiseException(
    const std::shared_ptr<Instruction>& instruction) {
  exceptionInsn_ = instruction;
}

void SmeAccelerator::handleException() {
  using Exception = aarch64::InstructionException;

  assert(exceptionInsn_.has_value() && "Cannot handle non-existent exception");
  const auto exception = std::move(exceptionInsn_.value());

  flush(exception->getInstructionId());

  // NOLINTBEGIN(*-pro-type-static-cast-downcast)
  const auto& archInsn = *static_cast<aarch64::Instruction*>(exception.get());
  // NOLINTEND(*-pro-type-static-cast-downcast)
  switch (archInsn.getException()) {
    case Exception::StreamingModeUpdate:
    case Exception::ZAregisterStatusUpdate:
    case Exception::SMZAUpdate: {
      handleSmeStateChange(archInsn);
      break;
    }
    default: {
      assert(false && "Unsupported SME Accelerator exception");
    }
  }
  exceptionInsn_.reset();
}

void SmeAccelerator::handleSmeStateChange(
    const aarch64::Instruction& instruction) {
  using namespace aarch64;

  // Get Architecture
  const auto& arch = instruction.getArchitecture();
  // Retrieve register file structure from SimInfo
  const auto& regFileStruct = config::SimInfo::getArchRegStruct();
  // Retrieve metadata from architecture
  const auto& metadata = instruction.getMetadata();
  const auto exception = instruction.getException();

  uint64_t newSVCR = 0;
  const uint64_t currSVCR = arch.getSVCRval();

  // Check if exception was called by AArch64_MSR (msr systemreg, xt) or
  // AArch64_MSRpstatesvcrImm1 (msr svcr<sm|za|smza>, #imm)
  if (metadata.opcode == Opcode::AArch64_MSR) {
    newSVCR = instruction.getSourceOperands()[0].get<uint64_t>();
  } else if (metadata.opcode == Opcode::AArch64_MSRpstatesvcrImm1) {
    // Ensure operand metadata is as expected
    assert(metadata.operands[0].type == AARCH64_OP_SYSALIAS);
    assert(metadata.operands[0].sysop.sub_type == AARCH64_OP_SVCR);
    // extract SVCR bits
    const auto svcrBits =
        static_cast<uint64_t>(metadata.operands[0].sysop.alias.svcr);
    // Ensure SVCR Bits are valid
    assert(svcrBits == AARCH64_SVCR_SVCRSM || svcrBits == AARCH64_SVCR_SVCRZA ||
           svcrBits == AARCH64_SVCR_SVCRSMZA);

    const uint64_t imm = metadata.operands[1].imm;
    assert((imm == 0 || imm == 1) &&
           "[SimEng:SMEAccelerator] SVCR Instruction invalid - Imm value "
           "can only be 0 or 1");
    // Zero out SM & ZA bits as appropriate
    newSVCR = currSVCR & ~svcrBits;
    // Update only relevant bits of SVCR
    newSVCR = newSVCR | svcrBits * imm;
  } else {
    std::cerr << "[SimEng::SMEAccelerator] SVCR system register exception "
                 "triggered by incorrect instruction. Opcode "
              << metadata.opcode << std::endl;
    exit(1);
  }
  // TODO: Should `arch` be updated here?
  // arch.setSVCRval(newSVCR);

  // Initialize vectors for all registers & values
  std::vector<Register> regs;
  std::vector<RegisterValue> regValues;

  // If SVCR.ZA has changed state then zero out ZA and ZT0 registers
  if (exception != InstructionException::StreamingModeUpdate) {
    if ((newSVCR & AARCH64_SVCR_SVCRZA) != (currSVCR & AARCH64_SVCR_SVCRZA)) {
      for (uint16_t i = 0; i < regFileStruct[RegisterType::MATRIX].quantity;
           i++) {
        regs.push_back({RegisterType::MATRIX, i});
        regValues.emplace_back(0, 256);
      }
      regs.push_back({RegisterType::TABLE, 0});
      regValues.emplace_back(0, 64);
    }
  }
  // If SVCR.SM has changed state then zero out SVE, NEON, Predicate
  // registers, else don't
  if (exception != InstructionException::ZAregisterStatusUpdate) {
    if ((newSVCR & AARCH64_SVCR_SVCRSM) != (currSVCR & AARCH64_SVCR_SVCRSM)) {
      for (uint16_t i = 0; i < regFileStruct[RegisterType::VECTOR].quantity;
           i++) {
        regs.push_back({RegisterType::VECTOR, i});
        regValues.emplace_back(0, 256);
        if (i < regFileStruct[RegisterType::PREDICATE].quantity) {
          regs.push_back({RegisterType::PREDICATE, i});
          regValues.emplace_back(0, 32);
        }
      }
    }
  }

  // Update SVCR system register in regFile
  regs.push_back(
      {RegisterType::SYSTEM,
       static_cast<uint16_t>(arch.getSystemRegisterTag(AARCH64_SYSREG_SVCR))});
  regValues.emplace_back(newSVCR, 8);

  auto& regFile = mappedRegisterFileSet_;
  for (size_t i = 0; i < regs.size(); i++) {
    regFile.set(regs[i], regValues[i]);
  }
}

void SmeAccelerator::flush(const uint64_t flushAfter) {
  const auto flushAfterIt =
      std::find_if(insns_.begin(), insns_.end(),
                   [flushAfter](const std::shared_ptr<Instruction>& insn) {
                     return insn->getInstructionId() == flushAfter;
                   });
  assert(flushAfterIt != insns_.end() &&
         "Cannot flush: unknown instruction ID");
  Accelerator::flush(*flushAfterIt);

  renameToDispatchBuffer_.fill(nullptr);
  renameToDispatchBuffer_.stall(false);

  // Flush everything younger than the bad instruction from the ROB
  reorderBuffer_.flush(flushAfter);
  dispatchIssueUnit_.purgeFlushed();
  loadStoreQueue_.purgeFlushed();
  for (auto& eu : executionUnits_) {
    eu.purgeFlushed();
  }

  std::deque<std::shared_ptr<Instruction>> purged{};
  for (auto& insn : insns_) {
    if (insn->isFlushed()) continue;
    purged.push_back(insn);
  }
  std::swap(insns_, purged);
}

}  // namespace accelerator
}  // namespace models
}  // namespace simeng
