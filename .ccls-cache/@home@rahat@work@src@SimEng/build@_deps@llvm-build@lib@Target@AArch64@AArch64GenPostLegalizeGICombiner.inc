/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Global Combiner                                                            *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef AARCH64POSTLEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_DEPS
#include "llvm/ADT/SparseBitVector.h"
namespace llvm {
extern cl::OptionCategory GICombinerOptionCategory;
} // end namespace llvm
#endif // ifdef AARCH64POSTLEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_DEPS

#ifdef AARCH64POSTLEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_H
class AArch64GenPostLegalizerCombinerHelperRuleConfig {
  SparseBitVector<> DisabledRules;

public:
  bool parseCommandLineOption();
  bool isRuleDisabled(unsigned ID) const;
  bool setRuleEnabled(StringRef RuleIdentifier);
  bool setRuleDisabled(StringRef RuleIdentifier);
};

class AArch64GenPostLegalizerCombinerHelper {
  const AArch64GenPostLegalizerCombinerHelperRuleConfig *RuleConfig;

public:
  template <typename... Args>AArch64GenPostLegalizerCombinerHelper(const AArch64GenPostLegalizerCombinerHelperRuleConfig &RuleConfig, Args &&... args) : RuleConfig(&RuleConfig) {}

  bool tryCombineAll(
    GISelChangeObserver &Observer,
    MachineInstr &MI,
    MachineIRBuilder &B,
    CombinerHelper &Helper) const;
};

static Optional<uint64_t> getRuleIdxForIdentifier(StringRef RuleIdentifier) {
  uint64_t I;
  // getAtInteger(...) returns false on success
  bool Parsed = !RuleIdentifier.getAsInteger(0, I);
  if (Parsed)
    return I;

#ifndef NDEBUG
  switch (RuleIdentifier.size()) {
  default: break;
  case 9:	 // 2 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "opy_prop", 8) != 0)
        break;
      return 0;	 // "copy_prop"
    case 'm':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ul_const", 8) != 0)
        break;
      return 11;	 // "mul_const"
    }
    break;
  case 10:	 // 2 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'i':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "2p_to_p2i", 9) != 0)
        break;
      return 30;	 // "i2p_to_p2i"
    case 'p':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "2i_to_i2p", 9) != 0)
        break;
      return 29;	 // "p2i_to_i2p"
    }
    break;
  case 12:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "redundant_or", 12) != 0)
      break;
    return 10;	 // "redundant_or"
  case 13:	 // 4 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "onstant_fold", 12) != 0)
        break;
      return 23;	 // "constant_fold"
    case 'l':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "oad_and_mask", 12) != 0)
        break;
      return 3;	 // "load_and_mask"
    case 'm':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "erge_unmerge", 12) != 0)
        break;
      return 19;	 // "merge_unmerge"
    case 'r':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "edundant_and", 12) != 0)
        break;
      return 7;	 // "redundant_and"
    }
    break;
  case 14:	 // 2 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "inop_same_val", 13) != 0)
        break;
      return 26;	 // "binop_same_val"
    case 'f':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "neg_fneg_fold", 13) != 0)
        break;
      return 32;	 // "fneg_fneg_fold"
    }
    break;
  case 15:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'e':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "xtending_loads", 14) != 0)
        break;
      return 2;	 // "extending_loads"
    case 'o':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "verlapping_and", 14) != 0)
        break;
      return 35;	 // "overlapping_and"
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "elect_same_val", 14) != 0)
        break;
      return 24;	 // "select_same_val"
    }
    break;
  case 16:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "select_undef_cmp", 16) != 0)
      break;
    return 20;	 // "select_undef_cmp"
  case 17:	 // 2 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "nyext_trunc_fold", 16) != 0)
        break;
      return 31;	 // "anyext_trunc_fold"
    case 'e':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "rase_undef_store", 16) != 0)
        break;
      return 1;	 // "erase_undef_store"
    }
    break;
  case 18:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "inop_left_to_zero", 17) != 0)
        break;
      return 27;	 // "binop_left_to_zero"
    case 'f':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "old_merge_to_zext", 17) != 0)
        break;
      return 22;	 // "fold_merge_to_zext"
    case 'r':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ight_identity_one", 17) != 0)
        break;
      return 33;	 // "right_identity_one"
    }
    break;
  case 19:	 // 6 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "inop_right_to_zero", 18) != 0)
        break;
      return 28;	 // "binop_right_to_zero"
    case 'p':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "tr_add_immed_chain", 18) != 0)
        break;
      return 34;	 // "ptr_add_immed_chain"
    case 'r':	 // 2 strings to match.
      switch (RuleIdentifier[1]) {
      default: break;
      case 'i':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "ght_identity_zero", 17) != 0)
          break;
        return 25;	 // "right_identity_zero"
      case 'o':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "tate_out_of_range", 17) != 0)
          break;
        return 17;	 // "rotate_out_of_range"
      }
      break;
    case 's':	 // 2 strings to match.
      if (RuleIdentifier[1] != 'e')
        break;
      switch (RuleIdentifier[2]) {
      default: break;
      case 'l':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+3, "ect_constant_cmp", 16) != 0)
          break;
        return 21;	 // "select_constant_cmp"
      case 'x':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+3, "t_trunc_sextload", 16) != 0)
          break;
        return 4;	 // "sext_trunc_sextload"
      }
      break;
    }
    break;
  case 20:	 // 2 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'r':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "edundant_sext_inreg", 19) != 0)
        break;
      return 12;	 // "redundant_sext_inreg"
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "plit_store_zero_128", 19) != 0)
        break;
      return 36;	 // "split_store_zero_128"
    }
    break;
  case 21:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "mutate_anyext_to_zext", 21) != 0)
      break;
    return 5;	 // "mutate_anyext_to_zext"
  case 24:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "xor_of_and_with_same_reg", 24) != 0)
      break;
    return 8;	 // "xor_of_and_with_same_reg"
  case 25:	 // 2 strings to match.
    if (memcmp(RuleIdentifier.data()+0, "bitfield_extract_from_", 22) != 0)
      break;
    switch (RuleIdentifier[22]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+23, "nd", 2) != 0)
        break;
      return 14;	 // "bitfield_extract_from_and"
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+23, "hr", 2) != 0)
        break;
      return 15;	 // "bitfield_extract_from_shr"
    }
    break;
  case 26:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "extractvecelt_pairwise_add", 26) != 0)
      break;
    return 9;	 // "extractvecelt_pairwise_add"
  case 29:	 // 2 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "itfield_extract_from_shr_and", 28) != 0)
        break;
      return 16;	 // "bitfield_extract_from_shr_and"
    case 'i':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "cmp_to_true_false_known_bits", 28) != 0)
        break;
      return 18;	 // "icmp_to_true_false_known_bits"
    }
    break;
  case 32:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "bitfield_extract_from_sext_inreg", 32) != 0)
      break;
    return 13;	 // "bitfield_extract_from_sext_inreg"
  case 37:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "hoist_logic_op_with_same_opcode_hands", 37) != 0)
      break;
    return 6;	 // "hoist_logic_op_with_same_opcode_hands"
  }
#endif // ifndef NDEBUG

  return None;
}
static Optional<std::pair<uint64_t, uint64_t>> getRuleRangeForIdentifier(StringRef RuleIdentifier) {
  std::pair<StringRef, StringRef> RangePair = RuleIdentifier.split('-');
  if (!RangePair.second.empty()) {
    const auto First = getRuleIdxForIdentifier(RangePair.first);
    const auto Last = getRuleIdxForIdentifier(RangePair.second);
    if (!First.hasValue() || !Last.hasValue())
      return None;
    if (First >= Last)
      report_fatal_error("Beginning of range should be before end of range");
    return {{*First, *Last + 1}};
  } else if (RangePair.first == "*") {
    return {{0, 37}};
  } else {
    const auto I = getRuleIdxForIdentifier(RangePair.first);
    if (!I.hasValue())
      return None;
    return {{*I, *I + 1}};
  }
  return None;
}

bool AArch64GenPostLegalizerCombinerHelperRuleConfig::setRuleEnabled(StringRef RuleIdentifier) {
  auto MaybeRange = getRuleRangeForIdentifier(RuleIdentifier);
  if (!MaybeRange.hasValue())
    return false;
  for (auto I = MaybeRange->first; I < MaybeRange->second; ++I)
    DisabledRules.reset(I);
  return true;
}

bool AArch64GenPostLegalizerCombinerHelperRuleConfig::setRuleDisabled(StringRef RuleIdentifier) {
  auto MaybeRange = getRuleRangeForIdentifier(RuleIdentifier);
  if (!MaybeRange.hasValue())
    return false;
  for (auto I = MaybeRange->first; I < MaybeRange->second; ++I)
    DisabledRules.set(I);
  return true;
}

bool AArch64GenPostLegalizerCombinerHelperRuleConfig::isRuleDisabled(unsigned RuleID) const {
  return DisabledRules.test(RuleID);
}
#endif // ifdef AARCH64POSTLEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_H

#ifdef AARCH64POSTLEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_CPP

std::vector<std::string> AArch64PostLegalizerCombinerHelperOption;
cl::list<std::string> AArch64PostLegalizerCombinerHelperDisableOption(
    "aarch64postlegalizercombinerhelper-disable-rule",
    cl::desc("Disable one or more combiner rules temporarily in the AArch64PostLegalizerCombinerHelper pass"),
    cl::CommaSeparated,
    cl::Hidden,
    cl::cat(GICombinerOptionCategory),
    cl::callback([](const std::string &Str) {
      AArch64PostLegalizerCombinerHelperOption.push_back(Str);
    }));
cl::list<std::string> AArch64PostLegalizerCombinerHelperOnlyEnableOption(
    "aarch64postlegalizercombinerhelper-only-enable-rule",
    cl::desc("Disable all rules in the AArch64PostLegalizerCombinerHelper pass then re-enable the specified ones"),
    cl::Hidden,
    cl::cat(GICombinerOptionCategory),
    cl::callback([](const std::string &CommaSeparatedArg) {
      StringRef Str = CommaSeparatedArg;
      AArch64PostLegalizerCombinerHelperOption.push_back("*");
      do {
        auto X = Str.split(",");
        AArch64PostLegalizerCombinerHelperOption.push_back(("!" + X.first).str());
        Str = X.second;
      } while (!Str.empty());
    }));

bool AArch64GenPostLegalizerCombinerHelperRuleConfig::parseCommandLineOption() {
  for (StringRef Identifier : AArch64PostLegalizerCombinerHelperOption) {
    bool Enabled = Identifier.consume_front("!");
    if (Enabled && !setRuleEnabled(Identifier))
      return false;
    if (!Enabled && !setRuleDisabled(Identifier))
      return false;
  }
  return true;
}

bool AArch64GenPostLegalizerCombinerHelper::tryCombineAll(
    GISelChangeObserver &Observer,
    MachineInstr &MI,
    MachineIRBuilder &B,
    CombinerHelper &Helper) const {
  MachineBasicBlock *MBB = MI.getParent();
  MachineFunction *MF = MBB->getParent();
  MachineRegisterInfo &MRI = MF->getRegInfo();
  SmallVector<MachineInstr *, 8> MIs = {&MI};

  (void)MBB; (void)MF; (void)MRI; (void)RuleConfig;

  // Match data
  PreferredTuple MatchData2;
  std::function<void(MachineIRBuilder &)> MatchData3;
  InstructionStepsMatchInfo MatchData6;
  Register MatchData7;
  std::pair<Register, Register> MatchData8;
  std::tuple<unsigned, LLT, Register> MatchData9;
  Register MatchData10;
  std::function<void(MachineIRBuilder&, Register)> MatchData11;
  std::function<void(MachineIRBuilder &)> MatchData13;
  std::function<void(MachineIRBuilder &)> MatchData14;
  std::function<void(MachineIRBuilder &)> MatchData15;
  std::function<void(MachineIRBuilder &)> MatchData16;
  int64_t MatchData18;
  Register MatchData19;
  unsigned MatchData21;
  APInt MatchData23;
  Register MatchData29;
  Register MatchData30;
  Register MatchData31;
  Register MatchData32;
  PtrAddChain MatchData34;
  std::function<void(MachineIRBuilder &)> MatchData35;

  int Partition = -1;
  Partition = -1;
  switch (MIs[0]->getOpcode()) {
  case TargetOpcode::COPY: Partition = 0; break;
  case TargetOpcode::G_STORE: Partition = 1; break;
  case TargetOpcode::G_LOAD: Partition = 2; break;
  case TargetOpcode::G_SEXTLOAD: Partition = 3; break;
  case TargetOpcode::G_ZEXTLOAD: Partition = 4; break;
  case TargetOpcode::G_AND: Partition = 5; break;
  case TargetOpcode::G_SEXT_INREG: Partition = 6; break;
  case TargetOpcode::G_ANYEXT: Partition = 7; break;
  case TargetOpcode::G_OR: Partition = 8; break;
  case TargetOpcode::G_XOR: Partition = 9; break;
  case TargetOpcode::G_EXTRACT_VECTOR_ELT: Partition = 10; break;
  case TargetOpcode::G_MUL: Partition = 11; break;
  case TargetOpcode::G_ASHR: Partition = 12; break;
  case TargetOpcode::G_LSHR: Partition = 13; break;
  case TargetOpcode::G_ROTR: Partition = 14; break;
  case TargetOpcode::G_ROTL: Partition = 15; break;
  case TargetOpcode::G_ICMP: Partition = 16; break;
  case TargetOpcode::G_MERGE_VALUES: Partition = 17; break;
  case TargetOpcode::G_SELECT: Partition = 18; break;
  case TargetOpcode::G_ADD: Partition = 19; break;
  case TargetOpcode::G_SUB: Partition = 20; break;
  case TargetOpcode::G_SHL: Partition = 21; break;
  case TargetOpcode::G_PTR_ADD: Partition = 22; break;
  case TargetOpcode::G_SDIV: Partition = 23; break;
  case TargetOpcode::G_UDIV: Partition = 24; break;
  case TargetOpcode::G_SREM: Partition = 25; break;
  case TargetOpcode::G_UREM: Partition = 26; break;
  case TargetOpcode::G_INTTOPTR: Partition = 27; break;
  case TargetOpcode::G_PTRTOINT: Partition = 28; break;
  case TargetOpcode::G_FNEG: Partition = 29; break;
  }
  // Default case but without conflicting with potential default case in selection.
  if (Partition == -1) return false;
  if (Partition == 0 /* TargetOpcode::COPY */) {
    // Leaf name: copy_prop
    // Rule: copy_prop
    if (!RuleConfig->isRuleDisabled(0)) {
      if (1
          && [&]() {
           return Helper.matchCombineCopy(*MIs[0]); 
          return true;
      }()) {
        Helper.applyCombineCopy(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 1 /* TargetOpcode::G_STORE */) {
    // Leaf name: erase_undef_store
    // Rule: erase_undef_store
    if (!RuleConfig->isRuleDisabled(1)) {
      if (1
          && [&]() {
           return Helper.matchUndefStore(*MIs[0]); 
          return true;
      }()) {
        return Helper.eraseInst(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: split_store_zero_128
    // Rule: split_store_zero_128
    if (!RuleConfig->isRuleDisabled(36)) {
      if (1
          && [&]() {
           return matchSplitStoreZero128(*MIs[0], MRI); 
          return true;
      }()) {
        applySplitStoreZero128(*MIs[0], MRI, B, Observer); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 2 /* TargetOpcode::G_LOAD */) {
    // Leaf name: extending_loads
    // Rule: extending_loads
    if (!RuleConfig->isRuleDisabled(2)) {
      if (1
          && [&]() {
           return Helper.matchCombineExtendingLoads(*MIs[0], MatchData2); 
          return true;
      }()) {
        Helper.applyCombineExtendingLoads(*MIs[0], MatchData2); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 3 /* TargetOpcode::G_SEXTLOAD */) {
    // Leaf name: extending_loads
    // Rule: extending_loads
    if (!RuleConfig->isRuleDisabled(2)) {
      if (1
          && [&]() {
           return Helper.matchCombineExtendingLoads(*MIs[0], MatchData2); 
          return true;
      }()) {
        Helper.applyCombineExtendingLoads(*MIs[0], MatchData2); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 4 /* TargetOpcode::G_ZEXTLOAD */) {
    // Leaf name: extending_loads
    // Rule: extending_loads
    if (!RuleConfig->isRuleDisabled(2)) {
      if (1
          && [&]() {
           return Helper.matchCombineExtendingLoads(*MIs[0], MatchData2); 
          return true;
      }()) {
        Helper.applyCombineExtendingLoads(*MIs[0], MatchData2); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 5 /* TargetOpcode::G_AND */) {
    // Leaf name: load_and_mask
    // Rule: load_and_mask
    if (!RuleConfig->isRuleDisabled(3)) {
      if (1
          && [&]() {
           return Helper.matchCombineLoadWithAndMask(*MIs[0], MatchData3); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData3); 
        return true;
      }
    }
    // Leaf name: hoist_logic_op_with_same_opcode_hands
    // Rule: hoist_logic_op_with_same_opcode_hands
    if (!RuleConfig->isRuleDisabled(6)) {
      if (1
          && [&]() {
           return Helper.matchHoistLogicOpWithSameOpcodeHands(*MIs[0], MatchData6); 
          return true;
      }()) {
        Helper.applyBuildInstructionSteps(*MIs[0], MatchData6);
        return true;
      }
    }
    // Leaf name: redundant_and
    // Rule: redundant_and
    if (!RuleConfig->isRuleDisabled(7)) {
      if (1
          && [&]() {
           return Helper.matchRedundantAnd(*MIs[0], MatchData7); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData7); 
        return true;
      }
    }
    // Leaf name: bitfield_extract_from_and
    // Rule: bitfield_extract_from_and
    if (!RuleConfig->isRuleDisabled(14)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromAnd(*MIs[0], MatchData14); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData14); 
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(23)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData23); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData23); 
        return true;
      }
    }
    // Leaf name: binop_same_val
    // Rule: binop_same_val
    if (!RuleConfig->isRuleDisabled(26)) {
      if (1
          && [&]() {
           return Helper.matchBinOpSameVal(*MIs[0]); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: overlapping_and
    // Rule: overlapping_and
    if (!RuleConfig->isRuleDisabled(35)) {
      if (1
          && [&]() {
           return Helper.matchOverlappingAnd(*MIs[0], MatchData35); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData35); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 6 /* TargetOpcode::G_SEXT_INREG */) {
    // Leaf name: sext_trunc_sextload
    // Rule: sext_trunc_sextload
    if (!RuleConfig->isRuleDisabled(4)) {
      if (1
          && [&]() {
           return Helper.matchSextTruncSextLoad(*MIs[0]); 
          return true;
      }()) {
        Helper.applySextTruncSextLoad(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: redundant_sext_inreg
    // Rule: redundant_sext_inreg
    if (!RuleConfig->isRuleDisabled(12)) {
      if (1
          && [&]() {
           return Helper.matchRedundantSExtInReg(*MIs[0]); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: bitfield_extract_from_sext_inreg
    // Rule: bitfield_extract_from_sext_inreg
    if (!RuleConfig->isRuleDisabled(13)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromSExtInReg(*MIs[0], MatchData13); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData13); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 7 /* TargetOpcode::G_ANYEXT */) {
    // Leaf name: mutate_anyext_to_zext
    // Rule: mutate_anyext_to_zext
    if (!RuleConfig->isRuleDisabled(5)) {
      if (1
          && [&]() {
           return matchMutateAnyExtToZExt(*MIs[0], MRI); 
          return true;
      }()) {
        applyMutateAnyExtToZExt(*MIs[0], MRI, B, Observer); 
        return true;
      }
    }
    // Leaf name: anyext_trunc_fold
    // Rule: anyext_trunc_fold
    if (!RuleConfig->isRuleDisabled(31)) {
      if (1
          && [&]() {
           return Helper.matchCombineAnyExtTrunc(*MIs[0], MatchData31); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData31); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 8 /* TargetOpcode::G_OR */) {
    // Leaf name: hoist_logic_op_with_same_opcode_hands
    // Rule: hoist_logic_op_with_same_opcode_hands
    if (!RuleConfig->isRuleDisabled(6)) {
      if (1
          && [&]() {
           return Helper.matchHoistLogicOpWithSameOpcodeHands(*MIs[0], MatchData6); 
          return true;
      }()) {
        Helper.applyBuildInstructionSteps(*MIs[0], MatchData6);
        return true;
      }
    }
    // Leaf name: redundant_or
    // Rule: redundant_or
    if (!RuleConfig->isRuleDisabled(10)) {
      if (1
          && [&]() {
           return Helper.matchRedundantOr(*MIs[0], MatchData10); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData10); 
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(23)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData23); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData23); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: binop_same_val
    // Rule: binop_same_val
    if (!RuleConfig->isRuleDisabled(26)) {
      if (1
          && [&]() {
           return Helper.matchBinOpSameVal(*MIs[0]); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 9 /* TargetOpcode::G_XOR */) {
    // Leaf name: hoist_logic_op_with_same_opcode_hands
    // Rule: hoist_logic_op_with_same_opcode_hands
    if (!RuleConfig->isRuleDisabled(6)) {
      if (1
          && [&]() {
           return Helper.matchHoistLogicOpWithSameOpcodeHands(*MIs[0], MatchData6); 
          return true;
      }()) {
        Helper.applyBuildInstructionSteps(*MIs[0], MatchData6);
        return true;
      }
    }
    // Leaf name: xor_of_and_with_same_reg
    // Rule: xor_of_and_with_same_reg
    if (!RuleConfig->isRuleDisabled(8)) {
      if (1
          && [&]() {
           return Helper.matchXorOfAndWithSameReg(*MIs[0], MatchData8); 
          return true;
      }()) {
        Helper.applyXorOfAndWithSameReg(*MIs[0], MatchData8); 
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(23)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData23); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData23); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 10 /* TargetOpcode::G_EXTRACT_VECTOR_ELT */) {
    // Leaf name: extractvecelt_pairwise_add
    // Rule: extractvecelt_pairwise_add
    if (!RuleConfig->isRuleDisabled(9)) {
      if (1
          && [&]() {
           return matchExtractVecEltPairwiseAdd(*MIs[0], MRI, MatchData9); 
          return true;
      }()) {
        applyExtractVecEltPairwiseAdd(*MIs[0], MRI, B, MatchData9); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 11 /* TargetOpcode::G_MUL */) {
    // Leaf name: mul_const
    // Rule: mul_const
    if (!RuleConfig->isRuleDisabled(11)) {
      if (1
          && [&]() {
           return matchAArch64MulConstCombine(*MIs[0], MRI, MatchData11); 
          return true;
      }()) {
        applyAArch64MulConstCombine(*MIs[0], MRI, B, MatchData11); 
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(23)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData23); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData23); 
        return true;
      }
    }
    // Leaf name: binop_right_to_zero
    // Rule: binop_right_to_zero
    if (!RuleConfig->isRuleDisabled(28)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsZero(*MIs[0], 2); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 2); 
        return true;
      }
    }
    // Leaf name: right_identity_one
    // Rule: right_identity_one
    if (!RuleConfig->isRuleDisabled(33)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 12 /* TargetOpcode::G_ASHR */) {
    // Leaf name: bitfield_extract_from_shr
    // Rule: bitfield_extract_from_shr
    if (!RuleConfig->isRuleDisabled(15)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromShr(*MIs[0], MatchData15); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData15); 
        return true;
      }
    }
    // Leaf name: bitfield_extract_from_shr_and
    // Rule: bitfield_extract_from_shr_and
    if (!RuleConfig->isRuleDisabled(16)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromShrAnd(*MIs[0], MatchData16); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData16); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 13 /* TargetOpcode::G_LSHR */) {
    // Leaf name: bitfield_extract_from_shr
    // Rule: bitfield_extract_from_shr
    if (!RuleConfig->isRuleDisabled(15)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromShr(*MIs[0], MatchData15); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData15); 
        return true;
      }
    }
    // Leaf name: bitfield_extract_from_shr_and
    // Rule: bitfield_extract_from_shr_and
    if (!RuleConfig->isRuleDisabled(16)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromShrAnd(*MIs[0], MatchData16); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData16); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 14 /* TargetOpcode::G_ROTR */) {
    // Leaf name: rotate_out_of_range
    // Rule: rotate_out_of_range
    if (!RuleConfig->isRuleDisabled(17)) {
      if (1
          && [&]() {
           return Helper.matchRotateOutOfRange(*MIs[0]); 
          return true;
      }()) {
        Helper.applyRotateOutOfRange(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 15 /* TargetOpcode::G_ROTL */) {
    // Leaf name: rotate_out_of_range
    // Rule: rotate_out_of_range
    if (!RuleConfig->isRuleDisabled(17)) {
      if (1
          && [&]() {
           return Helper.matchRotateOutOfRange(*MIs[0]); 
          return true;
      }()) {
        Helper.applyRotateOutOfRange(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 16 /* TargetOpcode::G_ICMP */) {
    // Leaf name: icmp_to_true_false_known_bits
    // Rule: icmp_to_true_false_known_bits
    if (!RuleConfig->isRuleDisabled(18)) {
      if (1
          && [&]() {
           return Helper.matchICmpToTrueFalseKnownBits(*MIs[0], MatchData18); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData18); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 17 /* TargetOpcode::G_MERGE_VALUES */) {
    // Leaf name: merge_unmerge
    // Rule: merge_unmerge
    if (!RuleConfig->isRuleDisabled(19)) {
      if (1
          && [&]() {
           return Helper.matchCombineMergeUnmerge(*MIs[0], MatchData19); 
          return true;
      }()) {
        Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData19); 
        return true;
      }
    }
    // Leaf name: fold_merge_to_zext
    // Rule: fold_merge_to_zext
    if (!RuleConfig->isRuleDisabled(22)) {
      if (1
          && [&]() {
           return matchFoldMergeToZext(*MIs[0], MRI); 
          return true;
      }()) {
        applyFoldMergeToZext(*MIs[0], MRI, B, Observer); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 18 /* TargetOpcode::G_SELECT */) {
    // Leaf name: select_undef_cmp
    // Rule: select_undef_cmp
    if (!RuleConfig->isRuleDisabled(20)) {
      if (1
          && [&]() {
           return Helper.matchUndefSelectCmp(*MIs[0]); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 2); 
        return true;
      }
    }
    // Leaf name: select_constant_cmp
    // Rule: select_constant_cmp
    if (!RuleConfig->isRuleDisabled(21)) {
      if (1
          && [&]() {
           return Helper.matchConstantSelectCmp(*MIs[0], MatchData21); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], MatchData21); 
        return true;
      }
    }
    // Leaf name: select_same_val
    // Rule: select_same_val
    if (!RuleConfig->isRuleDisabled(24)) {
      if (1
          && [&]() {
           return Helper.matchSelectSameVal(*MIs[0]); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 2); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 19 /* TargetOpcode::G_ADD */) {
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(23)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData23); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData23); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 20 /* TargetOpcode::G_SUB */) {
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(23)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData23); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData23); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 21 /* TargetOpcode::G_SHL */) {
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 22 /* TargetOpcode::G_PTR_ADD */) {
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: ptr_add_immed_chain
    // Rule: ptr_add_immed_chain
    if (!RuleConfig->isRuleDisabled(34)) {
      if (1
          && [&]() {
           return Helper.matchPtrAddImmedChain(*MIs[0], MatchData34); 
          return true;
      }()) {
        Helper.applyPtrAddImmedChain(*MIs[0], MatchData34); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 23 /* TargetOpcode::G_SDIV */) {
    // Leaf name: binop_left_to_zero
    // Rule: binop_left_to_zero
    if (!RuleConfig->isRuleDisabled(27)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsZero(*MIs[0], 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 24 /* TargetOpcode::G_UDIV */) {
    // Leaf name: binop_left_to_zero
    // Rule: binop_left_to_zero
    if (!RuleConfig->isRuleDisabled(27)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsZero(*MIs[0], 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 25 /* TargetOpcode::G_SREM */) {
    // Leaf name: binop_left_to_zero
    // Rule: binop_left_to_zero
    if (!RuleConfig->isRuleDisabled(27)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsZero(*MIs[0], 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 26 /* TargetOpcode::G_UREM */) {
    // Leaf name: binop_left_to_zero
    // Rule: binop_left_to_zero
    if (!RuleConfig->isRuleDisabled(27)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsZero(*MIs[0], 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 27 /* TargetOpcode::G_INTTOPTR */) {
    // Leaf name: p2i_to_i2p
    // Rule: p2i_to_i2p
    if (!RuleConfig->isRuleDisabled(29)) {
      if (1
          && [&]() {
           return Helper.matchCombineI2PToP2I(*MIs[0], MatchData29); 
          return true;
      }()) {
        Helper.applyCombineI2PToP2I(*MIs[0], MatchData29); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 28 /* TargetOpcode::G_PTRTOINT */) {
    // Leaf name: i2p_to_p2i
    // Rule: i2p_to_p2i
    if (!RuleConfig->isRuleDisabled(30)) {
      if (1
          && [&]() {
           return Helper.matchCombineP2IToI2P(*MIs[0], MatchData30); 
          return true;
      }()) {
        Helper.applyCombineP2IToI2P(*MIs[0], MatchData30); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 29 /* TargetOpcode::G_FNEG */) {
    // Leaf name: fneg_fneg_fold
    // Rule: fneg_fneg_fold
    if (!RuleConfig->isRuleDisabled(32)) {
      if (1
          && [&]() {
           return Helper.matchCombineFNegOfFNeg(*MIs[0], MatchData32); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData32); 
        return true;
      }
    }
    return false;
  }

  return false;
}
#endif // ifdef AARCH64POSTLEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_CPP
