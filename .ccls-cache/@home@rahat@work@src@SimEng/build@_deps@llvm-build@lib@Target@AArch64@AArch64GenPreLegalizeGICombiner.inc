/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Global Combiner                                                            *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef AARCH64PRELEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_DEPS
#include "llvm/ADT/SparseBitVector.h"
namespace llvm {
extern cl::OptionCategory GICombinerOptionCategory;
} // end namespace llvm
#endif // ifdef AARCH64PRELEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_DEPS

#ifdef AARCH64PRELEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_H
class AArch64GenPreLegalizerCombinerHelperRuleConfig {
  SparseBitVector<> DisabledRules;

public:
  bool parseCommandLineOption();
  bool isRuleDisabled(unsigned ID) const;
  bool setRuleEnabled(StringRef RuleIdentifier);
  bool setRuleDisabled(StringRef RuleIdentifier);
};

class AArch64GenPreLegalizerCombinerHelper : public AArch64PreLegalizerCombinerHelperState {
  const AArch64GenPreLegalizerCombinerHelperRuleConfig *RuleConfig;

public:
  template <typename... Args>AArch64GenPreLegalizerCombinerHelper(const AArch64GenPreLegalizerCombinerHelperRuleConfig &RuleConfig, Args &&... args) : AArch64PreLegalizerCombinerHelperState(std::forward<Args>(args)...), RuleConfig(&RuleConfig) {}

  bool tryCombineAll(
    GISelChangeObserver &Observer,
    MachineInstr &MI,
    MachineIRBuilder &B) const;
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
  case 9:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "opy_prop", 8) != 0)
        break;
      return 0;	 // "copy_prop"
    case 'm':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ulo_by_2", 8) != 0)
        break;
      return 61;	 // "mulo_by_2"
    case 't':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "runc_shl", 8) != 0)
        break;
      return 57;	 // "trunc_shl"
    }
    break;
  case 10:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'i':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "2p_to_p2i", 9) != 0)
        break;
      return 25;	 // "i2p_to_p2i"
    case 'm':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ul_to_shl", 9) != 0)
        break;
      return 1;	 // "mul_to_shl"
    case 'p':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "2i_to_i2p", 9) != 0)
        break;
      return 24;	 // "p2i_to_i2p"
    }
    break;
  case 11:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "unmerge_cst", 11) != 0)
      break;
    return 52;	 // "unmerge_cst"
  case 12:	 // 4 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'e':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "xt_ext_fold", 11) != 0)
        break;
      return 47;	 // "ext_ext_fold"
    case 'm':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ulh_to_lshr", 11) != 0)
        break;
      return 78;	 // "mulh_to_lshr"
    case 'n':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ot_cmp_fold", 11) != 0)
        break;
      return 48;	 // "not_cmp_fold"
    case 'r':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "edundant_or", 11) != 0)
        break;
      return 42;	 // "redundant_or"
    }
    break;
  case 13:	 // 7 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "onstant_fold", 12) != 0)
        break;
      return 75;	 // "constant_fold"
    case 'l':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "oad_and_mask", 12) != 0)
        break;
      return 8;	 // "load_and_mask"
    case 'm':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "erge_unmerge", 12) != 0)
        break;
      return 55;	 // "merge_unmerge"
    case 'r':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "edundant_and", 12) != 0)
        break;
      return 40;	 // "redundant_and"
    case 'u':	 // 3 strings to match.
      switch (RuleIdentifier[1]) {
      default: break;
      case 'd':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "iv_by_const", 11) != 0)
          break;
        return 77;	 // "udiv_by_const"
      case 'n':	 // 2 strings to match.
        if (memcmp(RuleIdentifier.data()+2, "merge_", 6) != 0)
          break;
        switch (RuleIdentifier[8]) {
        default: break;
        case 'm':	 // 1 string to match.
          if (memcmp(RuleIdentifier.data()+9, "erge", 4) != 0)
            break;
          return 50;	 // "unmerge_merge"
        case 'u':	 // 1 string to match.
          if (memcmp(RuleIdentifier.data()+9, "ndef", 4) != 0)
            break;
          return 18;	 // "unmerge_undef"
        }
        break;
      }
      break;
    }
    break;
  case 14:	 // 8 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "inop_same_val", 13) != 0)
        break;
      return 21;	 // "binop_same_val"
    case 'c':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "onstant_fp_op", 13) != 0)
        break;
      return 58;	 // "constant_fp_op"
    case 'f':	 // 3 strings to match.
      switch (RuleIdentifier[1]) {
      default: break;
      case 'a':	 // 2 strings to match.
        if (memcmp(RuleIdentifier.data()+2, "bs_f", 4) != 0)
          break;
        switch (RuleIdentifier[6]) {
        default: break;
        case 'a':	 // 1 string to match.
          if (memcmp(RuleIdentifier.data()+7, "bs_fold", 7) != 0)
            break;
          return 51;	 // "fabs_fabs_fold"
        case 'n':	 // 1 string to match.
          if (memcmp(RuleIdentifier.data()+7, "eg_fold", 7) != 0)
            break;
          return 76;	 // "fabs_fneg_fold"
        }
        break;
      case 'n':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "eg_fneg_fold", 12) != 0)
          break;
        return 27;	 // "fneg_fneg_fold"
      }
      break;
    case 'm':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ul_by_neg_one", 13) != 0)
        break;
      return 3;	 // "mul_by_neg_one"
    case 'r':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "eassoc_ptradd", 13) != 0)
        break;
      return 32;	 // "reassoc_ptradd"
    case 't':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "runc_ext_fold", 13) != 0)
        break;
      return 56;	 // "trunc_ext_fold"
    }
    break;
  case 15:	 // 5 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'e':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "xtending_loads", 14) != 0)
        break;
      return 7;	 // "extending_loads"
    case 'l':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "oad_or_combine", 14) != 0)
        break;
      return 66;	 // "load_or_combine"
    case 'o':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "verlapping_and", 14) != 0)
        break;
      return 60;	 // "overlapping_and"
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "elect_same_val", 14) != 0)
        break;
      return 19;	 // "select_same_val"
    case 'z':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ext_trunc_fold", 14) != 0)
        break;
      return 44;	 // "zext_trunc_fold"
    }
    break;
  case 16:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "elect_undef_cmp", 15) != 0)
        break;
      return 38;	 // "select_undef_cmp"
    case 't':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "runcstore_merge", 15) != 0)
        break;
      return 67;	 // "truncstore_merge"
    case 'u':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ndef_to_fp_zero", 15) != 0)
        break;
      return 10;	 // "undef_to_fp_zero"
    }
    break;
  case 17:	 // 8 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'a':	 // 2 strings to match.
      switch (RuleIdentifier[1]) {
      default: break;
      case 'd':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "d_p2i_to_ptradd", 15) != 0)
          break;
        return 2;	 // "add_p2i_to_ptradd"
      case 'n':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "yext_trunc_fold", 15) != 0)
          break;
        return 26;	 // "anyext_trunc_fold"
      }
      break;
    case 'd':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "iv_rem_to_divrem", 16) != 0)
        break;
      return 68;	 // "div_rem_to_divrem"
    case 'e':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "rase_undef_store", 16) != 0)
        break;
      return 17;	 // "erase_undef_store"
    case 'p':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "tr_add_with_zero", 16) != 0)
        break;
      return 63;	 // "ptr_add_with_zero"
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "hift_immed_chain", 16) != 0)
        break;
      return 64;	 // "shift_immed_chain"
    case 'u':	 // 2 strings to match.
      switch (RuleIdentifier[1]) {
      default: break;
      case 'n':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "def_to_int_zero", 15) != 0)
          break;
        return 11;	 // "undef_to_int_zero"
      case 'r':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "em_pow2_to_mask", 15) != 0)
          break;
        return 43;	 // "urem_pow2_to_mask"
      }
      break;
    }
    break;
  case 18:	 // 4 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "inop_left_to_zero", 17) != 0)
        break;
      return 22;	 // "binop_left_to_zero"
    case 'f':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "old_global_offset", 17) != 0)
        break;
      return 91;	 // "fold_global_offset"
    case 'r':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ight_identity_one", 17) != 0)
        break;
      return 28;	 // "right_identity_one"
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ext_inreg_of_load", 17) != 0)
        break;
      return 35;	 // "sext_inreg_of_load"
    }
    break;
  case 19:	 // 7 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "inop_right_to_zero", 18) != 0)
        break;
      return 23;	 // "binop_right_to_zero"
    case 'c':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "onst_ptradd_to_i2p", 18) != 0)
        break;
      return 59;	 // "const_ptradd_to_i2p"
    case 'e':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "xtend_through_phis", 18) != 0)
        break;
      return 29;	 // "extend_through_phis"
    case 'p':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "tr_add_immed_chain", 18) != 0)
        break;
      return 33;	 // "ptr_add_immed_chain"
    case 'r':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ight_identity_zero", 18) != 0)
        break;
      return 20;	 // "right_identity_zero"
    case 's':	 // 2 strings to match.
      switch (RuleIdentifier[1]) {
      default: break;
      case 'e':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "lect_constant_cmp", 17) != 0)
          break;
        return 39;	 // "select_constant_cmp"
      case 'i':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+2, "mplify_add_to_sub", 17) != 0)
          break;
        return 30;	 // "simplify_add_to_sub"
      }
      break;
    }
    break;
  case 20:	 // 5 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "nd_or_disjoint_mask", 19) != 0)
        break;
      return 80;	 // "and_or_disjoint_mask"
    case 'i':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "cmp_redundant_trunc", 19) != 0)
        break;
      return 90;	 // "icmp_redundant_trunc"
    case 'r':	 // 2 strings to match.
      if (memcmp(RuleIdentifier.data()+1, "edu", 3) != 0)
        break;
      switch (RuleIdentifier[4]) {
      default: break;
      case 'c':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+5, "e_shl_of_extend", 15) != 0)
          break;
        return 36;	 // "reduce_shl_of_extend"
      case 'n':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+5, "dant_sext_inreg", 15) != 0)
          break;
        return 41;	 // "redundant_sext_inreg"
      }
      break;
    case 'u':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "nmerge_zext_to_zext", 19) != 0)
        break;
      return 54;	 // "unmerge_zext_to_zext"
    }
    break;
  case 21:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'f':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "constant_to_constant", 20) != 0)
        break;
      return 89;	 // "fconstant_to_constant"
    case 'u':	 // 2 strings to match.
      if (RuleIdentifier[1] != 'n')
        break;
      switch (RuleIdentifier[2]) {
      default: break;
      case 'd':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+3, "ef_to_negative_one", 18) != 0)
          break;
        return 12;	 // "undef_to_negative_one"
      case 'm':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+3, "erge_dead_to_trunc", 18) != 0)
          break;
        return 53;	 // "unmerge_dead_to_trunc"
      }
      break;
    }
    break;
  case 22:	 // 5 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'f':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "unnel_shift_to_rotate", 21) != 0)
        break;
      return 70;	 // "funnel_shift_to_rotate"
    case 'i':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "cmp_to_lhs_known_bits", 21) != 0)
        break;
      return 46;	 // "icmp_to_lhs_known_bits"
    case 'p':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ropagate_undef_any_op", 21) != 0)
        break;
      return 14;	 // "propagate_undef_any_op"
    case 'r':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "edundant_neg_operands", 21) != 0)
        break;
      return 79;	 // "redundant_neg_operands"
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "hl_ashr_to_sext_inreg", 21) != 0)
        break;
      return 34;	 // "shl_ashr_to_sext_inreg"
    }
    break;
  case 23:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "propagate_undef_all_ops", 23) != 0)
      break;
    return 15;	 // "propagate_undef_all_ops"
  case 24:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "inop_left_undef_to_zero", 23) != 0)
        break;
      return 13;	 // "binop_left_undef_to_zero"
    case 'n':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "arrow_binop_feeding_and", 23) != 0)
        break;
      return 37;	 // "narrow_binop_feeding_and"
    case 'x':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "or_of_and_with_same_reg", 23) != 0)
        break;
      return 62;	 // "xor_of_and_with_same_reg"
    }
    break;
  case 25:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 2 strings to match.
      if (memcmp(RuleIdentifier.data()+1, "itfield_extract_from_", 21) != 0)
        break;
      switch (RuleIdentifier[22]) {
      default: break;
      case 'a':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+23, "nd", 2) != 0)
          break;
        return 72;	 // "bitfield_extract_from_and"
      case 's':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+23, "hr", 2) != 0)
          break;
        return 73;	 // "bitfield_extract_from_shr"
      }
      break;
    case 'e':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "xtract_vec_elt_build_vec", 24) != 0)
        break;
      return 5;	 // "extract_vec_elt_build_vec"
    }
    break;
  case 26:	 // 2 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ombine_indexed_load_store", 25) != 0)
        break;
      return 9;	 // "combine_indexed_load_store"
    case 'f':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "unnel_shift_from_or_shift", 25) != 0)
        break;
      return 69;	 // "funnel_shift_from_or_shift"
    }
    break;
  case 28:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'o':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "pt_brcond_by_inverting_cond", 27) != 0)
        break;
      return 49;	 // "opt_brcond_by_inverting_cond"
    case 'p':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ropagate_undef_shuffle_mask", 27) != 0)
        break;
      return 16;	 // "propagate_undef_shuffle_mask"
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "hift_of_shifted_logic_chain", 27) != 0)
        break;
      return 65;	 // "shift_of_shifted_logic_chain"
    }
    break;
  case 29:	 // 2 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "itfield_extract_from_shr_and", 28) != 0)
        break;
      return 74;	 // "bitfield_extract_from_shr_and"
    case 'i':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "cmp_to_true_false_known_bits", 28) != 0)
        break;
      return 45;	 // "icmp_to_true_false_known_bits"
    }
    break;
  case 32:	 // 3 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'b':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "itfield_extract_from_sext_inreg", 31) != 0)
        break;
      return 71;	 // "bitfield_extract_from_sext_inreg"
    case 'c':	 // 2 strings to match.
      if (memcmp(RuleIdentifier.data()+1, "ombine_f", 8) != 0)
        break;
      switch (RuleIdentifier[9]) {
      default: break;
      case 'a':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+10, "dd_fmul_to_fmad_or_fma", 22) != 0)
          break;
        return 81;	 // "combine_fadd_fmul_to_fmad_or_fma"
      case 's':	 // 1 string to match.
        if (memcmp(RuleIdentifier.data()+10, "ub_fmul_to_fmad_or_fma", 22) != 0)
          break;
        return 85;	 // "combine_fsub_fmul_to_fmad_or_fma"
      }
      break;
    }
    break;
  case 34:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "extract_all_elts_from_build_vector", 34) != 0)
      break;
    return 6;	 // "extract_all_elts_from_build_vector"
  case 36:	 // 2 strings to match.
    if (memcmp(RuleIdentifier.data()+0, "combine_", 8) != 0)
      break;
    switch (RuleIdentifier[8]) {
    default: break;
    case 'f':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+9, "add_fma_fmul_to_fmad_or_fma", 27) != 0)
        break;
      return 83;	 // "combine_fadd_fma_fmul_to_fmad_or_fma"
    case 'i':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+9, "nsert_vec_elts_build_vector", 27) != 0)
        break;
      return 4;	 // "combine_insert_vec_elts_build_vector"
    }
    break;
  case 37:	 // 2 strings to match.
    switch (RuleIdentifier[0]) {
    default: break;
    case 'c':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "ombine_fsub_fneg_fmul_to_fmad_or_fma", 36) != 0)
        break;
      return 86;	 // "combine_fsub_fneg_fmul_to_fmad_or_fma"
    case 'h':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+1, "oist_logic_op_with_same_opcode_hands", 36) != 0)
        break;
      return 31;	 // "hoist_logic_op_with_same_opcode_hands"
    }
    break;
  case 38:	 // 2 strings to match.
    if (memcmp(RuleIdentifier.data()+0, "combine_f", 9) != 0)
      break;
    switch (RuleIdentifier[9]) {
    default: break;
    case 'a':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+10, "dd_fpext_fmul_to_fmad_or_fma", 28) != 0)
        break;
      return 82;	 // "combine_fadd_fpext_fmul_to_fmad_or_fma"
    case 's':	 // 1 string to match.
      if (memcmp(RuleIdentifier.data()+10, "ub_fpext_fmul_to_fmad_or_fma", 28) != 0)
        break;
      return 87;	 // "combine_fsub_fpext_fmul_to_fmad_or_fma"
    }
    break;
  case 42:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "combine_fadd_fpext_fma_fmul_to_fmad_or_fma", 42) != 0)
      break;
    return 84;	 // "combine_fadd_fpext_fma_fmul_to_fmad_or_fma"
  case 43:	 // 1 string to match.
    if (memcmp(RuleIdentifier.data()+0, "combine_fsub_fpext_fneg_fmul_to_fmad_or_fma", 43) != 0)
      break;
    return 88;	 // "combine_fsub_fpext_fneg_fmul_to_fmad_or_fma"
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
    return {{0, 92}};
  } else {
    const auto I = getRuleIdxForIdentifier(RangePair.first);
    if (!I.hasValue())
      return None;
    return {{*I, *I + 1}};
  }
  return None;
}

bool AArch64GenPreLegalizerCombinerHelperRuleConfig::setRuleEnabled(StringRef RuleIdentifier) {
  auto MaybeRange = getRuleRangeForIdentifier(RuleIdentifier);
  if (!MaybeRange.hasValue())
    return false;
  for (auto I = MaybeRange->first; I < MaybeRange->second; ++I)
    DisabledRules.reset(I);
  return true;
}

bool AArch64GenPreLegalizerCombinerHelperRuleConfig::setRuleDisabled(StringRef RuleIdentifier) {
  auto MaybeRange = getRuleRangeForIdentifier(RuleIdentifier);
  if (!MaybeRange.hasValue())
    return false;
  for (auto I = MaybeRange->first; I < MaybeRange->second; ++I)
    DisabledRules.set(I);
  return true;
}

bool AArch64GenPreLegalizerCombinerHelperRuleConfig::isRuleDisabled(unsigned RuleID) const {
  return DisabledRules.test(RuleID);
}
#endif // ifdef AARCH64PRELEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_H

#ifdef AARCH64PRELEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_CPP

std::vector<std::string> AArch64PreLegalizerCombinerHelperOption;
cl::list<std::string> AArch64PreLegalizerCombinerHelperDisableOption(
    "aarch64prelegalizercombinerhelper-disable-rule",
    cl::desc("Disable one or more combiner rules temporarily in the AArch64PreLegalizerCombinerHelper pass"),
    cl::CommaSeparated,
    cl::Hidden,
    cl::cat(GICombinerOptionCategory),
    cl::callback([](const std::string &Str) {
      AArch64PreLegalizerCombinerHelperOption.push_back(Str);
    }));
cl::list<std::string> AArch64PreLegalizerCombinerHelperOnlyEnableOption(
    "aarch64prelegalizercombinerhelper-only-enable-rule",
    cl::desc("Disable all rules in the AArch64PreLegalizerCombinerHelper pass then re-enable the specified ones"),
    cl::Hidden,
    cl::cat(GICombinerOptionCategory),
    cl::callback([](const std::string &CommaSeparatedArg) {
      StringRef Str = CommaSeparatedArg;
      AArch64PreLegalizerCombinerHelperOption.push_back("*");
      do {
        auto X = Str.split(",");
        AArch64PreLegalizerCombinerHelperOption.push_back(("!" + X.first).str());
        Str = X.second;
      } while (!Str.empty());
    }));

bool AArch64GenPreLegalizerCombinerHelperRuleConfig::parseCommandLineOption() {
  for (StringRef Identifier : AArch64PreLegalizerCombinerHelperOption) {
    bool Enabled = Identifier.consume_front("!");
    if (Enabled && !setRuleEnabled(Identifier))
      return false;
    if (!Enabled && !setRuleDisabled(Identifier))
      return false;
  }
  return true;
}

bool AArch64GenPreLegalizerCombinerHelper::tryCombineAll(
    GISelChangeObserver &Observer,
    MachineInstr &MI,
    MachineIRBuilder &B) const {
  MachineBasicBlock *MBB = MI.getParent();
  MachineFunction *MF = MBB->getParent();
  MachineRegisterInfo &MRI = MF->getRegInfo();
  SmallVector<MachineInstr *, 8> MIs = {&MI};

  (void)MBB; (void)MF; (void)MRI; (void)RuleConfig;

  // Match data
  unsigned MatchData1;
  std::pair<Register, bool> MatchData2;
  SmallVector<Register, 4> MatchData4;
  Register MatchData5;
  SmallVector<std::pair<Register, MachineInstr*>> MatchData6;
  PreferredTuple MatchData7;
  std::function<void(MachineIRBuilder &)> MatchData8;
  IndexedLoadStoreMatchInfo MatchData9;
  std::function<void(MachineIRBuilder &)> MatchData18;
  Register MatchData24;
  Register MatchData25;
  Register MatchData26;
  Register MatchData27;
  MachineInstr* MatchData29;
  std::tuple<Register, Register> MatchData30;
  InstructionStepsMatchInfo MatchData31;
  std::function<void(MachineIRBuilder &)> MatchData32;
  PtrAddChain MatchData33;
  std::tuple<Register, int64_t> MatchData34;
  std::tuple<Register, unsigned> MatchData35;
  RegisterImmPair MatchData36;
  std::function<void(MachineIRBuilder &)> MatchData37;
  unsigned MatchData39;
  Register MatchData40;
  Register MatchData42;
  Register MatchData44;
  int64_t MatchData45;
  std::function<void(MachineIRBuilder &)> MatchData46;
  std::tuple<Register, unsigned> MatchData47;
  SmallVector<Register, 4> MatchData48;
  MachineInstr * MatchData49;
  SmallVector<Register, 8> MatchData50;
  Register MatchData51;
  SmallVector<APInt, 8> MatchData52;
  Register MatchData55;
  std::pair<Register, unsigned> MatchData56;
  std::pair<Register, Register> MatchData57;
  Optional<APFloat> MatchData58;
  APInt MatchData59;
  std::function<void(MachineIRBuilder &)> MatchData60;
  std::function<void(MachineIRBuilder &)> MatchData61;
  std::pair<Register, Register> MatchData62;
  RegisterImmPair MatchData64;
  ShiftOfShiftedLogic MatchData65;
  std::function<void(MachineIRBuilder &)> MatchData66;
  MergeTruncStoresInfo MatchData67;
  MachineInstr * MatchData68;
  std::function<void(MachineIRBuilder &)> MatchData69;
  std::function<void(MachineIRBuilder &)> MatchData71;
  std::function<void(MachineIRBuilder &)> MatchData72;
  std::function<void(MachineIRBuilder &)> MatchData73;
  std::function<void(MachineIRBuilder &)> MatchData74;
  APInt MatchData75;
  std::function<void(MachineIRBuilder &)> MatchData76;
  std::function<void(MachineIRBuilder &)> MatchData79;
  std::function<void(MachineIRBuilder &)> MatchData80;
  std::function<void(MachineIRBuilder &)> MatchData81;
  std::function<void(MachineIRBuilder &)> MatchData82;
  std::function<void(MachineIRBuilder &)> MatchData83;
  std::function<void(MachineIRBuilder &)> MatchData84;
  std::function<void(MachineIRBuilder &)> MatchData85;
  std::function<void(MachineIRBuilder &)> MatchData86;
  std::function<void(MachineIRBuilder &)> MatchData87;
  std::function<void(MachineIRBuilder &)> MatchData88;
  Register MatchData90;
  std::pair<uint64_t, uint64_t> MatchData91;

  int Partition = -1;
  Partition = -1;
  switch (MIs[0]->getOpcode()) {
  case TargetOpcode::COPY: Partition = 0; break;
  case TargetOpcode::G_MUL: Partition = 1; break;
  case TargetOpcode::G_ADD: Partition = 2; break;
  case TargetOpcode::G_INSERT_VECTOR_ELT: Partition = 3; break;
  case TargetOpcode::G_EXTRACT_VECTOR_ELT: Partition = 4; break;
  case TargetOpcode::G_BUILD_VECTOR: Partition = 5; break;
  case TargetOpcode::G_LOAD: Partition = 6; break;
  case TargetOpcode::G_SEXTLOAD: Partition = 7; break;
  case TargetOpcode::G_ZEXTLOAD: Partition = 8; break;
  case TargetOpcode::G_AND: Partition = 9; break;
  case TargetOpcode::G_STORE: Partition = 10; break;
  case TargetOpcode::G_UITOFP: Partition = 11; break;
  case TargetOpcode::G_SITOFP: Partition = 12; break;
  case TargetOpcode::G_OR: Partition = 13; break;
  case TargetOpcode::G_SHL: Partition = 14; break;
  case TargetOpcode::G_FPTOSI: Partition = 15; break;
  case TargetOpcode::G_FPTOUI: Partition = 16; break;
  case TargetOpcode::G_SUB: Partition = 17; break;
  case TargetOpcode::G_XOR: Partition = 18; break;
  case TargetOpcode::G_TRUNC: Partition = 19; break;
  case TargetOpcode::G_SHUFFLE_VECTOR: Partition = 20; break;
  case TargetOpcode::G_UNMERGE_VALUES: Partition = 21; break;
  case TargetOpcode::G_SELECT: Partition = 22; break;
  case TargetOpcode::G_ASHR: Partition = 23; break;
  case TargetOpcode::G_LSHR: Partition = 24; break;
  case TargetOpcode::G_PTR_ADD: Partition = 25; break;
  case TargetOpcode::G_ROTL: Partition = 26; break;
  case TargetOpcode::G_ROTR: Partition = 27; break;
  case TargetOpcode::G_SDIV: Partition = 28; break;
  case TargetOpcode::G_UDIV: Partition = 29; break;
  case TargetOpcode::G_SREM: Partition = 30; break;
  case TargetOpcode::G_UREM: Partition = 31; break;
  case TargetOpcode::G_INTTOPTR: Partition = 32; break;
  case TargetOpcode::G_PTRTOINT: Partition = 33; break;
  case TargetOpcode::G_ANYEXT: Partition = 34; break;
  case TargetOpcode::G_FNEG: Partition = 35; break;
  case TargetOpcode::G_PHI: Partition = 36; break;
  case TargetOpcode::G_SEXT_INREG: Partition = 37; break;
  case TargetOpcode::G_ZEXT: Partition = 38; break;
  case TargetOpcode::G_ICMP: Partition = 39; break;
  case TargetOpcode::G_SEXT: Partition = 40; break;
  case TargetOpcode::G_BR: Partition = 41; break;
  case TargetOpcode::G_FABS: Partition = 42; break;
  case TargetOpcode::G_MERGE_VALUES: Partition = 43; break;
  case TargetOpcode::G_FPTRUNC: Partition = 44; break;
  case TargetOpcode::G_FSQRT: Partition = 45; break;
  case TargetOpcode::G_FLOG2: Partition = 46; break;
  case TargetOpcode::G_UMULO: Partition = 47; break;
  case TargetOpcode::G_SMULO: Partition = 48; break;
  case TargetOpcode::G_SSHLSAT: Partition = 49; break;
  case TargetOpcode::G_USHLSAT: Partition = 50; break;
  case TargetOpcode::G_FSHL: Partition = 51; break;
  case TargetOpcode::G_FSHR: Partition = 52; break;
  case TargetOpcode::G_UMULH: Partition = 53; break;
  case TargetOpcode::G_FADD: Partition = 54; break;
  case TargetOpcode::G_FSUB: Partition = 55; break;
  case TargetOpcode::G_FMUL: Partition = 56; break;
  case TargetOpcode::G_FDIV: Partition = 57; break;
  case TargetOpcode::G_FMAD: Partition = 58; break;
  case TargetOpcode::G_FMA: Partition = 59; break;
  case TargetOpcode::G_FCONSTANT: Partition = 60; break;
  case TargetOpcode::G_GLOBAL_VALUE: Partition = 61; break;
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
  if (Partition == 1 /* TargetOpcode::G_MUL */) {
    // Leaf name: mul_to_shl
    // Rule: mul_to_shl
    if (!RuleConfig->isRuleDisabled(1)) {
      if (1
          && [&]() {
           return Helper.matchCombineMulToShl(*MIs[0], MatchData1); 
          return true;
      }()) {
        Helper.applyCombineMulToShl(*MIs[0], MatchData1); 
        return true;
      }
    }
    // Leaf name: mul_by_neg_one
    // Rule: mul_by_neg_one
    if (!RuleConfig->isRuleDisabled(3)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), -1); 
          return true;
      }()) {
        Helper.applyCombineMulByNegativeOne(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: undef_to_int_zero
    // Rule: undef_to_int_zero
    if (!RuleConfig->isRuleDisabled(11)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], 0); 
        return true;
      }
    }
    // Leaf name: binop_right_to_zero
    // Rule: binop_right_to_zero
    if (!RuleConfig->isRuleDisabled(23)) {
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
    if (!RuleConfig->isRuleDisabled(28)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(75)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData75); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData75); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 2 /* TargetOpcode::G_ADD */) {
    // Leaf name: add_p2i_to_ptradd
    // Rule: add_p2i_to_ptradd
    if (!RuleConfig->isRuleDisabled(2)) {
      if (1
          && [&]() {
           return Helper.matchCombineAddP2IToPtrAdd(*MIs[0], MatchData2); 
          return true;
      }()) {
        Helper.applyCombineAddP2IToPtrAdd(*MIs[0], MatchData2); 
        return true;
      }
    }
    // Leaf name: propagate_undef_any_op
    // Rule: propagate_undef_any_op
    if (!RuleConfig->isRuleDisabled(14)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithUndef(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: simplify_add_to_sub
    // Rule: simplify_add_to_sub
    if (!RuleConfig->isRuleDisabled(30)) {
      if (1
          && [&]() {
           return Helper.matchSimplifyAddToSub(*MIs[0], MatchData30); 
          return true;
      }()) {
        Helper.applySimplifyAddToSub(*MIs[0], MatchData30);
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(75)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData75); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData75); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 3 /* TargetOpcode::G_INSERT_VECTOR_ELT */) {
    // Leaf name: combine_insert_vec_elts_build_vector
    // Rule: combine_insert_vec_elts_build_vector
    if (!RuleConfig->isRuleDisabled(4)) {
      if (1
          && [&]() {
           return Helper.matchCombineInsertVecElts(*MIs[0], MatchData4); 
          return true;
      }()) {
        Helper.applyCombineInsertVecElts(*MIs[0], MatchData4); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 4 /* TargetOpcode::G_EXTRACT_VECTOR_ELT */) {
    // Leaf name: extract_vec_elt_build_vec
    // Rule: extract_vec_elt_build_vec
    if (!RuleConfig->isRuleDisabled(5)) {
      if (1
          && [&]() {
           return Helper.matchExtractVecEltBuildVec(*MIs[0], MatchData5); 
          return true;
      }()) {
        Helper.applyExtractVecEltBuildVec(*MIs[0], MatchData5); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 5 /* TargetOpcode::G_BUILD_VECTOR */) {
    // Leaf name: extract_all_elts_from_build_vector
    // Rule: extract_all_elts_from_build_vector
    if (!RuleConfig->isRuleDisabled(6)) {
      if (1
          && [&]() {
           return Helper.matchExtractAllEltsFromBuildVector(*MIs[0], MatchData6); 
          return true;
      }()) {
        Helper.applyExtractAllEltsFromBuildVector(*MIs[0], MatchData6); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 6 /* TargetOpcode::G_LOAD */) {
    // Leaf name: extending_loads
    // Rule: extending_loads
    if (!RuleConfig->isRuleDisabled(7)) {
      if (1
          && [&]() {
           return Helper.matchCombineExtendingLoads(*MIs[0], MatchData7); 
          return true;
      }()) {
        Helper.applyCombineExtendingLoads(*MIs[0], MatchData7); 
        return true;
      }
    }
    // Leaf name: combine_indexed_load_store
    // Rule: combine_indexed_load_store
    if (!RuleConfig->isRuleDisabled(9)) {
      if (1
          && [&]() {
           return Helper.matchCombineIndexedLoadStore(*MIs[0], MatchData9); 
          return true;
      }()) {
        Helper.applyCombineIndexedLoadStore(*MIs[0], MatchData9); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 7 /* TargetOpcode::G_SEXTLOAD */) {
    // Leaf name: extending_loads
    // Rule: extending_loads
    if (!RuleConfig->isRuleDisabled(7)) {
      if (1
          && [&]() {
           return Helper.matchCombineExtendingLoads(*MIs[0], MatchData7); 
          return true;
      }()) {
        Helper.applyCombineExtendingLoads(*MIs[0], MatchData7); 
        return true;
      }
    }
    // Leaf name: combine_indexed_load_store
    // Rule: combine_indexed_load_store
    if (!RuleConfig->isRuleDisabled(9)) {
      if (1
          && [&]() {
           return Helper.matchCombineIndexedLoadStore(*MIs[0], MatchData9); 
          return true;
      }()) {
        Helper.applyCombineIndexedLoadStore(*MIs[0], MatchData9); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 8 /* TargetOpcode::G_ZEXTLOAD */) {
    // Leaf name: extending_loads
    // Rule: extending_loads
    if (!RuleConfig->isRuleDisabled(7)) {
      if (1
          && [&]() {
           return Helper.matchCombineExtendingLoads(*MIs[0], MatchData7); 
          return true;
      }()) {
        Helper.applyCombineExtendingLoads(*MIs[0], MatchData7); 
        return true;
      }
    }
    // Leaf name: combine_indexed_load_store
    // Rule: combine_indexed_load_store
    if (!RuleConfig->isRuleDisabled(9)) {
      if (1
          && [&]() {
           return Helper.matchCombineIndexedLoadStore(*MIs[0], MatchData9); 
          return true;
      }()) {
        Helper.applyCombineIndexedLoadStore(*MIs[0], MatchData9); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 9 /* TargetOpcode::G_AND */) {
    // Leaf name: load_and_mask
    // Rule: load_and_mask
    if (!RuleConfig->isRuleDisabled(8)) {
      if (1
          && [&]() {
           return Helper.matchCombineLoadWithAndMask(*MIs[0], MatchData8); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData8); 
        return true;
      }
    }
    // Leaf name: undef_to_int_zero
    // Rule: undef_to_int_zero
    if (!RuleConfig->isRuleDisabled(11)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], 0); 
        return true;
      }
    }
    // Leaf name: binop_same_val
    // Rule: binop_same_val
    if (!RuleConfig->isRuleDisabled(21)) {
      if (1
          && [&]() {
           return Helper.matchBinOpSameVal(*MIs[0]); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: hoist_logic_op_with_same_opcode_hands
    // Rule: hoist_logic_op_with_same_opcode_hands
    if (!RuleConfig->isRuleDisabled(31)) {
      if (1
          && [&]() {
           return Helper.matchHoistLogicOpWithSameOpcodeHands(*MIs[0], MatchData31); 
          return true;
      }()) {
        Helper.applyBuildInstructionSteps(*MIs[0], MatchData31);
        return true;
      }
    }
    // Leaf name: narrow_binop_feeding_and
    // Rule: narrow_binop_feeding_and
    if (!RuleConfig->isRuleDisabled(37)) {
      if (1
          && [&]() {
           return Helper.matchNarrowBinopFeedingAnd(*MIs[0], MatchData37); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData37); 
        return true;
      }
    }
    // Leaf name: redundant_and
    // Rule: redundant_and
    if (!RuleConfig->isRuleDisabled(40)) {
      if (1
          && [&]() {
           return Helper.matchRedundantAnd(*MIs[0], MatchData40); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData40); 
        return true;
      }
    }
    // Leaf name: overlapping_and
    // Rule: overlapping_and
    if (!RuleConfig->isRuleDisabled(60)) {
      if (1
          && [&]() {
           return Helper.matchOverlappingAnd(*MIs[0], MatchData60); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData60); 
        return true;
      }
    }
    // Leaf name: bitfield_extract_from_and
    // Rule: bitfield_extract_from_and
    if (!RuleConfig->isRuleDisabled(72)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromAnd(*MIs[0], MatchData72); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData72); 
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(75)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData75); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData75); 
        return true;
      }
    }
    // Leaf name: and_or_disjoint_mask
    // Rule: and_or_disjoint_mask
    if (!RuleConfig->isRuleDisabled(80)) {
      if (1
          && [&]() {
           return Helper.matchAndOrDisjointMask(*MIs[0], MatchData80); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData80); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 10 /* TargetOpcode::G_STORE */) {
    // Leaf name: combine_indexed_load_store
    // Rule: combine_indexed_load_store
    if (!RuleConfig->isRuleDisabled(9)) {
      if (1
          && [&]() {
           return Helper.matchCombineIndexedLoadStore(*MIs[0], MatchData9); 
          return true;
      }()) {
        Helper.applyCombineIndexedLoadStore(*MIs[0], MatchData9); 
        return true;
      }
    }
    // Leaf name: erase_undef_store
    // Rule: erase_undef_store
    if (!RuleConfig->isRuleDisabled(17)) {
      if (1
          && [&]() {
           return Helper.matchUndefStore(*MIs[0]); 
          return true;
      }()) {
        return Helper.eraseInst(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: truncstore_merge
    // Rule: truncstore_merge
    if (!RuleConfig->isRuleDisabled(67)) {
      if (1
          && [&]() {
           return Helper.matchTruncStoreMerge(*MIs[0], MatchData67); 
          return true;
      }()) {
        Helper.applyTruncStoreMerge(*MIs[0], MatchData67); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 11 /* TargetOpcode::G_UITOFP */) {
    // Leaf name: undef_to_fp_zero
    // Rule: undef_to_fp_zero
    if (!RuleConfig->isRuleDisabled(10)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithFConstant(*MIs[0], 0.0); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 12 /* TargetOpcode::G_SITOFP */) {
    // Leaf name: undef_to_fp_zero
    // Rule: undef_to_fp_zero
    if (!RuleConfig->isRuleDisabled(10)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithFConstant(*MIs[0], 0.0); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 13 /* TargetOpcode::G_OR */) {
    // Leaf name: undef_to_negative_one
    // Rule: undef_to_negative_one
    if (!RuleConfig->isRuleDisabled(12)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], -1); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
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
    if (!RuleConfig->isRuleDisabled(21)) {
      if (1
          && [&]() {
           return Helper.matchBinOpSameVal(*MIs[0]); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: hoist_logic_op_with_same_opcode_hands
    // Rule: hoist_logic_op_with_same_opcode_hands
    if (!RuleConfig->isRuleDisabled(31)) {
      if (1
          && [&]() {
           return Helper.matchHoistLogicOpWithSameOpcodeHands(*MIs[0], MatchData31); 
          return true;
      }()) {
        Helper.applyBuildInstructionSteps(*MIs[0], MatchData31);
        return true;
      }
    }
    // Leaf name: redundant_or
    // Rule: redundant_or
    if (!RuleConfig->isRuleDisabled(42)) {
      if (1
          && [&]() {
           return Helper.matchRedundantOr(*MIs[0], MatchData42); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData42); 
        return true;
      }
    }
    // Leaf name: load_or_combine
    // Rule: load_or_combine
    if (!RuleConfig->isRuleDisabled(66)) {
      if (1
          && [&]() {
           return Helper.matchLoadOrCombine(*MIs[0], MatchData66); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData66); 
        return true;
      }
    }
    // Leaf name: funnel_shift_from_or_shift
    // Rule: funnel_shift_from_or_shift
    if (!RuleConfig->isRuleDisabled(69)) {
      if (1
          && [&]() {
           return Helper.matchOrShiftToFunnelShift(*MIs[0], MatchData69); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData69); 
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(75)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData75); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData75); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 14 /* TargetOpcode::G_SHL */) {
    // Leaf name: binop_left_undef_to_zero
    // Rule: binop_left_undef_to_zero
    if (!RuleConfig->isRuleDisabled(13)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsUndef(*MIs[0], 1); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], 0); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: reduce_shl_of_extend
    // Rule: reduce_shl_of_extend
    if (!RuleConfig->isRuleDisabled(36)) {
      if (1
          && [&]() {
           return Helper.matchCombineShlOfExtend(*MIs[0], MatchData36); 
          return true;
      }()) {
        Helper.applyCombineShlOfExtend(*MIs[0], MatchData36); 
        return true;
      }
    }
    // Leaf name: shift_immed_chain
    // Rule: shift_immed_chain
    if (!RuleConfig->isRuleDisabled(64)) {
      if (1
          && [&]() {
           return Helper.matchShiftImmedChain(*MIs[0], MatchData64); 
          return true;
      }()) {
        Helper.applyShiftImmedChain(*MIs[0], MatchData64); 
        return true;
      }
    }
    // Leaf name: shift_of_shifted_logic_chain
    // Rule: shift_of_shifted_logic_chain
    if (!RuleConfig->isRuleDisabled(65)) {
      if (1
          && [&]() {
           return Helper.matchShiftOfShiftedLogic(*MIs[0], MatchData65); 
          return true;
      }()) {
        Helper.applyShiftOfShiftedLogic(*MIs[0], MatchData65); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 15 /* TargetOpcode::G_FPTOSI */) {
    // Leaf name: propagate_undef_any_op
    // Rule: propagate_undef_any_op
    if (!RuleConfig->isRuleDisabled(14)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithUndef(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 16 /* TargetOpcode::G_FPTOUI */) {
    // Leaf name: propagate_undef_any_op
    // Rule: propagate_undef_any_op
    if (!RuleConfig->isRuleDisabled(14)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithUndef(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 17 /* TargetOpcode::G_SUB */) {
    // Leaf name: propagate_undef_any_op
    // Rule: propagate_undef_any_op
    if (!RuleConfig->isRuleDisabled(14)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithUndef(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(75)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData75); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData75); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 18 /* TargetOpcode::G_XOR */) {
    // Leaf name: propagate_undef_any_op
    // Rule: propagate_undef_any_op
    if (!RuleConfig->isRuleDisabled(14)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithUndef(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: hoist_logic_op_with_same_opcode_hands
    // Rule: hoist_logic_op_with_same_opcode_hands
    if (!RuleConfig->isRuleDisabled(31)) {
      if (1
          && [&]() {
           return Helper.matchHoistLogicOpWithSameOpcodeHands(*MIs[0], MatchData31); 
          return true;
      }()) {
        Helper.applyBuildInstructionSteps(*MIs[0], MatchData31);
        return true;
      }
    }
    // Leaf name: not_cmp_fold
    // Rule: not_cmp_fold
    if (!RuleConfig->isRuleDisabled(48)) {
      if (1
          && [&]() {
           return Helper.matchNotCmp(*MIs[0], MatchData48); 
          return true;
      }()) {
        Helper.applyNotCmp(*MIs[0], MatchData48); 
        return true;
      }
    }
    // Leaf name: xor_of_and_with_same_reg
    // Rule: xor_of_and_with_same_reg
    if (!RuleConfig->isRuleDisabled(62)) {
      if (1
          && [&]() {
           return Helper.matchXorOfAndWithSameReg(*MIs[0], MatchData62); 
          return true;
      }()) {
        Helper.applyXorOfAndWithSameReg(*MIs[0], MatchData62); 
        return true;
      }
    }
    // Leaf name: constant_fold
    // Rule: constant_fold
    if (!RuleConfig->isRuleDisabled(75)) {
      if (1
          && [&]() {
           return Helper.matchConstantFold(*MIs[0], MatchData75); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData75); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 19 /* TargetOpcode::G_TRUNC */) {
    // Leaf name: propagate_undef_any_op
    // Rule: propagate_undef_any_op
    if (!RuleConfig->isRuleDisabled(14)) {
      if (1
          && [&]() {
           return Helper.matchAnyExplicitUseIsUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithUndef(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: trunc_ext_fold
    // Rule: trunc_ext_fold
    if (!RuleConfig->isRuleDisabled(56)) {
      if (1
          && [&]() {
           return Helper.matchCombineTruncOfExt(*MIs[0], MatchData56); 
          return true;
      }()) {
        Helper.applyCombineTruncOfExt(*MIs[0], MatchData56); 
        return true;
      }
    }
    // Leaf name: trunc_shl
    // Rule: trunc_shl
    if (!RuleConfig->isRuleDisabled(57)) {
      if (1
          && [&]() {
           return Helper.matchCombineTruncOfShl(*MIs[0], MatchData57); 
          return true;
      }()) {
        Helper.applyCombineTruncOfShl(*MIs[0], MatchData57); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 20 /* TargetOpcode::G_SHUFFLE_VECTOR */) {
    // Leaf name: propagate_undef_all_ops
    // Rule: propagate_undef_all_ops
    if (!RuleConfig->isRuleDisabled(15)) {
      if (1
          && [&]() {
           return Helper.matchAllExplicitUsesAreUndef(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithUndef(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: propagate_undef_shuffle_mask
    // Rule: propagate_undef_shuffle_mask
    if (!RuleConfig->isRuleDisabled(16)) {
      if (1
          && [&]() {
           return Helper.matchUndefShuffleVectorMask(*MIs[0]); 
          return true;
      }()) {
        Helper.replaceInstWithUndef(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 21 /* TargetOpcode::G_UNMERGE_VALUES */) {
    // Leaf name: unmerge_undef
    // Rule: unmerge_undef
    if (!RuleConfig->isRuleDisabled(18)) {
      if (1
          && [&]() {
           return Helper.matchCombineUnmergeUndef(*MIs[0], MatchData18); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData18); 
        return true;
      }
    }
    // Leaf name: unmerge_merge
    // Rule: unmerge_merge
    if (!RuleConfig->isRuleDisabled(50)) {
      if (1
          && [&]() {
           return Helper.matchCombineUnmergeMergeToPlainValues(*MIs[0], MatchData50); 
          return true;
      }()) {
        Helper.applyCombineUnmergeMergeToPlainValues(*MIs[0], MatchData50); 
        return true;
      }
    }
    // Leaf name: unmerge_cst
    // Rule: unmerge_cst
    if (!RuleConfig->isRuleDisabled(52)) {
      if (1
          && [&]() {
           return Helper.matchCombineUnmergeConstant(*MIs[0], MatchData52); 
          return true;
      }()) {
        Helper.applyCombineUnmergeConstant(*MIs[0], MatchData52); 
        return true;
      }
    }
    // Leaf name: unmerge_dead_to_trunc
    // Rule: unmerge_dead_to_trunc
    if (!RuleConfig->isRuleDisabled(53)) {
      if (1
          && [&]() {
           return Helper.matchCombineUnmergeWithDeadLanesToTrunc(*MIs[0]); 
          return true;
      }()) {
        Helper.applyCombineUnmergeWithDeadLanesToTrunc(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: unmerge_zext_to_zext
    // Rule: unmerge_zext_to_zext
    if (!RuleConfig->isRuleDisabled(54)) {
      if (1
          && [&]() {
           return Helper.matchCombineUnmergeZExtToZExt(*MIs[0]); 
          return true;
      }()) {
        Helper.applyCombineUnmergeZExtToZExt(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 22 /* TargetOpcode::G_SELECT */) {
    // Leaf name: select_same_val
    // Rule: select_same_val
    if (!RuleConfig->isRuleDisabled(19)) {
      if (1
          && [&]() {
           return Helper.matchSelectSameVal(*MIs[0]); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 2); 
        return true;
      }
    }
    // Leaf name: select_undef_cmp
    // Rule: select_undef_cmp
    if (!RuleConfig->isRuleDisabled(38)) {
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
    if (!RuleConfig->isRuleDisabled(39)) {
      if (1
          && [&]() {
           return Helper.matchConstantSelectCmp(*MIs[0], MatchData39); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], MatchData39); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 23 /* TargetOpcode::G_ASHR */) {
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: shl_ashr_to_sext_inreg
    // Rule: shl_ashr_to_sext_inreg
    if (!RuleConfig->isRuleDisabled(34)) {
      if (1
          && [&]() {
           return Helper.matchAshrShlToSextInreg(*MIs[0], MatchData34); 
          return true;
      }()) {
        Helper.applyAshShlToSextInreg(*MIs[0], MatchData34);
        return true;
      }
    }
    // Leaf name: shift_immed_chain
    // Rule: shift_immed_chain
    if (!RuleConfig->isRuleDisabled(64)) {
      if (1
          && [&]() {
           return Helper.matchShiftImmedChain(*MIs[0], MatchData64); 
          return true;
      }()) {
        Helper.applyShiftImmedChain(*MIs[0], MatchData64); 
        return true;
      }
    }
    // Leaf name: shift_of_shifted_logic_chain
    // Rule: shift_of_shifted_logic_chain
    if (!RuleConfig->isRuleDisabled(65)) {
      if (1
          && [&]() {
           return Helper.matchShiftOfShiftedLogic(*MIs[0], MatchData65); 
          return true;
      }()) {
        Helper.applyShiftOfShiftedLogic(*MIs[0], MatchData65); 
        return true;
      }
    }
    // Leaf name: bitfield_extract_from_shr
    // Rule: bitfield_extract_from_shr
    if (!RuleConfig->isRuleDisabled(73)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromShr(*MIs[0], MatchData73); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData73); 
        return true;
      }
    }
    // Leaf name: bitfield_extract_from_shr_and
    // Rule: bitfield_extract_from_shr_and
    if (!RuleConfig->isRuleDisabled(74)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromShrAnd(*MIs[0], MatchData74); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData74); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 24 /* TargetOpcode::G_LSHR */) {
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: shift_immed_chain
    // Rule: shift_immed_chain
    if (!RuleConfig->isRuleDisabled(64)) {
      if (1
          && [&]() {
           return Helper.matchShiftImmedChain(*MIs[0], MatchData64); 
          return true;
      }()) {
        Helper.applyShiftImmedChain(*MIs[0], MatchData64); 
        return true;
      }
    }
    // Leaf name: shift_of_shifted_logic_chain
    // Rule: shift_of_shifted_logic_chain
    if (!RuleConfig->isRuleDisabled(65)) {
      if (1
          && [&]() {
           return Helper.matchShiftOfShiftedLogic(*MIs[0], MatchData65); 
          return true;
      }()) {
        Helper.applyShiftOfShiftedLogic(*MIs[0], MatchData65); 
        return true;
      }
    }
    // Leaf name: bitfield_extract_from_shr
    // Rule: bitfield_extract_from_shr
    if (!RuleConfig->isRuleDisabled(73)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromShr(*MIs[0], MatchData73); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData73); 
        return true;
      }
    }
    // Leaf name: bitfield_extract_from_shr_and
    // Rule: bitfield_extract_from_shr_and
    if (!RuleConfig->isRuleDisabled(74)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromShrAnd(*MIs[0], MatchData74); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData74); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 25 /* TargetOpcode::G_PTR_ADD */) {
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
      if (1
          && [&]() {
           return Helper.matchConstantOp(MIs[0]->getOperand(2), 0); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: reassoc_ptradd
    // Rule: reassoc_ptradd
    if (!RuleConfig->isRuleDisabled(32)) {
      if (1
          && [&]() {
           return Helper.matchReassocPtrAdd(*MIs[0], MatchData32); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData32); 
        return true;
      }
    }
    // Leaf name: ptr_add_immed_chain
    // Rule: ptr_add_immed_chain
    if (!RuleConfig->isRuleDisabled(33)) {
      if (1
          && [&]() {
           return Helper.matchPtrAddImmedChain(*MIs[0], MatchData33); 
          return true;
      }()) {
        Helper.applyPtrAddImmedChain(*MIs[0], MatchData33); 
        return true;
      }
    }
    // Leaf name: const_ptradd_to_i2p
    // Rule: const_ptradd_to_i2p
    if (!RuleConfig->isRuleDisabled(59)) {
      if (1
          && [&]() {
           return Helper.matchCombineConstPtrAddToI2P(*MIs[0], MatchData59); 
          return true;
      }()) {
        Helper.applyCombineConstPtrAddToI2P(*MIs[0], MatchData59); 
        return true;
      }
    }
    // Leaf name: ptr_add_with_zero
    // Rule: ptr_add_with_zero
    if (!RuleConfig->isRuleDisabled(63)) {
      if (1
          && [&]() {
           return Helper.matchPtrAddZero(*MIs[0]); 
          return true;
      }()) {
        Helper.applyPtrAddZero(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 26 /* TargetOpcode::G_ROTL */) {
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
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
  if (Partition == 27 /* TargetOpcode::G_ROTR */) {
    // Leaf name: right_identity_zero
    // Rule: right_identity_zero
    if (!RuleConfig->isRuleDisabled(20)) {
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
  if (Partition == 28 /* TargetOpcode::G_SDIV */) {
    // Leaf name: binop_left_to_zero
    // Rule: binop_left_to_zero
    if (!RuleConfig->isRuleDisabled(22)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsZero(*MIs[0], 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: div_rem_to_divrem
    // Rule: div_rem_to_divrem
    if (!RuleConfig->isRuleDisabled(68)) {
      if (1
          && [&]() {
           return Helper.matchCombineDivRem(*MIs[0], MatchData68); 
          return true;
      }()) {
        Helper.applyCombineDivRem(*MIs[0], MatchData68); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 29 /* TargetOpcode::G_UDIV */) {
    // Leaf name: binop_left_to_zero
    // Rule: binop_left_to_zero
    if (!RuleConfig->isRuleDisabled(22)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsZero(*MIs[0], 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: div_rem_to_divrem
    // Rule: div_rem_to_divrem
    if (!RuleConfig->isRuleDisabled(68)) {
      if (1
          && [&]() {
           return Helper.matchCombineDivRem(*MIs[0], MatchData68); 
          return true;
      }()) {
        Helper.applyCombineDivRem(*MIs[0], MatchData68); 
        return true;
      }
    }
    // Leaf name: udiv_by_const
    // Rule: udiv_by_const
    if (!RuleConfig->isRuleDisabled(77)) {
      if (1
          && [&]() {
           return Helper.matchUDivByConst(*MIs[0]); 
          return true;
      }()) {
        Helper.applyUDivByConst(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 30 /* TargetOpcode::G_SREM */) {
    // Leaf name: binop_left_to_zero
    // Rule: binop_left_to_zero
    if (!RuleConfig->isRuleDisabled(22)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsZero(*MIs[0], 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: div_rem_to_divrem
    // Rule: div_rem_to_divrem
    if (!RuleConfig->isRuleDisabled(68)) {
      if (1
          && [&]() {
           return Helper.matchCombineDivRem(*MIs[0], MatchData68); 
          return true;
      }()) {
        Helper.applyCombineDivRem(*MIs[0], MatchData68); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 31 /* TargetOpcode::G_UREM */) {
    // Leaf name: binop_left_to_zero
    // Rule: binop_left_to_zero
    if (!RuleConfig->isRuleDisabled(22)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsZero(*MIs[0], 1); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithOperand(*MIs[0], 1); 
        return true;
      }
    }
    // Leaf name: urem_pow2_to_mask
    // Rule: urem_pow2_to_mask
    if (!RuleConfig->isRuleDisabled(43)) {
      if (1
          && [&]() {
           return Helper.matchOperandIsKnownToBeAPowerOfTwo(*MIs[0], 2); 
          return true;
      }()) {
        Helper.applySimplifyURemByPow2(*MIs[0]); 
        return true;
      }
    }
    // Leaf name: div_rem_to_divrem
    // Rule: div_rem_to_divrem
    if (!RuleConfig->isRuleDisabled(68)) {
      if (1
          && [&]() {
           return Helper.matchCombineDivRem(*MIs[0], MatchData68); 
          return true;
      }()) {
        Helper.applyCombineDivRem(*MIs[0], MatchData68); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 32 /* TargetOpcode::G_INTTOPTR */) {
    // Leaf name: p2i_to_i2p
    // Rule: p2i_to_i2p
    if (!RuleConfig->isRuleDisabled(24)) {
      if (1
          && [&]() {
           return Helper.matchCombineI2PToP2I(*MIs[0], MatchData24); 
          return true;
      }()) {
        Helper.applyCombineI2PToP2I(*MIs[0], MatchData24); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 33 /* TargetOpcode::G_PTRTOINT */) {
    // Leaf name: i2p_to_p2i
    // Rule: i2p_to_p2i
    if (!RuleConfig->isRuleDisabled(25)) {
      if (1
          && [&]() {
           return Helper.matchCombineP2IToI2P(*MIs[0], MatchData25); 
          return true;
      }()) {
        Helper.applyCombineP2IToI2P(*MIs[0], MatchData25); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 34 /* TargetOpcode::G_ANYEXT */) {
    // Leaf name: anyext_trunc_fold
    // Rule: anyext_trunc_fold
    if (!RuleConfig->isRuleDisabled(26)) {
      if (1
          && [&]() {
           return Helper.matchCombineAnyExtTrunc(*MIs[0], MatchData26); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData26); 
        return true;
      }
    }
    // Leaf name: ext_ext_fold
    // Rule: ext_ext_fold
    if (!RuleConfig->isRuleDisabled(47)) {
      if (1
          && [&]() {
           return Helper.matchCombineExtOfExt(*MIs[0], MatchData47); 
          return true;
      }()) {
        Helper.applyCombineExtOfExt(*MIs[0], MatchData47); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 35 /* TargetOpcode::G_FNEG */) {
    // Leaf name: fneg_fneg_fold
    // Rule: fneg_fneg_fold
    if (!RuleConfig->isRuleDisabled(27)) {
      if (1
          && [&]() {
           return Helper.matchCombineFNegOfFNeg(*MIs[0], MatchData27); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData27); 
        return true;
      }
    }
    // Leaf name: constant_fp_op
    // Rule: constant_fp_op
    if (!RuleConfig->isRuleDisabled(58)) {
      if (1
          && [&]() {
           return Helper.matchCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
          return true;
      }()) {
        Helper.applyCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 36 /* TargetOpcode::G_PHI */) {
    // Leaf name: extend_through_phis
    // Rule: extend_through_phis
    if (!RuleConfig->isRuleDisabled(29)) {
      if (1
          && [&]() {
           return Helper.matchExtendThroughPhis(*MIs[0], MatchData29); 
          return true;
      }()) {
        Helper.applyExtendThroughPhis(*MIs[0], MatchData29); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 37 /* TargetOpcode::G_SEXT_INREG */) {
    // Leaf name: sext_inreg_of_load
    // Rule: sext_inreg_of_load
    if (!RuleConfig->isRuleDisabled(35)) {
      if (1
          && [&]() {
           return Helper.matchSextInRegOfLoad(*MIs[0], MatchData35); 
          return true;
      }()) {
        Helper.applySextInRegOfLoad(*MIs[0], MatchData35); 
        return true;
      }
    }
    // Leaf name: redundant_sext_inreg
    // Rule: redundant_sext_inreg
    if (!RuleConfig->isRuleDisabled(41)) {
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
    if (!RuleConfig->isRuleDisabled(71)) {
      if (1
          && [&]() {
           return Helper.matchBitfieldExtractFromSExtInReg(*MIs[0], MatchData71); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData71); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 38 /* TargetOpcode::G_ZEXT */) {
    // Leaf name: zext_trunc_fold
    // Rule: zext_trunc_fold
    if (!RuleConfig->isRuleDisabled(44)) {
      if (1
          && [&]() {
           return Helper.matchCombineZextTrunc(*MIs[0], MatchData44); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData44); 
        return true;
      }
    }
    // Leaf name: ext_ext_fold
    // Rule: ext_ext_fold
    if (!RuleConfig->isRuleDisabled(47)) {
      if (1
          && [&]() {
           return Helper.matchCombineExtOfExt(*MIs[0], MatchData47); 
          return true;
      }()) {
        Helper.applyCombineExtOfExt(*MIs[0], MatchData47); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 39 /* TargetOpcode::G_ICMP */) {
    // Leaf name: icmp_to_true_false_known_bits
    // Rule: icmp_to_true_false_known_bits
    if (!RuleConfig->isRuleDisabled(45)) {
      if (1
          && [&]() {
           return Helper.matchICmpToTrueFalseKnownBits(*MIs[0], MatchData45); 
          return true;
      }()) {
        Helper.replaceInstWithConstant(*MIs[0], MatchData45); 
        return true;
      }
    }
    // Leaf name: icmp_to_lhs_known_bits
    // Rule: icmp_to_lhs_known_bits
    if (!RuleConfig->isRuleDisabled(46)) {
      if (1
          && [&]() {
           return Helper.matchICmpToLHSKnownBits(*MIs[0], MatchData46); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData46); 
        return true;
      }
    }
    // Leaf name: icmp_redundant_trunc
    // Rule: icmp_redundant_trunc
    if (!RuleConfig->isRuleDisabled(90)) {
      if (1
          && [&]() {
           return matchICmpRedundantTrunc(*MIs[0], MRI, Helper.getKnownBits(), MatchData90); 
          return true;
      }()) {
        applyICmpRedundantTrunc(*MIs[0], MRI, B, Observer, MatchData90); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 40 /* TargetOpcode::G_SEXT */) {
    // Leaf name: ext_ext_fold
    // Rule: ext_ext_fold
    if (!RuleConfig->isRuleDisabled(47)) {
      if (1
          && [&]() {
           return Helper.matchCombineExtOfExt(*MIs[0], MatchData47); 
          return true;
      }()) {
        Helper.applyCombineExtOfExt(*MIs[0], MatchData47); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 41 /* TargetOpcode::G_BR */) {
    // Leaf name: opt_brcond_by_inverting_cond
    // Rule: opt_brcond_by_inverting_cond
    if (!RuleConfig->isRuleDisabled(49)) {
      if (1
          && [&]() {
           return Helper.matchOptBrCondByInvertingCond(*MIs[0], MatchData49); 
          return true;
      }()) {
        Helper.applyOptBrCondByInvertingCond(*MIs[0], MatchData49); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 42 /* TargetOpcode::G_FABS */) {
    // Leaf name: fabs_fabs_fold
    // Rule: fabs_fabs_fold
    if (!RuleConfig->isRuleDisabled(51)) {
      if (1
          && [&]() {
           return Helper.matchCombineFAbsOfFAbs(*MIs[0], MatchData51); 
          return true;
      }()) {
        return Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData51); 
        return true;
      }
    }
    // Leaf name: constant_fp_op
    // Rule: constant_fp_op
    if (!RuleConfig->isRuleDisabled(58)) {
      if (1
          && [&]() {
           return Helper.matchCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
          return true;
      }()) {
        Helper.applyCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
        return true;
      }
    }
    // Leaf name: fabs_fneg_fold
    // Rule: fabs_fneg_fold
    if (!RuleConfig->isRuleDisabled(76)) {
      if (1
          && [&]() {
           return Helper.matchCombineFAbsOfFNeg(*MIs[0], MatchData76); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData76); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 43 /* TargetOpcode::G_MERGE_VALUES */) {
    // Leaf name: merge_unmerge
    // Rule: merge_unmerge
    if (!RuleConfig->isRuleDisabled(55)) {
      if (1
          && [&]() {
           return Helper.matchCombineMergeUnmerge(*MIs[0], MatchData55); 
          return true;
      }()) {
        Helper.replaceSingleDefInstWithReg(*MIs[0], MatchData55); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 44 /* TargetOpcode::G_FPTRUNC */) {
    // Leaf name: constant_fp_op
    // Rule: constant_fp_op
    if (!RuleConfig->isRuleDisabled(58)) {
      if (1
          && [&]() {
           return Helper.matchCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
          return true;
      }()) {
        Helper.applyCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 45 /* TargetOpcode::G_FSQRT */) {
    // Leaf name: constant_fp_op
    // Rule: constant_fp_op
    if (!RuleConfig->isRuleDisabled(58)) {
      if (1
          && [&]() {
           return Helper.matchCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
          return true;
      }()) {
        Helper.applyCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 46 /* TargetOpcode::G_FLOG2 */) {
    // Leaf name: constant_fp_op
    // Rule: constant_fp_op
    if (!RuleConfig->isRuleDisabled(58)) {
      if (1
          && [&]() {
           return Helper.matchCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
          return true;
      }()) {
        Helper.applyCombineConstantFoldFpUnary(*MIs[0], MatchData58); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 47 /* TargetOpcode::G_UMULO */) {
    // Leaf name: mulo_by_2
    // Rule: mulo_by_2
    if (!RuleConfig->isRuleDisabled(61)) {
      if (1
          && [&]() {
           return Helper.matchMulOBy2(*MIs[0], MatchData61); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData61); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 48 /* TargetOpcode::G_SMULO */) {
    // Leaf name: mulo_by_2
    // Rule: mulo_by_2
    if (!RuleConfig->isRuleDisabled(61)) {
      if (1
          && [&]() {
           return Helper.matchMulOBy2(*MIs[0], MatchData61); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData61); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 49 /* TargetOpcode::G_SSHLSAT */) {
    // Leaf name: shift_immed_chain
    // Rule: shift_immed_chain
    if (!RuleConfig->isRuleDisabled(64)) {
      if (1
          && [&]() {
           return Helper.matchShiftImmedChain(*MIs[0], MatchData64); 
          return true;
      }()) {
        Helper.applyShiftImmedChain(*MIs[0], MatchData64); 
        return true;
      }
    }
    // Leaf name: shift_of_shifted_logic_chain
    // Rule: shift_of_shifted_logic_chain
    if (!RuleConfig->isRuleDisabled(65)) {
      if (1
          && [&]() {
           return Helper.matchShiftOfShiftedLogic(*MIs[0], MatchData65); 
          return true;
      }()) {
        Helper.applyShiftOfShiftedLogic(*MIs[0], MatchData65); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 50 /* TargetOpcode::G_USHLSAT */) {
    // Leaf name: shift_immed_chain
    // Rule: shift_immed_chain
    if (!RuleConfig->isRuleDisabled(64)) {
      if (1
          && [&]() {
           return Helper.matchShiftImmedChain(*MIs[0], MatchData64); 
          return true;
      }()) {
        Helper.applyShiftImmedChain(*MIs[0], MatchData64); 
        return true;
      }
    }
    // Leaf name: shift_of_shifted_logic_chain
    // Rule: shift_of_shifted_logic_chain
    if (!RuleConfig->isRuleDisabled(65)) {
      if (1
          && [&]() {
           return Helper.matchShiftOfShiftedLogic(*MIs[0], MatchData65); 
          return true;
      }()) {
        Helper.applyShiftOfShiftedLogic(*MIs[0], MatchData65); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 51 /* TargetOpcode::G_FSHL */) {
    // Leaf name: funnel_shift_to_rotate
    // Rule: funnel_shift_to_rotate
    if (!RuleConfig->isRuleDisabled(70)) {
      if (1
          && [&]() {
           return Helper.matchFunnelShiftToRotate(*MIs[0]); 
          return true;
      }()) {
        Helper.applyFunnelShiftToRotate(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 52 /* TargetOpcode::G_FSHR */) {
    // Leaf name: funnel_shift_to_rotate
    // Rule: funnel_shift_to_rotate
    if (!RuleConfig->isRuleDisabled(70)) {
      if (1
          && [&]() {
           return Helper.matchFunnelShiftToRotate(*MIs[0]); 
          return true;
      }()) {
        Helper.applyFunnelShiftToRotate(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 53 /* TargetOpcode::G_UMULH */) {
    // Leaf name: mulh_to_lshr
    // Rule: mulh_to_lshr
    if (!RuleConfig->isRuleDisabled(78)) {
      if (1
          && [&]() {
           return Helper.matchUMulHToLShr(*MIs[0]); 
          return true;
      }()) {
        Helper.applyUMulHToLShr(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 54 /* TargetOpcode::G_FADD */) {
    // Leaf name: redundant_neg_operands
    // Rule: redundant_neg_operands
    if (!RuleConfig->isRuleDisabled(79)) {
      if (1
          && [&]() {
           return Helper.matchRedundantNegOperands(*MIs[0], MatchData79); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData79); 
        return true;
      }
    }
    // Leaf name: combine_fadd_fmul_to_fmad_or_fma
    // Rule: combine_fadd_fmul_to_fmad_or_fma
    if (!RuleConfig->isRuleDisabled(81)) {
      if (1
          && [&]() {
           return Helper.matchCombineFAddFMulToFMadOrFMA(*MIs[0],
                                                              MatchData81); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData81); 
        return true;
      }
    }
    // Leaf name: combine_fadd_fpext_fmul_to_fmad_or_fma
    // Rule: combine_fadd_fpext_fmul_to_fmad_or_fma
    if (!RuleConfig->isRuleDisabled(82)) {
      if (1
          && [&]() {
           return Helper.matchCombineFAddFpExtFMulToFMadOrFMA(*MIs[0],
                                                                   MatchData82); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData82); 
        return true;
      }
    }
    // Leaf name: combine_fadd_fma_fmul_to_fmad_or_fma
    // Rule: combine_fadd_fma_fmul_to_fmad_or_fma
    if (!RuleConfig->isRuleDisabled(83)) {
      if (1
          && [&]() {
           return Helper.matchCombineFAddFMAFMulToFMadOrFMA(*MIs[0],
                                                                 MatchData83); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData83); 
        return true;
      }
    }
    // Leaf name: combine_fadd_fpext_fma_fmul_to_fmad_or_fma
    // Rule: combine_fadd_fpext_fma_fmul_to_fmad_or_fma
    if (!RuleConfig->isRuleDisabled(84)) {
      if (1
          && [&]() {
           return Helper.matchCombineFAddFpExtFMulToFMadOrFMAAggressive(
                                                      *MIs[0], MatchData84); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData84); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 55 /* TargetOpcode::G_FSUB */) {
    // Leaf name: redundant_neg_operands
    // Rule: redundant_neg_operands
    if (!RuleConfig->isRuleDisabled(79)) {
      if (1
          && [&]() {
           return Helper.matchRedundantNegOperands(*MIs[0], MatchData79); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData79); 
        return true;
      }
    }
    // Leaf name: combine_fsub_fmul_to_fmad_or_fma
    // Rule: combine_fsub_fmul_to_fmad_or_fma
    if (!RuleConfig->isRuleDisabled(85)) {
      if (1
          && [&]() {
           return Helper.matchCombineFSubFMulToFMadOrFMA(*MIs[0],
                                                              MatchData85); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData85); 
        return true;
      }
    }
    // Leaf name: combine_fsub_fneg_fmul_to_fmad_or_fma
    // Rule: combine_fsub_fneg_fmul_to_fmad_or_fma
    if (!RuleConfig->isRuleDisabled(86)) {
      if (1
          && [&]() {
           return Helper.matchCombineFSubFNegFMulToFMadOrFMA(*MIs[0],
                                                                  MatchData86); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData86); 
        return true;
      }
    }
    // Leaf name: combine_fsub_fpext_fmul_to_fmad_or_fma
    // Rule: combine_fsub_fpext_fmul_to_fmad_or_fma
    if (!RuleConfig->isRuleDisabled(87)) {
      if (1
          && [&]() {
           return Helper.matchCombineFSubFpExtFMulToFMadOrFMA(*MIs[0],
                                                                   MatchData87); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData87); 
        return true;
      }
    }
    // Leaf name: combine_fsub_fpext_fneg_fmul_to_fmad_or_fma
    // Rule: combine_fsub_fpext_fneg_fmul_to_fmad_or_fma
    if (!RuleConfig->isRuleDisabled(88)) {
      if (1
          && [&]() {
           return Helper.matchCombineFSubFpExtFNegFMulToFMadOrFMA(
                                                *MIs[0], MatchData88); 
          return true;
      }()) {
        Helper.applyBuildFn(*MIs[0], MatchData88); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 56 /* TargetOpcode::G_FMUL */) {
    // Leaf name: redundant_neg_operands
    // Rule: redundant_neg_operands
    if (!RuleConfig->isRuleDisabled(79)) {
      if (1
          && [&]() {
           return Helper.matchRedundantNegOperands(*MIs[0], MatchData79); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData79); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 57 /* TargetOpcode::G_FDIV */) {
    // Leaf name: redundant_neg_operands
    // Rule: redundant_neg_operands
    if (!RuleConfig->isRuleDisabled(79)) {
      if (1
          && [&]() {
           return Helper.matchRedundantNegOperands(*MIs[0], MatchData79); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData79); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 58 /* TargetOpcode::G_FMAD */) {
    // Leaf name: redundant_neg_operands
    // Rule: redundant_neg_operands
    if (!RuleConfig->isRuleDisabled(79)) {
      if (1
          && [&]() {
           return Helper.matchRedundantNegOperands(*MIs[0], MatchData79); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData79); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 59 /* TargetOpcode::G_FMA */) {
    // Leaf name: redundant_neg_operands
    // Rule: redundant_neg_operands
    if (!RuleConfig->isRuleDisabled(79)) {
      if (1
          && [&]() {
           return Helper.matchRedundantNegOperands(*MIs[0], MatchData79); 
          return true;
      }()) {
        Helper.applyBuildFnNoErase(*MIs[0], MatchData79); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 60 /* TargetOpcode::G_FCONSTANT */) {
    // Leaf name: fconstant_to_constant
    // Rule: fconstant_to_constant
    if (!RuleConfig->isRuleDisabled(89)) {
      if (1
          && [&]() {
           return matchFConstantToConstant(*MIs[0], MRI); 
          return true;
      }()) {
        applyFConstantToConstant(*MIs[0]); 
        return true;
      }
    }
    return false;
  }
  if (Partition == 61 /* TargetOpcode::G_GLOBAL_VALUE */) {
    // Leaf name: fold_global_offset
    // Rule: fold_global_offset
    if (!RuleConfig->isRuleDisabled(91)) {
      if (1
          && [&]() {
           return matchFoldGlobalOffset(*MIs[0], MRI, MatchData91); 
          return true;
      }()) {
         return applyFoldGlobalOffset(*MIs[0], MRI, B, Observer, MatchData91);
        return true;
      }
    }
    return false;
  }

  return false;
}
#endif // ifdef AARCH64PRELEGALIZERCOMBINERHELPER_GENCOMBINERHELPER_CPP
