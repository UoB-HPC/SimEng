// Temporary; until execute has been verified to work correctly.
#ifndef NDEBUG
#include <iostream>
#endif

#include "simeng/arch/aarch64/helpers/arithmetic.hh"
#include "simeng/arch/aarch64/helpers/auxiliaryFunctions.hh"
#include "simeng/arch/aarch64/helpers/bitmanip.hh"
#include "simeng/arch/aarch64/helpers/comparison.hh"
#include "simeng/arch/aarch64/helpers/conditional.hh"
#include "simeng/arch/aarch64/helpers/divide.hh"
#include "simeng/arch/aarch64/helpers/float.hh"
#include "simeng/arch/aarch64/helpers/load.hh"
#include "simeng/arch/aarch64/helpers/logical.hh"
#include "simeng/arch/aarch64/helpers/multiply.hh"
#include "simeng/arch/aarch64/helpers/neon.hh"
#include "simeng/arch/aarch64/helpers/store.hh"
#include "simeng/arch/aarch64/helpers/sve.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

void Instruction::executionNYI() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::ExecutionNotYetImplemented;
  return;
}

void Instruction::executionINV() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::EncodingUnallocated;
}

void Instruction::execute() {
  assert(!executed_ && "Attempted to execute an instruction more than once");
  assert(
      canExecute() &&
      "Attempted to execute an instruction before all operands were provided");

  const uint16_t VL_bits = architecture_.getVectorLength();
  executed_ = true;
  switch (metadata.opcode) {
    case Opcode::AArch64_ABS_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABS_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABS_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABS_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABSv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABSv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABSv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABSv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABSv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABSv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABSv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ABSv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADCSWr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADCSXr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADCWr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADCXr: {  // adc xd, xn, xm
      auto [result, nzcv] = arithmeticHelp::addCarry_3ops<uint64_t>(operands);
      results[0] = result;
      break;
    }
    case Opcode::AArch64_ADDHNv2i64_v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDHNv2i64_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDHNv4i32_v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDHNv4i32_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDHNv8i16_v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDHNv8i16_v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDPL_XXI: {  // addpl xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = static_cast<int64_t>(metadata.operands[2].imm);
      // convert PL from VL_bits
      const uint64_t PL = VL_bits / 64;
      results[0] = x + (PL * y);
      break;
    }
    case Opcode::AArch64_ADDPv16i8: {  // addp vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecAddp_3ops<uint8_t, 16>(operands);
      break;
    }
    case Opcode::AArch64_ADDPv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDPv2i64: {  // addp vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecAddp_3ops<uint64_t, 2>(operands);
      break;
    }
    case Opcode::AArch64_ADDPv2i64p: {  // addp dd, vn.2d
      results[0] = neonHelp::vecSumElems_2ops<uint64_t, 2>(operands);
      break;
    }
    case Opcode::AArch64_ADDPv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDPv4i32: {  // addp vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecAddp_3ops<uint32_t, 4>(operands);
      break;
    }
    case Opcode::AArch64_ADDPv8i16: {  // addp vd.8h, vn.8h, vm.8h
      results[0] = neonHelp::vecAddp_3ops<uint16_t, 8>(operands);
      break;
    }
    case Opcode::AArch64_ADDPv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDSWri: {  // adds wd, wn, #imm{, shift}
      auto [result, nzcv] =
          arithmeticHelp::addShift_imm<uint32_t>(operands, metadata, true);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ADDSWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDSWrs: {  // adds wd, wn, wm{, shift}
      auto [result, nzcv] =
          arithmeticHelp::addShift_3ops<uint32_t>(operands, metadata, true);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ADDSWrx: {  // adds wd, wn, wm{, extend {#amount}}
      auto [result, nzcv] =
          arithmeticHelp::addExtend_3ops<uint32_t>(operands, metadata, true);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ADDSXri: {  // adds xd, xn, #imm{, shift}
      auto [result, nzcv] =
          arithmeticHelp::addShift_imm<uint64_t>(operands, metadata, true);
      results[0] = nzcv;
      results[1] = result;
      break;
    }
    case Opcode::AArch64_ADDSXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDSXrs: {  // adds xd, xn, xm{, shift}
      auto [result, nzcv] =
          arithmeticHelp::addShift_3ops<uint64_t>(operands, metadata, true);
      results[0] = nzcv;
      results[1] = result;
      break;
    }
    case Opcode::AArch64_ADDSXrx:      // adds xd, xn, wm{, extend {#amount}}
    case Opcode::AArch64_ADDSXrx64: {  // adds xd, xn, xm{, extend {#amount}}
      auto [result, nzcv] =
          arithmeticHelp::addExtend_3ops<uint64_t>(operands, metadata, true);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ADDVL_XXI: {  // addvl xd, xn, #imm
      auto x = operands[0].get<uint64_t>();
      auto y = static_cast<int64_t>(metadata.operands[2].imm);
      // convert VL from LEN (number of 128-bits) to bytes
      const uint64_t VL = VL_bits / 8;
      results[0] = x + (VL * y);
      break;
    }
    case Opcode::AArch64_ADDVv16i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDVv8i8v: {  // addv bd, vn.8b
      results[0] = neonHelp::vecSumElems_2ops<uint8_t, 8>(operands);
      break;
    }
    case Opcode::AArch64_ADDWri: {  // add wd, wn, #imm{, shift}
      auto [result, nzcv] =
          arithmeticHelp::addShift_imm<uint32_t>(operands, metadata, false);
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ADDWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDWrs: {  // add wd, wn, wm{, shift #amount}
      auto [result, nzcv] =
          arithmeticHelp::addShift_3ops<uint32_t>(operands, metadata, false);
      results[0] = static_cast<uint64_t>(result);
      break;
    }
    case Opcode::AArch64_ADDWrx: {  // add wd, wn, wm{, extend #amount}
      auto [result, nzcv] =
          arithmeticHelp::addExtend_3ops<uint32_t>(operands, metadata, false);
      results[0] = result;
      break;
    }
    case Opcode::AArch64_ADDXri: {  // add xd, xn, #imm{, shift}
      auto [result, nzcv] =
          arithmeticHelp::addShift_imm<uint64_t>(operands, metadata, false);
      results[0] = RegisterValue(result);
      break;
    }
    case Opcode::AArch64_ADDXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDXrs: {  // add xd, xn, xm, {shift #amount}
      auto [result, nzcv] =
          arithmeticHelp::addShift_3ops<uint64_t>(operands, metadata, false);
      results[0] = result;
      break;
    }
    case Opcode::AArch64_ADDXrx:      // add xd, xn, wm{, extend {#amount}}
    case Opcode::AArch64_ADDXrx64: {  // add xd, xn, xm{, extend {#amount}}
      auto [result, nzcv] =
          arithmeticHelp::addExtend_3ops<uint64_t>(operands, metadata, false);
      results[0] = result;
      break;
    }
    case Opcode::AArch64_ADD_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADD_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADD_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADD_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADD_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADD_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADD_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADD_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADD_ZZZ_B: {  // add zd.b, zn.b, zm.b
      results[0] = sveHelp::sveAdd_3ops<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_ADD_ZZZ_D: {  // add zd.d, zn.d, zm.d
      results[0] = sveHelp::sveAdd_3ops<uint64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_ADD_ZZZ_H: {  // add zd.h, zn.h, zm.h
      results[0] = sveHelp::sveAdd_3ops<uint16_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_ADD_ZZZ_S: {  // add zd.s, zn.s, zm.s
      results[0] = sveHelp::sveAdd_3ops<uint32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_ADDlowTLS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADDv16i8: {  // add vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecAdd_3ops<uint8_t, 16>(operands);
      break;
    }
    case Opcode::AArch64_ADDv1i64: {  // add dd, dn, dm
      results[0] = neonHelp::vecAdd_3ops<uint64_t, 1>(operands);
      break;
    }
    case Opcode::AArch64_ADDv2i32: {  // add vd.2s, vn.2s, vm.2s
      results[0] = neonHelp::vecAdd_3ops<uint32_t, 2>(operands);
      break;
    }
    case Opcode::AArch64_ADDv2i64: {  // add vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecAdd_3ops<uint64_t, 2>(operands);
      break;
    }
    case Opcode::AArch64_ADDv4i16: {  // add vd.4h, vn.4h, vm.4h
      results[0] = neonHelp::vecAdd_3ops<uint16_t, 4>(operands);
      break;
    }
    case Opcode::AArch64_ADDv4i32: {  // add vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecAdd_3ops<uint32_t, 4>(operands);
      break;
    }
    case Opcode::AArch64_ADDv8i16: {  // add vd.8h, vn.8h, vm.8h
      results[0] = neonHelp::vecAdd_3ops<uint16_t, 8>(operands);
      break;
    }
    case Opcode::AArch64_ADDv8i8: {  // add vd.8b, vn.8b, vm.8b
      results[0] = neonHelp::vecAdd_3ops<uint8_t, 8>(operands);
      break;
    }
    case Opcode::AArch64_ADJCALLSTACKDOWN: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADJCALLSTACKUP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR: {  // adr xd, #imm
      results[0] = instructionAddress_ + metadata.operands[1].imm;
      break;
    }
    case Opcode::AArch64_ADRP: {  // adrp xd, #imm
      // Clear lowest 12 bits of address and add immediate (already shifted by
      // decoder)
      results[0] = (instructionAddress_ & ~(0xFFF)) + metadata.operands[1].imm;
      break;
    }
    case Opcode::AArch64_ADR_LSL_ZZZ_D_0: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_LSL_ZZZ_D_1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_LSL_ZZZ_D_2: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_LSL_ZZZ_D_3: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_LSL_ZZZ_S_0: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_LSL_ZZZ_S_1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_LSL_ZZZ_S_2: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_LSL_ZZZ_S_3: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_SXTW_ZZZ_D_0: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_SXTW_ZZZ_D_1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_SXTW_ZZZ_D_2: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_SXTW_ZZZ_D_3: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_UXTW_ZZZ_D_0: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_UXTW_ZZZ_D_1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_UXTW_ZZZ_D_2: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ADR_UXTW_ZZZ_D_3: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AESDrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AESErr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AESIMCrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AESIMCrrTied: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AESMCrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AESMCrrTied: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDSWri: {  // ands wd, wn, #imm
      auto [result, nzcv] = logicalHelp::logicOp_imm<uint32_t>(
          operands, metadata, true,
          [](uint32_t x, uint32_t y) -> uint32_t { return x & y; });
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ANDSWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDSWrs: {  // ands wd, wn, wm{, shift #amount}
      auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint32_t>(
          operands, metadata, true,
          [](uint32_t x, uint32_t y) -> uint32_t { return x & y; });
      results[0] = nzcv;
      results[1] = static_cast<uint64_t>(result);
      break;
    }
    case Opcode::AArch64_ANDSXri: {  // ands xd, xn, #imm
      auto [result, nzcv] = logicalHelp::logicOp_imm<uint64_t>(
          operands, metadata, true,
          [](uint64_t x, uint64_t y) -> uint64_t { return x & y; });
      results[0] = nzcv;
      results[1] = result;
      break;
    }
    case Opcode::AArch64_ANDSXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDSXrs: {  // ands xd, xn, xm{, shift #amount}
      auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint64_t>(
          operands, metadata, true,
          [](uint64_t x, uint64_t y) -> uint64_t { return x & y; });
      results[0] = nzcv;
      results[1] = result;
      break;
    }
    case Opcode::AArch64_ANDS_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDV_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDWri: {  // and wd, wn, #imm
      auto [result, nzcv] = logicalHelp::logicOp_imm<uint32_t>(
          operands, metadata, false,
          [](uint32_t x, uint32_t y) -> uint32_t { return x & y; });
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ANDWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDWrs: {  // and wd, wn, wm{, shift #amount}
      auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint32_t>(
          operands, metadata, false,
          [](uint32_t x, uint32_t y) -> uint32_t { return x & y; });
      results[0] = static_cast<uint64_t>(result);
      break;
    }
    case Opcode::AArch64_ANDXri: {  // and xd, xn, #imm
      auto [result, nzcv] = logicalHelp::logicOp_imm<uint64_t>(
          operands, metadata, false,
          [](uint64_t x, uint64_t y) -> uint64_t { return x & y; });
      results[0] = result;
      break;
    }
    case Opcode::AArch64_ANDXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDXrs: {  // and xd, xn, xm{, shift #amount}
      auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint64_t>(
          operands, metadata, false,
          [](uint64_t x, uint64_t y) -> uint64_t { return x & y; });
      results[0] = result;
      break;
    }
    case Opcode::AArch64_AND_PPzPP: {  // and pd.b, pg/z, pn.b, pm.b
      results[0] = sveHelp::sveLogicOp_preds<uint8_t>(
          operands, VL_bits,
          [](uint64_t x, uint64_t y) -> uint64_t { return x & y; });
      break;
    }
    case Opcode::AArch64_AND_ZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AND_ZPmZ_B: {  // and zdn.b, pg/m, zdn.b, zm.b
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<uint8_t>(
          operands, VL_bits,
          [](uint8_t x, uint8_t y) -> uint8_t { return x & y; });
      break;
    }
    case Opcode::AArch64_AND_ZPmZ_D: {  // and zdn.d, pg/m, zdn.d, zm.d
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<uint64_t>(
          operands, VL_bits,
          [](uint64_t x, uint64_t y) -> uint64_t { return x & y; });
      break;
    }
    case Opcode::AArch64_AND_ZPmZ_H: {  // and zdn.h, pg/m, zdn.h, zm.h
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<uint16_t>(
          operands, VL_bits,
          [](uint16_t x, uint16_t y) -> uint16_t { return x & y; });
      break;
    }
    case Opcode::AArch64_AND_ZPmZ_S: {  // and zdn.s, pg/m, zdn.s, zm.s
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<uint32_t>(
          operands, VL_bits,
          [](uint32_t x, uint32_t y) -> uint32_t { return x & y; });
      break;
    }
    case Opcode::AArch64_AND_ZZZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ANDv16i8: {  // and vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecLogicOp_3vecs<uint8_t, 16>(
          operands, [](uint8_t x, uint8_t y) -> uint8_t { return x & y; });
      break;
    }
    case Opcode::AArch64_ANDv8i8: {  // and vd.8b, vn.8b, vm.8b
      results[0] = neonHelp::vecLogicOp_3vecs<uint8_t, 8>(
          operands, [](uint8_t x, uint8_t y) -> uint8_t { return x & y; });
      break;
    }
    case Opcode::AArch64_ASRD_ZPmI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASRD_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASRD_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASRD_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASRR_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASRR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASRR_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASRR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASRVWr: {  // asrv wd, wn, wm
      results[0] = {logicalHelp::asrv_3gpr<int32_t>(operands), 8};
      break;
    }
    case Opcode::AArch64_ASRVXr: {  // asrv xd, xn, xm
      results[0] = logicalHelp::asrv_3gpr<int64_t>(operands);
      break;
    }
    case Opcode::AArch64_ASR_WIDE_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_WIDE_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_WIDE_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_WIDE_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_WIDE_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_WIDE_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZPmI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ASR_ZZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTDA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTDB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTDZA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTDZB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIA1716: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIASP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIAZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIB1716: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIBSP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIBZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIZA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_AUTIZB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_B: {  // b label
      branchTaken_ = true;
      branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      break;
    }
    case Opcode::AArch64_BCAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BFMWri: {  // bfm wd, wn, #immr, #imms
      results[0] = RegisterValue(
          bitmanipHelp::bfm_2imms<uint32_t>(operands, metadata, false, false),
          8);
      break;
    }
    case Opcode::AArch64_BFMXri: {  // bfm xd, xn, #immr, #imms
      results[0] =
          bitmanipHelp::bfm_2imms<uint64_t>(operands, metadata, false, false);
      break;
    }
    case Opcode::AArch64_BICSWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BICSWrs: {  // bics wd, wn, wm{, shift #amount}
      auto [result, nzcv] =
          logicalHelp::bicShift_3ops<uint32_t>(operands, metadata, true);
      results[0] = nzcv;
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_BICSXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BICSXrs: {  // bics xd, xn, xm{, shift #amount}
      auto [result, nzcv] =
          logicalHelp::bicShift_3ops<uint64_t>(operands, metadata, true);
      results[0] = nzcv;
      results[1] = result;
      break;
    }
    case Opcode::AArch64_BICS_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BICWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BICWrs: {  // bic wd, wn, wm{, shift #amount}
      auto [result, nzcv] =
          logicalHelp::bicShift_3ops<uint32_t>(operands, metadata, false);
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_BICXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BICXrs: {  // bic xd, xn, xm{, shift #amount}
      auto [result, nzcv] =
          logicalHelp::bicShift_3ops<uint64_t>(operands, metadata, false);
      results[0] = result;
      break;
    }
    case Opcode::AArch64_BIC_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BIC_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BIC_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BIC_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BIC_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BIC_ZZZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BICv16i8: {  // bic vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecBic_3ops<uint8_t, 16>(operands);
      break;
    }
    case Opcode::AArch64_BICv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BICv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BICv4i32: {  // bic vd.4s, #imm{, lsl #shift}
      results[0] = neonHelp::vecBicShift_imm<uint32_t, 4>(operands, metadata);
      break;
    }
    case Opcode::AArch64_BICv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BICv8i8: {  // bic vd.8b, vn.8b, vm.8b
      results[0] = neonHelp::vecBic_3ops<uint8_t, 8>(operands);
      break;
    }
    case Opcode::AArch64_BIFv16i8: {  // bif vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecBitwiseInsert<16>(operands, true);
      break;
    }
    case Opcode::AArch64_BIFv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BITv16i8: {  // bit vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecBitwiseInsert<16>(operands, false);
      break;
    }
    case Opcode::AArch64_BITv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BL: {  // bl #imm
      branchTaken_ = true;
      branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      results[0] = static_cast<uint64_t>(instructionAddress_ + 4);
      break;
    }
    case Opcode::AArch64_BLR: {  // blr xn
      branchTaken_ = true;
      branchAddress_ = operands[0].get<uint64_t>();
      results[0] = static_cast<uint64_t>(instructionAddress_ + 4);
      break;
    }
    case Opcode::AArch64_BLRAA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BLRAAZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BLRAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BLRABZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BR: {  // br xn
      branchTaken_ = true;
      branchAddress_ = operands[0].get<uint64_t>();
      break;
    }
    case Opcode::AArch64_BRAA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRAAZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRABZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRK: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKAS_PPzP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKA_PPmP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKA_PPzP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKBS_PPzP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKB_PPmP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKB_PPzP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKNS_PPzP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKN_PPzP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKPAS_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKPA_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKPBS_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BRKPB_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_BSLv16i8: {  // bsl vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecBsl<16>(operands);
      break;
    }
    case Opcode::AArch64_BSLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_Bcc: {  // b.cond label
      if (AuxFunc::conditionHolds(metadata.cc, operands[0].get<uint8_t>())) {
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
      } else {
        branchTaken_ = false;
        branchAddress_ = instructionAddress_ + 4;
      }
      break;
    }
    case Opcode::AArch64_CASAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASALW: {  // casal ws, wt, [xn|sp]
      // LOAD / STORE
      const uint32_t s = operands[0].get<uint32_t>();
      const uint32_t t = operands[1].get<uint32_t>();
      const uint32_t n = memoryData[0].get<uint32_t>();
      if (n == s) memoryData[0] = t;
      break;
    }
    case Opcode::AArch64_CASALX: {  // casal xs, xt, [xn|sp]
      // LOAD / STORE
      const uint64_t s = operands[0].get<uint64_t>();
      const uint64_t t = operands[1].get<uint64_t>();
      const uint64_t n = memoryData[0].get<uint64_t>();
      if (n == s) memoryData[0] = t;
      break;
    }
    case Opcode::AArch64_CASAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASPALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASPALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASPAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASPAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASPLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASPLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASPW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASPX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CASX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CBNZW: {  // cbnz wn, #imm
      auto [taken, addr] = conditionalHelp::condBranch_cmpToZero<uint32_t>(
          operands, metadata, instructionAddress_,
          [](uint32_t x) -> bool { return x != 0; });
      branchTaken_ = taken;
      branchAddress_ = addr;
      break;
    }
    case Opcode::AArch64_CBNZX: {  // cbnz xn, #imm
      auto [taken, addr] = conditionalHelp::condBranch_cmpToZero<uint64_t>(
          operands, metadata, instructionAddress_,
          [](uint64_t x) -> bool { return x != 0; });
      branchTaken_ = taken;
      branchAddress_ = addr;
      break;
    }
    case Opcode::AArch64_CBZW: {  // cbz wn, #imm
      auto [taken, addr] = conditionalHelp::condBranch_cmpToZero<uint32_t>(
          operands, metadata, instructionAddress_,
          [](uint32_t x) -> bool { return x == 0; });
      branchTaken_ = taken;
      branchAddress_ = addr;
      break;
    }
    case Opcode::AArch64_CBZX: {  // cbz xn, #imm
      auto [taken, addr] = conditionalHelp::condBranch_cmpToZero<uint64_t>(
          operands, metadata, instructionAddress_,
          [](uint64_t x) -> bool { return x == 0; });
      branchTaken_ = taken;
      branchAddress_ = addr;
      break;
    }
    case Opcode::AArch64_CCMNWi: {  // ccmn wn, #imm, #nzcv, cc
      results[0] = conditionalHelp::ccmn_imm<uint32_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_CCMNWr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CCMNXi: {  // ccmn xn, #imm, #nzcv, cc
      results[0] = conditionalHelp::ccmn_imm<uint64_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_CCMNXr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CCMPWi: {  // ccmp wn, #imm, #nzcv, cc
      results[0] = conditionalHelp::ccmp_imm<uint32_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_CCMPWr: {  // ccmp wn, wm, #nzcv, cc
      results[0] = conditionalHelp::ccmp_reg<uint32_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_CCMPXi: {  // ccmp xn, #imm, #nzcv, cc
      results[0] = conditionalHelp::ccmp_imm<uint64_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_CCMPXr: {  // ccmp xn, xm, #nzcv, cc
      results[0] = conditionalHelp::ccmp_reg<uint64_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_CFINV: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_RPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_RPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_RPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_RPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_ZPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_ZPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_ZPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTA_ZPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_RPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_RPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_RPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_RPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_ZPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_ZPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_ZPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLASTB_ZPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLREX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLSWr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLSXr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLS_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLS_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLS_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLS_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLSv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLSv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLSv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLSv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLSv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLSv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZWr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZXr: {  // clz xd, xn
      results[0] = arithmeticHelp::clz_reg<int64_t>(operands);
      break;
    }
    case Opcode::AArch64_CLZ_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZ_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZ_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZ_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CLZv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv16i8: {  // cmeq vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecCompare<uint8_t, 16>(
          operands, false,
          [](uint8_t x, uint8_t y) -> bool { return (x == y); });
      break;
    }
    case Opcode::AArch64_CMEQv16i8rz: {  // cmeq vd.16b, vn.16b, #0
      results[0] = neonHelp::vecCompare<uint8_t, 16>(
          operands, true,
          [](uint8_t x, uint8_t y) -> bool { return (x == y); });
      break;
    }
    case Opcode::AArch64_CMEQv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv2i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv2i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv4i32: {  // cmeq vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecCompare<uint32_t, 4>(
          operands, false,
          [](uint32_t x, uint32_t y) -> bool { return (x == y); });
      break;
    }
    case Opcode::AArch64_CMEQv4i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMEQv8i8rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv16i8rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv2i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv2i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv4i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGEv8i8rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv16i8rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv2i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv2i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv4i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMGTv8i8rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHIv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHIv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHIv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHIv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHIv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHIv4i32: {  // cmhi vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecCompare<uint32_t, 4>(
          operands, false,
          [](uint32_t x, uint32_t y) -> bool { return (x > y); });
      break;
    }
    case Opcode::AArch64_CMHIv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHIv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHSv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHSv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHSv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHSv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHSv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHSv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHSv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMHSv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLEv16i8rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLEv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLEv2i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLEv2i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLEv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLEv4i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLEv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLEv8i8rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLTv16i8rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLTv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLTv2i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLTv2i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLTv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLTv4i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLTv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMLTv8i8rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPEQ_PPzZI_B: {  // cmpeq pd.b, pg/z, zn.b, #imm
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint8_t>(
          operands, metadata, VL_bits, true,
          [](uint8_t x, uint8_t y) -> bool { return x == y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPEQ_PPzZI_D: {  // cmpeq pd.d, pg/z, zn.d, #imm
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint64_t>(
          operands, metadata, VL_bits, true,
          [](uint64_t x, uint64_t y) -> bool { return x == y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPEQ_PPzZI_H: {  // cmpeq pd.h, pg/z, zn.h, #imm
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint16_t>(
          operands, metadata, VL_bits, true,
          [](uint16_t x, uint16_t y) -> bool { return x == y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPEQ_PPzZI_S: {  // cmpeq pd.s, pg/z, zn.s, #imm
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint32_t>(
          operands, metadata, VL_bits, true,
          [](uint32_t x, uint32_t y) -> bool { return x == y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPEQ_PPzZZ_B: {  // cmpeq pd.b, pg/z, zn.b, zm.b
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint8_t>(
          operands, metadata, VL_bits, false,
          [](uint8_t x, uint8_t y) -> bool { return x == y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPEQ_PPzZZ_D: {  // cmpeq pd.d, pg/z, zn.d, zm.d
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint64_t>(
          operands, metadata, VL_bits, false,
          [](uint64_t x, uint64_t y) -> bool { return x == y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPEQ_PPzZZ_H: {  // cmpeq pd.h, pg/z, zn.h, zm.h
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint16_t>(
          operands, metadata, VL_bits, false,
          [](uint16_t x, uint16_t y) -> bool { return x == y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPEQ_PPzZZ_S: {  // cmpeq pd.s, pg/z, zn.s, zm.s
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint32_t>(
          operands, metadata, VL_bits, false,
          [](uint32_t x, uint32_t y) -> bool { return x == y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPEQ_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPEQ_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPEQ_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_PPzZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_PPzZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_PPzZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_PPzZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_PPzZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGE_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGT_PPzZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGT_PPzZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGT_PPzZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGT_PPzZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGT_PPzZZ_B: {  // cmpgt pd.b, pg/z, zn.b, zm.b
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int8_t>(
          operands, metadata, VL_bits, false,
          [](int8_t x, int8_t y) -> bool { return x > y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPGT_PPzZZ_D: {  // cmpgt pd.d, pg/z, zn.d, zm.d
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int64_t>(
          operands, metadata, VL_bits, false,
          [](int64_t x, int64_t y) -> bool { return x > y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPGT_PPzZZ_H: {  // cmpgt pd.h, pg/z, zn.h, zm.h
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int16_t>(
          operands, metadata, VL_bits, false,
          [](int16_t x, int16_t y) -> bool { return x > y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPGT_PPzZZ_S: {  // cmpgt pd.s, pg/z, zn.s, zm.s
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int32_t>(
          operands, metadata, VL_bits, false,
          [](int32_t x, int32_t y) -> bool { return x > y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPGT_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGT_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPGT_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHI_PPzZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHI_PPzZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHI_PPzZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHI_PPzZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHI_PPzZZ_B: {  // cmphi pd.b, pg/z, zn.b, zm.b
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint8_t>(
          operands, metadata, VL_bits, false,
          [](uint8_t x, uint8_t y) -> bool { return x > y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPHI_PPzZZ_D: {  // cmphi pd.d, pg/z, zn.d, zm.d
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint64_t>(
          operands, metadata, VL_bits, false,
          [](uint64_t x, uint64_t y) -> bool { return x > y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPHI_PPzZZ_H: {  // cmphi pd.h, pg/z, zn.h, zm.h
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint16_t>(
          operands, metadata, VL_bits, false,
          [](uint16_t x, uint16_t y) -> bool { return x > y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPHI_PPzZZ_S: {  // cmphi pd.s, pg/z, zn.s, zm.s
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<uint32_t>(
          operands, metadata, VL_bits, false,
          [](uint32_t x, uint32_t y) -> bool { return x > y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPHI_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHI_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHI_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_PPzZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_PPzZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_PPzZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_PPzZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_PPzZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPHS_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLE_PPzZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLE_PPzZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLE_PPzZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLE_PPzZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLE_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLE_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLE_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLO_PPzZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLO_PPzZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLO_PPzZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLO_PPzZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLO_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLO_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLO_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLS_PPzZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLS_PPzZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLS_PPzZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLS_PPzZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLS_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLS_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLS_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLT_PPzZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLT_PPzZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLT_PPzZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLT_PPzZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLT_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLT_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPLT_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_PPzZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_PPzZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_PPzZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_PPzZI_S: {  // cmpne pd.s, pg/z. zn.s, #imm
      auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int32_t>(
          operands, metadata, VL_bits, true,
          [](int32_t x, int32_t y) -> bool { return x != y; });
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_CMPNE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_PPzZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_WIDE_PPzZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_WIDE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMPNE_WIDE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMP_SWAP_128: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMP_SWAP_16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMP_SWAP_32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMP_SWAP_64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMP_SWAP_8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMTSTv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMTSTv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMTSTv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMTSTv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMTSTv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMTSTv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMTSTv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CMTSTv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNOT_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNOT_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNOT_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNOT_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNTB_XPiI: {  // cntb xd{, pattern{, #imm}}
      results[0] = sveHelp::sveCnt_gpr<uint8_t>(metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_CNTD_XPiI: {  // cntd xd{, pattern{, #imm}}
      results[0] = sveHelp::sveCnt_gpr<uint64_t>(metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_CNTH_XPiI: {  // cnth xd{, pattern{, #imm}}
      results[0] = sveHelp::sveCnt_gpr<uint16_t>(metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_CNTP_XPP_B: {  // cntp xd, pg, pn.b
      results[0] = sveHelp::sveCntp<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_CNTP_XPP_D: {  // cntp xd, pg, pn.d
      results[0] = sveHelp::sveCntp<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_CNTP_XPP_H: {  // cntp xd, pg, pn.h
      results[0] = sveHelp::sveCntp<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_CNTP_XPP_S: {  // cntp xd, pg, pn.s
      results[0] = sveHelp::sveCntp<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_CNTW_XPiI: {  // cntw xd{, pattern{, #imm}}
      results[0] = sveHelp::sveCnt_gpr<uint32_t>(metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_CNT_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNT_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNT_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNT_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNTv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CNTv8i8: {  // cnt vd.8b, vn.8b
      results[0] = neonHelp::vecCountPerByte<uint8_t, 8>(operands);
      break;
    }
    case Opcode::AArch64_COMPACT_ZPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_COMPACT_ZPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmR_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmR_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmR_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmR_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmV_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmV_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmV_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPmV_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPzI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPzI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPzI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPY_ZPzI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPYi16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CPYi32: {
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint32_t, 1>(operands, metadata, false);
      break;
    }
    case Opcode::AArch64_CPYi64: {
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint64_t, 1>(operands, metadata, false);
      break;
    }
    case Opcode::AArch64_CPYi8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CRC32Brr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CRC32CBrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CRC32CHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CRC32CWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CRC32CXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CRC32Hrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CRC32Wrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CRC32Xrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CSELWr: {  // csel wd, wn, wm, cc
      results[0] = static_cast<uint64_t>(conditionalHelp::cs_4ops<uint32_t>(
          operands, metadata, [](uint32_t x) -> uint32_t { return x; }));
      break;
    }
    case Opcode::AArch64_CSELXr: {  // csel xd, xn, xm, cc
      results[0] = conditionalHelp::cs_4ops<uint64_t>(
          operands, metadata, [](uint64_t x) -> uint64_t { return x; });
      break;
    }
    case Opcode::AArch64_CSINCWr: {  // csinc wd, wn, wm, cc
      results[0] = static_cast<uint64_t>(conditionalHelp::cs_4ops<uint32_t>(
          operands, metadata, [](uint32_t x) -> uint32_t { return x + 1; }));
      break;
    }
    case Opcode::AArch64_CSINCXr: {  // csinc xd, xn, xm, cc
      results[0] = conditionalHelp::cs_4ops<uint64_t>(
          operands, metadata, [](uint64_t x) -> uint64_t { return x + 1; });
      break;
    }
    case Opcode::AArch64_CSINVWr: {  // csinv wd, wn, wm, cc
      results[0] = static_cast<uint64_t>(conditionalHelp::cs_4ops<uint32_t>(
          operands, metadata, [](uint32_t x) -> uint32_t { return ~x; }));
      break;
    }
    case Opcode::AArch64_CSINVXr: {  // csinv xd, xn, xm, cc
      results[0] = conditionalHelp::cs_4ops<uint64_t>(
          operands, metadata, [](uint64_t x) -> uint64_t { return ~x; });
      break;
    }
    case Opcode::AArch64_CSNEGWr: {  // csneg wd, wn, wm, cc
      results[0] = static_cast<int64_t>(conditionalHelp::cs_4ops<int32_t>(
          operands, metadata, [](int32_t x) -> int32_t { return -x; }));
      break;
    }
    case Opcode::AArch64_CSNEGXr: {  // csneg xd, xn, xm, cc
      results[0] = conditionalHelp::cs_4ops<uint64_t>(
          operands, metadata, [](uint64_t x) -> uint64_t { return -x; });
      break;
    }
    case Opcode::AArch64_CTERMEQ_WW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CTERMEQ_XX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CTERMNE_WW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CTERMNE_XX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_CompilerBarrier: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DCPS1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DCPS2: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DCPS3: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECB_XPiI: {  // decb xdn{, pattern{, MUL #imm}}
      results[0] = sveHelp::sveDec_scalar<uint8_t>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_DECD_XPiI: {  // decd xdn{, pattern{, MUL #imm}}
      results[0] =
          sveHelp::sveDec_scalar<uint64_t>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_DECD_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECH_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECH_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECP_XP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECP_XP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECP_XP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECP_XP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECP_ZP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECP_ZP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECP_ZP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECW_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DECW_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DMB: {  // dmb option|#imm
      // TODO: Respect memory barriers
      break;
    }
    case Opcode::AArch64_DRPS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DSB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUPM_ZI: {  // dupm zd.t, #imm
      const uint64_t imm = static_cast<uint64_t>(metadata.operands[1].imm);
      uint64_t out[32] = {0};
      for (int i = 0; i < (VL_bits / 64); i++) {
        out[i] = imm;
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_DUP_ZI_B: {  // dup zd.b, #imm{, shift}
      results[0] = sveHelp::sveDup_immOrScalar<int8_t>(operands, metadata,
                                                       VL_bits, true);
      break;
    }
    case Opcode::AArch64_DUP_ZI_D: {  // dup zd.d, #imm{, shift}
      results[0] = sveHelp::sveDup_immOrScalar<int64_t>(operands, metadata,
                                                        VL_bits, true);
      break;
    }
    case Opcode::AArch64_DUP_ZI_H: {  // dup zd.h, #imm{, shift}
      results[0] = sveHelp::sveDup_immOrScalar<int16_t>(operands, metadata,
                                                        VL_bits, true);
      break;
    }
    case Opcode::AArch64_DUP_ZI_S: {  // dup zd.s, #imm{, shift}
      results[0] = sveHelp::sveDup_immOrScalar<int32_t>(operands, metadata,
                                                        VL_bits, true);
      break;
    }
    case Opcode::AArch64_DUP_ZR_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUP_ZR_D: {  // dup zd.d, xn
      results[0] = sveHelp::sveDup_immOrScalar<int64_t>(operands, metadata,
                                                        VL_bits, false);
      break;
    }
    case Opcode::AArch64_DUP_ZR_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUP_ZR_S: {  // dup zd.s, wn
      results[0] = sveHelp::sveDup_immOrScalar<int32_t>(operands, metadata,
                                                        VL_bits, false);
      break;
    }
    case Opcode::AArch64_DUP_ZZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUP_ZZI_D: {  // dup zd.d, zn.d[#imm]
      results[0] =
          sveHelp::sveDup_vecIndexed<uint64_t>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_DUP_ZZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUP_ZZI_Q: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUP_ZZI_S: {  // dup zd.s, zn.s[#imm]
      results[0] =
          sveHelp::sveDup_vecIndexed<uint32_t>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_DUPv16i8gpr: {  // dup vd.16b, wn
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint8_t, 16>(operands, metadata, true);
      break;
    }
    case Opcode::AArch64_DUPv16i8lane: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUPv2i32gpr: {  // dup vd.2s, wn
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint32_t, 2>(operands, metadata, true);
      break;
    }
    case Opcode::AArch64_DUPv2i32lane: {  // dup vd.2s, vn.s[index]
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint32_t, 2>(operands, metadata, false);
      break;
    }
    case Opcode::AArch64_DUPv2i64gpr: {  // dup vd.2d, xn
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint64_t, 2>(operands, metadata, true);
      break;
    }
    case Opcode::AArch64_DUPv2i64lane: {  // dup vd.2d, vn.d[index]
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint64_t, 2>(operands, metadata, false);
      break;
    }
    case Opcode::AArch64_DUPv4i16gpr: {  // dup vd.4h, wn
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint16_t, 4>(operands, metadata, true);
      break;
    }
    case Opcode::AArch64_DUPv4i16lane: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUPv4i32gpr: {  // dup vd.4s, wn
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint32_t, 4>(operands, metadata, true);
      break;
    }
    case Opcode::AArch64_DUPv4i32lane: {  // dup vd.4s, vn.s[index]
      results[0] =
          neonHelp::vecDup_gprOrIndex<uint32_t, 4>(operands, metadata, false);
      break;
    }
    case Opcode::AArch64_DUPv8i16gpr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUPv8i16lane: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUPv8i8gpr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_DUPv8i8lane: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EONWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EONWrs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EONXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EONXrs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EOR3: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EORS_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EORV_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EORV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EORV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EORV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EORWri: {  // eor wd, wn, #imm
      results[0] = logicalHelp::logicOp_imm<uint32_t>(
          operands, metadata, false,
          [](uint32_t x, uint32_t y) -> uint32_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EORWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EORWrs: {  // eor wd, wn, wm{, shift #imm}
      results[0] = logicalHelp::logicOpShift_3ops<uint32_t>(
          operands, metadata, false,
          [](uint32_t x, uint32_t y) -> uint32_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EORXri: {  // eor xd, xn, #imm
      results[0] = logicalHelp::logicOp_imm<uint64_t>(
          operands, metadata, false,
          [](uint64_t x, uint64_t y) -> uint64_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EORXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EORXrs: {  // eor xd, xn, xm{, shift #amount}
      results[0] = logicalHelp::logicOpShift_3ops<uint64_t>(
          operands, metadata, false,
          [](uint64_t x, uint64_t y) -> uint64_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EOR_PPzPP: {
      results[0] = sveHelp::sveLogicOp_preds<uint8_t>(
          operands, VL_bits,
          [](uint64_t x, uint64_t y) -> uint64_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EOR_ZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EOR_ZPmZ_B: {  // eor zdn.b, pg/m, zdn.b, zm.b
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<uint8_t>(
          operands, VL_bits,
          [](uint8_t x, uint8_t y) -> uint8_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EOR_ZPmZ_D: {  // eor zdn.d, pg/m, zdn.d, zm.d
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<uint64_t>(
          operands, VL_bits,
          [](uint64_t x, uint64_t y) -> uint64_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EOR_ZPmZ_H: {  // eor zdn.h, pg/m, zdn.h, zm.h
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<uint16_t>(
          operands, VL_bits,
          [](uint16_t x, uint16_t y) -> uint16_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EOR_ZPmZ_S: {  // eor zdn.s, pg/m, zdn.s, zm.s
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<uint32_t>(
          operands, VL_bits,
          [](uint32_t x, uint32_t y) -> uint32_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EOR_ZZZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EORv16i8: {  // eor vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecLogicOp_3vecs<uint8_t, 16>(
          operands, [](uint8_t x, uint8_t y) -> uint8_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_EORv8i8: {  // eor vd.8b, vn.8b, vm.8b
      results[0] = neonHelp::vecLogicOp_3vecs<uint8_t, 8>(
          operands, [](uint8_t x, uint8_t y) -> uint8_t { return x ^ y; });
      break;
    }
    case Opcode::AArch64_ERET: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ERETAA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ERETAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EXTRWrri: {  // extr wd, wn, wm, #lsb
      results[0] =
          bitmanipHelp::extrLSB_registers<uint32_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_EXTRXrri: {  // extr xd, xn, xm, #lsb
      results[0] =
          bitmanipHelp::extrLSB_registers<uint64_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_EXT_ZZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_EXTv16i8: {  // ext vd.16b, vn.16b, vm.16b, #index
      results[0] = neonHelp::vecExtVecs_index<uint8_t, 16>(operands, metadata);
      break;
    }
    case Opcode::AArch64_EXTv8i8: {  // ext vd.8b, vn.8b, vm.8b, #index
      results[0] = neonHelp::vecExtVecs_index<uint8_t, 8>(operands, metadata);
      break;
    }
    case Opcode::AArch64_F128CSEL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABD16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABD32: {  // fabd sd, sn, sm
      results[0] = floatHelp::fabd_3ops<float>(operands);
      break;
    }
    case Opcode::AArch64_FABD64: {  // fabd dd, dn, dm
      results[0] = floatHelp::fabd_3ops<double>(operands);
      break;
    }
    case Opcode::AArch64_FABD_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABD_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABD_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABDv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABDv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABDv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABDv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABDv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABSDr: {  // fabs dd, dn
      results[0] = floatHelp::fabs_2ops<double>(operands);
      break;
    }
    case Opcode::AArch64_FABSHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABSSr: {  // fabs sd, sn
      results[0] = floatHelp::fabs_2ops<float>(operands);
      break;
    }
    case Opcode::AArch64_FABS_ZPmZ_D: {  // fabs zd.d, pg/m, zn.d
      results[0] = sveHelp::sveFabsPredicated<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FABS_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABS_ZPmZ_S: {  // fabs zd.s, pg/m, zn.s
      results[0] = sveHelp::sveFabsPredicated<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FABSv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABSv2f64: {  // fabs vd.2d, vn.2d
      results[0] = neonHelp::vecFabs_2ops<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FABSv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FABSv4f32: {  // fabs vd.4s, vn.4s
      results[0] = neonHelp::vecFabs_2ops<float, 4>(operands);
      break;
    }
    case Opcode::AArch64_FABSv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGE16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGE32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGE64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGE_PPzZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGEv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGEv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGEv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGEv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGEv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGT16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGT32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGT64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGT_PPzZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGT_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGT_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGTv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGTv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGTv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGTv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FACGTv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDA_VPZ_D: {  // fadda dd, pg/m, dn, zm.d
      results[0] = sveHelp::sveFaddaPredicated<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FADDA_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDA_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDDrr: {  // fadd dd, dn, dm
      results[0] = {arithmeticHelp::add_3ops<double>(operands), 256};
      break;
    }
    case Opcode::AArch64_FADDHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDPv2f32: {  // faddp vd.2s, vn.2s, vm.2s
      results[0] = neonHelp::vecAddp_3ops<float, 2>(operands);
      break;
    }
    case Opcode::AArch64_FADDPv2f64: {  // faddp vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecAddp_3ops<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FADDPv2i16p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDPv2i32p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDPv2i64p: {  // faddp dd, vn.2d
      results[0] = neonHelp::vecSumElems_2ops<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FADDPv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDPv4f32: {  // faddp vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecAddp_3ops<float, 4>(operands);
      break;
    }
    case Opcode::AArch64_FADDPv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDSrr: {  // fadd sd, sn, sm
      results[0] = {arithmeticHelp::add_3ops<float>(operands), 256};
      break;
    }
    case Opcode::AArch64_FADDV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADD_ZPmI_D: {  // fadd zdn.d, pg/m, zdn.d, const
      results[0] =
          sveHelp::sveAddPredicated_const<double>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_FADD_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADD_ZPmI_S: {  // fadd zdn.s, pg/m, zdn.s, const
      results[0] =
          sveHelp::sveAddPredicated_const<float>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_FADD_ZPmZ_D: {  // fadd zdn.d, pg/m, zdn.d, zm.d
      results[0] = sveHelp::sveAddPredicated_vecs<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FADD_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADD_ZPmZ_S: {  // fadd zdn.s, pg/m, zdn.s, zm.s
      results[0] = sveHelp::sveAddPredicated_vecs<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FADD_ZZZ_D: {  // fadd zd.d, zn.d, zm.d
      results[0] = sveHelp::sveAdd_3ops<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FADD_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADD_ZZZ_S: {  // fadd zd.s, zn.s, zm.s
      results[0] = sveHelp::sveAdd_3ops<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FADDv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDv2f64: {  // fadd vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecAdd_3ops<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FADDv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FADDv4f32: {  // fadd vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecAdd_3ops<float, 4>(operands);
      break;
    }
    case Opcode::AArch64_FADDv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCADD_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCADD_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCADD_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCADDv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCADDv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCADDv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCADDv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCADDv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCCMPDrr:     // fccmp sn, sm, #nzcv, cc
    case Opcode::AArch64_FCCMPEDrr: {  // fccmpe sn, sm, #nzcv, cc
      results[0] = floatHelp::fccmp<double>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FCCMPEHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCCMPESrr: {  // fccmpe sn, sm, #nzcv, cc
      results[0] = floatHelp::fccmp<float>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FCCMPHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCCMPSrr: {  // fccmp sn, sm, #nzcv, cc
      results[0] = floatHelp::fccmp<float>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FCMEQ16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQ32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQ64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQ_PPzZ0_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQ_PPzZ0_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQ_PPzZ0_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQ_PPzZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQ_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQ_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv1i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv1i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv2i32rz: {  // fcmeq vd.2s, vd.2s, #0.0
      results[0] = neonHelp::vecFCompare<float, uint32_t, 2>(
          operands, true, [](float x, float y) -> bool { return x == y; });
      break;
    }
    case Opcode::AArch64_FCMEQv2i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv4i32rz: {  // fcmeq vd.4s vn.4s, #0.0
      results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
          operands, true, [](float x, float y) -> bool { return x == y; });
      break;
    }
    case Opcode::AArch64_FCMEQv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMEQv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGE16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGE32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGE64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGE_PPzZ0_D: {  // fcmge pd.d, pg/z, zn.d, #0.0
      results[0] = sveHelp::sveComparePredicated_vecsToPred<double>(
          operands, metadata, VL_bits, true,
          [](double x, double y) -> bool { return x >= y; });
      break;
    }
    case Opcode::AArch64_FCMGE_PPzZ0_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGE_PPzZ0_S: {  // fcmge pd.s, pg/z, zn.s, #0.0
      results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
          operands, metadata, VL_bits, true,
          [](float x, float y) -> bool { return x >= y; });
      break;
    }
    case Opcode::AArch64_FCMGE_PPzZZ_D: {  // fcmge pd.d, pg/z, zn.d, zm.d
      results[0] = sveHelp::sveComparePredicated_vecsToPred<double>(
          operands, metadata, VL_bits, false,
          [](double x, double y) -> bool { return x >= y; });
      break;
    }
    case Opcode::AArch64_FCMGE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGE_PPzZZ_S: {  // fcmge pd.s, pg/z, zn.s, zm.s
      results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
          operands, metadata, VL_bits, false,
          [](float x, float y) -> bool { return x >= y; });
      break;
    }
    case Opcode::AArch64_FCMGEv1i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGEv1i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGEv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGEv2f32: {  // fcmge vd.2s, vn.2s, vm.2s
      results[0] = neonHelp::vecFCompare<float, uint32_t, 2>(
          operands, false, [](float x, float y) -> bool { return x >= y; });
      break;
    }
    case Opcode::AArch64_FCMGEv2f64: {  // fcmge vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecFCompare<double, uint64_t, 2>(
          operands, false, [](float x, double y) -> bool { return x >= y; });
      break;
    }
    case Opcode::AArch64_FCMGEv2i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGEv2i64rz: {  // fcmge vd.2d, vn.2d, 0.0
      results[0] = neonHelp::vecFCompare<double, uint64_t, 2>(
          operands, true, [](double x, double y) -> bool { return x >= y; });
      break;
    }
    case Opcode::AArch64_FCMGEv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGEv4f32: {  // fcmge vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
          operands, false, [](float x, float y) -> bool { return x >= y; });
      break;
    }
    case Opcode::AArch64_FCMGEv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGEv4i32rz: {  // fcmge vd.4s, vn.4s, 0.0
      results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
          operands, true, [](float x, float y) -> bool { return x >= y; });
      break;
    }
    case Opcode::AArch64_FCMGEv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGEv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGT16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGT32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGT64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGT_PPzZ0_D: {  // fcmgt pd.d, pg/z, zn.d, #0.0
      results[0] = sveHelp::sveComparePredicated_vecsToPred<double>(
          operands, metadata, VL_bits, true,
          [](double x, double y) -> bool { return x > y; });
      break;
    }
    case Opcode::AArch64_FCMGT_PPzZ0_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGT_PPzZ0_S: {  // fcmgt pd.s, pg/z, zn.s, #0.0
      results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
          operands, metadata, VL_bits, true,
          [](float x, float y) -> bool { return x > y; });
      break;
    }
    case Opcode::AArch64_FCMGT_PPzZZ_D: {  // fcmgt pd.d, pg/z, zn.d, zm.d
      results[0] = sveHelp::sveComparePredicated_vecsToPred<double>(
          operands, metadata, VL_bits, false,
          [](double x, double y) -> bool { return x > y; });
      break;
    }
    case Opcode::AArch64_FCMGT_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGT_PPzZZ_S: {  // fcmgt pd.s, pg/z, zn.s, zm.
      results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
          operands, metadata, VL_bits, false,
          [](float x, float y) -> bool { return x > y; });
      break;
    }
    case Opcode::AArch64_FCMGTv1i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGTv1i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGTv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGTv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGTv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGTv2i32rz: {  // fcmgt vd.2s, vn.2s, #0.0
      results[0] = neonHelp::vecFCompare<float, uint32_t, 2>(
          operands, true, [](float x, float y) -> bool { return x > y; });
      break;
    }
    case Opcode::AArch64_FCMGTv2i64rz: {  // fcmgt vd.2d, vn.2d, #0.0
      results[0] = neonHelp::vecFCompare<double, uint64_t, 2>(
          operands, true, [](double x, double y) -> bool { return x > y; });
      break;
    }
    case Opcode::AArch64_FCMGTv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGTv4f32: {  // fcmgt vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
          operands, false, [](float x, float y) -> bool { return x > y; });
      break;
    }
    case Opcode::AArch64_FCMGTv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGTv4i32rz: {  // fcmgt vd.4s, vn.4s, #0.0
      results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
          operands, true, [](float x, float y) -> bool { return x > y; });
      break;
    }
    case Opcode::AArch64_FCMGTv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMGTv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLA_ZPmZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLA_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLA_ZPmZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLA_ZZZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLA_ZZZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLAv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLAv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLAv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLAv4f16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLAv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLAv4f32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLAv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLAv8f16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLE_PPzZ0_D: {  // fcmle pd.d, pg/z, zn.d, #0.0
      results[0] = sveHelp::sveComparePredicated_vecsToPred<double>(
          operands, metadata, VL_bits, true,
          [](double x, double y) -> bool { return x <= y; });
      break;
    }
    case Opcode::AArch64_FCMLE_PPzZ0_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLE_PPzZ0_S: {  // fcmle pd.s, pg/z, zn.s, #0.0
      results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
          operands, metadata, VL_bits, true,
          [](float x, float y) -> bool { return x <= y; });
      break;
    }
    case Opcode::AArch64_FCMLEv1i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLEv1i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLEv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLEv2i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLEv2i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLEv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLEv4i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLEv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLT_PPzZ0_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLT_PPzZ0_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLT_PPzZ0_S: {  // fcmlt pd.s, pg/z, zn.s, #0.0
      results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
          operands, metadata, VL_bits, true,
          [](float x, float y) -> bool { return x < y; });
      break;
    }
    case Opcode::AArch64_FCMLTv1i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLTv1i32rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLTv1i64rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLTv2i32rz: {  // fcmlt vd.2s, vn.2s, #0.0
      results[0] = neonHelp::vecFCompare<float, uint32_t, 2>(
          operands, true, [](float x, float y) -> bool { return x < y; });
      break;
    }
    case Opcode::AArch64_FCMLTv2i64rz: {  // fcmlt vd.2d, vn.2d, #0.0
      results[0] = neonHelp::vecFCompare<double, uint64_t, 2>(
          operands, true, [](double x, double y) -> bool { return x < y; });
      break;
    }
    case Opcode::AArch64_FCMLTv4i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMLTv4i32rz: {  // fcmlt vd.4s, vn.4s, #0.0
      results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
          operands, true, [](float x, float y) -> bool { return x < y; });
      break;
    }
    case Opcode::AArch64_FCMLTv8i16rz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMNE_PPzZ0_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMNE_PPzZ0_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMNE_PPzZ0_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMNE_PPzZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMNE_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMNE_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMPDri: {  // fcmp dn, #imm
      results[0] = floatHelp::fcmp<double>(operands, true);
      break;
    }
    case Opcode::AArch64_FCMPDrr: {  // fcmp dn, dm
      results[0] = floatHelp::fcmp<double>(operands, false);
      break;
    }
    case Opcode::AArch64_FCMPEDri: {  // fcmpe dn, #imm
      results[0] = floatHelp::fcmp<double>(operands, true);
      break;
    }
    case Opcode::AArch64_FCMPEDrr: {  // fcmpe dn, dm
      results[0] = floatHelp::fcmp<double>(operands, false);
      break;
    }
    case Opcode::AArch64_FCMPEHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMPEHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMPESri: {  // fcmpe sn, #imm
      results[0] = floatHelp::fcmp<float>(operands, true);
      break;
    }
    case Opcode::AArch64_FCMPESrr: {  // fcmpe sn, sm
      results[0] = floatHelp::fcmp<float>(operands, false);
      break;
    }
    case Opcode::AArch64_FCMPHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMPHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMPSri: {  // fcmp sn, #imm
      results[0] = floatHelp::fcmp<float>(operands, true);
      break;
    }
    case Opcode::AArch64_FCMPSrr: {  // fcmp sn, sm
      results[0] = floatHelp::fcmp<float>(operands, false);
      break;
    }
    case Opcode::AArch64_FCMUO_PPzZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMUO_PPzZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCMUO_PPzZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCPY_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCPY_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCPY_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCSELDrrr: {  // fcsel dd, dn, dm, cond
      results[0] = {
          conditionalHelp::cs_4ops<double>(
              operands, metadata, [](double x) -> double { return x; }),
          256};
      break;
    }
    case Opcode::AArch64_FCSELHrrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCSELSrrr: {  // fcsel sd, sn, sm, cond
      results[0] = {conditionalHelp::cs_4ops<float>(
                        operands, metadata, [](float x) -> float { return x; }),
                    256};
      break;
    }
    case Opcode::AArch64_FCVTASUWDr: {  // fcvtas wd, dn
      results[0] = RegisterValue(
          static_cast<int32_t>(round(operands[0].get<double>())), 8);
      break;
    }
    case Opcode::AArch64_FCVTASUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASUWSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASUXDr: {  // fcvtas xd, dn
      results[0] = static_cast<int64_t>(round(operands[0].get<double>()));
      break;
    }
    case Opcode::AArch64_FCVTASUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASUXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTASv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUUWDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUUWSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUUXDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUUXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTAUv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTDHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTDSr: {  // fcvt dd, sn
      // TODO: Handle NaNs, denorms, and saturation?
      results[0] =
          RegisterValue(static_cast<double>(operands[0].get<float>()), 256);
      break;
    }
    case Opcode::AArch64_FCVTHDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTHSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTLv2i32: {  // fcvtl vd.2d, vn.2s
      const float* n = operands[0].getAsVector<float>();
      double out[2] = {static_cast<double>(n[0]), static_cast<double>(n[1])};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_FCVTLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTLv4i32: {  // fcvtl2 vd.2d, vn.4s
      const float* n = operands[0].getAsVector<float>();
      double out[2] = {static_cast<double>(n[2]), static_cast<double>(n[3])};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_FCVTLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSUWDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSUWSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSUXDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSUXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMSv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUUWDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUUWSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUUXDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUUXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTMUv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSUWDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSUWSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSUXDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSUXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNSv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUUWDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUUWSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUUXDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUUXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNUv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNv2i32: {  // fcvtn vd.2s, vn.2d
      const double* n = operands[0].getAsVector<double>();
      float out[2] = {static_cast<float>(n[0]), static_cast<float>(n[1])};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_FCVTNv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTNv4i32: {  // fcvtn2 vd.4s, vn.2d
      const double* n = operands[0].getAsVector<double>();
      float out[4] = {0.f, 0.f, static_cast<float>(n[0]),
                      static_cast<float>(n[1])};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_FCVTNv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSUWDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSUWSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSUXDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSUXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPSv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUUWDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUUWSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUUXDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUUXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTPUv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTSDr: {  // fcvt sd, dn
      // TODO: Handle NaNs, denorms, and saturation?
      results[0] =
          RegisterValue(static_cast<float>(operands[0].get<double>()), 256);
      break;
    }
    case Opcode::AArch64_FCVTSHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTXNv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTXNv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTXNv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSSWDri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSSWHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSSWSri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSSXDri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSSXHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSSXSri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSUWDr: {  // fcvtzs wd, dn
      double n = operands[0].get<double>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = RegisterValue(static_cast<int32_t>(std::trunc(n)), 8);
      break;
    }
    case Opcode::AArch64_FCVTZSUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSUWSr: {  // fcvtzs wd, sn
      float n = operands[0].get<float>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = RegisterValue(static_cast<int32_t>(std::trunc(n)), 8);
      break;
    }
    case Opcode::AArch64_FCVTZSUXDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSUXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZS_ZPmZ_DtoD: {  // fcvtzs zd.d, pg/m, zn.d
      results[0] =
          sveHelp::sveFcvtzsPredicated<int64_t, double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FCVTZS_ZPmZ_DtoS: {  // fcvtzs zd.s, pg/m, zn.d
      results[0] =
          sveHelp::sveFcvtzsPredicated<int32_t, double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FCVTZS_ZPmZ_HtoD: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZS_ZPmZ_HtoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZS_ZPmZ_HtoS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZS_ZPmZ_StoD: {  // fcvtzs zd.d, pg/m, zn.s
      results[0] =
          sveHelp::sveFcvtzsPredicated<int64_t, float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FCVTZS_ZPmZ_StoS: {  // fcvtzs zd.s, pg/m, zn.s
      results[0] =
          sveHelp::sveFcvtzsPredicated<int32_t, float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FCVTZSd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv2f64: {  // fcvtzs vd.2d, vn.2d
      const double* n = operands[0].getAsVector<double>();
      // TODO: Handle NaNs, denorms, and saturation
      int64_t out[2] = {static_cast<int64_t>(std::trunc(n[0])),
                        static_cast<int64_t>(std::trunc(n[1]))};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_FCVTZSv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZSv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUSWDri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUSWHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUSWSri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUSXDri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUSXHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUSXSri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUUWDr: {  // fcvtzu wd, dn
      const double n = operands[0].get<double>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = RegisterValue(static_cast<int32_t>(std::trunc(n)), 8);
      break;
    }
    case Opcode::AArch64_FCVTZUUWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUUWSr: {  // fcvtzu wd, sn
      const float n = operands[0].get<float>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = RegisterValue(static_cast<int32_t>(std::trunc(n)), 8);
      break;
    }
    case Opcode::AArch64_FCVTZUUXDr: {  // fcvtzu xd, dn
      const double n = operands[0].get<double>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = static_cast<int64_t>(std::trunc(n));
      break;
    }
    case Opcode::AArch64_FCVTZUUXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUUXSr: {  // fcvtzu xd, sn
      const float n = operands[0].get<float>();
      // TODO: Handle NaNs, denorms, and saturation
      results[0] = static_cast<int64_t>(std::trunc(n));
      break;
    }
    case Opcode::AArch64_FCVTZU_ZPmZ_DtoD: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZU_ZPmZ_DtoS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZU_ZPmZ_HtoD: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZU_ZPmZ_HtoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZU_ZPmZ_HtoS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZU_ZPmZ_StoD: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZU_ZPmZ_StoS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVTZUv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVT_ZPmZ_DtoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVT_ZPmZ_DtoS: {  // fcvt zd.s, pg/m, zn.d
      results[0] = sveHelp::sveFcvtPredicated<float, double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FCVT_ZPmZ_HtoD: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVT_ZPmZ_HtoS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FCVT_ZPmZ_StoD: {  // fcvt zd.d, pg/m, zn.s
      results[0] = sveHelp::sveFcvtPredicated<double, float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FCVT_ZPmZ_StoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDIVDrr: {  // fdiv dd, dn, dm
      results[0] = {divideHelp::div_3ops<double>(operands), 256};
      break;
    }
    case Opcode::AArch64_FDIVHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDIVR_ZPmZ_D: {  // fdivr zdn.d, pg/m, zdn.d, zm.d
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<double>(
          operands, VL_bits,
          [](double x, double y) -> double { return (y / x); });
      break;
    }
    case Opcode::AArch64_FDIVR_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDIVR_ZPmZ_S: {  // fdivr zdn.s, pg/m, zdn.s, zm.s
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<float>(
          operands, VL_bits, [](float x, float y) -> float { return (y / x); });
      break;
    }
    case Opcode::AArch64_FDIVSrr: {  // fdiv sd, sn, sm
      results[0] = {divideHelp::div_3ops<float>(operands), 256};
      break;
    }
    case Opcode::AArch64_FDIV_ZPmZ_D: {  // fdiv zdn.d, pg/m, zdn.d, zm.d
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<double>(
          operands, VL_bits,
          [](double x, double y) -> double { return (x / y); });
      break;
    }
    case Opcode::AArch64_FDIV_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDIV_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDIVv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDIVv2f64: {  // fdiv vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecLogicOp_3vecs<double, 2>(
          operands, [](double x, double y) -> double { return x / y; });
      break;
    }
    case Opcode::AArch64_FDIVv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDIVv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDIVv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDUP_ZI_D: {  // fdup zd.d, #imm
      results[0] = sveHelp::sveDup_immOrScalar<double>(operands, metadata,
                                                       VL_bits, true);
      break;
    }
    case Opcode::AArch64_FDUP_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FDUP_ZI_S: {  // fdup zd.s, #imm
      results[0] =
          sveHelp::sveDup_immOrScalar<float>(operands, metadata, VL_bits, true);
      break;
    }
    case Opcode::AArch64_FEXPA_ZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FEXPA_ZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FEXPA_ZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FJCVTZS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMADDDrrr: {  // fmadd dn, dm, da
      results[0] = {multiplyHelp::madd_4ops<double>(operands), 256};
      break;
    }
    case Opcode::AArch64_FMADDHrrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMADDSrrr: {  // fmadd sn, sm, sa
      results[0] = {multiplyHelp::madd_4ops<float>(operands), 256};
      break;
    }
    case Opcode::AArch64_FMAD_ZPmZZ_D: {  // fmad zd.d, pg/m, zn.d, zm.d
      results[0] = sveHelp::sveFmadPredicated_vecs<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMAD_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAD_ZPmZZ_S: {  // fmad zd.s, pg/m, zn.s, zm.s
      results[0] = sveHelp::sveFmadPredicated_vecs<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMAXDrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMDrr: {  // fmaxnm dd, dn, dm
      results[0] = floatHelp::fmaxnm_3ops<double>(operands);
      break;
    }
    case Opcode::AArch64_FMAXNMHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMPv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMPv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMPv2i16p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMPv2i32p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMPv2i64p: {  // fmaxnmp dd, vd.2d
      const double* n = operands[0].getAsVector<double>();
      results[0] = {std::fmax(n[0], n[1]), 256};
      break;
    }
    case Opcode::AArch64_FMAXNMPv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMPv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMPv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMSrr: {  // fmaxnm sd, sn, sm
      results[0] = floatHelp::fmaxnm_3ops<float>(operands);
      break;
    }
    case Opcode::AArch64_FMAXNMV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNM_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNM_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNM_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNM_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNM_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNM_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMv2f64: {  // fmaxnm vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecLogicOp_3vecs<double, 2>(
          operands,
          [](double x, double y) -> double { return std::fmax(x, y); });
      break;
    }
    case Opcode::AArch64_FMAXNMv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXNMv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXPv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXPv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXPv2i16p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXPv2i32p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXPv2i64p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXPv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXPv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXPv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXSrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAX_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAX_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAX_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAX_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAX_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAX_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMAXv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINDrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMDrr: {  // fminnm dd, dn, dm
      results[0] = floatHelp::fminnm_3ops<double>(operands);
      break;
    }
    case Opcode::AArch64_FMINNMHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMPv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMPv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMPv2i16p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMPv2i32p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMPv2i64p: {  // fminnmp dd, vd.2d
      const double* n = operands[0].getAsVector<double>();
      results[0] = {std::fmin(n[0], n[1]), 256};
      break;
    }
    case Opcode::AArch64_FMINNMPv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMPv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMPv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMSrr: {  // fminnm sd, sn, sm
      results[0] = floatHelp::fminnm_3ops<float>(operands);
      break;
    }
    case Opcode::AArch64_FMINNMV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNM_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNM_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNM_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNM_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNM_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNM_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMv2f64: {  // fminnm vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecLogicOp_3vecs<double, 2>(
          operands,
          [](double x, double y) -> double { return std::fmin(x, y); });
      break;
    }
    case Opcode::AArch64_FMINNMv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINNMv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINPv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINPv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINPv2i16p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINPv2i32p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINPv2i64p: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINPv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINPv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINPv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINSrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMIN_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMIN_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMIN_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMIN_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMIN_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMIN_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMINv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLA_ZPmZZ_D: {  // fmla zd.d, pg/m, zn.d, zm.d
      results[0] = sveHelp::sveMlaPredicated_vecs<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMLA_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLA_ZPmZZ_S: {  // fmla zd.s, pg/m, zn.s, zm.s
      results[0] = sveHelp::sveMlaPredicated_vecs<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMLA_ZZZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLA_ZZZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLA_ZZZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv1i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv1i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv1i64_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv2f64: {  // fmla vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecFmla_3vecs<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FMLAv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv2i64_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv4f32: {  // fmla vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecFmla_3vecs<float, 4>(operands);
      break;
    }
    case Opcode::AArch64_FMLAv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv4i32_indexed: {  // fmla vd.4s, vn.4s, vm.s[index]
      results[0] = neonHelp::vecFmlaIndexed_3vecs<float, 4>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FMLAv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLAv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLS_ZPmZZ_D: {  // fmls zd.d, pg/m, zn.d, zm.d
      results[0] = sveHelp::sveFmlsPredicated_vecs<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMLS_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLS_ZPmZZ_S: {  // fmls zd.s, pg/m, zn.s, zm.s
      results[0] = sveHelp::sveFmlsPredicated_vecs<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMLS_ZZZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLS_ZZZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLS_ZZZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv1i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv1i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv1i64_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv2f64: {  // fmls vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecFmls_3vecs<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FMLSv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv2i64_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv4f32: {  // fmls vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecFmls_3vecs<float, 4>(operands);
      break;
    }
    case Opcode::AArch64_FMLSv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv4i32_indexed: {  // fmls vd.4s, vn.4s, vm.s[index]
      results[0] = neonHelp::vecFmlsIndexed_3vecs<float, 4>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FMLSv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMLSv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVD0: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVDXHighr: {  // fmov xd, vn.d[1]
      results[0] = operands[0].getAsVector<double>()[1];
      break;
    }
    case Opcode::AArch64_FMOVDXr: {  // fmov xd, dn
      results[0] = operands[0].get<double>();
      break;
    }
    case Opcode::AArch64_FMOVDi: {  // fmov dn, #imm
      results[0] = RegisterValue(metadata.operands[1].fp, 256);
      break;
    }
    case Opcode::AArch64_FMOVDr: {  // fmov dd, dn
      results[0] = RegisterValue(operands[0].get<double>(), 256);
      break;
    }
    case Opcode::AArch64_FMOVH0: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVHWr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVHXr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVHi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVS0: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVSWr: {  // fmov wd, sn
      results[0] = RegisterValue(operands[0].get<float>(), 8);
      break;
    }
    case Opcode::AArch64_FMOVSi: {  // fmov sn, #imm
      results[0] =
          RegisterValue(static_cast<float>(metadata.operands[1].fp), 256);
      break;
    }
    case Opcode::AArch64_FMOVSr: {  // fmov sd, sn
      results[0] = RegisterValue(operands[0].get<float>(), 256);
      break;
    }
    case Opcode::AArch64_FMOVWHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVWSr: {  // fmov sd, wn
      results[0] = RegisterValue(operands[0].get<float>(), 256);
      break;
    }
    case Opcode::AArch64_FMOVXDHighr: {  // fmov vd.d[1], xn
      double out[2] = {operands[0].get<double>(), operands[1].get<double>()};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_FMOVXDr: {  // fmov dd, xn
      results[0] = RegisterValue(operands[0].get<double>(), 256);
      break;
    }
    case Opcode::AArch64_FMOVXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVv2f32_ns: {  // fmov vd.2s, #imm
      results[0] = neonHelp::vecMovi_imm<float, 2>(metadata);
      break;
    }
    case Opcode::AArch64_FMOVv2f64_ns: {  // fmov vd.2d, #imm
      results[0] = neonHelp::vecMovi_imm<double, 2>(metadata);
      break;
    }
    case Opcode::AArch64_FMOVv4f16_ns: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMOVv4f32_ns: {  // fmov vd.4s, #imm
      results[0] = neonHelp::vecMovi_imm<float, 4>(metadata);
      break;
    }
    case Opcode::AArch64_FMOVv8f16_ns: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMSB_ZPmZZ_D: {  // fmsb zd.d, pg/m, zn.d, zm.d
      results[0] = sveHelp::sveFmsbPredicated_vecs<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMSB_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMSB_ZPmZZ_S: {  // fmsb zd.s, pg/m, zn.s, zm.s
      results[0] = sveHelp::sveFmsbPredicated_vecs<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMSUBDrrr: {  // fmsub dn, dm, da
      results[0] = {multiplyHelp::msub_4ops<double>(operands), 256};
      break;
    }
    case Opcode::AArch64_FMSUBHrrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMSUBSrrr: {  // fmsub sn, sm, sa
      results[0] = {multiplyHelp::msub_4ops<float>(operands), 256};
      break;
    }
    case Opcode::AArch64_FMULDrr: {  // fmul dd, dn, dm
      results[0] = {multiplyHelp::mul_3ops<double>(operands), 256};
      break;
    }
    case Opcode::AArch64_FMULHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULSrr: {  // fmul sd, sn, sm
      results[0] = {multiplyHelp::mul_3ops<float>(operands), 256};
      break;
    }
    case Opcode::AArch64_FMULX16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULX32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULX64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULX_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULX_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULX_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv1i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv1i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv1i64_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv2i64_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULXv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMUL_ZPmI_D: {  // fmul zd.d, pg/m, zn.d, #imm
      results[0] =
          sveHelp::sveMulPredicated<double>(operands, metadata, VL_bits, true);
      break;
    }
    case Opcode::AArch64_FMUL_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMUL_ZPmI_S: {  // fmul zd.s, pg/m, zn.s, #imm
      results[0] =
          sveHelp::sveMulPredicated<float>(operands, metadata, VL_bits, true);
      break;
    }
    case Opcode::AArch64_FMUL_ZPmZ_D: {  // fmul zdn.d, pg/m, zdn.d, zm.d
      results[0] =
          sveHelp::sveMulPredicated<double>(operands, metadata, VL_bits, false);
      break;
    }
    case Opcode::AArch64_FMUL_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMUL_ZPmZ_S: {  // fmul zdn.s, pg/m, zdn.s, zm.s
      results[0] =
          sveHelp::sveMulPredicated<float>(operands, metadata, VL_bits, false);
      break;
    }
    case Opcode::AArch64_FMUL_ZZZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMUL_ZZZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMUL_ZZZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMUL_ZZZ_D: {  // fmul zd.d, zn.d, zm.d
      results[0] = sveHelp::sveFmul_3ops<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMUL_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMUL_ZZZ_S: {  // fmul zd.s, zn.s, zm.s
      results[0] = sveHelp::sveFmul_3ops<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FMULv1i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULv1i32_indexed: {  // fmul sd, sn, vm.s[index]
      results[0] = neonHelp::vecFmulIndexed_vecs<float, 1>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FMULv1i64_indexed: {  // fmul dd, dn, vm.d[index]
      results[0] = neonHelp::vecFmulIndexed_vecs<double, 1>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FMULv2f32: {  // fmul vd.2s, vn.2s, vm.2s
      results[0] = neonHelp::vecLogicOp_3vecs<float, 2>(
          operands, [](float x, float y) -> float { return x * y; });
      break;
    }
    case Opcode::AArch64_FMULv2f64: {  // fmul vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecLogicOp_3vecs<double, 2>(
          operands, [](double x, double y) -> double { return x * y; });
      break;
    }
    case Opcode::AArch64_FMULv2i32_indexed: {  // fmul vd.2s, vn.2s, vm.s[index]
      results[0] = neonHelp::vecFmulIndexed_vecs<float, 2>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FMULv2i64_indexed: {  // fmul vd.2d, vn.2d, vm.d[index]
      results[0] = neonHelp::vecFmulIndexed_vecs<double, 2>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FMULv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULv4f32: {  // fmul vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecLogicOp_3vecs<float, 4>(
          operands, [](float x, float y) -> float { return x * y; });
      break;
    }
    case Opcode::AArch64_FMULv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULv4i32_indexed: {  // fmul vd.4s, vn.4s, vm.s[index]
      results[0] = neonHelp::vecFmulIndexed_vecs<float, 4>(operands, metadata);
      break;
    }
    case Opcode::AArch64_FMULv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FMULv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNEGDr: {  // fneg dd, dn
      results[0] = RegisterValue(-operands[0].get<double>(), 256);
      break;
    }
    case Opcode::AArch64_FNEGHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNEGSr: {  // fneg sd, sn
      results[0] = RegisterValue(-operands[0].get<float>(), 256);
      break;
    }
    case Opcode::AArch64_FNEG_ZPmZ_D: {  // fneg zd.d, pg/m, zn.d
      results[0] = sveHelp::sveFnegPredicated<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FNEG_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNEG_ZPmZ_S: {  // fneg zd.s, pg/m, zn.s
      results[0] = sveHelp::sveFnegPredicated<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FNEGv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNEGv2f64: {  // fneg vd.2d, vn.2d
      results[0] = neonHelp::vecFneg_2ops<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FNEGv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNEGv4f32: {  // fneg vd.4s, vn.4s
      results[0] = neonHelp::vecFneg_2ops<float, 4>(operands);
      break;
    }
    case Opcode::AArch64_FNEGv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMADDDrrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMADDHrrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMADDSrrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMAD_ZPmZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMAD_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMAD_ZPmZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMLA_ZPmZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMLA_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMLA_ZPmZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMLS_ZPmZZ_D: {  // fnmls zd.d, pg/m, zn.d, zm.d
      results[0] = sveHelp::sveFnmlsPredicated<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FNMLS_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMLS_ZPmZZ_S: {  // fnmls zd.s, pg/m, zn.s, zm.s
      results[0] = sveHelp::sveFnmlsPredicated<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FNMSB_ZPmZZ_D: {  // fnmsb zdn.d, pg/m, zm.d, za.d
      results[0] = sveHelp::sveFnmsbPredicated<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FNMSB_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMSB_ZPmZZ_S: {  // fnmsb zdn.s, pg/m, zm.s, za.s
      results[0] = sveHelp::sveFnmsbPredicated<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FNMSUBDrrr: {  // fnmsub dd, dn, dm, da
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      double a = operands[2].get<double>();
      results[0] = {std::fma(n, m, -a), 256};
      break;
    }
    case Opcode::AArch64_FNMSUBHrrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMSUBSrrr: {  // fnmsub sd, sn, sm, sa
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      float a = operands[2].get<float>();
      results[0] = {std::fma(n, m, -a), 256};
      break;
    }
    case Opcode::AArch64_FNMULDrr: {  // fnmul dd, dn, dm
      double n = operands[0].get<double>();
      double m = operands[1].get<double>();
      results[0] = {-(n * m), 256};
      break;
    }
    case Opcode::AArch64_FNMULHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FNMULSrr: {  // fnmul sd, sn, sm
      float n = operands[0].get<float>();
      float m = operands[1].get<float>();
      results[0] = {-(n * m), 256};
      break;
    }
    case Opcode::AArch64_FRECPE_ZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPE_ZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPE_ZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPEv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPEv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPEv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPEv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPEv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPEv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPEv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPEv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPS16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPS32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPS64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPS_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPS_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPS_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPSv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPSv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPSv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPSv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPSv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPX_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPX_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPX_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPXv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPXv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRECPXv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTADr: {  // frinta dd, dn
      results[0] = RegisterValue(round(operands[0].get<double>()), 256);
      break;
    }
    case Opcode::AArch64_FRINTAHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTASr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTA_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTA_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTA_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTAv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTAv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTAv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTAv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTAv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTIDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTIHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTISr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTI_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTI_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTI_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTIv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTIv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTIv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTIv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTIv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTMDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTMHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTMSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTM_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTM_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTM_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTMv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTMv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTMv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTMv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTMv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTNDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTNHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTNSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTN_ZPmZ_D: {  // frintn zd.d, pg/m, zn.d
      results[0] =
          sveHelp::sveFrintnPredicated<int64_t, double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FRINTN_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTN_ZPmZ_S: {  // frintn zd.s, pg/m, zn.s
      results[0] =
          sveHelp::sveFrintnPredicated<int32_t, float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FRINTNv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTNv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTNv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTNv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTNv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTPDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTPHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTPSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTP_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTP_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTP_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTPv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTPv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTPv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTPv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTPv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTXDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTXHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTXSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTX_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTX_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTX_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTXv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTXv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTXv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTXv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTXv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZDr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZSr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZ_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZ_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZ_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRINTZv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTE_ZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTE_ZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTE_ZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTEv1f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTEv1i32: {  // frsqrte sd, sn
      results[0] = neonHelp::vecFrsqrte_2ops<float, 1>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTEv1i64: {  // frsqrte dd, dn
      results[0] = neonHelp::vecFrsqrte_2ops<double, 1>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTEv2f32: {  // frsqrte vd.2s, vn.2s
      results[0] = neonHelp::vecFrsqrte_2ops<float, 2>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTEv2f64: {  // frsqrte vd.2d, vn.2d
      results[0] = neonHelp::vecFrsqrte_2ops<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTEv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTEv4f32: {  // frsqrte vd.4s, vn.4s
      results[0] = neonHelp::vecFrsqrte_2ops<float, 4>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTEv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTS16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTS32: {  // frsqrts sd, sn, sm
      results[0] = neonHelp::vecFrsqrts_3ops<float, 1>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTS64: {  // frsqrts dd, dn, dm
      results[0] = neonHelp::vecFrsqrts_3ops<double, 1>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTS_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTS_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTS_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTSv2f32: {  // frsqrts vd.2s, vn.2s, vn.2s
      results[0] = neonHelp::vecFrsqrts_3ops<float, 2>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTSv2f64: {  // frsqrts vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecFrsqrts_3ops<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTSv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FRSQRTSv4f32: {  // frsqrts vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecFrsqrts_3ops<float, 4>(operands);
      break;
    }
    case Opcode::AArch64_FRSQRTSv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSCALE_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSCALE_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSCALE_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSQRTDr: {  // fsqrt dd, dn
      results[0] = {::sqrt(operands[0].get<double>()), 256};
      break;
    }
    case Opcode::AArch64_FSQRTHr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSQRTSr: {  // fsqrt sd, sn
      results[0] = {::sqrtf(operands[0].get<float>()), 256};
      break;
    }
    case Opcode::AArch64_FSQRT_ZPmZ_D: {  // fsqrt zd.d, pg/m, zn.d
      results[0] = sveHelp::sveFsqrtPredicated_2vecs<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FSQRT_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSQRT_ZPmZ_S: {  // fsqrt zd.s, pg/m, zn.s
      results[0] = sveHelp::sveFsqrtPredicated_2vecs<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FSQRTv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSQRTv2f64: {  // fsqrt vd.2d, vn.2d
      results[0] = neonHelp::vecFsqrt_2ops<double, 2>(operands);
      break;
    }
    case Opcode::AArch64_FSQRTv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSQRTv4f32: {  // fsqrt vd.4s, vn.4s
      results[0] = neonHelp::vecFsqrt_2ops<float, 4>(operands);
      break;
    }
    case Opcode::AArch64_FSQRTv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBDrr: {  // fsub dd, dn, dm
      results[0] = neonHelp::vecLogicOp_3vecs<double, 1>(
          operands, [](double x, double y) -> double { return x - y; });
      break;
    }
    case Opcode::AArch64_FSUBHrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBR_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBR_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBR_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBR_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBSrr: {  // fsub ss, sn, sm
      results[0] = neonHelp::vecLogicOp_3vecs<float, 1>(
          operands, [](double x, double y) -> double { return x - y; });
      break;
    }
    case Opcode::AArch64_FSUB_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUB_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUB_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUB_ZPmZ_D: {  // fsub zdn.d, pg/m, zdn.d, zm.d
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<double>(
          operands, VL_bits,
          [](double x, double y) -> double { return x - y; });
      break;
    }
    case Opcode::AArch64_FSUB_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUB_ZPmZ_S: {  // fsub zdn.s, pg/m, zdn.s, zm.s
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<float>(
          operands, VL_bits, [](float x, float y) -> float { return x - y; });
      break;
    }
    case Opcode::AArch64_FSUB_ZZZ_D: {  // fsub zd.d, zn.d, zm.d
      results[0] = sveHelp::sveSub_3vecs<double>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FSUB_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUB_ZZZ_S: {  // fsub zd.s, zn.s, zm.s
      results[0] = sveHelp::sveSub_3vecs<float>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_FSUBv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBv2f64: {  // fsub vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecLogicOp_3vecs<double, 2>(
          operands, [](double x, double y) -> double { return x - y; });
      break;
    }
    case Opcode::AArch64_FSUBv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FSUBv4f32: {  // fsub vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecLogicOp_3vecs<float, 4>(
          operands, [](float x, float y) -> float { return x - y; });
      break;
    }
    case Opcode::AArch64_FSUBv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FTMAD_ZZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FTMAD_ZZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FTMAD_ZZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FTSMUL_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FTSMUL_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FTSMUL_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FTSSEL_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FTSSEL_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_FTSSEL_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1B_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1B_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1B_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1B_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1B_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1B_S_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1B_S_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1D_IMM_REAL: {  // ld1d {zd.d}, pg/z, [zn.d{, #imm}]
      // LOAD
      const uint64_t* p = operands[0].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[32] = {0};
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          out[i] = memoryData[index].get<uint64_t>();
          index++;
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_GLD1D_REAL:  // ld1d {zt.d}, pg/z, [xn, zm.d]
      // LOAD
      [[fallthrough]];
    case Opcode::AArch64_GLD1D_SCALED_REAL: {  // ld1d {zt.d}, pg/z, [xn, zm.d,
                                               // LSL #3]
      // LOAD
      const uint64_t* p = operands[0].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      uint64_t out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          out[i] = memoryData[index].get<uint64_t>();
          index++;
        }
      }

      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_GLD1D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_D_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_S_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_S_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_S_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1H_S_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SB_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SB_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SB_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SB_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SB_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SB_S_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SB_S_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_D_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_S_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_S_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_S_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SH_S_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SW_D_IMM_REAL: {  // ld1sw {zd.d}, pg/z, [zn.d{,
                                               // #imm}]
      // LOAD
      const uint64_t* p = operands[0].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      int64_t out[32] = {0};
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          out[i] = static_cast<int64_t>(memoryData[index].get<int32_t>());
          index++;
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_GLD1SW_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SW_D_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SW_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SW_D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SW_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1SW_D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_D_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLD1W_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1B_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1B_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1B_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1B_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1B_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1B_S_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1B_S_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1D_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_D_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_S_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_S_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_S_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1H_S_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SB_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SB_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SB_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SB_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SB_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SB_S_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SB_S_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_D_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_S_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_S_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_S_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SH_S_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SW_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SW_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SW_D_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SW_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SW_D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SW_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1SW_D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_D_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_D_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_D_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_D_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_D_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_SXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_SXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_UXTW_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_GLDFF1W_UXTW_SCALED_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_HINT: {  // nop|yield|wfe|wfi|etc...
      // TODO: Observe hints
      break;
    }
    case Opcode::AArch64_HLT: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_HVC: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INCB_XPiI: {  // incb xdn{, pattern{, #imm}}
      const uint64_t n = operands[0].get<uint64_t>();
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      results[0] = n + ((VL_bits / 8) * imm);
      break;
    }
    case Opcode::AArch64_INCD_XPiI: {  // incd xdn{, pattern{, #imm}}
      const uint64_t n = operands[0].get<uint64_t>();
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      results[0] = n + ((VL_bits / 64) * imm);
      break;
    }
    case Opcode::AArch64_INCD_ZPiI: {  // incd zdn.d{, pattern{, #imm}}
      results[0] = sveHelp::sveInc_imm<uint64_t>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_INCH_XPiI: {  // inch xdn{, pattern{, #imm}}
      const uint64_t n = operands[0].get<uint64_t>();
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      results[0] = n + ((VL_bits / 16) * imm);
      break;
    }
    case Opcode::AArch64_INCH_ZPiI: {  // inch zdn.h{, pattern{, #imm}}
      results[0] = sveHelp::sveInc_imm<uint16_t>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_INCP_XP_B: {  // incp xdn, pm.b
      results[0] = sveHelp::sveIncp_gpr<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_INCP_XP_D: {  // incp xdn, pm.d
      results[0] = sveHelp::sveIncp_gpr<uint64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_INCP_XP_H: {  // incp xdn, pm.h
      results[0] = sveHelp::sveIncp_gpr<uint16_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_INCP_XP_S: {  // incp xdn, pm.s
      results[0] = sveHelp::sveIncp_gpr<uint32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_INCP_ZP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INCP_ZP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INCP_ZP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INCW_XPiI: {  // incw xdn{, pattern{, #imm}}
      const uint64_t n = operands[0].get<uint64_t>();
      const uint8_t imm = static_cast<uint8_t>(metadata.operands[1].imm);
      results[0] = n + ((VL_bits / 32) * imm);
      break;
    }
    case Opcode::AArch64_INCW_ZPiI: {  // incw zdn.s{, pattern{, #imm}}
      results[0] = sveHelp::sveInc_imm<uint32_t>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_INDEX_II_B: {  // index zd.b, #imm, #imm
      results[0] =
          sveHelp::sveIndex<int8_t>(operands, metadata, VL_bits, true, true);
      break;
    }
    case Opcode::AArch64_INDEX_II_D: {  // index zd.d, #imm, #imm
      results[0] =
          sveHelp::sveIndex<int64_t>(operands, metadata, VL_bits, true, true);
      break;
    }
    case Opcode::AArch64_INDEX_II_H: {  // index zd.h, #imm, #imm
      results[0] =
          sveHelp::sveIndex<int16_t>(operands, metadata, VL_bits, true, true);
      break;
    }
    case Opcode::AArch64_INDEX_II_S: {  // index zd.s, #imm, #imm
      results[0] =
          sveHelp::sveIndex<int32_t>(operands, metadata, VL_bits, true, true);
      break;
    }
    case Opcode::AArch64_INDEX_IR_B: {  // index zd.b, #imm, wn
      results[0] = sveHelp::sveIndex<int8_t, int32_t>(operands, metadata,
                                                      VL_bits, true, false);
      break;
    }
    case Opcode::AArch64_INDEX_IR_D: {  // index zd.d, #imm, xn
      results[0] = sveHelp::sveIndex<int64_t, int64_t>(operands, metadata,
                                                       VL_bits, true, false);
      break;
    }
    case Opcode::AArch64_INDEX_IR_H: {  // index zd.h, #imm, wn
      results[0] = sveHelp::sveIndex<int16_t, int32_t>(operands, metadata,
                                                       VL_bits, true, false);
      break;
    }
    case Opcode::AArch64_INDEX_IR_S: {  // index zd.s, #imm, wn
      results[0] = sveHelp::sveIndex<int32_t, int32_t>(operands, metadata,
                                                       VL_bits, true, false);
      break;
    }
    case Opcode::AArch64_INDEX_RI_B: {  // index zd.b, wn, #imm
      results[0] = sveHelp::sveIndex<int8_t, int32_t>(operands, metadata,
                                                      VL_bits, false, true);
      break;
    }
    case Opcode::AArch64_INDEX_RI_D: {  // index zd.d, xn, #imm
      results[0] = sveHelp::sveIndex<int64_t, int64_t>(operands, metadata,
                                                       VL_bits, false, true);
      break;
    }
    case Opcode::AArch64_INDEX_RI_H: {  // index zd.h, wn, #imm
      results[0] = sveHelp::sveIndex<int16_t, int32_t>(operands, metadata,
                                                       VL_bits, false, true);
      break;
    }
    case Opcode::AArch64_INDEX_RI_S: {  // index zd.s, wn, #imm
      results[0] = sveHelp::sveIndex<int32_t, int32_t>(operands, metadata,
                                                       VL_bits, false, true);
      break;
    }
    case Opcode::AArch64_INDEX_RR_B: {  // index zd.b, wn, wm
      results[0] = sveHelp::sveIndex<int8_t, int32_t>(operands, metadata,
                                                      VL_bits, false, false);
      break;
    }
    case Opcode::AArch64_INDEX_RR_D: {  // index zd.d, xn, xm
      results[0] = sveHelp::sveIndex<int64_t, int64_t>(operands, metadata,
                                                       VL_bits, false, false);
      break;
    }
    case Opcode::AArch64_INDEX_RR_H: {  // index zd.h, wn, wm
      results[0] = sveHelp::sveIndex<int16_t, int32_t>(operands, metadata,
                                                       VL_bits, false, false);
      break;
    }
    case Opcode::AArch64_INDEX_RR_S: {  // index zd.s, wn, wm
      results[0] = sveHelp::sveIndex<int32_t, int32_t>(operands, metadata,
                                                       VL_bits, false, false);
      break;
    }
    case Opcode::AArch64_INSR_ZR_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INSR_ZR_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INSR_ZR_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INSR_ZR_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INSR_ZV_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INSR_ZV_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INSR_ZV_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INSR_ZV_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INSvi16gpr: {  // ins vd.h[index], wn
      results[0] =
          neonHelp::vecInsIndex_gpr<uint16_t, uint32_t, 8>(operands, metadata);
      break;
    }
    case Opcode::AArch64_INSvi16lane: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_INSvi32gpr: {  // ins vd.s[index], wn
      results[0] =
          neonHelp::vecInsIndex_gpr<uint32_t, uint32_t, 4>(operands, metadata);
      break;
    }
    case Opcode::AArch64_INSvi32lane: {  // ins vd.s[index1], vn.s[index2]
      results[0] = neonHelp::vecIns_2Index<uint32_t, 4>(operands, metadata);
      break;
    }
    case Opcode::AArch64_INSvi64gpr: {  // ins vd.d[index], xn
      results[0] =
          neonHelp::vecInsIndex_gpr<uint64_t, uint64_t, 2>(operands, metadata);
      break;
    }
    case Opcode::AArch64_INSvi64lane: {  // ins vd.d[index1], vn.d[index2]
      results[0] = neonHelp::vecIns_2Index<uint64_t, 2>(operands, metadata);
      break;
    }
    case Opcode::AArch64_INSvi8gpr: {  // ins vd.b[index], wn
      results[0] =
          neonHelp::vecInsIndex_gpr<uint8_t, uint32_t, 16>(operands, metadata);
      break;
    }
    case Opcode::AArch64_INSvi8lane: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ISB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTA_RPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTA_RPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTA_RPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTA_RPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTA_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTA_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTA_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTA_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTB_RPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTB_RPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTB_RPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTB_RPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTB_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTB_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTB_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LASTB_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1B: {  // ld1b  {zt.b}, pg/z, [xn, xm]
      // LOAD
      const uint64_t* p = operands[0].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 8;
      uint16_t index = 0;
      uint8_t out[256] = {0};
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << (i % 64);
        if (p[i / 64] & shifted_active) {
          out[i] = memoryData[index].get<uint8_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1B_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1B_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1B_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1B_H_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1B_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1B_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1B_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1D: {  // ld1d  {zt.d}, pg/z, [xn, xm, lsl #3]
      // LOAD
      const uint64_t* p = operands[0].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      uint64_t out[32] = {0};
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          out[i] = memoryData[index].get<uint64_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1D_IMM_REAL: {  // ld1d  {zt.d}, pg/z, [xn{, #imm,
                                           // mul vl}]
      // LOAD
      const uint64_t* p = operands[0].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      uint64_t out[32] = {0};
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          out[i] = memoryData[index].get<uint64_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Fourv16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Fourv8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1H: {  // ld1h  {zt.h}, pg/z, [xn, xm, lsl #1]
      // LOAD
      const uint64_t* p = operands[0].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 16;
      uint16_t index = 0;
      uint16_t out[128] = {0};
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 32) * 2);
        if (p[i / 32] & shifted_active) {
          out[i] = memoryData[index].get<uint16_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1H_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1H_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1H_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1H_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1H_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Onev8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RB_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RB_H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RB_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RB_S_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RD_IMM: {  // ld1rd {zt.d}, pg/z, [xn, #imm]
      // LOAD
      const uint16_t partition_num = VL_bits / 64;
      uint64_t out[32] = {0};
      uint16_t index = 0;
      // Check if any lanes are active, otherwise set all to 0 and break early
      bool active = false;
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      for (int i = 0; i < 4; i++) {
        if (p[i] != 0) {
          active = true;
          break;
        }
      }

      if (active) {
        uint64_t data = memoryData[0].get<uint64_t>();
        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = p[index / 8] & 1ull << ((index % 8) * 8);
          out[i] = shifted_active ? data : 0;
          index++;
        }
      }

      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1RH_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RH_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RH_S_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RQ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RQ_B_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RQ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RQ_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RQ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RQ_H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RQ_W: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RQ_W_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RSB_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RSB_H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RSB_S_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RSH_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RSH_S_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RSW_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RW_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1RW_IMM: {  // ld1rw {zt.s}, pg/z, [xn, #imm]
      // LOAD
      const uint16_t partition_num = VL_bits / 32;
      uint32_t out[64] = {0};
      uint16_t index = 0;
      // Check if any lanes are active, otherwise set all to 0 and break early
      bool active = false;
      const uint64_t* p = operands[0].getAsVector<uint64_t>();
      for (int i = 0; i < 4; i++) {
        if (p[i] != 0) {
          active = true;
          break;
        }
      }
      if (active) {
        uint32_t data = memoryData[0].get<uint32_t>();
        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = p[index / 16] & 1ull << ((index % 16) * 4);
          out[i] = shifted_active ? data : 0;
          index++;
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Rv16b: {  // ld1r {vt.16b}, [xn]
      // LOAD
      uint8_t val = memoryData[0].get<uint8_t>();
      uint8_t out[16] = {val, val, val, val, val, val, val, val,
                         val, val, val, val, val, val, val, val};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Rv16b_POST: {  // ld1r {vt.16b}, [xn], #imm
      // LOAD
      uint8_t val = memoryData[0].get<uint8_t>();
      uint8_t out[16] = {val, val, val, val, val, val, val, val,
                         val, val, val, val, val, val, val, val};
      results[0] = {out, 256};
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1Rv1d: {  // ld1r {vt.1d}, [xn]
      // LOAD
      uint64_t val = memoryData[0].get<uint64_t>();
      uint64_t out[2] = {val, 0};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Rv1d_POST: {  // ld1r {vt.1d}, [xn], #imm
      // LOAD
      uint64_t val = memoryData[0].get<uint64_t>();
      uint64_t out[2] = {val, 0};
      results[0] = {out, 256};
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1Rv2d: {  // ld1r {vt.2d}, [xn]
      // LOAD
      uint64_t val = memoryData[0].get<uint64_t>();
      uint64_t out[2] = {val, val};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Rv2d_POST: {  // ld1r {vt.2d}, [xn], #imm
      // LOAD
      uint64_t val = memoryData[0].get<uint64_t>();
      uint64_t out[2] = {val, val};
      results[0] = {out, 256};
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1Rv2s: {  // ld1r {vt.2s}, [xn]
      // LOAD
      uint32_t val = memoryData[0].get<uint32_t>();
      uint32_t out[4] = {val, val, 0, 0};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Rv2s_POST: {  // ld1r {vt.2s}, [xn], #imm
      // LOAD
      uint32_t val = memoryData[0].get<uint32_t>();
      uint32_t out[4] = {val, val, 0, 0};
      results[0] = {out, 256};
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1Rv4h: {  // ld1r {vt.4h}, [xn]
      // LOAD
      uint16_t val = memoryData[0].get<uint16_t>();
      uint16_t out[8] = {val, val, val, val, 0, 0, 0, 0};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Rv4h_POST: {  // ld1r {vt.4h}, [xn], #imm
      // LOAD
      uint16_t val = memoryData[0].get<uint16_t>();
      uint16_t out[8] = {val, val, val, val, 0, 0, 0, 0};
      results[0] = {out, 256};
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1Rv4s: {  // ld1r {vt.4s}, [xn]
      // LOAD
      uint32_t val = memoryData[0].get<uint32_t>();
      uint32_t out[4] = {val, val, val, val};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Rv4s_POST: {  // ld1r {vt.4s}, [xn], #imm
      // LOAD
      uint32_t val = memoryData[0].get<uint32_t>();
      uint32_t out[4] = {val, val, val, val};
      results[0] = {out, 256};
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1Rv8b: {  // ld1r {vt.8b}, [xn]
      // LOAD
      uint8_t val = memoryData[0].get<uint8_t>();
      uint8_t out[16] = {val, val, val, val, val, val, val, val,
                         0,   0,   0,   0,   0,   0,   0,   0};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Rv8b_POST: {  // ld1r {vt.8b}, [xn], #imm
      // LOAD
      uint8_t val = memoryData[0].get<uint8_t>();
      uint8_t out[16] = {val, val, val, val, val, val, val, val,
                         0,   0,   0,   0,   0,   0,   0,   0};
      results[0] = {out, 256};
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1Rv8h: {  // ld1r {vt.8h}, [xn]
      // LOAD
      uint16_t val = memoryData[0].get<uint16_t>();
      uint16_t out[8] = {val, val, val, val, val, val, val, val};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1Rv8h_POST: {  // ld1r {vt.8h}, [xn], #imm
      // LOAD
      uint16_t val = memoryData[0].get<uint16_t>();
      uint16_t out[8] = {val, val, val, val, val, val, val, val};
      results[0] = {out, 256};
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1SB_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SB_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SB_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SB_H_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SB_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SB_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SH_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SH_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SH_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SH_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SW_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1SW_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Threev8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov16b: {  // ld1 {vt1.16b, vt2.16b}, [xn]
      // LOAD
      results[0] = memoryData[0].zeroExtend(memoryData[0].size(), 256);
      results[1] = memoryData[1].zeroExtend(memoryData[1].size(), 256);
      break;
    }
    case Opcode::AArch64_LD1Twov16b_POST: {  // ld1 {vt1.16b, vt2.16b}, [xn],
                                             //   #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(memoryData[0].size(), 256);
      results[1] = memoryData[1].zeroExtend(memoryData[1].size(), 256);
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_LD1Twov1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1Twov8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1W: {  // ld1w  {zt.s}, pg/z, [xn, xm, lsl #2]
      // LOAD
      const uint64_t* p = operands[0].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 32;
      uint16_t index = 0;
      uint32_t out[64] = {0};
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 16) * 4);
        if (p[i / 16] & shifted_active) {
          out[i] = memoryData[index].get<uint32_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1W_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1W_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1W_IMM_REAL: {  // ld1w  {zt.s}, pg/z, [xn{, #imm,
                                           // mul vl}]
      // LOAD
      const uint64_t* p = operands[0].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 32;
      uint16_t index = 0;
      uint32_t out[64] = {0};
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 16) * 4);
        if (p[i / 16] & shifted_active) {
          out[i] = memoryData[index].get<uint32_t>();
          index++;
        } else {
          out[i] = 0;
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1i16_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1i32: {  // ld1 {vt.s}[index], [xn]
      // LOAD
      const int index = metadata.operands[0].vector_index;
      const uint32_t* vt = operands[0].getAsVector<uint32_t>();
      uint32_t out[4];
      for (int i = 0; i < 4; i++) {
        out[i] = (i == index) ? memoryData[0].get<uint32_t>() : vt[i];
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1i32_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1i64: {  // ld1 {vt.d}[index], [xn]
      // LOAD
      const int index = metadata.operands[0].vector_index;
      const uint64_t* vt = operands[0].getAsVector<uint64_t>();
      uint64_t out[2];
      for (int i = 0; i < 2; i++) {
        out[i] = (i == index) ? memoryData[0].get<uint64_t>() : vt[i];
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LD1i64_POST: {  // ld1 {vt.d}[index], [xn], #8
      // LOAD
      const int index = metadata.operands[0].vector_index;
      const uint64_t* vt = operands[0].getAsVector<uint64_t>();
      uint64_t out[2];
      for (int i = 0; i < 2; i++) {
        out[i] = (i == index) ? memoryData[0].get<uint64_t>() : vt[i];
      }
      results[0] = {out, 256};
      results[1] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LD1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD1i8_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2B_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Rv8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov4s_POST: {  // ld2 {vt1.4s, vt2.4s}, [xn], #imm
      // LOAD
      const float* region1 = memoryData[0].getAsVector<float>();
      const float* region2 = memoryData[1].getAsVector<float>();
      float t1[4] = {region1[0], region1[2], region2[0], region2[2]};
      float t2[4] = {region1[1], region1[3], region2[1], region2[3]};
      results[0] = {t1, 256};
      results[1] = {t2, 256};
      uint64_t offset = 32;
      if (metadata.operandCount == 4) {
        offset = operands[3].get<uint64_t>();
      }
      results[2] = operands[2].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_LD2Twov8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2Twov8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2W: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2W_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2i16_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2i32_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2i64_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD2i8_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3B_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Rv8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3Threev8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3W: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3W_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3i16_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3i32_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3i64_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD3i8_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4B_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Fourv8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4Rv8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4W: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4W_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4i16_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4i32_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4i64_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LD4i8_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDLW:  // ldaddl ws, wt, [xn]
      // LOAD
      [[fallthrough]];
    case Opcode::AArch64_LDADDW: {  // ldadd ws, wt, [xn]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      memoryData[0] = RegisterValue(
          memoryData[0].get<uint32_t>() + operands[0].get<uint32_t>(), 4);
      break;
    }
    case Opcode::AArch64_LDADDLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDADDX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPRB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPRH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPRW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPRX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPURBi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPURHi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPURSBWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPURSBXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPURSHWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPURSHXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPURSWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPURXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAPURi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDARB: {  // ldarb wt, [xn]
      // LOAD
      results[0] = memoryData[0].zeroExtend(1, 8);
      break;
    }
    case Opcode::AArch64_LDARH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDARW: {  // ldar wt, [xn]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDARX: {  // ldar xt, [xn]
      // LOAD
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDAXPW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAXPX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAXRB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAXRH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDAXRW: {  // ldaxr wd, [xn]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDAXRX: {  // ldaxr xd, [xn]
      // LOAD
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDCLRAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDCLRX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDEORX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1B_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1B_H_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1B_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1B_S_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1H_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1H_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1H_S_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1SB_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1SB_H_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1SB_S_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1SH_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1SH_S_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1SW_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1W_D_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDFF1W_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDLARB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDLARH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDLARW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDLARX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1B_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1B_H_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1B_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1B_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1H_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1H_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1H_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1SB_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1SB_H_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1SB_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1SH_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1SH_S_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1SW_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1W_D_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNF1W_IMM_REAL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNPDi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNPQi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNPSi: {  // ldnp st1, st2, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 256);
      results[1] = memoryData[1].zeroExtend(4, 256);
      break;
    }
    case Opcode::AArch64_LDNPWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNPXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNT1B_ZRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNT1B_ZRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNT1D_ZRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNT1D_ZRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNT1H_ZRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNT1H_ZRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNT1W_ZRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDNT1W_ZRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDPDi: {  // ldp dt1, dt2, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(8, 256);
      results[1] = memoryData[1].zeroExtend(8, 256);
      break;
    }
    case Opcode::AArch64_LDPDpost: {  // ldp dt1, dt2, [xn], #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(8, 256);
      results[1] = memoryData[1].zeroExtend(8, 256);
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_LDPDpre: {  // ldp dt1, dt2, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(8, 256);
      results[1] = memoryData[1].zeroExtend(8, 256);
      results[2] = operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_LDPQi: {  // ldp qt1, qt2, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(16, 256);
      results[1] = memoryData[1].zeroExtend(16, 256);
      break;
    }
    case Opcode::AArch64_LDPQpost: {  // ldp qt1, qt2, [xn], #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(16, 256);
      results[1] = memoryData[1].zeroExtend(16, 256);
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_LDPQpre: {  // ldp qt1, qt2, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(16, 256);
      results[1] = memoryData[1].zeroExtend(16, 256);
      results[2] = operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_LDPSWi: {  // ldpsw xt1, xt2, [xn {, #imm}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = memoryData[1].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDPSWpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDPSWpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDPSi: {  // ldp st1, st2, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 256);
      results[1] = memoryData[1].zeroExtend(4, 256);
      break;
    }
    case Opcode::AArch64_LDPSpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDPSpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDPWi: {  // ldp wt1, wt2, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = memoryData[1].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDPWpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDPWpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDPXi: {  // ldp xt1, xt2, [xn, #imm]
      // LOAD
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      break;
    }
    case Opcode::AArch64_LDPXpost: {  // ldp xt1, xt2, [xn], #imm
      // LOAD
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_LDPXpre: {  // ldp xt1, xt2, [xn, #imm]!
      // LOAD
      results[0] = memoryData[0];
      results[1] = memoryData[1];
      results[2] = operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRAAindexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRAAwriteback: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRABindexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRABwriteback: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRBBpost: {  // ldrb wt, [xn], #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(1, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRBBpre: {  // ldrb wt, [xn, #imm]!
      // LOAD
      results[0] = memoryData[0].zeroExtend(1, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRBBroW: {  // ldrb wt,
                                      //  [xn, wm{, extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(1, 8);
      break;
    }
    case Opcode::AArch64_LDRBBroX: {  // ldrb wt,
                                      //  [xn, xm{, extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(1, 8);
      break;
    }
    case Opcode::AArch64_LDRBBui: {  // ldrb wt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(1, 8);
      break;
    }
    case Opcode::AArch64_LDRBpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRBpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRBroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRBroX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRBui: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRDl: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRDpost: {  // ldr dt, [xn], #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 256);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRDpre: {  // ldr dt, [xn, #imm]!
      // LOAD
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 256);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRDroW: {  // ldr dt, [xn, wm, {extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 256);
      break;
    }
    case Opcode::AArch64_LDRDroX: {  // ldr dt, [xn, xm, {extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 256);
      break;
    }
    case Opcode::AArch64_LDRDui: {  // ldr dt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(8, 256);
      break;
    }
    case Opcode::AArch64_LDRHHpost: {  // ldrh wt, [xn], #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(2, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRHHpre: {  // ldrh wt, [xn, #imm]!
      // LOAD
      results[0] = memoryData[0].zeroExtend(2, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRHHroW: {  // ldrh wt, [xn, wm, {extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(2, 8);
      break;
    }
    case Opcode::AArch64_LDRHHroX: {  // ldrh wt, [xn, xm, {extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(2, 8);
      break;
    }
    case Opcode::AArch64_LDRHHui: {  // ldrh wt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(2, 8);
      break;
    }
    case Opcode::AArch64_LDRHpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRHpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRHroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRHroX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRHui: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRQl: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRQpost: {  // ldr qt, [xn], #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(16, 256);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRQpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRQroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRQroX: {  // ldr qt, [xn, xm, {extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(16, 256);
      break;
    }
    case Opcode::AArch64_LDRQui: {  // ldr qt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(16, 256);
      break;
    }
    case Opcode::AArch64_LDRSBWpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSBWpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSBWroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSBWroX: {  // ldrsb wt, [xn, xm{, extend {#amount}}]
      // LOAD
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int8_t>()), 4)
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSBWui: {  // ldrsb wt, [xn, #imm]
      // LOAD
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int8_t>()))
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSBXpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSBXpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSBXroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSBXroX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSBXui: {  // ldrsb xt, [xn, #imm]
      // LOAD
      results[0] = static_cast<int64_t>(memoryData[0].get<int8_t>());
      break;
    }
    case Opcode::AArch64_LDRSHWpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSHWpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSHWroW: {  // ldrsh wt, [xn, wm{, extend {#amount}}]
      // LOAD
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4)
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSHWroX: {  // ldrsh wt, [xn, xm{, extend {#amount}}]
      // LOAD
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4)
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSHWui: {  // ldrsh wt, [xn, #imm]
      // LOAD
      results[0] =
          RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4)
              .zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSHXpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSHXpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSHXroW: {  // ldrsh xt, [xn, wm{, extend {#amount}}]
      // LOAD
      results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
      break;
    }
    case Opcode::AArch64_LDRSHXroX: {  // ldrsh xt, [xn, xm{, extend {#amount}}]
      // LOAD
      results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
      break;
    }
    case Opcode::AArch64_LDRSHXui: {  // ldrsh xt, [xn, #imm]
      // LOAD
      results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
      break;
    }
    case Opcode::AArch64_LDRSWl: {  // ldrsw xt, #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRSWpost: {  // ldrsw xt, [xn], #simm
      // LOAD
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRSWpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSWroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSWroX: {  // ldrsw xt, [xn, xm{, extend {#amount}}]
      // LOAD
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      break;
    }
    case Opcode::AArch64_LDRSWui: {  // ldrsw xt, [xn{, #pimm}]
      // LOAD
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      break;
    }
    case Opcode::AArch64_LDRSl: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRSpost: {  // ldr st, [xn], #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 256);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRSpre: {  // ldr st, [xn, #imm]!
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 256);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRSroW: {  // ldr st, [xn, wm, {extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 256);
      break;
    }
    case Opcode::AArch64_LDRSroX: {  // ldr st, [xn, xm, {extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 256);
      break;
    }
    case Opcode::AArch64_LDRSui: {  // ldr st, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 256);
      break;
    }
    case Opcode::AArch64_LDRWl: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDRWpost: {  // ldr wt, [xn], #imm
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRWpre: {  // ldr wt, [xn, #imm]!
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRWroW: {  // ldr wt, [xn, wm, {extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRWroX: {  // ldr wt, [xn, xm, {extend {#amount}}]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDRWui: {  // ldr wt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(memoryAddresses[0].size, 8);
      break;
    }
    case Opcode::AArch64_LDRXl: {  // ldr xt, #imm
      // LOAD
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDRXpost: {  // ldr xt, [xn], #imm
      // LOAD
      results[0] = memoryData[0];
      results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_LDRXpre: {  // ldr xt, [xn, #imm]!
      // LOAD
      results[0] = memoryData[0];
      results[1] = operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_LDRXroW: {  // ldr xt, [xn, wn{, extend {#amount}}]
      // LOAD
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDRXroX: {  // ldr xt, [xn, xn{, extend {#amount}}]
      // LOAD
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDRXui: {  // ldr xt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDR_PXI: {  // ldr pt, [xn{, #imm, mul vl}]
      // LOAD
      const uint64_t PL_bits = VL_bits / 8;
      const uint16_t partition_num = PL_bits / 8;

      uint64_t out[4] = {0};
      for (int i = 0; i < partition_num; i++) {
        uint8_t data = memoryData[i].get<uint8_t>();
        for (int j = 0; j < 8; j++) {
          out[i / 8] |= (data & (1 << j)) ? 1ull << ((j + (i * 8)) % 64) : 0;
        }
      }
      results[0] = out;
      break;
    }
    case Opcode::AArch64_LDR_ZXI: {  // ldr zt, [xn{, #imm, mul vl}]
      // LOAD
      const uint16_t partition_num = VL_bits / 8;
      uint8_t out[256] = {0};

      for (int i = 0; i < partition_num; i++) {
        out[i] = memoryData[i].get<uint8_t>();
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_LDSETAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSETX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMAXX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDSMINX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDTRBi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDTRHi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDTRSBWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDTRSBXi: {  // ldtrsb xt, [xn, #imm]
      // LOAD
      // TODO: implement
      results[0] = RegisterValue(0, 8);
      break;
    }
    case Opcode::AArch64_LDTRSHWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDTRSHXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDTRSWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDTRWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDTRXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMAXX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDUMINX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDURBBi: {  // ldurb wt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(1, 8);
      break;
    }
    case Opcode::AArch64_LDURBi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDURDi: {  // ldur dt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(8, 256);
      break;
    }
    case Opcode::AArch64_LDURHHi: {  // ldurh wt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(2, 8);
      break;
    }
    case Opcode::AArch64_LDURHi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDURQi: {  // ldur qt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(16, 256);
      break;
    }
    case Opcode::AArch64_LDURSBWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDURSBXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDURSHWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDURSHXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDURSWi: {  // ldursw xt, [xn, #imm]
      // LOAD
      results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
      break;
    }
    case Opcode::AArch64_LDURSi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDURWi: {  // ldur wt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDURXi: {  // ldur xt, [xn, #imm]
      // LOAD
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LDXPW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDXPX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDXRB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDXRH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LDXRW: {  // ldxr wt, [xn]
      // LOAD
      results[0] = memoryData[0].zeroExtend(4, 8);
      break;
    }
    case Opcode::AArch64_LDXRX: {  // ldxr xt, [xn]
      // LOAD
      results[0] = memoryData[0];
      break;
    }
    case Opcode::AArch64_LOADgot: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSLR_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSLR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSLR_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSLR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSLVWr: {  // lslv wd, wn, wm
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>() & 0b11111;
      results[0] = static_cast<uint64_t>(x << y);
      break;
    }
    case Opcode::AArch64_LSLVXr: {  // lslv xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>() & 0b111111;
      results[0] = x << y;
      break;
    }
    case Opcode::AArch64_LSL_WIDE_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_WIDE_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_WIDE_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_WIDE_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_WIDE_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_WIDE_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZPmI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSL_ZZI_S: {  // lsl zd.s, zn.s, #imm
      results[0] = sveHelp::sveLsl_imm<uint32_t>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_LSRR_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSRR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSRR_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSRR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSRVWr: {  // lsrv wd, wn, wm
      auto x = operands[0].get<uint32_t>();
      auto y = operands[1].get<uint32_t>() & 0b11111;
      results[0] = static_cast<uint64_t>(x >> y);
      break;
    }
    case Opcode::AArch64_LSRVXr: {  // lsrv xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>() & 0b111111;
      results[0] = x >> y;
      break;
    }
    case Opcode::AArch64_LSR_WIDE_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_WIDE_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_WIDE_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_WIDE_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_WIDE_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_WIDE_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZPmI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZPmI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZPmI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZPmI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_LSR_ZZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MADDWrrr: {  // madd wd, wn, wm, wa
      results[0] =
          static_cast<uint64_t>(multiplyHelp::madd_4ops<uint32_t>(operands));
      break;
    }
    case Opcode::AArch64_MADDXrrr: {  // madd xd, xn, xm, xa
      results[0] = multiplyHelp::madd_4ops<uint64_t>(operands);
      break;
    }
    case Opcode::AArch64_MAD_ZPmZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MAD_ZPmZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MAD_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MAD_ZPmZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLA_ZPmZZ_B: {  // mla zda.b, pg/m, zn.b, zm.b
      results[0] = sveHelp::sveMlaPredicated_vecs<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_MLA_ZPmZZ_D: {  // mla zda.d, pg/m, zn.d, zm.d
      results[0] = sveHelp::sveMlaPredicated_vecs<uint64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_MLA_ZPmZZ_H: {  // mla zda.h, pg/m, zn.h, zm.h
      results[0] = sveHelp::sveMlaPredicated_vecs<uint16_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_MLA_ZPmZZ_S: {  // mla zda.s, pg/m, zn.s, zm.s
      results[0] = sveHelp::sveMlaPredicated_vecs<uint32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_MLAv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLAv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLAv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLAv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLAv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLAv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLAv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLAv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLAv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLAv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLS_ZPmZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLS_ZPmZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLS_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLS_ZPmZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MLSv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVID: {  // movi dd, #imm
      uint64_t bits = static_cast<uint64_t>(metadata.operands[1].imm);
      results[0] = {bits, 256};
      break;
    }
    case Opcode::AArch64_MOVIv16b_ns: {  // movi vd.16b, #imm
      results[0] = neonHelp::vecMovi_imm<uint8_t, 16>(metadata);
      break;
    }
    case Opcode::AArch64_MOVIv2d_ns: {  // movi vd.2d, #imm
      results[0] = neonHelp::vecMovi_imm<uint64_t, 2>(metadata);
      break;
    }
    case Opcode::AArch64_MOVIv2i32: {  // movi vd.2s, #imm{, lsl #shift}
      results[0] = neonHelp::vecMoviShift_imm<uint32_t, 2>(metadata, false);
      break;
    }
    case Opcode::AArch64_MOVIv2s_msl: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVIv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVIv4i32: {  // movi vd.4s, #imm{, LSL #shift}
      results[0] = neonHelp::vecMoviShift_imm<uint32_t, 4>(metadata, false);
      break;
    }
    case Opcode::AArch64_MOVIv4s_msl: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVIv8b_ns: {  // movi vd.8b, #imm
      results[0] = neonHelp::vecMovi_imm<uint8_t, 8>(metadata);
      break;
    }
    case Opcode::AArch64_MOVIv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVKWi: {  // movk wd, #imm
      results[0] = RegisterValue(
          arithmeticHelp::movkShift_imm<uint32_t>(operands, metadata), 8);
      break;
    }
    case Opcode::AArch64_MOVKXi: {  // movk xd, #imm
      results[0] = arithmeticHelp::movkShift_imm<uint64_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_MOVNWi: {  // movn wd, #imm{, LSL #shift}
      results[0] = arithmeticHelp::movnShift_imm<uint32_t>(
          metadata, [](uint64_t x) -> uint32_t { return ~x; });
      break;
    }
    case Opcode::AArch64_MOVNXi: {  // movn xd, #imm{, LSL #shift}
      results[0] = arithmeticHelp::movnShift_imm<uint64_t>(
          metadata, [](uint64_t x) -> uint64_t { return ~x; });
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZPmZ_D: {  // movprfx zd.d, pg/m, zn.d
      results[0] = sveHelp::sveMovprfxPredicated_destUnchanged<uint64_t>(
          operands, VL_bits);
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZPzZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZPzZ_D: {  // movprfx zd.d, pg/z, zn.d
      results[0] =
          sveHelp::sveMovprfxPredicated_destToZero<uint64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZPzZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZPzZ_S: {  // movprfx zd.s, pg/z, zn.s
      results[0] =
          sveHelp::sveMovprfxPredicated_destToZero<uint32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_MOVPRFX_ZZ: {  // movprfx zd, zn
      // TODO: Adopt hint logic of the MOVPRFX instruction
      results[0] = operands[0];
      break;
    }
    case Opcode::AArch64_MOVZWi: {  // movz wd, #imm
      results[0] = arithmeticHelp::movnShift_imm<uint32_t>(
          metadata, [](uint64_t x) -> uint32_t { return x; });
      break;
    }
    case Opcode::AArch64_MOVZXi: {  // movz xd, #imm
      results[0] = arithmeticHelp::movnShift_imm<uint64_t>(
          metadata, [](uint64_t x) -> uint64_t { return x; });
      break;
    }
    case Opcode::AArch64_MOVaddr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVaddrBA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVaddrCP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVaddrEXT: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVaddrJT: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVaddrTLS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVbaseTLS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVi32imm: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MOVi64imm: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MRS: {  // mrs xt, (systemreg|Sop0_op1_Cn_Cm_op2)
      results[0] = operands[0];
      break;
    }
    case Opcode::AArch64_MSB_ZPmZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MSB_ZPmZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MSB_ZPmZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MSB_ZPmZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MSR: {  // mrs (systemreg|Sop0_op1_Cn_Cm_op2), xt
      results[0] = operands[0];
      break;
    }
    case Opcode::AArch64_MSRpstateImm1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MSRpstateImm4: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MSUBWrrr: {  // msub wd, wn, wm, wa
      results[0] = {multiplyHelp::msub_4ops<uint32_t>(operands), 8};
      break;
    }
    case Opcode::AArch64_MSUBXrrr: {  // msub xd, xn, xm, xa
      results[0] = multiplyHelp::msub_4ops<uint64_t>(operands);
      break;
    }
    case Opcode::AArch64_MUL_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MUL_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MUL_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MUL_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MUL_ZPmZ_B: {  // mul zdn.b, pg/m, zdn.b, zm.b
      results[0] = sveHelp::sveMulPredicated<uint8_t>(operands, metadata,
                                                      VL_bits, false);
      break;
    }
    case Opcode::AArch64_MUL_ZPmZ_D: {  // mul zdn.d, pg/m, zdn.d, zm.d
      results[0] = sveHelp::sveMulPredicated<uint64_t>(operands, metadata,
                                                       VL_bits, false);
      break;
    }
    case Opcode::AArch64_MUL_ZPmZ_H: {  // mul zdn.h, pg/m, zdn.h, zm.h
      results[0] = sveHelp::sveMulPredicated<uint16_t>(operands, metadata,
                                                       VL_bits, false);
      break;
    }
    case Opcode::AArch64_MUL_ZPmZ_S: {  // mul zdn.s, pg/m, zdn.s, zm.s
      results[0] = sveHelp::sveMulPredicated<uint32_t>(operands, metadata,
                                                       VL_bits, false);
      break;
    }
    case Opcode::AArch64_MULv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MULv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MULv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MULv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MULv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MULv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MULv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MULv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MULv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MULv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MVNIv2i32: {  // mvni vd.2s, #imm{, lsl #shift}
      results[0] = neonHelp::vecMoviShift_imm<uint32_t, 2>(metadata, true);
      break;
    }
    case Opcode::AArch64_MVNIv2s_msl: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MVNIv4i16: {  // mvni vd.4h, #imm{, lsl #shift}
      results[0] = neonHelp::vecMoviShift_imm<uint16_t, 4>(metadata, true);
      break;
    }
    case Opcode::AArch64_MVNIv4i32: {  // mvni vd.4s, #imm{, lsl #shift}
      results[0] = neonHelp::vecMoviShift_imm<uint32_t, 4>(metadata, true);
      break;
    }
    case Opcode::AArch64_MVNIv4s_msl: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_MVNIv8i16: {  // mvni vd.8h, #imm{, lsl #shift}
      results[0] = neonHelp::vecMoviShift_imm<uint16_t, 8>(metadata, true);
      break;
    }
    case Opcode::AArch64_NANDS_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NAND_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEG_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEG_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEG_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEG_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEGv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEGv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEGv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEGv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEGv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEGv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEGv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NEGv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NORS_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NOR_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NOT_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NOT_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NOT_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NOT_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_NOTv16i8: {  // not vd.16b, vn.16b
      results[0] = neonHelp::vecLogicOp_2vecs<uint8_t, 16>(
          operands, [](uint8_t x) -> uint8_t { return ~x; });
      break;
    }
    case Opcode::AArch64_NOTv8i8: {  // not vd.8b, vn.8b
      results[0] = neonHelp::vecLogicOp_2vecs<uint8_t, 8>(
          operands, [](uint8_t x) -> uint8_t { return ~x; });
      break;
    }
    case Opcode::AArch64_ORNS_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORNWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORNWrs: {  // orn wd, wn, wm{, shift{ #amount}}
      auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint32_t>(
          operands, metadata, false,
          [](uint32_t x, uint32_t y) -> uint32_t { return x | (~y); });
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ORNXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORNXrs: {  // orn xd, xn, xm{, shift{ #amount}}
      auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint64_t>(
          operands, metadata, false,
          [](uint64_t x, uint64_t y) -> uint64_t { return x | (~y); });
      results[0] = result;
      break;
    }
    case Opcode::AArch64_ORN_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORNv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORNv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORRS_PPzPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORRWri: {  // orr wd, wn, #imm
      auto [result, nzcv] = logicalHelp::logicOp_imm<uint32_t>(
          operands, metadata, false,
          [](uint32_t x, uint32_t y) -> uint32_t { return x | y; });
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ORRWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORRWrs: {  // orr wd, wn, wm{, shift{ #amount}}
      results[0] = static_cast<uint64_t>(
          comparisonHelp::orrShift_3ops<uint32_t>(operands, metadata));
      break;
    }
    case Opcode::AArch64_ORRXri: {  // orr xd, xn, #imm
      auto [result, nzcv] = logicalHelp::logicOp_imm<uint64_t>(
          operands, metadata, false,
          [](uint64_t x, uint64_t y) -> uint64_t { return x | y; });
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_ORRXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORRXrs: {  // orr xd, xn, xm{, shift{ #amount}}
      results[0] = comparisonHelp::orrShift_3ops<uint64_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_ORR_PPzPP: {  // orr pd.b, pg/z, pn.b, pm.b
      results[0] = sveHelp::sveLogicOp_preds<uint8_t>(
          operands, VL_bits,
          [](uint64_t x, uint64_t y) -> uint64_t { return x | y; });
      break;
    }
    case Opcode::AArch64_ORR_ZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORR_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORR_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORR_ZZZ: {  // orr zd.d, zn.d, zm.d
      results[0] = sveHelp::sveOrr_3vecs<uint64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_ORRv16i8: {  // orr vd.16b, Vn.16b, Vm.16b
      results[0] = neonHelp::vecLogicOp_3vecs<uint8_t, 16>(
          operands, [](uint8_t x, uint8_t y) -> uint8_t { return x | y; });
      break;
    }
    case Opcode::AArch64_ORRv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORRv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORRv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORRv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORRv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORV_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ORV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACDA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACDB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACDZA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACDZB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACGA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIA1716: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIASP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIAZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIB1716: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIBSP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIBZ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIZA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PACIZB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PFALSE: {  // pfalse pd.b
      uint64_t out[4] = {0, 0, 0, 0};
      results[0] = out;
    }
    case Opcode::AArch64_PMULLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PMULLv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PMULLv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PMULLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PMULv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PMULv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PNEXT_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PNEXT_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PNEXT_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PNEXT_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFB_D_PZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFB_D_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFB_D_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFB_D_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFB_PRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFB_PRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFB_S_PZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFB_S_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFB_S_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFD_D_PZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFD_D_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFD_D_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFD_D_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFD_PRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFD_PRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFD_S_PZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFD_S_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFD_S_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFH_D_PZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFH_D_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFH_D_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFH_D_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFH_PRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFH_PRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFH_S_PZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFH_S_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFH_S_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFMl: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFMroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFMroX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend{, #amount}}]
      break;
    }
    case Opcode::AArch64_PRFS_PRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFUMi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFW_D_PZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFW_D_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFW_D_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFW_D_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFW_PRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFW_S_PZI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFW_S_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PRFW_S_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PTEST_PP: {  // ptest pg, pn.b
      const uint64_t* g = operands[0].getAsVector<uint64_t>();
      const uint64_t* s = operands[1].getAsVector<uint64_t>();
      std::array<uint64_t, 4> masked_n = {(g[0] & s[0]), (g[1] & s[1]),
                                          (g[2] & s[2]), (g[3] & s[3])};
      // Byte count = 1 as destination predicate is regarding single bytes.
      results[0] = AuxFunc::getNZCVfromPred(masked_n, VL_bits, 1);
      break;
    }
    case Opcode::AArch64_PTRUES_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PTRUES_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PTRUES_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PTRUES_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_PTRUE_B: {  // ptrue pd.b{, pattern}
      results[0] = sveHelp::svePtrue<uint8_t>(VL_bits);
      break;
    }
    case Opcode::AArch64_PTRUE_D: {  // ptrue pd.d{, pattern}
      results[0] = sveHelp::svePtrue<uint64_t>(VL_bits);
      break;
    }
    case Opcode::AArch64_PTRUE_H: {  // ptrue pd.h{, pattern}
      results[0] = sveHelp::svePtrue<uint16_t>(VL_bits);
      break;
    }
    case Opcode::AArch64_PTRUE_S: {  // ptrue pd.s{, pattern}
      results[0] = sveHelp::svePtrue<uint32_t>(VL_bits);
      break;
    }
    case Opcode::AArch64_PUNPKHI_PP: {  // punpkhi pd.h, pn.b
      results[0] = sveHelp::svePunpk(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_PUNPKLO_PP: {  // punpklo pd.h, pn.b
      results[0] = sveHelp::svePunpk(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_RADDHNv2i64_v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RADDHNv2i64_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RADDHNv4i32_v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RADDHNv4i32_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RADDHNv8i16_v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RADDHNv8i16_v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RAX1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RBITWr: {  // rbit wd, wn
      results[0] = bitmanipHelp::rbit<uint32_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_RBITXr: {  // rbit xd, xn
      results[0] = bitmanipHelp::rbit<uint64_t>(operands, metadata);
      break;
    }
    case Opcode::AArch64_RBIT_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RBIT_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RBIT_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RBIT_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RBITv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RBITv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RDFFRS_PPz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RDFFR_P: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RDFFR_PPz: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RDVLI_XI: {  // rdvl xd, #imm
      int8_t imm = static_cast<int8_t>(metadata.operands[1].imm);
      results[0] = (uint64_t)(imm * (VL_bits / 8));
      break;
    }
    case Opcode::AArch64_RET: {  // ret {xr}
      branchTaken_ = true;
      branchAddress_ = operands[0].get<uint64_t>();
      break;
    }
    case Opcode::AArch64_RETAA: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RETAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RET_ReallyLR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV16Wr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV16Xr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV16v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV16v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV32Xr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV32v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV32v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV32v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV32v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV64v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV64v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV64v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV64v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV64v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REV64v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REVB_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REVB_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REVB_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REVH_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REVH_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REVW_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REVWr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_REVXr: {  // rev xd, xn
      results[0] = bitmanipHelp::rev<uint64_t>(operands);
      break;
    }
    case Opcode::AArch64_REV_PP_B: {  // rev pd.b, pn.b
      results[0] = sveHelp::sveRev_predicates<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_REV_PP_D: {  // rev pd.d, pn.d
      results[0] = sveHelp::sveRev_predicates<uint64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_REV_PP_H: {  // rev pd.h, pn.h
      results[0] = sveHelp::sveRev_predicates<uint16_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_REV_PP_S: {  // rev pd.s, pn.s
      results[0] = sveHelp::sveRev_predicates<uint32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_REV_ZZ_B: {  // rev zd.b, zn.b
      results[0] = sveHelp::sveRev_vecs<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_REV_ZZ_D: {  // rev zd.d, zn.d
      results[0] = sveHelp::sveRev_vecs<uint64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_REV_ZZ_H: {  // rev zd.h, zn.h
      results[0] = sveHelp::sveRev_vecs<uint16_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_REV_ZZ_S: {  // rev zd.s, zn.s
      results[0] = sveHelp::sveRev_vecs<uint32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_RMIF: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RORVWr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RORVXr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSHRNv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSHRNv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSHRNv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSHRNv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSHRNv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSHRNv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSUBHNv2i64_v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSUBHNv2i64_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSUBHNv4i32_v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSUBHNv4i32_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSUBHNv8i16_v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_RSUBHNv8i16_v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABALv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABALv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABALv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABALv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABALv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABALv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABAv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABAv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABAv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABAv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABAv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABAv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABD_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABD_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABD_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABD_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SABDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADALPv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADALPv2i32_v1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADALPv4i16_v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADALPv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADALPv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADALPv8i8_v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLPv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLPv2i32_v1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLPv4i16_v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLPv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLPv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLPv8i8_v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLVv16i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLVv8i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDV_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDWv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDWv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDWv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDWv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDWv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SADDWv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SBCSWr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SBCSXr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SBCWr: {  // sbc wd, wn, wm
      results[0] = {arithmeticHelp::sbc<uint32_t>(operands), 8};
      break;
    }
    case Opcode::AArch64_SBCXr: {  // sbc xd, xn, xm
      results[0] = arithmeticHelp::sbc<uint64_t>(operands);
      break;
    }
    case Opcode::AArch64_SBFMWri: {  // sbfm wd, wn, #immr, #imms
      results[0] = RegisterValue(
          bitmanipHelp::bfm_2imms<uint32_t>(operands, metadata, true, true), 8);
      break;
    }
    case Opcode::AArch64_SBFMXri: {  // sbfm xd, xn, #immr, #imms
      results[0] =
          bitmanipHelp::bfm_2imms<uint64_t>(operands, metadata, true, true);
      break;
    }
    case Opcode::AArch64_SCVTFSWDri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFSWHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFSWSri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFSXDri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFSXHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFSXSri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFUWDri: {  // scvtf dd, wn
      results[0] = {static_cast<double>(operands[0].get<int32_t>()), 256};
      break;
    }
    case Opcode::AArch64_SCVTFUWHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFUWSri: {  // scvtf sd, wn
      results[0] = {static_cast<float>(operands[0].get<int32_t>()), 256};
      break;
    }
    case Opcode::AArch64_SCVTFUXDri: {  // scvtf dd, xn
      results[0] = {static_cast<double>(operands[0].get<int64_t>()), 256};
      break;
    }
    case Opcode::AArch64_SCVTFUXHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFUXSri: {  // scvtf sd, xn
      results[0] = {static_cast<float>(operands[0].get<int64_t>()), 256};
      break;
    }
    case Opcode::AArch64_SCVTF_ZPmZ_DtoD: {  // scvtf zd.d, pg/m, zn.d
      results[0] =
          sveHelp::sveFcvtPredicated<double, int64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SCVTF_ZPmZ_DtoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTF_ZPmZ_DtoS: {  // scvtf zd.s, pg/m, zn.d
      results[0] =
          sveHelp::sveFcvtPredicated<float, int64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SCVTF_ZPmZ_HtoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTF_ZPmZ_StoD: {  // scvtf zd.d, pg/m, zn.s
      results[0] =
          sveHelp::sveFcvtPredicated<double, int32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SCVTF_ZPmZ_StoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTF_ZPmZ_StoS: {  // scvtf zd.s, pg/m, zn.s
      results[0] =
          sveHelp::sveFcvtPredicated<float, int32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SCVTFd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFv1i32: {  // scvtf sd, sn
      results[0] = {static_cast<float>(operands[0].get<int32_t>()), 256};
      break;
    }
    case Opcode::AArch64_SCVTFv1i64: {  // scvtf dd, dn
      results[0] = {static_cast<double>(operands[0].get<int64_t>()), 256};
      break;
    }
    case Opcode::AArch64_SCVTFv2f32: {  // scvtf vd.2s, vn.2s
      results[0] = neonHelp::vecScvtf_2vecs<float, int32_t, 2>(
          operands, [](int32_t x) -> float { return static_cast<float>(x); });
      break;
    }
    case Opcode::AArch64_SCVTFv2f64: {  // scvtf vd.2d, vn.2d
      results[0] = neonHelp::vecScvtf_2vecs<double, int64_t, 2>(
          operands, [](int64_t x) -> double { return static_cast<double>(x); });
      break;
    }
    case Opcode::AArch64_SCVTFv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFv4f32: {  // scvtf vd.4s, vn.4s
      results[0] = neonHelp::vecScvtf_2vecs<float, int32_t, 4>(
          operands, [](int32_t x) -> float { return static_cast<float>(x); });
      break;
    }
    case Opcode::AArch64_SCVTFv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SCVTFv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDIVR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDIVR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDIVWr: {  // sdiv wd, wn, wm
      results[0] = RegisterValue(divideHelp::div_3ops<int32_t>(operands), 8);
      break;
    }
    case Opcode::AArch64_SDIVXr: {  // sdiv xd, xn, xm
      results[0] = RegisterValue(divideHelp::div_3ops<int64_t>(operands), 8);
      break;
    }
    case Opcode::AArch64_SDIV_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDIV_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDOT_ZZZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDOT_ZZZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDOT_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDOT_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDOTlanev16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDOTlanev8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDOTv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SDOTv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SEL_PPPP: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SEL_ZPZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SEL_ZPZZ_D: {  // sel zd.d, pg, zn.d, zm.d
      results[0] = sveHelp::sveSel_zpzz<uint64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SEL_ZPZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SEL_ZPZZ_S: {  // sel zd.s, pg, zn.s, zm.s
      results[0] = sveHelp::sveSel_zpzz<uint32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SETF16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SETF8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SETFFR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA1Crrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA1Hrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA1Mrrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA1Prrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA1SU0rrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA1SU1rr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA256H2rrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA256Hrrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA256SU0rr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA256SU1rrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA512H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA512H2: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA512SU0: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHA512SU1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHADDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHADDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHADDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHADDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHADDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHADDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLLv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLLv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLd: {  // shl dd, dn #imm
      const uint64_t n = operands[0].get<uint64_t>();
      int64_t shift = metadata.operands[2].imm;
      results[0] = RegisterValue(static_cast<uint64_t>(n << shift), 256);
      break;
    }
    case Opcode::AArch64_SHLv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLv4i32_shift: {  // shl vd.4s, vn.4s, #imm
      results[0] =
          neonHelp::vecShlShift_vecImm<uint32_t, 4>(operands, metadata);
      break;
    }
    case Opcode::AArch64_SHLv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHLv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHRNv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHRNv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHRNv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHRNv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHRNv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHRNv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHSUBv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHSUBv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHSUBv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHSUBv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHSUBv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SHSUBv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SLId: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SLIv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SLIv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SLIv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SLIv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SLIv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SLIv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SLIv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SM3PARTW1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SM3PARTW2: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SM3SS1: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SM3TT1A: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SM3TT1B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SM3TT2A: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SM3TT2B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SM4E: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SM4ENCKEY: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMADDLrrr: {  // smaddl xd, wn, wm, xa
      auto n = static_cast<int64_t>(operands[0].get<int32_t>());
      auto m = static_cast<int64_t>(operands[1].get<int32_t>());
      auto a = operands[2].get<int64_t>();
      results[0] = a + (n * m);
      break;
    }
    case Opcode::AArch64_SMAXPv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXPv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXPv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXPv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXPv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXPv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXV_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXVv16i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXVv8i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAX_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAX_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAX_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAX_ZI_S: {  // smax zdn.s, zdn.s, #imm
      results[0] = sveHelp::sveMax_vecImm<int32_t>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_SMAX_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAX_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAX_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAX_ZPmZ_S: {  // smax zd.s, pg/m, zn.s, zm.s
      results[0] = sveHelp::sveMaxPredicated_vecs<int32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SMAXv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXv4i32: {  // smax vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecLogicOp_3vecs<int32_t, 4>(
          operands,
          [](int32_t x, int32_t y) -> int32_t { return std::max(x, y); });
      break;
    }
    case Opcode::AArch64_SMAXv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMAXv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMC: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINPv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINPv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINPv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINPv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINPv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINPv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINV_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINV_VPZ_S: {  // sminv sd, pg, zn.s
      results[0] = sveHelp::sveSminv<int32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SMINVv16i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINVv4i32v: {  // sminv sd, vn.4s
      results[0] = neonHelp::vecSminv_2ops<int32_t, 4>(operands);
      break;
    }
    case Opcode::AArch64_SMINVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINVv8i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMIN_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMIN_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMIN_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMIN_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMIN_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMIN_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMIN_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMIN_ZPmZ_S: {  // smin zd.s, pg/m, zn.s, zm.s
      results[0] = sveHelp::sveLogicOpPredicated_3vecs<int32_t>(
          operands, VL_bits,
          [](int32_t x, int32_t y) -> int32_t { return std::min(x, y); });
      break;
    }
    case Opcode::AArch64_SMINv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINv4i32: {  // smin vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecLogicOp_3vecs<int32_t, 4>(
          operands,
          [](int32_t x, int32_t y) -> int32_t { return std::min(x, y); });
      break;
    }
    case Opcode::AArch64_SMINv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMINv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLALv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMLSLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMOVvi16to32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMOVvi16to64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMOVvi32to64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMOVvi8to32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMOVvi8to64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMSUBLrrr: {  // smsubl xd, wn, wm, xa
      const int32_t n = operands[0].get<int32_t>();
      const int32_t m = operands[1].get<int32_t>();
      const int64_t a = operands[2].get<int64_t>();
      results[0] = a - (n * m);
      break;
    }
    case Opcode::AArch64_SMULH_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULH_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULH_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULH_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULHrr: {  // smulh xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      // TODO: signed
      results[0] = AuxFunc::mulhi(x, y);
      break;
    }
    case Opcode::AArch64_SMULLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULLv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULLv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULLv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULLv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SMULLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SPLICE_ZPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SPLICE_ZPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SPLICE_ZPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SPLICE_ZPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQABSv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADD_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADD_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADD_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADD_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADD_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADD_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADD_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADD_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQADDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECB_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECB_XPiWdI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECD_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECD_XPiWdI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECD_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECH_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECH_XPiWdI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECH_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_XPWd_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_XPWd_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_XPWd_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_XPWd_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_XP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_XP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_XP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_XP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_ZP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_ZP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECP_ZP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECW_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECW_XPiWdI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDECW_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALi16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALi32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv1i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv1i64_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLALv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLi16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLi32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv1i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv1i64_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMLSLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv1i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv1i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULHv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLi16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLi32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv1i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv1i64_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQDMULLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCB_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCB_XPiWdI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCD_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCD_XPiWdI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCD_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCH_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCH_XPiWdI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCH_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_XPWd_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_XPWd_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_XPWd_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_XPWd_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_XP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_XP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_XP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_XP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_ZP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_ZP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCP_ZP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCW_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCW_XPiWdI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQINCW_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQNEGv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHi16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHi32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLAHv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHi16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHi32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMLSHv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv1i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv1i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRDMULHv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRNb: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRNh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRNs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRNv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRNv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRNv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRNv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRNv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRNv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRUNb: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRUNh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRUNs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRUNv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRUNv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRUNv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRUNv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRUNv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQRSHRUNv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUb: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLUv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLb: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHLv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRNb: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRNh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRNs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRNv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRNv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRNv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRNv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRNv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRNv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRUNb: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRUNh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRUNs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRUNv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRUNv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRUNv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRUNv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRUNv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSHRUNv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUB_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUB_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUB_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUB_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUB_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUB_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUB_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUB_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQSUBv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTNv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTNv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTNv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTNv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTNv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTNv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTNv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTNv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTNv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTUNv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTUNv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTUNv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTUNv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTUNv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTUNv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTUNv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTUNv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SQXTUNv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRHADDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRHADDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRHADDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRHADDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRHADDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRHADDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRId: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRIv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRIv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRIv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRIv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRIv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRIv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRIv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHLv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHLv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHLv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHLv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHRd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHRv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHRv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHRv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHRv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHRv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHRv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSHRv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSRAd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSRAv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSRAv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSRAv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSRAv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSRAv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSRAv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SRSRAv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLLv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLLv2i32_shift: {  // sshll vd.2d, vn.2s, #imm
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      uint64_t shift = metadata.operands[2].imm;
      int64_t out[2] = {
          static_cast<int64_t>(static_cast<int32_t>(n[0] << shift)),
          static_cast<int64_t>(static_cast<int32_t>(n[1] << shift))};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_SSHLLv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLLv4i32_shift: {  // sshll2 vd.2d, vn.4s, #imm
      const uint32_t* n = operands[0].getAsVector<uint32_t>();
      uint64_t shift = metadata.operands[2].imm;
      int64_t out[2] = {
          static_cast<int64_t>(static_cast<int32_t>(n[2] << shift)),
          static_cast<int64_t>(static_cast<int32_t>(n[3] << shift))};
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_SSHLLv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLLv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHRd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHRv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHRv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHRv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHRv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHRv4i32_shift: {  // sshr vd.4s, vn.4s, #imm
      results[0] = neonHelp::vecSshrShift_imm<int32_t, 4>(operands, metadata);
      break;
    }
    case Opcode::AArch64_SSHRv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSHRv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSRAd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSRAv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSRAv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSRAv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSRAv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSRAv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSRAv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSRAv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1B_D: {  // st1b {zd.d}, pg, [xn, zm.d]
      // STORE
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          memoryData[index] = static_cast<uint8_t>(d[i]);
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_SST1B_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1B_D_SXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1B_D_UXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1B_S_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1B_S_SXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1B_S_UXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1D: {  // st1d {zt.d}, pg, [xn, zm.d]
      // STORE
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_SST1D_IMM: {  // st1d {zd.d}, pg, [zn.d{, #imm}]
      // STORE
      const uint64_t* t = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          memoryData[index] = t[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_SST1D_SCALED: {  // st1d {zt.d}, pg, [xn, zm.d, lsl #
                                          // 3]
      // STORE
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_SST1D_SXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1D_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1D_UXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1D_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_D_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_D_SXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_D_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_D_UXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_D_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_S_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_S_SXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_S_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_S_UXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1H_S_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_D_IMM: {  // st1w {zt.d}, pg, [zn.d{, #imm}]
      // STORE
      const uint64_t* t = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          memoryData[index] = t[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_SST1W_D_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_D_SXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_D_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_D_UXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_D_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_IMM: {  // st1w {zt.s}, pg, [zn.s{, #imm}]
      // STORE
      const uint32_t* t = operands[0].getAsVector<uint32_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 32;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 16) * 4);
        if (p[i / 16] & shifted_active) {
          memoryData[index] = t[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_SST1W_SXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_SXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_UXTW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SST1W_UXTW_SCALED: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBWv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBWv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBWv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBWv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBWv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SSUBWv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1B: {  // st1b {zt.b}, pg, [xn, xm]
      // STORE
      const uint8_t* d = operands[0].getAsVector<uint8_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 8;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << (i % 64);
        if (p[i / 64] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_ST1B_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1B_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1B_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1B_H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1B_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1B_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1B_S_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1D: {  // st1d {zt.d}, pg, [xn, xm, lsl #3]
      // STORE
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_ST1D_IMM: {  // st1d {zt.d}, pg, [xn{, #imm, mul vl}]
      // STORE
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_ST1Fourv16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Fourv8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1H_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1H_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1H_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1H_S_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Onev8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Threev8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov16b: {  // st1v {vt.16b, vt2.16b}, [xn]
      // STORE
      const uint8_t* t = operands[0].getAsVector<uint8_t>();
      const uint8_t* t2 = operands[1].getAsVector<uint8_t>();
      for (int i = 0; i < 16; i++) {
        memoryData[i] = t[i];
      }
      for (int i = 0; i < 16; i++) {
        memoryData[i + 16] = t2[i];
      }
      break;
    }
    case Opcode::AArch64_ST1Twov16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov1d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov1d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1Twov8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1W: {  // st1w {zt.s}, pg, [xn, xm, lsl #2]
      // STORE
      const uint32_t* d = operands[0].getAsVector<uint32_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 32;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 16) * 4);
        if (p[i / 16] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_ST1W_D: {  // st1w {zt.d}, pg, [xn, xm, lsl #2]
      // STORE
      const uint64_t* d = operands[0].getAsVector<uint64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 64;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          memoryData[index] = static_cast<uint32_t>(d[i]);
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_ST1W_D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST1W_IMM: {  // st1w {zt.s}, pg, [xn{, #imm, mul vl}]
      // STORE
      const uint32_t* d = operands[0].getAsVector<uint32_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();

      const uint16_t partition_num = VL_bits / 32;
      uint16_t index = 0;
      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 16) * 4);
        if (p[i / 16] & shifted_active) {
          memoryData[index] = d[i];
          index++;
        }
      }
      break;
    }
    case Opcode::AArch64_ST1i16: {  // st1 {vt.h}[index], [xn]
      // STORE
      const uint16_t* t = operands[0].getAsVector<uint16_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      break;
    }
    case Opcode::AArch64_ST1i16_POST: {  // st1 {vt.h}[index], [xn], xm
                                         // st1 {vt.h}[index], [xn], #2
      // STORE
      const uint16_t* t = operands[0].getAsVector<uint16_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      uint64_t offset = 2;
      if (metadata.operandCount == 3) {
        offset = operands[2].get<uint64_t>();
      }
      results[0] = operands[1].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_ST1i32: {  // st1 {vt.s}[index], [xn]
      // STORE
      const uint32_t* t = operands[0].getAsVector<uint32_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      break;
    }
    case Opcode::AArch64_ST1i32_POST: {  // st1 {vt.s}[index], [xn], xm
                                         // st1 {vt.s}[index], [xn], #4
      // STORE
      const uint32_t* t = operands[0].getAsVector<uint32_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      uint64_t offset = 4;
      if (metadata.operandCount == 3) {
        offset = operands[2].get<uint64_t>();
      }
      results[0] = operands[1].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_ST1i64: {  // st1 {vt.d}[index], [xn]
      // STORE
      const uint64_t* t = operands[0].getAsVector<uint64_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      break;
    }
    case Opcode::AArch64_ST1i64_POST: {  // st1 {vt.d}[index], [xn], xm
                                         // st1 {vt.d}[index], [xn], #8
      // STORE
      const uint64_t* t = operands[0].getAsVector<uint64_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      uint64_t offset = 8;
      if (metadata.operandCount == 3) {
        offset = operands[2].get<uint64_t>();
      }
      results[0] = operands[1].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_ST1i8: {  // st1 {vt.b}[index], [xn]
      // STORE
      const uint8_t* t = operands[0].getAsVector<uint8_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      break;
    }
    case Opcode::AArch64_ST1i8_POST: {  // st1 {vt.b}[index], [xn], xm
                                        // st1 {vt.b}[index], [xn], #1
      // STORE
      const uint8_t* t = operands[0].getAsVector<uint8_t>();
      memoryData[0] = t[metadata.operands[0].vector_index];
      uint64_t offset = 1;
      if (metadata.operandCount == 3) {
        offset = operands[2].get<uint64_t>();
      }
      results[0] = RegisterValue(operands[1].get<uint64_t>() + offset, 8);
      break;
    }
    case Opcode::AArch64_ST2B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2B_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov4s_POST: {  // st2 {vt1.4s, vt2.4s}, [xn], #imm
      // STORE
      const float* t1 = operands[0].getAsVector<float>();
      const float* t2 = operands[1].getAsVector<float>();
      for (int i = 0; i < 4; i++) {
        memoryData[2 * i] = t1[i];
        memoryData[2 * i + 1] = t2[i];
      }
      uint64_t offset = 32;
      if (metadata.operandCount == 4) {
        offset = operands[3].get<uint64_t>();
      }
      results[0] = operands[2].get<uint64_t>() + offset;
      break;
    }
    case Opcode::AArch64_ST2Twov8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2Twov8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2W: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2W_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2i16_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2i32_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2i64_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST2i8_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3B_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3Threev8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3W: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3W_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3i16_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3i32_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3i64_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST3i8_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4B_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4D_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv16b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv16b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv2d: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv2d_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv2s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv2s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv4h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv4h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv4s: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv4s_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv8b: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv8b_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv8h: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4Fourv8h_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4H_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4W: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4W_IMM: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4i16_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4i32_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4i64_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ST4i8_POST: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLLRB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLLRH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLLRW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLLRX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLRB: {  // stlrb wt, [xn]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STLRH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLRW:    // stlr wt, [xn]
    case Opcode::AArch64_STLRX: {  // stlr xt, [xn]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STLURBi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLURHi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLURWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLURXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLXPW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLXPX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLXRB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLXRH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STLXRW:    // stlxr ws, wt, [xn]
    case Opcode::AArch64_STLXRX: {  // stlxr ws, xt, [xn]
      // STORE
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
      break;
    }
    case Opcode::AArch64_STNPDi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNPQi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNPSi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNPWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNPXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNT1B_ZRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNT1B_ZRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNT1D_ZRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNT1D_ZRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNT1H_ZRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNT1H_ZRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNT1W_ZRI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STNT1W_ZRR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STPDi: {  // stp dt1, dt2, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STPDpost: {  // stp dt1, dt2, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_STPDpre: {  // stp dt1, dt2, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_STPQi: {  // stp qt1, qt2, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STPQpost: {  // stp qt1, qt2, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_STPQpre: {  // stp qt1, qt2, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_STPSi: {  // stp st1, st2, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STPSpost: {  // stp st1, st2, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_STPSpre: {  // stp st1, st2, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_STPWi: {  // stp wt1, wt2, [xn, #imm]
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STPWpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STPWpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STPXi: {  // stp xt1, xt2, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      break;
    }
    case Opcode::AArch64_STPXpost: {  // stp xt1, xt2, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
      break;
    }
    case Opcode::AArch64_STPXpre: {  // stp xt1, xt2, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      memoryData[1] = operands[1];
      results[0] = operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
      break;
    }
    case Opcode::AArch64_STRBBpost: {  // strb wd, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRBBpre: {  // strb wd, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRBBroW: {  // strb wd,
                                      //  [xn, wm{, extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRBBroX: {  // strb wd,
                                      //  [xn, xm{, extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRBBui: {  // strb wd, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRBpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRBpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRBroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRBroX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRBui: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRDpost: {  // str dt, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRDpre: {  // str dd, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRDroW: {  // str dt, [xn, wm{, #extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRDroX: {  // str dt, [xn, xm{, #extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRDui: {  // str dt, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRHHpost: {  // strh wt, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRHHpre: {  // strh wd, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRHHroW: {  // strh wd,
                                      //  [xn, wm{, extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRHHroX: {  // strh wd,
                                      //  [xn, xm{, extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRHHui: {  // strh wt, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRHpost: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRHpre: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRHroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRHroX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRHui: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRQpost: {  // str qt, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRQpre: {  // str qt, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRQroW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STRQroX: {  // str qt, [xn, xm{, extend, {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRQui: {  // str qt, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRSpost: {  // str st, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRSpre: {  // str sd, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRSroW: {  // str st, [xn, wm{, #extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRSroX: {  // str st, [xn, xm{, #extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRSui: {  // str st, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRWpost: {  // str wt, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRWpre: {  // str wd, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRWroW: {  // str wd, [xn, wm{, extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRWroX: {  // str wt, [xn, xm{, extend, {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRWui: {  // str wt, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRXpost: {  // str xt, [xn], #imm
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
      break;
    }
    case Opcode::AArch64_STRXpre: {  // str xd, [xn, #imm]!
      // STORE
      memoryData[0] = operands[0];
      results[0] = operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
      break;
    }
    case Opcode::AArch64_STRXroW: {  // str xd, [xn, wm{, extend {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRXroX: {  // str xt, [xn, xm{, extend, {#amount}}]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STRXui: {  // str xt, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STR_PXI: {  // str pt, [xn{, #imm, mul vl}]
      // STORE
      const uint64_t PL_bits = VL_bits / 8;
      const uint16_t partition_num = PL_bits / 8;
      const uint8_t* p = operands[0].getAsVector<uint8_t>();
      for (int i = 0; i < partition_num; i++) {
        memoryData[i] = p[i];
      }
      break;
    }
    case Opcode::AArch64_STR_ZXI: {  // str zt, [xn{, #imm, mul vl}]
      // STORE
      const uint16_t partition_num = VL_bits / 8;
      const uint8_t* z = operands[0].getAsVector<uint8_t>();
      for (int i = 0; i < partition_num; i++) {
        memoryData[i] = z[i];
      }
      break;
    }
    case Opcode::AArch64_STTRBi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STTRHi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STTRWi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STTRXi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STURBBi: {  // sturb wd, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STURBi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STURDi:     // stur dt, [xn, #imm]
    case Opcode::AArch64_STURHHi: {  // sturh wt, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STURHi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STURQi:    // stur qt, [xn, #imm]
    case Opcode::AArch64_STURSi:    // stur st, [xn, #imm]
    case Opcode::AArch64_STURWi:    // stur wt, [xn, #imm]
    case Opcode::AArch64_STURXi: {  // stur xt, [xn, #imm]
      // STORE
      memoryData[0] = operands[0];
      break;
    }
    case Opcode::AArch64_STXPW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STXPX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STXRB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STXRH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_STXRW: {  // stxr ws, wt, [xn]
      // STORE
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
      break;
    }
    case Opcode::AArch64_STXRX: {  // stxr ws, xt, [xn]
      // STORE
      memoryData[0] = operands[0];
      // TODO: Implement atomic memory access
      results[0] = static_cast<uint64_t>(0);
      break;
    }
    case Opcode::AArch64_SUBHNv2i64_v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBHNv2i64_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBHNv4i32_v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBHNv4i32_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBHNv8i16_v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBHNv8i16_v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBR_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBR_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBR_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBR_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBR_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBR_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBSWri: {  // subs wd, wn, #imm
      auto [result, nzcv] =
          arithmeticHelp::subShift_imm<uint32_t>(operands, metadata, true);
      results[0] = RegisterValue(nzcv);
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_SUBSWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBSWrs: {  // subs wd, wn, wm{, shift #amount}
      auto [result, nzcv] =
          arithmeticHelp::subShift_3ops<uint32_t>(operands, metadata, true);
      results[0] = RegisterValue(nzcv);
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_SUBSWrx: {  // subs wd, wn, wm{, extend #amount}
      auto [result, nzcv] =
          arithmeticHelp::subExtend_3ops<uint32_t>(operands, metadata, true);
      results[0] = RegisterValue(nzcv);
      results[1] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_SUBSXri: {  // subs xd, xn, #imm
      auto [result, nzcv] =
          arithmeticHelp::subShift_imm<uint64_t>(operands, metadata, true);
      results[0] = RegisterValue(nzcv);
      results[1] = RegisterValue(result);
      break;
    }
    case Opcode::AArch64_SUBSXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBSXrs: {  // subs xd, xn, xm{, shift #amount}
      auto [result, nzcv] =
          arithmeticHelp::subShift_3ops<uint64_t>(operands, metadata, true);
      results[0] = RegisterValue(nzcv);
      results[1] = RegisterValue(result);
      break;
    }
    case Opcode::AArch64_SUBSXrx:      // subs xd, xn, wm{, extend #amount}
    case Opcode::AArch64_SUBSXrx64: {  // subs xd, xn, xm{, extend #amount}
      auto [result, nzcv] =
          arithmeticHelp::subExtend_3ops<uint64_t>(operands, metadata, true);
      results[0] = RegisterValue(nzcv);
      results[1] = RegisterValue(result);
      break;
    }
    case Opcode::AArch64_SUBWri: {  // sub wd, wn, #imm{, <shift>}
      auto [result, nzcv] =
          arithmeticHelp::subShift_imm<uint32_t>(operands, metadata, false);
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_SUBWrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBWrs: {  // sub wd, wn, wm{, shift #amount}
      auto [result, nzcv] =
          arithmeticHelp::subShift_3ops<uint32_t>(operands, metadata, false);
      results[0] = RegisterValue(result, 8);
      break;
    }
    case Opcode::AArch64_SUBWrx: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBXri: {  // sub xd, xn, #imm{, <shift>}
      auto [result, nzcv] =
          arithmeticHelp::subShift_imm<uint64_t>(operands, metadata, false);
      results[0] = RegisterValue(result);
      break;
    }
    case Opcode::AArch64_SUBXrr: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUBXrs: {  // sub xd, xn, xm{, shift #amount}
      auto [result, nzcv] =
          arithmeticHelp::subShift_3ops<uint64_t>(operands, metadata, false);
      results[0] = RegisterValue(result);
      break;
    }
    case Opcode::AArch64_SUBXrx:      // sub xd, xn, wm{, extend #amount}
    case Opcode::AArch64_SUBXrx64: {  // sub xd, xn, xm{, extend #amount}
      auto [result, nzcv] =
          arithmeticHelp::subExtend_3ops<uint64_t>(operands, metadata, false);
      results[0] = RegisterValue(result);
      break;
    }
    case Opcode::AArch64_SUB_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUB_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUB_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUB_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUB_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUB_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUB_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUB_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUB_ZZZ_B: {  // sub zd.b, zn.b, zm.b
      results[0] = sveHelp::sveSub_3vecs<uint8_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SUB_ZZZ_D: {  // sub zd.d, zn.d, zm.d
      results[0] = sveHelp::sveSub_3vecs<uint64_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SUB_ZZZ_H: {  // sub zd.h, zn.h, zm.h
      results[0] = sveHelp::sveSub_3vecs<uint16_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SUB_ZZZ_S: {  // sub zd.s, zn.s, zm.s
      results[0] = sveHelp::sveSub_3vecs<uint32_t>(operands, VL_bits);
      break;
    }
    case Opcode::AArch64_SUBv16i8: {  // sub vd.16b, vn.16b, vm.16b
      results[0] = neonHelp::vecLogicOp_3vecs<uint8_t, 16>(
          operands, [](uint8_t x, uint8_t y) -> uint8_t { return x - y; });
      break;
    }
    case Opcode::AArch64_SUBv1i64: {  // sub dd, dn, dm
      results[0] = neonHelp::vecLogicOp_3vecs<uint64_t, 1>(
          operands, [](uint64_t x, uint64_t y) -> uint64_t { return x - y; });
      break;
    }
    case Opcode::AArch64_SUBv2i32: {  // sub vd.2s, vn.2s, vm.2s
      results[0] = neonHelp::vecLogicOp_3vecs<uint32_t, 2>(
          operands, [](uint32_t x, uint32_t y) -> uint32_t { return x - y; });
      break;
    }
    case Opcode::AArch64_SUBv2i64: {  // sub vd.2d, vn.2d, vm.2d
      results[0] = neonHelp::vecLogicOp_3vecs<uint64_t, 2>(
          operands, [](uint64_t x, uint64_t y) -> uint64_t { return x - y; });
      break;
    }
    case Opcode::AArch64_SUBv4i16: {  // sub vd.4h, vn.4h, vm.4h
      results[0] = neonHelp::vecLogicOp_3vecs<uint16_t, 4>(
          operands, [](uint64_t x, uint16_t y) -> uint16_t { return x - y; });
      break;
    }
    case Opcode::AArch64_SUBv4i32: {  // sub vd.4s, vn.4s, vm.4s
      results[0] = neonHelp::vecLogicOp_3vecs<uint32_t, 4>(
          operands, [](uint32_t x, uint32_t y) -> uint32_t { return x - y; });
      break;
    }
    case Opcode::AArch64_SUBv8i16: {  // sub vd.8h, vn.8h, vm.8h
      results[0] = neonHelp::vecLogicOp_3vecs<uint16_t, 8>(
          operands, [](uint16_t x, uint16_t y) -> uint16_t { return x - y; });
      break;
    }
    case Opcode::AArch64_SUBv8i8: {  // sub vd.8b, vn.8b, vm.8b
      results[0] = neonHelp::vecLogicOp_3vecs<uint8_t, 8>(
          operands, [](uint8_t x, uint8_t y) -> uint8_t { return x - y; });
      break;
    }
    case Opcode::AArch64_SUNPKHI_ZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUNPKHI_ZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUNPKHI_ZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUNPKLO_ZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUNPKLO_ZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUNPKLO_ZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SUQADDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SVC: {  // svc #imm
      exceptionEncountered_ = true;
      exception_ = InstructionException::SupervisorCall;
      break;
    }
    case Opcode::AArch64_SWPAB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPAH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPALB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPALH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPALW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPALX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPAW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPAX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPLB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPLH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPLW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPLX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPW: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SWPX: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SXTB_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SXTB_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SXTB_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SXTH_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SXTH_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SXTW_ZPmZ_D: {  // sxtw zd.d, pg/m, zn.d
      const int64_t* d = operands[0].getAsVector<int64_t>();
      const uint64_t* p = operands[1].getAsVector<uint64_t>();
      const int64_t* n = operands[2].getAsVector<int64_t>();

      const uint16_t partition_num = VL_bits / 64;
      int64_t out[32] = {0};

      for (int i = 0; i < partition_num; i++) {
        uint64_t shifted_active = 1ull << ((i % 8) * 8);
        if (p[i / 8] & shifted_active) {
          // Cast to 32-bit to get 'least significant sub-element'
          // Then cast back to 64-bit to sign-extend this 'sub-element'
          out[i] = static_cast<int64_t>(static_cast<int32_t>(n[i]));
        } else {
          out[i] = d[i];
        }
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_SYSLxt: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_SYSxt: {  // sys #<op1>, cn, cm, #<op2>{, xt}
      if (metadata.id == ARM64_INS_DC) {
        uint64_t address = operands[0].get<uint64_t>();
        uint8_t dzp = operands[1].get<uint64_t>() & 8;
        uint8_t N = std::pow(2, operands[1].get<uint64_t>() & 7);
        if (metadata.operands[0].sys == ARM64_DC_ZVA) {
          if (dzp) {
            // TODO
          }
        }
      }
      break;
    }
    case Opcode::AArch64_TBL_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBL_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBL_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBL_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBLv16i8Four: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBLv16i8One: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBLv16i8Three: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBLv16i8Two: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBLv8i8Four: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBLv8i8One: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBLv8i8Three: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBLv8i8Two: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBNZW: {  // tbnz wn, #imm, label
      auto [taken, addr] = conditionalHelp::tbnz_tbz<uint32_t>(
          operands, metadata, instructionAddress_, true);
      branchTaken_ = taken;
      branchAddress_ = addr;
      break;
    }
    case Opcode::AArch64_TBNZX: {  // tbnz xn, #imm, label
      auto [taken, addr] = conditionalHelp::tbnz_tbz<uint64_t>(
          operands, metadata, instructionAddress_, true);
      branchTaken_ = taken;
      branchAddress_ = addr;
      break;
    }
    case Opcode::AArch64_TBXv16i8Four: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBXv16i8One: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBXv16i8Three: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBXv16i8Two: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBXv8i8Four: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBXv8i8One: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBXv8i8Three: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBXv8i8Two: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TBZW: {  // tbz wn, #imm, label
      auto [taken, addr] = conditionalHelp::tbnz_tbz<uint32_t>(
          operands, metadata, instructionAddress_, false);
      branchTaken_ = taken;
      branchAddress_ = addr;
      break;
    }
    case Opcode::AArch64_TBZX: {  // tbz xn, #imm, label
      auto [taken, addr] = conditionalHelp::tbnz_tbz<uint64_t>(
          operands, metadata, instructionAddress_, false);
      branchTaken_ = taken;
      branchAddress_ = addr;
      break;
    }
    case Opcode::AArch64_TCRETURNdi: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TCRETURNri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TLSDESCCALL: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TLSDESC_CALLSEQ: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1_PPP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1_PPP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1_PPP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1_PPP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN1v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2_PPP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2_PPP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2_PPP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2_PPP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TRN2v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_TSB: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABALv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABALv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABALv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABALv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABALv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABALv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABAv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABAv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABAv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABAv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABAv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABAv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABD_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABD_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABD_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABD_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UABDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADALPv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADALPv2i32_v1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADALPv4i16_v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADALPv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADALPv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADALPv8i8_v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLPv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLPv2i32_v1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLPv4i16_v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLPv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLPv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLPv8i8_v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLVv16i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLVv8i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDV_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDWv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDWv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDWv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDWv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDWv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UADDWv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UBFMWri: {  // ubfm wd, wn, #immr, #imms
      results[0] = RegisterValue(
          bitmanipHelp::bfm_2imms<uint32_t>(operands, metadata, false, true),
          8);
      break;
    }
    case Opcode::AArch64_UBFMXri: {  // ubfm xd, xn, #immr, #imms
      results[0] =
          bitmanipHelp::bfm_2imms<uint64_t>(operands, metadata, false, true);
      break;
    }
    case Opcode::AArch64_UCVTFSWDri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFSWHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFSWSri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFSXDri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFSXHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFSXSri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFUWDri: {  // ucvtf dd, wn
      results[0] =
          RegisterValue(static_cast<double>(operands[0].get<uint32_t>()), 256);
      break;
    }
    case Opcode::AArch64_UCVTFUWHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFUWSri: {  // ucvtf sd, wn
      results[0] =
          RegisterValue(static_cast<float>(operands[0].get<uint32_t>()), 256);
      break;
    }
    case Opcode::AArch64_UCVTFUXDri: {  // ucvtf dd, xn
      results[0] =
          RegisterValue(static_cast<double>(operands[0].get<uint64_t>()), 256);
      break;
    }
    case Opcode::AArch64_UCVTFUXHri: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFUXSri: {  // ucvtf sd, xn
      results[0] =
          RegisterValue(static_cast<float>(operands[0].get<uint64_t>()), 256);
      break;
    }
    case Opcode::AArch64_UCVTF_ZPmZ_DtoD: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTF_ZPmZ_DtoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTF_ZPmZ_DtoS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTF_ZPmZ_HtoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTF_ZPmZ_StoD: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTF_ZPmZ_StoH: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTF_ZPmZ_StoS: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv1i32: {  // ucvtf sd, sn
      results[0] =
          RegisterValue(static_cast<float>(operands[0].get<uint32_t>()), 256);
      break;
    }
    case Opcode::AArch64_UCVTFv1i64: {  // ucvtf dd, dn
      results[0] =
          RegisterValue(static_cast<double>(operands[0].get<uint64_t>()), 256);
      break;
    }
    case Opcode::AArch64_UCVTFv2f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv2f64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv4f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv4f32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv8f16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UCVTFv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDIVR_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDIVR_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDIVWr: {  // udiv wd, wn, wm
      results[0] = RegisterValue(divideHelp::div_3ops<uint32_t>(operands), 8);
      break;
    }
    case Opcode::AArch64_UDIVXr: {  // udiv xd, xn, xm
      results[0] = RegisterValue(divideHelp::div_3ops<uint64_t>(operands), 8);
      break;
    }
    case Opcode::AArch64_UDIV_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDIV_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDOT_ZZZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDOT_ZZZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDOT_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDOT_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDOTlanev16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDOTlanev8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDOTv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UDOTv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHADDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHADDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHADDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHADDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHADDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHADDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHSUBv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHSUBv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHSUBv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHSUBv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHSUBv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UHSUBv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMADDLrrr: {  // umaddl xd, wn, wm, xa
      auto n = static_cast<uint64_t>(operands[0].get<uint32_t>());
      auto m = static_cast<uint64_t>(operands[1].get<uint32_t>());
      auto a = operands[2].get<uint64_t>();
      results[0] = a + (n * m);
      break;
    }
    case Opcode::AArch64_UMAXPv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXPv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXPv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXPv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXPv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXPv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXV_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXVv16i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXVv8i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAX_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAX_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAX_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAX_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAX_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAX_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAX_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAX_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMAXv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINPv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINPv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINPv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINPv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINPv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINPv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINV_VPZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINV_VPZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINV_VPZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINV_VPZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINVv16i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINVv4i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINVv4i32v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINVv8i16v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINVv8i8v: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMIN_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMIN_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMIN_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMIN_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMIN_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMIN_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMIN_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMIN_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMINv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLALv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMLSLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMOVvi16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMOVvi32: {  // umov wd, vn.s[index]
      const uint32_t* vec = operands[0].getAsVector<uint32_t>();
      results[0] = RegisterValue(vec[metadata.operands[1].vector_index], 8);
      break;
    }
    case Opcode::AArch64_UMOVvi64: {  // umov xd, vn.d[index]
      const uint64_t* vec = operands[0].getAsVector<uint64_t>();
      results[0] = vec[metadata.operands[1].vector_index];
      break;
    }
    case Opcode::AArch64_UMOVvi8: {  // umov wd, vn.b[index]
      const uint8_t* vec = operands[0].getAsVector<uint8_t>();
      results[0] = RegisterValue(vec[metadata.operands[1].vector_index], 8);
      break;
    }
    case Opcode::AArch64_UMSUBLrrr: {  // umsubl xd, wn, wm, xa
      uint64_t n = static_cast<uint64_t>(operands[0].get<uint32_t>());
      uint64_t m = static_cast<uint64_t>(operands[1].get<uint32_t>());
      uint64_t a = operands[2].get<uint64_t>();
      results[0] = a - (n * m);
      break;
    }
    case Opcode::AArch64_UMULH_ZPmZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULH_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULH_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULH_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULHrr: {  // umulh xd, xn, xm
      auto x = operands[0].get<uint64_t>();
      auto y = operands[1].get<uint64_t>();
      results[0] = AuxFunc::mulhi(x, y);
      break;
    }
    case Opcode::AArch64_UMULLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULLv2i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULLv4i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULLv4i32_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULLv8i16_indexed: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UMULLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADD_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADD_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADD_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADD_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADD_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADD_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADD_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADD_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQADDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECB_WPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECB_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECD_WPiI: {  // uqdecd wd{, pattern{, MUL #imm}}
      results[0] =
          sveHelp::sveUqdec<uint32_t, 64u>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_UQDECD_XPiI: {  // uqdecd xd{, pattern{, MUL #imm}}
      results[0] =
          sveHelp::sveUqdec<uint64_t, 64u>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_UQDECD_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECH_WPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECH_XPiI: {  // uqdech xd{, pattern{, MUL #imm}}
      results[0] =
          sveHelp::sveUqdec<uint64_t, 16u>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_UQDECH_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_WP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_WP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_WP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_WP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_XP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_XP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_XP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_XP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_ZP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_ZP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECP_ZP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECW_WPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQDECW_XPiI: {  // uqdecw xd{, pattern{, MUL #imm}}
      results[0] =
          sveHelp::sveUqdec<uint64_t, 32u>(operands, metadata, VL_bits);
      break;
    }
    case Opcode::AArch64_UQDECW_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCB_WPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCB_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCD_WPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCD_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCD_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCH_WPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCH_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCH_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_WP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_WP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_WP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_WP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_XP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_XP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_XP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_XP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_ZP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_ZP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCP_ZP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCW_WPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCW_XPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQINCW_ZPiI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHRNb: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHRNh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHRNs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHRNv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHRNv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHRNv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHRNv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHRNv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQRSHRNv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLb: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHLv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHRNb: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHRNh: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHRNs: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHRNv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHRNv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHRNv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHRNv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHRNv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSHRNv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUB_ZI_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUB_ZI_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUB_ZI_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUB_ZI_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUB_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUB_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUB_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUB_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQSUBv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQXTNv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQXTNv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQXTNv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQXTNv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQXTNv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQXTNv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQXTNv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQXTNv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UQXTNv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URECPEv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URECPEv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URHADDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URHADDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URHADDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URHADDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URHADDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URHADDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHLv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHLv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHLv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHLv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHRd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHRv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHRv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHRv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHRv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHRv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHRv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSHRv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSQRTEv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSQRTEv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSRAd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSRAv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSRAv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSRAv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSRAv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSRAv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSRAv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_URSRAv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLLv16i8_shift: {  // ushll2 vd.8h, vn.16b, #imm
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      const uint64_t shift = metadata.operands[2].imm;
      uint16_t out[8] = {0};
      for (int i = 0; i < 8; i++) {
        out[i] = n[i + 8] << shift;
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_USHLLv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLLv4i16_shift: {  // ushll vd.4s, vn.4h, #imm
      const uint16_t* n = operands[0].getAsVector<uint16_t>();
      const uint64_t shift = metadata.operands[2].imm;
      uint32_t out[4] = {0};
      for (int i = 0; i < 4; i++) {
        out[i] = n[i] << shift;
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_USHLLv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLLv8i16_shift: {  // ushll2 vd.4s, vn.8h, #imm
      const uint16_t* n = operands[0].getAsVector<uint16_t>();
      const uint64_t shift = metadata.operands[2].imm;
      uint32_t out[4] = {0};
      for (int i = 0; i < 4; i++) {
        out[i] = n[i + 4] << shift;
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_USHLLv8i8_shift: {  // ushll vd.8h, vn.8b, #imm
      const uint8_t* n = operands[0].getAsVector<uint8_t>();
      const uint64_t shift = metadata.operands[2].imm;
      uint16_t out[8] = {0};
      for (int i = 0; i < 8; i++) {
        out[i] = n[i] << shift;
      }
      results[0] = {out, 256};
      break;
    }
    case Opcode::AArch64_USHLv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHLv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHRd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHRv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHRv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHRv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHRv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHRv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHRv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USHRv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv1i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv1i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv1i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv1i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USQADDv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USRAd: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USRAv16i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USRAv2i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USRAv2i64_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USRAv4i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USRAv4i32_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USRAv8i16_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USRAv8i8_shift: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBLv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBLv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBLv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBLv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBLv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBLv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBWv16i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBWv2i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBWv4i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBWv4i32_v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBWv8i16_v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_USUBWv8i8_v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UUNPKHI_ZZ_D: {  // uunpkhi zd.d, zn.s
      results[0] =
          sveHelp::sveUnpk_vecs<uint64_t, uint32_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_UUNPKHI_ZZ_H: {  // uunpkhi zd.h, zn.b
      results[0] =
          sveHelp::sveUnpk_vecs<uint16_t, uint8_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_UUNPKHI_ZZ_S: {  // uunpkhi zd.s, zn.h
      results[0] =
          sveHelp::sveUnpk_vecs<uint32_t, uint16_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_UUNPKLO_ZZ_D: {  // uunpklo zd.d, zn.s
      results[0] =
          sveHelp::sveUnpk_vecs<uint64_t, uint32_t>(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_UUNPKLO_ZZ_H: {  // uunpklo zd.h, zn.b
      results[0] =
          sveHelp::sveUnpk_vecs<uint16_t, uint8_t>(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_UUNPKLO_ZZ_S: {  // uunpklo zd.s, zn.h
      results[0] =
          sveHelp::sveUnpk_vecs<uint32_t, uint16_t>(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_UXTB_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UXTB_ZPmZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UXTB_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UXTH_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UXTH_ZPmZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UXTW_ZPmZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1_PPP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1_PPP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1_PPP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1_PPP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1_ZZZ_S: {  // uzp1 zd.s, zn.s, zm.s
      results[0] = sveHelp::sveUzp_vecs<uint32_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_UZP1v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP1v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2_PPP_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2_PPP_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2_PPP_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2_PPP_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2_ZZZ_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2_ZZZ_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_UZP2v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELE_PWW_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELE_PWW_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELE_PWW_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELE_PWW_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELE_PXX_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELE_PXX_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELE_PXX_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELE_PXX_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELO_PWW_B: {  // whilelo pd.b, wn, wm
      auto [output, nzcv] =
          sveHelp::sveWhilelo<uint32_t, uint8_t>(operands, VL_bits, true);
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_WHILELO_PWW_D: {  // whilelo pd.d, wn, wm
      auto [output, nzcv] =
          sveHelp::sveWhilelo<uint32_t, uint64_t>(operands, VL_bits, true);
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_WHILELO_PWW_H: {  // whilelo pd.h, wn, wm
      auto [output, nzcv] =
          sveHelp::sveWhilelo<uint32_t, uint16_t>(operands, VL_bits, true);
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_WHILELO_PWW_S: {  // whilelo pd.s, wn, wm
      auto [output, nzcv] =
          sveHelp::sveWhilelo<uint32_t, uint32_t>(operands, VL_bits, true);
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_WHILELO_PXX_B: {  // whilelo pd.b, xn, xm
      auto [output, nzcv] =
          sveHelp::sveWhilelo<uint64_t, uint8_t>(operands, VL_bits, true);
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_WHILELO_PXX_D: {  // whilelo pd.d, xn, xm
      auto [output, nzcv] =
          sveHelp::sveWhilelo<uint64_t, uint64_t>(operands, VL_bits, true);
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_WHILELO_PXX_H: {  // whilelo pd.h, xn, xm
      auto [output, nzcv] =
          sveHelp::sveWhilelo<uint64_t, uint16_t>(operands, VL_bits, true);
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_WHILELO_PXX_S: {  // whilelo pd.s, xn, xm
      auto [output, nzcv] =
          sveHelp::sveWhilelo<uint64_t, uint32_t>(operands, VL_bits, true);
      results[0] = nzcv;
      results[1] = output;
      break;
    }
    case Opcode::AArch64_WHILELS_PWW_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELS_PWW_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELS_PWW_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELS_PWW_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELS_PXX_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELS_PXX_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELS_PXX_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELS_PXX_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELT_PWW_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELT_PWW_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELT_PWW_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELT_PWW_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELT_PXX_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELT_PXX_D: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELT_PXX_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WHILELT_PXX_S: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_WRFFR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_XAR: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_XPACD: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_XPACI: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_XPACLRI: {  // xpaclri
      // SimEng doesn't support PAC, so do nothing
      break;
    }
    case Opcode::AArch64_XTNv16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_XTNv2i32: {  // xtn vd.2s, vn.2d
      results[0] = neonHelp::vecXtn<uint32_t, uint64_t, 2>(operands, false);
      break;
    }
    case Opcode::AArch64_XTNv4i16: {  // xtn vd.4h, vn.4s
      results[0] = neonHelp::vecXtn<uint16_t, uint32_t, 4>(operands, false);
      break;
    }
    case Opcode::AArch64_XTNv4i32: {  // xtn2 vd.4s, vn.2d
      results[0] = neonHelp::vecXtn<uint32_t, uint64_t, 4>(operands, true);
      break;
    }
    case Opcode::AArch64_XTNv8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_XTNv8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP1_PPP_B: {  // zip1 pd.b, pn.b, pm.b
      results[0] = sveHelp::sveZip_preds<uint8_t>(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_ZIP1_PPP_D: {  // zip1 pd.d, pn.d, pm.d
      results[0] = sveHelp::sveZip_preds<uint64_t>(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_ZIP1_PPP_H: {  // zip1 pd.h, pn.h, pm.h
      results[0] = sveHelp::sveZip_preds<uint16_t>(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_ZIP1_PPP_S: {  // zip1 pd.s, pn.s, pm.s
      results[0] = sveHelp::sveZip_preds<uint32_t>(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_ZIP1_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP1_ZZZ_D: {  // zip1 zd.d, zn.d, zm.d
      results[0] = sveHelp::sveZip_vecs<uint64_t>(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_ZIP1_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP1_ZZZ_S: {  // zip1 zd.s, zn.s, zm.s
      results[0] = sveHelp::sveZip_vecs<uint32_t>(operands, VL_bits, false);
      break;
    }
    case Opcode::AArch64_ZIP1v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP1v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP1v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP1v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP1v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP1v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP1v8i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP2_PPP_B: {  // zip2 pd.b, pn.b, pm.b
      results[0] = sveHelp::sveZip_preds<uint8_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_ZIP2_PPP_D: {  // zip2 pd.d, pn.d, pm.d
      results[0] = sveHelp::sveZip_preds<uint64_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_ZIP2_PPP_H: {  // zip2 pd.h, pn.h, pm.h
      results[0] = sveHelp::sveZip_preds<uint16_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_ZIP2_PPP_S: {  // zip2 pd.s, pn.s, pm.s
      results[0] = sveHelp::sveZip_preds<uint32_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_ZIP2_ZZZ_B: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP2_ZZZ_D: {  // zip2 zd.d, zn.d, zm.d
      results[0] = sveHelp::sveZip_vecs<uint64_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_ZIP2_ZZZ_H: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP2_ZZZ_S: {  // zip2 zd.s, zn.s, zm.s
      results[0] = sveHelp::sveZip_vecs<uint32_t>(operands, VL_bits, true);
      break;
    }
    case Opcode::AArch64_ZIP2v16i8: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP2v2i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP2v2i64: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP2v4i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP2v4i32: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP2v8i16: {
      return executionNYI();
      break;
    }
    case Opcode::AArch64_ZIP2v8i8: {
      return executionNYI();
      break;
    }
    default:
      return executionINV();
  }

#ifndef NDEBUG
  // Check if upper bits of vector registers are zeroed because Z configuration
  // extend to 256 bytes whilst V configurations only extend to 16 bytes.
  // Thus upper 240 bytes must be ignored by being set to 0.
  for (int i = 0; i < destinationRegisterCount; i++) {
    if ((destinationRegisters[i].type == RegisterType::VECTOR) && !isSVEData_) {
      if (results[i].size() != 256)
        std::cerr << metadata.mnemonic << " opcode: " << metadata.opcode
                  << " has not been zero extended correctly\n";
    }
  }
#endif
}  // namespace aarch64

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng