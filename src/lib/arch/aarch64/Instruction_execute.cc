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
  return;
}

void Instruction::streamingModeUpdated() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::StreamingModeUpdate;
  return;
}

void Instruction::zaRegisterStatusUpdated() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::ZAregisterStatusUpdate;
  return;
}

void Instruction::SMZAupdated() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::SMZAUpdate;
  return;
}

void Instruction::ZAdisabled() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::ZAdisabled;
  return;
}

void Instruction::SMdisabled() {
  exceptionEncountered_ = true;
  exception_ = InstructionException::SMdisabled;
  return;
}

void Instruction::execute() {
  assert(!executed_ && "Attempted to execute an instruction more than once");
  assert(
      canExecute() &&
      "Attempted to execute an instruction before all operands were provided");
  // 0th bit of SVCR register determins if streaming-mode is enabled.
  const bool SMenabled = architecture_.getSVCRval() & 1;
  // 1st bit of SVCR register determins if ZA register is enabled.
  const bool ZAenabled = architecture_.getSVCRval() & 2;
  // When streaming mode is enabled, the architectural vector length goes from
  // SVE's VL to SME's SVL.
  const uint16_t VL_bits = SMenabled ? architecture_.getStreamingVectorLength()
                                     : architecture_.getVectorLength();
  executed_ = true;
  if (isMicroOp_) {
    switch (microOpcode_) {
      case MicroOpcode::LDR_ADDR: {
        uint16_t regSize =
            (isScalarData_ || isVectorData_ || isSVEData_) ? 256 : 8;
        for (size_t dest = 0; dest < getDestinationRegisters().size(); dest++) {
          results[dest] = memoryData[dest].zeroExtend(dataSize_, regSize);
        }
        break;
      }
      case MicroOpcode::OFFSET_IMM: {
        results[0] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
        break;
      }
      case MicroOpcode::STR_DATA: {
        setMemoryAddresses({{0, 0}});
        memoryData[0] = operands[0];
        break;
      }
      default:
        return executionNYI();
    }
  } else {
    switch (metadata.opcode) {
      case Opcode::AArch64_ADCXr: {  // adc xd, xn, xm
        auto [result, nzcv] = arithmeticHelp::addCarry_3ops<uint64_t>(operands);
        results[0] = result;
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
      case Opcode::AArch64_ADDPv2i64: {  // addp vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecAddp_3ops<uint64_t, 2>(operands);
        break;
      }
      case Opcode::AArch64_ADDPv2i64p: {  // addp dd, vn.2d
        results[0] = neonHelp::vecSumElems_2ops<uint64_t, 2>(operands);
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
      case Opcode::AArch64_ADDSWri: {  // adds wd, wn, #imm{, shift}
        auto [result, nzcv] =
            arithmeticHelp::addShift_imm<uint32_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = {result, 8};
        break;
      }
      case Opcode::AArch64_ADDSWrs: {  // adds wd, wn, wm{, shift}
        auto [result, nzcv] =
            arithmeticHelp::addShift_3ops<uint32_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = {result, 8};
        break;
      }
      case Opcode::AArch64_ADDSWrx: {  // adds wd, wn, wm{, extend {#amount}}
        auto [result, nzcv] =
            arithmeticHelp::addExtend_3ops<uint32_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = {result, 8};
        break;
      }
      case Opcode::AArch64_ADDSXri: {  // adds xd, xn, #imm{, shift}
        auto [result, nzcv] =
            arithmeticHelp::addShift_imm<uint64_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = result;
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
      case Opcode::AArch64_ADDVv8i8v: {  // addv bd, vn.8b
        results[0] = neonHelp::vecSumElems_2ops<uint8_t, 8>(operands);
        break;
      }
      case Opcode::AArch64_ADDWri: {  // add wd, wn, #imm{, shift}
        auto [result, nzcv] =
            arithmeticHelp::addShift_imm<uint32_t>(operands, metadata, false);
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_ADDWrs: {  // add wd, wn, wm{, shift #amount}
        auto [result, nzcv] =
            arithmeticHelp::addShift_3ops<uint32_t>(operands, metadata, false);
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_ADDWrx: {  // add wd, wn, wm{, extend #amount}
        auto [result, nzcv] =
            arithmeticHelp::addExtend_3ops<uint32_t>(operands, metadata, false);
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_ADDXri: {  // add xd, xn, #imm{, shift}
        auto [result, nzcv] =
            arithmeticHelp::addShift_imm<uint64_t>(operands, metadata, false);
        results[0] = result;
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
      case Opcode::AArch64_ADD_ZPmZ_B: {  // add zdn.b, pg/m, zdn.b, zm.b
        results[0] = sveHelp::sveAddPredicated_vecs<uint8_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_ADD_ZPmZ_D: {  // add zdn.d, pg/m, zdn.d, zm.d
        results[0] =
            sveHelp::sveAddPredicated_vecs<uint64_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_ADD_ZPmZ_H: {  // add zdn.h, pg/m, zdn.h, zm.h
        results[0] =
            sveHelp::sveAddPredicated_vecs<uint16_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_ADD_ZPmZ_S: {  // add zdn.s, pg/m, zdn.s, zm.s
        results[0] =
            sveHelp::sveAddPredicated_vecs<uint32_t>(operands, VL_bits);
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
      case Opcode::AArch64_ADR: {  // adr xd, #imm
        results[0] = instructionAddress_ + metadata.operands[1].imm;
        break;
      }
      case Opcode::AArch64_ADRP: {  // adrp xd, #imm
        // Clear lowest 12 bits of address and add immediate (already shifted by
        // decoder)
        results[0] =
            (instructionAddress_ & ~(0xFFF)) + metadata.operands[1].imm;
        break;
      }
      case Opcode::AArch64_ADR_LSL_ZZZ_D_0:    // adr zd.d, [zn.d, zm.d]
      case Opcode::AArch64_ADR_LSL_ZZZ_D_1:    // adr zd.d, [zn.d, zm.d, lsl #1]
      case Opcode::AArch64_ADR_LSL_ZZZ_D_2:    // adr zd.d, [zn.d, zm.d, lsl #2]
      case Opcode::AArch64_ADR_LSL_ZZZ_D_3: {  // adr zd.d, [zn.d, zm.d, lsl #3]
        results[0] = sveHelp::sveAdr_packedOffsets<uint64_t>(operands, metadata,
                                                             VL_bits);
        break;
      }
      case Opcode::AArch64_ADR_LSL_ZZZ_S_0:    // adr zd.s, [zn.s, zm.s]
      case Opcode::AArch64_ADR_LSL_ZZZ_S_1:    // adr zd.s, [zn.s, zm.s, lsl #1]
      case Opcode::AArch64_ADR_LSL_ZZZ_S_2:    // adr zd.s, [zn.s, zm.s, lsl #2]
      case Opcode::AArch64_ADR_LSL_ZZZ_S_3: {  // adr zd.s, [zn.s, zm.s, lsl #3]
        results[0] = sveHelp::sveAdr_packedOffsets<uint32_t>(operands, metadata,
                                                             VL_bits);
        break;
      }
      case Opcode::AArch64_ANDSWri: {  // ands wd, wn, #imm
        auto [result, nzcv] = logicalHelp::logicOp_imm<uint32_t>(
            operands, metadata, true,
            [](uint32_t x, uint32_t y) -> uint32_t { return x & y; });
        results[0] = nzcv;
        results[1] = {result, 8};
        break;
      }
      case Opcode::AArch64_ANDSWrs: {  // ands wd, wn, wm{, shift #amount}
        auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint32_t>(
            operands, metadata, true,
            [](uint32_t x, uint32_t y) -> uint32_t { return x & y; });
        results[0] = nzcv;
        results[1] = {result, 8};
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
      case Opcode::AArch64_ANDSXrs: {  // ands xd, xn, xm{, shift #amount}
        auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint64_t>(
            operands, metadata, true,
            [](uint64_t x, uint64_t y) -> uint64_t { return x & y; });
        results[0] = nzcv;
        results[1] = result;
        break;
      }
      case Opcode::AArch64_ANDWri: {  // and wd, wn, #imm
        auto [result, nzcv] = logicalHelp::logicOp_imm<uint32_t>(
            operands, metadata, false,
            [](uint32_t x, uint32_t y) -> uint32_t { return x & y; });
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_ANDWrs: {  // and wd, wn, wm{, shift #amount}
        auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint32_t>(
            operands, metadata, false,
            [](uint32_t x, uint32_t y) -> uint32_t { return x & y; });
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_ANDXri: {  // and xd, xn, #imm
        auto [result, nzcv] = logicalHelp::logicOp_imm<uint64_t>(
            operands, metadata, false,
            [](uint64_t x, uint64_t y) -> uint64_t { return x & y; });
        results[0] = result;
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
      case Opcode::AArch64_AND_ZI: {  // and zdn, zdn, #imm
        const uint64_t* dn = operands[0].getAsVector<uint64_t>();
        const uint64_t imm = static_cast<uint64_t>(metadata.operands[2].imm);

        const uint16_t partition_num = VL_bits / 64;
        uint64_t out[32] = {0};
        for (int i = 0; i < partition_num; i++) {
          out[i] = dn[i] & imm;
        }
        results[0] = {out, 256};
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
      case Opcode::AArch64_ASRVWr: {  // asrv wd, wn, wm
        results[0] = {logicalHelp::asrv_3gpr<int32_t>(operands), 8};
        break;
      }
      case Opcode::AArch64_ASRVXr: {  // asrv xd, xn, xm
        results[0] = logicalHelp::asrv_3gpr<int64_t>(operands);
        break;
      }
      case Opcode::AArch64_B: {  // b label
        branchTaken_ = true;
        branchAddress_ = instructionAddress_ + metadata.operands[0].imm;
        break;
      }
      case Opcode::AArch64_BFMWri: {  // bfm wd, wn, #immr, #imms
        results[0] = {
            bitmanipHelp::bfm_2imms<uint32_t>(operands, metadata, false, false),
            8};
        break;
      }
      case Opcode::AArch64_BFMXri: {  // bfm xd, xn, #immr, #imms
        results[0] =
            bitmanipHelp::bfm_2imms<uint64_t>(operands, metadata, false, false);
        break;
      }
      case Opcode::AArch64_BICSWrs: {  // bics wd, wn, wm{, shift #amount}
        auto [result, nzcv] =
            logicalHelp::bicShift_3ops<uint32_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = {result, 8};
        break;
      }
      case Opcode::AArch64_BICSXrs: {  // bics xd, xn, xm{, shift #amount}
        auto [result, nzcv] =
            logicalHelp::bicShift_3ops<uint64_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = result;
        break;
      }
      case Opcode::AArch64_BICWrs: {  // bic wd, wn, wm{, shift #amount}
        auto [result, nzcv] =
            logicalHelp::bicShift_3ops<uint32_t>(operands, metadata, false);
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_BICXrs: {  // bic xd, xn, xm{, shift #amount}
        auto [result, nzcv] =
            logicalHelp::bicShift_3ops<uint64_t>(operands, metadata, false);
        results[0] = result;
        break;
      }
      case Opcode::AArch64_BICv16i8: {  // bic vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecBic_3ops<uint8_t, 16>(operands);
        break;
      }
      case Opcode::AArch64_BICv4i32: {  // bic vd.4s, #imm{, lsl #shift}
        results[0] = neonHelp::vecBicShift_imm<uint32_t, 4>(operands, metadata);
        break;
      }
      case Opcode::AArch64_BICv8i16: {  // bic vd.8h, #imm{, lsl #shift}
        results[0] = neonHelp::vecBicShift_imm<uint16_t, 8>(operands, metadata);
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
      case Opcode::AArch64_BITv16i8: {  // bit vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecBitwiseInsert<16>(operands, false);
        break;
      }
      case Opcode::AArch64_BITv8i8: {  // bit vd.8b, vn.8b, vm.8b
        results[0] = neonHelp::vecBitwiseInsert<8>(operands, false);
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
      case Opcode::AArch64_BR: {  // br xn
        branchTaken_ = true;
        branchAddress_ = operands[0].get<uint64_t>();
        break;
      }
      case Opcode::AArch64_BRK: {
        // TODO: Generate breakpoint exception
        break;
      }
      case Opcode::AArch64_BSLv16i8: {  // bsl vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecBsl<16>(operands);
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
      case Opcode::AArch64_CCMNXi: {  // ccmn xn, #imm, #nzcv, cc
        results[0] = conditionalHelp::ccmn_imm<uint64_t>(operands, metadata);
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
      case Opcode::AArch64_CLZXr: {  // clz xd, xn
        results[0] = arithmeticHelp::clz_reg<int64_t>(operands);
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
      case Opcode::AArch64_CMEQv4i32: {  // cmeq vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecCompare<uint32_t, 4>(
            operands, false,
            [](uint32_t x, uint32_t y) -> bool { return (x == y); });
        break;
      }
      case Opcode::AArch64_CMEQv8i8: {  // cmeq vd.8b, vn.8b, vm.8b
        results[0] = neonHelp::vecCompare<int8_t, 8>(
            operands, false,
            [](int8_t x, int8_t y) -> bool { return (x == y); });
        break;
      }
      case Opcode::AArch64_CMEQv8i8rz: {  // cmeq vd.8b, vn.8b, #0
        results[0] = neonHelp::vecCompare<int8_t, 8>(
            operands, true,
            [](int8_t x, int8_t y) -> bool { return (x == y); });
        break;
      }
      case Opcode::AArch64_CMHIv4i32: {  // cmhi vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecCompare<uint32_t, 4>(
            operands, false,
            [](uint32_t x, uint32_t y) -> bool { return (x > y); });
        break;
      }
      case Opcode::AArch64_CMHSv16i8: {  // cmhs vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecCompare<int8_t, 16>(
            operands, false,
            [](int8_t x, int8_t y) -> bool { return (x >= y); });
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
      case Opcode::AArch64_CMPNE_PPzZI_B: {  // cmpne pd.b, pg/z. zn.b, #imm
        auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int8_t>(
            operands, metadata, VL_bits, true,
            [](int8_t x, int8_t y) -> bool { return x != y; });
        results[0] = nzcv;
        results[1] = output;
        break;
      }
      case Opcode::AArch64_CMPNE_PPzZI_D: {  // cmpne pd.d, pg/z. zn.d, #imm
        auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int64_t>(
            operands, metadata, VL_bits, true,
            [](int64_t x, int64_t y) -> bool { return x != y; });
        results[0] = nzcv;
        results[1] = output;
        break;
      }
      case Opcode::AArch64_CMPNE_PPzZI_H: {  // cmpne pd.h, pg/z. zn.h, #imm
        auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int16_t>(
            operands, metadata, VL_bits, true,
            [](int16_t x, int16_t y) -> bool { return x != y; });
        results[0] = nzcv;
        results[1] = output;
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
      case Opcode::AArch64_CMPNE_PPzZZ_B: {  // cmpne pd.b, pg/z, zn.b, zm.b
        auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int8_t>(
            operands, metadata, VL_bits, false,
            [](int8_t x, int8_t y) -> bool { return x != y; });
        results[0] = nzcv;
        results[1] = output;
        break;
      }
      case Opcode::AArch64_CMPNE_PPzZZ_D: {  // cmpne pd.d, pg/z, zn.d, zm.d
        auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int64_t>(
            operands, metadata, VL_bits, false,
            [](int64_t x, int64_t y) -> bool { return x != y; });
        results[0] = nzcv;
        results[1] = output;
        break;
      }
      case Opcode::AArch64_CMPNE_PPzZZ_H: {  // cmpne pd.h, pg/z, zn.h, zm.h
        auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int16_t>(
            operands, metadata, VL_bits, false,
            [](int16_t x, int16_t y) -> bool { return x != y; });
        results[0] = nzcv;
        results[1] = output;
        break;
      }
      case Opcode::AArch64_CMPNE_PPzZZ_S: {  // cmpne pd.s, pg/z, zn.s, zm.s
        auto [output, nzcv] = sveHelp::sveCmpPredicated_toPred<int32_t>(
            operands, metadata, VL_bits, false,
            [](int32_t x, int32_t y) -> bool { return x != y; });
        results[0] = nzcv;
        results[1] = output;
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
      case Opcode::AArch64_CNTv8i8: {  // cnt vd.8b, vn.8b
        results[0] = neonHelp::vecCountPerByte<uint8_t, 8>(operands);
        break;
      }
      case Opcode::AArch64_CPY_ZPzI_B: {  // cpy zd.b, pg/z, #imm{, shift}
        results[0] = sveHelp::sveCpy_imm<int8_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_CPY_ZPzI_D: {  // cpy zd.d, pg/z, #imm{, shift}
        results[0] = sveHelp::sveCpy_imm<int64_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_CPY_ZPzI_H: {  // cpy zd.h, pg/z, #imm{, shift}
        results[0] = sveHelp::sveCpy_imm<int16_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_CPY_ZPzI_S: {  // cpy zd.s, pg/z, #imm{, shift}
        results[0] = sveHelp::sveCpy_imm<int32_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_DUPi32: {  // dup vd, vn.s[index]
        results[0] =
            neonHelp::vecDup_gprOrIndex<uint32_t, 1>(operands, metadata, false);
        break;
      }
      case Opcode::AArch64_DUPi64: {  // dup vd, vn.d[index]
        results[0] =
            neonHelp::vecDup_gprOrIndex<uint64_t, 1>(operands, metadata, false);
        break;
      }
      case Opcode::AArch64_CSELWr: {  // csel wd, wn, wm, cc
        results[0] = {
            conditionalHelp::cs_4ops<uint32_t>(
                operands, metadata, [](uint32_t x) -> uint32_t { return x; }),
            8};
        break;
      }
      case Opcode::AArch64_CSELXr: {  // csel xd, xn, xm, cc
        results[0] = conditionalHelp::cs_4ops<uint64_t>(
            operands, metadata, [](uint64_t x) -> uint64_t { return x; });
        break;
      }
      case Opcode::AArch64_CSINCWr: {  // csinc wd, wn, wm, cc
        results[0] = {conditionalHelp::cs_4ops<uint32_t>(
                          operands, metadata,
                          [](uint32_t x) -> uint32_t { return x + 1; }),
                      8};
        break;
      }
      case Opcode::AArch64_CSINCXr: {  // csinc xd, xn, xm, cc
        results[0] = conditionalHelp::cs_4ops<uint64_t>(
            operands, metadata, [](uint64_t x) -> uint64_t { return x + 1; });
        break;
      }
      case Opcode::AArch64_CSINVWr: {  // csinv wd, wn, wm, cc
        results[0] = {
            conditionalHelp::cs_4ops<uint32_t>(
                operands, metadata, [](uint32_t x) -> uint32_t { return ~x; }),
            8};
        break;
      }
      case Opcode::AArch64_CSINVXr: {  // csinv xd, xn, xm, cc
        results[0] = conditionalHelp::cs_4ops<uint64_t>(
            operands, metadata, [](uint64_t x) -> uint64_t { return ~x; });
        break;
      }
      case Opcode::AArch64_CSNEGWr: {  // csneg wd, wn, wm, cc
        results[0] = {
            conditionalHelp::cs_4ops<int32_t>(
                operands, metadata, [](int32_t x) -> int32_t { return -x; }),
            8};
        break;
      }
      case Opcode::AArch64_CSNEGXr: {  // csneg xd, xn, xm, cc
        results[0] = conditionalHelp::cs_4ops<uint64_t>(
            operands, metadata, [](uint64_t x) -> uint64_t { return -x; });
        break;
      }
      case Opcode::AArch64_DECB_XPiI: {  // decb xdn{, pattern{, MUL #imm}}
        results[0] =
            sveHelp::sveDec_scalar<int8_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_DECD_XPiI: {  // decd xdn{, pattern{, MUL #imm}}
        results[0] =
            sveHelp::sveDec_scalar<int64_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_DMB: {  // dmb option|#imm
        // TODO: Respect memory barriers
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
      case Opcode::AArch64_DUP_ZR_B: {  // dup zd.b, wn
        results[0] = sveHelp::sveDup_immOrScalar<int8_t>(operands, metadata,
                                                         VL_bits, false);
        break;
      }
      case Opcode::AArch64_DUP_ZR_D: {  // dup zd.d, xn
        results[0] = sveHelp::sveDup_immOrScalar<int64_t>(operands, metadata,
                                                          VL_bits, false);
        break;
      }
      case Opcode::AArch64_DUP_ZR_H: {  // dup zd.h, wn
        results[0] = sveHelp::sveDup_immOrScalar<int16_t>(operands, metadata,
                                                          VL_bits, false);
        break;
      }
      case Opcode::AArch64_DUP_ZR_S: {  // dup zd.s, wn
        results[0] = sveHelp::sveDup_immOrScalar<int32_t>(operands, metadata,
                                                          VL_bits, false);
        break;
      }
      case Opcode::AArch64_DUP_ZZI_D: {  // dup zd.d, zn.d[#imm]
        results[0] =
            sveHelp::sveDup_vecIndexed<uint64_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_DUP_ZZI_Q: {  // dup zd.q, zn.q[#imm]
        // No data-type for quadwords, but as data is just being moved around we
        // can use uint64_t.
        const uint16_t index =
            2 * static_cast<uint16_t>(metadata.operands[1].vector_index);
        const uint64_t* n = operands[0].getAsVector<uint64_t>();

        const uint16_t partition_num = VL_bits / 128;
        uint64_t out[32] = {0};

        if (index < partition_num) {
          const uint64_t elementHi = n[index];
          const uint64_t elementLo = n[index + 1];
          for (int i = 0; i < partition_num; i++) {
            out[2 * i] = elementHi;      // Copy over top half of quadword
            out[2 * i + 1] = elementLo;  // Copy over lower half of quadword
          }
        }
        results[0] = out;
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
      case Opcode::AArch64_DUPv8i16gpr: {  // dup vd.8h, wn
        results[0] =
            neonHelp::vecDup_gprOrIndex<uint16_t, 8>(operands, metadata, true);
        break;
      }
      case Opcode::AArch64_EORWri: {  // eor wd, wn, #imm
        auto [result, nzcv] = logicalHelp::logicOp_imm<uint32_t>(
            operands, metadata, false,
            [](uint32_t x, uint32_t y) -> uint32_t { return x ^ y; });
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_EORWrs: {  // eor wd, wn, wm{, shift #imm}
        auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint32_t>(
            operands, metadata, false,
            [](uint32_t x, uint32_t y) -> uint32_t { return x ^ y; });
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_EORXri: {  // eor xd, xn, #imm
        auto [result, nzcv] = logicalHelp::logicOp_imm<uint64_t>(
            operands, metadata, false,
            [](uint64_t x, uint64_t y) -> uint64_t { return x ^ y; });
        results[0] = result;
        break;
      }
      case Opcode::AArch64_EORXrs: {  // eor xd, xn, xm{, shift #amount}
        auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint64_t>(
            operands, metadata, false,
            [](uint64_t x, uint64_t y) -> uint64_t { return x ^ y; });
        results[0] = result;
        break;
      }
      case Opcode::AArch64_EOR_PPzPP: {
        results[0] = sveHelp::sveLogicOp_preds<uint8_t>(
            operands, VL_bits,
            [](uint64_t x, uint64_t y) -> uint64_t { return x ^ y; });
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
      case Opcode::AArch64_EXTRWrri: {  // extr wd, wn, wm, #lsb
        results[0] = {
            bitmanipHelp::extrLSB_registers<uint32_t>(operands, metadata), 8};
        break;
      }
      case Opcode::AArch64_EXTRXrri: {  // extr xd, xn, xm, #lsb
        results[0] =
            bitmanipHelp::extrLSB_registers<uint64_t>(operands, metadata);
        break;
      }
      case Opcode::AArch64_EXTv16i8: {  // ext vd.16b, vn.16b, vm.16b, #index
        results[0] =
            neonHelp::vecExtVecs_index<uint8_t, 16>(operands, metadata);
        break;
      }
      case Opcode::AArch64_EXTv8i8: {  // ext vd.8b, vn.8b, vm.8b, #index
        results[0] = neonHelp::vecExtVecs_index<uint8_t, 8>(operands, metadata);
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
      case Opcode::AArch64_FABSDr: {  // fabs dd, dn
        results[0] = floatHelp::fabs_2ops<double>(operands);
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
      case Opcode::AArch64_FABS_ZPmZ_S: {  // fabs zd.s, pg/m, zn.s
        results[0] = sveHelp::sveFabsPredicated<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FABSv2f64: {  // fabs vd.2d, vn.2d
        results[0] = neonHelp::vecFabs_2ops<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FABSv4f32: {  // fabs vd.4s, vn.4s
        results[0] = neonHelp::vecFabs_2ops<float, 4>(operands);
        break;
      }
      case Opcode::AArch64_FADDA_VPZ_D: {  // fadda dd, pg/m, dn, zm.d
        results[0] = sveHelp::sveFaddaPredicated<double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FADDA_VPZ_S: {  // fadda sd, pg/m, sn, zm.s
        results[0] = sveHelp::sveFaddaPredicated<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FADDDrr: {  // fadd dd, dn, dm
        results[0] = {arithmeticHelp::add_3ops<double>(operands), 256};
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
      case Opcode::AArch64_FADDPv2i32p: {  // faddp dd, vn.2s
        results[0] = neonHelp::vecSumElems_2ops<float, 2>(operands);
        break;
      }
      case Opcode::AArch64_FADDPv2i64p: {  // faddp dd, vn.2d
        results[0] = neonHelp::vecSumElems_2ops<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FADDPv4f32: {  // faddp vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecAddp_3ops<float, 4>(operands);
        break;
      }
      case Opcode::AArch64_FADDSrr: {  // fadd sd, sn, sm
        results[0] = {arithmeticHelp::add_3ops<float>(operands), 256};
        break;
      }
      case Opcode::AArch64_FADD_ZPmI_D: {  // fadd zdn.d, pg/m, zdn.d, const
        results[0] = sveHelp::sveAddPredicated_const<double>(operands, metadata,
                                                             VL_bits);
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
      case Opcode::AArch64_FADD_ZPmZ_S: {  // fadd zdn.s, pg/m, zdn.s, zm.s
        results[0] = sveHelp::sveAddPredicated_vecs<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FADD_ZZZ_D: {  // fadd zd.d, zn.d, zm.d
        results[0] = sveHelp::sveAdd_3ops<double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FADD_ZZZ_S: {  // fadd zd.s, zn.s, zm.s
        results[0] = sveHelp::sveAdd_3ops<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FADDv2f32: {  // fadd vd.2s, vn.2s, vm.2s
        results[0] = neonHelp::vecAdd_3ops<float, 2>(operands);
        break;
      }
      case Opcode::AArch64_FADDv2f64: {  // fadd vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecAdd_3ops<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FADDv4f32: {  // fadd vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecAdd_3ops<float, 4>(operands);
        break;
      }
      case Opcode::AArch64_FCADD_ZPmZ_D: {  // fcadd zdn.d, pg/m, zdn.d, zm.d,
                                            // #imm
        results[0] =
            sveHelp::sveFcaddPredicated<double>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_FCCMPDrr:     // fccmp sn, sm, #nzcv, cc
      case Opcode::AArch64_FCCMPEDrr: {  // fccmpe sn, sm, #nzcv, cc
        results[0] = floatHelp::fccmp<double>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FCCMPESrr: {  // fccmpe sn, sm, #nzcv, cc
        results[0] = floatHelp::fccmp<float>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FCCMPSrr: {  // fccmp sn, sm, #nzcv, cc
        results[0] = floatHelp::fccmp<float>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FCMEQv2i32rz: {  // fcmeq vd.2s, vd.2s, #0.0
        results[0] = neonHelp::vecFCompare<float, uint32_t, 2>(
            operands, true, [](float x, float y) -> bool { return x == y; });
        break;
      }
      case Opcode::AArch64_FCMEQv4i32rz: {  // fcmeq vd.4s vn.4s, #0.0
        results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
            operands, true, [](float x, float y) -> bool { return x == y; });
        break;
      }
      case Opcode::AArch64_FCMGE_PPzZ0_D: {  // fcmge pd.d, pg/z, zn.d, #0.0
        results[0] = sveHelp::sveComparePredicated_vecsToPred<double>(
            operands, metadata, VL_bits, true,
            [](double x, double y) -> bool { return x >= y; });
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
      case Opcode::AArch64_FCMGE_PPzZZ_S: {  // fcmge pd.s, pg/z, zn.s, zm.s
        results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
            operands, metadata, VL_bits, false,
            [](float x, float y) -> bool { return x >= y; });
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
      case Opcode::AArch64_FCMGEv2i64rz: {  // fcmge vd.2d, vn.2d, 0.0
        results[0] = neonHelp::vecFCompare<double, uint64_t, 2>(
            operands, true, [](double x, double y) -> bool { return x >= y; });
        break;
      }
      case Opcode::AArch64_FCMGEv4f32: {  // fcmge vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
            operands, false, [](float x, float y) -> bool { return x >= y; });
        break;
      }
      case Opcode::AArch64_FCMGEv4i32rz: {  // fcmge vd.4s, vn.4s, 0.0
        results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
            operands, true, [](float x, float y) -> bool { return x >= y; });
        break;
      }
      case Opcode::AArch64_FCMGT_PPzZ0_D: {  // fcmgt pd.d, pg/z, zn.d, #0.0
        results[0] = sveHelp::sveComparePredicated_vecsToPred<double>(
            operands, metadata, VL_bits, true,
            [](double x, double y) -> bool { return x > y; });
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
      case Opcode::AArch64_FCMGT_PPzZZ_S: {  // fcmgt pd.s, pg/z, zn.s, zm.
        results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
            operands, metadata, VL_bits, false,
            [](float x, float y) -> bool { return x > y; });
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
      case Opcode::AArch64_FCMGTv4f32: {  // fcmgt vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
            operands, false, [](float x, float y) -> bool { return x > y; });
        break;
      }
      case Opcode::AArch64_FCMGTv4i32rz: {  // fcmgt vd.4s, vn.4s, #0.0
        results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
            operands, true, [](float x, float y) -> bool { return x > y; });
        break;
      }
      case Opcode::AArch64_FCMLA_ZPmZZ_D: {  // fcmla zda, pg/m, zn, zm, #imm
        results[0] =
            sveHelp::sveFcmlaPredicated<double>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_FCMLE_PPzZ0_D: {  // fcmle pd.d, pg/z, zn.d, #0.0
        results[0] = sveHelp::sveComparePredicated_vecsToPred<double>(
            operands, metadata, VL_bits, true,
            [](double x, double y) -> bool { return x <= y; });
        break;
      }
      case Opcode::AArch64_FCMLE_PPzZ0_S: {  // fcmle pd.s, pg/z, zn.s, #0.0
        results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
            operands, metadata, VL_bits, true,
            [](float x, float y) -> bool { return x <= y; });
        break;
      }
      case Opcode::AArch64_FCMLT_PPzZ0_S: {  // fcmlt pd.s, pg/z, zn.s, #0.0
        results[0] = sveHelp::sveComparePredicated_vecsToPred<float>(
            operands, metadata, VL_bits, true,
            [](float x, float y) -> bool { return x < y; });
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
      case Opcode::AArch64_FCMLTv4i32rz: {  // fcmlt vd.4s, vn.4s, #0.0
        results[0] = neonHelp::vecFCompare<float, uint32_t, 4>(
            operands, true, [](float x, float y) -> bool { return x < y; });
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
      case Opcode::AArch64_FCMPESri: {  // fcmpe sn, #imm
        results[0] = floatHelp::fcmp<float>(operands, true);
        break;
      }
      case Opcode::AArch64_FCMPESrr: {  // fcmpe sn, sm
        results[0] = floatHelp::fcmp<float>(operands, false);
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
      case Opcode::AArch64_FCPY_ZPmI_D: {  // fcpy zd.d, pg/m, #const
        results[0] = sveHelp::sveFcpy_imm<double>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_FCPY_ZPmI_S: {  // fcpy zd.s, pg/m, #const
        results[0] = sveHelp::sveFcpy_imm<float>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_FCSELDrrr: {  // fcsel dd, dn, dm, cond
        results[0] = {
            conditionalHelp::cs_4ops<double>(
                operands, metadata, [](double x) -> double { return x; }),
            256};
        break;
      }
      case Opcode::AArch64_FCSELSrrr: {  // fcsel sd, sn, sm, cond
        results[0] = {
            conditionalHelp::cs_4ops<float>(operands, metadata,
                                            [](float x) -> float { return x; }),
            256};
        break;
      }
      case Opcode::AArch64_FCVTASUWDr: {  // fcvtas wd, dn
        results[0] = {static_cast<int32_t>(round(operands[0].get<double>())),
                      8};
        break;
      }
      case Opcode::AArch64_FCVTASUXDr: {  // fcvtas xd, dn
        results[0] = static_cast<int64_t>(round(operands[0].get<double>()));
        break;
      }
      case Opcode::AArch64_FCVTDSr: {  // fcvt dd, sn
        // TODO: Handle NaNs, denorms, and saturation?
        results[0] = neonHelp::vecFcvtl<double, float, 1>(operands, false);
        break;
      }
      case Opcode::AArch64_FCVTLv2i32: {  // fcvtl vd.2d, vn.2s
        results[0] = neonHelp::vecFcvtl<double, float, 2>(operands, false);
        break;
      }
      case Opcode::AArch64_FCVTLv4i32: {  // fcvtl2 vd.2d, vn.4s
        results[0] = neonHelp::vecFcvtl<double, float, 2>(operands, true);
        break;
      }
      case Opcode::AArch64_FCVTNv2i32: {  // fcvtn vd.2s, vn.2d
        results[0] = neonHelp::vecFcvtn<float, double, 2>(operands, false);
        break;
      }
      case Opcode::AArch64_FCVTNv4i32: {  // fcvtn2 vd.4s, vn.2d
        results[0] = neonHelp::vecFcvtn<float, double, 4>(operands, true);
        break;
      }
      case Opcode::AArch64_FCVTSDr: {  // fcvt sd, dn
        // TODO: Handle NaNs, denorms, and saturation?
        results[0] = neonHelp::vecFcvtl<float, double, 1>(operands, false);
        break;
      }
      case Opcode::AArch64_FCVTZSUWDr: {  // fcvtzs wd, dn
        // TODO: Handle NaNs, denorms, and saturation
        results[0] = {
            static_cast<int32_t>(std::trunc(operands[0].get<double>())), 8};
        break;
      }
      case Opcode::AArch64_FCVTZSUWSr: {  // fcvtzs wd, sn
        // TODO: Handle NaNs, denorms, and saturation
        results[0] = {
            static_cast<int32_t>(std::trunc(operands[0].get<float>())), 8};
        break;
      }
      case Opcode::AArch64_FCVTZSUXDr: {
        // TODO: Handle NaNs, denorms, and saturation
        results[0] = {
            static_cast<int64_t>(std::trunc(operands[0].get<double>())), 8};
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
      case Opcode::AArch64_FCVTZSv2f64: {  // fcvtzs vd.2d, vn.2d
        results[0] = neonHelp::vecFcvtzs<int64_t, double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FCVTZUUWDr: {  // fcvtzu wd, dn
        // TODO: Handle NaNs, denorms, and saturation
        results[0] = {
            static_cast<int32_t>(std::trunc(operands[0].get<double>())), 8};
        break;
      }
      case Opcode::AArch64_FCVTZUUWSr: {  // fcvtzu wd, sn
        // TODO: Handle NaNs, denorms, and saturation
        results[0] = {
            static_cast<int32_t>(std::trunc(operands[0].get<float>())), 8};
        break;
      }
      case Opcode::AArch64_FCVTZUUXDr: {  // fcvtzu xd, dn
        // TODO: Handle NaNs, denorms, and saturation
        results[0] =
            static_cast<int64_t>(std::trunc(operands[0].get<double>()));
        break;
      }
      case Opcode::AArch64_FCVTZUUXSr: {  // fcvtzu xd, sn
        // TODO: Handle NaNs, denorms, and saturation
        results[0] = static_cast<int64_t>(std::trunc(operands[0].get<float>()));
        break;
      }
      case Opcode::AArch64_FCVT_ZPmZ_DtoS: {  // fcvt zd.s, pg/m, zn.d
        results[0] =
            sveHelp::sveFcvtPredicated<float, double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FCVT_ZPmZ_StoD: {  // fcvt zd.d, pg/m, zn.s
        results[0] =
            sveHelp::sveFcvtPredicated<double, float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FDIVDrr: {  // fdiv dd, dn, dm
        results[0] = {divideHelp::div_3ops<double>(operands), 256};
        break;
      }
      case Opcode::AArch64_FDIVR_ZPmZ_D: {  // fdivr zdn.d, pg/m, zdn.d, zm.d
        results[0] = sveHelp::sveLogicOpPredicated_3vecs<double>(
            operands, VL_bits,
            [](double x, double y) -> double { return (y / x); });
        break;
      }
      case Opcode::AArch64_FDIVR_ZPmZ_S: {  // fdivr zdn.s, pg/m, zdn.s, zm.s
        results[0] = sveHelp::sveLogicOpPredicated_3vecs<float>(
            operands, VL_bits,
            [](float x, float y) -> float { return (y / x); });
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
      case Opcode::AArch64_FDIVv2f64: {  // fdiv vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecLogicOp_3vecs<double, 2>(
            operands, [](double x, double y) -> double { return x / y; });
        break;
      }
      case Opcode::AArch64_FDUP_ZI_D: {  // fdup zd.d, #imm
        results[0] = sveHelp::sveDup_immOrScalar<double>(operands, metadata,
                                                         VL_bits, true);
        break;
      }
      case Opcode::AArch64_FDUP_ZI_S: {  // fdup zd.s, #imm
        results[0] = sveHelp::sveDup_immOrScalar<float>(operands, metadata,
                                                        VL_bits, true);
        break;
      }
      case Opcode::AArch64_FMADDDrrr: {  // fmadd dn, dm, da
        results[0] = {multiplyHelp::madd_4ops<double>(operands), 256};
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
      case Opcode::AArch64_FMAD_ZPmZZ_S: {  // fmad zd.s, pg/m, zn.s, zm.s
        results[0] = sveHelp::sveFmadPredicated_vecs<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FMAXNMDrr: {  // fmaxnm dd, dn, dm
        results[0] = floatHelp::fmaxnm_3ops<double>(operands);
        break;
      }
      case Opcode::AArch64_FMAXNMPv2i64p: {  // fmaxnmp dd, vd.2d
        results[0] = neonHelp::vecMaxnmp_2ops<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FMAXNMSrr: {  // fmaxnm sd, sn, sm
        results[0] = floatHelp::fmaxnm_3ops<float>(operands);
        break;
      }
      case Opcode::AArch64_FMAXNMv2f64: {  // fmaxnm vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecLogicOp_3vecs<double, 2>(
            operands,
            [](double x, double y) -> double { return std::fmax(x, y); });
        break;
      }
      case Opcode::AArch64_FMINNMDrr: {  // fminnm dd, dn, dm
        results[0] = floatHelp::fminnm_3ops<double>(operands);
        break;
      }
      case Opcode::AArch64_FMINNMPv2i64p: {  // fminnmp dd, vd.2d
        results[0] = neonHelp::vecMinv_2ops<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FMINNMSrr: {  // fminnm sd, sn, sm
        results[0] = floatHelp::fminnm_3ops<float>(operands);
        break;
      }
      case Opcode::AArch64_FMINNMv2f64: {  // fminnm vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecLogicOp_3vecs<double, 2>(
            operands,
            [](double x, double y) -> double { return std::fmin(x, y); });
        break;
      }
      case Opcode::AArch64_FMLA_ZPmZZ_D: {  // fmla zd.d, pg/m, zn.d, zm.d
        results[0] = sveHelp::sveMlaPredicated_vecs<double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FMLA_ZPmZZ_S: {  // fmla zd.s, pg/m, zn.s, zm.s
        results[0] = sveHelp::sveMlaPredicated_vecs<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FMLAv2f32: {  // fmla vd.2s, vn.2s, vm.2s
        results[0] = neonHelp::vecFmla_3vecs<float, 2>(operands);
        break;
      }
      case Opcode::AArch64_FMLA_ZZZI_D: {  // fmla zda.d, zn.d, zm.d[index]
        results[0] =
            sveHelp::sveMlaIndexed_vecs<double>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_FMLA_ZZZI_S: {  // fmla zda.s, zn.s, zm.s[index]
        results[0] =
            sveHelp::sveMlaIndexed_vecs<float>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_FMLAv2f64: {  // fmla vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecFmla_3vecs<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FMLAv2i32_indexed: {  // fmla vd.2s, vn.2s,
                                                 // vm.2s[index]
        results[0] =
            neonHelp::vecFmlaIndexed_3vecs<float, 2>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FMLAv2i64_indexed: {  // fmla vd.2d, vn.2d,
                                                 // vm.d[index]
        results[0] =
            neonHelp::vecFmlaIndexed_3vecs<double, 2>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FMLAv4f32: {  // fmla vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecFmla_3vecs<float, 4>(operands);
        break;
      }
      case Opcode::AArch64_FMLAv4i32_indexed: {  // fmla vd.4s, vn.4s,
                                                 // vm.s[index]
        results[0] =
            neonHelp::vecFmlaIndexed_3vecs<float, 4>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FMLS_ZPmZZ_D: {  // fmls zd.d, pg/m, zn.d, zm.d
        results[0] = sveHelp::sveFmlsPredicated_vecs<double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FMLS_ZPmZZ_S: {  // fmls zd.s, pg/m, zn.s, zm.s
        results[0] = sveHelp::sveFmlsPredicated_vecs<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FMLSv2f64: {  // fmls vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecFmls_3vecs<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FMLSv2i64_indexed: {
        results[0] =
            neonHelp::vecFmlsIndexed_3vecs<double, 2>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FMLSv4f32: {  // fmls vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecFmls_3vecs<float, 4>(operands);
        break;
      }
      case Opcode::AArch64_FMLSv4i32_indexed: {  // fmls vd.4s, vn.4s,
                                                 // vm.s[index]
        results[0] =
            neonHelp::vecFmlsIndexed_3vecs<float, 4>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FMOPA_MPPZZ_S: {  // fmopa zada.s, pn/m, pm/m, zn.s,
                                             // zm.s
        // SME
        // Check core is in correct context mode (check SM first)
        if (!SMenabled) return SMdisabled();
        if (!ZAenabled) return ZAdisabled();

        const uint16_t rowCount = VL_bits / 32;
        const uint64_t* pn = operands[rowCount].getAsVector<uint64_t>();
        const uint64_t* pm = operands[rowCount + 1].getAsVector<uint64_t>();
        const float* zn = operands[rowCount + 2].getAsVector<float>();
        const float* zm = operands[rowCount + 3].getAsVector<float>();

        // zn is row, zm is col
        for (int row = 0; row < rowCount; row++) {
          float outRow[64] = {0};
          uint64_t shifted_active_row = 1ull << ((row % 16) * 4);
          const float* zadaRow = operands[row].getAsVector<float>();
          for (int col = 0; col < rowCount; col++) {
            float zadaElem = zadaRow[col];
            uint64_t shifted_active_col = 1ull << ((col % 16) * 4);
            if ((pm[col / 16] & shifted_active_col) &&
                (pn[row / 16] & shifted_active_row))
              outRow[col] = zadaElem + (zn[row] * zm[col]);
            else
              outRow[col] = zadaElem;
          }
          results[row] = {outRow, 256};
        }
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
        results[0] = {metadata.operands[1].fp, 256};
        break;
      }
      case Opcode::AArch64_FMOVDr: {  // fmov dd, dn
        results[0] = {operands[0].get<double>(), 256};
        break;
      }
      case Opcode::AArch64_FMOVSWr: {  // fmov wd, sn
        results[0] = {operands[0].get<float>(), 8};
        break;
      }
      case Opcode::AArch64_FMOVSi: {  // fmov sn, #imm
        results[0] = {static_cast<float>(metadata.operands[1].fp), 256};
        break;
      }
      case Opcode::AArch64_FMOVSr: {  // fmov sd, sn
        results[0] = {operands[0].get<float>(), 256};
        break;
      }
      case Opcode::AArch64_FMOVWSr: {  // fmov sd, wn
        results[0] = {operands[0].get<float>(), 256};
        break;
      }
      case Opcode::AArch64_FMOVXDHighr: {  // fmov vd.d[1], xn
        double out[2] = {operands[0].get<double>(), operands[1].get<double>()};
        results[0] = {out, 256};
        break;
      }
      case Opcode::AArch64_FMOVXDr: {  // fmov dd, xn
        results[0] = {operands[0].get<double>(), 256};
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
      case Opcode::AArch64_FMOVv4f32_ns: {  // fmov vd.4s, #imm
        results[0] = neonHelp::vecMovi_imm<float, 4>(metadata);
        break;
      }
      case Opcode::AArch64_FMSB_ZPmZZ_D: {  // fmsb zd.d, pg/m, zn.d, zm.d
        results[0] = sveHelp::sveFmsbPredicated_vecs<double>(operands, VL_bits);
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
      case Opcode::AArch64_FMSUBSrrr: {  // fmsub sn, sm, sa
        results[0] = {multiplyHelp::msub_4ops<float>(operands), 256};
        break;
      }
      case Opcode::AArch64_FMULDrr: {  // fmul dd, dn, dm
        results[0] = {multiplyHelp::mul_3ops<double>(operands), 256};
        break;
      }
      case Opcode::AArch64_FMULSrr: {  // fmul sd, sn, sm
        results[0] = {multiplyHelp::mul_3ops<float>(operands), 256};
        break;
      }
      case Opcode::AArch64_FMUL_ZPmI_D: {  // fmul zd.d, pg/m, zn.d, #imm
        results[0] = sveHelp::sveMulPredicated<double>(operands, metadata,
                                                       VL_bits, true);
        break;
      }
      case Opcode::AArch64_FMUL_ZPmI_S: {  // fmul zd.s, pg/m, zn.s, #imm
        results[0] =
            sveHelp::sveMulPredicated<float>(operands, metadata, VL_bits, true);
        break;
      }
      case Opcode::AArch64_FMUL_ZPmZ_D: {  // fmul zdn.d, pg/m, zdn.d, zm.d
        results[0] = sveHelp::sveMulPredicated<double>(operands, metadata,
                                                       VL_bits, false);
        break;
      }
      case Opcode::AArch64_FMUL_ZPmZ_S: {  // fmul zdn.s, pg/m, zdn.s, zm.s
        results[0] = sveHelp::sveMulPredicated<float>(operands, metadata,
                                                      VL_bits, false);
        break;
      }
      case Opcode::AArch64_FMUL_ZZZ_D: {  // fmul zd.d, zn.d, zm.d
        results[0] = sveHelp::sveFmul_3ops<double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FMUL_ZZZ_S: {  // fmul zd.s, zn.s, zm.s
        results[0] = sveHelp::sveFmul_3ops<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FMULv1i32_indexed: {  // fmul sd, sn, vm.s[index]
        results[0] =
            neonHelp::vecFmulIndexed_vecs<float, 1>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FMULv1i64_indexed: {  // fmul dd, dn, vm.d[index]
        results[0] =
            neonHelp::vecFmulIndexed_vecs<double, 1>(operands, metadata);
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
      case Opcode::AArch64_FMULv2i32_indexed: {  // fmul vd.2s, vn.2s,
                                                 // vm.s[index]
        results[0] =
            neonHelp::vecFmulIndexed_vecs<float, 2>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FMULv2i64_indexed: {  // fmul vd.2d, vn.2d,
                                                 // vm.d[index]
        results[0] =
            neonHelp::vecFmulIndexed_vecs<double, 2>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FMULv4f32: {  // fmul vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecLogicOp_3vecs<float, 4>(
            operands, [](float x, float y) -> float { return x * y; });
        break;
      }
      case Opcode::AArch64_FMULv4i32_indexed: {  // fmul vd.4s, vn.4s,
                                                 // vm.s[index]
        results[0] =
            neonHelp::vecFmulIndexed_vecs<float, 4>(operands, metadata);
        break;
      }
      case Opcode::AArch64_FNEGDr: {  // fneg dd, dn
        results[0] = {-operands[0].get<double>(), 256};
        break;
      }
      case Opcode::AArch64_FNEGSr: {  // fneg sd, sn
        results[0] = {-operands[0].get<float>(), 256};
        break;
      }
      case Opcode::AArch64_FNEG_ZPmZ_D: {  // fneg zd.d, pg/m, zn.d
        results[0] = sveHelp::sveFnegPredicated<double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FNEG_ZPmZ_S: {  // fneg zd.s, pg/m, zn.s
        results[0] = sveHelp::sveFnegPredicated<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FNEGv2f64: {  // fneg vd.2d, vn.2d
        results[0] = neonHelp::vecFneg_2ops<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FNEGv4f32: {  // fneg vd.4s, vn.4s
        results[0] = neonHelp::vecFneg_2ops<float, 4>(operands);
        break;
      }
      case Opcode::AArch64_FNMADDDrrr: {  // fnmadd dd, dn, dm, da
        results[0] = floatHelp::fnmadd_4ops<double>(operands);
        break;
      }
      case Opcode::AArch64_FNMADDSrrr: {  // fnmadd sd, sn, sm, sa
        results[0] = floatHelp::fnmadd_4ops<float>(operands);
        break;
      }
      case Opcode::AArch64_FNMLS_ZPmZZ_D: {  // fnmls zd.d, pg/m, zn.d, zm.d
        results[0] = sveHelp::sveFnmlsPredicated<double>(operands, VL_bits);
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
      case Opcode::AArch64_FNMSB_ZPmZZ_S: {  // fnmsb zdn.s, pg/m, zm.s, za.s
        results[0] = sveHelp::sveFnmsbPredicated<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FNMSUBDrrr: {  // fnmsub dd, dn, dm, da
        results[0] = floatHelp::fnmsub_4ops<double>(operands);
        break;
      }
      case Opcode::AArch64_FNMSUBSrrr: {  // fnmsub sd, sn, sm, sa
        results[0] = floatHelp::fnmsub_4ops<float>(operands);
        break;
      }
      case Opcode::AArch64_FNMULDrr: {  // fnmul dd, dn, dm
        results[0] = neonHelp::vecLogicOp_3vecs<double, 1>(
            operands, [](double x, double y) -> double { return -(x * y); });
        break;
      }
      case Opcode::AArch64_FNMULSrr: {  // fnmul sd, sn, sm
        results[0] = neonHelp::vecLogicOp_3vecs<float, 1>(
            operands, [](float x, float y) -> float { return -(x * y); });
        break;
      }
      case Opcode::AArch64_FRINTADr: {  // frinta dd, dn
        results[0] = {round(operands[0].get<double>()), 256};
        break;
      }
      case Opcode::AArch64_FRINTN_ZPmZ_D: {  // frintn zd.d, pg/m, zn.d
        results[0] =
            sveHelp::sveFrintnPredicated<int64_t, double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FRINTN_ZPmZ_S: {  // frintn zd.s, pg/m, zn.s
        results[0] =
            sveHelp::sveFrintnPredicated<int32_t, float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FRINTPDr: {  // frintp dd, dn
        results[0] = floatHelp::frintpScalar_2ops<double>(operands);
        break;
      }
      case Opcode::AArch64_FRINTPSr: {  // frintp sd, sn
        results[0] = floatHelp::frintpScalar_2ops<float>(operands);
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
      case Opcode::AArch64_FRSQRTEv4f32: {  // frsqrte vd.4s, vn.4s
        results[0] = neonHelp::vecFrsqrte_2ops<float, 4>(operands);
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
      case Opcode::AArch64_FRSQRTSv2f32: {  // frsqrts vd.2s, vn.2s, vn.2s
        results[0] = neonHelp::vecFrsqrts_3ops<float, 2>(operands);
        break;
      }
      case Opcode::AArch64_FRSQRTSv2f64: {  // frsqrts vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecFrsqrts_3ops<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FRSQRTSv4f32: {  // frsqrts vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecFrsqrts_3ops<float, 4>(operands);
        break;
      }
      case Opcode::AArch64_FSQRTDr: {  // fsqrt dd, dn
        results[0] = {::sqrt(operands[0].get<double>()), 256};
        break;
      }
      case Opcode::AArch64_FSQRTSr: {  // fsqrt sd, sn
        results[0] = {::sqrtf(operands[0].get<float>()), 256};
        break;
      }
      case Opcode::AArch64_FSQRT_ZPmZ_D: {  // fsqrt zd.d, pg/m, zn.d
        results[0] =
            sveHelp::sveFsqrtPredicated_2vecs<double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FSQRT_ZPmZ_S: {  // fsqrt zd.s, pg/m, zn.s
        results[0] =
            sveHelp::sveFsqrtPredicated_2vecs<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FSQRTv2f64: {  // fsqrt vd.2d, vn.2d
        results[0] = neonHelp::vecFsqrt_2ops<double, 2>(operands);
        break;
      }
      case Opcode::AArch64_FSQRTv4f32: {  // fsqrt vd.4s, vn.4s
        results[0] = neonHelp::vecFsqrt_2ops<float, 4>(operands);
        break;
      }
      case Opcode::AArch64_FSUBDrr: {  // fsub dd, dn, dm
        results[0] = neonHelp::vecLogicOp_3vecs<double, 1>(
            operands, [](double x, double y) -> double { return x - y; });
        break;
      }
      case Opcode::AArch64_FSUBR_ZPmZ_D: {  // fsubr zdn.d, pg/m, zdn.d, zm.d
        results[0] =
            sveHelp::sveSubrPredicated_3vecs<double>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FSUBR_ZPmZ_S: {  // fsubr zdn.s, pg/m, zdn.s, zm.s
        results[0] = sveHelp::sveSubrPredicated_3vecs<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FSUBSrr: {  // fsub ss, sn, sm
        results[0] = neonHelp::vecLogicOp_3vecs<float, 1>(
            operands, [](double x, double y) -> double { return x - y; });
        break;
      }
      case Opcode::AArch64_FSUB_ZPmI_D: {  // fsub zdn.d, pg/m, zdn.d, #imm
        results[0] =
            sveHelp::sveSubPredicated_imm<double>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_FSUB_ZPmI_S: {  // fsub zdn.s, pg/m, zdn.s, #imm
        results[0] =
            sveHelp::sveSubPredicated_imm<float>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_FSUB_ZPmZ_D: {  // fsub zdn.d, pg/m, zdn.d, zm.d
        results[0] = sveHelp::sveLogicOpPredicated_3vecs<double>(
            operands, VL_bits,
            [](double x, double y) -> double { return x - y; });
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
      case Opcode::AArch64_FSUB_ZZZ_S: {  // fsub zd.s, zn.s, zm.s
        results[0] = sveHelp::sveSub_3vecs<float>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_FSUBv2f32: {
        results[0] = neonHelp::vecLogicOp_3vecs<float, 2>(
            operands, [](float x, float y) -> float { return x - y; });
        break;
      }
      case Opcode::AArch64_FSUBv2f64: {  // fsub vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecLogicOp_3vecs<double, 2>(
            operands, [](double x, double y) -> double { return x - y; });
        break;
      }
      case Opcode::AArch64_FSUBv4f32: {  // fsub vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecLogicOp_3vecs<float, 4>(
            operands, [](float x, float y) -> float { return x - y; });
        break;
      }
      case Opcode::AArch64_GLD1D_IMM_REAL: {  // ld1d {zd.d}, pg/z, [zn.d{,
                                              // #imm}]
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
      case Opcode::AArch64_GLD1D_SCALED_REAL: {  // ld1d {zt.d}, pg/z, [xn,
                                                 // zm.d, LSL #3]
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
      case Opcode::AArch64_GLD1W_D_SCALED_REAL: {  // ld1w {zd.d}, pg/z,
                                                   // [<xn|sp>, zm.d, lsl #2]
        // LOAD
        const uint64_t* p = operands[0].getAsVector<uint64_t>();

        const uint16_t partition_num = VL_bits / 64;
        uint64_t out[32] = {0};
        uint16_t index = 0;
        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            out[i] = static_cast<uint64_t>(memoryData[index].get<uint32_t>());
            index++;
          }
        }
        results[0] = {out, 256};
        break;
      }
      case Opcode::AArch64_HINT: {  // nop|yield|wfe|wfi|etc...
        // TODO: Observe hints
        break;
      }
      case Opcode::AArch64_INCB_XPiI: {  // incb xdn{, pattern{, #imm}}
        results[0] =
            sveHelp::sveInc_gprImm<int8_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_INCD_XPiI: {  // incd xdn{, pattern{, #imm}}
        results[0] =
            sveHelp::sveInc_gprImm<int64_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_INCD_ZPiI: {  // incd zdn.d{, pattern{, #imm}}
        results[0] = sveHelp::sveInc_imm<int64_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_INCH_XPiI: {  // inch xdn{, pattern{, #imm}}
        results[0] =
            sveHelp::sveInc_gprImm<int16_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_INCH_ZPiI: {  // inch zdn.h{, pattern{, #imm}}
        results[0] = sveHelp::sveInc_imm<int16_t>(operands, metadata, VL_bits);
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
      case Opcode::AArch64_INCW_XPiI: {  // incw xdn{, pattern{, #imm}}
        results[0] =
            sveHelp::sveInc_gprImm<int32_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_INCW_ZPiI: {  // incw zdn.s{, pattern{, #imm}}
        results[0] = sveHelp::sveInc_imm<int32_t>(operands, metadata, VL_bits);
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
      case Opcode::AArch64_INSvi16gpr: {  // ins vd.h[index], wn
        results[0] = neonHelp::vecInsIndex_gpr<uint16_t, uint32_t, 8>(operands,
                                                                      metadata);
        break;
      }
      case Opcode::AArch64_INSvi32gpr: {  // ins vd.s[index], wn
        results[0] = neonHelp::vecInsIndex_gpr<uint32_t, uint32_t, 4>(operands,
                                                                      metadata);
        break;
      }
      case Opcode::AArch64_INSvi32lane: {  // ins vd.s[index1], vn.s[index2]
        results[0] = neonHelp::vecIns_2Index<uint32_t, 4>(operands, metadata);
        break;
      }
      case Opcode::AArch64_INSvi64gpr: {  // ins vd.d[index], xn
        results[0] = neonHelp::vecInsIndex_gpr<uint64_t, uint64_t, 2>(operands,
                                                                      metadata);
        break;
      }
      case Opcode::AArch64_INSvi64lane: {  // ins vd.d[index1], vn.d[index2]
        results[0] = neonHelp::vecIns_2Index<uint64_t, 2>(operands, metadata);
        break;
      }
      case Opcode::AArch64_INSvi8gpr: {  // ins vd.b[index], wn
        results[0] = neonHelp::vecInsIndex_gpr<uint8_t, uint32_t, 16>(operands,
                                                                      metadata);
        break;
      }
      case Opcode::AArch64_LD1_MXIPXX_H_S: {  // ld1w {zath.s[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, LSL #2}]
        // SME, LOAD
        if (!ZAenabled) {
          // Not in right context mode. Raise exception
          return ZAdisabled();
        }
        const uint16_t partition_num = VL_bits / 32;
        const uint32_t ws = operands[partition_num].get<uint32_t>();
        const uint64_t* pg =
            operands[partition_num + 1].getAsVector<uint64_t>();

        const uint32_t sliceNum =
            (ws + metadata.operands[0].sme_index.disp) % partition_num;
        uint16_t index = 0;
        uint32_t out[64] = {0};
        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (pg[i / 16] & shifted_active) {
            out[i] = memoryData[index].get<uint32_t>();
            index++;
          } else {
            out[i] = 0;
          }
        }

        // All Slice vectors are added to results[] so need to update the
        // correct one
        for (int i = 0; i < partition_num; i++) {
          if (i == sliceNum)
            results[i] = {out, 256};
          else
            // Maintain un-updated rows.
            results[i] = operands[i];
        }
        break;
      }
      case Opcode::AArch64_LD1_MXIPXX_V_S: {  // ld1w {zatv.s[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, LSL #2}]
        // SME, LOAD
        if (!ZAenabled) {
          // Not in right context mode. Raise exception
          return ZAdisabled();
        }
        const uint16_t partition_num = VL_bits / 32;
        const uint32_t ws = operands[partition_num].get<uint32_t>();
        const uint64_t* pg =
            operands[partition_num + 1].getAsVector<uint64_t>();

        const uint32_t sliceNum =
            (ws + metadata.operands[0].sme_index.disp) % partition_num;
        uint16_t index = 0;
        for (int i = 0; i < partition_num; i++) {
          uint32_t* row =
              const_cast<uint32_t*>(operands[i].getAsVector<uint32_t>());
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (pg[i / 16] & shifted_active) {
            row[sliceNum] = memoryData[index].get<uint32_t>();
            index++;
          } else {
            row[sliceNum] = 0;
          }
          results[i] = RegisterValue(reinterpret_cast<char*>(row), 256);
        }
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
      case Opcode::AArch64_LD1Onev16b: {  // ld1 {vt.16b} [xn]
        results[0] = memoryData[0].zeroExtend(memoryData[0].size(), 256);
        break;
      }
      case Opcode::AArch64_LD1Onev16b_POST: {  // ld1 {vt.16b}, [xn], #imm
        results[0] = memoryData[0].zeroExtend(memoryData[0].size(), 256);
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
      case Opcode::AArch64_LD1RQ_D_IMM: {  // ld1rqd {zd.d}, pg/z, [xn{, #imm}]
        // LOAD
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;
        uint64_t out[32] = {0};
        uint16_t index = 0;

        // Get mini-vector (quadword)
        uint64_t mini[2] = {0};
        for (int i = 0; i < 2; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            mini[i] = memoryData[index].get<uint64_t>();
            index++;
          }
        }

        // Duplicate mini-vector into output vector
        for (int i = 0; i < (partition_num / 2); i++) {
          out[2 * i] = mini[0];
          out[(2 * i) + 1] = mini[1];
        }
        results[0] = {out, 256};
        break;
      }
      case Opcode::AArch64_LD1RQ_W_IMM: {  // ld1rqw {zd.s}, pg/z, [xn{, #imm}]
        // LOAD
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 32;
        uint32_t out[64] = {0};
        uint16_t index = 0;

        // Get mini-vector (quadword)
        uint32_t mini[4] = {0};
        for (int i = 0; i < 4; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (p[i / 16] & shifted_active)
            mini[i] = memoryData[index].get<uint32_t>();
          index++;
        }

        // Duplicate mini-vector into output vector
        for (int i = 0; i < (partition_num / 4); i++) {
          out[4 * i] = mini[0];
          out[(4 * i) + 1] = mini[1];
          out[(4 * i) + 2] = mini[2];
          out[(4 * i) + 3] = mini[3];
        }
        results[0] = {out, 256};
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
            uint64_t shifted_active = p[index / 16] & 1ull
                                                          << ((index % 16) * 4);
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
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
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
      case Opcode::AArch64_LD2D:  // ld2d {zt1.d, zt2.d}, pg/z, [<xn|sp>, xm,
                                  // lsl #3]
      case Opcode::AArch64_LD2D_IMM: {  // ld2d {zt1.d, zt2.d}, pg/z, [<xn|sp>{,
                                        // #imm, mul vl}]
        // LOAD
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;
        uint16_t index = 0;
        uint64_t out1[32] = {0};
        uint64_t out2[32] = {0};

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            out1[i] = memoryData[index].get<uint64_t>();
            index++;
            out2[i] = memoryData[index].get<uint64_t>();
            index++;
          } else {
            out1[i] = 0;
            out2[i] = 0;
          }
        }
        results[0] = {out1, 256};
        results[1] = {out2, 256};
        break;
      }
      case Opcode::AArch64_LD2Twov4s: {  // ld2 {vt1.4s, vt2.4s} [xn]
        const float* region1 = memoryData[0].getAsVector<float>();
        const float* region2 = memoryData[1].getAsVector<float>();

        // LD2 multistruct uses de-interleaving
        float t1[4] = {region1[0], region1[2], region2[0], region2[2]};
        float t2[4] = {region1[1], region1[3], region2[1], region2[3]};
        results[0] = {t1, 256};
        results[1] = {t2, 256};
        break;
      }
      case Opcode::AArch64_LD2Twov4s_POST: {  // ld2 {vt1.4s, vt2.4s}, [xn],
                                              // #imm
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
      case Opcode::AArch64_LD3D_IMM: {  // ld3d {zt1.d, zt2.d, zt3.d}, pg/z,
                                        // [xn|sp{, #imm, MUL VL}]
        // LOAD
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;
        uint16_t index = 0;
        uint64_t out1[32] = {0};
        uint64_t out2[32] = {0};
        uint64_t out3[32] = {0};

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            out1[i] = memoryData[index].get<uint64_t>();
            index++;
            out2[i] = memoryData[index].get<uint64_t>();
            index++;
            out3[i] = memoryData[index].get<uint64_t>();
            index++;
          } else {
            out1[i] = 0;
            out2[i] = 0;
            out3[i] = 0;
          }
        }
        results[0] = {out1, 256};
        results[1] = {out2, 256};
        results[2] = {out3, 256};
        break;
      }
      case Opcode::AArch64_LD4D_IMM: {  // ld4d {zt1.d, zt2.d, zt3.d, zt4.d},
                                        // pg/z, [xn|sp{, #imm, MUL VL}]
        // LOAD
        const uint64_t* p = operands[0].getAsVector<uint64_t>();
        const uint16_t partition_num = VL_bits / 64;
        uint16_t index = 0;
        uint64_t out1[32] = {0};
        uint64_t out2[32] = {0};
        uint64_t out3[32] = {0};
        uint64_t out4[32] = {0};

        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            out1[i] = memoryData[index].get<uint64_t>();
            index++;
            out2[i] = memoryData[index].get<uint64_t>();
            index++;
            out3[i] = memoryData[index].get<uint64_t>();
            index++;
            out4[i] = memoryData[index].get<uint64_t>();
            index++;
          } else {
            out1[i] = 0;
            out2[i] = 0;
            out3[i] = 0;
            out4[i] = 0;
          }
        }

        results[0] = {out1, 256};
        results[1] = {out2, 256};
        results[2] = {out3, 256};
        results[3] = {out4, 256};
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
      case Opcode::AArch64_LDARB: {  // ldarb wt, [xn]
        // LOAD
        results[0] = memoryData[0].zeroExtend(1, 8);
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
      case Opcode::AArch64_LDNPSi: {  // ldnp st1, st2, [xn, #imm]
        // LOAD
        results[0] = memoryData[0].zeroExtend(4, 256);
        results[1] = memoryData[1].zeroExtend(4, 256);
        break;
      }
      case Opcode::AArch64_LDPDi:    // ldp dt1, dt2, [xn, #imm]
      case Opcode::AArch64_LDPQi:    // ldp qt1, qt2, [xn, #imm]
      case Opcode::AArch64_LDPSi:    // ldp st1, st2, [xn, #imm]
      case Opcode::AArch64_LDPWi:    // ldp wt1, wt2, [xn, #imm]
      case Opcode::AArch64_LDPXi: {  // ldp xt1, xt2, [xn, #imm]
        uint16_t regSize =
            (isScalarData_ || isVectorData_ || isSVEData_) ? 256 : 8;
        results[0] = memoryData[0].zeroExtend(dataSize_, regSize);
        results[1] = memoryData[1].zeroExtend(dataSize_, regSize);
        break;
      }
      case Opcode::AArch64_LDPDpost:    // ldp dt1, dt2, [xn], #imm
      case Opcode::AArch64_LDPQpost:    // ldp qt1, qt2, [xn], #imm
      case Opcode::AArch64_LDPSpost:    // ldp st1, st2, [xn], #imm
      case Opcode::AArch64_LDPWpost:    // ldp wt1, wt2, [xn], #imm
      case Opcode::AArch64_LDPXpost: {  // ldp xt1, xt2, [xn], #imm
        uint16_t regSize =
            (isScalarData_ || isVectorData_ || isSVEData_) ? 256 : 8;
        results[0] = memoryData[0].zeroExtend(dataSize_, regSize);
        results[1] = memoryData[1].zeroExtend(dataSize_, regSize);
        results[2] = operands[0].get<uint64_t>() + metadata.operands[3].imm;
        break;
      }
      case Opcode::AArch64_LDPDpre:    // ldp dt1, dt2, [xn, #imm]!
      case Opcode::AArch64_LDPQpre:    // ldp qt1, qt2, [xn, #imm]!
      case Opcode::AArch64_LDPSpre:    // ldp st1, st2, [xn, #imm]!
      case Opcode::AArch64_LDPWpre:    // ldp wt1, wt2, [xn, #imm]!
      case Opcode::AArch64_LDPXpre: {  // ldp xt1, xt2, [xn, #imm]!
        uint16_t regSize =
            (isScalarData_ || isVectorData_ || isSVEData_) ? 256 : 8;
        results[0] = memoryData[0].zeroExtend(dataSize_, regSize);
        results[1] = memoryData[1].zeroExtend(dataSize_, regSize);
        results[2] =
            operands[0].get<uint64_t>() + metadata.operands[2].mem.disp;
        break;
      }
      case Opcode::AArch64_LDPSWi: {  // ldpsw xt1, xt2, [xn {, #imm}]
        // LOAD
        results[0] = memoryData[0].zeroExtend(4, 8);
        results[1] = memoryData[1].zeroExtend(4, 8);
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
        results[1] =
            operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
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
      case Opcode::AArch64_LDRBui:    // ldr bt, [xn, #imm]
      case Opcode::AArch64_LDRDui:    // ldr dt, [xn, #imm]
      case Opcode::AArch64_LDRHui:    // ldr ht, [xn, #imm]
      case Opcode::AArch64_LDRQui:    // ldr qt, [xn, #imm]
      case Opcode::AArch64_LDRSui:    // ldr st, [xn, #imm]
      case Opcode::AArch64_LDRWui:    // ldr wt, [xn, #imm]
      case Opcode::AArch64_LDRXui: {  // ldr xt, [xn, #imm]
        uint16_t regSize =
            (isScalarData_ || isVectorData_ || isSVEData_) ? 256 : 8;
        results[0] = memoryData[0].zeroExtend(dataSize_, regSize);
        break;
      }
      case Opcode::AArch64_LDRBpost:    // ldr bt, [xn], #imm
      case Opcode::AArch64_LDRDpost:    // ldr dt, [xn], #imm
      case Opcode::AArch64_LDRHpost:    // ldr ht, [xn], #imm
      case Opcode::AArch64_LDRQpost:    // ldr qt, [xn], #imm
      case Opcode::AArch64_LDRSpost:    // ldr st, [xn], #imm
      case Opcode::AArch64_LDRWpost:    // ldr wt, [xn], #imm
      case Opcode::AArch64_LDRXpost: {  // ldr xt, [xn], #imm
        uint16_t regSize =
            (isScalarData_ || isVectorData_ || isSVEData_) ? 256 : 8;
        results[0] = memoryData[0].zeroExtend(dataSize_, regSize);
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
        break;
      }
      case Opcode::AArch64_LDRBpre:    // ldr bt, [xn, #imm]!
      case Opcode::AArch64_LDRDpre:    // ldr dt, [xn, #imm]!
      case Opcode::AArch64_LDRHpre:    // ldr ht, [xn, #imm]!
      case Opcode::AArch64_LDRQpre:    // ldr qt, [xn, #imm]!
      case Opcode::AArch64_LDRSpre:    // ldr st, [xn, #imm]!
      case Opcode::AArch64_LDRWpre:    // ldr wt, [xn, #imm]!
      case Opcode::AArch64_LDRXpre: {  // ldr xt, [xn, #imm]!
        uint16_t regSize =
            (isScalarData_ || isVectorData_ || isSVEData_) ? 256 : 8;
        results[0] = memoryData[0].zeroExtend(dataSize_, regSize);
        results[1] =
            operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
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
      case Opcode::AArch64_LDRHHpost: {  // ldrh wt, [xn], #imm
        // LOAD
        results[0] = memoryData[0].zeroExtend(2, 8);
        results[1] = operands[0].get<uint64_t>() + metadata.operands[2].imm;
        break;
      }
      case Opcode::AArch64_LDRHHpre: {  // ldrh wt, [xn, #imm]!
        // LOAD
        results[0] = memoryData[0].zeroExtend(2, 8);
        results[1] =
            operands[0].get<uint64_t>() + metadata.operands[1].mem.disp;
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
      case Opcode::AArch64_LDRQroX: {  // ldr qt, [xn, xm, {extend {#amount}}]
        // LOAD
        results[0] = memoryData[0].zeroExtend(16, 256);
        break;
      }
      case Opcode::AArch64_LDRSBWroX: {  // ldrsb wt, [xn, xm{, extend
                                         // {#amount}}]
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
      case Opcode::AArch64_LDRSBXui: {  // ldrsb xt, [xn, #imm]
        // LOAD
        results[0] = static_cast<int64_t>(memoryData[0].get<int8_t>());
        break;
      }
      case Opcode::AArch64_LDRSHWroW: {  // ldrsh wt, [xn, wm{, extend
                                         // {#amount}}]
        // LOAD
        results[0] =
            RegisterValue(static_cast<int32_t>(memoryData[0].get<int16_t>()), 4)
                .zeroExtend(4, 8);
        break;
      }
      case Opcode::AArch64_LDRSHWroX: {  // ldrsh wt, [xn, xm{, extend
                                         // {#amount}}]
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
      case Opcode::AArch64_LDRSHXroW: {  // ldrsh xt, [xn, wm{, extend
                                         // {#amount}}]
        // LOAD
        results[0] = static_cast<int64_t>(memoryData[0].get<int16_t>());
        break;
      }
      case Opcode::AArch64_LDRSHXroX: {  // ldrsh xt, [xn, xm{, extend
                                         // {#amount}}]
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
      case Opcode::AArch64_LDRSWroX: {  // ldrsw xt, [xn, xm{, extend
                                        // {#amount}}]
        // LOAD
        results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
        break;
      }
      case Opcode::AArch64_LDRSWui: {  // ldrsw xt, [xn{, #pimm}]
        // LOAD
        results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
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
      case Opcode::AArch64_LDRXl: {  // ldr xt, #imm
        // LOAD
        results[0] = memoryData[0];
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
      case Opcode::AArch64_LDTRSBXi: {  // ldtrsb xt, [xn, #imm]
        // LOAD
        // TODO: implement
        results[0] = RegisterValue(0, 8);
        break;
      }
      case Opcode::AArch64_LDURBBi: {  // ldurb wt, [xn, #imm]
        // LOAD
        results[0] = memoryData[0].zeroExtend(1, 8);
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
      case Opcode::AArch64_LDURQi: {  // ldur qt, [xn, #imm]
        // LOAD
        results[0] = memoryData[0].zeroExtend(16, 256);
        break;
      }
      case Opcode::AArch64_LDURSWi: {  // ldursw xt, [xn, #imm]
        // LOAD
        results[0] = static_cast<int64_t>(memoryData[0].get<int32_t>());
        break;
      }
      case Opcode::AArch64_LDURSi: {  // ldur sd, [<xn|sp>{, #imm}]
        // LOAD
        results[0] = {memoryData[0].get<float>(), 256};
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
      case Opcode::AArch64_LSLVWr: {  // lslv wd, wn, wm
        results[0] = {
            logicalHelp::logicalShiftLR_3ops<uint32_t>(operands, true), 8};
        break;
      }
      case Opcode::AArch64_LSLVXr: {  // lslv xd, xn, xm
        results[0] = logicalHelp::logicalShiftLR_3ops<uint64_t>(operands, true);
        break;
      }
      case Opcode::AArch64_LSL_ZZI_S: {  // lsl zd.s, zn.s, #imm
        results[0] = sveHelp::sveLsl_imm<uint32_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_LSRVWr: {  // lsrv wd, wn, wm
        results[0] = {
            logicalHelp::logicalShiftLR_3ops<uint32_t>(operands, false), 8};
        break;
      }
      case Opcode::AArch64_LSRVXr: {  // lsrv xd, xn, xm
        results[0] =
            logicalHelp::logicalShiftLR_3ops<uint64_t>(operands, false);
        break;
      }
      case Opcode::AArch64_MADDWrrr: {  // madd wd, wn, wm, wa
        results[0] = {multiplyHelp::madd_4ops<uint32_t>(operands), 8};
        break;
      }
      case Opcode::AArch64_MADDXrrr: {  // madd xd, xn, xm, xa
        results[0] = multiplyHelp::madd_4ops<uint64_t>(operands);
        break;
      }
      case Opcode::AArch64_MLA_ZPmZZ_B: {  // mla zda.b, pg/m, zn.b, zm.b
        results[0] = sveHelp::sveMlaPredicated_vecs<uint8_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_MLA_ZPmZZ_D: {  // mla zda.d, pg/m, zn.d, zm.d
        results[0] =
            sveHelp::sveMlaPredicated_vecs<uint64_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_MLA_ZPmZZ_H: {  // mla zda.h, pg/m, zn.h, zm.h
        results[0] =
            sveHelp::sveMlaPredicated_vecs<uint16_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_MLA_ZPmZZ_S: {  // mla zda.s, pg/m, zn.s, zm.s
        results[0] =
            sveHelp::sveMlaPredicated_vecs<uint32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_MOVID: {  // movi dd, #imm
        results[0] = {static_cast<uint64_t>(metadata.operands[1].imm), 256};
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
      case Opcode::AArch64_MOVIv4i32: {  // movi vd.4s, #imm{, LSL #shift}
        results[0] = neonHelp::vecMoviShift_imm<uint32_t, 4>(metadata, false);
        break;
      }
      case Opcode::AArch64_MOVIv8b_ns: {  // movi vd.8b, #imm
        results[0] = neonHelp::vecMovi_imm<uint8_t, 8>(metadata);
        break;
      }
      case Opcode::AArch64_MOVKWi: {  // movk wd, #imm
        results[0] = {
            arithmeticHelp::movkShift_imm<uint32_t>(operands, metadata), 8};
        break;
      }
      case Opcode::AArch64_MOVKXi: {  // movk xd, #imm
        results[0] =
            arithmeticHelp::movkShift_imm<uint64_t>(operands, metadata);
        break;
      }
      case Opcode::AArch64_MOVNWi: {  // movn wd, #imm{, LSL #shift}
        results[0] = {arithmeticHelp::movnShift_imm<uint32_t>(
                          metadata, [](uint64_t x) -> uint32_t { return ~x; }),
                      8};
        break;
      }
      case Opcode::AArch64_MOVNXi: {  // movn xd, #imm{, LSL #shift}
        results[0] = arithmeticHelp::movnShift_imm<uint64_t>(
            metadata, [](uint64_t x) -> uint64_t { return ~x; });
        break;
      }
      case Opcode::AArch64_MOVPRFX_ZPmZ_D: {  // movprfx zd.d, pg/m, zn.d
        results[0] = sveHelp::sveMovprfxPredicated_destUnchanged<uint64_t>(
            operands, VL_bits);
        break;
      }
      case Opcode::AArch64_MOVPRFX_ZPzZ_D: {  // movprfx zd.d, pg/z, zn.d
        results[0] = sveHelp::sveMovprfxPredicated_destToZero<uint64_t>(
            operands, VL_bits);
        break;
      }
      case Opcode::AArch64_MOVPRFX_ZPzZ_S: {  // movprfx zd.s, pg/z, zn.s
        results[0] = sveHelp::sveMovprfxPredicated_destToZero<uint32_t>(
            operands, VL_bits);
        break;
      }
      case Opcode::AArch64_MOVPRFX_ZZ: {  // movprfx zd, zn
        // TODO: Adopt hint logic of the MOVPRFX instruction
        results[0] = operands[0];
        break;
      }
      case Opcode::AArch64_MOVZWi: {  // movz wd, #imm
        results[0] = {arithmeticHelp::movnShift_imm<uint32_t>(
                          metadata, [](uint64_t x) -> uint32_t { return x; }),
                      8};
        break;
      }
      case Opcode::AArch64_MOVZXi: {  // movz xd, #imm
        results[0] = arithmeticHelp::movnShift_imm<uint64_t>(
            metadata, [](uint64_t x) -> uint64_t { return x; });
        break;
      }
      case Opcode::AArch64_MRS: {  // mrs xt, (systemreg|Sop0_op1_Cn_Cm_op2)
        results[0] = operands[0];
        break;
      }
      case Opcode::AArch64_MSR: {  // msr (systemreg|Sop0_op1_Cn_Cm_op2), xt
        results[0] = operands[0];
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
      case Opcode::AArch64_MSRpstatesvcrImm1: {  // msr svcr<sm|za|smza>, #imm
        // This instruction is always used by SMSTART and SMSTOP aliases.
        const uint64_t svcrBits =
            static_cast<uint64_t>(metadata.operands[0].svcr);
        const uint8_t imm = metadata.operands[1].imm;

        // Changing value of SM or ZA bits in SVCR zeros out vector, predicate,
        // and ZA registers. Raise an exception to do this.
        switch (svcrBits) {
          case ARM64_SVCR_SVCRSM:
            return streamingModeUpdated();
          case ARM64_SVCR_SVCRZA:
            return zaRegisterStatusUpdated();
          case ARM64_SVCR_SVCRSMZA:
            return SMZAupdated();
          default:
            // Invalid instruction
            return executionINV();
        }
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
      case Opcode::AArch64_MVNIv2i32: {  // mvni vd.2s, #imm{, lsl #shift}
        results[0] = neonHelp::vecMoviShift_imm<uint32_t, 2>(metadata, true);
        break;
      }
      case Opcode::AArch64_MVNIv2s_msl: {  // mvni vd.2s, #imm, msl #amount
        results[0] = neonHelp::vecMoviShift_imm<uint32_t, 2>(metadata, true);
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
      case Opcode::AArch64_MVNIv4s_msl: {  // mvni vd.4s #imm, msl #amount
        results[0] = neonHelp::vecMoviShift_imm<uint32_t, 4>(metadata, true);
        break;
      }
      case Opcode::AArch64_MVNIv8i16: {  // mvni vd.8h, #imm{, lsl #shift}
        results[0] = neonHelp::vecMoviShift_imm<uint16_t, 8>(metadata, true);
        break;
      }
      case Opcode::AArch64_NEGv2i64: {  // neg vd.2d, vn.2d
        results[0] = neonHelp::vecFneg_2ops<int64_t, 2>(operands);
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
      case Opcode::AArch64_ORNWrs: {  // orn wd, wn, wm{, shift{ #amount}}
        auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint32_t>(
            operands, metadata, false,
            [](uint32_t x, uint32_t y) -> uint32_t { return x | (~y); });
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_ORNXrs: {  // orn xd, xn, xm{, shift{ #amount}}
        auto [result, nzcv] = logicalHelp::logicOpShift_3ops<uint64_t>(
            operands, metadata, false,
            [](uint64_t x, uint64_t y) -> uint64_t { return x | (~y); });
        results[0] = result;
        break;
      }
      case Opcode::AArch64_ORRWri: {  // orr wd, wn, #imm
        auto [result, nzcv] = logicalHelp::logicOp_imm<uint32_t>(
            operands, metadata, false,
            [](uint32_t x, uint32_t y) -> uint32_t { return x | y; });
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_ORRWrs: {  // orr wd, wn, wm{, shift{ #amount}}
        results[0] = {
            comparisonHelp::orrShift_3ops<uint32_t>(operands, metadata), 8};
        break;
      }
      case Opcode::AArch64_ORRXri: {  // orr xd, xn, #imm
        auto [result, nzcv] = logicalHelp::logicOp_imm<uint64_t>(
            operands, metadata, false,
            [](uint64_t x, uint64_t y) -> uint64_t { return x | y; });
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_ORRXrs: {  // orr xd, xn, xm{, shift{ #amount}}
        results[0] =
            comparisonHelp::orrShift_3ops<uint64_t>(operands, metadata);
        break;
      }
      case Opcode::AArch64_ORR_PPzPP: {  // orr pd.b, pg/z, pn.b, pm.b
        results[0] = sveHelp::sveLogicOp_preds<uint8_t>(
            operands, VL_bits,
            [](uint64_t x, uint64_t y) -> uint64_t { return x | y; });
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
      case Opcode::AArch64_ORRv8i8: {  // orr vd.8b, vn.8b, vm.8b
        results[0] = neonHelp::vecLogicOp_3vecs<uint8_t, 8>(
            operands, [](uint8_t x, uint8_t y) -> uint8_t { return x | y; });
        break;
      }
      case Opcode::AArch64_PFALSE: {  // pfalse pd.b
        uint64_t out[4] = {0, 0, 0, 0};
        results[0] = out;
        break;
      }
      case Opcode::AArch64_PRFMui: {  // prfm op, [xn, xm{, extend{, #amount}}]
        break;
      }
      case Opcode::AArch64_PSEL_PPPRI_B: {  // psel pd, pn, pm.b[wa, #imm]
        results[0] = sveHelp::svePsel<uint8_t>(operands, metadata);
        break;
      }
      case Opcode::AArch64_PSEL_PPPRI_D: {  // psel pd, pn, pm.d[wa, #imm]
        results[0] = sveHelp::svePsel<uint64_t>(operands, metadata);
        break;
      }
      case Opcode::AArch64_PSEL_PPPRI_H: {  // psel pd, pn, pm.h[wa, #imm]
        results[0] = sveHelp::svePsel<uint16_t>(operands, metadata);
        break;
      }
      case Opcode::AArch64_PSEL_PPPRI_S: {  // psel pd, pn, pm.s[wa, #imm]
        results[0] = sveHelp::svePsel<uint32_t>(operands, metadata);
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
      case Opcode::AArch64_PTRUE_B: {  // ptrue pd.b{, pattern}
        results[0] = sveHelp::svePtrue<uint8_t>(metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_PTRUE_D: {  // ptrue pd.d{, pattern}
        results[0] = sveHelp::svePtrue<uint64_t>(metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_PTRUE_H: {  // ptrue pd.h{, pattern}
        results[0] = sveHelp::svePtrue<uint16_t>(metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_PTRUE_S: {  // ptrue pd.s{, pattern}
        results[0] = sveHelp::svePtrue<uint32_t>(metadata, VL_bits);
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
      case Opcode::AArch64_RBITWr: {  // rbit wd, wn
        results[0] = {bitmanipHelp::rbit<uint32_t>(operands, metadata), 8};
        break;
      }
      case Opcode::AArch64_RBITXr: {  // rbit xd, xn
        results[0] = bitmanipHelp::rbit<uint64_t>(operands, metadata);
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
      case Opcode::AArch64_REV16v16i8: {  // rev16 Vd.16b, Vn.16b
        results[0] = neonHelp::vecRev<int8_t, 16, 16>(operands);
        break;
      }
      case Opcode::AArch64_REV16v8i8: {  // rev16 Vd.8b, Vn.8b
        results[0] = neonHelp::vecRev<int8_t, 16, 8>(operands);
        break;
      }
      case Opcode::AArch64_REV32v16i8: {  // rev32 Vd.16b, Vn.16b
        results[0] = neonHelp::vecRev<int8_t, 32, 16>(operands);
        break;
      }
      case Opcode::AArch64_REV32v4i16: {  // rev32 Vd.4h, Vn.4h
        results[0] = neonHelp::vecRev<int16_t, 32, 4>(operands);
        break;
      }
      case Opcode::AArch64_REV32v8i16: {  // rev32 Vd.8h, Vn.8h
        results[0] = neonHelp::vecRev<int16_t, 32, 8>(operands);
        break;
      }
      case Opcode::AArch64_REV32v8i8: {  // rev32 Vd.8b, Vn.8b
        results[0] = neonHelp::vecRev<int8_t, 32, 8>(operands);
        break;
      }
      case Opcode::AArch64_REV64v16i8: {  // rev64 Vd.16b, Vn.16b
        results[0] = neonHelp::vecRev<int8_t, 64, 16>(operands);
        break;
      }
      case Opcode::AArch64_REV64v2i32: {  // rev64 Vd.2s, Vn.2s
        results[0] = neonHelp::vecRev<int32_t, 64, 2>(operands);
        break;
      }
      case Opcode::AArch64_REV64v4i16: {  // rev64 Vd.4h, Vn.4h
        results[0] = neonHelp::vecRev<int16_t, 64, 4>(operands);
        break;
      }
      case Opcode::AArch64_REV64v4i32: {  // rev64 Vd.4s, Vn.4s
        results[0] = neonHelp::vecRev<int32_t, 64, 4>(operands);
        break;
      }
      case Opcode::AArch64_REV64v8i16: {  // rev64 Vd.8h, Vn.8h
        results[0] = neonHelp::vecRev<int16_t, 64, 8>(operands);
        break;
      }
      case Opcode::AArch64_REV64v8i8: {  // rev64 Vd.8b Vn.8b
        results[0] = neonHelp::vecRev<int8_t, 64, 8>(operands);
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
      case Opcode::AArch64_RORVWr: {  // rorv wd, wn, wm
        results[0] = {logicalHelp::rorv_3ops<uint32_t>(operands), 8};
        break;
      }
      case Opcode::AArch64_RORVXr: {  // rorv xd, xn, xm
        results[0] = logicalHelp::rorv_3ops<uint64_t>(operands);
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
        results[0] = {
            bitmanipHelp::bfm_2imms<uint32_t>(operands, metadata, true, true),
            8};
        break;
      }
      case Opcode::AArch64_SBFMXri: {  // sbfm xd, xn, #immr, #imms
        results[0] =
            bitmanipHelp::bfm_2imms<uint64_t>(operands, metadata, true, true);
        break;
      }
      case Opcode::AArch64_SCVTFSXDri: {  // scvtf dd, xn, #fbits
        results[0] =
            floatHelp::scvtf_FixedPoint<double, int64_t>(operands, metadata);
        break;
      }
      case Opcode::AArch64_SCVTFSXSri: {  // scvtf sd, xn, #fbits
        results[0] =
            floatHelp::scvtf_FixedPoint<float, int64_t>(operands, metadata);
        break;
      }
      case Opcode::AArch64_SCVTFUWDri: {  // scvtf dd, wn
        results[0] = {static_cast<double>(operands[0].get<int32_t>()), 256};
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
      case Opcode::AArch64_SCVTFUXSri: {  // scvtf sd, xn
        results[0] = {static_cast<float>(operands[0].get<int64_t>()), 256};
        break;
      }
      case Opcode::AArch64_SCVTF_ZPmZ_DtoD: {  // scvtf zd.d, pg/m, zn.d
        results[0] =
            sveHelp::sveFcvtPredicated<double, int64_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SCVTF_ZPmZ_DtoS: {  // scvtf zd.s, pg/m, zn.d
        results[0] =
            sveHelp::sveFcvtPredicated<float, int64_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SCVTF_ZPmZ_StoD: {  // scvtf zd.d, pg/m, zn.s
        results[0] =
            sveHelp::sveFcvtPredicated<double, int32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SCVTF_ZPmZ_StoS: {  // scvtf zd.s, pg/m, zn.s
        results[0] =
            sveHelp::sveFcvtPredicated<float, int32_t>(operands, VL_bits);
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
            operands,
            [](int64_t x) -> double { return static_cast<double>(x); });
        break;
      }
      case Opcode::AArch64_SCVTFv4f32: {  // scvtf vd.4s, vn.4s
        results[0] = neonHelp::vecScvtf_2vecs<float, int32_t, 4>(
            operands, [](int32_t x) -> float { return static_cast<float>(x); });
        break;
      }
      case Opcode::AArch64_SDIVWr: {  // sdiv wd, wn, wm
        results[0] = {divideHelp::div_3ops<int32_t>(operands), 8};
        break;
      }
      case Opcode::AArch64_SDIVXr: {  // sdiv xd, xn, xm
        results[0] = {divideHelp::div_3ops<int64_t>(operands), 8};
        break;
      }
      case Opcode::AArch64_SEL_ZPZZ_D: {  // sel zd.d, pg, zn.d, zm.d
        results[0] = sveHelp::sveSel_zpzz<uint64_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SEL_ZPZZ_S: {  // sel zd.s, pg, zn.s, zm.s
        results[0] = sveHelp::sveSel_zpzz<uint32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SHLd: {  // shl dd, dn #imm
        results[0] =
            neonHelp::vecShlShift_vecImm<uint64_t, 1>(operands, metadata);
        break;
      }
      case Opcode::AArch64_SHLv4i32_shift: {  // shl vd.4s, vn.4s, #imm
        results[0] =
            neonHelp::vecShlShift_vecImm<uint32_t, 4>(operands, metadata);
        break;
      }
      case Opcode::AArch64_SMADDLrrr: {  // smaddl xd, wn, wm, xa
        results[0] = multiplyHelp::maddl_4ops<int64_t, int32_t>(operands);
        break;
      }
      case Opcode::AArch64_SMAX_ZI_S: {  // smax zdn.s, zdn.s, #imm
        results[0] =
            sveHelp::sveMax_vecImm<int32_t>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_SMAX_ZPmZ_S: {  // smax zd.s, pg/m, zn.s, zm.s
        results[0] = sveHelp::sveMaxPredicated_vecs<int32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SMAXv4i32: {  // smax vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecLogicOp_3vecs<int32_t, 4>(
            operands,
            [](int32_t x, int32_t y) -> int32_t { return std::max(x, y); });
        break;
      }
      case Opcode::AArch64_SMINV_VPZ_S: {  // sminv sd, pg, zn.s
        results[0] = sveHelp::sveSminv<int32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SMINVv4i32v: {  // sminv sd, vn.4s
        results[0] = neonHelp::vecMinv_2ops<int32_t, 4>(operands);
        break;
      }
      case Opcode::AArch64_SMIN_ZPmZ_S: {  // smin zd.s, pg/m, zn.s, zm.s
        results[0] = sveHelp::sveLogicOpPredicated_3vecs<int32_t>(
            operands, VL_bits,
            [](int32_t x, int32_t y) -> int32_t { return std::min(x, y); });
        break;
      }
      case Opcode::AArch64_SMINv4i32: {  // smin vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecLogicOp_3vecs<int32_t, 4>(
            operands,
            [](int32_t x, int32_t y) -> int32_t { return std::min(x, y); });
        break;
      }
      case Opcode::AArch64_SMSUBLrrr: {  // smsubl xd, wn, wm, xa
        results[0] = arithmeticHelp::msubl_4ops<int64_t, int32_t>(operands);
        break;
      }
      case Opcode::AArch64_SMULH_ZPmZ_B: {  // smulh zdn.b, pg/m, zdn.b, zm.b
        results[0] =
            sveHelp::sveMulhPredicated<int8_t, int16_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SMULH_ZPmZ_H: {  // smulh zdn.h, pg/m, zdn.h, zm.h
        results[0] =
            sveHelp::sveMulhPredicated<int16_t, int32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SMULH_ZPmZ_S: {  // smulh zdn.s, pg/m, zdn.s, zm.s
        results[0] =
            sveHelp::sveMulhPredicated<int32_t, int64_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SMULHrr: {  // smulh xd, xn, xm
        // TODO: signed
        results[0] = AuxFunc::mulhi(operands[0].get<uint64_t>(),
                                    operands[1].get<uint64_t>());
        break;
      }
      case Opcode::AArch64_SSHLLv2i32_shift: {  // sshll vd.2d, vn.2s, #imm
        results[0] = neonHelp::vecShllShift_vecImm<int64_t, int32_t, 2>(
            operands, metadata, false);
        break;
      }
      case Opcode::AArch64_SSHLLv4i32_shift: {  // sshll2 vd.2d, vn.4s, #imm
        results[0] = neonHelp::vecShllShift_vecImm<int64_t, int32_t, 2>(
            operands, metadata, true);
        break;
      }
      case Opcode::AArch64_SSHRv4i32_shift: {  // sshr vd.4s, vn.4s, #imm
        results[0] = neonHelp::vecSshrShift_imm<int32_t, 4>(operands, metadata);
        break;
      }
      case Opcode::AArch64_SST1B_D_REAL: {  // st1b {zd.d}, pg, [xn, zm.d]
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
      case Opcode::AArch64_SST1D_REAL: {  // st1d {zt.d}, pg, [xn, zm.d]
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
      case Opcode::AArch64_SST1D_SCALED_SCALED_REAL: {  // st1d {zt.d}, pg, [xn,
                                                        // zm.d, lsl #
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
      case Opcode::AArch64_ST1_MXIPXX_H_S: {  // st1w {zath.s[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, LSL #2}]
        // SME, STORE
        if (!ZAenabled) {
          // Not in right context mode. Raise exception
          return ZAdisabled();
        }
        const uint16_t partition_num = VL_bits / 32;
        const uint32_t ws = operands[partition_num].get<uint32_t>();
        const uint64_t* pg =
            operands[partition_num + 1].getAsVector<uint64_t>();

        const uint32_t sliceNum =
            (ws + metadata.operands[0].sme_index.disp) % partition_num;

        const uint32_t* tileSlice = operands[sliceNum].getAsVector<uint32_t>();
        uint16_t index = 0;
        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (pg[i / 16] & shifted_active) {
            memoryData[index] = tileSlice[i];
            index++;
          }
        }
        break;
      }
      case Opcode::AArch64_ST1_MXIPXX_V_S: {  // st1w {zatv.s[ws, #imm]}, pg/z,
                                              // [<xn|sp>{, xm, LSL #2}]
        // SME, STORE
        if (!ZAenabled) {
          // Not in right context mode. Raise exception
          return ZAdisabled();
        }
        const uint16_t partition_num = VL_bits / 32;
        const uint32_t ws = operands[partition_num].get<uint32_t>();
        const uint64_t* pg =
            operands[partition_num + 1].getAsVector<uint64_t>();

        const uint32_t sliceNum =
            (ws + metadata.operands[0].sme_index.disp) % partition_num;
        uint16_t index = 0;
        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 16) * 4);
          if (pg[i / 16] & shifted_active) {
            memoryData[index] = operands[i].getAsVector<uint32_t>()[sliceNum];
            index++;
          }
        }

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
      case Opcode::AArch64_ST2D_IMM: {  // st2d {zt1.d, zt2.d}, pg, [<xn|sp>{,
                                        // #imm, mul vl}]
        // STORE
        const uint64_t* d1 = operands[0].getAsVector<uint64_t>();
        const uint64_t* d2 = operands[1].getAsVector<uint64_t>();
        const uint64_t* p = operands[2].getAsVector<uint64_t>();

        const uint16_t partition_num = VL_bits / 64;
        uint16_t index = 0;
        for (int i = 0; i < partition_num; i++) {
          uint64_t shifted_active = 1ull << ((i % 8) * 8);
          if (p[i / 8] & shifted_active) {
            memoryData[index] = d1[i];
            index++;
            memoryData[index] = d2[i];
            index++;
          }
        }
        break;
      }
      case Opcode::AArch64_ST2Twov4s_POST: {  // st2 {vt1.4s, vt2.4s}, [xn],
                                              // #imm
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
      case Opcode::AArch64_STLRB: {  // stlrb wt, [xn]
        // STORE
        memoryData[0] = operands[0];
        break;
      }
      case Opcode::AArch64_STLRW:    // stlr wt, [xn]
      case Opcode::AArch64_STLRX: {  // stlr xt, [xn]
        // STORE
        memoryData[0] = operands[0];
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
      case Opcode::AArch64_STPDi:    // stp dt1, dt2, [xn, #imm]
      case Opcode::AArch64_STPQi:    // stp qt1, qt2, [xn, #imm]
      case Opcode::AArch64_STPSi:    // stp st1, st2, [xn, #imm]
      case Opcode::AArch64_STPWi:    // stp wt1, wt2, [xn, #imm]
      case Opcode::AArch64_STPXi: {  // stp xt1, xt2, [xn, #imm]
        memoryData[0] = operands[0];
        memoryData[1] = operands[1];
        break;
      }
      case Opcode::AArch64_STPDpost:    // stp dt1, dt2, [xn], #imm
      case Opcode::AArch64_STPQpost:    // stp qt1, qt2, [xn], #imm
      case Opcode::AArch64_STPSpost:    // stp st1, st2, [xn], #imm
      case Opcode::AArch64_STPWpost:    // stp wt1, wt2, [xn], #imm
      case Opcode::AArch64_STPXpost: {  // stp xt1, xt2, [xn], #imm
        memoryData[0] = operands[0];
        memoryData[1] = operands[1];
        results[0] = operands[2].get<uint64_t>() + metadata.operands[3].imm;
        break;
      }
      case Opcode::AArch64_STPDpre:    // stp dt1, dt2, [xn, #imm]!
      case Opcode::AArch64_STPQpre:    // stp qt1, qt2, [xn, #imm]!
      case Opcode::AArch64_STPSpre:    // stp st1, st2, [xn, #imm]!
      case Opcode::AArch64_STPWpre:    // stp wt1, wt2, [xn, #imm]!
      case Opcode::AArch64_STPXpre: {  // stp xt1, xt2, [xn, #imm]!
        memoryData[0] = operands[0];
        memoryData[1] = operands[1];
        results[0] =
            operands[2].get<uint64_t>() + metadata.operands[2].mem.disp;
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
        results[0] =
            operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
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
      case Opcode::AArch64_STRBui:    // str bt, [xn, #imm]
      case Opcode::AArch64_STRDui:    // str dt, [xn, #imm]
      case Opcode::AArch64_STRHui:    // str ht, [xn, #imm]
      case Opcode::AArch64_STRQui:    // str qt, [xn, #imm]
      case Opcode::AArch64_STRSui:    // str st, [xn, #imm]
      case Opcode::AArch64_STRWui:    // str wt, [xn, #imm]
      case Opcode::AArch64_STRXui: {  // str xt, [xn, #imm]
        memoryData[0] = operands[0];
        break;
      }
      case Opcode::AArch64_STRBpost:    // str bt, [xn], #imm
      case Opcode::AArch64_STRDpost:    // str dt, [xn], #imm
      case Opcode::AArch64_STRHpost:    // str ht, [xn], #imm
      case Opcode::AArch64_STRQpost:    // str qt, [xn], #imm
      case Opcode::AArch64_STRSpost:    // str st, [xn], #imm
      case Opcode::AArch64_STRWpost:    // str wt, [xn], #imm
      case Opcode::AArch64_STRXpost: {  // str xt, [xn], #imm
        memoryData[0] = operands[0];
        results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
        break;
      }
      case Opcode::AArch64_STRBpre:    // str bt, [xn, #imm]!
      case Opcode::AArch64_STRDpre:    // str dt, [xn, #imm]!
      case Opcode::AArch64_STRHpre:    // str ht, [xn, #imm]!
      case Opcode::AArch64_STRQpre:    // str qt, [xn, #imm]!
      case Opcode::AArch64_STRSpre:    // str st, [xn, #imm]!
      case Opcode::AArch64_STRWpre:    // str wt, [xn, #imm]!
      case Opcode::AArch64_STRXpre: {  // str xt, [xn, #imm]!
        memoryData[0] = operands[0];
        results[0] =
            operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
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
      case Opcode::AArch64_STRHHpost: {  // strh wt, [xn], #imm
        // STORE
        memoryData[0] = operands[0];
        results[0] = operands[1].get<uint64_t>() + metadata.operands[2].imm;
        break;
      }
      case Opcode::AArch64_STRHHpre: {  // strh wd, [xn, #imm]!
        // STORE
        memoryData[0] = operands[0];
        results[0] =
            operands[1].get<uint64_t>() + metadata.operands[1].mem.disp;
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
      case Opcode::AArch64_STRQroX: {  // str qt, [xn, xm{, extend, {#amount}}]
        // STORE
        memoryData[0] = operands[0];
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
      case Opcode::AArch64_STURBBi: {  // sturb wd, [xn, #imm]
        // STORE
        memoryData[0] = operands[0];
        break;
      }
      case Opcode::AArch64_STURDi:     // stur dt, [xn, #imm]
      case Opcode::AArch64_STURHHi: {  // sturh wt, [xn, #imm]
        // STORE
        memoryData[0] = operands[0];
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
      case Opcode::AArch64_SUBSWri: {  // subs wd, wn, #imm
        auto [result, nzcv] =
            arithmeticHelp::subShift_imm<uint32_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = {result, 8};
        break;
      }
      case Opcode::AArch64_SUBSWrs: {  // subs wd, wn, wm{, shift #amount}
        auto [result, nzcv] =
            arithmeticHelp::subShift_3ops<uint32_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = {result, 8};
        break;
      }
      case Opcode::AArch64_SUBSWrx: {  // subs wd, wn, wm{, extend #amount}
        auto [result, nzcv] =
            arithmeticHelp::subExtend_3ops<uint32_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = {result, 8};
        break;
      }
      case Opcode::AArch64_SUBSXri: {  // subs xd, xn, #imm
        auto [result, nzcv] =
            arithmeticHelp::subShift_imm<uint64_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = result;
        break;
      }
      case Opcode::AArch64_SUBSXrs: {  // subs xd, xn, xm{, shift #amount}
        auto [result, nzcv] =
            arithmeticHelp::subShift_3ops<uint64_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = result;
        break;
      }
      case Opcode::AArch64_SUBSXrx:      // subs xd, xn, wm{, extend #amount}
      case Opcode::AArch64_SUBSXrx64: {  // subs xd, xn, xm{, extend #amount}
        auto [result, nzcv] =
            arithmeticHelp::subExtend_3ops<uint64_t>(operands, metadata, true);
        results[0] = nzcv;
        results[1] = result;
        break;
      }
      case Opcode::AArch64_SUBWri: {  // sub wd, wn, #imm{, <shift>}
        auto [result, nzcv] =
            arithmeticHelp::subShift_imm<uint32_t>(operands, metadata, false);
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_SUBWrs: {  // sub wd, wn, wm{, shift #amount}
        auto [result, nzcv] =
            arithmeticHelp::subShift_3ops<uint32_t>(operands, metadata, false);
        results[0] = {result, 8};
        break;
      }
      case Opcode::AArch64_SUBXri: {  // sub xd, xn, #imm{, <shift>}
        auto [result, nzcv] =
            arithmeticHelp::subShift_imm<uint64_t>(operands, metadata, false);
        results[0] = result;
        break;
      }
      case Opcode::AArch64_SUBXrs: {  // sub xd, xn, xm{, shift #amount}
        auto [result, nzcv] =
            arithmeticHelp::subShift_3ops<uint64_t>(operands, metadata, false);
        results[0] = result;
        break;
      }
      case Opcode::AArch64_SUBXrx:      // sub xd, xn, wm{, extend #amount}
      case Opcode::AArch64_SUBXrx64: {  // sub xd, xn, xm{, extend #amount}
        auto [result, nzcv] =
            arithmeticHelp::subExtend_3ops<uint64_t>(operands, metadata, false);
        results[0] = result;
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
      case Opcode::AArch64_SVC: {  // svc #imm
        exceptionEncountered_ = true;
        exception_ = InstructionException::SupervisorCall;
        break;
      }
      case Opcode::AArch64_SXTW_ZPmZ_D: {  // sxtw zd.d, pg/m, zn.d
        results[0] =
            sveHelp::sveSxtPredicated<int64_t, int32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_SYSxt: {  // sys #<op1>, cn, cm, #<op2>{, xt}
        // if (metadata.id == ARM64_INS_DC) {
        //   uint64_t address = operands[0].get<uint64_t>();
        //   uint8_t dzp = operands[1].get<uint64_t>() & 8;
        //   uint8_t N = std::pow(2, operands[1].get<uint64_t>() & 7);
        //   if (metadata.operands[0].sys == ARM64_DC_ZVA) {
        //     if (dzp) {
        //       // TODO
        //     }
        //   }
        // }
        break;
      }
      case Opcode::AArch64_TBLv16i8Four: {  // tbl Vd.16b {Vn.16b, Vn+1.16b,
                                            // Vn+2.16b,Vn+3.16b } Vm.16b
        results[0] = neonHelp::vecTbl<16>(operands, metadata);
        break;
      }
      case Opcode::AArch64_TBLv16i8One: {  // tbl Vd.16b {Vn.16b} Vm.16b
        results[0] = neonHelp::vecTbl<16>(operands, metadata);
        break;
      }
      case Opcode::AArch64_TBLv16i8Three: {  // tbl Vd.16b {Vn.16b, Vn+1.16b,
                                             // Vn+2.16b } Vm.16b
        results[0] = neonHelp::vecTbl<16>(operands, metadata);
        break;
      }
      case Opcode::AArch64_TBLv16i8Two: {  // tbl Vd.16b {Vn.16b, Vn+1.16b }
                                           // Vm.16b
        results[0] = neonHelp::vecTbl<16>(operands, metadata);
        break;
      }
      case Opcode::AArch64_TBLv8i8Four: {  // tbl Vd.8b {Vn.16b, Vn+1.16b,
                                           // Vn+2.16b,Vn+3.16b } Vm.8b
        results[0] = neonHelp::vecTbl<8>(operands, metadata);
        break;
      }
      case Opcode::AArch64_TBLv8i8One: {  // tbl Vd.8b {Vn.16b} Vm.8b
        results[0] = neonHelp::vecTbl<8>(operands, metadata);
        break;
      }
      case Opcode::AArch64_TBLv8i8Three: {  // tbl Vd.8b {Vn.16b, Vn+1.16b,
                                            // Vn+2.16b } Vm.8b
        results[0] = neonHelp::vecTbl<8>(operands, metadata);
        break;
      }
      case Opcode::AArch64_TBLv8i8Two: {  // tbl Vd.8b {Vn.16b, Vn+1.16b } Vm.8b
        results[0] = neonHelp::vecTbl<8>(operands, metadata);
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
      case Opcode::AArch64_TRN1_ZZZ_B: {  // trn1 zd.b, zn.b, zm.b
        results[0] = sveHelp::sveTrn1_3vecs<uint8_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_TRN1_ZZZ_D: {  // trn1 zd.d, zn.d, zm.d
        results[0] = sveHelp::sveTrn1_3vecs<uint64_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_TRN1_ZZZ_H: {  // trn1 zd.h, zn.h, zm.h
        results[0] = sveHelp::sveTrn1_3vecs<uint16_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_TRN1_ZZZ_S: {  // trn1 zd.s, zn.s, zm.s
        results[0] = sveHelp::sveTrn1_3vecs<uint32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_TRN1v16i8: {  // trn1 vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecTrn1<uint8_t, 16>(operands);
        break;
      }
      case Opcode::AArch64_TRN1v2i32: {  // trn1 vd.2s, vn.2s, vm.2s
        results[0] = neonHelp::vecTrn1<uint32_t, 2>(operands);
        break;
      }
      case Opcode::AArch64_TRN1v2i64: {  // trn1 vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecTrn1<uint64_t, 2>(operands);
        break;
      }
      case Opcode::AArch64_TRN1v4i16: {  // trn1 vd.4h, vn.4h, vm.4h
        results[0] = neonHelp::vecTrn1<uint16_t, 4>(operands);
        break;
      }
      case Opcode::AArch64_TRN1v4i32: {  // trn1 vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecTrn1<uint32_t, 4>(operands);
        break;
      }
      case Opcode::AArch64_TRN1v8i16: {  // trn1 vd.8h, vn.8h, vm.8h
        results[0] = neonHelp::vecTrn1<uint16_t, 8>(operands);
        break;
      }
      case Opcode::AArch64_TRN1v8i8: {  // trn1 vd.8b, vn.8b, vm.8b
        results[0] = neonHelp::vecTrn1<uint8_t, 8>(operands);
        break;
      }
      case Opcode::AArch64_TRN2_ZZZ_B: {  // trn2 zd.b, zn.b, zm.b
        results[0] = sveHelp::sveTrn2_3vecs<uint8_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_TRN2_ZZZ_D: {  // trn2 zd.d, zn.d, zm.d
        results[0] = sveHelp::sveTrn2_3vecs<uint64_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_TRN2_ZZZ_H: {  // trn2 zd.h, zn.h, zm.h
        results[0] = sveHelp::sveTrn2_3vecs<uint16_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_TRN2_ZZZ_S: {  // trn2 zd.s, zn.s, zm.s
        results[0] = sveHelp::sveTrn2_3vecs<uint32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_TRN2v16i8: {  // trn2 vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecTrn2<uint8_t, 16>(operands);
        break;
      }
      case Opcode::AArch64_TRN2v2i32: {  // trn2 vd.2s, vn.2s, vm.2s
        results[0] = neonHelp::vecTrn2<uint32_t, 2>(operands);
        break;
      }
      case Opcode::AArch64_TRN2v2i64: {  // trn2 vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecTrn2<uint64_t, 2>(operands);
        break;
      }
      case Opcode::AArch64_TRN2v4i16: {  // trn2 vd.4h, vn.4h, vm.4h
        results[0] = neonHelp::vecTrn2<uint16_t, 4>(operands);
        break;
      }
      case Opcode::AArch64_TRN2v4i32: {  // trn2 vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecTrn2<uint32_t, 4>(operands);
        break;
      }
      case Opcode::AArch64_TRN2v8i16: {  // trn2 vd.8h, vn.8h, vm.8h
        results[0] = neonHelp::vecTrn2<uint16_t, 8>(operands);
        break;
      }
      case Opcode::AArch64_TRN2v8i8: {  // trn2 vd.8b, vn.8b, vm.8b
        results[0] = neonHelp::vecTrn2<uint8_t, 8>(operands);
        break;
      }
      case Opcode::AArch64_UADDV_VPZ_B: {  // uaddv dd, pg, zn.b
        results[0] = sveHelp::sveAddvPredicated<uint8_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_UADDV_VPZ_D: {  // uaddv dd, pg, zn.d
        results[0] = sveHelp::sveAddvPredicated<uint64_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_UADDV_VPZ_H: {  // uaddv dd, pg, zn.h
        results[0] = sveHelp::sveAddvPredicated<uint16_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_UADDV_VPZ_S: {  // uaddv dd, pg, zn.s
        results[0] = sveHelp::sveAddvPredicated<uint32_t>(operands, VL_bits);
        break;
      }
      case Opcode::AArch64_UBFMWri: {  // ubfm wd, wn, #immr, #imms
        results[0] = {
            bitmanipHelp::bfm_2imms<uint32_t>(operands, metadata, false, true),
            8};
        break;
      }
      case Opcode::AArch64_UBFMXri: {  // ubfm xd, xn, #immr, #imms
        results[0] =
            bitmanipHelp::bfm_2imms<uint64_t>(operands, metadata, false, true);
        break;
      }
      case Opcode::AArch64_UCVTFUWDri: {  // ucvtf dd, wn
        results[0] = {static_cast<double>(operands[0].get<uint32_t>()), 256};
        break;
      }
      case Opcode::AArch64_UCVTFUWSri: {  // ucvtf sd, wn
        results[0] = {static_cast<float>(operands[0].get<uint32_t>()), 256};
        break;
      }
      case Opcode::AArch64_UCVTFUXDri: {  // ucvtf dd, xn
        results[0] = {static_cast<double>(operands[0].get<uint64_t>()), 256};
        break;
      }
      case Opcode::AArch64_UCVTFUXSri: {  // ucvtf sd, xn
        results[0] = {static_cast<float>(operands[0].get<uint64_t>()), 256};
        break;
      }
      case Opcode::AArch64_UCVTFv1i32: {  // ucvtf sd, sn
        results[0] = {static_cast<float>(operands[0].get<uint32_t>()), 256};
        break;
      }
      case Opcode::AArch64_UCVTFv1i64: {  // ucvtf dd, dn
        results[0] = {static_cast<double>(operands[0].get<uint64_t>()), 256};
        break;
      }
      case Opcode::AArch64_UDIVWr: {  // udiv wd, wn, wm
        results[0] = {divideHelp::div_3ops<uint32_t>(operands), 8};
        break;
      }
      case Opcode::AArch64_UDIVXr: {  // udiv xd, xn, xm
        results[0] = {divideHelp::div_3ops<uint64_t>(operands), 8};
        break;
      }
      case Opcode::AArch64_UMADDLrrr: {  // umaddl xd, wn, wm, xa
        results[0] = multiplyHelp::maddl_4ops<uint64_t, uint32_t>(operands);
        break;
      }
      case Opcode::AArch64_UMAXPv16i8: {  // umaxp vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecUMaxP<uint8_t, 16>(operands);
        break;
      }
      case Opcode::AArch64_UMINPv16i8: {  // uminp vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecUMinP<uint8_t, 16>(operands);
        break;
      }
      case Opcode::AArch64_UMOVvi32_idx0:  // umov wd, vn.s[0]
      case Opcode::AArch64_UMOVvi32: {     // umov wd, vn.s[index]
        const uint32_t* vec = operands[0].getAsVector<uint32_t>();
        results[0] = {vec[metadata.operands[1].vector_index], 8};
        break;
      }
      case Opcode::AArch64_UMOVvi64_idx0:  // umov xd, vn.d[0]
      case Opcode::AArch64_UMOVvi64: {     // umov xd, vn.d[index]
        const uint64_t* vec = operands[0].getAsVector<uint64_t>();
        results[0] = vec[metadata.operands[1].vector_index];
        break;
      }
      case Opcode::AArch64_UMOVvi8_idx0:  // umov wd, vn.b[0]
      case Opcode::AArch64_UMOVvi8: {     // umov wd, vn.b[index]
        const uint8_t* vec = operands[0].getAsVector<uint8_t>();
        results[0] = {vec[metadata.operands[1].vector_index], 8};
        break;
      }
      case Opcode::AArch64_UMSUBLrrr: {  // umsubl xd, wn, wm, xa
        results[0] = arithmeticHelp::msubl_4ops<uint64_t, uint32_t>(operands);
        break;
      }
      case Opcode::AArch64_UMULHrr: {  // umulh xd, xn, xm
        results[0] = AuxFunc::mulhi(operands[0].get<uint64_t>(),
                                    operands[1].get<uint64_t>());
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
      case Opcode::AArch64_UQDECH_XPiI: {  // uqdech xd{, pattern{, MUL #imm}}
        results[0] =
            sveHelp::sveUqdec<uint64_t, 16u>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_UQDECW_XPiI: {  // uqdecw xd{, pattern{, MUL #imm}}
        results[0] =
            sveHelp::sveUqdec<uint64_t, 32u>(operands, metadata, VL_bits);
        break;
      }
      case Opcode::AArch64_USHLLv16i8_shift: {  // ushll2 vd.8h, vn.16b, #imm
        results[0] = neonHelp::vecShllShift_vecImm<uint16_t, uint8_t, 8>(
            operands, metadata, true);
        break;
      }
      case Opcode::AArch64_USHLLv4i16_shift: {  // ushll vd.4s, vn.4h, #imm
        results[0] = neonHelp::vecShllShift_vecImm<uint32_t, uint16_t, 4>(
            operands, metadata, false);
        break;
      }
      case Opcode::AArch64_USHLLv8i16_shift: {  // ushll2 vd.4s, vn.8h, #imm
        results[0] = neonHelp::vecShllShift_vecImm<uint32_t, uint16_t, 4>(
            operands, metadata, true);
        break;
      }
      case Opcode::AArch64_USHLLv8i8_shift: {  // ushll vd.8h, vn.8b, #imm
        results[0] = neonHelp::vecShllShift_vecImm<uint16_t, uint8_t, 8>(
            operands, metadata, false);
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
      case Opcode::AArch64_UZP1_ZZZ_S: {  // uzp1 zd.s, zn.s, zm.s
        results[0] = sveHelp::sveUzp_vecs<uint32_t>(operands, VL_bits, true);
        break;
      }
      case Opcode::AArch64_UZP1v16i8: {  // uzp1 vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecUzp<int8_t, 16>(operands, true);
        break;
      }
      case Opcode::AArch64_UZP1v2i32: {  // uzp1 vd.2s, vn.2s, vm.2s
        results[0] = neonHelp::vecUzp<int32_t, 2>(operands, true);
        break;
      }
      case Opcode::AArch64_UZP1v2i64: {  // uzp1 vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecUzp<int64_t, 2>(operands, true);
        break;
      }
      case Opcode::AArch64_UZP1v4i16: {  // uzp1 vd.4h, vn.4h, vm.4h
        results[0] = neonHelp::vecUzp<int16_t, 4>(operands, true);
        break;
      }
      case Opcode::AArch64_UZP1v4i32: {  // uzp1 vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecUzp<int32_t, 4>(operands, true);
        break;
      }
      case Opcode::AArch64_UZP1v8i16: {  // uzp1 vd.8h, vn.8h, vm.8h
        results[0] = neonHelp::vecUzp<int16_t, 8>(operands, true);
        break;
      }
      case Opcode::AArch64_UZP1v8i8: {  // uzp1 vd.8b, vn.8b, vm.8b
        results[0] = neonHelp::vecUzp<int8_t, 8>(operands, true);
        break;
      }
      case Opcode::AArch64_UZP2v16i8: {  // uzp2 vd.16b, vn.16b, vm.16b
        results[0] = neonHelp::vecUzp<int8_t, 16>(operands, false);
        break;
      }
      case Opcode::AArch64_UZP2v2i32: {  // uzp2 vd.2s, vn.2s, vm.2s
        results[0] = neonHelp::vecUzp<int32_t, 2>(operands, false);
        break;
      }
      case Opcode::AArch64_UZP2v2i64: {  // uzp2 vd.2d, vn.2d, vm.2d
        results[0] = neonHelp::vecUzp<int64_t, 2>(operands, false);
        break;
      }
      case Opcode::AArch64_UZP2v4i16: {  // uzp2 vd.4h, vn.4h, vm.4h
        results[0] = neonHelp::vecUzp<int16_t, 4>(operands, false);
        break;
      }
      case Opcode::AArch64_UZP2v4i32: {  // uzp2 vd.4s, vn.4s, vm.4s
        results[0] = neonHelp::vecUzp<int32_t, 4>(operands, false);
        break;
      }
      case Opcode::AArch64_UZP2v8i16: {  // uzp2 vd.8h, vn.8h, vm.8h
        results[0] = neonHelp::vecUzp<int16_t, 8>(operands, false);
        break;
      }
      case Opcode::AArch64_UZP2v8i8: {  // uzp2 vd.8b, vn.8b, vm.8b
        results[0] = neonHelp::vecUzp<int8_t, 8>(operands, false);
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
      case Opcode::AArch64_WHILELT_PXX_B: {  // whilelt pd.b, xn, xm
        auto [output, nzcv] =
            sveHelp::sveWhilelo<int64_t, int8_t>(operands, VL_bits, true);
        results[0] = nzcv;
        results[1] = output;
        break;
      }
      case Opcode::AArch64_WHILELT_PXX_D: {  // whilelt pd.d, xn, xm
        auto [output, nzcv] =
            sveHelp::sveWhilelo<int64_t, int64_t>(operands, VL_bits, true);
        results[0] = nzcv;
        results[1] = output;
        break;
      }
      case Opcode::AArch64_WHILELT_PXX_H: {  // whilelt pd.h, xn, xm
        auto [output, nzcv] =
            sveHelp::sveWhilelo<int64_t, int16_t>(operands, VL_bits, true);
        results[0] = nzcv;
        results[1] = output;
        break;
      }
      case Opcode::AArch64_WHILELT_PXX_S: {  // whilelt pd.s, xn, xm
        auto [output, nzcv] =
            sveHelp::sveWhilelo<int64_t, int32_t>(operands, VL_bits, true);
        results[0] = nzcv;
        results[1] = output;
        break;
      }
      case Opcode::AArch64_XPACLRI: {  // xpaclri
        // SimEng doesn't support PAC, so do nothing
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
      case Opcode::AArch64_ZIP1_ZZZ_D: {  // zip1 zd.d, zn.d, zm.d
        results[0] = sveHelp::sveZip_vecs<uint64_t>(operands, VL_bits, false);
        break;
      }
      case Opcode::AArch64_ZIP1_ZZZ_S: {  // zip1 zd.s, zn.s, zm.s
        results[0] = sveHelp::sveZip_vecs<uint32_t>(operands, VL_bits, false);
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
      case Opcode::AArch64_ZIP2_ZZZ_D: {  // zip2 zd.d, zn.d, zm.d
        results[0] = sveHelp::sveZip_vecs<uint64_t>(operands, VL_bits, true);
        break;
      }
      case Opcode::AArch64_ZIP2_ZZZ_S: {  // zip2 zd.s, zn.s, zm.s
        results[0] = sveHelp::sveZip_vecs<uint32_t>(operands, VL_bits, true);
        break;
      }
      case Opcode::AArch64_ZERO_M: {  // zero {mask}
        // SME
        if (!ZAenabled) {
          // Not in right context mode. Raise exception
          return ZAdisabled();
        }
        for (int i = 0; i < destinationRegisterCount; i++) {
          results[i] = RegisterValue(0, 256);
        }
        break;
      }
      default:
        return executionNYI();
    }
  }

#ifndef NDEBUG
  // Check if upper bits of vector registers are zeroed because Z
  // configuration extend to 256 bytes whilst V configurations only extend
  // to 16 bytes. Thus upper 240 bytes must be ignored by being set to 0.
  for (int i = 0; i < destinationRegisterCount; i++) {
    if ((destinationRegisters[i].type == RegisterType::VECTOR) && !isSVEData_) {
      if (results[i].size() != 256)
        std::cerr << "[SimEng:Instruction_execute] " << metadata.mnemonic
                  << " opcode: " << metadata.opcode
                  << " has not been zero extended correctly\n";
    }
  }
#endif
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng