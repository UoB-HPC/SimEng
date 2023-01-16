/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Subtarget Enumeration Source Fragment                                      *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_SUBTARGETINFO_ENUM
#undef GET_SUBTARGETINFO_ENUM

namespace llvm {
namespace RISCV {
enum {
  Feature64Bit = 0,
  FeatureNoRVCHints = 1,
  FeatureRV32E = 2,
  FeatureRelax = 3,
  FeatureReserveX1 = 4,
  FeatureReserveX2 = 5,
  FeatureReserveX3 = 6,
  FeatureReserveX4 = 7,
  FeatureReserveX5 = 8,
  FeatureReserveX6 = 9,
  FeatureReserveX7 = 10,
  FeatureReserveX8 = 11,
  FeatureReserveX9 = 12,
  FeatureReserveX10 = 13,
  FeatureReserveX11 = 14,
  FeatureReserveX12 = 15,
  FeatureReserveX13 = 16,
  FeatureReserveX14 = 17,
  FeatureReserveX15 = 18,
  FeatureReserveX16 = 19,
  FeatureReserveX17 = 20,
  FeatureReserveX18 = 21,
  FeatureReserveX19 = 22,
  FeatureReserveX20 = 23,
  FeatureReserveX21 = 24,
  FeatureReserveX22 = 25,
  FeatureReserveX23 = 26,
  FeatureReserveX24 = 27,
  FeatureReserveX25 = 28,
  FeatureReserveX26 = 29,
  FeatureReserveX27 = 30,
  FeatureReserveX28 = 31,
  FeatureReserveX29 = 32,
  FeatureReserveX30 = 33,
  FeatureReserveX31 = 34,
  FeatureSaveRestore = 35,
  FeatureStdExtA = 36,
  FeatureStdExtC = 37,
  FeatureStdExtD = 38,
  FeatureStdExtF = 39,
  FeatureStdExtM = 40,
  FeatureStdExtV = 41,
  FeatureStdExtZba = 42,
  FeatureStdExtZbb = 43,
  FeatureStdExtZbc = 44,
  FeatureStdExtZbe = 45,
  FeatureStdExtZbf = 46,
  FeatureStdExtZbkb = 47,
  FeatureStdExtZbkc = 48,
  FeatureStdExtZbkx = 49,
  FeatureStdExtZbm = 50,
  FeatureStdExtZbp = 51,
  FeatureStdExtZbr = 52,
  FeatureStdExtZbs = 53,
  FeatureStdExtZbt = 54,
  FeatureStdExtZdinx = 55,
  FeatureStdExtZfh = 56,
  FeatureStdExtZfhmin = 57,
  FeatureStdExtZfinx = 58,
  FeatureStdExtZhinx = 59,
  FeatureStdExtZhinxmin = 60,
  FeatureStdExtZk = 61,
  FeatureStdExtZkn = 62,
  FeatureStdExtZknd = 63,
  FeatureStdExtZkne = 64,
  FeatureStdExtZknh = 65,
  FeatureStdExtZkr = 66,
  FeatureStdExtZks = 67,
  FeatureStdExtZksed = 68,
  FeatureStdExtZksh = 69,
  FeatureStdExtZkt = 70,
  FeatureStdExtZve32f = 71,
  FeatureStdExtZve32x = 72,
  FeatureStdExtZve64d = 73,
  FeatureStdExtZve64f = 74,
  FeatureStdExtZve64x = 75,
  FeatureStdExtZvl32b = 76,
  FeatureStdExtZvl64b = 77,
  FeatureStdExtZvl128b = 78,
  FeatureStdExtZvl256b = 79,
  FeatureStdExtZvl512b = 80,
  FeatureStdExtZvl1024b = 81,
  FeatureStdExtZvl2048b = 82,
  FeatureStdExtZvl4096b = 83,
  FeatureStdExtZvl8192b = 84,
  FeatureStdExtZvl16384b = 85,
  FeatureStdExtZvl32768b = 86,
  TuneSiFive7 = 87,
  NumSubtargetFeatures = 88
};
} // end namespace RISCV
} // end namespace llvm

#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

namespace llvm {
// Sorted (by key) array of values for CPU features.
extern const llvm::SubtargetFeatureKV RISCVFeatureKV[] = {
  { "64bit", "Implements RV64", RISCV::Feature64Bit, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "a", "'A' (Atomic Instructions)", RISCV::FeatureStdExtA, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "c", "'C' (Compressed Instructions)", RISCV::FeatureStdExtC, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "d", "'D' (Double-Precision Floating-Point)", RISCV::FeatureStdExtD, { { { 0x8000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "e", "Implements RV32E (provides 16 rather than 32 GPRs)", RISCV::FeatureRV32E, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "experimental-zbe", "'Zbe' (Extract-Deposit 'Zb' Instructions)", RISCV::FeatureStdExtZbe, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "experimental-zbf", "'Zbf' (Bit-Field 'Zb' Instructions)", RISCV::FeatureStdExtZbf, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "experimental-zbm", "'Zbm' (Matrix 'Zb' Instructions)", RISCV::FeatureStdExtZbm, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "experimental-zbp", "'Zbp' (Permutation 'Zb' Instructions)", RISCV::FeatureStdExtZbp, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "experimental-zbr", "'Zbr' (Polynomial Reduction 'Zb' Instructions)", RISCV::FeatureStdExtZbr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "experimental-zbt", "'Zbt' (Ternary 'Zb' Instructions)", RISCV::FeatureStdExtZbt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "f", "'F' (Single-Precision Floating-Point)", RISCV::FeatureStdExtF, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "m", "'M' (Integer Multiplication and Division)", RISCV::FeatureStdExtM, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "no-rvc-hints", "Disable RVC Hint Instructions.", RISCV::FeatureNoRVCHints, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "relax", "Enable Linker relaxation.", RISCV::FeatureRelax, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x1", "Reserve X1", RISCV::FeatureReserveX1, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x10", "Reserve X10", RISCV::FeatureReserveX10, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x11", "Reserve X11", RISCV::FeatureReserveX11, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x12", "Reserve X12", RISCV::FeatureReserveX12, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x13", "Reserve X13", RISCV::FeatureReserveX13, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x14", "Reserve X14", RISCV::FeatureReserveX14, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x15", "Reserve X15", RISCV::FeatureReserveX15, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x16", "Reserve X16", RISCV::FeatureReserveX16, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x17", "Reserve X17", RISCV::FeatureReserveX17, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x18", "Reserve X18", RISCV::FeatureReserveX18, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x19", "Reserve X19", RISCV::FeatureReserveX19, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x2", "Reserve X2", RISCV::FeatureReserveX2, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x20", "Reserve X20", RISCV::FeatureReserveX20, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x21", "Reserve X21", RISCV::FeatureReserveX21, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x22", "Reserve X22", RISCV::FeatureReserveX22, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x23", "Reserve X23", RISCV::FeatureReserveX23, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x24", "Reserve X24", RISCV::FeatureReserveX24, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x25", "Reserve X25", RISCV::FeatureReserveX25, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x26", "Reserve X26", RISCV::FeatureReserveX26, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x27", "Reserve X27", RISCV::FeatureReserveX27, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x28", "Reserve X28", RISCV::FeatureReserveX28, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x29", "Reserve X29", RISCV::FeatureReserveX29, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x3", "Reserve X3", RISCV::FeatureReserveX3, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x30", "Reserve X30", RISCV::FeatureReserveX30, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x31", "Reserve X31", RISCV::FeatureReserveX31, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x4", "Reserve X4", RISCV::FeatureReserveX4, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x5", "Reserve X5", RISCV::FeatureReserveX5, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x6", "Reserve X6", RISCV::FeatureReserveX6, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x7", "Reserve X7", RISCV::FeatureReserveX7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x8", "Reserve X8", RISCV::FeatureReserveX8, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "reserve-x9", "Reserve X9", RISCV::FeatureReserveX9, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "save-restore", "Enable save/restore.", RISCV::FeatureSaveRestore, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "sifive7", "SiFive 7-Series processors", RISCV::TuneSiFive7, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "v", "'V' (Vector Extension for Application Processors)", RISCV::FeatureStdExtV, { { { 0xc000000000ULL, 0x4000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zba", "'Zba' (Address Generation Instructions)", RISCV::FeatureStdExtZba, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zbb", "'Zbb' (Basic Bit-Manipulation)", RISCV::FeatureStdExtZbb, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zbc", "'Zbc' (Carry-Less Multiplication)", RISCV::FeatureStdExtZbc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zbkb", "'Zbkb' (Bitmanip instructions for Cryptography)", RISCV::FeatureStdExtZbkb, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zbkc", "'Zbkc' (Carry-less multiply instructions for Cryptography)", RISCV::FeatureStdExtZbkc, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zbkx", "'Zbkx' (Crossbar permutation instructions)", RISCV::FeatureStdExtZbkx, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zbs", "'Zbs' (Single-Bit Instructions)", RISCV::FeatureStdExtZbs, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zdinx", "'Zdinx' (Double in Integer)", RISCV::FeatureStdExtZdinx, { { { 0x400000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zfh", "'Zfh' (Half-Precision Floating-Point)", RISCV::FeatureStdExtZfh, { { { 0x8000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zfhmin", "'Zfhmin' (Half-Precision Floating-Point Minimal)", RISCV::FeatureStdExtZfhmin, { { { 0x8000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zfinx", "'Zfinx' (Float in Integer)", RISCV::FeatureStdExtZfinx, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zhinx", "'Zhinx' (Half Float in Integer)", RISCV::FeatureStdExtZhinx, { { { 0x400000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zhinxmin", "'Zhinxmin' (Half Float in Integer Minimal)", RISCV::FeatureStdExtZhinxmin, { { { 0x400000000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zk", "'Zk' (Standard scalar cryptography extension)", RISCV::FeatureStdExtZk, { { { 0x4000000000000000ULL, 0x44ULL, 0x0ULL, 0x0ULL, } } } },
  { "zkn", "'Zkn' (NIST Algorithm Suite)", RISCV::FeatureStdExtZkn, { { { 0x8003800000000000ULL, 0x3ULL, 0x0ULL, 0x0ULL, } } } },
  { "zknd", "'Zknd' (NIST Suite: AES Decryption)", RISCV::FeatureStdExtZknd, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zkne", "'Zkne' (NIST Suite: AES Encryption)", RISCV::FeatureStdExtZkne, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zknh", "'Zknh' (NIST Suite: Hash Function Instructions)", RISCV::FeatureStdExtZknh, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zkr", "'Zkr' (Entropy Source Extension)", RISCV::FeatureStdExtZkr, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zks", "'Zks' (ShangMi Algorithm Suite)", RISCV::FeatureStdExtZks, { { { 0x3800000000000ULL, 0x30ULL, 0x0ULL, 0x0ULL, } } } },
  { "zksed", "'Zksed' (ShangMi Suite: SM4 Block Cipher Instructions)", RISCV::FeatureStdExtZksed, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zksh", "'Zksh' (ShangMi Suite: SM3 Hash Function Instructions)", RISCV::FeatureStdExtZksh, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zkt", "'Zkt' (Data Independent Execution Latency)", RISCV::FeatureStdExtZkt, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zve32f", "'Zve32f' (Vector Extensions for Embedded Processors with maximal 32 EEW and F extension)", RISCV::FeatureStdExtZve32f, { { { 0x0ULL, 0x100ULL, 0x0ULL, 0x0ULL, } } } },
  { "zve32x", "'Zve32x' (Vector Extensions for Embedded Processors with maximal 32 EEW)", RISCV::FeatureStdExtZve32x, { { { 0x0ULL, 0x1000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zve64d", "'Zve64d' (Vector Extensions for Embedded Processors with maximal 64 EEW, F and D extension)", RISCV::FeatureStdExtZve64d, { { { 0x0ULL, 0x400ULL, 0x0ULL, 0x0ULL, } } } },
  { "zve64f", "'Zve64f' (Vector Extensions for Embedded Processors with maximal 64 EEW and F extension)", RISCV::FeatureStdExtZve64f, { { { 0x0ULL, 0x880ULL, 0x0ULL, 0x0ULL, } } } },
  { "zve64x", "'Zve64x' (Vector Extensions for Embedded Processors with maximal 64 EEW)", RISCV::FeatureStdExtZve64x, { { { 0x0ULL, 0x2100ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl1024b", "'Zvl' (Minimum Vector Length) 1024", RISCV::FeatureStdExtZvl1024b, { { { 0x0ULL, 0x10000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl128b", "'Zvl' (Minimum Vector Length) 128", RISCV::FeatureStdExtZvl128b, { { { 0x0ULL, 0x2000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl16384b", "'Zvl' (Minimum Vector Length) 16384", RISCV::FeatureStdExtZvl16384b, { { { 0x0ULL, 0x100000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl2048b", "'Zvl' (Minimum Vector Length) 2048", RISCV::FeatureStdExtZvl2048b, { { { 0x0ULL, 0x20000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl256b", "'Zvl' (Minimum Vector Length) 256", RISCV::FeatureStdExtZvl256b, { { { 0x0ULL, 0x4000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl32768b", "'Zvl' (Minimum Vector Length) 32768", RISCV::FeatureStdExtZvl32768b, { { { 0x0ULL, 0x200000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl32b", "'Zvl' (Minimum Vector Length) 32", RISCV::FeatureStdExtZvl32b, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl4096b", "'Zvl' (Minimum Vector Length) 4096", RISCV::FeatureStdExtZvl4096b, { { { 0x0ULL, 0x40000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl512b", "'Zvl' (Minimum Vector Length) 512", RISCV::FeatureStdExtZvl512b, { { { 0x0ULL, 0x8000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl64b", "'Zvl' (Minimum Vector Length) 64", RISCV::FeatureStdExtZvl64b, { { { 0x0ULL, 0x1000ULL, 0x0ULL, 0x0ULL, } } } },
  { "zvl8192b", "'Zvl' (Minimum Vector Length) 8192", RISCV::FeatureStdExtZvl8192b, { { { 0x0ULL, 0x80000ULL, 0x0ULL, 0x0ULL, } } } },
};

#ifdef DBGFIELD
#error "<target>GenSubtargetInfo.inc requires a DBGFIELD macro"
#endif
#if !defined(NDEBUG) || defined(LLVM_ENABLE_DUMP)
#define DBGFIELD(x) x,
#else
#define DBGFIELD(x)
#endif

// ===============================================================
// Data tables for the new per-operand machine model.

// {ProcResourceIdx, Cycles}
extern const llvm::MCWriteProcResEntry RISCVWriteProcResTable[] = {
  { 0,  0}, // Invalid
  { 1,  1}, // #1
  { 7,  1}, // #2
  { 2,  1}, // #3
  { 5, 33}, // #4
  { 5, 34}, // #5
  { 3,  1}, // #6
  { 4, 20}, // #7
  { 4, 25}, // #8
  { 6,  1}, // #9
  { 4,  1}, // #10
  { 3,  1}, // #11
  { 4,  1}, // #12
  { 4,  1}, // #13
  { 5,  1}, // #14
  { 2, 15}, // #15
  { 4,  1}, // #16
  { 5, 16}, // #17
  { 1, 55}, // #18
  { 4,  1}, // #19
  { 5, 56}, // #20
  { 1, 26}, // #21
  { 4,  1}, // #22
  { 5, 27} // #23
}; // RISCVWriteProcResTable

// {Cycles, WriteResourceID}
extern const llvm::MCWriteLatencyEntry RISCVWriteLatencyTable[] = {
  { 0,  0}, // Invalid
  { 1,  0}, // #1 WriteIALU_WriteIALU32_WriteJmp_WriteCSR_WriteFST64_WriteFST32_WriteJal_WriteJalr_WriteJmpReg_WriteNop_WriteSTD_WriteShiftImm_WriteSTW_WriteSTB_WriteAtomicSTD_WriteAtomicSTW_WriteSTH_WriteShiftReg_WriteShiftImm32_WriteShiftReg32
  { 2,  0}, // #2 WriteAtomicD_WriteAtomicW_WriteFLD64_WriteFLD32_WriteLDD_WriteLDW_WriteFClass64_WriteFClass32_WriteFCvtI64ToF64_WriteFCvtF32ToF64_WriteFCvtI32ToF64_WriteFCvtF64ToI64_WriteFCvtF32ToI64_WriteFCvtF64ToF32_WriteFCvtI64ToF32_WriteFCvtI32ToF32_WriteFCvtF64ToI32_WriteFCvtF32ToI32_WriteFCmp64_WriteFCmp32_WriteFMovI64ToF64_WriteFMovI32ToF32_WriteFMovF64ToI64_WriteFMovF32ToI32_WriteAtomicLDD_WriteAtomicLDW_WriteLDWU
  {33,  0}, // #3 WriteIDiv
  {34,  0}, // #4 WriteIDiv32
  { 6,  0}, // #5 WriteFALU64_WriteFMinMax64_WriteFSGNJ64
  { 4,  0}, // #6 WriteFALU32_WriteFMinMax32_WriteFSGNJ32_WriteIMul_WriteIMul32
  {20,  0}, // #7 WriteFDiv64_WriteFDiv32_WriteFSqrt32
  { 7,  0}, // #8 WriteFMA64_WriteFMul64_WriteFALU64
  { 5,  0}, // #9 WriteFMA32_WriteFMul32_WriteFALU32
  {25,  0}, // #10 WriteFSqrt64
  { 3,  0}, // #11 WriteLDB_WriteLDH_WriteIALU_WriteIALU32_WriteAtomicD_WriteAtomicW_WriteLDD_WriteLDW_WriteShiftImm_WriteFClass64_WriteFClass32_WriteFCvtI64ToF64_WriteFCvtF32ToF64_WriteFCvtI32ToF64_WriteFCvtF64ToI64_WriteFCvtF32ToI64_WriteFCvtF64ToF32_WriteFCvtI64ToF32_WriteFCvtI32ToF32_WriteFCvtF64ToI32_WriteFCvtF32ToI32_WriteFCmp64_WriteFCmp32_WriteFMinMax64_WriteFMinMax32_WriteFMovI64ToF64_WriteFMovI32ToF32_WriteFMovF64ToI64_WriteFMovF32ToI32_WriteFSGNJ64_WriteFSGNJ32_WriteAtomicLDD_WriteAtomicLDW_WriteLDWU_WriteIMul_WriteIMul32_WriteShiftReg_WriteShiftImm32_WriteShiftReg32
  {16,  0}, // #12 WriteIDiv_WriteIDiv32
  {56,  0}, // #13 WriteFDiv64_WriteFSqrt64
  {27,  0} // #14 WriteFDiv32_WriteFSqrt32
}; // RISCVWriteLatencyTable

// {UseIdx, WriteResourceID, Cycles}
extern const llvm::MCReadAdvanceEntry RISCVReadAdvanceTable[] = {
  {0,  0,  0}, // Invalid
  {0,  0,  0}, // #1
  {1,  0,  0}, // #2
  {0,  0,  0}, // #3
  {1,  0,  0}, // #4
  {2,  0,  0} // #5
}; // RISCVReadAdvanceTable

// {Name, NumMicroOps, BeginGroup, EndGroup, RetireOOO, WriteProcResIdx,#, WriteLatencyIdx,#, ReadAdvanceIdx,#}
static const llvm::MCSchedClassDesc RocketModelSchedClasses[] = {
  {DBGFIELD("InvalidSchedClass")  8191, false, false, false, 0, 0,  0, 0,  0, 0},
  {DBGFIELD("WriteVAALUV_ReadVAALUV_ReadVAALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #1
  {DBGFIELD("WriteVAALUX_ReadVAALUV_ReadVAALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #2
  {DBGFIELD("WriteVICALUI_ReadVIALUCV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #3
  {DBGFIELD("WriteVICALUV_ReadVIALUCV_ReadVIALUCV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #4
  {DBGFIELD("WriteVICALUX_ReadVIALUCV_ReadVIALUCX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #5
  {DBGFIELD("WriteVIALUI_ReadVIALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #6
  {DBGFIELD("WriteVIALUV_ReadVIALUV_ReadVIALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #7
  {DBGFIELD("WriteVIALUX_ReadVIALUV_ReadVIALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #8
  {DBGFIELD("WriteVCompressV_ReadVCompressV_ReadVCompressV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #9
  {DBGFIELD("WriteVMPopV_ReadVMPopV_ReadVMPopV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #10
  {DBGFIELD("WriteVIDivV_ReadVIDivV_ReadVIDivV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #11
  {DBGFIELD("WriteVIDivX_ReadVIDivV_ReadVIDivX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #12
  {DBGFIELD("WriteVFALUF_ReadVFALUV_ReadVFALUF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #13
  {DBGFIELD("WriteVFALUV_ReadVFALUV_ReadVFALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #14
  {DBGFIELD("WriteVFClassV_ReadVFClassV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #15
  {DBGFIELD("WriteVFCvtIToFV_ReadVFCvtIToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #16
  {DBGFIELD("WriteVFCvtFToIV_ReadVFCvtFToIV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #17
  {DBGFIELD("WriteVFDivF_ReadVFDivV_ReadVFDivF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #18
  {DBGFIELD("WriteVFDivV_ReadVFDivV_ReadVFDivV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #19
  {DBGFIELD("WriteVMFFSV_ReadVMFFSV_ReadVMFFSV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #20
  {DBGFIELD("WriteVFMulAddF_ReadVFMulAddV_ReadVFMulAddV_ReadVFMulAddF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #21
  {DBGFIELD("WriteVFMulAddV_ReadVFMulAddV_ReadVFMulAddV_ReadVFMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #22
  {DBGFIELD("WriteVFCmpF_ReadVFCmpV_ReadVFCmpF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #23
  {DBGFIELD("WriteVFCmpV_ReadVFCmpV_ReadVFCmpV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #24
  {DBGFIELD("WriteVFMergeV_ReadVFMergeV_ReadVFMergeF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #25
  {DBGFIELD("WriteVFMulF_ReadVFMulV_ReadVFMulF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #26
  {DBGFIELD("WriteVFMulV_ReadVFMulV_ReadVFMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #27
  {DBGFIELD("WriteVFMovVF_ReadVFMovVF") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #28
  {DBGFIELD("WriteVFMovFV_ReadVFMovFV_ReadVFMovFX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #29
  {DBGFIELD("WriteVFMovV_ReadVFMovF") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #30
  {DBGFIELD("WriteVFNCvtFToFV_ReadVFNCvtFToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #31
  {DBGFIELD("WriteVFNCvtIToFV_ReadVFNCvtIToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #32
  {DBGFIELD("WriteVFNCvtFToIV_ReadVFNCvtFToIV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #33
  {DBGFIELD("WriteVFRecpV_ReadVFRecpV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #34
  {DBGFIELD("WriteVFRedV_ReadVFRedV_ReadVFRedV_ReadVFRedV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #35
  {DBGFIELD("WriteVFRedOV_ReadVFRedOV_ReadVFRedOV_ReadVFRedOV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #36
  {DBGFIELD("WriteVFSgnjF_ReadVFSgnjV_ReadVFSgnjF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #37
  {DBGFIELD("WriteVFSgnjV_ReadVFSgnjV_ReadVFSgnjV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #38
  {DBGFIELD("WriteVFSlide1F_ReadVFSlideV_ReadVFSlideF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #39
  {DBGFIELD("WriteVFSqrtV_ReadVFSqrtV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #40
  {DBGFIELD("WriteVFWALUF_ReadVFWALUV_ReadVFWALUF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #41
  {DBGFIELD("WriteVFWALUV_ReadVFWALUV_ReadVFWALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #42
  {DBGFIELD("WriteVFWCvtFToFV_ReadVFWCvtFToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #43
  {DBGFIELD("WriteVFWCvtIToFV_ReadVFWCvtIToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #44
  {DBGFIELD("WriteVFWCvtFToIV_ReadVFWCvtFToIV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #45
  {DBGFIELD("WriteVFWMulAddF_ReadVFWMulAddV_ReadVFWMulAddV_ReadVFWMulAddF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #46
  {DBGFIELD("WriteVFWMulAddV_ReadVFWMulAddV_ReadVFWMulAddV_ReadVFWMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #47
  {DBGFIELD("WriteVFWMulF_ReadVFWMulV_ReadVFWMulF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #48
  {DBGFIELD("WriteVFWMulV_ReadVFWMulV_ReadVFWMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #49
  {DBGFIELD("WriteVFWRedV_ReadVFWRedV_ReadVFWRedV_ReadVFWRedV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #50
  {DBGFIELD("WriteVMIdxV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #51
  {DBGFIELD("WriteVMIotV_ReadVMIotV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #52
  {DBGFIELD("WriteVLDFF16_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #53
  {DBGFIELD("WriteVLDE16_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #54
  {DBGFIELD("WriteVLDFF32_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #55
  {DBGFIELD("WriteVLDE32_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #56
  {DBGFIELD("WriteVLDFF64_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #57
  {DBGFIELD("WriteVLDE64_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #58
  {DBGFIELD("WriteVLDFF8_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #59
  {DBGFIELD("WriteVLDE8_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #60
  {DBGFIELD("WriteVLDM_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #61
  {DBGFIELD("WriteVLDOX16_ReadVLDX_ReadVLDOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #62
  {DBGFIELD("WriteVLDOX32_ReadVLDX_ReadVLDOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #63
  {DBGFIELD("WriteVLDOX64_ReadVLDX_ReadVLDOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #64
  {DBGFIELD("WriteVLDOX8_ReadVLDX_ReadVLDOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #65
  {DBGFIELD("WriteVLDS16_ReadVLDX_ReadVLDSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #66
  {DBGFIELD("WriteVLDS32_ReadVLDX_ReadVLDSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #67
  {DBGFIELD("WriteVLDS64_ReadVLDX_ReadVLDSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #68
  {DBGFIELD("WriteVLDS8_ReadVLDX_ReadVLDSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #69
  {DBGFIELD("WriteVLDUX16_ReadVLDX_ReadVLDUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #70
  {DBGFIELD("WriteVLDUX32_ReadVLDX_ReadVLDUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #71
  {DBGFIELD("WriteVLDUX64_ReadVLDX_ReadVLDUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #72
  {DBGFIELD("WriteVLDUX8_ReadVLDX_ReadVLDUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #73
  {DBGFIELD("WriteVIMulAddV_ReadVIMulAddV_ReadVIMulAddV_ReadVIMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #74
  {DBGFIELD("WriteVIMulAddX_ReadVIMulAddV_ReadVIMulAddV_ReadVIMulAddX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #75
  {DBGFIELD("WriteVICALUI_ReadVIALUCV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #76
  {DBGFIELD("WriteVICALUV_ReadVIALUCV_ReadVIALUCV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #77
  {DBGFIELD("WriteVICALUX_ReadVIALUCV_ReadVIALUCX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #78
  {DBGFIELD("WriteVMALUV_ReadVMALUV_ReadVMALUV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #79
  {DBGFIELD("WriteVICmpV_ReadVICmpV_ReadVICmpV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #80
  {DBGFIELD("WriteVICmpX_ReadVICmpV_ReadVICmpX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #81
  {DBGFIELD("WriteVIMergeI_ReadVIMergeV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #82
  {DBGFIELD("WriteVIMergeV_ReadVIMergeV_ReadVIMergeV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #83
  {DBGFIELD("WriteVIMergeX_ReadVIMergeV_ReadVIMergeX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #84
  {DBGFIELD("WriteVMSFSV_ReadVMSFSV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #85
  {DBGFIELD("WriteVICmpI_ReadVICmpV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #86
  {DBGFIELD("WriteVIMulV_ReadVIMulV_ReadVIMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #87
  {DBGFIELD("WriteVIMulX_ReadVIMulV_ReadVIMulX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #88
  {DBGFIELD("WriteVIMovXV_ReadVIMovXV_ReadVIMovXX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #89
  {DBGFIELD("WriteVIMovI")        8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #90
  {DBGFIELD("WriteVIMovV_ReadVIMovV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #91
  {DBGFIELD("WriteVIMovX_ReadVIMovX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #92
  {DBGFIELD("WriteVIMovVX_ReadVIMovVX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #93
  {DBGFIELD("WriteVNClipI_ReadVNClipV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #94
  {DBGFIELD("WriteVNClipV_ReadVNClipV_ReadVNClipV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #95
  {DBGFIELD("WriteVNClipX_ReadVNClipV_ReadVNClipX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #96
  {DBGFIELD("WriteVNShiftI_ReadVNShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #97
  {DBGFIELD("WriteVNShiftV_ReadVNShiftV_ReadVNShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #98
  {DBGFIELD("WriteVNShiftX_ReadVNShiftV_ReadVNShiftX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #99
  {DBGFIELD("WriteVIRedV_ReadVIRedV_ReadVIRedV_ReadVIRedV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #100
  {DBGFIELD("WriteVGatherV_ReadVGatherV_ReadVGatherV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #101
  {DBGFIELD("WriteVGatherI_ReadVGatherV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #102
  {DBGFIELD("WriteVGatherV_ReadVGatherV_ReadVGatherV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #103
  {DBGFIELD("WriteVGatherX_ReadVGatherV_ReadVGatherX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #104
  {DBGFIELD("WriteVSALUI_ReadVSALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #105
  {DBGFIELD("WriteVSALUV_ReadVSALUV_ReadVSALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #106
  {DBGFIELD("WriteVSALUX_ReadVSALUV_ReadVSALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #107
  {DBGFIELD("WriteVSTE16_ReadVSTE16V_ReadVSTX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #108
  {DBGFIELD("WriteVSTE32_ReadVSTE32V_ReadVSTX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #109
  {DBGFIELD("WriteVSTE64_ReadVSTE64V_ReadVSTX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #110
  {DBGFIELD("WriteVSTE8_ReadVSTE8V_ReadVSTX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #111
  {DBGFIELD("WriteVExtV_ReadVExtV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #112
  {DBGFIELD("WriteVISlide1X_ReadVISlideV_ReadVISlideX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #113
  {DBGFIELD("WriteVISlideI_ReadVISlideV_ReadVISlideV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #114
  {DBGFIELD("WriteVISlideX_ReadVISlideV_ReadVISlideV_ReadVISlideX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #115
  {DBGFIELD("WriteVShiftI_ReadVShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #116
  {DBGFIELD("WriteVShiftV_ReadVShiftV_ReadVShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #117
  {DBGFIELD("WriteVShiftX_ReadVShiftV_ReadVShiftX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #118
  {DBGFIELD("WriteVSMulV_ReadVSMulV_ReadVSMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #119
  {DBGFIELD("WriteVSMulX_ReadVSMulV_ReadVSMulX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #120
  {DBGFIELD("WriteVSTM_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #121
  {DBGFIELD("WriteVSTOX16_ReadVSTOX16_ReadVSTX_ReadVSTOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #122
  {DBGFIELD("WriteVSTOX32_ReadVSTOX32_ReadVSTX_ReadVSTOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #123
  {DBGFIELD("WriteVSTOX64_ReadVSTOX64_ReadVSTX_ReadVSTOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #124
  {DBGFIELD("WriteVSTOX8_ReadVSTOX8_ReadVSTX_ReadVSTOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #125
  {DBGFIELD("WriteVSTS16_ReadVSTS16V_ReadVSTX_ReadVSTSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #126
  {DBGFIELD("WriteVSTS32_ReadVSTS32V_ReadVSTX_ReadVSTSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #127
  {DBGFIELD("WriteVSTS64_ReadVSTS64V_ReadVSTX_ReadVSTSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #128
  {DBGFIELD("WriteVSTS8_ReadVSTS8V_ReadVSTX_ReadVSTSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #129
  {DBGFIELD("WriteVSShiftI_ReadVSShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #130
  {DBGFIELD("WriteVSShiftV_ReadVSShiftV_ReadVSShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #131
  {DBGFIELD("WriteVSShiftX_ReadVSShiftV_ReadVSShiftX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #132
  {DBGFIELD("WriteVSTUX16_ReadVSTUX16_ReadVSTX_ReadVSTUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #133
  {DBGFIELD("WriteVSTUX32_ReadVSTUX32_ReadVSTX_ReadVSTUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #134
  {DBGFIELD("WriteVSTUX64_ReadVSTUX64_ReadVSTX_ReadVSTUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #135
  {DBGFIELD("WriteVSTUX8_ReadVSTUX8_ReadVSTX_ReadVSTUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #136
  {DBGFIELD("WriteVIWALUV_ReadVIWALUV_ReadVIWALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #137
  {DBGFIELD("WriteVIWALUX_ReadVIWALUV_ReadVIWALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #138
  {DBGFIELD("WriteVIWMulAddV_ReadVIWMulAddV_ReadVIWMulAddV_ReadVIWMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #139
  {DBGFIELD("WriteVIWMulAddX_ReadVIWMulAddV_ReadVIWMulAddV_ReadVIWMulAddX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #140
  {DBGFIELD("WriteVIWMulV_ReadVIWMulV_ReadVIWMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #141
  {DBGFIELD("WriteVIWMulX_ReadVIWMulV_ReadVIWMulX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #142
  {DBGFIELD("WriteVIWRedV_ReadVIWRedV_ReadVIWRedV_ReadVIWRedV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #143
  {DBGFIELD("WriteIALU_ReadIALU_ReadIALU") 1, false, false, false,  1, 1,  1, 1,  1, 2}, // #144
  {DBGFIELD("WriteIALU_ReadIALU") 1, false, false, false,  1, 1,  1, 1,  0, 1}, // #145
  {DBGFIELD("WriteIALU32_ReadIALU32") 1, false, false, false,  1, 1,  1, 1,  0, 1}, // #146
  {DBGFIELD("WriteIALU32_ReadIALU32_ReadIALU32") 1, false, false, false,  1, 1,  1, 1,  1, 2}, // #147
  {DBGFIELD("WriteAtomicD_ReadAtomicDA_ReadAtomicDD") 1, false, false, false,  2, 1,  2, 1,  1, 2}, // #148
  {DBGFIELD("WriteAtomicW_ReadAtomicWA_ReadAtomicWD") 1, false, false, false,  2, 1,  2, 1,  1, 2}, // #149
  {DBGFIELD("WriteIALU")          1, false, false, false,  1, 1,  1, 1,  0, 0}, // #150
  {DBGFIELD("WriteSingleBit_ReadSingleBit_ReadSingleBit") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #151
  {DBGFIELD("WriteSingleBitImm_ReadSingleBitImm") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #152
  {DBGFIELD("WriteJmp_ReadJmp_ReadJmp") 1, false, false, false,  3, 1,  1, 1,  1, 2}, // #153
  {DBGFIELD("WriteBFP_ReadBFP_ReadBFP") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #154
  {DBGFIELD("WriteBFP32_ReadBFP32_ReadBFP32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #155
  {DBGFIELD("WriteCLMUL_ReadCLMUL_ReadCLMUL") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #156
  {DBGFIELD("WriteCLZ_ReadCLZ")   8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #157
  {DBGFIELD("WriteCLZ32_ReadCLZ32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #158
  {DBGFIELD("WriteCPOP_ReadCPOP") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #159
  {DBGFIELD("WriteCPOP32_ReadCPOP32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #160
  {DBGFIELD("WriteCSR_ReadCSR")   1, false, false, false,  0, 0,  1, 1,  0, 1}, // #161
  {DBGFIELD("WriteCSR")           1, false, false, false,  0, 0,  1, 1,  0, 0}, // #162
  {DBGFIELD("WriteCTZ_ReadCTZ")   8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #163
  {DBGFIELD("WriteCTZ32_ReadCTZ32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #164
  {DBGFIELD("WriteJmp")           1, false, false, false,  3, 1,  1, 1,  0, 0}, // #165
  {DBGFIELD("WriteFLD64_ReadMemBase") 1, false, false, false,  2, 1,  2, 1,  0, 1}, // #166
  {DBGFIELD("WriteFLD32_ReadMemBase") 1, false, false, false,  2, 1,  2, 1,  0, 1}, // #167
  {DBGFIELD("WriteFST64_ReadStoreData_ReadMemBase") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #168
  {DBGFIELD("WriteFST32_ReadStoreData_ReadMemBase") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #169
  {DBGFIELD("WriteJal")           1, false, false, false,  3, 1,  1, 1,  0, 0}, // #170
  {DBGFIELD("WriteJalr_ReadJalr") 1, false, false, false,  3, 1,  1, 1,  0, 1}, // #171
  {DBGFIELD("WriteJmpReg")        1, false, false, false,  3, 1,  1, 1,  0, 0}, // #172
  {DBGFIELD("WriteLDD_ReadMemBase") 1, false, false, false,  2, 1,  2, 1,  0, 1}, // #173
  {DBGFIELD("WriteLDW_ReadMemBase") 1, false, false, false,  2, 1,  2, 1,  0, 1}, // #174
  {DBGFIELD("WriteNop")           1, false, false, false,  0, 0,  1, 1,  0, 0}, // #175
  {DBGFIELD("WriteSTD_ReadStoreData_ReadMemBase") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #176
  {DBGFIELD("WriteShiftImm_ReadShiftImm") 1, false, false, false,  1, 1,  1, 1,  0, 1}, // #177
  {DBGFIELD("WriteSTW_ReadStoreData_ReadMemBase") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #178
  {DBGFIELD("WriteIDiv_ReadIDiv_ReadIDiv") 1, false, false, false,  4, 1,  3, 1,  1, 2}, // #179
  {DBGFIELD("WriteIDiv32_ReadIDiv32_ReadIDiv32") 1, false, false, false,  5, 1,  4, 1,  1, 2}, // #180
  {DBGFIELD("WriteFALU64_ReadFALU64_ReadFALU64") 1, false, false, false,  6, 1,  5, 1,  1, 2}, // #181
  {DBGFIELD("WriteFALU16_ReadFALU16_ReadFALU16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #182
  {DBGFIELD("WriteFALU32_ReadFALU32_ReadFALU32") 1, false, false, false,  6, 1,  6, 1,  1, 2}, // #183
  {DBGFIELD("WriteFClass64_ReadFClass64") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #184
  {DBGFIELD("WriteFClass16_ReadFClass16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #185
  {DBGFIELD("WriteFClass32_ReadFClass32") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #186
  {DBGFIELD("WriteFCvtF16ToF64_ReadFCvtF16ToF64") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #187
  {DBGFIELD("WriteFCvtI64ToF64_ReadFCvtI64ToF64") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #188
  {DBGFIELD("WriteFCvtF32ToF64_ReadFCvtF32ToF64") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #189
  {DBGFIELD("WriteFCvtI32ToF64_ReadFCvtI32ToF64") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #190
  {DBGFIELD("WriteFCvtF64ToF16_ReadFCvtF64ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #191
  {DBGFIELD("WriteFCvtI64ToF16_ReadFCvtI64ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #192
  {DBGFIELD("WriteFCvtF32ToF16_ReadFCvtF32ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #193
  {DBGFIELD("WriteFCvtI32ToF16_ReadFCvtI32ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #194
  {DBGFIELD("WriteFCvtF64ToI64_ReadFCvtF64ToI64") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #195
  {DBGFIELD("WriteFCvtF16ToI64_ReadFCvtF16ToI64") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #196
  {DBGFIELD("WriteFCvtF32ToI64_ReadFCvtF32ToI64") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #197
  {DBGFIELD("WriteFCvtF64ToF32_ReadFCvtF64ToF32") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #198
  {DBGFIELD("WriteFCvtF16ToF32_ReadFCvtF16ToF32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #199
  {DBGFIELD("WriteFCvtI64ToF32_ReadFCvtI64ToF32") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #200
  {DBGFIELD("WriteFCvtI32ToF32_ReadFCvtI32ToF32") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #201
  {DBGFIELD("WriteFCvtF64ToI32_ReadFCvtF64ToI32") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #202
  {DBGFIELD("WriteFCvtF16ToI32_ReadFCvtF16ToI32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #203
  {DBGFIELD("WriteFCvtF32ToI32_ReadFCvtF32ToI32") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #204
  {DBGFIELD("WriteFDiv64_ReadFDiv64_ReadFDiv64") 1, false, false, false,  7, 1,  7, 1,  1, 2}, // #205
  {DBGFIELD("WriteFDiv16_ReadFDiv16_ReadFDiv16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #206
  {DBGFIELD("WriteFDiv32_ReadFDiv32_ReadFDiv32") 1, false, false, false,  7, 1,  7, 1,  1, 2}, // #207
  {DBGFIELD("WriteFCmp64_ReadFCmp64_ReadFCmp64") 1, false, false, false,  6, 1,  2, 1,  1, 2}, // #208
  {DBGFIELD("WriteFCmp16_ReadFCmp16_ReadFCmp16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #209
  {DBGFIELD("WriteFCmp32_ReadFCmp32_ReadFCmp32") 1, false, false, false,  6, 1,  2, 1,  1, 2}, // #210
  {DBGFIELD("WriteFLD64_ReadFMemBase") 1, false, false, false,  2, 1,  2, 1,  0, 1}, // #211
  {DBGFIELD("WriteFLD16_ReadFMemBase") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #212
  {DBGFIELD("WriteFLD32_ReadFMemBase") 1, false, false, false,  2, 1,  2, 1,  0, 1}, // #213
  {DBGFIELD("WriteFMA64_ReadFMA64_ReadFMA64_ReadFMA64") 1, false, false, false,  6, 1,  8, 1,  3, 3}, // #214
  {DBGFIELD("WriteFMA16_ReadFMA16_ReadFMA16_ReadFMA16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #215
  {DBGFIELD("WriteFMA32_ReadFMA32_ReadFMA32_ReadFMA32") 1, false, false, false,  6, 1,  9, 1,  3, 3}, // #216
  {DBGFIELD("WriteFMinMax64_ReadFMinMax64_ReadFMinMax64") 1, false, false, false,  6, 1,  5, 1,  1, 2}, // #217
  {DBGFIELD("WriteFMinMax16_ReadFMinMax16_ReadFMinMax16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #218
  {DBGFIELD("WriteFMinMax32_ReadFMinMax32_ReadFMinMax32") 1, false, false, false,  6, 1,  6, 1,  1, 2}, // #219
  {DBGFIELD("WriteFMul64_ReadFMul64_ReadFMul64") 1, false, false, false,  6, 1,  8, 1,  1, 2}, // #220
  {DBGFIELD("WriteFMul16_ReadFMul16_ReadFMul16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #221
  {DBGFIELD("WriteFMul32_ReadFMul32_ReadFMul32") 1, false, false, false,  6, 1,  9, 1,  1, 2}, // #222
  {DBGFIELD("WriteFMovI64ToF64_ReadFMovI64ToF64") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #223
  {DBGFIELD("WriteFMovI16ToF16_ReadFMovI16ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #224
  {DBGFIELD("WriteFMovI32ToF32_ReadFMovI32ToF32") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #225
  {DBGFIELD("WriteFMovF64ToI64_ReadFMovF64ToI64") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #226
  {DBGFIELD("WriteFMovF16ToI16_ReadFMovF16ToI16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #227
  {DBGFIELD("WriteFMovF32ToI32_ReadFMovF32ToI32") 1, false, false, false,  6, 1,  2, 1,  0, 1}, // #228
  {DBGFIELD("WriteFST64_ReadStoreData_ReadFMemBase") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #229
  {DBGFIELD("WriteFSGNJ64_ReadFSGNJ64_ReadFSGNJ64") 1, false, false, false,  6, 1,  5, 1,  1, 2}, // #230
  {DBGFIELD("WriteFSGNJ16_ReadFSGNJ16_ReadFSGNJ16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #231
  {DBGFIELD("WriteFSGNJ32_ReadFSGNJ32_ReadFSGNJ32") 1, false, false, false,  6, 1,  6, 1,  1, 2}, // #232
  {DBGFIELD("WriteFST16_ReadStoreData_ReadFMemBase") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #233
  {DBGFIELD("WriteFSqrt64_ReadFSqrt64") 1, false, false, false,  8, 1, 10, 1,  0, 1}, // #234
  {DBGFIELD("WriteFSqrt16_ReadFSqrt16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #235
  {DBGFIELD("WriteFSqrt32_ReadFSqrt32") 1, false, false, false,  7, 1,  7, 1,  0, 1}, // #236
  {DBGFIELD("WriteFST32_ReadStoreData_ReadFMemBase") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #237
  {DBGFIELD("WriteLDB_ReadMemBase") 1, false, false, false,  2, 1, 11, 1,  0, 1}, // #238
  {DBGFIELD("WriteLDH_ReadMemBase") 1, false, false, false,  2, 1, 11, 1,  0, 1}, // #239
  {DBGFIELD("WriteAtomicLDD_ReadAtomicLDD") 1, false, false, false,  2, 1,  2, 1,  0, 1}, // #240
  {DBGFIELD("WriteAtomicLDW_ReadAtomicLDW") 1, false, false, false,  2, 1,  2, 1,  0, 1}, // #241
  {DBGFIELD("WriteLDWU_ReadMemBase") 1, false, false, false,  2, 1,  2, 1,  0, 1}, // #242
  {DBGFIELD("WriteIMul_ReadIMul_ReadIMul") 1, false, false, false,  9, 1,  6, 1,  1, 2}, // #243
  {DBGFIELD("WriteIMul32_ReadIMul32_ReadIMul32") 1, false, false, false,  9, 1,  6, 1,  1, 2}, // #244
  {DBGFIELD("WriteORCB_ReadORCB") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #245
  {DBGFIELD("WriteREV8_ReadREV8") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #246
  {DBGFIELD("WriteRotateReg_ReadRotateReg_ReadRotateReg") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #247
  {DBGFIELD("WriteRotateReg32_ReadRotateReg32_ReadRotateReg32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #248
  {DBGFIELD("WriteRotateImm_ReadRotateImm") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #249
  {DBGFIELD("WriteRotateImm32_ReadRotateImm32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #250
  {DBGFIELD("WriteSTB_ReadStoreData_ReadMemBase") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #251
  {DBGFIELD("WriteAtomicSTD_ReadAtomicSTD_ReadAtomicSTD") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #252
  {DBGFIELD("WriteAtomicSTW_ReadAtomicSTW_ReadAtomicSTW") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #253
  {DBGFIELD("WriteSTH_ReadStoreData_ReadMemBase") 1, false, false, false,  2, 1,  1, 1,  1, 2}, // #254
  {DBGFIELD("WriteSHXADD_ReadSHXADD_ReadSHXADD") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #255
  {DBGFIELD("WriteSHXADD32_ReadSHXADD32_ReadSHXADD32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #256
  {DBGFIELD("WriteShiftReg_ReadShiftReg_ReadShiftReg") 1, false, false, false,  1, 1,  1, 1,  1, 2}, // #257
  {DBGFIELD("WriteShiftImm32_ReadShiftImm32") 1, false, false, false,  1, 1,  1, 1,  0, 1}, // #258
  {DBGFIELD("WriteShiftReg32_ReadShiftReg32_ReadShiftReg32") 1, false, false, false,  1, 1,  1, 1,  1, 2}, // #259
  {DBGFIELD("WriteVMPopV_ReadVMPopV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #260
  {DBGFIELD("WriteVMFFSV_ReadVMFFSV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #261
  {DBGFIELD("WriteVFMulAddF_ReadVFMulAddV_ReadVFMulAddF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #262
  {DBGFIELD("WriteVFMulAddV_ReadVFMulAddV_ReadVFMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #263
  {DBGFIELD("WriteVFRedV_ReadVFRedV_ReadVFRedV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #264
  {DBGFIELD("WriteVFRedOV_ReadVFRedOV_ReadVFRedOV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #265
  {DBGFIELD("WriteVFWMulAddF_ReadVFWMulAddV_ReadVFWMulAddF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #266
  {DBGFIELD("WriteVFWMulAddV_ReadVFWMulAddV_ReadVFWMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #267
  {DBGFIELD("WriteVFWRedOV_ReadVFWRedOV_ReadVFWRedOV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #268
  {DBGFIELD("WriteVFWRedV_ReadVFWRedV_ReadVFWRedV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #269
  {DBGFIELD("WriteVLD1R16_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #270
  {DBGFIELD("WriteVLD1R32_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #271
  {DBGFIELD("WriteVLD1R64_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #272
  {DBGFIELD("WriteVLD1R8_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #273
  {DBGFIELD("WriteVLD2R16_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #274
  {DBGFIELD("WriteVLD2R32_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #275
  {DBGFIELD("WriteVLD2R64_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #276
  {DBGFIELD("WriteVLD2R8_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #277
  {DBGFIELD("WriteVLD4R16_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #278
  {DBGFIELD("WriteVLD4R32_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #279
  {DBGFIELD("WriteVLD4R64_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #280
  {DBGFIELD("WriteVLD4R8_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #281
  {DBGFIELD("WriteVLD8R16_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #282
  {DBGFIELD("WriteVLD8R32_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #283
  {DBGFIELD("WriteVLD8R64_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #284
  {DBGFIELD("WriteVLD8R8_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #285
  {DBGFIELD("WriteVIMulAddV_ReadVIMulAddV_ReadVIMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #286
  {DBGFIELD("WriteVIMulAddX_ReadVIMulAddV_ReadVIMulAddX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #287
  {DBGFIELD("WriteVICmpV_ReadVICmpV_ReadVICmpX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #288
  {DBGFIELD("WriteVMov1V_ReadVMov1V") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #289
  {DBGFIELD("WriteVMov2V_ReadVMov2V") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #290
  {DBGFIELD("WriteVMov4V_ReadVMov4V") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #291
  {DBGFIELD("WriteVMov8V_ReadVMov8V") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #292
  {DBGFIELD("WriteVIRedV_ReadVIRedV_ReadVIRedV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #293
  {DBGFIELD("WriteVIALUV_ReadVIALUV_ReadVIALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #294
  {DBGFIELD("WriteVST1R_ReadVST1R_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #295
  {DBGFIELD("WriteVST2R_ReadVST2R_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #296
  {DBGFIELD("WriteVST4R_ReadVST4R_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #297
  {DBGFIELD("WriteVST8R_ReadVST8R_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #298
  {DBGFIELD("WriteVISlideI_ReadVISlideV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #299
  {DBGFIELD("WriteVISlideX_ReadVISlideV_ReadVISlideX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #300
  {DBGFIELD("WriteVSTM_ReadVSTM_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #301
  {DBGFIELD("WriteVIWMulAddV_ReadVIWMulAddV_ReadVIWMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #302
  {DBGFIELD("WriteVIWMulAddX_ReadVIWMulAddV_ReadVIWMulAddX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #303
  {DBGFIELD("WriteVIWRedV_ReadVIWRedV_ReadVIWRedV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #304
  {DBGFIELD("COPY")               1, false, false, false,  1, 1,  1, 1,  0, 0}, // #305
}; // RocketModelSchedClasses

// {Name, NumMicroOps, BeginGroup, EndGroup, RetireOOO, WriteProcResIdx,#, WriteLatencyIdx,#, ReadAdvanceIdx,#}
static const llvm::MCSchedClassDesc SiFive7ModelSchedClasses[] = {
  {DBGFIELD("InvalidSchedClass")  8191, false, false, false, 0, 0,  0, 0,  0, 0},
  {DBGFIELD("WriteVAALUV_ReadVAALUV_ReadVAALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #1
  {DBGFIELD("WriteVAALUX_ReadVAALUV_ReadVAALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #2
  {DBGFIELD("WriteVICALUI_ReadVIALUCV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #3
  {DBGFIELD("WriteVICALUV_ReadVIALUCV_ReadVIALUCV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #4
  {DBGFIELD("WriteVICALUX_ReadVIALUCV_ReadVIALUCX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #5
  {DBGFIELD("WriteVIALUI_ReadVIALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #6
  {DBGFIELD("WriteVIALUV_ReadVIALUV_ReadVIALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #7
  {DBGFIELD("WriteVIALUX_ReadVIALUV_ReadVIALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #8
  {DBGFIELD("WriteVCompressV_ReadVCompressV_ReadVCompressV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #9
  {DBGFIELD("WriteVMPopV_ReadVMPopV_ReadVMPopV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #10
  {DBGFIELD("WriteVIDivV_ReadVIDivV_ReadVIDivV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #11
  {DBGFIELD("WriteVIDivX_ReadVIDivV_ReadVIDivX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #12
  {DBGFIELD("WriteVFALUF_ReadVFALUV_ReadVFALUF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #13
  {DBGFIELD("WriteVFALUV_ReadVFALUV_ReadVFALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #14
  {DBGFIELD("WriteVFClassV_ReadVFClassV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #15
  {DBGFIELD("WriteVFCvtIToFV_ReadVFCvtIToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #16
  {DBGFIELD("WriteVFCvtFToIV_ReadVFCvtFToIV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #17
  {DBGFIELD("WriteVFDivF_ReadVFDivV_ReadVFDivF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #18
  {DBGFIELD("WriteVFDivV_ReadVFDivV_ReadVFDivV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #19
  {DBGFIELD("WriteVMFFSV_ReadVMFFSV_ReadVMFFSV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #20
  {DBGFIELD("WriteVFMulAddF_ReadVFMulAddV_ReadVFMulAddV_ReadVFMulAddF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #21
  {DBGFIELD("WriteVFMulAddV_ReadVFMulAddV_ReadVFMulAddV_ReadVFMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #22
  {DBGFIELD("WriteVFCmpF_ReadVFCmpV_ReadVFCmpF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #23
  {DBGFIELD("WriteVFCmpV_ReadVFCmpV_ReadVFCmpV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #24
  {DBGFIELD("WriteVFMergeV_ReadVFMergeV_ReadVFMergeF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #25
  {DBGFIELD("WriteVFMulF_ReadVFMulV_ReadVFMulF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #26
  {DBGFIELD("WriteVFMulV_ReadVFMulV_ReadVFMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #27
  {DBGFIELD("WriteVFMovVF_ReadVFMovVF") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #28
  {DBGFIELD("WriteVFMovFV_ReadVFMovFV_ReadVFMovFX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #29
  {DBGFIELD("WriteVFMovV_ReadVFMovF") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #30
  {DBGFIELD("WriteVFNCvtFToFV_ReadVFNCvtFToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #31
  {DBGFIELD("WriteVFNCvtIToFV_ReadVFNCvtIToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #32
  {DBGFIELD("WriteVFNCvtFToIV_ReadVFNCvtFToIV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #33
  {DBGFIELD("WriteVFRecpV_ReadVFRecpV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #34
  {DBGFIELD("WriteVFRedV_ReadVFRedV_ReadVFRedV_ReadVFRedV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #35
  {DBGFIELD("WriteVFRedOV_ReadVFRedOV_ReadVFRedOV_ReadVFRedOV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #36
  {DBGFIELD("WriteVFSgnjF_ReadVFSgnjV_ReadVFSgnjF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #37
  {DBGFIELD("WriteVFSgnjV_ReadVFSgnjV_ReadVFSgnjV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #38
  {DBGFIELD("WriteVFSlide1F_ReadVFSlideV_ReadVFSlideF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #39
  {DBGFIELD("WriteVFSqrtV_ReadVFSqrtV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #40
  {DBGFIELD("WriteVFWALUF_ReadVFWALUV_ReadVFWALUF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #41
  {DBGFIELD("WriteVFWALUV_ReadVFWALUV_ReadVFWALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #42
  {DBGFIELD("WriteVFWCvtFToFV_ReadVFWCvtFToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #43
  {DBGFIELD("WriteVFWCvtIToFV_ReadVFWCvtIToFV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #44
  {DBGFIELD("WriteVFWCvtFToIV_ReadVFWCvtFToIV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #45
  {DBGFIELD("WriteVFWMulAddF_ReadVFWMulAddV_ReadVFWMulAddV_ReadVFWMulAddF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #46
  {DBGFIELD("WriteVFWMulAddV_ReadVFWMulAddV_ReadVFWMulAddV_ReadVFWMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #47
  {DBGFIELD("WriteVFWMulF_ReadVFWMulV_ReadVFWMulF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #48
  {DBGFIELD("WriteVFWMulV_ReadVFWMulV_ReadVFWMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #49
  {DBGFIELD("WriteVFWRedV_ReadVFWRedV_ReadVFWRedV_ReadVFWRedV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #50
  {DBGFIELD("WriteVMIdxV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #51
  {DBGFIELD("WriteVMIotV_ReadVMIotV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #52
  {DBGFIELD("WriteVLDFF16_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #53
  {DBGFIELD("WriteVLDE16_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #54
  {DBGFIELD("WriteVLDFF32_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #55
  {DBGFIELD("WriteVLDE32_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #56
  {DBGFIELD("WriteVLDFF64_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #57
  {DBGFIELD("WriteVLDE64_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #58
  {DBGFIELD("WriteVLDFF8_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #59
  {DBGFIELD("WriteVLDE8_ReadVLDX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #60
  {DBGFIELD("WriteVLDM_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #61
  {DBGFIELD("WriteVLDOX16_ReadVLDX_ReadVLDOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #62
  {DBGFIELD("WriteVLDOX32_ReadVLDX_ReadVLDOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #63
  {DBGFIELD("WriteVLDOX64_ReadVLDX_ReadVLDOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #64
  {DBGFIELD("WriteVLDOX8_ReadVLDX_ReadVLDOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #65
  {DBGFIELD("WriteVLDS16_ReadVLDX_ReadVLDSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #66
  {DBGFIELD("WriteVLDS32_ReadVLDX_ReadVLDSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #67
  {DBGFIELD("WriteVLDS64_ReadVLDX_ReadVLDSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #68
  {DBGFIELD("WriteVLDS8_ReadVLDX_ReadVLDSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #69
  {DBGFIELD("WriteVLDUX16_ReadVLDX_ReadVLDUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #70
  {DBGFIELD("WriteVLDUX32_ReadVLDX_ReadVLDUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #71
  {DBGFIELD("WriteVLDUX64_ReadVLDX_ReadVLDUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #72
  {DBGFIELD("WriteVLDUX8_ReadVLDX_ReadVLDUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #73
  {DBGFIELD("WriteVIMulAddV_ReadVIMulAddV_ReadVIMulAddV_ReadVIMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #74
  {DBGFIELD("WriteVIMulAddX_ReadVIMulAddV_ReadVIMulAddV_ReadVIMulAddX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #75
  {DBGFIELD("WriteVICALUI_ReadVIALUCV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #76
  {DBGFIELD("WriteVICALUV_ReadVIALUCV_ReadVIALUCV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #77
  {DBGFIELD("WriteVICALUX_ReadVIALUCV_ReadVIALUCX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #78
  {DBGFIELD("WriteVMALUV_ReadVMALUV_ReadVMALUV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #79
  {DBGFIELD("WriteVICmpV_ReadVICmpV_ReadVICmpV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #80
  {DBGFIELD("WriteVICmpX_ReadVICmpV_ReadVICmpX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #81
  {DBGFIELD("WriteVIMergeI_ReadVIMergeV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #82
  {DBGFIELD("WriteVIMergeV_ReadVIMergeV_ReadVIMergeV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #83
  {DBGFIELD("WriteVIMergeX_ReadVIMergeV_ReadVIMergeX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #84
  {DBGFIELD("WriteVMSFSV_ReadVMSFSV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #85
  {DBGFIELD("WriteVICmpI_ReadVICmpV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #86
  {DBGFIELD("WriteVIMulV_ReadVIMulV_ReadVIMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #87
  {DBGFIELD("WriteVIMulX_ReadVIMulV_ReadVIMulX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #88
  {DBGFIELD("WriteVIMovXV_ReadVIMovXV_ReadVIMovXX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #89
  {DBGFIELD("WriteVIMovI")        8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #90
  {DBGFIELD("WriteVIMovV_ReadVIMovV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #91
  {DBGFIELD("WriteVIMovX_ReadVIMovX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #92
  {DBGFIELD("WriteVIMovVX_ReadVIMovVX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #93
  {DBGFIELD("WriteVNClipI_ReadVNClipV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #94
  {DBGFIELD("WriteVNClipV_ReadVNClipV_ReadVNClipV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #95
  {DBGFIELD("WriteVNClipX_ReadVNClipV_ReadVNClipX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #96
  {DBGFIELD("WriteVNShiftI_ReadVNShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #97
  {DBGFIELD("WriteVNShiftV_ReadVNShiftV_ReadVNShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #98
  {DBGFIELD("WriteVNShiftX_ReadVNShiftV_ReadVNShiftX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #99
  {DBGFIELD("WriteVIRedV_ReadVIRedV_ReadVIRedV_ReadVIRedV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #100
  {DBGFIELD("WriteVGatherV_ReadVGatherV_ReadVGatherV") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #101
  {DBGFIELD("WriteVGatherI_ReadVGatherV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #102
  {DBGFIELD("WriteVGatherV_ReadVGatherV_ReadVGatherV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #103
  {DBGFIELD("WriteVGatherX_ReadVGatherV_ReadVGatherX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #104
  {DBGFIELD("WriteVSALUI_ReadVSALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #105
  {DBGFIELD("WriteVSALUV_ReadVSALUV_ReadVSALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #106
  {DBGFIELD("WriteVSALUX_ReadVSALUV_ReadVSALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #107
  {DBGFIELD("WriteVSTE16_ReadVSTE16V_ReadVSTX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #108
  {DBGFIELD("WriteVSTE32_ReadVSTE32V_ReadVSTX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #109
  {DBGFIELD("WriteVSTE64_ReadVSTE64V_ReadVSTX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #110
  {DBGFIELD("WriteVSTE8_ReadVSTE8V_ReadVSTX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #111
  {DBGFIELD("WriteVExtV_ReadVExtV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #112
  {DBGFIELD("WriteVISlide1X_ReadVISlideV_ReadVISlideX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #113
  {DBGFIELD("WriteVISlideI_ReadVISlideV_ReadVISlideV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #114
  {DBGFIELD("WriteVISlideX_ReadVISlideV_ReadVISlideV_ReadVISlideX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #115
  {DBGFIELD("WriteVShiftI_ReadVShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #116
  {DBGFIELD("WriteVShiftV_ReadVShiftV_ReadVShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #117
  {DBGFIELD("WriteVShiftX_ReadVShiftV_ReadVShiftX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #118
  {DBGFIELD("WriteVSMulV_ReadVSMulV_ReadVSMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #119
  {DBGFIELD("WriteVSMulX_ReadVSMulV_ReadVSMulX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #120
  {DBGFIELD("WriteVSTM_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #121
  {DBGFIELD("WriteVSTOX16_ReadVSTOX16_ReadVSTX_ReadVSTOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #122
  {DBGFIELD("WriteVSTOX32_ReadVSTOX32_ReadVSTX_ReadVSTOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #123
  {DBGFIELD("WriteVSTOX64_ReadVSTOX64_ReadVSTX_ReadVSTOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #124
  {DBGFIELD("WriteVSTOX8_ReadVSTOX8_ReadVSTX_ReadVSTOXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #125
  {DBGFIELD("WriteVSTS16_ReadVSTS16V_ReadVSTX_ReadVSTSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #126
  {DBGFIELD("WriteVSTS32_ReadVSTS32V_ReadVSTX_ReadVSTSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #127
  {DBGFIELD("WriteVSTS64_ReadVSTS64V_ReadVSTX_ReadVSTSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #128
  {DBGFIELD("WriteVSTS8_ReadVSTS8V_ReadVSTX_ReadVSTSX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #129
  {DBGFIELD("WriteVSShiftI_ReadVSShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #130
  {DBGFIELD("WriteVSShiftV_ReadVSShiftV_ReadVSShiftV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #131
  {DBGFIELD("WriteVSShiftX_ReadVSShiftV_ReadVSShiftX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #132
  {DBGFIELD("WriteVSTUX16_ReadVSTUX16_ReadVSTX_ReadVSTUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #133
  {DBGFIELD("WriteVSTUX32_ReadVSTUX32_ReadVSTX_ReadVSTUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #134
  {DBGFIELD("WriteVSTUX64_ReadVSTUX64_ReadVSTX_ReadVSTUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #135
  {DBGFIELD("WriteVSTUX8_ReadVSTUX8_ReadVSTX_ReadVSTUXV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #136
  {DBGFIELD("WriteVIWALUV_ReadVIWALUV_ReadVIWALUV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #137
  {DBGFIELD("WriteVIWALUX_ReadVIWALUV_ReadVIWALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #138
  {DBGFIELD("WriteVIWMulAddV_ReadVIWMulAddV_ReadVIWMulAddV_ReadVIWMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #139
  {DBGFIELD("WriteVIWMulAddX_ReadVIWMulAddV_ReadVIWMulAddV_ReadVIWMulAddX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #140
  {DBGFIELD("WriteVIWMulV_ReadVIWMulV_ReadVIWMulV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #141
  {DBGFIELD("WriteVIWMulX_ReadVIWMulV_ReadVIWMulX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #142
  {DBGFIELD("WriteVIWRedV_ReadVIWRedV_ReadVIWRedV_ReadVIWRedV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #143
  {DBGFIELD("WriteIALU_ReadIALU_ReadIALU") 1, false, false, false, 10, 1, 11, 1,  1, 2}, // #144
  {DBGFIELD("WriteIALU_ReadIALU") 1, false, false, false, 10, 1, 11, 1,  0, 1}, // #145
  {DBGFIELD("WriteIALU32_ReadIALU32") 1, false, false, false, 10, 1, 11, 1,  0, 1}, // #146
  {DBGFIELD("WriteIALU32_ReadIALU32_ReadIALU32") 1, false, false, false, 10, 1, 11, 1,  1, 2}, // #147
  {DBGFIELD("WriteAtomicD_ReadAtomicDA_ReadAtomicDD") 1, false, false, false, 11, 2, 11, 1,  1, 2}, // #148
  {DBGFIELD("WriteAtomicW_ReadAtomicWA_ReadAtomicWD") 1, false, false, false, 11, 2, 11, 1,  1, 2}, // #149
  {DBGFIELD("WriteIALU")          1, false, false, false, 10, 1, 11, 1,  0, 0}, // #150
  {DBGFIELD("WriteSingleBit_ReadSingleBit_ReadSingleBit") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #151
  {DBGFIELD("WriteSingleBitImm_ReadSingleBitImm") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #152
  {DBGFIELD("WriteJmp_ReadJmp_ReadJmp") 1, false, false, false, 13, 2,  1, 1,  1, 2}, // #153
  {DBGFIELD("WriteBFP_ReadBFP_ReadBFP") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #154
  {DBGFIELD("WriteBFP32_ReadBFP32_ReadBFP32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #155
  {DBGFIELD("WriteCLMUL_ReadCLMUL_ReadCLMUL") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #156
  {DBGFIELD("WriteCLZ_ReadCLZ")   8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #157
  {DBGFIELD("WriteCLZ32_ReadCLZ32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #158
  {DBGFIELD("WriteCPOP_ReadCPOP") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #159
  {DBGFIELD("WriteCPOP32_ReadCPOP32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #160
  {DBGFIELD("WriteCSR_ReadCSR")   1, false, false, false, 13, 2,  1, 1,  0, 1}, // #161
  {DBGFIELD("WriteCSR")           1, false, false, false, 13, 2,  1, 1,  0, 0}, // #162
  {DBGFIELD("WriteCTZ_ReadCTZ")   8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #163
  {DBGFIELD("WriteCTZ32_ReadCTZ32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #164
  {DBGFIELD("WriteJmp")           1, false, false, false, 13, 2,  1, 1,  0, 0}, // #165
  {DBGFIELD("WriteFLD64_ReadMemBase") 1, false, false, false, 11, 2,  2, 1,  0, 1}, // #166
  {DBGFIELD("WriteFLD32_ReadMemBase") 1, false, false, false, 11, 2,  2, 1,  0, 1}, // #167
  {DBGFIELD("WriteFST64_ReadStoreData_ReadMemBase") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #168
  {DBGFIELD("WriteFST32_ReadStoreData_ReadMemBase") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #169
  {DBGFIELD("WriteJal")           1, false, false, false, 13, 2,  1, 1,  0, 0}, // #170
  {DBGFIELD("WriteJalr_ReadJalr") 1, false, false, false, 13, 2,  1, 1,  0, 1}, // #171
  {DBGFIELD("WriteJmpReg")        1, false, false, false, 13, 2,  1, 1,  0, 0}, // #172
  {DBGFIELD("WriteLDD_ReadMemBase") 1, false, false, false, 11, 2, 11, 1,  0, 1}, // #173
  {DBGFIELD("WriteLDW_ReadMemBase") 1, false, false, false, 11, 2, 11, 1,  0, 1}, // #174
  {DBGFIELD("WriteNop")           1, false, false, false,  0, 0,  1, 1,  0, 0}, // #175
  {DBGFIELD("WriteSTD_ReadStoreData_ReadMemBase") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #176
  {DBGFIELD("WriteShiftImm_ReadShiftImm") 1, false, false, false, 10, 1, 11, 1,  0, 1}, // #177
  {DBGFIELD("WriteSTW_ReadStoreData_ReadMemBase") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #178
  {DBGFIELD("WriteIDiv_ReadIDiv_ReadIDiv") 1, false, false, false, 15, 3, 12, 1,  1, 2}, // #179
  {DBGFIELD("WriteIDiv32_ReadIDiv32_ReadIDiv32") 1, false, false, false, 15, 3, 12, 1,  1, 2}, // #180
  {DBGFIELD("WriteFALU64_ReadFALU64_ReadFALU64") 1, false, false, false, 13, 2,  8, 1,  1, 2}, // #181
  {DBGFIELD("WriteFALU16_ReadFALU16_ReadFALU16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #182
  {DBGFIELD("WriteFALU32_ReadFALU32_ReadFALU32") 1, false, false, false, 13, 2,  9, 1,  1, 2}, // #183
  {DBGFIELD("WriteFClass64_ReadFClass64") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #184
  {DBGFIELD("WriteFClass16_ReadFClass16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #185
  {DBGFIELD("WriteFClass32_ReadFClass32") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #186
  {DBGFIELD("WriteFCvtF16ToF64_ReadFCvtF16ToF64") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #187
  {DBGFIELD("WriteFCvtI64ToF64_ReadFCvtI64ToF64") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #188
  {DBGFIELD("WriteFCvtF32ToF64_ReadFCvtF32ToF64") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #189
  {DBGFIELD("WriteFCvtI32ToF64_ReadFCvtI32ToF64") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #190
  {DBGFIELD("WriteFCvtF64ToF16_ReadFCvtF64ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #191
  {DBGFIELD("WriteFCvtI64ToF16_ReadFCvtI64ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #192
  {DBGFIELD("WriteFCvtF32ToF16_ReadFCvtF32ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #193
  {DBGFIELD("WriteFCvtI32ToF16_ReadFCvtI32ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #194
  {DBGFIELD("WriteFCvtF64ToI64_ReadFCvtF64ToI64") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #195
  {DBGFIELD("WriteFCvtF16ToI64_ReadFCvtF16ToI64") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #196
  {DBGFIELD("WriteFCvtF32ToI64_ReadFCvtF32ToI64") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #197
  {DBGFIELD("WriteFCvtF64ToF32_ReadFCvtF64ToF32") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #198
  {DBGFIELD("WriteFCvtF16ToF32_ReadFCvtF16ToF32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #199
  {DBGFIELD("WriteFCvtI64ToF32_ReadFCvtI64ToF32") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #200
  {DBGFIELD("WriteFCvtI32ToF32_ReadFCvtI32ToF32") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #201
  {DBGFIELD("WriteFCvtF64ToI32_ReadFCvtF64ToI32") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #202
  {DBGFIELD("WriteFCvtF16ToI32_ReadFCvtF16ToI32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #203
  {DBGFIELD("WriteFCvtF32ToI32_ReadFCvtF32ToI32") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #204
  {DBGFIELD("WriteFDiv64_ReadFDiv64_ReadFDiv64") 1, false, false, false, 18, 3, 13, 1,  1, 2}, // #205
  {DBGFIELD("WriteFDiv16_ReadFDiv16_ReadFDiv16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #206
  {DBGFIELD("WriteFDiv32_ReadFDiv32_ReadFDiv32") 1, false, false, false, 21, 3, 14, 1,  1, 2}, // #207
  {DBGFIELD("WriteFCmp64_ReadFCmp64_ReadFCmp64") 1, false, false, false, 13, 2, 11, 1,  1, 2}, // #208
  {DBGFIELD("WriteFCmp16_ReadFCmp16_ReadFCmp16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #209
  {DBGFIELD("WriteFCmp32_ReadFCmp32_ReadFCmp32") 1, false, false, false, 13, 2, 11, 1,  1, 2}, // #210
  {DBGFIELD("WriteFLD64_ReadFMemBase") 1, false, false, false, 11, 2,  2, 1,  0, 1}, // #211
  {DBGFIELD("WriteFLD16_ReadFMemBase") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #212
  {DBGFIELD("WriteFLD32_ReadFMemBase") 1, false, false, false, 11, 2,  2, 1,  0, 1}, // #213
  {DBGFIELD("WriteFMA64_ReadFMA64_ReadFMA64_ReadFMA64") 1, false, false, false, 13, 2,  8, 1,  3, 3}, // #214
  {DBGFIELD("WriteFMA16_ReadFMA16_ReadFMA16_ReadFMA16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #215
  {DBGFIELD("WriteFMA32_ReadFMA32_ReadFMA32_ReadFMA32") 1, false, false, false, 13, 2,  9, 1,  3, 3}, // #216
  {DBGFIELD("WriteFMinMax64_ReadFMinMax64_ReadFMinMax64") 1, false, false, false, 13, 2, 11, 1,  1, 2}, // #217
  {DBGFIELD("WriteFMinMax16_ReadFMinMax16_ReadFMinMax16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #218
  {DBGFIELD("WriteFMinMax32_ReadFMinMax32_ReadFMinMax32") 1, false, false, false, 13, 2, 11, 1,  1, 2}, // #219
  {DBGFIELD("WriteFMul64_ReadFMul64_ReadFMul64") 1, false, false, false, 13, 2,  8, 1,  1, 2}, // #220
  {DBGFIELD("WriteFMul16_ReadFMul16_ReadFMul16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #221
  {DBGFIELD("WriteFMul32_ReadFMul32_ReadFMul32") 1, false, false, false, 13, 2,  9, 1,  1, 2}, // #222
  {DBGFIELD("WriteFMovI64ToF64_ReadFMovI64ToF64") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #223
  {DBGFIELD("WriteFMovI16ToF16_ReadFMovI16ToF16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #224
  {DBGFIELD("WriteFMovI32ToF32_ReadFMovI32ToF32") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #225
  {DBGFIELD("WriteFMovF64ToI64_ReadFMovF64ToI64") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #226
  {DBGFIELD("WriteFMovF16ToI16_ReadFMovF16ToI16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #227
  {DBGFIELD("WriteFMovF32ToI32_ReadFMovF32ToI32") 1, false, false, false, 13, 2, 11, 1,  0, 1}, // #228
  {DBGFIELD("WriteFST64_ReadStoreData_ReadFMemBase") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #229
  {DBGFIELD("WriteFSGNJ64_ReadFSGNJ64_ReadFSGNJ64") 1, false, false, false, 13, 2, 11, 1,  1, 2}, // #230
  {DBGFIELD("WriteFSGNJ16_ReadFSGNJ16_ReadFSGNJ16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #231
  {DBGFIELD("WriteFSGNJ32_ReadFSGNJ32_ReadFSGNJ32") 1, false, false, false, 13, 2, 11, 1,  1, 2}, // #232
  {DBGFIELD("WriteFST16_ReadStoreData_ReadFMemBase") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #233
  {DBGFIELD("WriteFSqrt64_ReadFSqrt64") 1, false, false, false, 18, 3, 13, 1,  0, 1}, // #234
  {DBGFIELD("WriteFSqrt16_ReadFSqrt16") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #235
  {DBGFIELD("WriteFSqrt32_ReadFSqrt32") 1, false, false, false, 21, 3, 14, 1,  0, 1}, // #236
  {DBGFIELD("WriteFST32_ReadStoreData_ReadFMemBase") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #237
  {DBGFIELD("WriteLDB_ReadMemBase") 1, false, false, false, 11, 2, 11, 1,  0, 1}, // #238
  {DBGFIELD("WriteLDH_ReadMemBase") 1, false, false, false, 11, 2, 11, 1,  0, 1}, // #239
  {DBGFIELD("WriteAtomicLDD_ReadAtomicLDD") 1, false, false, false, 11, 2, 11, 1,  0, 1}, // #240
  {DBGFIELD("WriteAtomicLDW_ReadAtomicLDW") 1, false, false, false, 11, 2, 11, 1,  0, 1}, // #241
  {DBGFIELD("WriteLDWU_ReadMemBase") 1, false, false, false, 11, 2, 11, 1,  0, 1}, // #242
  {DBGFIELD("WriteIMul_ReadIMul_ReadIMul") 1, false, false, false, 13, 2, 11, 1,  1, 2}, // #243
  {DBGFIELD("WriteIMul32_ReadIMul32_ReadIMul32") 1, false, false, false, 13, 2, 11, 1,  1, 2}, // #244
  {DBGFIELD("WriteORCB_ReadORCB") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #245
  {DBGFIELD("WriteREV8_ReadREV8") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #246
  {DBGFIELD("WriteRotateReg_ReadRotateReg_ReadRotateReg") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #247
  {DBGFIELD("WriteRotateReg32_ReadRotateReg32_ReadRotateReg32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #248
  {DBGFIELD("WriteRotateImm_ReadRotateImm") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #249
  {DBGFIELD("WriteRotateImm32_ReadRotateImm32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #250
  {DBGFIELD("WriteSTB_ReadStoreData_ReadMemBase") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #251
  {DBGFIELD("WriteAtomicSTD_ReadAtomicSTD_ReadAtomicSTD") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #252
  {DBGFIELD("WriteAtomicSTW_ReadAtomicSTW_ReadAtomicSTW") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #253
  {DBGFIELD("WriteSTH_ReadStoreData_ReadMemBase") 1, false, false, false, 11, 2,  1, 1,  1, 2}, // #254
  {DBGFIELD("WriteSHXADD_ReadSHXADD_ReadSHXADD") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #255
  {DBGFIELD("WriteSHXADD32_ReadSHXADD32_ReadSHXADD32") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #256
  {DBGFIELD("WriteShiftReg_ReadShiftReg_ReadShiftReg") 1, false, false, false, 10, 1, 11, 1,  1, 2}, // #257
  {DBGFIELD("WriteShiftImm32_ReadShiftImm32") 1, false, false, false, 10, 1, 11, 1,  0, 1}, // #258
  {DBGFIELD("WriteShiftReg32_ReadShiftReg32_ReadShiftReg32") 1, false, false, false, 10, 1, 11, 1,  1, 2}, // #259
  {DBGFIELD("WriteVMPopV_ReadVMPopV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #260
  {DBGFIELD("WriteVMFFSV_ReadVMFFSV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #261
  {DBGFIELD("WriteVFMulAddF_ReadVFMulAddV_ReadVFMulAddF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #262
  {DBGFIELD("WriteVFMulAddV_ReadVFMulAddV_ReadVFMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #263
  {DBGFIELD("WriteVFRedV_ReadVFRedV_ReadVFRedV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #264
  {DBGFIELD("WriteVFRedOV_ReadVFRedOV_ReadVFRedOV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #265
  {DBGFIELD("WriteVFWMulAddF_ReadVFWMulAddV_ReadVFWMulAddF_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #266
  {DBGFIELD("WriteVFWMulAddV_ReadVFWMulAddV_ReadVFWMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #267
  {DBGFIELD("WriteVFWRedOV_ReadVFWRedOV_ReadVFWRedOV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #268
  {DBGFIELD("WriteVFWRedV_ReadVFWRedV_ReadVFWRedV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #269
  {DBGFIELD("WriteVLD1R16_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #270
  {DBGFIELD("WriteVLD1R32_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #271
  {DBGFIELD("WriteVLD1R64_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #272
  {DBGFIELD("WriteVLD1R8_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #273
  {DBGFIELD("WriteVLD2R16_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #274
  {DBGFIELD("WriteVLD2R32_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #275
  {DBGFIELD("WriteVLD2R64_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #276
  {DBGFIELD("WriteVLD2R8_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #277
  {DBGFIELD("WriteVLD4R16_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #278
  {DBGFIELD("WriteVLD4R32_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #279
  {DBGFIELD("WriteVLD4R64_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #280
  {DBGFIELD("WriteVLD4R8_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #281
  {DBGFIELD("WriteVLD8R16_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #282
  {DBGFIELD("WriteVLD8R32_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #283
  {DBGFIELD("WriteVLD8R64_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #284
  {DBGFIELD("WriteVLD8R8_ReadVLDX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #285
  {DBGFIELD("WriteVIMulAddV_ReadVIMulAddV_ReadVIMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #286
  {DBGFIELD("WriteVIMulAddX_ReadVIMulAddV_ReadVIMulAddX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #287
  {DBGFIELD("WriteVICmpV_ReadVICmpV_ReadVICmpX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #288
  {DBGFIELD("WriteVMov1V_ReadVMov1V") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #289
  {DBGFIELD("WriteVMov2V_ReadVMov2V") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #290
  {DBGFIELD("WriteVMov4V_ReadVMov4V") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #291
  {DBGFIELD("WriteVMov8V_ReadVMov8V") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #292
  {DBGFIELD("WriteVIRedV_ReadVIRedV_ReadVIRedV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #293
  {DBGFIELD("WriteVIALUV_ReadVIALUV_ReadVIALUX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #294
  {DBGFIELD("WriteVST1R_ReadVST1R_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #295
  {DBGFIELD("WriteVST2R_ReadVST2R_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #296
  {DBGFIELD("WriteVST4R_ReadVST4R_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #297
  {DBGFIELD("WriteVST8R_ReadVST8R_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #298
  {DBGFIELD("WriteVISlideI_ReadVISlideV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #299
  {DBGFIELD("WriteVISlideX_ReadVISlideV_ReadVISlideX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #300
  {DBGFIELD("WriteVSTM_ReadVSTM_ReadVSTX") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #301
  {DBGFIELD("WriteVIWMulAddV_ReadVIWMulAddV_ReadVIWMulAddV_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #302
  {DBGFIELD("WriteVIWMulAddX_ReadVIWMulAddV_ReadVIWMulAddX_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #303
  {DBGFIELD("WriteVIWRedV_ReadVIWRedV_ReadVIWRedV0_ReadVMask") 8191, false, false, false,  0, 0,  0, 0,  0, 0}, // #304
  {DBGFIELD("COPY")               1, false, false, false, 10, 1, 11, 1,  0, 0}, // #305
}; // SiFive7ModelSchedClasses

#undef DBGFIELD

static const llvm::MCSchedModel NoSchedModel = {
  MCSchedModel::DefaultIssueWidth,
  MCSchedModel::DefaultMicroOpBufferSize,
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  MCSchedModel::DefaultLoadLatency,
  MCSchedModel::DefaultHighLatency,
  MCSchedModel::DefaultMispredictPenalty,
  false, // PostRAScheduler
  false, // CompleteModel
  0, // Processor ID
  nullptr, nullptr, 0, 0, // No instruction-level machine model.
  nullptr, // No Itinerary
  nullptr // No extra processor descriptor
};

static const unsigned RocketModelProcResourceSubUnits[] = {
  0,  // Invalid
};

// {Name, NumUnits, SuperIdx, BufferSize, SubUnitsIdxBegin}
static const llvm::MCProcResourceDesc RocketModelProcResources[] = {
  {"InvalidUnit", 0, 0, 0, 0},
  {"RocketUnitALU",   1, 0, 0, nullptr}, // #1
  {"RocketUnitB",     1, 0, 0, nullptr}, // #2
  {"RocketUnitFPALU", 1, 0, 0, nullptr}, // #3
  {"RocketUnitFPDivSqrt", 1, 0, 1, nullptr}, // #4
  {"RocketUnitIDiv",  1, 0, 1, nullptr}, // #5
  {"RocketUnitIMul",  1, 0, 0, nullptr}, // #6
  {"RocketUnitMem",   1, 0, 0, nullptr}, // #7
};

static const llvm::MCSchedModel RocketModel = {
  1, // IssueWidth
  0, // MicroOpBufferSize
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  3, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  3, // MispredictPenalty
  false, // PostRAScheduler
  false, // CompleteModel
  1, // Processor ID
  RocketModelProcResources,
  RocketModelSchedClasses,
  8,
  306,
  nullptr, // No Itinerary
  nullptr // No extra processor descriptor
};

static const unsigned SiFive7ModelProcResourceSubUnits[] = {
  0,  // Invalid
  3,   5,   // SiFive7PipeAB
};

// {Name, NumUnits, SuperIdx, BufferSize, SubUnitsIdxBegin}
static const llvm::MCProcResourceDesc SiFive7ModelProcResources[] = {
  {"InvalidUnit", 0, 0, 0, 0},
  {"SiFive7FDiv",     1, 5, 1, nullptr}, // #1, Super=SiFive7PipeB
  {"SiFive7IDiv",     1, 5, 1, nullptr}, // #2, Super=SiFive7PipeB
  {"SiFive7PipeA",    1, 0, 0, nullptr}, // #3
  {"SiFive7PipeAB",   2, 0, -1, SiFive7ModelProcResourceSubUnits + 1}, // #4
  {"SiFive7PipeB",    1, 0, 0, nullptr}, // #5
};

static const llvm::MCSchedModel SiFive7Model = {
  2, // IssueWidth
  0, // MicroOpBufferSize
  MCSchedModel::DefaultLoopMicroOpBufferSize,
  3, // LoadLatency
  MCSchedModel::DefaultHighLatency,
  3, // MispredictPenalty
  false, // PostRAScheduler
  false, // CompleteModel
  2, // Processor ID
  SiFive7ModelProcResources,
  SiFive7ModelSchedClasses,
  6,
  306,
  nullptr, // No Itinerary
  nullptr // No extra processor descriptor
};

// Sorted (by key) array of values for CPU subtype.
extern const llvm::SubtargetSubTypeKV RISCVSubTypeKV[] = {
 { "generic-rv32", { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &NoSchedModel },
 { "generic-rv64", { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &NoSchedModel },
 { "rocket-rv32", { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "rocket-rv64", { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-7-rv32", { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, } } }, &SiFive7Model },
 { "sifive-7-rv64", { { { 0x1ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, } } }, &SiFive7Model },
 { "sifive-e20", { { { 0x12000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-e21", { { { 0x13000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-e24", { { { 0x1b000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-e31", { { { 0x13000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-e34", { { { 0x1b000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-e76", { { { 0x1b000000000ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, } } }, &SiFive7Model },
 { "sifive-s21", { { { 0x13000000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-s51", { { { 0x13000000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-s54", { { { 0x1f000000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-s76", { { { 0x1f000000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, } } }, &SiFive7Model },
 { "sifive-u54", { { { 0x1f000000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, &RocketModel },
 { "sifive-u74", { { { 0x1f000000001ULL, 0x0ULL, 0x0ULL, 0x0ULL, } } }, { { { 0x0ULL, 0x800000ULL, 0x0ULL, 0x0ULL, } } }, &SiFive7Model },
};

namespace RISCV_MC {
unsigned resolveVariantSchedClassImpl(unsigned SchedClass,
    const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) {
  // Don't know how to resolve this scheduling class.
  return 0;
}
} // end namespace RISCV_MC

struct RISCVGenMCSubtargetInfo : public MCSubtargetInfo {
  RISCVGenMCSubtargetInfo(const Triple &TT,
    StringRef CPU, StringRef TuneCPU, StringRef FS,
    ArrayRef<SubtargetFeatureKV> PF,
    ArrayRef<SubtargetSubTypeKV> PD,
    const MCWriteProcResEntry *WPR,
    const MCWriteLatencyEntry *WL,
    const MCReadAdvanceEntry *RA, const InstrStage *IS,
    const unsigned *OC, const unsigned *FP) :
      MCSubtargetInfo(TT, CPU, TuneCPU, FS, PF, PD,
                      WPR, WL, RA, IS, OC, FP) { }

  unsigned resolveVariantSchedClass(unsigned SchedClass,
      const MCInst *MI, const MCInstrInfo *MCII,
      unsigned CPUID) const override {
    return RISCV_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, CPUID);
  }
  unsigned getHwMode() const override;
};
unsigned RISCVGenMCSubtargetInfo::getHwMode() const {
  if (checkFeatures("+64bit")) return 1;
  return 0;
}

static inline MCSubtargetInfo *createRISCVMCSubtargetInfoImpl(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS) {
  return new RISCVGenMCSubtargetInfo(TT, CPU, TuneCPU, FS, RISCVFeatureKV, RISCVSubTypeKV, 
                      RISCVWriteProcResTable, RISCVWriteLatencyTable, RISCVReadAdvanceTable, 
                      nullptr, nullptr, nullptr);
}

} // end namespace llvm

#endif // GET_SUBTARGETINFO_MC_DESC


#ifdef GET_SUBTARGETINFO_TARGET_DESC
#undef GET_SUBTARGETINFO_TARGET_DESC

#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

// ParseSubtargetFeatures - Parses features string setting specified
// subtarget options.
void llvm::RISCVSubtarget::ParseSubtargetFeatures(StringRef CPU, StringRef TuneCPU, StringRef FS) {
  LLVM_DEBUG(dbgs() << "\nFeatures:" << FS);
  LLVM_DEBUG(dbgs() << "\nCPU:" << CPU);
  LLVM_DEBUG(dbgs() << "\nTuneCPU:" << TuneCPU << "\n\n");
  InitMCProcessorInfo(CPU, TuneCPU, FS);
  const FeatureBitset &Bits = getFeatureBits();
  if (Bits[RISCV::Feature64Bit]) HasRV64 = true;
  if (Bits[RISCV::FeatureNoRVCHints]) EnableRVCHintInstrs = false;
  if (Bits[RISCV::FeatureRV32E]) IsRV32E = true;
  if (Bits[RISCV::FeatureRelax]) EnableLinkerRelax = true;
  if (Bits[RISCV::FeatureReserveX1]) UserReservedRegister[RISCV::X1] = true;
  if (Bits[RISCV::FeatureReserveX2]) UserReservedRegister[RISCV::X2] = true;
  if (Bits[RISCV::FeatureReserveX3]) UserReservedRegister[RISCV::X3] = true;
  if (Bits[RISCV::FeatureReserveX4]) UserReservedRegister[RISCV::X4] = true;
  if (Bits[RISCV::FeatureReserveX5]) UserReservedRegister[RISCV::X5] = true;
  if (Bits[RISCV::FeatureReserveX6]) UserReservedRegister[RISCV::X6] = true;
  if (Bits[RISCV::FeatureReserveX7]) UserReservedRegister[RISCV::X7] = true;
  if (Bits[RISCV::FeatureReserveX8]) UserReservedRegister[RISCV::X8] = true;
  if (Bits[RISCV::FeatureReserveX9]) UserReservedRegister[RISCV::X9] = true;
  if (Bits[RISCV::FeatureReserveX10]) UserReservedRegister[RISCV::X10] = true;
  if (Bits[RISCV::FeatureReserveX11]) UserReservedRegister[RISCV::X11] = true;
  if (Bits[RISCV::FeatureReserveX12]) UserReservedRegister[RISCV::X12] = true;
  if (Bits[RISCV::FeatureReserveX13]) UserReservedRegister[RISCV::X13] = true;
  if (Bits[RISCV::FeatureReserveX14]) UserReservedRegister[RISCV::X14] = true;
  if (Bits[RISCV::FeatureReserveX15]) UserReservedRegister[RISCV::X15] = true;
  if (Bits[RISCV::FeatureReserveX16]) UserReservedRegister[RISCV::X16] = true;
  if (Bits[RISCV::FeatureReserveX17]) UserReservedRegister[RISCV::X17] = true;
  if (Bits[RISCV::FeatureReserveX18]) UserReservedRegister[RISCV::X18] = true;
  if (Bits[RISCV::FeatureReserveX19]) UserReservedRegister[RISCV::X19] = true;
  if (Bits[RISCV::FeatureReserveX20]) UserReservedRegister[RISCV::X20] = true;
  if (Bits[RISCV::FeatureReserveX21]) UserReservedRegister[RISCV::X21] = true;
  if (Bits[RISCV::FeatureReserveX22]) UserReservedRegister[RISCV::X22] = true;
  if (Bits[RISCV::FeatureReserveX23]) UserReservedRegister[RISCV::X23] = true;
  if (Bits[RISCV::FeatureReserveX24]) UserReservedRegister[RISCV::X24] = true;
  if (Bits[RISCV::FeatureReserveX25]) UserReservedRegister[RISCV::X25] = true;
  if (Bits[RISCV::FeatureReserveX26]) UserReservedRegister[RISCV::X26] = true;
  if (Bits[RISCV::FeatureReserveX27]) UserReservedRegister[RISCV::X27] = true;
  if (Bits[RISCV::FeatureReserveX28]) UserReservedRegister[RISCV::X28] = true;
  if (Bits[RISCV::FeatureReserveX29]) UserReservedRegister[RISCV::X29] = true;
  if (Bits[RISCV::FeatureReserveX30]) UserReservedRegister[RISCV::X30] = true;
  if (Bits[RISCV::FeatureReserveX31]) UserReservedRegister[RISCV::X31] = true;
  if (Bits[RISCV::FeatureSaveRestore]) EnableSaveRestore = true;
  if (Bits[RISCV::FeatureStdExtA]) HasStdExtA = true;
  if (Bits[RISCV::FeatureStdExtC]) HasStdExtC = true;
  if (Bits[RISCV::FeatureStdExtD]) HasStdExtD = true;
  if (Bits[RISCV::FeatureStdExtF]) HasStdExtF = true;
  if (Bits[RISCV::FeatureStdExtM]) HasStdExtM = true;
  if (Bits[RISCV::FeatureStdExtV]) HasStdExtV = true;
  if (Bits[RISCV::FeatureStdExtZba]) HasStdExtZba = true;
  if (Bits[RISCV::FeatureStdExtZbb]) HasStdExtZbb = true;
  if (Bits[RISCV::FeatureStdExtZbc]) HasStdExtZbc = true;
  if (Bits[RISCV::FeatureStdExtZbe]) HasStdExtZbe = true;
  if (Bits[RISCV::FeatureStdExtZbf]) HasStdExtZbf = true;
  if (Bits[RISCV::FeatureStdExtZbkb]) HasStdExtZbkb = true;
  if (Bits[RISCV::FeatureStdExtZbkc]) HasStdExtZbkc = true;
  if (Bits[RISCV::FeatureStdExtZbkx]) HasStdExtZbkx = true;
  if (Bits[RISCV::FeatureStdExtZbm]) HasStdExtZbm = true;
  if (Bits[RISCV::FeatureStdExtZbp]) HasStdExtZbp = true;
  if (Bits[RISCV::FeatureStdExtZbr]) HasStdExtZbr = true;
  if (Bits[RISCV::FeatureStdExtZbs]) HasStdExtZbs = true;
  if (Bits[RISCV::FeatureStdExtZbt]) HasStdExtZbt = true;
  if (Bits[RISCV::FeatureStdExtZdinx]) HasStdExtZdinx = true;
  if (Bits[RISCV::FeatureStdExtZfh]) HasStdExtZfh = true;
  if (Bits[RISCV::FeatureStdExtZfhmin]) HasStdExtZfhmin = true;
  if (Bits[RISCV::FeatureStdExtZfinx]) HasStdExtZfinx = true;
  if (Bits[RISCV::FeatureStdExtZhinx]) HasStdExtZhinx = true;
  if (Bits[RISCV::FeatureStdExtZhinxmin]) HasStdExtZhinxmin = true;
  if (Bits[RISCV::FeatureStdExtZk]) HasStdExtZk = true;
  if (Bits[RISCV::FeatureStdExtZkn]) HasStdExtZkn = true;
  if (Bits[RISCV::FeatureStdExtZknd]) HasStdExtZknd = true;
  if (Bits[RISCV::FeatureStdExtZkne]) HasStdExtZkne = true;
  if (Bits[RISCV::FeatureStdExtZknh]) HasStdExtZknh = true;
  if (Bits[RISCV::FeatureStdExtZkr]) HasStdExtZkr = true;
  if (Bits[RISCV::FeatureStdExtZks]) HasStdExtZks = true;
  if (Bits[RISCV::FeatureStdExtZksed]) HasStdExtZksed = true;
  if (Bits[RISCV::FeatureStdExtZksh]) HasStdExtZksh = true;
  if (Bits[RISCV::FeatureStdExtZkt]) HasStdExtZkt = true;
  if (Bits[RISCV::FeatureStdExtZve32f]) HasStdExtZve32f = true;
  if (Bits[RISCV::FeatureStdExtZve32x]) HasStdExtZve32x = true;
  if (Bits[RISCV::FeatureStdExtZve64d]) HasStdExtZve64d = true;
  if (Bits[RISCV::FeatureStdExtZve64f]) HasStdExtZve64f = true;
  if (Bits[RISCV::FeatureStdExtZve64x]) HasStdExtZve64x = true;
  if (Bits[RISCV::FeatureStdExtZvl32b] && ZvlLen < ExtZvl::Zvl32b) ZvlLen = ExtZvl::Zvl32b;
  if (Bits[RISCV::FeatureStdExtZvl64b] && ZvlLen < ExtZvl::Zvl64b) ZvlLen = ExtZvl::Zvl64b;
  if (Bits[RISCV::FeatureStdExtZvl128b] && ZvlLen < ExtZvl::Zvl128b) ZvlLen = ExtZvl::Zvl128b;
  if (Bits[RISCV::FeatureStdExtZvl256b] && ZvlLen < ExtZvl::Zvl256b) ZvlLen = ExtZvl::Zvl256b;
  if (Bits[RISCV::FeatureStdExtZvl512b] && ZvlLen < ExtZvl::Zvl512b) ZvlLen = ExtZvl::Zvl512b;
  if (Bits[RISCV::FeatureStdExtZvl1024b] && ZvlLen < ExtZvl::Zvl1024b) ZvlLen = ExtZvl::Zvl1024b;
  if (Bits[RISCV::FeatureStdExtZvl2048b] && ZvlLen < ExtZvl::Zvl2048b) ZvlLen = ExtZvl::Zvl2048b;
  if (Bits[RISCV::FeatureStdExtZvl4096b] && ZvlLen < ExtZvl::Zvl4096b) ZvlLen = ExtZvl::Zvl4096b;
  if (Bits[RISCV::FeatureStdExtZvl8192b] && ZvlLen < ExtZvl::Zvl8192b) ZvlLen = ExtZvl::Zvl8192b;
  if (Bits[RISCV::FeatureStdExtZvl16384b] && ZvlLen < ExtZvl::Zvl16384b) ZvlLen = ExtZvl::Zvl16384b;
  if (Bits[RISCV::FeatureStdExtZvl32768b] && ZvlLen < ExtZvl::Zvl32768b) ZvlLen = ExtZvl::Zvl32768b;
  if (Bits[RISCV::TuneSiFive7] && RISCVProcFamily < SiFive7) RISCVProcFamily = SiFive7;
}
#endif // GET_SUBTARGETINFO_TARGET_DESC


#ifdef GET_SUBTARGETINFO_HEADER
#undef GET_SUBTARGETINFO_HEADER

namespace llvm {
class DFAPacketizer;
namespace RISCV_MC {
unsigned resolveVariantSchedClassImpl(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID);
} // end namespace RISCV_MC

struct RISCVGenSubtargetInfo : public TargetSubtargetInfo {
  explicit RISCVGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS);
public:
  unsigned resolveSchedClass(unsigned SchedClass,  const MachineInstr *DefMI, const TargetSchedModel *SchedModel) const override;
  unsigned resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const override;
  DFAPacketizer *createDFAPacketizer(const InstrItineraryData *IID) const;
  unsigned getHwMode() const override;
};
} // end namespace llvm

#endif // GET_SUBTARGETINFO_HEADER


#ifdef GET_SUBTARGETINFO_CTOR
#undef GET_SUBTARGETINFO_CTOR

#include "llvm/CodeGen/TargetSchedule.h"

namespace llvm {
extern const llvm::SubtargetFeatureKV RISCVFeatureKV[];
extern const llvm::SubtargetSubTypeKV RISCVSubTypeKV[];
extern const llvm::MCWriteProcResEntry RISCVWriteProcResTable[];
extern const llvm::MCWriteLatencyEntry RISCVWriteLatencyTable[];
extern const llvm::MCReadAdvanceEntry RISCVReadAdvanceTable[];
RISCVGenSubtargetInfo::RISCVGenSubtargetInfo(const Triple &TT, StringRef CPU, StringRef TuneCPU, StringRef FS)
  : TargetSubtargetInfo(TT, CPU, TuneCPU, FS, makeArrayRef(RISCVFeatureKV, 88), makeArrayRef(RISCVSubTypeKV, 18), 
                        RISCVWriteProcResTable, RISCVWriteLatencyTable, RISCVReadAdvanceTable, 
                        nullptr, nullptr, nullptr) {}

unsigned RISCVGenSubtargetInfo
::resolveSchedClass(unsigned SchedClass, const MachineInstr *MI, const TargetSchedModel *SchedModel) const {
  report_fatal_error("Expected a variant SchedClass");
} // RISCVGenSubtargetInfo::resolveSchedClass

unsigned RISCVGenSubtargetInfo
::resolveVariantSchedClass(unsigned SchedClass, const MCInst *MI, const MCInstrInfo *MCII, unsigned CPUID) const {
  return RISCV_MC::resolveVariantSchedClassImpl(SchedClass, MI, MCII, CPUID);
} // RISCVGenSubtargetInfo::resolveVariantSchedClass

unsigned RISCVGenSubtargetInfo::getHwMode() const {
  if (checkFeatures("+64bit")) return 1;
  return 0;
}
} // end namespace llvm

#endif // GET_SUBTARGETINFO_CTOR


#ifdef GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS
#undef GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS

#endif // GET_STIPREDICATE_DECLS_FOR_MC_ANALYSIS


#ifdef GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS
#undef GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS

#endif // GET_STIPREDICATE_DEFS_FOR_MC_ANALYSIS

