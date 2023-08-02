#include <algorithm>
#include <cassert>

#include "InstructionMetadata.hh"

namespace simeng {
namespace arch {
namespace aarch64 {

std::unordered_map<uint32_t, Instruction> Architecture::decodeCache;
std::forward_list<InstructionMetadata> Architecture::metadataCache;
uint64_t Architecture::SVCRval_;

Architecture::Architecture(kernel::Linux& kernel, YAML::Node config)
    : linux_(kernel),
      microDecoder_(std::make_unique<MicroDecoder>(config)),
      VL_(config["Core"]["Vector-Length"].as<uint64_t>()),
      SVL_(config["Core"]["Streaming-Vector-Length"].as<uint64_t>()),
      vctModulo_((config["Core"]["Clock-Frequency"].as<float>() * 1e9) /
                 (config["Core"]["Timer-Frequency"].as<uint32_t>() * 1e6)) {
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &capstoneHandle) != CS_ERR_OK) {
    std::cerr << "[SimEng:Architecture] Could not create capstone handle"
              << std::endl;
    exit(1);
  }

  cs_option(capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

  // Generate zero-indexed system register map
  systemRegisterMap_[ARM64_SYSREG_ACCDATA_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ACTLR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ACTLR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ACTLR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AFSR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AFSR0_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AFSR0_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AFSR0_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AFSR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AFSR1_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AFSR1_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AFSR1_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMAIR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMAIR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMAIR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMAIR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMCFGR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMCGCR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMCNTENCLR0_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMCNTENCLR1_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMCNTENSET0_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMCNTENSET1_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMCR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR00_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR01_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR02_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR03_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR10_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR110_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR111_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR112_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR113_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR114_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR115_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR11_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR12_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR13_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR14_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR15_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR16_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR17_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR18_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTR19_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF00_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF010_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF011_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF012_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF013_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF014_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF015_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF01_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF02_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF03_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF04_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF05_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF06_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF07_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF08_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF09_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF10_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF110_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF111_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF112_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF113_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF114_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF115_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF11_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF12_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF13_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF14_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF15_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF16_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF17_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF18_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVCNTVOFF19_EL2] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER00_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER01_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER02_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER03_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER10_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER110_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER111_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER112_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER113_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER114_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER115_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER11_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER12_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER13_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER14_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER15_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER16_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER17_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER18_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMEVTYPER19_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_AMUSERENR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APDAKEYHI_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APDAKEYLO_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APDBKEYHI_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APDBKEYLO_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APGAKEYHI_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APGAKEYLO_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APIAKEYHI_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APIAKEYLO_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APIBKEYHI_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_APIBKEYLO_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBCR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBFCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBIDR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF10_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF11_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF12_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF13_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF14_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF15_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF16_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF17_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF18_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF19_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF20_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF21_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF22_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF23_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF24_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF25_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF26_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF27_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF28_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF29_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF30_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF31_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF7_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF8_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINF9_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBINFINJ_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC10_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC11_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC12_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC13_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC14_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC15_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC16_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC17_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC18_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC19_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC20_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC21_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC22_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC23_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC24_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC25_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC26_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC27_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC28_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC29_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC30_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC31_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC7_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC8_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRC9_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBSRCINJ_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT10_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT11_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT12_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT13_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT14_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT15_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT16_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT17_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT18_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT19_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT20_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT21_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT22_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT23_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT24_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT25_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT26_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT27_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT28_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT29_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT30_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT31_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT7_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT8_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGT9_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTGTINJ_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_BRBTS_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CCSIDR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CCSIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CLIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTFRQ_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHCTL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHPS_CTL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHPS_CVAL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHPS_TVAL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHP_CTL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHP_CVAL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHP_TVAL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHVS_CTL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHVS_CVAL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHVS_TVAL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHV_CTL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHV_CVAL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTHV_TVAL_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTISCALE_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTKCTL_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTKCTL_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTPCTSS_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTPCT_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTPOFF_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTPS_CTL_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTPS_CVAL_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTPS_TVAL_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTP_CTL_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTP_CTL_EL02] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTP_CVAL_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTP_CVAL_EL02] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTP_TVAL_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTP_TVAL_EL02] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTSCALE_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTVCTSS_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTVCT_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTVFRQ_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTVOFF_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTV_CTL_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTV_CTL_EL02] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTV_CVAL_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTV_CVAL_EL02] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTV_TVAL_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CNTV_TVAL_EL02] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CONTEXTIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CONTEXTIDR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CONTEXTIDR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CPACR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CPACR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CPM_IOACC_CTL_EL3] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CPTR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CPTR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CSSELR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CTR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_CURRENTEL] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DACR32_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DAIF] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGAUTHSTATUS_EL1] =
      systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR10_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR11_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR12_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR13_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR14_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR15_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR7_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR8_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBCR9_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR10_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR11_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR12_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR13_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR14_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR15_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR7_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR8_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGBVR9_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGCLAIMCLR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGCLAIMSET_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGDTRRX_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGDTRTX_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGDTR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGPRCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGVCR32_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR10_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR11_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR12_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR13_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR14_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR15_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR7_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR8_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWCR9_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR10_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR11_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR12_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR13_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR14_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR15_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR7_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR8_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DBGWVR9_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DCZID_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DISR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DIT] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DLR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_DSPSR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ELR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ELR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ELR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ELR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERRIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERRSELR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXADDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXCTLR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXFR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXMISC0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXMISC1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXMISC2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXMISC3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXPFGCDN_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXPFGCTL_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXPFGF_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ERXSTATUS_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ESR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ESR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ESR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ESR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_FAR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_FAR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_FAR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_FAR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_FPCR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_FPEXC32_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_FPSR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_GCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_GMID_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_GPCCR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_GPTBR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HACR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HCRX_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HDFGRTR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HDFGWTR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HFGITR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HFGRTR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HFGWTR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HPFAR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_HSTR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_AP0R0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_AP0R1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_AP0R2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_AP0R3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_AP1R0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_AP1R1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_AP1R2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_AP1R3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_ASGI1R_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_BPR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_BPR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_CTLR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_CTLR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_DIR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_EOIR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_EOIR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_HPPIR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_HPPIR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_IAR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_IAR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_IGRPEN0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_IGRPEN1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_IGRPEN1_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_PMR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_RPR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_SGI0R_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_SGI1R_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_SRE_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_SRE_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICC_SRE_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_AP0R0_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_AP0R1_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_AP0R2_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_AP0R3_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_AP1R0_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_AP1R1_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_AP1R2_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_AP1R3_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_EISR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_ELRSR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_HCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR0_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR10_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR11_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR12_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR13_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR14_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR15_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR1_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR2_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR3_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR4_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR5_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR6_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR7_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR8_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_LR9_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_MISR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_VMCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ICH_VTR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64AFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64AFR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64DFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64DFR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64ISAR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64ISAR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64ISAR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64MMFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64MMFR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64MMFR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64PFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64PFR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64SMFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AA64ZFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_AFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_DFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_ISAR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_ISAR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_ISAR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_ISAR3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_ISAR4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_ISAR5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_ISAR6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_MMFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_MMFR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_MMFR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_MMFR3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_MMFR4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_MMFR5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_PFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_PFR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ID_PFR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_IFSR32_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ISR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_LORC_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_LOREA_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_LORID_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_LORN_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_LORSA_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MAIR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MAIR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MAIR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MAIR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MDCCINT_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MDCCSR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MDCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MDCR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MDRAR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MDSCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MFAR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAM0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAM1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAM1_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAM2_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAM3_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMHCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMSM_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMVPM0_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMVPM1_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMVPM2_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMVPM3_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMVPM4_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMVPM5_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMVPM6_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMVPM7_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPAMVPMV_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPUIR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MPUIR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MVFR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MVFR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_MVFR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_NZCV] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_OSDLR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_OSDTRRX_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_OSDTRTX_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_OSECCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_OSLAR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_OSLSR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PAN] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PAR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMBIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMBLIMITR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMBPTR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMBSR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMCCFILTR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMCCNTR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMCEID0_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMCEID1_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMCNTENCLR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMCNTENSET_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMCR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR0_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR10_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR11_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR12_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR13_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR14_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR15_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR16_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR17_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR18_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR19_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR1_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR20_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR21_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR22_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR23_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR24_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR25_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR26_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR27_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR28_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR29_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR2_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR30_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR3_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR4_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR5_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR6_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR7_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR8_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVCNTR9_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER0_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER10_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER11_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER12_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER13_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER14_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER15_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER16_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER17_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER18_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER19_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER1_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER20_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER21_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER22_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER23_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER24_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER25_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER26_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER27_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER28_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER29_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER2_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER30_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER3_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER4_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER5_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER6_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER7_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER8_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMEVTYPER9_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMINTENCLR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMINTENSET_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMMIR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMOVSCLR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMOVSSET_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSCR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSELR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSEVFR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSFCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSICR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSIRR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSLATFR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSNEVFR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMSWINC_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMUSERENR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMXEVCNTR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PMXEVTYPER_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR10_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR10_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR11_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR11_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR12_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR12_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR13_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR13_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR14_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR14_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR15_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR15_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR1_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR2_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR3_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR4_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR5_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR6_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR7_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR7_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR8_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR8_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR9_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR9_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRBAR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRENR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRENR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR10_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR10_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR11_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR11_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR12_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR12_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR13_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR13_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR14_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR14_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR15_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR15_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR1_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR2_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR2_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR3_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR3_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR4_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR4_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR5_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR5_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR6_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR6_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR7_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR7_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR8_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR8_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR9_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR9_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRLAR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRSELR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_PRSELR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_REVIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_RGSR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_RMR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_RMR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_RMR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_RNDR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_RNDRRS] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_RVBAR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_RVBAR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_RVBAR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCTLR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCTLR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCTLR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCTLR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCXTNUM_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCXTNUM_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCXTNUM_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCXTNUM_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SCXTNUM_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SDER32_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SDER32_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SMCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SMCR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SMCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SMCR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SMIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SMPRIMAP_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SMPRI_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SPSEL] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SPSR_ABT] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SPSR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SPSR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SPSR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SPSR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SPSR_FIQ] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SPSR_IRQ] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SPSR_UND] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SP_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SP_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SP_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SSBS] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_SVCR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TCO] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TCR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TCR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TEECR32_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TEEHBR32_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TFSRE0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TFSR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TFSR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TFSR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TFSR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TPIDR2_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TPIDRRO_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TPIDR_EL0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TPIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TPIDR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TPIDR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRBBASER_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRBIDR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRBLIMITR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRBMAR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRBPTR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRBSR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRBTRG_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR10] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR11] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR13] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR14] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR15] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR8] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACATR9] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR10] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR11] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR13] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR14] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR15] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR8] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCACVR9] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCAUTHSTATUS] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCAUXCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCBBCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCCCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCCTLR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCCTLR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCVR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCVR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCVR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCVR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCVR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCVR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCVR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDCVR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCIDR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCLAIMCLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCLAIMSET] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTCTLR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTCTLR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTCTLR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTCTLR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTRLDVR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTRLDVR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTRLDVR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTRLDVR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTVR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTVR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTVR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCNTVR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCCONFIGR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDEVAFF0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDEVAFF1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDEVARCH] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDEVID] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDEVTYPE] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCMR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCMR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCMR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCMR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCMR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCMR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCMR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCMR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCVR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCVR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCVR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCVR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCVR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCVR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCVR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCDVCVR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCEVENTCTL0R] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCEVENTCTL1R] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCEXTINSELR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCEXTINSELR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCEXTINSELR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCEXTINSELR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCEXTINSELR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR10] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR11] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR13] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR8] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIDR9] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIMSPEC0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIMSPEC1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIMSPEC2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIMSPEC3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIMSPEC4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIMSPEC5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIMSPEC6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCIMSPEC7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCITCTRL] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCLAR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCLSR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCOSLAR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCOSLSR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPDCR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPDSR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPIDR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPIDR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPIDR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPIDR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPIDR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPIDR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPIDR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPIDR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPRGCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCPROCSELR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCQCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR10] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR11] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR13] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR14] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR15] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR16] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR17] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR18] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR19] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR20] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR21] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR22] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR23] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR24] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR25] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR26] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR27] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR28] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR29] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR30] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR31] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR8] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSCTLR9] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCRSR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSEQEVR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSEQEVR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSEQEVR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSEQRSTEVR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSEQSTR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCCR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCCR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCCR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCCR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCCR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCCR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCCR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCCR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCSR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCSR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCSR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCSR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCSR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCSR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCSR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSCSR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSPCICR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSPCICR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSPCICR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSPCICR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSPCICR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSPCICR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSPCICR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSSPCICR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSTALLCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSTATR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCSYNCPR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCTRACEIDR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCTSCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVDARCCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVDCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVDSACCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVICTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVIIECTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVIPCSSCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVISSCTLR] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCCTLR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCCTLR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCVR0] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCVR1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCVR2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCVR3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCVR4] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCVR5] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCVR6] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRCVMIDCVR7] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRFCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRFCR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TRFCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TTBR0_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TTBR0_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TTBR0_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TTBR0_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TTBR1_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TTBR1_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_TTBR1_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_UAO] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VBAR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VBAR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VBAR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VBAR_EL3] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VDISR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VMPIDR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VNCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VPIDR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VSCTLR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VSESR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VSTCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VSTTBR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VTCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_VTTBR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ZCR_EL1] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ZCR_EL12] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ZCR_EL2] = systemRegisterMap_.size();
  systemRegisterMap_[ARM64_SYSREG_ZCR_EL3] = systemRegisterMap_.size();

  systemRegisterMap_[0xcd82] = systemRegisterMap_.size();  // s3_1_c11_c0_2

  // Get Virtual Counter Timer and Processor Cycle Counter system registers.
  VCTreg_ = {
      RegisterType::SYSTEM,
      static_cast<uint16_t>(getSystemRegisterTag(ARM64_SYSREG_CNTVCT_EL0))};
  PCCreg_ = {
      RegisterType::SYSTEM,
      static_cast<uint16_t>(getSystemRegisterTag(ARM64_SYSREG_PMCCNTR_EL0))};

  // Instantiate an ExecutionInfo entry for each group in the InstructionGroup
  // namespace.
  for (int i = 0; i < NUM_GROUPS; i++) {
    groupExecutionInfo_[i] = {1, 1, {}};
  }
  // Extract execution latency/throughput for each group
  std::vector<uint8_t> inheritanceDistance(NUM_GROUPS, UINT8_MAX);
  for (size_t i = 0; i < config["Latencies"].size(); i++) {
    YAML::Node port_node = config["Latencies"][i];
    uint16_t latency = port_node["Execution-Latency"].as<uint16_t>();
    uint16_t throughput = port_node["Execution-Throughput"].as<uint16_t>();
    for (size_t j = 0; j < port_node["Instruction-Group"].size(); j++) {
      uint16_t group = port_node["Instruction-Group"][j].as<uint16_t>();
      groupExecutionInfo_[group].latency = latency;
      groupExecutionInfo_[group].stallCycles = throughput;
      // Set zero inheritance distance for latency assignment as it's explicitly
      // defined
      inheritanceDistance[group] = 0;
      // Add inherited support for those appropriate groups
      std::queue<uint16_t> groups;
      groups.push(group);
      // Set a distance counter as 1 to represent 1 level of inheritance
      uint8_t distance = 1;
      while (groups.size()) {
        // Determine if there's any inheritance
        if (groupInheritance.find(groups.front()) != groupInheritance.end()) {
          std::vector<uint16_t> inheritedGroups =
              groupInheritance.at(groups.front());
          for (int k = 0; k < inheritedGroups.size(); k++) {
            // Determine if this group has inherited latency values from a
            // smaller distance
            if (inheritanceDistance[inheritedGroups[k]] > distance) {
              groupExecutionInfo_[inheritedGroups[k]].latency = latency;
              groupExecutionInfo_[inheritedGroups[k]].stallCycles = throughput;
              inheritanceDistance[inheritedGroups[k]] = distance;
            }
            groups.push(inheritedGroups[k]);
          }
        }
        groups.pop();
        distance++;
      }
    }
    // Store any opcode-based latency override
    for (size_t j = 0; j < port_node["Instruction-Opcode"].size(); j++) {
      uint16_t opcode = port_node["Instruction-Opcode"][j].as<uint16_t>();
      opcodeExecutionInfo_[opcode].latency = latency;
      opcodeExecutionInfo_[opcode].stallCycles = throughput;
    }
  }

  // ports entries in the groupExecutionInfo_ entries only apply for models
  // using the outoforder core archetype
  if (config["Core"]["Simulation-Mode"].as<std::string>() == "outoforder") {
    // Create mapping between instructions groups and the ports that support
    // them
    for (size_t i = 0; i < config["Ports"].size(); i++) {
      // Store which ports support which groups
      YAML::Node group_node = config["Ports"][i]["Instruction-Group-Support"];
      for (size_t j = 0; j < group_node.size(); j++) {
        uint16_t group = group_node[j].as<uint16_t>();
        uint8_t newPort = static_cast<uint8_t>(i);
        groupExecutionInfo_[group].ports.push_back(newPort);
        // Add inherited support for those appropriate groups
        std::queue<uint16_t> groups;
        groups.push(group);
        while (groups.size()) {
          // Determine if there's any inheritance
          if (groupInheritance.find(groups.front()) != groupInheritance.end()) {
            std::vector<uint16_t> inheritedGroups =
                groupInheritance.at(groups.front());
            for (int k = 0; k < inheritedGroups.size(); k++) {
              groupExecutionInfo_[inheritedGroups[k]].ports.push_back(newPort);
              groups.push(inheritedGroups[k]);
            }
          }
          groups.pop();
        }
      }
      // Store any opcode-based port support override
      YAML::Node opcode_node = config["Ports"][i]["Instruction-Opcode-Support"];
      for (size_t j = 0; j < opcode_node.size(); j++) {
        // If latency information hasn't been defined, set to zero as to inform
        // later access to use group defined latencies instead
        uint16_t opcode = opcode_node[j].as<uint16_t>();
        opcodeExecutionInfo_.try_emplace(
            opcode, simeng::arch::aarch64::ExecutionInfo{0, 0, {}});
        opcodeExecutionInfo_[opcode].ports.push_back(static_cast<uint8_t>(i));
      }
    }
  }
}
Architecture::~Architecture() {
  cs_close(&capstoneHandle);
  decodeCache.clear();
  metadataCache.clear();
  groupExecutionInfo_.clear();
  SVCRval_ = 0;
}

uint8_t Architecture::predecode(const void* ptr, uint8_t bytesAvailable,
                                uint64_t instructionAddress,
                                MacroOp& output) const {
  // Check that instruction address is 4-byte aligned as required by Armv9.2-a
  if (instructionAddress & 0x3) {
    // Consume 1-byte and raise a misaligned PC exception
    auto metadata = InstructionMetadata((uint8_t*)ptr, 1);
    metadataCache.emplace_front(metadata);
    output.resize(1);
    auto& uop = output[0];
    uop = std::make_shared<Instruction>(*this, metadataCache.front(),
                                        InstructionException::MisalignedPC);
    uop->setInstructionAddress(instructionAddress);
    // Return non-zero value to avoid fatal error
    return 1;
  }

  assert(bytesAvailable >= 4 &&
         "Fewer than 4 bytes supplied to AArch64 decoder");

  // Dereference the instruction pointer to obtain the instruction word
  // `ptr` is not guaranteed to be aligned.
  uint32_t insn;
  memcpy(&insn, ptr, 4);

  // Try to find the decoding in the decode cache
  auto iter = decodeCache.find(insn);
  if (iter == decodeCache.end()) {
    // No decoding present. Generate a fresh decoding, and add to cache
    cs_insn rawInsn;
    cs_detail rawDetail;
    rawInsn.detail = &rawDetail;

    size_t size = 4;
    uint64_t address = 0;

    const uint8_t* encoding = reinterpret_cast<const uint8_t*>(ptr);

    bool success =
        cs_disasm_iter(capstoneHandle, &encoding, &size, &address, &rawInsn);

    auto metadata =
        success ? InstructionMetadata(rawInsn) : InstructionMetadata(encoding);

    // Cache the metadata
    metadataCache.push_front(metadata);

    // Create an instruction using the metadata
    Instruction newInsn(*this, metadataCache.front(), MicroOpInfo());
    // Set execution information for this instruction
    newInsn.setExecutionInfo(getExecutionInfo(newInsn));
    // Cache the instruction
    iter = decodeCache.insert({insn, newInsn}).first;
  }

  // Split instruction into 1 or more defined micro-ops
  uint8_t num_ops = microDecoder_->decode(*this, iter->first, iter->second,
                                          output, capstoneHandle);

  // Set instruction address and branch prediction for each micro-op generated
  for (int i = 0; i < num_ops; i++) {
    output[i]->setInstructionAddress(instructionAddress);
  }

  return 4;
}

ExecutionInfo Architecture::getExecutionInfo(Instruction& insn) const {
  // Asusme no opcode-based override
  ExecutionInfo exeInfo = groupExecutionInfo_.at(insn.getGroup());
  if (opcodeExecutionInfo_.find(insn.getMetadata().opcode) !=
      opcodeExecutionInfo_.end()) {
    // Replace with overrided values
    ExecutionInfo overrideInfo =
        opcodeExecutionInfo_.at(insn.getMetadata().opcode);
    if (overrideInfo.latency != 0) exeInfo.latency = overrideInfo.latency;
    if (overrideInfo.stallCycles != 0)
      exeInfo.stallCycles = overrideInfo.stallCycles;
    if (overrideInfo.ports.size()) exeInfo.ports = overrideInfo.ports;
  }
  return exeInfo;
}

std::shared_ptr<arch::ExceptionHandler> Architecture::handleException(
    const std::shared_ptr<simeng::Instruction>& instruction, const Core& core,
    MemoryInterface& memory) const {
  return std::make_shared<ExceptionHandler>(instruction, core, memory, linux_);
}

std::vector<RegisterFileStructure> Architecture::getRegisterFileStructures()
    const {
  uint16_t numSysRegs = static_cast<uint16_t>(systemRegisterMap_.size());
  const uint16_t ZAsize = static_cast<uint16_t>(SVL_ / 8);  // Convert to bytes
  return {
      {8, 32},          // General purpose
      {256, 32},        // Vector
      {32, 17},         // Predicate
      {1, 1},           // NZCV
      {8, numSysRegs},  // System
      {256, ZAsize},    // Matrix (Each row is a register)
  };
}

int32_t Architecture::getSystemRegisterTag(uint16_t reg) const {
  // Check below is done for speculative instructions that may be passed into
  // the function but will not be executed. If such invalid speculative
  // instructions get through they can cause an out-of-range error.
  if (!systemRegisterMap_.count(reg)) return -1;
  return systemRegisterMap_.at(reg);
}

uint16_t Architecture::getNumSystemRegisters() const {
  return static_cast<uint16_t>(systemRegisterMap_.size());
}

ProcessStateChange Architecture::getInitialState() const {
  ProcessStateChange changes;
  // Set ProcessStateChange type
  changes.type = ChangeType::REPLACEMENT;

  uint64_t stackPointer = linux_.getInitialStackPointer();
  // Set the stack pointer register
  changes.modifiedRegisters.push_back({RegisterType::GENERAL, 31});
  changes.modifiedRegisterValues.push_back(stackPointer);

  // Set the system registers
  // Temporary: state that DCZ can support clearing 64 bytes at a time,
  // but is disabled due to bit 4 being set
  changes.modifiedRegisters.push_back(
      {RegisterType::SYSTEM,
       static_cast<uint16_t>(getSystemRegisterTag(ARM64_SYSREG_DCZID_EL0))});
  changes.modifiedRegisterValues.push_back(static_cast<uint64_t>(0b10100));

  return changes;
}

void Architecture::forwardPMUInc(uint16_t event, uint64_t value) const {
  linux_.pmuIncrement(event, value);
}

uint8_t Architecture::getMaxInstructionSize() const { return 4; }

uint64_t Architecture::getVectorLength() const { return VL_; }

uint64_t Architecture::getStreamingVectorLength() const { return SVL_; }

void Architecture::updateSystemTimerRegisters(RegisterFileSet* regFile,
                                              const uint64_t iterations) const {
  // Update the Processor Cycle Counter to total cycles completed.
  regFile->set(PCCreg_, iterations);
  // Update Virtual Counter Timer at correct frequency.
  if (iterations % (uint64_t)vctModulo_ == 0) {
    regFile->set(VCTreg_, regFile->get(VCTreg_).get<uint64_t>() + 1);
  }
}

std::vector<RegisterFileStructure>
Architecture::getConfigPhysicalRegisterStructure(YAML::Node config) const {
  // Matrix-Count multiplied by (SVL/8) as internal representation of
  // ZA is a block of row-vector-registers. Therefore we need to
  // convert physical counts from whole-ZA to rows-in-ZA.
  uint16_t matCount =
      config["Register-Set"]["Matrix-Count"].as<uint16_t>() *
      (config["Core"]["Streaming-Vector-Length"].as<uint16_t>() / 8);
  return {
      {8, config["Register-Set"]["GeneralPurpose-Count"].as<uint16_t>()},
      {256, config["Register-Set"]["FloatingPoint/SVE-Count"].as<uint16_t>()},
      {32, config["Register-Set"]["Predicate-Count"].as<uint16_t>()},
      {1, config["Register-Set"]["Conditional-Count"].as<uint16_t>()},
      {8, getNumSystemRegisters()},
      {256, matCount}};
}

std::vector<uint16_t> Architecture::getConfigPhysicalRegisterQuantities(
    YAML::Node config) const {
  // Matrix-Count multiplied by (SVL/8) as internal representation of
  // ZA is a block of row-vector-registers. Therefore we need to
  // convert physical counts from whole-ZA to rows-in-ZA.
  uint16_t matCount =
      config["Register-Set"]["Matrix-Count"].as<uint16_t>() *
      (config["Core"]["Streaming-Vector-Length"].as<uint16_t>() / 8);
  return {config["Register-Set"]["GeneralPurpose-Count"].as<uint16_t>(),
          config["Register-Set"]["FloatingPoint/SVE-Count"].as<uint16_t>(),
          config["Register-Set"]["Predicate-Count"].as<uint16_t>(),
          config["Register-Set"]["Conditional-Count"].as<uint16_t>(),
          getNumSystemRegisters(),
          matCount};
}

/** The SVCR value is stored in Architecture to allow the value to be
 * retrieved within execution pipeline. This prevents adding an implicit
 * operand to every SME instruction; reducing the amount of complexity when
 * implementing SME execution logic. */
uint64_t Architecture::getSVCRval() const { return SVCRval_; }

void Architecture::setSVCRval(const uint64_t newVal) const {
  SVCRval_ = newVal;
}

}  // namespace aarch64
}  // namespace arch
}  // namespace simeng
