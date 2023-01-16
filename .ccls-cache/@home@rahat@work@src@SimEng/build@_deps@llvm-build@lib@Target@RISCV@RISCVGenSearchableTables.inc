#ifdef GET_RISCVOpcodesList_DECL
const RISCVOpcode *lookupRISCVOpcodeByValue(uint8_t Value);
const RISCVOpcode *lookupRISCVOpcodeByName(StringRef Name);
#endif

#ifdef GET_RISCVOpcodesList_IMPL
constexpr RISCVOpcode RISCVOpcodesList[] = {
  { "LOAD", 0x3 }, // 0
  { "LOAD_FP", 0x7 }, // 1
  { "MISC_MEM", 0xF }, // 2
  { "OP_IMM", 0x13 }, // 3
  { "AUIPC", 0x17 }, // 4
  { "OP_IMM_32", 0x1B }, // 5
  { "STORE", 0x23 }, // 6
  { "STORE_FP", 0x27 }, // 7
  { "AMO", 0x2F }, // 8
  { "OP", 0x33 }, // 9
  { "LUI", 0x37 }, // 10
  { "OP_32", 0x3B }, // 11
  { "MADD", 0x43 }, // 12
  { "MSUB", 0x47 }, // 13
  { "NMSUB", 0x4B }, // 14
  { "NMADD", 0x4F }, // 15
  { "OP_FP", 0x53 }, // 16
  { "OP_V", 0x57 }, // 17
  { "BRANCH", 0x63 }, // 18
  { "JALR", 0x67 }, // 19
  { "JAL", 0x6F }, // 20
  { "SYSTEM", 0x73 }, // 21
 };

const RISCVOpcode *lookupRISCVOpcodeByValue(uint8_t Value) {
  struct KeyType {
    uint8_t Value;
  };
  KeyType Key = {Value};
  auto Table = makeArrayRef(RISCVOpcodesList);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const RISCVOpcode &LHS, const KeyType &RHS) {
      if (LHS.Value < RHS.Value)
        return true;
      if (LHS.Value > RHS.Value)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.Value != Idx->Value)
    return nullptr;
  return &*Idx;
}

const RISCVOpcode *lookupRISCVOpcodeByName(StringRef Name) {
  struct IndexType {
    const char * Name;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { "AMO", 8 },
    { "AUIPC", 4 },
    { "BRANCH", 18 },
    { "JAL", 20 },
    { "JALR", 19 },
    { "LOAD", 0 },
    { "LOAD_FP", 1 },
    { "LUI", 10 },
    { "MADD", 12 },
    { "MISC_MEM", 2 },
    { "MSUB", 13 },
    { "NMADD", 15 },
    { "NMSUB", 14 },
    { "OP", 9 },
    { "OP_32", 11 },
    { "OP_FP", 16 },
    { "OP_IMM", 3 },
    { "OP_IMM_32", 5 },
    { "OP_V", 17 },
    { "STORE", 6 },
    { "STORE_FP", 7 },
    { "SYSTEM", 21 },
  };

  struct KeyType {
    std::string Name;
  };
  KeyType Key = {Name.upper()};
  auto Table = makeArrayRef(Index);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const IndexType &LHS, const KeyType &RHS) {
      int CmpName = StringRef(LHS.Name).compare(RHS.Name);
      if (CmpName < 0) return true;
      if (CmpName > 0) return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.Name != Idx->Name)
    return nullptr;
  return &RISCVOpcodesList[Idx->_index];
}
#endif

#ifdef GET_RISCVVIntrinsicsTable_DECL
const RISCVVIntrinsicInfo *getRISCVVIntrinsicInfo(unsigned IntrinsicID);
#endif

#ifdef GET_RISCVVIntrinsicsTable_IMPL
constexpr RISCVVIntrinsicInfo RISCVVIntrinsicsTable[] = {
  { Intrinsic::riscv_vaadd, 0x1, 0x2 }, // 0
  { Intrinsic::riscv_vaadd_mask, 0x2, 0x4 }, // 1
  { Intrinsic::riscv_vaaddu, 0x1, 0x2 }, // 2
  { Intrinsic::riscv_vaaddu_mask, 0x2, 0x4 }, // 3
  { Intrinsic::riscv_vadc, 0x1, 0x3 }, // 4
  { Intrinsic::riscv_vadd, 0x1, 0x2 }, // 5
  { Intrinsic::riscv_vadd_mask, 0x2, 0x4 }, // 6
  { Intrinsic::riscv_vand, 0x1, 0x2 }, // 7
  { Intrinsic::riscv_vand_mask, 0x2, 0x4 }, // 8
  { Intrinsic::riscv_vasub, 0x1, 0x2 }, // 9
  { Intrinsic::riscv_vasub_mask, 0x2, 0x4 }, // 10
  { Intrinsic::riscv_vasubu, 0x1, 0x2 }, // 11
  { Intrinsic::riscv_vasubu_mask, 0x2, 0x4 }, // 12
  { Intrinsic::riscv_vcompress, 0xF, 0x3 }, // 13
  { Intrinsic::riscv_vcpop, 0xF, 0x1 }, // 14
  { Intrinsic::riscv_vcpop_mask, 0xF, 0x2 }, // 15
  { Intrinsic::riscv_vdiv, 0x1, 0x2 }, // 16
  { Intrinsic::riscv_vdiv_mask, 0x2, 0x4 }, // 17
  { Intrinsic::riscv_vdivu, 0x1, 0x2 }, // 18
  { Intrinsic::riscv_vdivu_mask, 0x2, 0x4 }, // 19
  { Intrinsic::riscv_vfadd, 0x1, 0x2 }, // 20
  { Intrinsic::riscv_vfadd_mask, 0x2, 0x4 }, // 21
  { Intrinsic::riscv_vfclass, 0xF, 0x1 }, // 22
  { Intrinsic::riscv_vfclass_mask, 0xF, 0x3 }, // 23
  { Intrinsic::riscv_vfcvt_f_x_v, 0xF, 0x1 }, // 24
  { Intrinsic::riscv_vfcvt_f_x_v_mask, 0xF, 0x3 }, // 25
  { Intrinsic::riscv_vfcvt_f_xu_v, 0xF, 0x1 }, // 26
  { Intrinsic::riscv_vfcvt_f_xu_v_mask, 0xF, 0x3 }, // 27
  { Intrinsic::riscv_vfcvt_rtz_x_f_v, 0xF, 0x1 }, // 28
  { Intrinsic::riscv_vfcvt_rtz_x_f_v_mask, 0xF, 0x3 }, // 29
  { Intrinsic::riscv_vfcvt_rtz_xu_f_v, 0xF, 0x1 }, // 30
  { Intrinsic::riscv_vfcvt_rtz_xu_f_v_mask, 0xF, 0x3 }, // 31
  { Intrinsic::riscv_vfcvt_x_f_v, 0xF, 0x1 }, // 32
  { Intrinsic::riscv_vfcvt_x_f_v_mask, 0xF, 0x3 }, // 33
  { Intrinsic::riscv_vfcvt_xu_f_v, 0xF, 0x1 }, // 34
  { Intrinsic::riscv_vfcvt_xu_f_v_mask, 0xF, 0x3 }, // 35
  { Intrinsic::riscv_vfdiv, 0x1, 0x2 }, // 36
  { Intrinsic::riscv_vfdiv_mask, 0x2, 0x4 }, // 37
  { Intrinsic::riscv_vfirst, 0xF, 0x1 }, // 38
  { Intrinsic::riscv_vfirst_mask, 0xF, 0x2 }, // 39
  { Intrinsic::riscv_vfmacc, 0x1, 0x3 }, // 40
  { Intrinsic::riscv_vfmacc_mask, 0x1, 0x4 }, // 41
  { Intrinsic::riscv_vfmadd, 0x1, 0x3 }, // 42
  { Intrinsic::riscv_vfmadd_mask, 0x1, 0x4 }, // 43
  { Intrinsic::riscv_vfmax, 0x1, 0x2 }, // 44
  { Intrinsic::riscv_vfmax_mask, 0x2, 0x4 }, // 45
  { Intrinsic::riscv_vfmerge, 0x1, 0x3 }, // 46
  { Intrinsic::riscv_vfmin, 0x1, 0x2 }, // 47
  { Intrinsic::riscv_vfmin_mask, 0x2, 0x4 }, // 48
  { Intrinsic::riscv_vfmsac, 0x1, 0x3 }, // 49
  { Intrinsic::riscv_vfmsac_mask, 0x1, 0x4 }, // 50
  { Intrinsic::riscv_vfmsub, 0x1, 0x3 }, // 51
  { Intrinsic::riscv_vfmsub_mask, 0x1, 0x4 }, // 52
  { Intrinsic::riscv_vfmul, 0x1, 0x2 }, // 53
  { Intrinsic::riscv_vfmul_mask, 0x2, 0x4 }, // 54
  { Intrinsic::riscv_vfmv_f_s, 0xF, 0x1F }, // 55
  { Intrinsic::riscv_vfmv_s_f, 0xF, 0x2 }, // 56
  { Intrinsic::riscv_vfmv_v_f, 0xF, 0x1 }, // 57
  { Intrinsic::riscv_vfncvt_f_f_w, 0xF, 0x1 }, // 58
  { Intrinsic::riscv_vfncvt_f_f_w_mask, 0xF, 0x3 }, // 59
  { Intrinsic::riscv_vfncvt_f_x_w, 0xF, 0x1 }, // 60
  { Intrinsic::riscv_vfncvt_f_x_w_mask, 0xF, 0x3 }, // 61
  { Intrinsic::riscv_vfncvt_f_xu_w, 0xF, 0x1 }, // 62
  { Intrinsic::riscv_vfncvt_f_xu_w_mask, 0xF, 0x3 }, // 63
  { Intrinsic::riscv_vfncvt_rod_f_f_w, 0xF, 0x1 }, // 64
  { Intrinsic::riscv_vfncvt_rod_f_f_w_mask, 0xF, 0x3 }, // 65
  { Intrinsic::riscv_vfncvt_rtz_x_f_w, 0xF, 0x1 }, // 66
  { Intrinsic::riscv_vfncvt_rtz_x_f_w_mask, 0xF, 0x3 }, // 67
  { Intrinsic::riscv_vfncvt_rtz_xu_f_w, 0xF, 0x1 }, // 68
  { Intrinsic::riscv_vfncvt_rtz_xu_f_w_mask, 0xF, 0x3 }, // 69
  { Intrinsic::riscv_vfncvt_x_f_w, 0xF, 0x1 }, // 70
  { Intrinsic::riscv_vfncvt_x_f_w_mask, 0xF, 0x3 }, // 71
  { Intrinsic::riscv_vfncvt_xu_f_w, 0xF, 0x1 }, // 72
  { Intrinsic::riscv_vfncvt_xu_f_w_mask, 0xF, 0x3 }, // 73
  { Intrinsic::riscv_vfnmacc, 0x1, 0x3 }, // 74
  { Intrinsic::riscv_vfnmacc_mask, 0x1, 0x4 }, // 75
  { Intrinsic::riscv_vfnmadd, 0x1, 0x3 }, // 76
  { Intrinsic::riscv_vfnmadd_mask, 0x1, 0x4 }, // 77
  { Intrinsic::riscv_vfnmsac, 0x1, 0x3 }, // 78
  { Intrinsic::riscv_vfnmsac_mask, 0x1, 0x4 }, // 79
  { Intrinsic::riscv_vfnmsub, 0x1, 0x3 }, // 80
  { Intrinsic::riscv_vfnmsub_mask, 0x1, 0x4 }, // 81
  { Intrinsic::riscv_vfrdiv, 0x1, 0x2 }, // 82
  { Intrinsic::riscv_vfrdiv_mask, 0x2, 0x4 }, // 83
  { Intrinsic::riscv_vfrec7, 0xF, 0x1 }, // 84
  { Intrinsic::riscv_vfrec7_mask, 0xF, 0x3 }, // 85
  { Intrinsic::riscv_vfredmax, 0xF, 0x3 }, // 86
  { Intrinsic::riscv_vfredmax_mask, 0xF, 0x4 }, // 87
  { Intrinsic::riscv_vfredmin, 0xF, 0x3 }, // 88
  { Intrinsic::riscv_vfredmin_mask, 0xF, 0x4 }, // 89
  { Intrinsic::riscv_vfredosum, 0xF, 0x3 }, // 90
  { Intrinsic::riscv_vfredosum_mask, 0xF, 0x4 }, // 91
  { Intrinsic::riscv_vfredusum, 0xF, 0x3 }, // 92
  { Intrinsic::riscv_vfredusum_mask, 0xF, 0x4 }, // 93
  { Intrinsic::riscv_vfrsqrt7, 0xF, 0x1 }, // 94
  { Intrinsic::riscv_vfrsqrt7_mask, 0xF, 0x3 }, // 95
  { Intrinsic::riscv_vfrsub, 0x1, 0x2 }, // 96
  { Intrinsic::riscv_vfrsub_mask, 0x2, 0x4 }, // 97
  { Intrinsic::riscv_vfsgnj, 0x1, 0x2 }, // 98
  { Intrinsic::riscv_vfsgnj_mask, 0x2, 0x4 }, // 99
  { Intrinsic::riscv_vfsgnjn, 0x1, 0x2 }, // 100
  { Intrinsic::riscv_vfsgnjn_mask, 0x2, 0x4 }, // 101
  { Intrinsic::riscv_vfsgnjx, 0x1, 0x2 }, // 102
  { Intrinsic::riscv_vfsgnjx_mask, 0x2, 0x4 }, // 103
  { Intrinsic::riscv_vfslide1down, 0x1, 0x2 }, // 104
  { Intrinsic::riscv_vfslide1down_mask, 0x2, 0x4 }, // 105
  { Intrinsic::riscv_vfslide1up, 0x1, 0x2 }, // 106
  { Intrinsic::riscv_vfslide1up_mask, 0x2, 0x4 }, // 107
  { Intrinsic::riscv_vfsqrt, 0xF, 0x1 }, // 108
  { Intrinsic::riscv_vfsqrt_mask, 0xF, 0x3 }, // 109
  { Intrinsic::riscv_vfsub, 0x1, 0x2 }, // 110
  { Intrinsic::riscv_vfsub_mask, 0x2, 0x4 }, // 111
  { Intrinsic::riscv_vfwadd, 0x1, 0x2 }, // 112
  { Intrinsic::riscv_vfwadd_mask, 0x2, 0x4 }, // 113
  { Intrinsic::riscv_vfwadd_w, 0x1, 0x2 }, // 114
  { Intrinsic::riscv_vfwadd_w_mask, 0x2, 0x4 }, // 115
  { Intrinsic::riscv_vfwcvt_f_f_v, 0xF, 0x1 }, // 116
  { Intrinsic::riscv_vfwcvt_f_f_v_mask, 0xF, 0x3 }, // 117
  { Intrinsic::riscv_vfwcvt_f_x_v, 0xF, 0x1 }, // 118
  { Intrinsic::riscv_vfwcvt_f_x_v_mask, 0xF, 0x3 }, // 119
  { Intrinsic::riscv_vfwcvt_f_xu_v, 0xF, 0x1 }, // 120
  { Intrinsic::riscv_vfwcvt_f_xu_v_mask, 0xF, 0x3 }, // 121
  { Intrinsic::riscv_vfwcvt_rtz_x_f_v, 0xF, 0x1 }, // 122
  { Intrinsic::riscv_vfwcvt_rtz_x_f_v_mask, 0xF, 0x3 }, // 123
  { Intrinsic::riscv_vfwcvt_rtz_xu_f_v, 0xF, 0x1 }, // 124
  { Intrinsic::riscv_vfwcvt_rtz_xu_f_v_mask, 0xF, 0x3 }, // 125
  { Intrinsic::riscv_vfwcvt_x_f_v, 0xF, 0x1 }, // 126
  { Intrinsic::riscv_vfwcvt_x_f_v_mask, 0xF, 0x3 }, // 127
  { Intrinsic::riscv_vfwcvt_xu_f_v, 0xF, 0x1 }, // 128
  { Intrinsic::riscv_vfwcvt_xu_f_v_mask, 0xF, 0x3 }, // 129
  { Intrinsic::riscv_vfwmacc, 0x1, 0x3 }, // 130
  { Intrinsic::riscv_vfwmacc_mask, 0x1, 0x4 }, // 131
  { Intrinsic::riscv_vfwmsac, 0x1, 0x3 }, // 132
  { Intrinsic::riscv_vfwmsac_mask, 0x1, 0x4 }, // 133
  { Intrinsic::riscv_vfwmul, 0x1, 0x2 }, // 134
  { Intrinsic::riscv_vfwmul_mask, 0x2, 0x4 }, // 135
  { Intrinsic::riscv_vfwnmacc, 0x1, 0x3 }, // 136
  { Intrinsic::riscv_vfwnmacc_mask, 0x1, 0x4 }, // 137
  { Intrinsic::riscv_vfwnmsac, 0x1, 0x3 }, // 138
  { Intrinsic::riscv_vfwnmsac_mask, 0x1, 0x4 }, // 139
  { Intrinsic::riscv_vfwredosum, 0xF, 0x3 }, // 140
  { Intrinsic::riscv_vfwredosum_mask, 0xF, 0x4 }, // 141
  { Intrinsic::riscv_vfwredusum, 0xF, 0x3 }, // 142
  { Intrinsic::riscv_vfwredusum_mask, 0xF, 0x4 }, // 143
  { Intrinsic::riscv_vfwsub, 0x1, 0x2 }, // 144
  { Intrinsic::riscv_vfwsub_mask, 0x2, 0x4 }, // 145
  { Intrinsic::riscv_vfwsub_w, 0x1, 0x2 }, // 146
  { Intrinsic::riscv_vfwsub_w_mask, 0x2, 0x4 }, // 147
  { Intrinsic::riscv_vid, 0xF, 0x0 }, // 148
  { Intrinsic::riscv_vid_mask, 0xF, 0x2 }, // 149
  { Intrinsic::riscv_viota, 0xF, 0x1 }, // 150
  { Intrinsic::riscv_viota_mask, 0xF, 0x3 }, // 151
  { Intrinsic::riscv_vle, 0xF, 0x2 }, // 152
  { Intrinsic::riscv_vle_mask, 0xF, 0x3 }, // 153
  { Intrinsic::riscv_vleff, 0xF, 0x2 }, // 154
  { Intrinsic::riscv_vleff_mask, 0xF, 0x3 }, // 155
  { Intrinsic::riscv_vlm, 0xF, 0x1 }, // 156
  { Intrinsic::riscv_vloxei, 0xF, 0x3 }, // 157
  { Intrinsic::riscv_vloxei_mask, 0xF, 0x4 }, // 158
  { Intrinsic::riscv_vloxseg2, 0xF, 0x2 }, // 159
  { Intrinsic::riscv_vloxseg2_mask, 0xF, 0x5 }, // 160
  { Intrinsic::riscv_vloxseg3, 0xF, 0x2 }, // 161
  { Intrinsic::riscv_vloxseg3_mask, 0xF, 0x6 }, // 162
  { Intrinsic::riscv_vloxseg4, 0xF, 0x2 }, // 163
  { Intrinsic::riscv_vloxseg4_mask, 0xF, 0x7 }, // 164
  { Intrinsic::riscv_vloxseg5, 0xF, 0x2 }, // 165
  { Intrinsic::riscv_vloxseg5_mask, 0xF, 0x8 }, // 166
  { Intrinsic::riscv_vloxseg6, 0xF, 0x2 }, // 167
  { Intrinsic::riscv_vloxseg6_mask, 0xF, 0x9 }, // 168
  { Intrinsic::riscv_vloxseg7, 0xF, 0x2 }, // 169
  { Intrinsic::riscv_vloxseg7_mask, 0xF, 0xA }, // 170
  { Intrinsic::riscv_vloxseg8, 0xF, 0x2 }, // 171
  { Intrinsic::riscv_vloxseg8_mask, 0xF, 0xB }, // 172
  { Intrinsic::riscv_vlse, 0xF, 0x3 }, // 173
  { Intrinsic::riscv_vlse_mask, 0xF, 0x4 }, // 174
  { Intrinsic::riscv_vlseg2, 0xF, 0x1 }, // 175
  { Intrinsic::riscv_vlseg2_mask, 0xF, 0x4 }, // 176
  { Intrinsic::riscv_vlseg2ff, 0xF, 0x1 }, // 177
  { Intrinsic::riscv_vlseg2ff_mask, 0xF, 0x4 }, // 178
  { Intrinsic::riscv_vlseg3, 0xF, 0x1 }, // 179
  { Intrinsic::riscv_vlseg3_mask, 0xF, 0x5 }, // 180
  { Intrinsic::riscv_vlseg3ff, 0xF, 0x1 }, // 181
  { Intrinsic::riscv_vlseg3ff_mask, 0xF, 0x5 }, // 182
  { Intrinsic::riscv_vlseg4, 0xF, 0x1 }, // 183
  { Intrinsic::riscv_vlseg4_mask, 0xF, 0x6 }, // 184
  { Intrinsic::riscv_vlseg4ff, 0xF, 0x1 }, // 185
  { Intrinsic::riscv_vlseg4ff_mask, 0xF, 0x6 }, // 186
  { Intrinsic::riscv_vlseg5, 0xF, 0x1 }, // 187
  { Intrinsic::riscv_vlseg5_mask, 0xF, 0x7 }, // 188
  { Intrinsic::riscv_vlseg5ff, 0xF, 0x1 }, // 189
  { Intrinsic::riscv_vlseg5ff_mask, 0xF, 0x7 }, // 190
  { Intrinsic::riscv_vlseg6, 0xF, 0x1 }, // 191
  { Intrinsic::riscv_vlseg6_mask, 0xF, 0x8 }, // 192
  { Intrinsic::riscv_vlseg6ff, 0xF, 0x1 }, // 193
  { Intrinsic::riscv_vlseg6ff_mask, 0xF, 0x8 }, // 194
  { Intrinsic::riscv_vlseg7, 0xF, 0x1 }, // 195
  { Intrinsic::riscv_vlseg7_mask, 0xF, 0x9 }, // 196
  { Intrinsic::riscv_vlseg7ff, 0xF, 0x1 }, // 197
  { Intrinsic::riscv_vlseg7ff_mask, 0xF, 0x9 }, // 198
  { Intrinsic::riscv_vlseg8, 0xF, 0x1 }, // 199
  { Intrinsic::riscv_vlseg8_mask, 0xF, 0xA }, // 200
  { Intrinsic::riscv_vlseg8ff, 0xF, 0x1 }, // 201
  { Intrinsic::riscv_vlseg8ff_mask, 0xF, 0xA }, // 202
  { Intrinsic::riscv_vlsseg2, 0xF, 0x2 }, // 203
  { Intrinsic::riscv_vlsseg2_mask, 0xF, 0x5 }, // 204
  { Intrinsic::riscv_vlsseg3, 0xF, 0x2 }, // 205
  { Intrinsic::riscv_vlsseg3_mask, 0xF, 0x6 }, // 206
  { Intrinsic::riscv_vlsseg4, 0xF, 0x2 }, // 207
  { Intrinsic::riscv_vlsseg4_mask, 0xF, 0x7 }, // 208
  { Intrinsic::riscv_vlsseg5, 0xF, 0x2 }, // 209
  { Intrinsic::riscv_vlsseg5_mask, 0xF, 0x8 }, // 210
  { Intrinsic::riscv_vlsseg6, 0xF, 0x2 }, // 211
  { Intrinsic::riscv_vlsseg6_mask, 0xF, 0x9 }, // 212
  { Intrinsic::riscv_vlsseg7, 0xF, 0x2 }, // 213
  { Intrinsic::riscv_vlsseg7_mask, 0xF, 0xA }, // 214
  { Intrinsic::riscv_vlsseg8, 0xF, 0x2 }, // 215
  { Intrinsic::riscv_vlsseg8_mask, 0xF, 0xB }, // 216
  { Intrinsic::riscv_vluxei, 0xF, 0x3 }, // 217
  { Intrinsic::riscv_vluxei_mask, 0xF, 0x4 }, // 218
  { Intrinsic::riscv_vluxseg2, 0xF, 0x2 }, // 219
  { Intrinsic::riscv_vluxseg2_mask, 0xF, 0x5 }, // 220
  { Intrinsic::riscv_vluxseg3, 0xF, 0x2 }, // 221
  { Intrinsic::riscv_vluxseg3_mask, 0xF, 0x6 }, // 222
  { Intrinsic::riscv_vluxseg4, 0xF, 0x2 }, // 223
  { Intrinsic::riscv_vluxseg4_mask, 0xF, 0x7 }, // 224
  { Intrinsic::riscv_vluxseg5, 0xF, 0x2 }, // 225
  { Intrinsic::riscv_vluxseg5_mask, 0xF, 0x8 }, // 226
  { Intrinsic::riscv_vluxseg6, 0xF, 0x2 }, // 227
  { Intrinsic::riscv_vluxseg6_mask, 0xF, 0x9 }, // 228
  { Intrinsic::riscv_vluxseg7, 0xF, 0x2 }, // 229
  { Intrinsic::riscv_vluxseg7_mask, 0xF, 0xA }, // 230
  { Intrinsic::riscv_vluxseg8, 0xF, 0x2 }, // 231
  { Intrinsic::riscv_vluxseg8_mask, 0xF, 0xB }, // 232
  { Intrinsic::riscv_vmacc, 0x1, 0x3 }, // 233
  { Intrinsic::riscv_vmacc_mask, 0x1, 0x4 }, // 234
  { Intrinsic::riscv_vmadc, 0x1, 0x2 }, // 235
  { Intrinsic::riscv_vmadc_carry_in, 0x1, 0x3 }, // 236
  { Intrinsic::riscv_vmadd, 0x1, 0x3 }, // 237
  { Intrinsic::riscv_vmadd_mask, 0x1, 0x4 }, // 238
  { Intrinsic::riscv_vmand, 0xF, 0x2 }, // 239
  { Intrinsic::riscv_vmandn, 0xF, 0x2 }, // 240
  { Intrinsic::riscv_vmax, 0x1, 0x2 }, // 241
  { Intrinsic::riscv_vmax_mask, 0x2, 0x4 }, // 242
  { Intrinsic::riscv_vmaxu, 0x1, 0x2 }, // 243
  { Intrinsic::riscv_vmaxu_mask, 0x2, 0x4 }, // 244
  { Intrinsic::riscv_vmclr, 0xF, 0x0 }, // 245
  { Intrinsic::riscv_vmerge, 0x1, 0x3 }, // 246
  { Intrinsic::riscv_vmfeq, 0x1, 0x2 }, // 247
  { Intrinsic::riscv_vmfeq_mask, 0x2, 0x4 }, // 248
  { Intrinsic::riscv_vmfge, 0x1, 0x2 }, // 249
  { Intrinsic::riscv_vmfge_mask, 0x2, 0x4 }, // 250
  { Intrinsic::riscv_vmfgt, 0x1, 0x2 }, // 251
  { Intrinsic::riscv_vmfgt_mask, 0x2, 0x4 }, // 252
  { Intrinsic::riscv_vmfle, 0x1, 0x2 }, // 253
  { Intrinsic::riscv_vmfle_mask, 0x2, 0x4 }, // 254
  { Intrinsic::riscv_vmflt, 0x1, 0x2 }, // 255
  { Intrinsic::riscv_vmflt_mask, 0x2, 0x4 }, // 256
  { Intrinsic::riscv_vmfne, 0x1, 0x2 }, // 257
  { Intrinsic::riscv_vmfne_mask, 0x2, 0x4 }, // 258
  { Intrinsic::riscv_vmin, 0x1, 0x2 }, // 259
  { Intrinsic::riscv_vmin_mask, 0x2, 0x4 }, // 260
  { Intrinsic::riscv_vminu, 0x1, 0x2 }, // 261
  { Intrinsic::riscv_vminu_mask, 0x2, 0x4 }, // 262
  { Intrinsic::riscv_vmnand, 0xF, 0x2 }, // 263
  { Intrinsic::riscv_vmnor, 0xF, 0x2 }, // 264
  { Intrinsic::riscv_vmor, 0xF, 0x2 }, // 265
  { Intrinsic::riscv_vmorn, 0xF, 0x2 }, // 266
  { Intrinsic::riscv_vmsbc, 0x1, 0x2 }, // 267
  { Intrinsic::riscv_vmsbc_borrow_in, 0x1, 0x3 }, // 268
  { Intrinsic::riscv_vmsbf, 0xF, 0x1 }, // 269
  { Intrinsic::riscv_vmsbf_mask, 0xF, 0x3 }, // 270
  { Intrinsic::riscv_vmseq, 0x1, 0x2 }, // 271
  { Intrinsic::riscv_vmseq_mask, 0x2, 0x4 }, // 272
  { Intrinsic::riscv_vmset, 0xF, 0x0 }, // 273
  { Intrinsic::riscv_vmsge, 0x1, 0x2 }, // 274
  { Intrinsic::riscv_vmsge_mask, 0x2, 0x4 }, // 275
  { Intrinsic::riscv_vmsgeu, 0x1, 0x2 }, // 276
  { Intrinsic::riscv_vmsgeu_mask, 0x2, 0x4 }, // 277
  { Intrinsic::riscv_vmsgt, 0x1, 0x2 }, // 278
  { Intrinsic::riscv_vmsgt_mask, 0x2, 0x4 }, // 279
  { Intrinsic::riscv_vmsgtu, 0x1, 0x2 }, // 280
  { Intrinsic::riscv_vmsgtu_mask, 0x2, 0x4 }, // 281
  { Intrinsic::riscv_vmsif, 0xF, 0x1 }, // 282
  { Intrinsic::riscv_vmsif_mask, 0xF, 0x3 }, // 283
  { Intrinsic::riscv_vmsle, 0x1, 0x2 }, // 284
  { Intrinsic::riscv_vmsle_mask, 0x2, 0x4 }, // 285
  { Intrinsic::riscv_vmsleu, 0x1, 0x2 }, // 286
  { Intrinsic::riscv_vmsleu_mask, 0x2, 0x4 }, // 287
  { Intrinsic::riscv_vmslt, 0x1, 0x2 }, // 288
  { Intrinsic::riscv_vmslt_mask, 0x2, 0x4 }, // 289
  { Intrinsic::riscv_vmsltu, 0x1, 0x2 }, // 290
  { Intrinsic::riscv_vmsltu_mask, 0x2, 0x4 }, // 291
  { Intrinsic::riscv_vmsne, 0x1, 0x2 }, // 292
  { Intrinsic::riscv_vmsne_mask, 0x2, 0x4 }, // 293
  { Intrinsic::riscv_vmsof, 0xF, 0x1 }, // 294
  { Intrinsic::riscv_vmsof_mask, 0xF, 0x3 }, // 295
  { Intrinsic::riscv_vmul, 0x1, 0x2 }, // 296
  { Intrinsic::riscv_vmul_mask, 0x2, 0x4 }, // 297
  { Intrinsic::riscv_vmulh, 0x1, 0x2 }, // 298
  { Intrinsic::riscv_vmulh_mask, 0x2, 0x4 }, // 299
  { Intrinsic::riscv_vmulhsu, 0x1, 0x2 }, // 300
  { Intrinsic::riscv_vmulhsu_mask, 0x2, 0x4 }, // 301
  { Intrinsic::riscv_vmulhu, 0x1, 0x2 }, // 302
  { Intrinsic::riscv_vmulhu_mask, 0x2, 0x4 }, // 303
  { Intrinsic::riscv_vmv_s_x, 0xF, 0x2 }, // 304
  { Intrinsic::riscv_vmv_v_v, 0xF, 0x1 }, // 305
  { Intrinsic::riscv_vmv_v_x, 0xF, 0x1 }, // 306
  { Intrinsic::riscv_vmv_x_s, 0xF, 0x1F }, // 307
  { Intrinsic::riscv_vmxnor, 0xF, 0x2 }, // 308
  { Intrinsic::riscv_vmxor, 0xF, 0x2 }, // 309
  { Intrinsic::riscv_vnclip, 0xF, 0x2 }, // 310
  { Intrinsic::riscv_vnclip_mask, 0xF, 0x4 }, // 311
  { Intrinsic::riscv_vnclipu, 0xF, 0x2 }, // 312
  { Intrinsic::riscv_vnclipu_mask, 0xF, 0x4 }, // 313
  { Intrinsic::riscv_vnmsac, 0x1, 0x3 }, // 314
  { Intrinsic::riscv_vnmsac_mask, 0x1, 0x4 }, // 315
  { Intrinsic::riscv_vnmsub, 0x1, 0x3 }, // 316
  { Intrinsic::riscv_vnmsub_mask, 0x1, 0x4 }, // 317
  { Intrinsic::riscv_vnsra, 0xF, 0x2 }, // 318
  { Intrinsic::riscv_vnsra_mask, 0xF, 0x4 }, // 319
  { Intrinsic::riscv_vnsrl, 0xF, 0x2 }, // 320
  { Intrinsic::riscv_vnsrl_mask, 0xF, 0x4 }, // 321
  { Intrinsic::riscv_vor, 0x1, 0x2 }, // 322
  { Intrinsic::riscv_vor_mask, 0x2, 0x4 }, // 323
  { Intrinsic::riscv_vredand, 0xF, 0x3 }, // 324
  { Intrinsic::riscv_vredand_mask, 0xF, 0x4 }, // 325
  { Intrinsic::riscv_vredmax, 0xF, 0x3 }, // 326
  { Intrinsic::riscv_vredmax_mask, 0xF, 0x4 }, // 327
  { Intrinsic::riscv_vredmaxu, 0xF, 0x3 }, // 328
  { Intrinsic::riscv_vredmaxu_mask, 0xF, 0x4 }, // 329
  { Intrinsic::riscv_vredmin, 0xF, 0x3 }, // 330
  { Intrinsic::riscv_vredmin_mask, 0xF, 0x4 }, // 331
  { Intrinsic::riscv_vredminu, 0xF, 0x3 }, // 332
  { Intrinsic::riscv_vredminu_mask, 0xF, 0x4 }, // 333
  { Intrinsic::riscv_vredor, 0xF, 0x3 }, // 334
  { Intrinsic::riscv_vredor_mask, 0xF, 0x4 }, // 335
  { Intrinsic::riscv_vredsum, 0xF, 0x3 }, // 336
  { Intrinsic::riscv_vredsum_mask, 0xF, 0x4 }, // 337
  { Intrinsic::riscv_vredxor, 0xF, 0x3 }, // 338
  { Intrinsic::riscv_vredxor_mask, 0xF, 0x4 }, // 339
  { Intrinsic::riscv_vrem, 0x1, 0x2 }, // 340
  { Intrinsic::riscv_vrem_mask, 0x2, 0x4 }, // 341
  { Intrinsic::riscv_vremu, 0x1, 0x2 }, // 342
  { Intrinsic::riscv_vremu_mask, 0x2, 0x4 }, // 343
  { Intrinsic::riscv_vrgather_vv, 0xF, 0x2 }, // 344
  { Intrinsic::riscv_vrgather_vv_mask, 0xF, 0x4 }, // 345
  { Intrinsic::riscv_vrgather_vx, 0xF, 0x2 }, // 346
  { Intrinsic::riscv_vrgather_vx_mask, 0xF, 0x4 }, // 347
  { Intrinsic::riscv_vrgatherei16_vv, 0xF, 0x2 }, // 348
  { Intrinsic::riscv_vrgatherei16_vv_mask, 0xF, 0x4 }, // 349
  { Intrinsic::riscv_vrsub, 0x1, 0x2 }, // 350
  { Intrinsic::riscv_vrsub_mask, 0x2, 0x4 }, // 351
  { Intrinsic::riscv_vsadd, 0x1, 0x2 }, // 352
  { Intrinsic::riscv_vsadd_mask, 0x2, 0x4 }, // 353
  { Intrinsic::riscv_vsaddu, 0x1, 0x2 }, // 354
  { Intrinsic::riscv_vsaddu_mask, 0x2, 0x4 }, // 355
  { Intrinsic::riscv_vsbc, 0x1, 0x3 }, // 356
  { Intrinsic::riscv_vse, 0xF, 0x2 }, // 357
  { Intrinsic::riscv_vse_mask, 0xF, 0x3 }, // 358
  { Intrinsic::riscv_vsext, 0xF, 0x1 }, // 359
  { Intrinsic::riscv_vsext_mask, 0xF, 0x3 }, // 360
  { Intrinsic::riscv_vslide1down, 0x1, 0x2 }, // 361
  { Intrinsic::riscv_vslide1down_mask, 0x2, 0x4 }, // 362
  { Intrinsic::riscv_vslide1up, 0x1, 0x2 }, // 363
  { Intrinsic::riscv_vslide1up_mask, 0x2, 0x4 }, // 364
  { Intrinsic::riscv_vslidedown, 0xF, 0x3 }, // 365
  { Intrinsic::riscv_vslidedown_mask, 0xF, 0x4 }, // 366
  { Intrinsic::riscv_vslideup, 0xF, 0x3 }, // 367
  { Intrinsic::riscv_vslideup_mask, 0xF, 0x4 }, // 368
  { Intrinsic::riscv_vsll, 0xF, 0x2 }, // 369
  { Intrinsic::riscv_vsll_mask, 0xF, 0x4 }, // 370
  { Intrinsic::riscv_vsm, 0xF, 0x2 }, // 371
  { Intrinsic::riscv_vsmul, 0x1, 0x2 }, // 372
  { Intrinsic::riscv_vsmul_mask, 0x2, 0x4 }, // 373
  { Intrinsic::riscv_vsoxei, 0xF, 0x3 }, // 374
  { Intrinsic::riscv_vsoxei_mask, 0xF, 0x4 }, // 375
  { Intrinsic::riscv_vsoxseg2, 0xF, 0x4 }, // 376
  { Intrinsic::riscv_vsoxseg2_mask, 0xF, 0x5 }, // 377
  { Intrinsic::riscv_vsoxseg3, 0xF, 0x5 }, // 378
  { Intrinsic::riscv_vsoxseg3_mask, 0xF, 0x6 }, // 379
  { Intrinsic::riscv_vsoxseg4, 0xF, 0x6 }, // 380
  { Intrinsic::riscv_vsoxseg4_mask, 0xF, 0x7 }, // 381
  { Intrinsic::riscv_vsoxseg5, 0xF, 0x7 }, // 382
  { Intrinsic::riscv_vsoxseg5_mask, 0xF, 0x8 }, // 383
  { Intrinsic::riscv_vsoxseg6, 0xF, 0x8 }, // 384
  { Intrinsic::riscv_vsoxseg6_mask, 0xF, 0x9 }, // 385
  { Intrinsic::riscv_vsoxseg7, 0xF, 0x9 }, // 386
  { Intrinsic::riscv_vsoxseg7_mask, 0xF, 0xA }, // 387
  { Intrinsic::riscv_vsoxseg8, 0xF, 0xA }, // 388
  { Intrinsic::riscv_vsoxseg8_mask, 0xF, 0xB }, // 389
  { Intrinsic::riscv_vsra, 0xF, 0x2 }, // 390
  { Intrinsic::riscv_vsra_mask, 0xF, 0x4 }, // 391
  { Intrinsic::riscv_vsrl, 0xF, 0x2 }, // 392
  { Intrinsic::riscv_vsrl_mask, 0xF, 0x4 }, // 393
  { Intrinsic::riscv_vsse, 0xF, 0x3 }, // 394
  { Intrinsic::riscv_vsse_mask, 0xF, 0x4 }, // 395
  { Intrinsic::riscv_vsseg2, 0xF, 0x3 }, // 396
  { Intrinsic::riscv_vsseg2_mask, 0xF, 0x4 }, // 397
  { Intrinsic::riscv_vsseg3, 0xF, 0x4 }, // 398
  { Intrinsic::riscv_vsseg3_mask, 0xF, 0x5 }, // 399
  { Intrinsic::riscv_vsseg4, 0xF, 0x5 }, // 400
  { Intrinsic::riscv_vsseg4_mask, 0xF, 0x6 }, // 401
  { Intrinsic::riscv_vsseg5, 0xF, 0x6 }, // 402
  { Intrinsic::riscv_vsseg5_mask, 0xF, 0x7 }, // 403
  { Intrinsic::riscv_vsseg6, 0xF, 0x7 }, // 404
  { Intrinsic::riscv_vsseg6_mask, 0xF, 0x8 }, // 405
  { Intrinsic::riscv_vsseg7, 0xF, 0x8 }, // 406
  { Intrinsic::riscv_vsseg7_mask, 0xF, 0x9 }, // 407
  { Intrinsic::riscv_vsseg8, 0xF, 0x9 }, // 408
  { Intrinsic::riscv_vsseg8_mask, 0xF, 0xA }, // 409
  { Intrinsic::riscv_vssra, 0xF, 0x2 }, // 410
  { Intrinsic::riscv_vssra_mask, 0xF, 0x4 }, // 411
  { Intrinsic::riscv_vssrl, 0xF, 0x2 }, // 412
  { Intrinsic::riscv_vssrl_mask, 0xF, 0x4 }, // 413
  { Intrinsic::riscv_vssseg2, 0xF, 0x4 }, // 414
  { Intrinsic::riscv_vssseg2_mask, 0xF, 0x5 }, // 415
  { Intrinsic::riscv_vssseg3, 0xF, 0x5 }, // 416
  { Intrinsic::riscv_vssseg3_mask, 0xF, 0x6 }, // 417
  { Intrinsic::riscv_vssseg4, 0xF, 0x6 }, // 418
  { Intrinsic::riscv_vssseg4_mask, 0xF, 0x7 }, // 419
  { Intrinsic::riscv_vssseg5, 0xF, 0x7 }, // 420
  { Intrinsic::riscv_vssseg5_mask, 0xF, 0x8 }, // 421
  { Intrinsic::riscv_vssseg6, 0xF, 0x8 }, // 422
  { Intrinsic::riscv_vssseg6_mask, 0xF, 0x9 }, // 423
  { Intrinsic::riscv_vssseg7, 0xF, 0x9 }, // 424
  { Intrinsic::riscv_vssseg7_mask, 0xF, 0xA }, // 425
  { Intrinsic::riscv_vssseg8, 0xF, 0xA }, // 426
  { Intrinsic::riscv_vssseg8_mask, 0xF, 0xB }, // 427
  { Intrinsic::riscv_vssub, 0x1, 0x2 }, // 428
  { Intrinsic::riscv_vssub_mask, 0x2, 0x4 }, // 429
  { Intrinsic::riscv_vssubu, 0x1, 0x2 }, // 430
  { Intrinsic::riscv_vssubu_mask, 0x2, 0x4 }, // 431
  { Intrinsic::riscv_vsub, 0x1, 0x2 }, // 432
  { Intrinsic::riscv_vsub_mask, 0x2, 0x4 }, // 433
  { Intrinsic::riscv_vsuxei, 0xF, 0x3 }, // 434
  { Intrinsic::riscv_vsuxei_mask, 0xF, 0x4 }, // 435
  { Intrinsic::riscv_vsuxseg2, 0xF, 0x4 }, // 436
  { Intrinsic::riscv_vsuxseg2_mask, 0xF, 0x5 }, // 437
  { Intrinsic::riscv_vsuxseg3, 0xF, 0x5 }, // 438
  { Intrinsic::riscv_vsuxseg3_mask, 0xF, 0x6 }, // 439
  { Intrinsic::riscv_vsuxseg4, 0xF, 0x6 }, // 440
  { Intrinsic::riscv_vsuxseg4_mask, 0xF, 0x7 }, // 441
  { Intrinsic::riscv_vsuxseg5, 0xF, 0x7 }, // 442
  { Intrinsic::riscv_vsuxseg5_mask, 0xF, 0x8 }, // 443
  { Intrinsic::riscv_vsuxseg6, 0xF, 0x8 }, // 444
  { Intrinsic::riscv_vsuxseg6_mask, 0xF, 0x9 }, // 445
  { Intrinsic::riscv_vsuxseg7, 0xF, 0x9 }, // 446
  { Intrinsic::riscv_vsuxseg7_mask, 0xF, 0xA }, // 447
  { Intrinsic::riscv_vsuxseg8, 0xF, 0xA }, // 448
  { Intrinsic::riscv_vsuxseg8_mask, 0xF, 0xB }, // 449
  { Intrinsic::riscv_vwadd, 0x1, 0x2 }, // 450
  { Intrinsic::riscv_vwadd_mask, 0x2, 0x4 }, // 451
  { Intrinsic::riscv_vwadd_w, 0x1, 0x2 }, // 452
  { Intrinsic::riscv_vwadd_w_mask, 0x2, 0x4 }, // 453
  { Intrinsic::riscv_vwaddu, 0x1, 0x2 }, // 454
  { Intrinsic::riscv_vwaddu_mask, 0x2, 0x4 }, // 455
  { Intrinsic::riscv_vwaddu_w, 0x1, 0x2 }, // 456
  { Intrinsic::riscv_vwaddu_w_mask, 0x2, 0x4 }, // 457
  { Intrinsic::riscv_vwmacc, 0x1, 0x3 }, // 458
  { Intrinsic::riscv_vwmacc_mask, 0x1, 0x4 }, // 459
  { Intrinsic::riscv_vwmaccsu, 0x1, 0x3 }, // 460
  { Intrinsic::riscv_vwmaccsu_mask, 0x1, 0x4 }, // 461
  { Intrinsic::riscv_vwmaccu, 0x1, 0x3 }, // 462
  { Intrinsic::riscv_vwmaccu_mask, 0x1, 0x4 }, // 463
  { Intrinsic::riscv_vwmaccus, 0x1, 0x3 }, // 464
  { Intrinsic::riscv_vwmaccus_mask, 0x1, 0x4 }, // 465
  { Intrinsic::riscv_vwmul, 0x1, 0x2 }, // 466
  { Intrinsic::riscv_vwmul_mask, 0x2, 0x4 }, // 467
  { Intrinsic::riscv_vwmulsu, 0x1, 0x2 }, // 468
  { Intrinsic::riscv_vwmulsu_mask, 0x2, 0x4 }, // 469
  { Intrinsic::riscv_vwmulu, 0x1, 0x2 }, // 470
  { Intrinsic::riscv_vwmulu_mask, 0x2, 0x4 }, // 471
  { Intrinsic::riscv_vwredsum, 0xF, 0x3 }, // 472
  { Intrinsic::riscv_vwredsum_mask, 0xF, 0x4 }, // 473
  { Intrinsic::riscv_vwredsumu, 0xF, 0x3 }, // 474
  { Intrinsic::riscv_vwredsumu_mask, 0xF, 0x4 }, // 475
  { Intrinsic::riscv_vwsub, 0x1, 0x2 }, // 476
  { Intrinsic::riscv_vwsub_mask, 0x2, 0x4 }, // 477
  { Intrinsic::riscv_vwsub_w, 0x1, 0x2 }, // 478
  { Intrinsic::riscv_vwsub_w_mask, 0x2, 0x4 }, // 479
  { Intrinsic::riscv_vwsubu, 0x1, 0x2 }, // 480
  { Intrinsic::riscv_vwsubu_mask, 0x2, 0x4 }, // 481
  { Intrinsic::riscv_vwsubu_w, 0x1, 0x2 }, // 482
  { Intrinsic::riscv_vwsubu_w_mask, 0x2, 0x4 }, // 483
  { Intrinsic::riscv_vxor, 0x1, 0x2 }, // 484
  { Intrinsic::riscv_vxor_mask, 0x2, 0x4 }, // 485
  { Intrinsic::riscv_vzext, 0xF, 0x1 }, // 486
  { Intrinsic::riscv_vzext_mask, 0xF, 0x3 }, // 487
 };

const RISCVVIntrinsicInfo *getRISCVVIntrinsicInfo(unsigned IntrinsicID) {
  struct KeyType {
    unsigned IntrinsicID;
  };
  KeyType Key = {IntrinsicID};
  auto Table = makeArrayRef(RISCVVIntrinsicsTable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const RISCVVIntrinsicInfo &LHS, const KeyType &RHS) {
      if (LHS.IntrinsicID < RHS.IntrinsicID)
        return true;
      if (LHS.IntrinsicID > RHS.IntrinsicID)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.IntrinsicID != Idx->IntrinsicID)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_RISCVVLETable_DECL
const VLEPseudo *getVLEPseudo(uint8_t Masked, uint8_t IsTU, uint8_t Strided, uint8_t FF, uint8_t Log2SEW, uint8_t LMUL);
#endif

#ifdef GET_RISCVVLETable_IMPL
constexpr VLEPseudo RISCVVLETable[] = {
  { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, PseudoVLM_V_B8 }, // 0
  { 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, PseudoVLM_V_B16 }, // 1
  { 0x0, 0x0, 0x0, 0x0, 0x0, 0x2, PseudoVLM_V_B32 }, // 2
  { 0x0, 0x0, 0x0, 0x0, 0x0, 0x3, PseudoVLM_V_B64 }, // 3
  { 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, PseudoVLM_V_B1 }, // 4
  { 0x0, 0x0, 0x0, 0x0, 0x0, 0x6, PseudoVLM_V_B2 }, // 5
  { 0x0, 0x0, 0x0, 0x0, 0x0, 0x7, PseudoVLM_V_B4 }, // 6
  { 0x0, 0x0, 0x0, 0x0, 0x3, 0x0, PseudoVLE8_V_M1 }, // 7
  { 0x0, 0x0, 0x0, 0x0, 0x3, 0x1, PseudoVLE8_V_M2 }, // 8
  { 0x0, 0x0, 0x0, 0x0, 0x3, 0x2, PseudoVLE8_V_M4 }, // 9
  { 0x0, 0x0, 0x0, 0x0, 0x3, 0x3, PseudoVLE8_V_M8 }, // 10
  { 0x0, 0x0, 0x0, 0x0, 0x3, 0x5, PseudoVLE8_V_MF8 }, // 11
  { 0x0, 0x0, 0x0, 0x0, 0x3, 0x6, PseudoVLE8_V_MF4 }, // 12
  { 0x0, 0x0, 0x0, 0x0, 0x3, 0x7, PseudoVLE8_V_MF2 }, // 13
  { 0x0, 0x0, 0x0, 0x0, 0x4, 0x0, PseudoVLE16_V_M1 }, // 14
  { 0x0, 0x0, 0x0, 0x0, 0x4, 0x1, PseudoVLE16_V_M2 }, // 15
  { 0x0, 0x0, 0x0, 0x0, 0x4, 0x2, PseudoVLE16_V_M4 }, // 16
  { 0x0, 0x0, 0x0, 0x0, 0x4, 0x3, PseudoVLE16_V_M8 }, // 17
  { 0x0, 0x0, 0x0, 0x0, 0x4, 0x6, PseudoVLE16_V_MF4 }, // 18
  { 0x0, 0x0, 0x0, 0x0, 0x4, 0x7, PseudoVLE16_V_MF2 }, // 19
  { 0x0, 0x0, 0x0, 0x0, 0x5, 0x0, PseudoVLE32_V_M1 }, // 20
  { 0x0, 0x0, 0x0, 0x0, 0x5, 0x1, PseudoVLE32_V_M2 }, // 21
  { 0x0, 0x0, 0x0, 0x0, 0x5, 0x2, PseudoVLE32_V_M4 }, // 22
  { 0x0, 0x0, 0x0, 0x0, 0x5, 0x3, PseudoVLE32_V_M8 }, // 23
  { 0x0, 0x0, 0x0, 0x0, 0x5, 0x7, PseudoVLE32_V_MF2 }, // 24
  { 0x0, 0x0, 0x0, 0x0, 0x6, 0x0, PseudoVLE64_V_M1 }, // 25
  { 0x0, 0x0, 0x0, 0x0, 0x6, 0x1, PseudoVLE64_V_M2 }, // 26
  { 0x0, 0x0, 0x0, 0x0, 0x6, 0x2, PseudoVLE64_V_M4 }, // 27
  { 0x0, 0x0, 0x0, 0x0, 0x6, 0x3, PseudoVLE64_V_M8 }, // 28
  { 0x0, 0x0, 0x0, 0x1, 0x3, 0x0, PseudoVLE8FF_V_M1 }, // 29
  { 0x0, 0x0, 0x0, 0x1, 0x3, 0x1, PseudoVLE8FF_V_M2 }, // 30
  { 0x0, 0x0, 0x0, 0x1, 0x3, 0x2, PseudoVLE8FF_V_M4 }, // 31
  { 0x0, 0x0, 0x0, 0x1, 0x3, 0x3, PseudoVLE8FF_V_M8 }, // 32
  { 0x0, 0x0, 0x0, 0x1, 0x3, 0x5, PseudoVLE8FF_V_MF8 }, // 33
  { 0x0, 0x0, 0x0, 0x1, 0x3, 0x6, PseudoVLE8FF_V_MF4 }, // 34
  { 0x0, 0x0, 0x0, 0x1, 0x3, 0x7, PseudoVLE8FF_V_MF2 }, // 35
  { 0x0, 0x0, 0x0, 0x1, 0x4, 0x0, PseudoVLE16FF_V_M1 }, // 36
  { 0x0, 0x0, 0x0, 0x1, 0x4, 0x1, PseudoVLE16FF_V_M2 }, // 37
  { 0x0, 0x0, 0x0, 0x1, 0x4, 0x2, PseudoVLE16FF_V_M4 }, // 38
  { 0x0, 0x0, 0x0, 0x1, 0x4, 0x3, PseudoVLE16FF_V_M8 }, // 39
  { 0x0, 0x0, 0x0, 0x1, 0x4, 0x6, PseudoVLE16FF_V_MF4 }, // 40
  { 0x0, 0x0, 0x0, 0x1, 0x4, 0x7, PseudoVLE16FF_V_MF2 }, // 41
  { 0x0, 0x0, 0x0, 0x1, 0x5, 0x0, PseudoVLE32FF_V_M1 }, // 42
  { 0x0, 0x0, 0x0, 0x1, 0x5, 0x1, PseudoVLE32FF_V_M2 }, // 43
  { 0x0, 0x0, 0x0, 0x1, 0x5, 0x2, PseudoVLE32FF_V_M4 }, // 44
  { 0x0, 0x0, 0x0, 0x1, 0x5, 0x3, PseudoVLE32FF_V_M8 }, // 45
  { 0x0, 0x0, 0x0, 0x1, 0x5, 0x7, PseudoVLE32FF_V_MF2 }, // 46
  { 0x0, 0x0, 0x0, 0x1, 0x6, 0x0, PseudoVLE64FF_V_M1 }, // 47
  { 0x0, 0x0, 0x0, 0x1, 0x6, 0x1, PseudoVLE64FF_V_M2 }, // 48
  { 0x0, 0x0, 0x0, 0x1, 0x6, 0x2, PseudoVLE64FF_V_M4 }, // 49
  { 0x0, 0x0, 0x0, 0x1, 0x6, 0x3, PseudoVLE64FF_V_M8 }, // 50
  { 0x0, 0x0, 0x1, 0x0, 0x3, 0x0, PseudoVLSE8_V_M1 }, // 51
  { 0x0, 0x0, 0x1, 0x0, 0x3, 0x1, PseudoVLSE8_V_M2 }, // 52
  { 0x0, 0x0, 0x1, 0x0, 0x3, 0x2, PseudoVLSE8_V_M4 }, // 53
  { 0x0, 0x0, 0x1, 0x0, 0x3, 0x3, PseudoVLSE8_V_M8 }, // 54
  { 0x0, 0x0, 0x1, 0x0, 0x3, 0x5, PseudoVLSE8_V_MF8 }, // 55
  { 0x0, 0x0, 0x1, 0x0, 0x3, 0x6, PseudoVLSE8_V_MF4 }, // 56
  { 0x0, 0x0, 0x1, 0x0, 0x3, 0x7, PseudoVLSE8_V_MF2 }, // 57
  { 0x0, 0x0, 0x1, 0x0, 0x4, 0x0, PseudoVLSE16_V_M1 }, // 58
  { 0x0, 0x0, 0x1, 0x0, 0x4, 0x1, PseudoVLSE16_V_M2 }, // 59
  { 0x0, 0x0, 0x1, 0x0, 0x4, 0x2, PseudoVLSE16_V_M4 }, // 60
  { 0x0, 0x0, 0x1, 0x0, 0x4, 0x3, PseudoVLSE16_V_M8 }, // 61
  { 0x0, 0x0, 0x1, 0x0, 0x4, 0x6, PseudoVLSE16_V_MF4 }, // 62
  { 0x0, 0x0, 0x1, 0x0, 0x4, 0x7, PseudoVLSE16_V_MF2 }, // 63
  { 0x0, 0x0, 0x1, 0x0, 0x5, 0x0, PseudoVLSE32_V_M1 }, // 64
  { 0x0, 0x0, 0x1, 0x0, 0x5, 0x1, PseudoVLSE32_V_M2 }, // 65
  { 0x0, 0x0, 0x1, 0x0, 0x5, 0x2, PseudoVLSE32_V_M4 }, // 66
  { 0x0, 0x0, 0x1, 0x0, 0x5, 0x3, PseudoVLSE32_V_M8 }, // 67
  { 0x0, 0x0, 0x1, 0x0, 0x5, 0x7, PseudoVLSE32_V_MF2 }, // 68
  { 0x0, 0x0, 0x1, 0x0, 0x6, 0x0, PseudoVLSE64_V_M1 }, // 69
  { 0x0, 0x0, 0x1, 0x0, 0x6, 0x1, PseudoVLSE64_V_M2 }, // 70
  { 0x0, 0x0, 0x1, 0x0, 0x6, 0x2, PseudoVLSE64_V_M4 }, // 71
  { 0x0, 0x0, 0x1, 0x0, 0x6, 0x3, PseudoVLSE64_V_M8 }, // 72
  { 0x0, 0x1, 0x0, 0x0, 0x3, 0x0, PseudoVLE8_V_M1_TU }, // 73
  { 0x0, 0x1, 0x0, 0x0, 0x3, 0x1, PseudoVLE8_V_M2_TU }, // 74
  { 0x0, 0x1, 0x0, 0x0, 0x3, 0x2, PseudoVLE8_V_M4_TU }, // 75
  { 0x0, 0x1, 0x0, 0x0, 0x3, 0x3, PseudoVLE8_V_M8_TU }, // 76
  { 0x0, 0x1, 0x0, 0x0, 0x3, 0x5, PseudoVLE8_V_MF8_TU }, // 77
  { 0x0, 0x1, 0x0, 0x0, 0x3, 0x6, PseudoVLE8_V_MF4_TU }, // 78
  { 0x0, 0x1, 0x0, 0x0, 0x3, 0x7, PseudoVLE8_V_MF2_TU }, // 79
  { 0x0, 0x1, 0x0, 0x0, 0x4, 0x0, PseudoVLE16_V_M1_TU }, // 80
  { 0x0, 0x1, 0x0, 0x0, 0x4, 0x1, PseudoVLE16_V_M2_TU }, // 81
  { 0x0, 0x1, 0x0, 0x0, 0x4, 0x2, PseudoVLE16_V_M4_TU }, // 82
  { 0x0, 0x1, 0x0, 0x0, 0x4, 0x3, PseudoVLE16_V_M8_TU }, // 83
  { 0x0, 0x1, 0x0, 0x0, 0x4, 0x6, PseudoVLE16_V_MF4_TU }, // 84
  { 0x0, 0x1, 0x0, 0x0, 0x4, 0x7, PseudoVLE16_V_MF2_TU }, // 85
  { 0x0, 0x1, 0x0, 0x0, 0x5, 0x0, PseudoVLE32_V_M1_TU }, // 86
  { 0x0, 0x1, 0x0, 0x0, 0x5, 0x1, PseudoVLE32_V_M2_TU }, // 87
  { 0x0, 0x1, 0x0, 0x0, 0x5, 0x2, PseudoVLE32_V_M4_TU }, // 88
  { 0x0, 0x1, 0x0, 0x0, 0x5, 0x3, PseudoVLE32_V_M8_TU }, // 89
  { 0x0, 0x1, 0x0, 0x0, 0x5, 0x7, PseudoVLE32_V_MF2_TU }, // 90
  { 0x0, 0x1, 0x0, 0x0, 0x6, 0x0, PseudoVLE64_V_M1_TU }, // 91
  { 0x0, 0x1, 0x0, 0x0, 0x6, 0x1, PseudoVLE64_V_M2_TU }, // 92
  { 0x0, 0x1, 0x0, 0x0, 0x6, 0x2, PseudoVLE64_V_M4_TU }, // 93
  { 0x0, 0x1, 0x0, 0x0, 0x6, 0x3, PseudoVLE64_V_M8_TU }, // 94
  { 0x0, 0x1, 0x0, 0x1, 0x3, 0x0, PseudoVLE8FF_V_M1_TU }, // 95
  { 0x0, 0x1, 0x0, 0x1, 0x3, 0x1, PseudoVLE8FF_V_M2_TU }, // 96
  { 0x0, 0x1, 0x0, 0x1, 0x3, 0x2, PseudoVLE8FF_V_M4_TU }, // 97
  { 0x0, 0x1, 0x0, 0x1, 0x3, 0x3, PseudoVLE8FF_V_M8_TU }, // 98
  { 0x0, 0x1, 0x0, 0x1, 0x3, 0x5, PseudoVLE8FF_V_MF8_TU }, // 99
  { 0x0, 0x1, 0x0, 0x1, 0x3, 0x6, PseudoVLE8FF_V_MF4_TU }, // 100
  { 0x0, 0x1, 0x0, 0x1, 0x3, 0x7, PseudoVLE8FF_V_MF2_TU }, // 101
  { 0x0, 0x1, 0x0, 0x1, 0x4, 0x0, PseudoVLE16FF_V_M1_TU }, // 102
  { 0x0, 0x1, 0x0, 0x1, 0x4, 0x1, PseudoVLE16FF_V_M2_TU }, // 103
  { 0x0, 0x1, 0x0, 0x1, 0x4, 0x2, PseudoVLE16FF_V_M4_TU }, // 104
  { 0x0, 0x1, 0x0, 0x1, 0x4, 0x3, PseudoVLE16FF_V_M8_TU }, // 105
  { 0x0, 0x1, 0x0, 0x1, 0x4, 0x6, PseudoVLE16FF_V_MF4_TU }, // 106
  { 0x0, 0x1, 0x0, 0x1, 0x4, 0x7, PseudoVLE16FF_V_MF2_TU }, // 107
  { 0x0, 0x1, 0x0, 0x1, 0x5, 0x0, PseudoVLE32FF_V_M1_TU }, // 108
  { 0x0, 0x1, 0x0, 0x1, 0x5, 0x1, PseudoVLE32FF_V_M2_TU }, // 109
  { 0x0, 0x1, 0x0, 0x1, 0x5, 0x2, PseudoVLE32FF_V_M4_TU }, // 110
  { 0x0, 0x1, 0x0, 0x1, 0x5, 0x3, PseudoVLE32FF_V_M8_TU }, // 111
  { 0x0, 0x1, 0x0, 0x1, 0x5, 0x7, PseudoVLE32FF_V_MF2_TU }, // 112
  { 0x0, 0x1, 0x0, 0x1, 0x6, 0x0, PseudoVLE64FF_V_M1_TU }, // 113
  { 0x0, 0x1, 0x0, 0x1, 0x6, 0x1, PseudoVLE64FF_V_M2_TU }, // 114
  { 0x0, 0x1, 0x0, 0x1, 0x6, 0x2, PseudoVLE64FF_V_M4_TU }, // 115
  { 0x0, 0x1, 0x0, 0x1, 0x6, 0x3, PseudoVLE64FF_V_M8_TU }, // 116
  { 0x0, 0x1, 0x1, 0x0, 0x3, 0x0, PseudoVLSE8_V_M1_TU }, // 117
  { 0x0, 0x1, 0x1, 0x0, 0x3, 0x1, PseudoVLSE8_V_M2_TU }, // 118
  { 0x0, 0x1, 0x1, 0x0, 0x3, 0x2, PseudoVLSE8_V_M4_TU }, // 119
  { 0x0, 0x1, 0x1, 0x0, 0x3, 0x3, PseudoVLSE8_V_M8_TU }, // 120
  { 0x0, 0x1, 0x1, 0x0, 0x3, 0x5, PseudoVLSE8_V_MF8_TU }, // 121
  { 0x0, 0x1, 0x1, 0x0, 0x3, 0x6, PseudoVLSE8_V_MF4_TU }, // 122
  { 0x0, 0x1, 0x1, 0x0, 0x3, 0x7, PseudoVLSE8_V_MF2_TU }, // 123
  { 0x0, 0x1, 0x1, 0x0, 0x4, 0x0, PseudoVLSE16_V_M1_TU }, // 124
  { 0x0, 0x1, 0x1, 0x0, 0x4, 0x1, PseudoVLSE16_V_M2_TU }, // 125
  { 0x0, 0x1, 0x1, 0x0, 0x4, 0x2, PseudoVLSE16_V_M4_TU }, // 126
  { 0x0, 0x1, 0x1, 0x0, 0x4, 0x3, PseudoVLSE16_V_M8_TU }, // 127
  { 0x0, 0x1, 0x1, 0x0, 0x4, 0x6, PseudoVLSE16_V_MF4_TU }, // 128
  { 0x0, 0x1, 0x1, 0x0, 0x4, 0x7, PseudoVLSE16_V_MF2_TU }, // 129
  { 0x0, 0x1, 0x1, 0x0, 0x5, 0x0, PseudoVLSE32_V_M1_TU }, // 130
  { 0x0, 0x1, 0x1, 0x0, 0x5, 0x1, PseudoVLSE32_V_M2_TU }, // 131
  { 0x0, 0x1, 0x1, 0x0, 0x5, 0x2, PseudoVLSE32_V_M4_TU }, // 132
  { 0x0, 0x1, 0x1, 0x0, 0x5, 0x3, PseudoVLSE32_V_M8_TU }, // 133
  { 0x0, 0x1, 0x1, 0x0, 0x5, 0x7, PseudoVLSE32_V_MF2_TU }, // 134
  { 0x0, 0x1, 0x1, 0x0, 0x6, 0x0, PseudoVLSE64_V_M1_TU }, // 135
  { 0x0, 0x1, 0x1, 0x0, 0x6, 0x1, PseudoVLSE64_V_M2_TU }, // 136
  { 0x0, 0x1, 0x1, 0x0, 0x6, 0x2, PseudoVLSE64_V_M4_TU }, // 137
  { 0x0, 0x1, 0x1, 0x0, 0x6, 0x3, PseudoVLSE64_V_M8_TU }, // 138
  { 0x1, 0x1, 0x0, 0x0, 0x3, 0x0, PseudoVLE8_V_M1_MASK }, // 139
  { 0x1, 0x1, 0x0, 0x0, 0x3, 0x1, PseudoVLE8_V_M2_MASK }, // 140
  { 0x1, 0x1, 0x0, 0x0, 0x3, 0x2, PseudoVLE8_V_M4_MASK }, // 141
  { 0x1, 0x1, 0x0, 0x0, 0x3, 0x3, PseudoVLE8_V_M8_MASK }, // 142
  { 0x1, 0x1, 0x0, 0x0, 0x3, 0x5, PseudoVLE8_V_MF8_MASK }, // 143
  { 0x1, 0x1, 0x0, 0x0, 0x3, 0x6, PseudoVLE8_V_MF4_MASK }, // 144
  { 0x1, 0x1, 0x0, 0x0, 0x3, 0x7, PseudoVLE8_V_MF2_MASK }, // 145
  { 0x1, 0x1, 0x0, 0x0, 0x4, 0x0, PseudoVLE16_V_M1_MASK }, // 146
  { 0x1, 0x1, 0x0, 0x0, 0x4, 0x1, PseudoVLE16_V_M2_MASK }, // 147
  { 0x1, 0x1, 0x0, 0x0, 0x4, 0x2, PseudoVLE16_V_M4_MASK }, // 148
  { 0x1, 0x1, 0x0, 0x0, 0x4, 0x3, PseudoVLE16_V_M8_MASK }, // 149
  { 0x1, 0x1, 0x0, 0x0, 0x4, 0x6, PseudoVLE16_V_MF4_MASK }, // 150
  { 0x1, 0x1, 0x0, 0x0, 0x4, 0x7, PseudoVLE16_V_MF2_MASK }, // 151
  { 0x1, 0x1, 0x0, 0x0, 0x5, 0x0, PseudoVLE32_V_M1_MASK }, // 152
  { 0x1, 0x1, 0x0, 0x0, 0x5, 0x1, PseudoVLE32_V_M2_MASK }, // 153
  { 0x1, 0x1, 0x0, 0x0, 0x5, 0x2, PseudoVLE32_V_M4_MASK }, // 154
  { 0x1, 0x1, 0x0, 0x0, 0x5, 0x3, PseudoVLE32_V_M8_MASK }, // 155
  { 0x1, 0x1, 0x0, 0x0, 0x5, 0x7, PseudoVLE32_V_MF2_MASK }, // 156
  { 0x1, 0x1, 0x0, 0x0, 0x6, 0x0, PseudoVLE64_V_M1_MASK }, // 157
  { 0x1, 0x1, 0x0, 0x0, 0x6, 0x1, PseudoVLE64_V_M2_MASK }, // 158
  { 0x1, 0x1, 0x0, 0x0, 0x6, 0x2, PseudoVLE64_V_M4_MASK }, // 159
  { 0x1, 0x1, 0x0, 0x0, 0x6, 0x3, PseudoVLE64_V_M8_MASK }, // 160
  { 0x1, 0x1, 0x0, 0x1, 0x3, 0x0, PseudoVLE8FF_V_M1_MASK }, // 161
  { 0x1, 0x1, 0x0, 0x1, 0x3, 0x1, PseudoVLE8FF_V_M2_MASK }, // 162
  { 0x1, 0x1, 0x0, 0x1, 0x3, 0x2, PseudoVLE8FF_V_M4_MASK }, // 163
  { 0x1, 0x1, 0x0, 0x1, 0x3, 0x3, PseudoVLE8FF_V_M8_MASK }, // 164
  { 0x1, 0x1, 0x0, 0x1, 0x3, 0x5, PseudoVLE8FF_V_MF8_MASK }, // 165
  { 0x1, 0x1, 0x0, 0x1, 0x3, 0x6, PseudoVLE8FF_V_MF4_MASK }, // 166
  { 0x1, 0x1, 0x0, 0x1, 0x3, 0x7, PseudoVLE8FF_V_MF2_MASK }, // 167
  { 0x1, 0x1, 0x0, 0x1, 0x4, 0x0, PseudoVLE16FF_V_M1_MASK }, // 168
  { 0x1, 0x1, 0x0, 0x1, 0x4, 0x1, PseudoVLE16FF_V_M2_MASK }, // 169
  { 0x1, 0x1, 0x0, 0x1, 0x4, 0x2, PseudoVLE16FF_V_M4_MASK }, // 170
  { 0x1, 0x1, 0x0, 0x1, 0x4, 0x3, PseudoVLE16FF_V_M8_MASK }, // 171
  { 0x1, 0x1, 0x0, 0x1, 0x4, 0x6, PseudoVLE16FF_V_MF4_MASK }, // 172
  { 0x1, 0x1, 0x0, 0x1, 0x4, 0x7, PseudoVLE16FF_V_MF2_MASK }, // 173
  { 0x1, 0x1, 0x0, 0x1, 0x5, 0x0, PseudoVLE32FF_V_M1_MASK }, // 174
  { 0x1, 0x1, 0x0, 0x1, 0x5, 0x1, PseudoVLE32FF_V_M2_MASK }, // 175
  { 0x1, 0x1, 0x0, 0x1, 0x5, 0x2, PseudoVLE32FF_V_M4_MASK }, // 176
  { 0x1, 0x1, 0x0, 0x1, 0x5, 0x3, PseudoVLE32FF_V_M8_MASK }, // 177
  { 0x1, 0x1, 0x0, 0x1, 0x5, 0x7, PseudoVLE32FF_V_MF2_MASK }, // 178
  { 0x1, 0x1, 0x0, 0x1, 0x6, 0x0, PseudoVLE64FF_V_M1_MASK }, // 179
  { 0x1, 0x1, 0x0, 0x1, 0x6, 0x1, PseudoVLE64FF_V_M2_MASK }, // 180
  { 0x1, 0x1, 0x0, 0x1, 0x6, 0x2, PseudoVLE64FF_V_M4_MASK }, // 181
  { 0x1, 0x1, 0x0, 0x1, 0x6, 0x3, PseudoVLE64FF_V_M8_MASK }, // 182
  { 0x1, 0x1, 0x1, 0x0, 0x3, 0x0, PseudoVLSE8_V_M1_MASK }, // 183
  { 0x1, 0x1, 0x1, 0x0, 0x3, 0x1, PseudoVLSE8_V_M2_MASK }, // 184
  { 0x1, 0x1, 0x1, 0x0, 0x3, 0x2, PseudoVLSE8_V_M4_MASK }, // 185
  { 0x1, 0x1, 0x1, 0x0, 0x3, 0x3, PseudoVLSE8_V_M8_MASK }, // 186
  { 0x1, 0x1, 0x1, 0x0, 0x3, 0x5, PseudoVLSE8_V_MF8_MASK }, // 187
  { 0x1, 0x1, 0x1, 0x0, 0x3, 0x6, PseudoVLSE8_V_MF4_MASK }, // 188
  { 0x1, 0x1, 0x1, 0x0, 0x3, 0x7, PseudoVLSE8_V_MF2_MASK }, // 189
  { 0x1, 0x1, 0x1, 0x0, 0x4, 0x0, PseudoVLSE16_V_M1_MASK }, // 190
  { 0x1, 0x1, 0x1, 0x0, 0x4, 0x1, PseudoVLSE16_V_M2_MASK }, // 191
  { 0x1, 0x1, 0x1, 0x0, 0x4, 0x2, PseudoVLSE16_V_M4_MASK }, // 192
  { 0x1, 0x1, 0x1, 0x0, 0x4, 0x3, PseudoVLSE16_V_M8_MASK }, // 193
  { 0x1, 0x1, 0x1, 0x0, 0x4, 0x6, PseudoVLSE16_V_MF4_MASK }, // 194
  { 0x1, 0x1, 0x1, 0x0, 0x4, 0x7, PseudoVLSE16_V_MF2_MASK }, // 195
  { 0x1, 0x1, 0x1, 0x0, 0x5, 0x0, PseudoVLSE32_V_M1_MASK }, // 196
  { 0x1, 0x1, 0x1, 0x0, 0x5, 0x1, PseudoVLSE32_V_M2_MASK }, // 197
  { 0x1, 0x1, 0x1, 0x0, 0x5, 0x2, PseudoVLSE32_V_M4_MASK }, // 198
  { 0x1, 0x1, 0x1, 0x0, 0x5, 0x3, PseudoVLSE32_V_M8_MASK }, // 199
  { 0x1, 0x1, 0x1, 0x0, 0x5, 0x7, PseudoVLSE32_V_MF2_MASK }, // 200
  { 0x1, 0x1, 0x1, 0x0, 0x6, 0x0, PseudoVLSE64_V_M1_MASK }, // 201
  { 0x1, 0x1, 0x1, 0x0, 0x6, 0x1, PseudoVLSE64_V_M2_MASK }, // 202
  { 0x1, 0x1, 0x1, 0x0, 0x6, 0x2, PseudoVLSE64_V_M4_MASK }, // 203
  { 0x1, 0x1, 0x1, 0x0, 0x6, 0x3, PseudoVLSE64_V_M8_MASK }, // 204
 };

const VLEPseudo *getVLEPseudo(uint8_t Masked, uint8_t IsTU, uint8_t Strided, uint8_t FF, uint8_t Log2SEW, uint8_t LMUL) {
  struct KeyType {
    uint8_t Masked;
    uint8_t IsTU;
    uint8_t Strided;
    uint8_t FF;
    uint8_t Log2SEW;
    uint8_t LMUL;
  };
  KeyType Key = {Masked, IsTU, Strided, FF, Log2SEW, LMUL};
  auto Table = makeArrayRef(RISCVVLETable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const VLEPseudo &LHS, const KeyType &RHS) {
      if (LHS.Masked < RHS.Masked)
        return true;
      if (LHS.Masked > RHS.Masked)
        return false;
      if (LHS.IsTU < RHS.IsTU)
        return true;
      if (LHS.IsTU > RHS.IsTU)
        return false;
      if (LHS.Strided < RHS.Strided)
        return true;
      if (LHS.Strided > RHS.Strided)
        return false;
      if (LHS.FF < RHS.FF)
        return true;
      if (LHS.FF > RHS.FF)
        return false;
      if (LHS.Log2SEW < RHS.Log2SEW)
        return true;
      if (LHS.Log2SEW > RHS.Log2SEW)
        return false;
      if (LHS.LMUL < RHS.LMUL)
        return true;
      if (LHS.LMUL > RHS.LMUL)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.Masked != Idx->Masked ||
      Key.IsTU != Idx->IsTU ||
      Key.Strided != Idx->Strided ||
      Key.FF != Idx->FF ||
      Key.Log2SEW != Idx->Log2SEW ||
      Key.LMUL != Idx->LMUL)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_RISCVVLSEGTable_DECL
const VLSEGPseudo *getVLSEGPseudo(uint8_t NF, uint8_t Masked, uint8_t Strided, uint8_t FF, uint8_t Log2SEW, uint8_t LMUL);
#endif

#ifdef GET_RISCVVLSEGTable_IMPL
constexpr VLSEGPseudo RISCVVLSEGTable[] = {
  { 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG2E8_V_M1 }, // 0
  { 0x2, 0x0, 0x0, 0x0, 0x3, 0x1, PseudoVLSEG2E8_V_M2 }, // 1
  { 0x2, 0x0, 0x0, 0x0, 0x3, 0x2, PseudoVLSEG2E8_V_M4 }, // 2
  { 0x2, 0x0, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG2E8_V_MF8 }, // 3
  { 0x2, 0x0, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG2E8_V_MF4 }, // 4
  { 0x2, 0x0, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG2E8_V_MF2 }, // 5
  { 0x2, 0x0, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG2E16_V_M1 }, // 6
  { 0x2, 0x0, 0x0, 0x0, 0x4, 0x1, PseudoVLSEG2E16_V_M2 }, // 7
  { 0x2, 0x0, 0x0, 0x0, 0x4, 0x2, PseudoVLSEG2E16_V_M4 }, // 8
  { 0x2, 0x0, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG2E16_V_MF4 }, // 9
  { 0x2, 0x0, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG2E16_V_MF2 }, // 10
  { 0x2, 0x0, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG2E32_V_M1 }, // 11
  { 0x2, 0x0, 0x0, 0x0, 0x5, 0x1, PseudoVLSEG2E32_V_M2 }, // 12
  { 0x2, 0x0, 0x0, 0x0, 0x5, 0x2, PseudoVLSEG2E32_V_M4 }, // 13
  { 0x2, 0x0, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG2E32_V_MF2 }, // 14
  { 0x2, 0x0, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG2E64_V_M1 }, // 15
  { 0x2, 0x0, 0x0, 0x0, 0x6, 0x1, PseudoVLSEG2E64_V_M2 }, // 16
  { 0x2, 0x0, 0x0, 0x0, 0x6, 0x2, PseudoVLSEG2E64_V_M4 }, // 17
  { 0x2, 0x0, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG2E8FF_V_M1 }, // 18
  { 0x2, 0x0, 0x0, 0x1, 0x3, 0x1, PseudoVLSEG2E8FF_V_M2 }, // 19
  { 0x2, 0x0, 0x0, 0x1, 0x3, 0x2, PseudoVLSEG2E8FF_V_M4 }, // 20
  { 0x2, 0x0, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG2E8FF_V_MF8 }, // 21
  { 0x2, 0x0, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG2E8FF_V_MF4 }, // 22
  { 0x2, 0x0, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG2E8FF_V_MF2 }, // 23
  { 0x2, 0x0, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG2E16FF_V_M1 }, // 24
  { 0x2, 0x0, 0x0, 0x1, 0x4, 0x1, PseudoVLSEG2E16FF_V_M2 }, // 25
  { 0x2, 0x0, 0x0, 0x1, 0x4, 0x2, PseudoVLSEG2E16FF_V_M4 }, // 26
  { 0x2, 0x0, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG2E16FF_V_MF4 }, // 27
  { 0x2, 0x0, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG2E16FF_V_MF2 }, // 28
  { 0x2, 0x0, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG2E32FF_V_M1 }, // 29
  { 0x2, 0x0, 0x0, 0x1, 0x5, 0x1, PseudoVLSEG2E32FF_V_M2 }, // 30
  { 0x2, 0x0, 0x0, 0x1, 0x5, 0x2, PseudoVLSEG2E32FF_V_M4 }, // 31
  { 0x2, 0x0, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG2E32FF_V_MF2 }, // 32
  { 0x2, 0x0, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG2E64FF_V_M1 }, // 33
  { 0x2, 0x0, 0x0, 0x1, 0x6, 0x1, PseudoVLSEG2E64FF_V_M2 }, // 34
  { 0x2, 0x0, 0x0, 0x1, 0x6, 0x2, PseudoVLSEG2E64FF_V_M4 }, // 35
  { 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG2E8_V_M1 }, // 36
  { 0x2, 0x0, 0x1, 0x0, 0x3, 0x1, PseudoVLSSEG2E8_V_M2 }, // 37
  { 0x2, 0x0, 0x1, 0x0, 0x3, 0x2, PseudoVLSSEG2E8_V_M4 }, // 38
  { 0x2, 0x0, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG2E8_V_MF8 }, // 39
  { 0x2, 0x0, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG2E8_V_MF4 }, // 40
  { 0x2, 0x0, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG2E8_V_MF2 }, // 41
  { 0x2, 0x0, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG2E16_V_M1 }, // 42
  { 0x2, 0x0, 0x1, 0x0, 0x4, 0x1, PseudoVLSSEG2E16_V_M2 }, // 43
  { 0x2, 0x0, 0x1, 0x0, 0x4, 0x2, PseudoVLSSEG2E16_V_M4 }, // 44
  { 0x2, 0x0, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG2E16_V_MF4 }, // 45
  { 0x2, 0x0, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG2E16_V_MF2 }, // 46
  { 0x2, 0x0, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG2E32_V_M1 }, // 47
  { 0x2, 0x0, 0x1, 0x0, 0x5, 0x1, PseudoVLSSEG2E32_V_M2 }, // 48
  { 0x2, 0x0, 0x1, 0x0, 0x5, 0x2, PseudoVLSSEG2E32_V_M4 }, // 49
  { 0x2, 0x0, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG2E32_V_MF2 }, // 50
  { 0x2, 0x0, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG2E64_V_M1 }, // 51
  { 0x2, 0x0, 0x1, 0x0, 0x6, 0x1, PseudoVLSSEG2E64_V_M2 }, // 52
  { 0x2, 0x0, 0x1, 0x0, 0x6, 0x2, PseudoVLSSEG2E64_V_M4 }, // 53
  { 0x2, 0x1, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG2E8_V_M1_MASK }, // 54
  { 0x2, 0x1, 0x0, 0x0, 0x3, 0x1, PseudoVLSEG2E8_V_M2_MASK }, // 55
  { 0x2, 0x1, 0x0, 0x0, 0x3, 0x2, PseudoVLSEG2E8_V_M4_MASK }, // 56
  { 0x2, 0x1, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG2E8_V_MF8_MASK }, // 57
  { 0x2, 0x1, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG2E8_V_MF4_MASK }, // 58
  { 0x2, 0x1, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG2E8_V_MF2_MASK }, // 59
  { 0x2, 0x1, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG2E16_V_M1_MASK }, // 60
  { 0x2, 0x1, 0x0, 0x0, 0x4, 0x1, PseudoVLSEG2E16_V_M2_MASK }, // 61
  { 0x2, 0x1, 0x0, 0x0, 0x4, 0x2, PseudoVLSEG2E16_V_M4_MASK }, // 62
  { 0x2, 0x1, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG2E16_V_MF4_MASK }, // 63
  { 0x2, 0x1, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG2E16_V_MF2_MASK }, // 64
  { 0x2, 0x1, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG2E32_V_M1_MASK }, // 65
  { 0x2, 0x1, 0x0, 0x0, 0x5, 0x1, PseudoVLSEG2E32_V_M2_MASK }, // 66
  { 0x2, 0x1, 0x0, 0x0, 0x5, 0x2, PseudoVLSEG2E32_V_M4_MASK }, // 67
  { 0x2, 0x1, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG2E32_V_MF2_MASK }, // 68
  { 0x2, 0x1, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG2E64_V_M1_MASK }, // 69
  { 0x2, 0x1, 0x0, 0x0, 0x6, 0x1, PseudoVLSEG2E64_V_M2_MASK }, // 70
  { 0x2, 0x1, 0x0, 0x0, 0x6, 0x2, PseudoVLSEG2E64_V_M4_MASK }, // 71
  { 0x2, 0x1, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG2E8FF_V_M1_MASK }, // 72
  { 0x2, 0x1, 0x0, 0x1, 0x3, 0x1, PseudoVLSEG2E8FF_V_M2_MASK }, // 73
  { 0x2, 0x1, 0x0, 0x1, 0x3, 0x2, PseudoVLSEG2E8FF_V_M4_MASK }, // 74
  { 0x2, 0x1, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG2E8FF_V_MF8_MASK }, // 75
  { 0x2, 0x1, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG2E8FF_V_MF4_MASK }, // 76
  { 0x2, 0x1, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG2E8FF_V_MF2_MASK }, // 77
  { 0x2, 0x1, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG2E16FF_V_M1_MASK }, // 78
  { 0x2, 0x1, 0x0, 0x1, 0x4, 0x1, PseudoVLSEG2E16FF_V_M2_MASK }, // 79
  { 0x2, 0x1, 0x0, 0x1, 0x4, 0x2, PseudoVLSEG2E16FF_V_M4_MASK }, // 80
  { 0x2, 0x1, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG2E16FF_V_MF4_MASK }, // 81
  { 0x2, 0x1, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG2E16FF_V_MF2_MASK }, // 82
  { 0x2, 0x1, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG2E32FF_V_M1_MASK }, // 83
  { 0x2, 0x1, 0x0, 0x1, 0x5, 0x1, PseudoVLSEG2E32FF_V_M2_MASK }, // 84
  { 0x2, 0x1, 0x0, 0x1, 0x5, 0x2, PseudoVLSEG2E32FF_V_M4_MASK }, // 85
  { 0x2, 0x1, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG2E32FF_V_MF2_MASK }, // 86
  { 0x2, 0x1, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG2E64FF_V_M1_MASK }, // 87
  { 0x2, 0x1, 0x0, 0x1, 0x6, 0x1, PseudoVLSEG2E64FF_V_M2_MASK }, // 88
  { 0x2, 0x1, 0x0, 0x1, 0x6, 0x2, PseudoVLSEG2E64FF_V_M4_MASK }, // 89
  { 0x2, 0x1, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG2E8_V_M1_MASK }, // 90
  { 0x2, 0x1, 0x1, 0x0, 0x3, 0x1, PseudoVLSSEG2E8_V_M2_MASK }, // 91
  { 0x2, 0x1, 0x1, 0x0, 0x3, 0x2, PseudoVLSSEG2E8_V_M4_MASK }, // 92
  { 0x2, 0x1, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG2E8_V_MF8_MASK }, // 93
  { 0x2, 0x1, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG2E8_V_MF4_MASK }, // 94
  { 0x2, 0x1, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG2E8_V_MF2_MASK }, // 95
  { 0x2, 0x1, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG2E16_V_M1_MASK }, // 96
  { 0x2, 0x1, 0x1, 0x0, 0x4, 0x1, PseudoVLSSEG2E16_V_M2_MASK }, // 97
  { 0x2, 0x1, 0x1, 0x0, 0x4, 0x2, PseudoVLSSEG2E16_V_M4_MASK }, // 98
  { 0x2, 0x1, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG2E16_V_MF4_MASK }, // 99
  { 0x2, 0x1, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG2E16_V_MF2_MASK }, // 100
  { 0x2, 0x1, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG2E32_V_M1_MASK }, // 101
  { 0x2, 0x1, 0x1, 0x0, 0x5, 0x1, PseudoVLSSEG2E32_V_M2_MASK }, // 102
  { 0x2, 0x1, 0x1, 0x0, 0x5, 0x2, PseudoVLSSEG2E32_V_M4_MASK }, // 103
  { 0x2, 0x1, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG2E32_V_MF2_MASK }, // 104
  { 0x2, 0x1, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG2E64_V_M1_MASK }, // 105
  { 0x2, 0x1, 0x1, 0x0, 0x6, 0x1, PseudoVLSSEG2E64_V_M2_MASK }, // 106
  { 0x2, 0x1, 0x1, 0x0, 0x6, 0x2, PseudoVLSSEG2E64_V_M4_MASK }, // 107
  { 0x3, 0x0, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG3E8_V_M1 }, // 108
  { 0x3, 0x0, 0x0, 0x0, 0x3, 0x1, PseudoVLSEG3E8_V_M2 }, // 109
  { 0x3, 0x0, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG3E8_V_MF8 }, // 110
  { 0x3, 0x0, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG3E8_V_MF4 }, // 111
  { 0x3, 0x0, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG3E8_V_MF2 }, // 112
  { 0x3, 0x0, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG3E16_V_M1 }, // 113
  { 0x3, 0x0, 0x0, 0x0, 0x4, 0x1, PseudoVLSEG3E16_V_M2 }, // 114
  { 0x3, 0x0, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG3E16_V_MF4 }, // 115
  { 0x3, 0x0, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG3E16_V_MF2 }, // 116
  { 0x3, 0x0, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG3E32_V_M1 }, // 117
  { 0x3, 0x0, 0x0, 0x0, 0x5, 0x1, PseudoVLSEG3E32_V_M2 }, // 118
  { 0x3, 0x0, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG3E32_V_MF2 }, // 119
  { 0x3, 0x0, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG3E64_V_M1 }, // 120
  { 0x3, 0x0, 0x0, 0x0, 0x6, 0x1, PseudoVLSEG3E64_V_M2 }, // 121
  { 0x3, 0x0, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG3E8FF_V_M1 }, // 122
  { 0x3, 0x0, 0x0, 0x1, 0x3, 0x1, PseudoVLSEG3E8FF_V_M2 }, // 123
  { 0x3, 0x0, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG3E8FF_V_MF8 }, // 124
  { 0x3, 0x0, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG3E8FF_V_MF4 }, // 125
  { 0x3, 0x0, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG3E8FF_V_MF2 }, // 126
  { 0x3, 0x0, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG3E16FF_V_M1 }, // 127
  { 0x3, 0x0, 0x0, 0x1, 0x4, 0x1, PseudoVLSEG3E16FF_V_M2 }, // 128
  { 0x3, 0x0, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG3E16FF_V_MF4 }, // 129
  { 0x3, 0x0, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG3E16FF_V_MF2 }, // 130
  { 0x3, 0x0, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG3E32FF_V_M1 }, // 131
  { 0x3, 0x0, 0x0, 0x1, 0x5, 0x1, PseudoVLSEG3E32FF_V_M2 }, // 132
  { 0x3, 0x0, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG3E32FF_V_MF2 }, // 133
  { 0x3, 0x0, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG3E64FF_V_M1 }, // 134
  { 0x3, 0x0, 0x0, 0x1, 0x6, 0x1, PseudoVLSEG3E64FF_V_M2 }, // 135
  { 0x3, 0x0, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG3E8_V_M1 }, // 136
  { 0x3, 0x0, 0x1, 0x0, 0x3, 0x1, PseudoVLSSEG3E8_V_M2 }, // 137
  { 0x3, 0x0, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG3E8_V_MF8 }, // 138
  { 0x3, 0x0, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG3E8_V_MF4 }, // 139
  { 0x3, 0x0, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG3E8_V_MF2 }, // 140
  { 0x3, 0x0, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG3E16_V_M1 }, // 141
  { 0x3, 0x0, 0x1, 0x0, 0x4, 0x1, PseudoVLSSEG3E16_V_M2 }, // 142
  { 0x3, 0x0, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG3E16_V_MF4 }, // 143
  { 0x3, 0x0, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG3E16_V_MF2 }, // 144
  { 0x3, 0x0, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG3E32_V_M1 }, // 145
  { 0x3, 0x0, 0x1, 0x0, 0x5, 0x1, PseudoVLSSEG3E32_V_M2 }, // 146
  { 0x3, 0x0, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG3E32_V_MF2 }, // 147
  { 0x3, 0x0, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG3E64_V_M1 }, // 148
  { 0x3, 0x0, 0x1, 0x0, 0x6, 0x1, PseudoVLSSEG3E64_V_M2 }, // 149
  { 0x3, 0x1, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG3E8_V_M1_MASK }, // 150
  { 0x3, 0x1, 0x0, 0x0, 0x3, 0x1, PseudoVLSEG3E8_V_M2_MASK }, // 151
  { 0x3, 0x1, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG3E8_V_MF8_MASK }, // 152
  { 0x3, 0x1, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG3E8_V_MF4_MASK }, // 153
  { 0x3, 0x1, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG3E8_V_MF2_MASK }, // 154
  { 0x3, 0x1, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG3E16_V_M1_MASK }, // 155
  { 0x3, 0x1, 0x0, 0x0, 0x4, 0x1, PseudoVLSEG3E16_V_M2_MASK }, // 156
  { 0x3, 0x1, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG3E16_V_MF4_MASK }, // 157
  { 0x3, 0x1, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG3E16_V_MF2_MASK }, // 158
  { 0x3, 0x1, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG3E32_V_M1_MASK }, // 159
  { 0x3, 0x1, 0x0, 0x0, 0x5, 0x1, PseudoVLSEG3E32_V_M2_MASK }, // 160
  { 0x3, 0x1, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG3E32_V_MF2_MASK }, // 161
  { 0x3, 0x1, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG3E64_V_M1_MASK }, // 162
  { 0x3, 0x1, 0x0, 0x0, 0x6, 0x1, PseudoVLSEG3E64_V_M2_MASK }, // 163
  { 0x3, 0x1, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG3E8FF_V_M1_MASK }, // 164
  { 0x3, 0x1, 0x0, 0x1, 0x3, 0x1, PseudoVLSEG3E8FF_V_M2_MASK }, // 165
  { 0x3, 0x1, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG3E8FF_V_MF8_MASK }, // 166
  { 0x3, 0x1, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG3E8FF_V_MF4_MASK }, // 167
  { 0x3, 0x1, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG3E8FF_V_MF2_MASK }, // 168
  { 0x3, 0x1, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG3E16FF_V_M1_MASK }, // 169
  { 0x3, 0x1, 0x0, 0x1, 0x4, 0x1, PseudoVLSEG3E16FF_V_M2_MASK }, // 170
  { 0x3, 0x1, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG3E16FF_V_MF4_MASK }, // 171
  { 0x3, 0x1, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG3E16FF_V_MF2_MASK }, // 172
  { 0x3, 0x1, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG3E32FF_V_M1_MASK }, // 173
  { 0x3, 0x1, 0x0, 0x1, 0x5, 0x1, PseudoVLSEG3E32FF_V_M2_MASK }, // 174
  { 0x3, 0x1, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG3E32FF_V_MF2_MASK }, // 175
  { 0x3, 0x1, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG3E64FF_V_M1_MASK }, // 176
  { 0x3, 0x1, 0x0, 0x1, 0x6, 0x1, PseudoVLSEG3E64FF_V_M2_MASK }, // 177
  { 0x3, 0x1, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG3E8_V_M1_MASK }, // 178
  { 0x3, 0x1, 0x1, 0x0, 0x3, 0x1, PseudoVLSSEG3E8_V_M2_MASK }, // 179
  { 0x3, 0x1, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG3E8_V_MF8_MASK }, // 180
  { 0x3, 0x1, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG3E8_V_MF4_MASK }, // 181
  { 0x3, 0x1, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG3E8_V_MF2_MASK }, // 182
  { 0x3, 0x1, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG3E16_V_M1_MASK }, // 183
  { 0x3, 0x1, 0x1, 0x0, 0x4, 0x1, PseudoVLSSEG3E16_V_M2_MASK }, // 184
  { 0x3, 0x1, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG3E16_V_MF4_MASK }, // 185
  { 0x3, 0x1, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG3E16_V_MF2_MASK }, // 186
  { 0x3, 0x1, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG3E32_V_M1_MASK }, // 187
  { 0x3, 0x1, 0x1, 0x0, 0x5, 0x1, PseudoVLSSEG3E32_V_M2_MASK }, // 188
  { 0x3, 0x1, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG3E32_V_MF2_MASK }, // 189
  { 0x3, 0x1, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG3E64_V_M1_MASK }, // 190
  { 0x3, 0x1, 0x1, 0x0, 0x6, 0x1, PseudoVLSSEG3E64_V_M2_MASK }, // 191
  { 0x4, 0x0, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG4E8_V_M1 }, // 192
  { 0x4, 0x0, 0x0, 0x0, 0x3, 0x1, PseudoVLSEG4E8_V_M2 }, // 193
  { 0x4, 0x0, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG4E8_V_MF8 }, // 194
  { 0x4, 0x0, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG4E8_V_MF4 }, // 195
  { 0x4, 0x0, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG4E8_V_MF2 }, // 196
  { 0x4, 0x0, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG4E16_V_M1 }, // 197
  { 0x4, 0x0, 0x0, 0x0, 0x4, 0x1, PseudoVLSEG4E16_V_M2 }, // 198
  { 0x4, 0x0, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG4E16_V_MF4 }, // 199
  { 0x4, 0x0, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG4E16_V_MF2 }, // 200
  { 0x4, 0x0, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG4E32_V_M1 }, // 201
  { 0x4, 0x0, 0x0, 0x0, 0x5, 0x1, PseudoVLSEG4E32_V_M2 }, // 202
  { 0x4, 0x0, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG4E32_V_MF2 }, // 203
  { 0x4, 0x0, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG4E64_V_M1 }, // 204
  { 0x4, 0x0, 0x0, 0x0, 0x6, 0x1, PseudoVLSEG4E64_V_M2 }, // 205
  { 0x4, 0x0, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG4E8FF_V_M1 }, // 206
  { 0x4, 0x0, 0x0, 0x1, 0x3, 0x1, PseudoVLSEG4E8FF_V_M2 }, // 207
  { 0x4, 0x0, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG4E8FF_V_MF8 }, // 208
  { 0x4, 0x0, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG4E8FF_V_MF4 }, // 209
  { 0x4, 0x0, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG4E8FF_V_MF2 }, // 210
  { 0x4, 0x0, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG4E16FF_V_M1 }, // 211
  { 0x4, 0x0, 0x0, 0x1, 0x4, 0x1, PseudoVLSEG4E16FF_V_M2 }, // 212
  { 0x4, 0x0, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG4E16FF_V_MF4 }, // 213
  { 0x4, 0x0, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG4E16FF_V_MF2 }, // 214
  { 0x4, 0x0, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG4E32FF_V_M1 }, // 215
  { 0x4, 0x0, 0x0, 0x1, 0x5, 0x1, PseudoVLSEG4E32FF_V_M2 }, // 216
  { 0x4, 0x0, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG4E32FF_V_MF2 }, // 217
  { 0x4, 0x0, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG4E64FF_V_M1 }, // 218
  { 0x4, 0x0, 0x0, 0x1, 0x6, 0x1, PseudoVLSEG4E64FF_V_M2 }, // 219
  { 0x4, 0x0, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG4E8_V_M1 }, // 220
  { 0x4, 0x0, 0x1, 0x0, 0x3, 0x1, PseudoVLSSEG4E8_V_M2 }, // 221
  { 0x4, 0x0, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG4E8_V_MF8 }, // 222
  { 0x4, 0x0, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG4E8_V_MF4 }, // 223
  { 0x4, 0x0, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG4E8_V_MF2 }, // 224
  { 0x4, 0x0, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG4E16_V_M1 }, // 225
  { 0x4, 0x0, 0x1, 0x0, 0x4, 0x1, PseudoVLSSEG4E16_V_M2 }, // 226
  { 0x4, 0x0, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG4E16_V_MF4 }, // 227
  { 0x4, 0x0, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG4E16_V_MF2 }, // 228
  { 0x4, 0x0, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG4E32_V_M1 }, // 229
  { 0x4, 0x0, 0x1, 0x0, 0x5, 0x1, PseudoVLSSEG4E32_V_M2 }, // 230
  { 0x4, 0x0, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG4E32_V_MF2 }, // 231
  { 0x4, 0x0, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG4E64_V_M1 }, // 232
  { 0x4, 0x0, 0x1, 0x0, 0x6, 0x1, PseudoVLSSEG4E64_V_M2 }, // 233
  { 0x4, 0x1, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG4E8_V_M1_MASK }, // 234
  { 0x4, 0x1, 0x0, 0x0, 0x3, 0x1, PseudoVLSEG4E8_V_M2_MASK }, // 235
  { 0x4, 0x1, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG4E8_V_MF8_MASK }, // 236
  { 0x4, 0x1, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG4E8_V_MF4_MASK }, // 237
  { 0x4, 0x1, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG4E8_V_MF2_MASK }, // 238
  { 0x4, 0x1, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG4E16_V_M1_MASK }, // 239
  { 0x4, 0x1, 0x0, 0x0, 0x4, 0x1, PseudoVLSEG4E16_V_M2_MASK }, // 240
  { 0x4, 0x1, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG4E16_V_MF4_MASK }, // 241
  { 0x4, 0x1, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG4E16_V_MF2_MASK }, // 242
  { 0x4, 0x1, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG4E32_V_M1_MASK }, // 243
  { 0x4, 0x1, 0x0, 0x0, 0x5, 0x1, PseudoVLSEG4E32_V_M2_MASK }, // 244
  { 0x4, 0x1, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG4E32_V_MF2_MASK }, // 245
  { 0x4, 0x1, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG4E64_V_M1_MASK }, // 246
  { 0x4, 0x1, 0x0, 0x0, 0x6, 0x1, PseudoVLSEG4E64_V_M2_MASK }, // 247
  { 0x4, 0x1, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG4E8FF_V_M1_MASK }, // 248
  { 0x4, 0x1, 0x0, 0x1, 0x3, 0x1, PseudoVLSEG4E8FF_V_M2_MASK }, // 249
  { 0x4, 0x1, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG4E8FF_V_MF8_MASK }, // 250
  { 0x4, 0x1, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG4E8FF_V_MF4_MASK }, // 251
  { 0x4, 0x1, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG4E8FF_V_MF2_MASK }, // 252
  { 0x4, 0x1, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG4E16FF_V_M1_MASK }, // 253
  { 0x4, 0x1, 0x0, 0x1, 0x4, 0x1, PseudoVLSEG4E16FF_V_M2_MASK }, // 254
  { 0x4, 0x1, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG4E16FF_V_MF4_MASK }, // 255
  { 0x4, 0x1, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG4E16FF_V_MF2_MASK }, // 256
  { 0x4, 0x1, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG4E32FF_V_M1_MASK }, // 257
  { 0x4, 0x1, 0x0, 0x1, 0x5, 0x1, PseudoVLSEG4E32FF_V_M2_MASK }, // 258
  { 0x4, 0x1, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG4E32FF_V_MF2_MASK }, // 259
  { 0x4, 0x1, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG4E64FF_V_M1_MASK }, // 260
  { 0x4, 0x1, 0x0, 0x1, 0x6, 0x1, PseudoVLSEG4E64FF_V_M2_MASK }, // 261
  { 0x4, 0x1, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG4E8_V_M1_MASK }, // 262
  { 0x4, 0x1, 0x1, 0x0, 0x3, 0x1, PseudoVLSSEG4E8_V_M2_MASK }, // 263
  { 0x4, 0x1, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG4E8_V_MF8_MASK }, // 264
  { 0x4, 0x1, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG4E8_V_MF4_MASK }, // 265
  { 0x4, 0x1, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG4E8_V_MF2_MASK }, // 266
  { 0x4, 0x1, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG4E16_V_M1_MASK }, // 267
  { 0x4, 0x1, 0x1, 0x0, 0x4, 0x1, PseudoVLSSEG4E16_V_M2_MASK }, // 268
  { 0x4, 0x1, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG4E16_V_MF4_MASK }, // 269
  { 0x4, 0x1, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG4E16_V_MF2_MASK }, // 270
  { 0x4, 0x1, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG4E32_V_M1_MASK }, // 271
  { 0x4, 0x1, 0x1, 0x0, 0x5, 0x1, PseudoVLSSEG4E32_V_M2_MASK }, // 272
  { 0x4, 0x1, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG4E32_V_MF2_MASK }, // 273
  { 0x4, 0x1, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG4E64_V_M1_MASK }, // 274
  { 0x4, 0x1, 0x1, 0x0, 0x6, 0x1, PseudoVLSSEG4E64_V_M2_MASK }, // 275
  { 0x5, 0x0, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG5E8_V_M1 }, // 276
  { 0x5, 0x0, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG5E8_V_MF8 }, // 277
  { 0x5, 0x0, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG5E8_V_MF4 }, // 278
  { 0x5, 0x0, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG5E8_V_MF2 }, // 279
  { 0x5, 0x0, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG5E16_V_M1 }, // 280
  { 0x5, 0x0, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG5E16_V_MF4 }, // 281
  { 0x5, 0x0, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG5E16_V_MF2 }, // 282
  { 0x5, 0x0, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG5E32_V_M1 }, // 283
  { 0x5, 0x0, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG5E32_V_MF2 }, // 284
  { 0x5, 0x0, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG5E64_V_M1 }, // 285
  { 0x5, 0x0, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG5E8FF_V_M1 }, // 286
  { 0x5, 0x0, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG5E8FF_V_MF8 }, // 287
  { 0x5, 0x0, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG5E8FF_V_MF4 }, // 288
  { 0x5, 0x0, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG5E8FF_V_MF2 }, // 289
  { 0x5, 0x0, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG5E16FF_V_M1 }, // 290
  { 0x5, 0x0, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG5E16FF_V_MF4 }, // 291
  { 0x5, 0x0, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG5E16FF_V_MF2 }, // 292
  { 0x5, 0x0, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG5E32FF_V_M1 }, // 293
  { 0x5, 0x0, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG5E32FF_V_MF2 }, // 294
  { 0x5, 0x0, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG5E64FF_V_M1 }, // 295
  { 0x5, 0x0, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG5E8_V_M1 }, // 296
  { 0x5, 0x0, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG5E8_V_MF8 }, // 297
  { 0x5, 0x0, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG5E8_V_MF4 }, // 298
  { 0x5, 0x0, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG5E8_V_MF2 }, // 299
  { 0x5, 0x0, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG5E16_V_M1 }, // 300
  { 0x5, 0x0, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG5E16_V_MF4 }, // 301
  { 0x5, 0x0, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG5E16_V_MF2 }, // 302
  { 0x5, 0x0, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG5E32_V_M1 }, // 303
  { 0x5, 0x0, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG5E32_V_MF2 }, // 304
  { 0x5, 0x0, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG5E64_V_M1 }, // 305
  { 0x5, 0x1, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG5E8_V_M1_MASK }, // 306
  { 0x5, 0x1, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG5E8_V_MF8_MASK }, // 307
  { 0x5, 0x1, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG5E8_V_MF4_MASK }, // 308
  { 0x5, 0x1, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG5E8_V_MF2_MASK }, // 309
  { 0x5, 0x1, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG5E16_V_M1_MASK }, // 310
  { 0x5, 0x1, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG5E16_V_MF4_MASK }, // 311
  { 0x5, 0x1, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG5E16_V_MF2_MASK }, // 312
  { 0x5, 0x1, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG5E32_V_M1_MASK }, // 313
  { 0x5, 0x1, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG5E32_V_MF2_MASK }, // 314
  { 0x5, 0x1, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG5E64_V_M1_MASK }, // 315
  { 0x5, 0x1, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG5E8FF_V_M1_MASK }, // 316
  { 0x5, 0x1, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG5E8FF_V_MF8_MASK }, // 317
  { 0x5, 0x1, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG5E8FF_V_MF4_MASK }, // 318
  { 0x5, 0x1, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG5E8FF_V_MF2_MASK }, // 319
  { 0x5, 0x1, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG5E16FF_V_M1_MASK }, // 320
  { 0x5, 0x1, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG5E16FF_V_MF4_MASK }, // 321
  { 0x5, 0x1, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG5E16FF_V_MF2_MASK }, // 322
  { 0x5, 0x1, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG5E32FF_V_M1_MASK }, // 323
  { 0x5, 0x1, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG5E32FF_V_MF2_MASK }, // 324
  { 0x5, 0x1, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG5E64FF_V_M1_MASK }, // 325
  { 0x5, 0x1, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG5E8_V_M1_MASK }, // 326
  { 0x5, 0x1, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG5E8_V_MF8_MASK }, // 327
  { 0x5, 0x1, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG5E8_V_MF4_MASK }, // 328
  { 0x5, 0x1, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG5E8_V_MF2_MASK }, // 329
  { 0x5, 0x1, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG5E16_V_M1_MASK }, // 330
  { 0x5, 0x1, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG5E16_V_MF4_MASK }, // 331
  { 0x5, 0x1, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG5E16_V_MF2_MASK }, // 332
  { 0x5, 0x1, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG5E32_V_M1_MASK }, // 333
  { 0x5, 0x1, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG5E32_V_MF2_MASK }, // 334
  { 0x5, 0x1, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG5E64_V_M1_MASK }, // 335
  { 0x6, 0x0, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG6E8_V_M1 }, // 336
  { 0x6, 0x0, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG6E8_V_MF8 }, // 337
  { 0x6, 0x0, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG6E8_V_MF4 }, // 338
  { 0x6, 0x0, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG6E8_V_MF2 }, // 339
  { 0x6, 0x0, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG6E16_V_M1 }, // 340
  { 0x6, 0x0, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG6E16_V_MF4 }, // 341
  { 0x6, 0x0, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG6E16_V_MF2 }, // 342
  { 0x6, 0x0, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG6E32_V_M1 }, // 343
  { 0x6, 0x0, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG6E32_V_MF2 }, // 344
  { 0x6, 0x0, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG6E64_V_M1 }, // 345
  { 0x6, 0x0, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG6E8FF_V_M1 }, // 346
  { 0x6, 0x0, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG6E8FF_V_MF8 }, // 347
  { 0x6, 0x0, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG6E8FF_V_MF4 }, // 348
  { 0x6, 0x0, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG6E8FF_V_MF2 }, // 349
  { 0x6, 0x0, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG6E16FF_V_M1 }, // 350
  { 0x6, 0x0, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG6E16FF_V_MF4 }, // 351
  { 0x6, 0x0, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG6E16FF_V_MF2 }, // 352
  { 0x6, 0x0, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG6E32FF_V_M1 }, // 353
  { 0x6, 0x0, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG6E32FF_V_MF2 }, // 354
  { 0x6, 0x0, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG6E64FF_V_M1 }, // 355
  { 0x6, 0x0, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG6E8_V_M1 }, // 356
  { 0x6, 0x0, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG6E8_V_MF8 }, // 357
  { 0x6, 0x0, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG6E8_V_MF4 }, // 358
  { 0x6, 0x0, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG6E8_V_MF2 }, // 359
  { 0x6, 0x0, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG6E16_V_M1 }, // 360
  { 0x6, 0x0, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG6E16_V_MF4 }, // 361
  { 0x6, 0x0, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG6E16_V_MF2 }, // 362
  { 0x6, 0x0, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG6E32_V_M1 }, // 363
  { 0x6, 0x0, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG6E32_V_MF2 }, // 364
  { 0x6, 0x0, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG6E64_V_M1 }, // 365
  { 0x6, 0x1, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG6E8_V_M1_MASK }, // 366
  { 0x6, 0x1, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG6E8_V_MF8_MASK }, // 367
  { 0x6, 0x1, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG6E8_V_MF4_MASK }, // 368
  { 0x6, 0x1, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG6E8_V_MF2_MASK }, // 369
  { 0x6, 0x1, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG6E16_V_M1_MASK }, // 370
  { 0x6, 0x1, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG6E16_V_MF4_MASK }, // 371
  { 0x6, 0x1, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG6E16_V_MF2_MASK }, // 372
  { 0x6, 0x1, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG6E32_V_M1_MASK }, // 373
  { 0x6, 0x1, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG6E32_V_MF2_MASK }, // 374
  { 0x6, 0x1, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG6E64_V_M1_MASK }, // 375
  { 0x6, 0x1, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG6E8FF_V_M1_MASK }, // 376
  { 0x6, 0x1, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG6E8FF_V_MF8_MASK }, // 377
  { 0x6, 0x1, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG6E8FF_V_MF4_MASK }, // 378
  { 0x6, 0x1, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG6E8FF_V_MF2_MASK }, // 379
  { 0x6, 0x1, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG6E16FF_V_M1_MASK }, // 380
  { 0x6, 0x1, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG6E16FF_V_MF4_MASK }, // 381
  { 0x6, 0x1, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG6E16FF_V_MF2_MASK }, // 382
  { 0x6, 0x1, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG6E32FF_V_M1_MASK }, // 383
  { 0x6, 0x1, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG6E32FF_V_MF2_MASK }, // 384
  { 0x6, 0x1, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG6E64FF_V_M1_MASK }, // 385
  { 0x6, 0x1, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG6E8_V_M1_MASK }, // 386
  { 0x6, 0x1, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG6E8_V_MF8_MASK }, // 387
  { 0x6, 0x1, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG6E8_V_MF4_MASK }, // 388
  { 0x6, 0x1, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG6E8_V_MF2_MASK }, // 389
  { 0x6, 0x1, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG6E16_V_M1_MASK }, // 390
  { 0x6, 0x1, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG6E16_V_MF4_MASK }, // 391
  { 0x6, 0x1, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG6E16_V_MF2_MASK }, // 392
  { 0x6, 0x1, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG6E32_V_M1_MASK }, // 393
  { 0x6, 0x1, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG6E32_V_MF2_MASK }, // 394
  { 0x6, 0x1, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG6E64_V_M1_MASK }, // 395
  { 0x7, 0x0, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG7E8_V_M1 }, // 396
  { 0x7, 0x0, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG7E8_V_MF8 }, // 397
  { 0x7, 0x0, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG7E8_V_MF4 }, // 398
  { 0x7, 0x0, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG7E8_V_MF2 }, // 399
  { 0x7, 0x0, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG7E16_V_M1 }, // 400
  { 0x7, 0x0, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG7E16_V_MF4 }, // 401
  { 0x7, 0x0, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG7E16_V_MF2 }, // 402
  { 0x7, 0x0, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG7E32_V_M1 }, // 403
  { 0x7, 0x0, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG7E32_V_MF2 }, // 404
  { 0x7, 0x0, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG7E64_V_M1 }, // 405
  { 0x7, 0x0, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG7E8FF_V_M1 }, // 406
  { 0x7, 0x0, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG7E8FF_V_MF8 }, // 407
  { 0x7, 0x0, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG7E8FF_V_MF4 }, // 408
  { 0x7, 0x0, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG7E8FF_V_MF2 }, // 409
  { 0x7, 0x0, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG7E16FF_V_M1 }, // 410
  { 0x7, 0x0, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG7E16FF_V_MF4 }, // 411
  { 0x7, 0x0, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG7E16FF_V_MF2 }, // 412
  { 0x7, 0x0, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG7E32FF_V_M1 }, // 413
  { 0x7, 0x0, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG7E32FF_V_MF2 }, // 414
  { 0x7, 0x0, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG7E64FF_V_M1 }, // 415
  { 0x7, 0x0, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG7E8_V_M1 }, // 416
  { 0x7, 0x0, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG7E8_V_MF8 }, // 417
  { 0x7, 0x0, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG7E8_V_MF4 }, // 418
  { 0x7, 0x0, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG7E8_V_MF2 }, // 419
  { 0x7, 0x0, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG7E16_V_M1 }, // 420
  { 0x7, 0x0, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG7E16_V_MF4 }, // 421
  { 0x7, 0x0, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG7E16_V_MF2 }, // 422
  { 0x7, 0x0, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG7E32_V_M1 }, // 423
  { 0x7, 0x0, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG7E32_V_MF2 }, // 424
  { 0x7, 0x0, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG7E64_V_M1 }, // 425
  { 0x7, 0x1, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG7E8_V_M1_MASK }, // 426
  { 0x7, 0x1, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG7E8_V_MF8_MASK }, // 427
  { 0x7, 0x1, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG7E8_V_MF4_MASK }, // 428
  { 0x7, 0x1, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG7E8_V_MF2_MASK }, // 429
  { 0x7, 0x1, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG7E16_V_M1_MASK }, // 430
  { 0x7, 0x1, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG7E16_V_MF4_MASK }, // 431
  { 0x7, 0x1, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG7E16_V_MF2_MASK }, // 432
  { 0x7, 0x1, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG7E32_V_M1_MASK }, // 433
  { 0x7, 0x1, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG7E32_V_MF2_MASK }, // 434
  { 0x7, 0x1, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG7E64_V_M1_MASK }, // 435
  { 0x7, 0x1, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG7E8FF_V_M1_MASK }, // 436
  { 0x7, 0x1, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG7E8FF_V_MF8_MASK }, // 437
  { 0x7, 0x1, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG7E8FF_V_MF4_MASK }, // 438
  { 0x7, 0x1, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG7E8FF_V_MF2_MASK }, // 439
  { 0x7, 0x1, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG7E16FF_V_M1_MASK }, // 440
  { 0x7, 0x1, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG7E16FF_V_MF4_MASK }, // 441
  { 0x7, 0x1, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG7E16FF_V_MF2_MASK }, // 442
  { 0x7, 0x1, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG7E32FF_V_M1_MASK }, // 443
  { 0x7, 0x1, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG7E32FF_V_MF2_MASK }, // 444
  { 0x7, 0x1, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG7E64FF_V_M1_MASK }, // 445
  { 0x7, 0x1, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG7E8_V_M1_MASK }, // 446
  { 0x7, 0x1, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG7E8_V_MF8_MASK }, // 447
  { 0x7, 0x1, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG7E8_V_MF4_MASK }, // 448
  { 0x7, 0x1, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG7E8_V_MF2_MASK }, // 449
  { 0x7, 0x1, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG7E16_V_M1_MASK }, // 450
  { 0x7, 0x1, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG7E16_V_MF4_MASK }, // 451
  { 0x7, 0x1, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG7E16_V_MF2_MASK }, // 452
  { 0x7, 0x1, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG7E32_V_M1_MASK }, // 453
  { 0x7, 0x1, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG7E32_V_MF2_MASK }, // 454
  { 0x7, 0x1, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG7E64_V_M1_MASK }, // 455
  { 0x8, 0x0, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG8E8_V_M1 }, // 456
  { 0x8, 0x0, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG8E8_V_MF8 }, // 457
  { 0x8, 0x0, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG8E8_V_MF4 }, // 458
  { 0x8, 0x0, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG8E8_V_MF2 }, // 459
  { 0x8, 0x0, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG8E16_V_M1 }, // 460
  { 0x8, 0x0, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG8E16_V_MF4 }, // 461
  { 0x8, 0x0, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG8E16_V_MF2 }, // 462
  { 0x8, 0x0, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG8E32_V_M1 }, // 463
  { 0x8, 0x0, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG8E32_V_MF2 }, // 464
  { 0x8, 0x0, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG8E64_V_M1 }, // 465
  { 0x8, 0x0, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG8E8FF_V_M1 }, // 466
  { 0x8, 0x0, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG8E8FF_V_MF8 }, // 467
  { 0x8, 0x0, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG8E8FF_V_MF4 }, // 468
  { 0x8, 0x0, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG8E8FF_V_MF2 }, // 469
  { 0x8, 0x0, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG8E16FF_V_M1 }, // 470
  { 0x8, 0x0, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG8E16FF_V_MF4 }, // 471
  { 0x8, 0x0, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG8E16FF_V_MF2 }, // 472
  { 0x8, 0x0, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG8E32FF_V_M1 }, // 473
  { 0x8, 0x0, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG8E32FF_V_MF2 }, // 474
  { 0x8, 0x0, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG8E64FF_V_M1 }, // 475
  { 0x8, 0x0, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG8E8_V_M1 }, // 476
  { 0x8, 0x0, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG8E8_V_MF8 }, // 477
  { 0x8, 0x0, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG8E8_V_MF4 }, // 478
  { 0x8, 0x0, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG8E8_V_MF2 }, // 479
  { 0x8, 0x0, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG8E16_V_M1 }, // 480
  { 0x8, 0x0, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG8E16_V_MF4 }, // 481
  { 0x8, 0x0, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG8E16_V_MF2 }, // 482
  { 0x8, 0x0, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG8E32_V_M1 }, // 483
  { 0x8, 0x0, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG8E32_V_MF2 }, // 484
  { 0x8, 0x0, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG8E64_V_M1 }, // 485
  { 0x8, 0x1, 0x0, 0x0, 0x3, 0x0, PseudoVLSEG8E8_V_M1_MASK }, // 486
  { 0x8, 0x1, 0x0, 0x0, 0x3, 0x5, PseudoVLSEG8E8_V_MF8_MASK }, // 487
  { 0x8, 0x1, 0x0, 0x0, 0x3, 0x6, PseudoVLSEG8E8_V_MF4_MASK }, // 488
  { 0x8, 0x1, 0x0, 0x0, 0x3, 0x7, PseudoVLSEG8E8_V_MF2_MASK }, // 489
  { 0x8, 0x1, 0x0, 0x0, 0x4, 0x0, PseudoVLSEG8E16_V_M1_MASK }, // 490
  { 0x8, 0x1, 0x0, 0x0, 0x4, 0x6, PseudoVLSEG8E16_V_MF4_MASK }, // 491
  { 0x8, 0x1, 0x0, 0x0, 0x4, 0x7, PseudoVLSEG8E16_V_MF2_MASK }, // 492
  { 0x8, 0x1, 0x0, 0x0, 0x5, 0x0, PseudoVLSEG8E32_V_M1_MASK }, // 493
  { 0x8, 0x1, 0x0, 0x0, 0x5, 0x7, PseudoVLSEG8E32_V_MF2_MASK }, // 494
  { 0x8, 0x1, 0x0, 0x0, 0x6, 0x0, PseudoVLSEG8E64_V_M1_MASK }, // 495
  { 0x8, 0x1, 0x0, 0x1, 0x3, 0x0, PseudoVLSEG8E8FF_V_M1_MASK }, // 496
  { 0x8, 0x1, 0x0, 0x1, 0x3, 0x5, PseudoVLSEG8E8FF_V_MF8_MASK }, // 497
  { 0x8, 0x1, 0x0, 0x1, 0x3, 0x6, PseudoVLSEG8E8FF_V_MF4_MASK }, // 498
  { 0x8, 0x1, 0x0, 0x1, 0x3, 0x7, PseudoVLSEG8E8FF_V_MF2_MASK }, // 499
  { 0x8, 0x1, 0x0, 0x1, 0x4, 0x0, PseudoVLSEG8E16FF_V_M1_MASK }, // 500
  { 0x8, 0x1, 0x0, 0x1, 0x4, 0x6, PseudoVLSEG8E16FF_V_MF4_MASK }, // 501
  { 0x8, 0x1, 0x0, 0x1, 0x4, 0x7, PseudoVLSEG8E16FF_V_MF2_MASK }, // 502
  { 0x8, 0x1, 0x0, 0x1, 0x5, 0x0, PseudoVLSEG8E32FF_V_M1_MASK }, // 503
  { 0x8, 0x1, 0x0, 0x1, 0x5, 0x7, PseudoVLSEG8E32FF_V_MF2_MASK }, // 504
  { 0x8, 0x1, 0x0, 0x1, 0x6, 0x0, PseudoVLSEG8E64FF_V_M1_MASK }, // 505
  { 0x8, 0x1, 0x1, 0x0, 0x3, 0x0, PseudoVLSSEG8E8_V_M1_MASK }, // 506
  { 0x8, 0x1, 0x1, 0x0, 0x3, 0x5, PseudoVLSSEG8E8_V_MF8_MASK }, // 507
  { 0x8, 0x1, 0x1, 0x0, 0x3, 0x6, PseudoVLSSEG8E8_V_MF4_MASK }, // 508
  { 0x8, 0x1, 0x1, 0x0, 0x3, 0x7, PseudoVLSSEG8E8_V_MF2_MASK }, // 509
  { 0x8, 0x1, 0x1, 0x0, 0x4, 0x0, PseudoVLSSEG8E16_V_M1_MASK }, // 510
  { 0x8, 0x1, 0x1, 0x0, 0x4, 0x6, PseudoVLSSEG8E16_V_MF4_MASK }, // 511
  { 0x8, 0x1, 0x1, 0x0, 0x4, 0x7, PseudoVLSSEG8E16_V_MF2_MASK }, // 512
  { 0x8, 0x1, 0x1, 0x0, 0x5, 0x0, PseudoVLSSEG8E32_V_M1_MASK }, // 513
  { 0x8, 0x1, 0x1, 0x0, 0x5, 0x7, PseudoVLSSEG8E32_V_MF2_MASK }, // 514
  { 0x8, 0x1, 0x1, 0x0, 0x6, 0x0, PseudoVLSSEG8E64_V_M1_MASK }, // 515
 };

const VLSEGPseudo *getVLSEGPseudo(uint8_t NF, uint8_t Masked, uint8_t Strided, uint8_t FF, uint8_t Log2SEW, uint8_t LMUL) {
  struct KeyType {
    uint8_t NF;
    uint8_t Masked;
    uint8_t Strided;
    uint8_t FF;
    uint8_t Log2SEW;
    uint8_t LMUL;
  };
  KeyType Key = {NF, Masked, Strided, FF, Log2SEW, LMUL};
  auto Table = makeArrayRef(RISCVVLSEGTable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const VLSEGPseudo &LHS, const KeyType &RHS) {
      if (LHS.NF < RHS.NF)
        return true;
      if (LHS.NF > RHS.NF)
        return false;
      if (LHS.Masked < RHS.Masked)
        return true;
      if (LHS.Masked > RHS.Masked)
        return false;
      if (LHS.Strided < RHS.Strided)
        return true;
      if (LHS.Strided > RHS.Strided)
        return false;
      if (LHS.FF < RHS.FF)
        return true;
      if (LHS.FF > RHS.FF)
        return false;
      if (LHS.Log2SEW < RHS.Log2SEW)
        return true;
      if (LHS.Log2SEW > RHS.Log2SEW)
        return false;
      if (LHS.LMUL < RHS.LMUL)
        return true;
      if (LHS.LMUL > RHS.LMUL)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.NF != Idx->NF ||
      Key.Masked != Idx->Masked ||
      Key.Strided != Idx->Strided ||
      Key.FF != Idx->FF ||
      Key.Log2SEW != Idx->Log2SEW ||
      Key.LMUL != Idx->LMUL)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_RISCVVLXSEGTable_DECL
const VLXSEGPseudo *getVLXSEGPseudo(uint8_t NF, uint8_t Masked, uint8_t Ordered, uint8_t Log2SEW, uint8_t LMUL, uint8_t IndexLMUL);
#endif

#ifdef GET_RISCVVLXSEGTable_IMPL
constexpr VLXSEGPseudo RISCVVLXSEGTable[] = {
  { 0x2, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG2EI8_V_M1_M1 }, // 0
  { 0x2, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG2EI8_V_MF8_M1 }, // 1
  { 0x2, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG2EI8_V_MF4_M1 }, // 2
  { 0x2, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG2EI8_V_MF2_M1 }, // 3
  { 0x2, 0x0, 0x0, 0x3, 0x1, 0x0, PseudoVLUXSEG2EI8_V_M1_M2 }, // 4
  { 0x2, 0x0, 0x0, 0x3, 0x1, 0x1, PseudoVLUXSEG2EI8_V_M2_M2 }, // 5
  { 0x2, 0x0, 0x0, 0x3, 0x1, 0x6, PseudoVLUXSEG2EI8_V_MF4_M2 }, // 6
  { 0x2, 0x0, 0x0, 0x3, 0x1, 0x7, PseudoVLUXSEG2EI8_V_MF2_M2 }, // 7
  { 0x2, 0x0, 0x0, 0x3, 0x2, 0x0, PseudoVLUXSEG2EI8_V_M1_M4 }, // 8
  { 0x2, 0x0, 0x0, 0x3, 0x2, 0x1, PseudoVLUXSEG2EI8_V_M2_M4 }, // 9
  { 0x2, 0x0, 0x0, 0x3, 0x2, 0x2, PseudoVLUXSEG2EI8_V_M4_M4 }, // 10
  { 0x2, 0x0, 0x0, 0x3, 0x2, 0x7, PseudoVLUXSEG2EI8_V_MF2_M4 }, // 11
  { 0x2, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG2EI8_V_MF8_MF8 }, // 12
  { 0x2, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG2EI8_V_MF8_MF4 }, // 13
  { 0x2, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG2EI8_V_MF4_MF4 }, // 14
  { 0x2, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG2EI8_V_MF8_MF2 }, // 15
  { 0x2, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG2EI8_V_MF4_MF2 }, // 16
  { 0x2, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG2EI8_V_MF2_MF2 }, // 17
  { 0x2, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG2EI16_V_M1_M1 }, // 18
  { 0x2, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG2EI16_V_M2_M1 }, // 19
  { 0x2, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG2EI16_V_MF4_M1 }, // 20
  { 0x2, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG2EI16_V_MF2_M1 }, // 21
  { 0x2, 0x0, 0x0, 0x4, 0x1, 0x0, PseudoVLUXSEG2EI16_V_M1_M2 }, // 22
  { 0x2, 0x0, 0x0, 0x4, 0x1, 0x1, PseudoVLUXSEG2EI16_V_M2_M2 }, // 23
  { 0x2, 0x0, 0x0, 0x4, 0x1, 0x2, PseudoVLUXSEG2EI16_V_M4_M2 }, // 24
  { 0x2, 0x0, 0x0, 0x4, 0x1, 0x7, PseudoVLUXSEG2EI16_V_MF2_M2 }, // 25
  { 0x2, 0x0, 0x0, 0x4, 0x2, 0x0, PseudoVLUXSEG2EI16_V_M1_M4 }, // 26
  { 0x2, 0x0, 0x0, 0x4, 0x2, 0x1, PseudoVLUXSEG2EI16_V_M2_M4 }, // 27
  { 0x2, 0x0, 0x0, 0x4, 0x2, 0x2, PseudoVLUXSEG2EI16_V_M4_M4 }, // 28
  { 0x2, 0x0, 0x0, 0x4, 0x2, 0x3, PseudoVLUXSEG2EI16_V_M8_M4 }, // 29
  { 0x2, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG2EI16_V_MF4_MF8 }, // 30
  { 0x2, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG2EI16_V_MF4_MF4 }, // 31
  { 0x2, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG2EI16_V_MF2_MF4 }, // 32
  { 0x2, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG2EI16_V_M1_MF2 }, // 33
  { 0x2, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG2EI16_V_MF4_MF2 }, // 34
  { 0x2, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG2EI16_V_MF2_MF2 }, // 35
  { 0x2, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG2EI32_V_M1_M1 }, // 36
  { 0x2, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG2EI32_V_M2_M1 }, // 37
  { 0x2, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG2EI32_V_M4_M1 }, // 38
  { 0x2, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG2EI32_V_MF2_M1 }, // 39
  { 0x2, 0x0, 0x0, 0x5, 0x1, 0x0, PseudoVLUXSEG2EI32_V_M1_M2 }, // 40
  { 0x2, 0x0, 0x0, 0x5, 0x1, 0x1, PseudoVLUXSEG2EI32_V_M2_M2 }, // 41
  { 0x2, 0x0, 0x0, 0x5, 0x1, 0x2, PseudoVLUXSEG2EI32_V_M4_M2 }, // 42
  { 0x2, 0x0, 0x0, 0x5, 0x1, 0x3, PseudoVLUXSEG2EI32_V_M8_M2 }, // 43
  { 0x2, 0x0, 0x0, 0x5, 0x2, 0x1, PseudoVLUXSEG2EI32_V_M2_M4 }, // 44
  { 0x2, 0x0, 0x0, 0x5, 0x2, 0x2, PseudoVLUXSEG2EI32_V_M4_M4 }, // 45
  { 0x2, 0x0, 0x0, 0x5, 0x2, 0x3, PseudoVLUXSEG2EI32_V_M8_M4 }, // 46
  { 0x2, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG2EI32_V_MF2_MF8 }, // 47
  { 0x2, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG2EI32_V_M1_MF4 }, // 48
  { 0x2, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG2EI32_V_MF2_MF4 }, // 49
  { 0x2, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG2EI32_V_M1_MF2 }, // 50
  { 0x2, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG2EI32_V_M2_MF2 }, // 51
  { 0x2, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG2EI32_V_MF2_MF2 }, // 52
  { 0x2, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG2EI64_V_M1_M1 }, // 53
  { 0x2, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG2EI64_V_M2_M1 }, // 54
  { 0x2, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG2EI64_V_M4_M1 }, // 55
  { 0x2, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG2EI64_V_M8_M1 }, // 56
  { 0x2, 0x0, 0x0, 0x6, 0x1, 0x1, PseudoVLUXSEG2EI64_V_M2_M2 }, // 57
  { 0x2, 0x0, 0x0, 0x6, 0x1, 0x2, PseudoVLUXSEG2EI64_V_M4_M2 }, // 58
  { 0x2, 0x0, 0x0, 0x6, 0x1, 0x3, PseudoVLUXSEG2EI64_V_M8_M2 }, // 59
  { 0x2, 0x0, 0x0, 0x6, 0x2, 0x2, PseudoVLUXSEG2EI64_V_M4_M4 }, // 60
  { 0x2, 0x0, 0x0, 0x6, 0x2, 0x3, PseudoVLUXSEG2EI64_V_M8_M4 }, // 61
  { 0x2, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG2EI64_V_M1_MF8 }, // 62
  { 0x2, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG2EI64_V_M1_MF4 }, // 63
  { 0x2, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG2EI64_V_M2_MF4 }, // 64
  { 0x2, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG2EI64_V_M1_MF2 }, // 65
  { 0x2, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG2EI64_V_M2_MF2 }, // 66
  { 0x2, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG2EI64_V_M4_MF2 }, // 67
  { 0x2, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG2EI8_V_M1_M1 }, // 68
  { 0x2, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG2EI8_V_MF8_M1 }, // 69
  { 0x2, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG2EI8_V_MF4_M1 }, // 70
  { 0x2, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG2EI8_V_MF2_M1 }, // 71
  { 0x2, 0x0, 0x1, 0x3, 0x1, 0x0, PseudoVLOXSEG2EI8_V_M1_M2 }, // 72
  { 0x2, 0x0, 0x1, 0x3, 0x1, 0x1, PseudoVLOXSEG2EI8_V_M2_M2 }, // 73
  { 0x2, 0x0, 0x1, 0x3, 0x1, 0x6, PseudoVLOXSEG2EI8_V_MF4_M2 }, // 74
  { 0x2, 0x0, 0x1, 0x3, 0x1, 0x7, PseudoVLOXSEG2EI8_V_MF2_M2 }, // 75
  { 0x2, 0x0, 0x1, 0x3, 0x2, 0x0, PseudoVLOXSEG2EI8_V_M1_M4 }, // 76
  { 0x2, 0x0, 0x1, 0x3, 0x2, 0x1, PseudoVLOXSEG2EI8_V_M2_M4 }, // 77
  { 0x2, 0x0, 0x1, 0x3, 0x2, 0x2, PseudoVLOXSEG2EI8_V_M4_M4 }, // 78
  { 0x2, 0x0, 0x1, 0x3, 0x2, 0x7, PseudoVLOXSEG2EI8_V_MF2_M4 }, // 79
  { 0x2, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG2EI8_V_MF8_MF8 }, // 80
  { 0x2, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG2EI8_V_MF8_MF4 }, // 81
  { 0x2, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG2EI8_V_MF4_MF4 }, // 82
  { 0x2, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG2EI8_V_MF8_MF2 }, // 83
  { 0x2, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG2EI8_V_MF4_MF2 }, // 84
  { 0x2, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG2EI8_V_MF2_MF2 }, // 85
  { 0x2, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG2EI16_V_M1_M1 }, // 86
  { 0x2, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG2EI16_V_M2_M1 }, // 87
  { 0x2, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG2EI16_V_MF4_M1 }, // 88
  { 0x2, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG2EI16_V_MF2_M1 }, // 89
  { 0x2, 0x0, 0x1, 0x4, 0x1, 0x0, PseudoVLOXSEG2EI16_V_M1_M2 }, // 90
  { 0x2, 0x0, 0x1, 0x4, 0x1, 0x1, PseudoVLOXSEG2EI16_V_M2_M2 }, // 91
  { 0x2, 0x0, 0x1, 0x4, 0x1, 0x2, PseudoVLOXSEG2EI16_V_M4_M2 }, // 92
  { 0x2, 0x0, 0x1, 0x4, 0x1, 0x7, PseudoVLOXSEG2EI16_V_MF2_M2 }, // 93
  { 0x2, 0x0, 0x1, 0x4, 0x2, 0x0, PseudoVLOXSEG2EI16_V_M1_M4 }, // 94
  { 0x2, 0x0, 0x1, 0x4, 0x2, 0x1, PseudoVLOXSEG2EI16_V_M2_M4 }, // 95
  { 0x2, 0x0, 0x1, 0x4, 0x2, 0x2, PseudoVLOXSEG2EI16_V_M4_M4 }, // 96
  { 0x2, 0x0, 0x1, 0x4, 0x2, 0x3, PseudoVLOXSEG2EI16_V_M8_M4 }, // 97
  { 0x2, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG2EI16_V_MF4_MF8 }, // 98
  { 0x2, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG2EI16_V_MF4_MF4 }, // 99
  { 0x2, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG2EI16_V_MF2_MF4 }, // 100
  { 0x2, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG2EI16_V_M1_MF2 }, // 101
  { 0x2, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG2EI16_V_MF4_MF2 }, // 102
  { 0x2, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG2EI16_V_MF2_MF2 }, // 103
  { 0x2, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG2EI32_V_M1_M1 }, // 104
  { 0x2, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG2EI32_V_M2_M1 }, // 105
  { 0x2, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG2EI32_V_M4_M1 }, // 106
  { 0x2, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG2EI32_V_MF2_M1 }, // 107
  { 0x2, 0x0, 0x1, 0x5, 0x1, 0x0, PseudoVLOXSEG2EI32_V_M1_M2 }, // 108
  { 0x2, 0x0, 0x1, 0x5, 0x1, 0x1, PseudoVLOXSEG2EI32_V_M2_M2 }, // 109
  { 0x2, 0x0, 0x1, 0x5, 0x1, 0x2, PseudoVLOXSEG2EI32_V_M4_M2 }, // 110
  { 0x2, 0x0, 0x1, 0x5, 0x1, 0x3, PseudoVLOXSEG2EI32_V_M8_M2 }, // 111
  { 0x2, 0x0, 0x1, 0x5, 0x2, 0x1, PseudoVLOXSEG2EI32_V_M2_M4 }, // 112
  { 0x2, 0x0, 0x1, 0x5, 0x2, 0x2, PseudoVLOXSEG2EI32_V_M4_M4 }, // 113
  { 0x2, 0x0, 0x1, 0x5, 0x2, 0x3, PseudoVLOXSEG2EI32_V_M8_M4 }, // 114
  { 0x2, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG2EI32_V_MF2_MF8 }, // 115
  { 0x2, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG2EI32_V_M1_MF4 }, // 116
  { 0x2, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG2EI32_V_MF2_MF4 }, // 117
  { 0x2, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG2EI32_V_M1_MF2 }, // 118
  { 0x2, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG2EI32_V_M2_MF2 }, // 119
  { 0x2, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG2EI32_V_MF2_MF2 }, // 120
  { 0x2, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG2EI64_V_M1_M1 }, // 121
  { 0x2, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG2EI64_V_M2_M1 }, // 122
  { 0x2, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG2EI64_V_M4_M1 }, // 123
  { 0x2, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG2EI64_V_M8_M1 }, // 124
  { 0x2, 0x0, 0x1, 0x6, 0x1, 0x1, PseudoVLOXSEG2EI64_V_M2_M2 }, // 125
  { 0x2, 0x0, 0x1, 0x6, 0x1, 0x2, PseudoVLOXSEG2EI64_V_M4_M2 }, // 126
  { 0x2, 0x0, 0x1, 0x6, 0x1, 0x3, PseudoVLOXSEG2EI64_V_M8_M2 }, // 127
  { 0x2, 0x0, 0x1, 0x6, 0x2, 0x2, PseudoVLOXSEG2EI64_V_M4_M4 }, // 128
  { 0x2, 0x0, 0x1, 0x6, 0x2, 0x3, PseudoVLOXSEG2EI64_V_M8_M4 }, // 129
  { 0x2, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG2EI64_V_M1_MF8 }, // 130
  { 0x2, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG2EI64_V_M1_MF4 }, // 131
  { 0x2, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG2EI64_V_M2_MF4 }, // 132
  { 0x2, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG2EI64_V_M1_MF2 }, // 133
  { 0x2, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG2EI64_V_M2_MF2 }, // 134
  { 0x2, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG2EI64_V_M4_MF2 }, // 135
  { 0x2, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG2EI8_V_M1_M1_MASK }, // 136
  { 0x2, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG2EI8_V_MF8_M1_MASK }, // 137
  { 0x2, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG2EI8_V_MF4_M1_MASK }, // 138
  { 0x2, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG2EI8_V_MF2_M1_MASK }, // 139
  { 0x2, 0x1, 0x0, 0x3, 0x1, 0x0, PseudoVLUXSEG2EI8_V_M1_M2_MASK }, // 140
  { 0x2, 0x1, 0x0, 0x3, 0x1, 0x1, PseudoVLUXSEG2EI8_V_M2_M2_MASK }, // 141
  { 0x2, 0x1, 0x0, 0x3, 0x1, 0x6, PseudoVLUXSEG2EI8_V_MF4_M2_MASK }, // 142
  { 0x2, 0x1, 0x0, 0x3, 0x1, 0x7, PseudoVLUXSEG2EI8_V_MF2_M2_MASK }, // 143
  { 0x2, 0x1, 0x0, 0x3, 0x2, 0x0, PseudoVLUXSEG2EI8_V_M1_M4_MASK }, // 144
  { 0x2, 0x1, 0x0, 0x3, 0x2, 0x1, PseudoVLUXSEG2EI8_V_M2_M4_MASK }, // 145
  { 0x2, 0x1, 0x0, 0x3, 0x2, 0x2, PseudoVLUXSEG2EI8_V_M4_M4_MASK }, // 146
  { 0x2, 0x1, 0x0, 0x3, 0x2, 0x7, PseudoVLUXSEG2EI8_V_MF2_M4_MASK }, // 147
  { 0x2, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG2EI8_V_MF8_MF8_MASK }, // 148
  { 0x2, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG2EI8_V_MF8_MF4_MASK }, // 149
  { 0x2, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG2EI8_V_MF4_MF4_MASK }, // 150
  { 0x2, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG2EI8_V_MF8_MF2_MASK }, // 151
  { 0x2, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG2EI8_V_MF4_MF2_MASK }, // 152
  { 0x2, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG2EI8_V_MF2_MF2_MASK }, // 153
  { 0x2, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG2EI16_V_M1_M1_MASK }, // 154
  { 0x2, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG2EI16_V_M2_M1_MASK }, // 155
  { 0x2, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG2EI16_V_MF4_M1_MASK }, // 156
  { 0x2, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG2EI16_V_MF2_M1_MASK }, // 157
  { 0x2, 0x1, 0x0, 0x4, 0x1, 0x0, PseudoVLUXSEG2EI16_V_M1_M2_MASK }, // 158
  { 0x2, 0x1, 0x0, 0x4, 0x1, 0x1, PseudoVLUXSEG2EI16_V_M2_M2_MASK }, // 159
  { 0x2, 0x1, 0x0, 0x4, 0x1, 0x2, PseudoVLUXSEG2EI16_V_M4_M2_MASK }, // 160
  { 0x2, 0x1, 0x0, 0x4, 0x1, 0x7, PseudoVLUXSEG2EI16_V_MF2_M2_MASK }, // 161
  { 0x2, 0x1, 0x0, 0x4, 0x2, 0x0, PseudoVLUXSEG2EI16_V_M1_M4_MASK }, // 162
  { 0x2, 0x1, 0x0, 0x4, 0x2, 0x1, PseudoVLUXSEG2EI16_V_M2_M4_MASK }, // 163
  { 0x2, 0x1, 0x0, 0x4, 0x2, 0x2, PseudoVLUXSEG2EI16_V_M4_M4_MASK }, // 164
  { 0x2, 0x1, 0x0, 0x4, 0x2, 0x3, PseudoVLUXSEG2EI16_V_M8_M4_MASK }, // 165
  { 0x2, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG2EI16_V_MF4_MF8_MASK }, // 166
  { 0x2, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG2EI16_V_MF4_MF4_MASK }, // 167
  { 0x2, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG2EI16_V_MF2_MF4_MASK }, // 168
  { 0x2, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG2EI16_V_M1_MF2_MASK }, // 169
  { 0x2, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG2EI16_V_MF4_MF2_MASK }, // 170
  { 0x2, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG2EI16_V_MF2_MF2_MASK }, // 171
  { 0x2, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG2EI32_V_M1_M1_MASK }, // 172
  { 0x2, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG2EI32_V_M2_M1_MASK }, // 173
  { 0x2, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG2EI32_V_M4_M1_MASK }, // 174
  { 0x2, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG2EI32_V_MF2_M1_MASK }, // 175
  { 0x2, 0x1, 0x0, 0x5, 0x1, 0x0, PseudoVLUXSEG2EI32_V_M1_M2_MASK }, // 176
  { 0x2, 0x1, 0x0, 0x5, 0x1, 0x1, PseudoVLUXSEG2EI32_V_M2_M2_MASK }, // 177
  { 0x2, 0x1, 0x0, 0x5, 0x1, 0x2, PseudoVLUXSEG2EI32_V_M4_M2_MASK }, // 178
  { 0x2, 0x1, 0x0, 0x5, 0x1, 0x3, PseudoVLUXSEG2EI32_V_M8_M2_MASK }, // 179
  { 0x2, 0x1, 0x0, 0x5, 0x2, 0x1, PseudoVLUXSEG2EI32_V_M2_M4_MASK }, // 180
  { 0x2, 0x1, 0x0, 0x5, 0x2, 0x2, PseudoVLUXSEG2EI32_V_M4_M4_MASK }, // 181
  { 0x2, 0x1, 0x0, 0x5, 0x2, 0x3, PseudoVLUXSEG2EI32_V_M8_M4_MASK }, // 182
  { 0x2, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG2EI32_V_MF2_MF8_MASK }, // 183
  { 0x2, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG2EI32_V_M1_MF4_MASK }, // 184
  { 0x2, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG2EI32_V_MF2_MF4_MASK }, // 185
  { 0x2, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG2EI32_V_M1_MF2_MASK }, // 186
  { 0x2, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG2EI32_V_M2_MF2_MASK }, // 187
  { 0x2, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG2EI32_V_MF2_MF2_MASK }, // 188
  { 0x2, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG2EI64_V_M1_M1_MASK }, // 189
  { 0x2, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG2EI64_V_M2_M1_MASK }, // 190
  { 0x2, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG2EI64_V_M4_M1_MASK }, // 191
  { 0x2, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG2EI64_V_M8_M1_MASK }, // 192
  { 0x2, 0x1, 0x0, 0x6, 0x1, 0x1, PseudoVLUXSEG2EI64_V_M2_M2_MASK }, // 193
  { 0x2, 0x1, 0x0, 0x6, 0x1, 0x2, PseudoVLUXSEG2EI64_V_M4_M2_MASK }, // 194
  { 0x2, 0x1, 0x0, 0x6, 0x1, 0x3, PseudoVLUXSEG2EI64_V_M8_M2_MASK }, // 195
  { 0x2, 0x1, 0x0, 0x6, 0x2, 0x2, PseudoVLUXSEG2EI64_V_M4_M4_MASK }, // 196
  { 0x2, 0x1, 0x0, 0x6, 0x2, 0x3, PseudoVLUXSEG2EI64_V_M8_M4_MASK }, // 197
  { 0x2, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG2EI64_V_M1_MF8_MASK }, // 198
  { 0x2, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG2EI64_V_M1_MF4_MASK }, // 199
  { 0x2, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG2EI64_V_M2_MF4_MASK }, // 200
  { 0x2, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG2EI64_V_M1_MF2_MASK }, // 201
  { 0x2, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG2EI64_V_M2_MF2_MASK }, // 202
  { 0x2, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG2EI64_V_M4_MF2_MASK }, // 203
  { 0x2, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG2EI8_V_M1_M1_MASK }, // 204
  { 0x2, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG2EI8_V_MF8_M1_MASK }, // 205
  { 0x2, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG2EI8_V_MF4_M1_MASK }, // 206
  { 0x2, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG2EI8_V_MF2_M1_MASK }, // 207
  { 0x2, 0x1, 0x1, 0x3, 0x1, 0x0, PseudoVLOXSEG2EI8_V_M1_M2_MASK }, // 208
  { 0x2, 0x1, 0x1, 0x3, 0x1, 0x1, PseudoVLOXSEG2EI8_V_M2_M2_MASK }, // 209
  { 0x2, 0x1, 0x1, 0x3, 0x1, 0x6, PseudoVLOXSEG2EI8_V_MF4_M2_MASK }, // 210
  { 0x2, 0x1, 0x1, 0x3, 0x1, 0x7, PseudoVLOXSEG2EI8_V_MF2_M2_MASK }, // 211
  { 0x2, 0x1, 0x1, 0x3, 0x2, 0x0, PseudoVLOXSEG2EI8_V_M1_M4_MASK }, // 212
  { 0x2, 0x1, 0x1, 0x3, 0x2, 0x1, PseudoVLOXSEG2EI8_V_M2_M4_MASK }, // 213
  { 0x2, 0x1, 0x1, 0x3, 0x2, 0x2, PseudoVLOXSEG2EI8_V_M4_M4_MASK }, // 214
  { 0x2, 0x1, 0x1, 0x3, 0x2, 0x7, PseudoVLOXSEG2EI8_V_MF2_M4_MASK }, // 215
  { 0x2, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG2EI8_V_MF8_MF8_MASK }, // 216
  { 0x2, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG2EI8_V_MF8_MF4_MASK }, // 217
  { 0x2, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG2EI8_V_MF4_MF4_MASK }, // 218
  { 0x2, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG2EI8_V_MF8_MF2_MASK }, // 219
  { 0x2, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG2EI8_V_MF4_MF2_MASK }, // 220
  { 0x2, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG2EI8_V_MF2_MF2_MASK }, // 221
  { 0x2, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG2EI16_V_M1_M1_MASK }, // 222
  { 0x2, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG2EI16_V_M2_M1_MASK }, // 223
  { 0x2, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG2EI16_V_MF4_M1_MASK }, // 224
  { 0x2, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG2EI16_V_MF2_M1_MASK }, // 225
  { 0x2, 0x1, 0x1, 0x4, 0x1, 0x0, PseudoVLOXSEG2EI16_V_M1_M2_MASK }, // 226
  { 0x2, 0x1, 0x1, 0x4, 0x1, 0x1, PseudoVLOXSEG2EI16_V_M2_M2_MASK }, // 227
  { 0x2, 0x1, 0x1, 0x4, 0x1, 0x2, PseudoVLOXSEG2EI16_V_M4_M2_MASK }, // 228
  { 0x2, 0x1, 0x1, 0x4, 0x1, 0x7, PseudoVLOXSEG2EI16_V_MF2_M2_MASK }, // 229
  { 0x2, 0x1, 0x1, 0x4, 0x2, 0x0, PseudoVLOXSEG2EI16_V_M1_M4_MASK }, // 230
  { 0x2, 0x1, 0x1, 0x4, 0x2, 0x1, PseudoVLOXSEG2EI16_V_M2_M4_MASK }, // 231
  { 0x2, 0x1, 0x1, 0x4, 0x2, 0x2, PseudoVLOXSEG2EI16_V_M4_M4_MASK }, // 232
  { 0x2, 0x1, 0x1, 0x4, 0x2, 0x3, PseudoVLOXSEG2EI16_V_M8_M4_MASK }, // 233
  { 0x2, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG2EI16_V_MF4_MF8_MASK }, // 234
  { 0x2, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG2EI16_V_MF4_MF4_MASK }, // 235
  { 0x2, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG2EI16_V_MF2_MF4_MASK }, // 236
  { 0x2, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG2EI16_V_M1_MF2_MASK }, // 237
  { 0x2, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG2EI16_V_MF4_MF2_MASK }, // 238
  { 0x2, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG2EI16_V_MF2_MF2_MASK }, // 239
  { 0x2, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG2EI32_V_M1_M1_MASK }, // 240
  { 0x2, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG2EI32_V_M2_M1_MASK }, // 241
  { 0x2, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG2EI32_V_M4_M1_MASK }, // 242
  { 0x2, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG2EI32_V_MF2_M1_MASK }, // 243
  { 0x2, 0x1, 0x1, 0x5, 0x1, 0x0, PseudoVLOXSEG2EI32_V_M1_M2_MASK }, // 244
  { 0x2, 0x1, 0x1, 0x5, 0x1, 0x1, PseudoVLOXSEG2EI32_V_M2_M2_MASK }, // 245
  { 0x2, 0x1, 0x1, 0x5, 0x1, 0x2, PseudoVLOXSEG2EI32_V_M4_M2_MASK }, // 246
  { 0x2, 0x1, 0x1, 0x5, 0x1, 0x3, PseudoVLOXSEG2EI32_V_M8_M2_MASK }, // 247
  { 0x2, 0x1, 0x1, 0x5, 0x2, 0x1, PseudoVLOXSEG2EI32_V_M2_M4_MASK }, // 248
  { 0x2, 0x1, 0x1, 0x5, 0x2, 0x2, PseudoVLOXSEG2EI32_V_M4_M4_MASK }, // 249
  { 0x2, 0x1, 0x1, 0x5, 0x2, 0x3, PseudoVLOXSEG2EI32_V_M8_M4_MASK }, // 250
  { 0x2, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG2EI32_V_MF2_MF8_MASK }, // 251
  { 0x2, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG2EI32_V_M1_MF4_MASK }, // 252
  { 0x2, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG2EI32_V_MF2_MF4_MASK }, // 253
  { 0x2, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG2EI32_V_M1_MF2_MASK }, // 254
  { 0x2, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG2EI32_V_M2_MF2_MASK }, // 255
  { 0x2, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG2EI32_V_MF2_MF2_MASK }, // 256
  { 0x2, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG2EI64_V_M1_M1_MASK }, // 257
  { 0x2, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG2EI64_V_M2_M1_MASK }, // 258
  { 0x2, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG2EI64_V_M4_M1_MASK }, // 259
  { 0x2, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG2EI64_V_M8_M1_MASK }, // 260
  { 0x2, 0x1, 0x1, 0x6, 0x1, 0x1, PseudoVLOXSEG2EI64_V_M2_M2_MASK }, // 261
  { 0x2, 0x1, 0x1, 0x6, 0x1, 0x2, PseudoVLOXSEG2EI64_V_M4_M2_MASK }, // 262
  { 0x2, 0x1, 0x1, 0x6, 0x1, 0x3, PseudoVLOXSEG2EI64_V_M8_M2_MASK }, // 263
  { 0x2, 0x1, 0x1, 0x6, 0x2, 0x2, PseudoVLOXSEG2EI64_V_M4_M4_MASK }, // 264
  { 0x2, 0x1, 0x1, 0x6, 0x2, 0x3, PseudoVLOXSEG2EI64_V_M8_M4_MASK }, // 265
  { 0x2, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG2EI64_V_M1_MF8_MASK }, // 266
  { 0x2, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG2EI64_V_M1_MF4_MASK }, // 267
  { 0x2, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG2EI64_V_M2_MF4_MASK }, // 268
  { 0x2, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG2EI64_V_M1_MF2_MASK }, // 269
  { 0x2, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG2EI64_V_M2_MF2_MASK }, // 270
  { 0x2, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG2EI64_V_M4_MF2_MASK }, // 271
  { 0x3, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG3EI8_V_M1_M1 }, // 272
  { 0x3, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG3EI8_V_MF8_M1 }, // 273
  { 0x3, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG3EI8_V_MF4_M1 }, // 274
  { 0x3, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG3EI8_V_MF2_M1 }, // 275
  { 0x3, 0x0, 0x0, 0x3, 0x1, 0x0, PseudoVLUXSEG3EI8_V_M1_M2 }, // 276
  { 0x3, 0x0, 0x0, 0x3, 0x1, 0x1, PseudoVLUXSEG3EI8_V_M2_M2 }, // 277
  { 0x3, 0x0, 0x0, 0x3, 0x1, 0x6, PseudoVLUXSEG3EI8_V_MF4_M2 }, // 278
  { 0x3, 0x0, 0x0, 0x3, 0x1, 0x7, PseudoVLUXSEG3EI8_V_MF2_M2 }, // 279
  { 0x3, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG3EI8_V_MF8_MF8 }, // 280
  { 0x3, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG3EI8_V_MF8_MF4 }, // 281
  { 0x3, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG3EI8_V_MF4_MF4 }, // 282
  { 0x3, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG3EI8_V_MF8_MF2 }, // 283
  { 0x3, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG3EI8_V_MF4_MF2 }, // 284
  { 0x3, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG3EI8_V_MF2_MF2 }, // 285
  { 0x3, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG3EI16_V_M1_M1 }, // 286
  { 0x3, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG3EI16_V_M2_M1 }, // 287
  { 0x3, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG3EI16_V_MF4_M1 }, // 288
  { 0x3, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG3EI16_V_MF2_M1 }, // 289
  { 0x3, 0x0, 0x0, 0x4, 0x1, 0x0, PseudoVLUXSEG3EI16_V_M1_M2 }, // 290
  { 0x3, 0x0, 0x0, 0x4, 0x1, 0x1, PseudoVLUXSEG3EI16_V_M2_M2 }, // 291
  { 0x3, 0x0, 0x0, 0x4, 0x1, 0x2, PseudoVLUXSEG3EI16_V_M4_M2 }, // 292
  { 0x3, 0x0, 0x0, 0x4, 0x1, 0x7, PseudoVLUXSEG3EI16_V_MF2_M2 }, // 293
  { 0x3, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG3EI16_V_MF4_MF8 }, // 294
  { 0x3, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG3EI16_V_MF4_MF4 }, // 295
  { 0x3, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG3EI16_V_MF2_MF4 }, // 296
  { 0x3, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG3EI16_V_M1_MF2 }, // 297
  { 0x3, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG3EI16_V_MF4_MF2 }, // 298
  { 0x3, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG3EI16_V_MF2_MF2 }, // 299
  { 0x3, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG3EI32_V_M1_M1 }, // 300
  { 0x3, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG3EI32_V_M2_M1 }, // 301
  { 0x3, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG3EI32_V_M4_M1 }, // 302
  { 0x3, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG3EI32_V_MF2_M1 }, // 303
  { 0x3, 0x0, 0x0, 0x5, 0x1, 0x0, PseudoVLUXSEG3EI32_V_M1_M2 }, // 304
  { 0x3, 0x0, 0x0, 0x5, 0x1, 0x1, PseudoVLUXSEG3EI32_V_M2_M2 }, // 305
  { 0x3, 0x0, 0x0, 0x5, 0x1, 0x2, PseudoVLUXSEG3EI32_V_M4_M2 }, // 306
  { 0x3, 0x0, 0x0, 0x5, 0x1, 0x3, PseudoVLUXSEG3EI32_V_M8_M2 }, // 307
  { 0x3, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG3EI32_V_MF2_MF8 }, // 308
  { 0x3, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG3EI32_V_M1_MF4 }, // 309
  { 0x3, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG3EI32_V_MF2_MF4 }, // 310
  { 0x3, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG3EI32_V_M1_MF2 }, // 311
  { 0x3, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG3EI32_V_M2_MF2 }, // 312
  { 0x3, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG3EI32_V_MF2_MF2 }, // 313
  { 0x3, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG3EI64_V_M1_M1 }, // 314
  { 0x3, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG3EI64_V_M2_M1 }, // 315
  { 0x3, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG3EI64_V_M4_M1 }, // 316
  { 0x3, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG3EI64_V_M8_M1 }, // 317
  { 0x3, 0x0, 0x0, 0x6, 0x1, 0x1, PseudoVLUXSEG3EI64_V_M2_M2 }, // 318
  { 0x3, 0x0, 0x0, 0x6, 0x1, 0x2, PseudoVLUXSEG3EI64_V_M4_M2 }, // 319
  { 0x3, 0x0, 0x0, 0x6, 0x1, 0x3, PseudoVLUXSEG3EI64_V_M8_M2 }, // 320
  { 0x3, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG3EI64_V_M1_MF8 }, // 321
  { 0x3, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG3EI64_V_M1_MF4 }, // 322
  { 0x3, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG3EI64_V_M2_MF4 }, // 323
  { 0x3, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG3EI64_V_M1_MF2 }, // 324
  { 0x3, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG3EI64_V_M2_MF2 }, // 325
  { 0x3, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG3EI64_V_M4_MF2 }, // 326
  { 0x3, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG3EI8_V_M1_M1 }, // 327
  { 0x3, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG3EI8_V_MF8_M1 }, // 328
  { 0x3, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG3EI8_V_MF4_M1 }, // 329
  { 0x3, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG3EI8_V_MF2_M1 }, // 330
  { 0x3, 0x0, 0x1, 0x3, 0x1, 0x0, PseudoVLOXSEG3EI8_V_M1_M2 }, // 331
  { 0x3, 0x0, 0x1, 0x3, 0x1, 0x1, PseudoVLOXSEG3EI8_V_M2_M2 }, // 332
  { 0x3, 0x0, 0x1, 0x3, 0x1, 0x6, PseudoVLOXSEG3EI8_V_MF4_M2 }, // 333
  { 0x3, 0x0, 0x1, 0x3, 0x1, 0x7, PseudoVLOXSEG3EI8_V_MF2_M2 }, // 334
  { 0x3, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG3EI8_V_MF8_MF8 }, // 335
  { 0x3, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG3EI8_V_MF8_MF4 }, // 336
  { 0x3, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG3EI8_V_MF4_MF4 }, // 337
  { 0x3, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG3EI8_V_MF8_MF2 }, // 338
  { 0x3, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG3EI8_V_MF4_MF2 }, // 339
  { 0x3, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG3EI8_V_MF2_MF2 }, // 340
  { 0x3, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG3EI16_V_M1_M1 }, // 341
  { 0x3, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG3EI16_V_M2_M1 }, // 342
  { 0x3, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG3EI16_V_MF4_M1 }, // 343
  { 0x3, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG3EI16_V_MF2_M1 }, // 344
  { 0x3, 0x0, 0x1, 0x4, 0x1, 0x0, PseudoVLOXSEG3EI16_V_M1_M2 }, // 345
  { 0x3, 0x0, 0x1, 0x4, 0x1, 0x1, PseudoVLOXSEG3EI16_V_M2_M2 }, // 346
  { 0x3, 0x0, 0x1, 0x4, 0x1, 0x2, PseudoVLOXSEG3EI16_V_M4_M2 }, // 347
  { 0x3, 0x0, 0x1, 0x4, 0x1, 0x7, PseudoVLOXSEG3EI16_V_MF2_M2 }, // 348
  { 0x3, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG3EI16_V_MF4_MF8 }, // 349
  { 0x3, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG3EI16_V_MF4_MF4 }, // 350
  { 0x3, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG3EI16_V_MF2_MF4 }, // 351
  { 0x3, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG3EI16_V_M1_MF2 }, // 352
  { 0x3, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG3EI16_V_MF4_MF2 }, // 353
  { 0x3, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG3EI16_V_MF2_MF2 }, // 354
  { 0x3, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG3EI32_V_M1_M1 }, // 355
  { 0x3, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG3EI32_V_M2_M1 }, // 356
  { 0x3, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG3EI32_V_M4_M1 }, // 357
  { 0x3, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG3EI32_V_MF2_M1 }, // 358
  { 0x3, 0x0, 0x1, 0x5, 0x1, 0x0, PseudoVLOXSEG3EI32_V_M1_M2 }, // 359
  { 0x3, 0x0, 0x1, 0x5, 0x1, 0x1, PseudoVLOXSEG3EI32_V_M2_M2 }, // 360
  { 0x3, 0x0, 0x1, 0x5, 0x1, 0x2, PseudoVLOXSEG3EI32_V_M4_M2 }, // 361
  { 0x3, 0x0, 0x1, 0x5, 0x1, 0x3, PseudoVLOXSEG3EI32_V_M8_M2 }, // 362
  { 0x3, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG3EI32_V_MF2_MF8 }, // 363
  { 0x3, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG3EI32_V_M1_MF4 }, // 364
  { 0x3, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG3EI32_V_MF2_MF4 }, // 365
  { 0x3, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG3EI32_V_M1_MF2 }, // 366
  { 0x3, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG3EI32_V_M2_MF2 }, // 367
  { 0x3, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG3EI32_V_MF2_MF2 }, // 368
  { 0x3, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG3EI64_V_M1_M1 }, // 369
  { 0x3, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG3EI64_V_M2_M1 }, // 370
  { 0x3, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG3EI64_V_M4_M1 }, // 371
  { 0x3, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG3EI64_V_M8_M1 }, // 372
  { 0x3, 0x0, 0x1, 0x6, 0x1, 0x1, PseudoVLOXSEG3EI64_V_M2_M2 }, // 373
  { 0x3, 0x0, 0x1, 0x6, 0x1, 0x2, PseudoVLOXSEG3EI64_V_M4_M2 }, // 374
  { 0x3, 0x0, 0x1, 0x6, 0x1, 0x3, PseudoVLOXSEG3EI64_V_M8_M2 }, // 375
  { 0x3, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG3EI64_V_M1_MF8 }, // 376
  { 0x3, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG3EI64_V_M1_MF4 }, // 377
  { 0x3, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG3EI64_V_M2_MF4 }, // 378
  { 0x3, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG3EI64_V_M1_MF2 }, // 379
  { 0x3, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG3EI64_V_M2_MF2 }, // 380
  { 0x3, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG3EI64_V_M4_MF2 }, // 381
  { 0x3, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG3EI8_V_M1_M1_MASK }, // 382
  { 0x3, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG3EI8_V_MF8_M1_MASK }, // 383
  { 0x3, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG3EI8_V_MF4_M1_MASK }, // 384
  { 0x3, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG3EI8_V_MF2_M1_MASK }, // 385
  { 0x3, 0x1, 0x0, 0x3, 0x1, 0x0, PseudoVLUXSEG3EI8_V_M1_M2_MASK }, // 386
  { 0x3, 0x1, 0x0, 0x3, 0x1, 0x1, PseudoVLUXSEG3EI8_V_M2_M2_MASK }, // 387
  { 0x3, 0x1, 0x0, 0x3, 0x1, 0x6, PseudoVLUXSEG3EI8_V_MF4_M2_MASK }, // 388
  { 0x3, 0x1, 0x0, 0x3, 0x1, 0x7, PseudoVLUXSEG3EI8_V_MF2_M2_MASK }, // 389
  { 0x3, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG3EI8_V_MF8_MF8_MASK }, // 390
  { 0x3, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG3EI8_V_MF8_MF4_MASK }, // 391
  { 0x3, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG3EI8_V_MF4_MF4_MASK }, // 392
  { 0x3, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG3EI8_V_MF8_MF2_MASK }, // 393
  { 0x3, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG3EI8_V_MF4_MF2_MASK }, // 394
  { 0x3, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG3EI8_V_MF2_MF2_MASK }, // 395
  { 0x3, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG3EI16_V_M1_M1_MASK }, // 396
  { 0x3, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG3EI16_V_M2_M1_MASK }, // 397
  { 0x3, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG3EI16_V_MF4_M1_MASK }, // 398
  { 0x3, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG3EI16_V_MF2_M1_MASK }, // 399
  { 0x3, 0x1, 0x0, 0x4, 0x1, 0x0, PseudoVLUXSEG3EI16_V_M1_M2_MASK }, // 400
  { 0x3, 0x1, 0x0, 0x4, 0x1, 0x1, PseudoVLUXSEG3EI16_V_M2_M2_MASK }, // 401
  { 0x3, 0x1, 0x0, 0x4, 0x1, 0x2, PseudoVLUXSEG3EI16_V_M4_M2_MASK }, // 402
  { 0x3, 0x1, 0x0, 0x4, 0x1, 0x7, PseudoVLUXSEG3EI16_V_MF2_M2_MASK }, // 403
  { 0x3, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG3EI16_V_MF4_MF8_MASK }, // 404
  { 0x3, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG3EI16_V_MF4_MF4_MASK }, // 405
  { 0x3, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG3EI16_V_MF2_MF4_MASK }, // 406
  { 0x3, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG3EI16_V_M1_MF2_MASK }, // 407
  { 0x3, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG3EI16_V_MF4_MF2_MASK }, // 408
  { 0x3, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG3EI16_V_MF2_MF2_MASK }, // 409
  { 0x3, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG3EI32_V_M1_M1_MASK }, // 410
  { 0x3, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG3EI32_V_M2_M1_MASK }, // 411
  { 0x3, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG3EI32_V_M4_M1_MASK }, // 412
  { 0x3, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG3EI32_V_MF2_M1_MASK }, // 413
  { 0x3, 0x1, 0x0, 0x5, 0x1, 0x0, PseudoVLUXSEG3EI32_V_M1_M2_MASK }, // 414
  { 0x3, 0x1, 0x0, 0x5, 0x1, 0x1, PseudoVLUXSEG3EI32_V_M2_M2_MASK }, // 415
  { 0x3, 0x1, 0x0, 0x5, 0x1, 0x2, PseudoVLUXSEG3EI32_V_M4_M2_MASK }, // 416
  { 0x3, 0x1, 0x0, 0x5, 0x1, 0x3, PseudoVLUXSEG3EI32_V_M8_M2_MASK }, // 417
  { 0x3, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG3EI32_V_MF2_MF8_MASK }, // 418
  { 0x3, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG3EI32_V_M1_MF4_MASK }, // 419
  { 0x3, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG3EI32_V_MF2_MF4_MASK }, // 420
  { 0x3, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG3EI32_V_M1_MF2_MASK }, // 421
  { 0x3, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG3EI32_V_M2_MF2_MASK }, // 422
  { 0x3, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG3EI32_V_MF2_MF2_MASK }, // 423
  { 0x3, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG3EI64_V_M1_M1_MASK }, // 424
  { 0x3, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG3EI64_V_M2_M1_MASK }, // 425
  { 0x3, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG3EI64_V_M4_M1_MASK }, // 426
  { 0x3, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG3EI64_V_M8_M1_MASK }, // 427
  { 0x3, 0x1, 0x0, 0x6, 0x1, 0x1, PseudoVLUXSEG3EI64_V_M2_M2_MASK }, // 428
  { 0x3, 0x1, 0x0, 0x6, 0x1, 0x2, PseudoVLUXSEG3EI64_V_M4_M2_MASK }, // 429
  { 0x3, 0x1, 0x0, 0x6, 0x1, 0x3, PseudoVLUXSEG3EI64_V_M8_M2_MASK }, // 430
  { 0x3, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG3EI64_V_M1_MF8_MASK }, // 431
  { 0x3, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG3EI64_V_M1_MF4_MASK }, // 432
  { 0x3, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG3EI64_V_M2_MF4_MASK }, // 433
  { 0x3, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG3EI64_V_M1_MF2_MASK }, // 434
  { 0x3, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG3EI64_V_M2_MF2_MASK }, // 435
  { 0x3, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG3EI64_V_M4_MF2_MASK }, // 436
  { 0x3, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG3EI8_V_M1_M1_MASK }, // 437
  { 0x3, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG3EI8_V_MF8_M1_MASK }, // 438
  { 0x3, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG3EI8_V_MF4_M1_MASK }, // 439
  { 0x3, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG3EI8_V_MF2_M1_MASK }, // 440
  { 0x3, 0x1, 0x1, 0x3, 0x1, 0x0, PseudoVLOXSEG3EI8_V_M1_M2_MASK }, // 441
  { 0x3, 0x1, 0x1, 0x3, 0x1, 0x1, PseudoVLOXSEG3EI8_V_M2_M2_MASK }, // 442
  { 0x3, 0x1, 0x1, 0x3, 0x1, 0x6, PseudoVLOXSEG3EI8_V_MF4_M2_MASK }, // 443
  { 0x3, 0x1, 0x1, 0x3, 0x1, 0x7, PseudoVLOXSEG3EI8_V_MF2_M2_MASK }, // 444
  { 0x3, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG3EI8_V_MF8_MF8_MASK }, // 445
  { 0x3, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG3EI8_V_MF8_MF4_MASK }, // 446
  { 0x3, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG3EI8_V_MF4_MF4_MASK }, // 447
  { 0x3, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG3EI8_V_MF8_MF2_MASK }, // 448
  { 0x3, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG3EI8_V_MF4_MF2_MASK }, // 449
  { 0x3, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG3EI8_V_MF2_MF2_MASK }, // 450
  { 0x3, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG3EI16_V_M1_M1_MASK }, // 451
  { 0x3, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG3EI16_V_M2_M1_MASK }, // 452
  { 0x3, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG3EI16_V_MF4_M1_MASK }, // 453
  { 0x3, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG3EI16_V_MF2_M1_MASK }, // 454
  { 0x3, 0x1, 0x1, 0x4, 0x1, 0x0, PseudoVLOXSEG3EI16_V_M1_M2_MASK }, // 455
  { 0x3, 0x1, 0x1, 0x4, 0x1, 0x1, PseudoVLOXSEG3EI16_V_M2_M2_MASK }, // 456
  { 0x3, 0x1, 0x1, 0x4, 0x1, 0x2, PseudoVLOXSEG3EI16_V_M4_M2_MASK }, // 457
  { 0x3, 0x1, 0x1, 0x4, 0x1, 0x7, PseudoVLOXSEG3EI16_V_MF2_M2_MASK }, // 458
  { 0x3, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG3EI16_V_MF4_MF8_MASK }, // 459
  { 0x3, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG3EI16_V_MF4_MF4_MASK }, // 460
  { 0x3, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG3EI16_V_MF2_MF4_MASK }, // 461
  { 0x3, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG3EI16_V_M1_MF2_MASK }, // 462
  { 0x3, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG3EI16_V_MF4_MF2_MASK }, // 463
  { 0x3, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG3EI16_V_MF2_MF2_MASK }, // 464
  { 0x3, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG3EI32_V_M1_M1_MASK }, // 465
  { 0x3, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG3EI32_V_M2_M1_MASK }, // 466
  { 0x3, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG3EI32_V_M4_M1_MASK }, // 467
  { 0x3, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG3EI32_V_MF2_M1_MASK }, // 468
  { 0x3, 0x1, 0x1, 0x5, 0x1, 0x0, PseudoVLOXSEG3EI32_V_M1_M2_MASK }, // 469
  { 0x3, 0x1, 0x1, 0x5, 0x1, 0x1, PseudoVLOXSEG3EI32_V_M2_M2_MASK }, // 470
  { 0x3, 0x1, 0x1, 0x5, 0x1, 0x2, PseudoVLOXSEG3EI32_V_M4_M2_MASK }, // 471
  { 0x3, 0x1, 0x1, 0x5, 0x1, 0x3, PseudoVLOXSEG3EI32_V_M8_M2_MASK }, // 472
  { 0x3, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG3EI32_V_MF2_MF8_MASK }, // 473
  { 0x3, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG3EI32_V_M1_MF4_MASK }, // 474
  { 0x3, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG3EI32_V_MF2_MF4_MASK }, // 475
  { 0x3, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG3EI32_V_M1_MF2_MASK }, // 476
  { 0x3, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG3EI32_V_M2_MF2_MASK }, // 477
  { 0x3, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG3EI32_V_MF2_MF2_MASK }, // 478
  { 0x3, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG3EI64_V_M1_M1_MASK }, // 479
  { 0x3, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG3EI64_V_M2_M1_MASK }, // 480
  { 0x3, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG3EI64_V_M4_M1_MASK }, // 481
  { 0x3, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG3EI64_V_M8_M1_MASK }, // 482
  { 0x3, 0x1, 0x1, 0x6, 0x1, 0x1, PseudoVLOXSEG3EI64_V_M2_M2_MASK }, // 483
  { 0x3, 0x1, 0x1, 0x6, 0x1, 0x2, PseudoVLOXSEG3EI64_V_M4_M2_MASK }, // 484
  { 0x3, 0x1, 0x1, 0x6, 0x1, 0x3, PseudoVLOXSEG3EI64_V_M8_M2_MASK }, // 485
  { 0x3, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG3EI64_V_M1_MF8_MASK }, // 486
  { 0x3, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG3EI64_V_M1_MF4_MASK }, // 487
  { 0x3, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG3EI64_V_M2_MF4_MASK }, // 488
  { 0x3, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG3EI64_V_M1_MF2_MASK }, // 489
  { 0x3, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG3EI64_V_M2_MF2_MASK }, // 490
  { 0x3, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG3EI64_V_M4_MF2_MASK }, // 491
  { 0x4, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG4EI8_V_M1_M1 }, // 492
  { 0x4, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG4EI8_V_MF8_M1 }, // 493
  { 0x4, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG4EI8_V_MF4_M1 }, // 494
  { 0x4, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG4EI8_V_MF2_M1 }, // 495
  { 0x4, 0x0, 0x0, 0x3, 0x1, 0x0, PseudoVLUXSEG4EI8_V_M1_M2 }, // 496
  { 0x4, 0x0, 0x0, 0x3, 0x1, 0x1, PseudoVLUXSEG4EI8_V_M2_M2 }, // 497
  { 0x4, 0x0, 0x0, 0x3, 0x1, 0x6, PseudoVLUXSEG4EI8_V_MF4_M2 }, // 498
  { 0x4, 0x0, 0x0, 0x3, 0x1, 0x7, PseudoVLUXSEG4EI8_V_MF2_M2 }, // 499
  { 0x4, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG4EI8_V_MF8_MF8 }, // 500
  { 0x4, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG4EI8_V_MF8_MF4 }, // 501
  { 0x4, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG4EI8_V_MF4_MF4 }, // 502
  { 0x4, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG4EI8_V_MF8_MF2 }, // 503
  { 0x4, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG4EI8_V_MF4_MF2 }, // 504
  { 0x4, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG4EI8_V_MF2_MF2 }, // 505
  { 0x4, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG4EI16_V_M1_M1 }, // 506
  { 0x4, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG4EI16_V_M2_M1 }, // 507
  { 0x4, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG4EI16_V_MF4_M1 }, // 508
  { 0x4, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG4EI16_V_MF2_M1 }, // 509
  { 0x4, 0x0, 0x0, 0x4, 0x1, 0x0, PseudoVLUXSEG4EI16_V_M1_M2 }, // 510
  { 0x4, 0x0, 0x0, 0x4, 0x1, 0x1, PseudoVLUXSEG4EI16_V_M2_M2 }, // 511
  { 0x4, 0x0, 0x0, 0x4, 0x1, 0x2, PseudoVLUXSEG4EI16_V_M4_M2 }, // 512
  { 0x4, 0x0, 0x0, 0x4, 0x1, 0x7, PseudoVLUXSEG4EI16_V_MF2_M2 }, // 513
  { 0x4, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG4EI16_V_MF4_MF8 }, // 514
  { 0x4, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG4EI16_V_MF4_MF4 }, // 515
  { 0x4, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG4EI16_V_MF2_MF4 }, // 516
  { 0x4, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG4EI16_V_M1_MF2 }, // 517
  { 0x4, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG4EI16_V_MF4_MF2 }, // 518
  { 0x4, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG4EI16_V_MF2_MF2 }, // 519
  { 0x4, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG4EI32_V_M1_M1 }, // 520
  { 0x4, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG4EI32_V_M2_M1 }, // 521
  { 0x4, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG4EI32_V_M4_M1 }, // 522
  { 0x4, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG4EI32_V_MF2_M1 }, // 523
  { 0x4, 0x0, 0x0, 0x5, 0x1, 0x0, PseudoVLUXSEG4EI32_V_M1_M2 }, // 524
  { 0x4, 0x0, 0x0, 0x5, 0x1, 0x1, PseudoVLUXSEG4EI32_V_M2_M2 }, // 525
  { 0x4, 0x0, 0x0, 0x5, 0x1, 0x2, PseudoVLUXSEG4EI32_V_M4_M2 }, // 526
  { 0x4, 0x0, 0x0, 0x5, 0x1, 0x3, PseudoVLUXSEG4EI32_V_M8_M2 }, // 527
  { 0x4, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG4EI32_V_MF2_MF8 }, // 528
  { 0x4, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG4EI32_V_M1_MF4 }, // 529
  { 0x4, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG4EI32_V_MF2_MF4 }, // 530
  { 0x4, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG4EI32_V_M1_MF2 }, // 531
  { 0x4, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG4EI32_V_M2_MF2 }, // 532
  { 0x4, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG4EI32_V_MF2_MF2 }, // 533
  { 0x4, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG4EI64_V_M1_M1 }, // 534
  { 0x4, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG4EI64_V_M2_M1 }, // 535
  { 0x4, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG4EI64_V_M4_M1 }, // 536
  { 0x4, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG4EI64_V_M8_M1 }, // 537
  { 0x4, 0x0, 0x0, 0x6, 0x1, 0x1, PseudoVLUXSEG4EI64_V_M2_M2 }, // 538
  { 0x4, 0x0, 0x0, 0x6, 0x1, 0x2, PseudoVLUXSEG4EI64_V_M4_M2 }, // 539
  { 0x4, 0x0, 0x0, 0x6, 0x1, 0x3, PseudoVLUXSEG4EI64_V_M8_M2 }, // 540
  { 0x4, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG4EI64_V_M1_MF8 }, // 541
  { 0x4, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG4EI64_V_M1_MF4 }, // 542
  { 0x4, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG4EI64_V_M2_MF4 }, // 543
  { 0x4, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG4EI64_V_M1_MF2 }, // 544
  { 0x4, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG4EI64_V_M2_MF2 }, // 545
  { 0x4, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG4EI64_V_M4_MF2 }, // 546
  { 0x4, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG4EI8_V_M1_M1 }, // 547
  { 0x4, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG4EI8_V_MF8_M1 }, // 548
  { 0x4, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG4EI8_V_MF4_M1 }, // 549
  { 0x4, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG4EI8_V_MF2_M1 }, // 550
  { 0x4, 0x0, 0x1, 0x3, 0x1, 0x0, PseudoVLOXSEG4EI8_V_M1_M2 }, // 551
  { 0x4, 0x0, 0x1, 0x3, 0x1, 0x1, PseudoVLOXSEG4EI8_V_M2_M2 }, // 552
  { 0x4, 0x0, 0x1, 0x3, 0x1, 0x6, PseudoVLOXSEG4EI8_V_MF4_M2 }, // 553
  { 0x4, 0x0, 0x1, 0x3, 0x1, 0x7, PseudoVLOXSEG4EI8_V_MF2_M2 }, // 554
  { 0x4, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG4EI8_V_MF8_MF8 }, // 555
  { 0x4, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG4EI8_V_MF8_MF4 }, // 556
  { 0x4, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG4EI8_V_MF4_MF4 }, // 557
  { 0x4, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG4EI8_V_MF8_MF2 }, // 558
  { 0x4, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG4EI8_V_MF4_MF2 }, // 559
  { 0x4, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG4EI8_V_MF2_MF2 }, // 560
  { 0x4, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG4EI16_V_M1_M1 }, // 561
  { 0x4, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG4EI16_V_M2_M1 }, // 562
  { 0x4, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG4EI16_V_MF4_M1 }, // 563
  { 0x4, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG4EI16_V_MF2_M1 }, // 564
  { 0x4, 0x0, 0x1, 0x4, 0x1, 0x0, PseudoVLOXSEG4EI16_V_M1_M2 }, // 565
  { 0x4, 0x0, 0x1, 0x4, 0x1, 0x1, PseudoVLOXSEG4EI16_V_M2_M2 }, // 566
  { 0x4, 0x0, 0x1, 0x4, 0x1, 0x2, PseudoVLOXSEG4EI16_V_M4_M2 }, // 567
  { 0x4, 0x0, 0x1, 0x4, 0x1, 0x7, PseudoVLOXSEG4EI16_V_MF2_M2 }, // 568
  { 0x4, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG4EI16_V_MF4_MF8 }, // 569
  { 0x4, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG4EI16_V_MF4_MF4 }, // 570
  { 0x4, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG4EI16_V_MF2_MF4 }, // 571
  { 0x4, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG4EI16_V_M1_MF2 }, // 572
  { 0x4, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG4EI16_V_MF4_MF2 }, // 573
  { 0x4, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG4EI16_V_MF2_MF2 }, // 574
  { 0x4, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG4EI32_V_M1_M1 }, // 575
  { 0x4, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG4EI32_V_M2_M1 }, // 576
  { 0x4, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG4EI32_V_M4_M1 }, // 577
  { 0x4, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG4EI32_V_MF2_M1 }, // 578
  { 0x4, 0x0, 0x1, 0x5, 0x1, 0x0, PseudoVLOXSEG4EI32_V_M1_M2 }, // 579
  { 0x4, 0x0, 0x1, 0x5, 0x1, 0x1, PseudoVLOXSEG4EI32_V_M2_M2 }, // 580
  { 0x4, 0x0, 0x1, 0x5, 0x1, 0x2, PseudoVLOXSEG4EI32_V_M4_M2 }, // 581
  { 0x4, 0x0, 0x1, 0x5, 0x1, 0x3, PseudoVLOXSEG4EI32_V_M8_M2 }, // 582
  { 0x4, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG4EI32_V_MF2_MF8 }, // 583
  { 0x4, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG4EI32_V_M1_MF4 }, // 584
  { 0x4, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG4EI32_V_MF2_MF4 }, // 585
  { 0x4, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG4EI32_V_M1_MF2 }, // 586
  { 0x4, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG4EI32_V_M2_MF2 }, // 587
  { 0x4, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG4EI32_V_MF2_MF2 }, // 588
  { 0x4, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG4EI64_V_M1_M1 }, // 589
  { 0x4, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG4EI64_V_M2_M1 }, // 590
  { 0x4, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG4EI64_V_M4_M1 }, // 591
  { 0x4, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG4EI64_V_M8_M1 }, // 592
  { 0x4, 0x0, 0x1, 0x6, 0x1, 0x1, PseudoVLOXSEG4EI64_V_M2_M2 }, // 593
  { 0x4, 0x0, 0x1, 0x6, 0x1, 0x2, PseudoVLOXSEG4EI64_V_M4_M2 }, // 594
  { 0x4, 0x0, 0x1, 0x6, 0x1, 0x3, PseudoVLOXSEG4EI64_V_M8_M2 }, // 595
  { 0x4, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG4EI64_V_M1_MF8 }, // 596
  { 0x4, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG4EI64_V_M1_MF4 }, // 597
  { 0x4, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG4EI64_V_M2_MF4 }, // 598
  { 0x4, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG4EI64_V_M1_MF2 }, // 599
  { 0x4, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG4EI64_V_M2_MF2 }, // 600
  { 0x4, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG4EI64_V_M4_MF2 }, // 601
  { 0x4, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG4EI8_V_M1_M1_MASK }, // 602
  { 0x4, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG4EI8_V_MF8_M1_MASK }, // 603
  { 0x4, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG4EI8_V_MF4_M1_MASK }, // 604
  { 0x4, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG4EI8_V_MF2_M1_MASK }, // 605
  { 0x4, 0x1, 0x0, 0x3, 0x1, 0x0, PseudoVLUXSEG4EI8_V_M1_M2_MASK }, // 606
  { 0x4, 0x1, 0x0, 0x3, 0x1, 0x1, PseudoVLUXSEG4EI8_V_M2_M2_MASK }, // 607
  { 0x4, 0x1, 0x0, 0x3, 0x1, 0x6, PseudoVLUXSEG4EI8_V_MF4_M2_MASK }, // 608
  { 0x4, 0x1, 0x0, 0x3, 0x1, 0x7, PseudoVLUXSEG4EI8_V_MF2_M2_MASK }, // 609
  { 0x4, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG4EI8_V_MF8_MF8_MASK }, // 610
  { 0x4, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG4EI8_V_MF8_MF4_MASK }, // 611
  { 0x4, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG4EI8_V_MF4_MF4_MASK }, // 612
  { 0x4, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG4EI8_V_MF8_MF2_MASK }, // 613
  { 0x4, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG4EI8_V_MF4_MF2_MASK }, // 614
  { 0x4, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG4EI8_V_MF2_MF2_MASK }, // 615
  { 0x4, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG4EI16_V_M1_M1_MASK }, // 616
  { 0x4, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG4EI16_V_M2_M1_MASK }, // 617
  { 0x4, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG4EI16_V_MF4_M1_MASK }, // 618
  { 0x4, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG4EI16_V_MF2_M1_MASK }, // 619
  { 0x4, 0x1, 0x0, 0x4, 0x1, 0x0, PseudoVLUXSEG4EI16_V_M1_M2_MASK }, // 620
  { 0x4, 0x1, 0x0, 0x4, 0x1, 0x1, PseudoVLUXSEG4EI16_V_M2_M2_MASK }, // 621
  { 0x4, 0x1, 0x0, 0x4, 0x1, 0x2, PseudoVLUXSEG4EI16_V_M4_M2_MASK }, // 622
  { 0x4, 0x1, 0x0, 0x4, 0x1, 0x7, PseudoVLUXSEG4EI16_V_MF2_M2_MASK }, // 623
  { 0x4, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG4EI16_V_MF4_MF8_MASK }, // 624
  { 0x4, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG4EI16_V_MF4_MF4_MASK }, // 625
  { 0x4, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG4EI16_V_MF2_MF4_MASK }, // 626
  { 0x4, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG4EI16_V_M1_MF2_MASK }, // 627
  { 0x4, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG4EI16_V_MF4_MF2_MASK }, // 628
  { 0x4, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG4EI16_V_MF2_MF2_MASK }, // 629
  { 0x4, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG4EI32_V_M1_M1_MASK }, // 630
  { 0x4, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG4EI32_V_M2_M1_MASK }, // 631
  { 0x4, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG4EI32_V_M4_M1_MASK }, // 632
  { 0x4, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG4EI32_V_MF2_M1_MASK }, // 633
  { 0x4, 0x1, 0x0, 0x5, 0x1, 0x0, PseudoVLUXSEG4EI32_V_M1_M2_MASK }, // 634
  { 0x4, 0x1, 0x0, 0x5, 0x1, 0x1, PseudoVLUXSEG4EI32_V_M2_M2_MASK }, // 635
  { 0x4, 0x1, 0x0, 0x5, 0x1, 0x2, PseudoVLUXSEG4EI32_V_M4_M2_MASK }, // 636
  { 0x4, 0x1, 0x0, 0x5, 0x1, 0x3, PseudoVLUXSEG4EI32_V_M8_M2_MASK }, // 637
  { 0x4, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG4EI32_V_MF2_MF8_MASK }, // 638
  { 0x4, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG4EI32_V_M1_MF4_MASK }, // 639
  { 0x4, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG4EI32_V_MF2_MF4_MASK }, // 640
  { 0x4, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG4EI32_V_M1_MF2_MASK }, // 641
  { 0x4, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG4EI32_V_M2_MF2_MASK }, // 642
  { 0x4, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG4EI32_V_MF2_MF2_MASK }, // 643
  { 0x4, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG4EI64_V_M1_M1_MASK }, // 644
  { 0x4, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG4EI64_V_M2_M1_MASK }, // 645
  { 0x4, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG4EI64_V_M4_M1_MASK }, // 646
  { 0x4, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG4EI64_V_M8_M1_MASK }, // 647
  { 0x4, 0x1, 0x0, 0x6, 0x1, 0x1, PseudoVLUXSEG4EI64_V_M2_M2_MASK }, // 648
  { 0x4, 0x1, 0x0, 0x6, 0x1, 0x2, PseudoVLUXSEG4EI64_V_M4_M2_MASK }, // 649
  { 0x4, 0x1, 0x0, 0x6, 0x1, 0x3, PseudoVLUXSEG4EI64_V_M8_M2_MASK }, // 650
  { 0x4, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG4EI64_V_M1_MF8_MASK }, // 651
  { 0x4, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG4EI64_V_M1_MF4_MASK }, // 652
  { 0x4, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG4EI64_V_M2_MF4_MASK }, // 653
  { 0x4, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG4EI64_V_M1_MF2_MASK }, // 654
  { 0x4, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG4EI64_V_M2_MF2_MASK }, // 655
  { 0x4, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG4EI64_V_M4_MF2_MASK }, // 656
  { 0x4, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG4EI8_V_M1_M1_MASK }, // 657
  { 0x4, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG4EI8_V_MF8_M1_MASK }, // 658
  { 0x4, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG4EI8_V_MF4_M1_MASK }, // 659
  { 0x4, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG4EI8_V_MF2_M1_MASK }, // 660
  { 0x4, 0x1, 0x1, 0x3, 0x1, 0x0, PseudoVLOXSEG4EI8_V_M1_M2_MASK }, // 661
  { 0x4, 0x1, 0x1, 0x3, 0x1, 0x1, PseudoVLOXSEG4EI8_V_M2_M2_MASK }, // 662
  { 0x4, 0x1, 0x1, 0x3, 0x1, 0x6, PseudoVLOXSEG4EI8_V_MF4_M2_MASK }, // 663
  { 0x4, 0x1, 0x1, 0x3, 0x1, 0x7, PseudoVLOXSEG4EI8_V_MF2_M2_MASK }, // 664
  { 0x4, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG4EI8_V_MF8_MF8_MASK }, // 665
  { 0x4, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG4EI8_V_MF8_MF4_MASK }, // 666
  { 0x4, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG4EI8_V_MF4_MF4_MASK }, // 667
  { 0x4, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG4EI8_V_MF8_MF2_MASK }, // 668
  { 0x4, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG4EI8_V_MF4_MF2_MASK }, // 669
  { 0x4, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG4EI8_V_MF2_MF2_MASK }, // 670
  { 0x4, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG4EI16_V_M1_M1_MASK }, // 671
  { 0x4, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG4EI16_V_M2_M1_MASK }, // 672
  { 0x4, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG4EI16_V_MF4_M1_MASK }, // 673
  { 0x4, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG4EI16_V_MF2_M1_MASK }, // 674
  { 0x4, 0x1, 0x1, 0x4, 0x1, 0x0, PseudoVLOXSEG4EI16_V_M1_M2_MASK }, // 675
  { 0x4, 0x1, 0x1, 0x4, 0x1, 0x1, PseudoVLOXSEG4EI16_V_M2_M2_MASK }, // 676
  { 0x4, 0x1, 0x1, 0x4, 0x1, 0x2, PseudoVLOXSEG4EI16_V_M4_M2_MASK }, // 677
  { 0x4, 0x1, 0x1, 0x4, 0x1, 0x7, PseudoVLOXSEG4EI16_V_MF2_M2_MASK }, // 678
  { 0x4, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG4EI16_V_MF4_MF8_MASK }, // 679
  { 0x4, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG4EI16_V_MF4_MF4_MASK }, // 680
  { 0x4, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG4EI16_V_MF2_MF4_MASK }, // 681
  { 0x4, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG4EI16_V_M1_MF2_MASK }, // 682
  { 0x4, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG4EI16_V_MF4_MF2_MASK }, // 683
  { 0x4, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG4EI16_V_MF2_MF2_MASK }, // 684
  { 0x4, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG4EI32_V_M1_M1_MASK }, // 685
  { 0x4, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG4EI32_V_M2_M1_MASK }, // 686
  { 0x4, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG4EI32_V_M4_M1_MASK }, // 687
  { 0x4, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG4EI32_V_MF2_M1_MASK }, // 688
  { 0x4, 0x1, 0x1, 0x5, 0x1, 0x0, PseudoVLOXSEG4EI32_V_M1_M2_MASK }, // 689
  { 0x4, 0x1, 0x1, 0x5, 0x1, 0x1, PseudoVLOXSEG4EI32_V_M2_M2_MASK }, // 690
  { 0x4, 0x1, 0x1, 0x5, 0x1, 0x2, PseudoVLOXSEG4EI32_V_M4_M2_MASK }, // 691
  { 0x4, 0x1, 0x1, 0x5, 0x1, 0x3, PseudoVLOXSEG4EI32_V_M8_M2_MASK }, // 692
  { 0x4, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG4EI32_V_MF2_MF8_MASK }, // 693
  { 0x4, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG4EI32_V_M1_MF4_MASK }, // 694
  { 0x4, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG4EI32_V_MF2_MF4_MASK }, // 695
  { 0x4, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG4EI32_V_M1_MF2_MASK }, // 696
  { 0x4, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG4EI32_V_M2_MF2_MASK }, // 697
  { 0x4, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG4EI32_V_MF2_MF2_MASK }, // 698
  { 0x4, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG4EI64_V_M1_M1_MASK }, // 699
  { 0x4, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG4EI64_V_M2_M1_MASK }, // 700
  { 0x4, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG4EI64_V_M4_M1_MASK }, // 701
  { 0x4, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG4EI64_V_M8_M1_MASK }, // 702
  { 0x4, 0x1, 0x1, 0x6, 0x1, 0x1, PseudoVLOXSEG4EI64_V_M2_M2_MASK }, // 703
  { 0x4, 0x1, 0x1, 0x6, 0x1, 0x2, PseudoVLOXSEG4EI64_V_M4_M2_MASK }, // 704
  { 0x4, 0x1, 0x1, 0x6, 0x1, 0x3, PseudoVLOXSEG4EI64_V_M8_M2_MASK }, // 705
  { 0x4, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG4EI64_V_M1_MF8_MASK }, // 706
  { 0x4, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG4EI64_V_M1_MF4_MASK }, // 707
  { 0x4, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG4EI64_V_M2_MF4_MASK }, // 708
  { 0x4, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG4EI64_V_M1_MF2_MASK }, // 709
  { 0x4, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG4EI64_V_M2_MF2_MASK }, // 710
  { 0x4, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG4EI64_V_M4_MF2_MASK }, // 711
  { 0x5, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG5EI8_V_M1_M1 }, // 712
  { 0x5, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG5EI8_V_MF8_M1 }, // 713
  { 0x5, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG5EI8_V_MF4_M1 }, // 714
  { 0x5, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG5EI8_V_MF2_M1 }, // 715
  { 0x5, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG5EI8_V_MF8_MF8 }, // 716
  { 0x5, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG5EI8_V_MF8_MF4 }, // 717
  { 0x5, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG5EI8_V_MF4_MF4 }, // 718
  { 0x5, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG5EI8_V_MF8_MF2 }, // 719
  { 0x5, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG5EI8_V_MF4_MF2 }, // 720
  { 0x5, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG5EI8_V_MF2_MF2 }, // 721
  { 0x5, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG5EI16_V_M1_M1 }, // 722
  { 0x5, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG5EI16_V_M2_M1 }, // 723
  { 0x5, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG5EI16_V_MF4_M1 }, // 724
  { 0x5, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG5EI16_V_MF2_M1 }, // 725
  { 0x5, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG5EI16_V_MF4_MF8 }, // 726
  { 0x5, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG5EI16_V_MF4_MF4 }, // 727
  { 0x5, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG5EI16_V_MF2_MF4 }, // 728
  { 0x5, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG5EI16_V_M1_MF2 }, // 729
  { 0x5, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG5EI16_V_MF4_MF2 }, // 730
  { 0x5, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG5EI16_V_MF2_MF2 }, // 731
  { 0x5, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG5EI32_V_M1_M1 }, // 732
  { 0x5, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG5EI32_V_M2_M1 }, // 733
  { 0x5, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG5EI32_V_M4_M1 }, // 734
  { 0x5, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG5EI32_V_MF2_M1 }, // 735
  { 0x5, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG5EI32_V_MF2_MF8 }, // 736
  { 0x5, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG5EI32_V_M1_MF4 }, // 737
  { 0x5, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG5EI32_V_MF2_MF4 }, // 738
  { 0x5, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG5EI32_V_M1_MF2 }, // 739
  { 0x5, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG5EI32_V_M2_MF2 }, // 740
  { 0x5, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG5EI32_V_MF2_MF2 }, // 741
  { 0x5, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG5EI64_V_M1_M1 }, // 742
  { 0x5, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG5EI64_V_M2_M1 }, // 743
  { 0x5, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG5EI64_V_M4_M1 }, // 744
  { 0x5, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG5EI64_V_M8_M1 }, // 745
  { 0x5, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG5EI64_V_M1_MF8 }, // 746
  { 0x5, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG5EI64_V_M1_MF4 }, // 747
  { 0x5, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG5EI64_V_M2_MF4 }, // 748
  { 0x5, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG5EI64_V_M1_MF2 }, // 749
  { 0x5, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG5EI64_V_M2_MF2 }, // 750
  { 0x5, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG5EI64_V_M4_MF2 }, // 751
  { 0x5, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG5EI8_V_M1_M1 }, // 752
  { 0x5, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG5EI8_V_MF8_M1 }, // 753
  { 0x5, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG5EI8_V_MF4_M1 }, // 754
  { 0x5, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG5EI8_V_MF2_M1 }, // 755
  { 0x5, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG5EI8_V_MF8_MF8 }, // 756
  { 0x5, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG5EI8_V_MF8_MF4 }, // 757
  { 0x5, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG5EI8_V_MF4_MF4 }, // 758
  { 0x5, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG5EI8_V_MF8_MF2 }, // 759
  { 0x5, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG5EI8_V_MF4_MF2 }, // 760
  { 0x5, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG5EI8_V_MF2_MF2 }, // 761
  { 0x5, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG5EI16_V_M1_M1 }, // 762
  { 0x5, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG5EI16_V_M2_M1 }, // 763
  { 0x5, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG5EI16_V_MF4_M1 }, // 764
  { 0x5, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG5EI16_V_MF2_M1 }, // 765
  { 0x5, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG5EI16_V_MF4_MF8 }, // 766
  { 0x5, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG5EI16_V_MF4_MF4 }, // 767
  { 0x5, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG5EI16_V_MF2_MF4 }, // 768
  { 0x5, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG5EI16_V_M1_MF2 }, // 769
  { 0x5, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG5EI16_V_MF4_MF2 }, // 770
  { 0x5, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG5EI16_V_MF2_MF2 }, // 771
  { 0x5, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG5EI32_V_M1_M1 }, // 772
  { 0x5, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG5EI32_V_M2_M1 }, // 773
  { 0x5, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG5EI32_V_M4_M1 }, // 774
  { 0x5, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG5EI32_V_MF2_M1 }, // 775
  { 0x5, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG5EI32_V_MF2_MF8 }, // 776
  { 0x5, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG5EI32_V_M1_MF4 }, // 777
  { 0x5, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG5EI32_V_MF2_MF4 }, // 778
  { 0x5, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG5EI32_V_M1_MF2 }, // 779
  { 0x5, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG5EI32_V_M2_MF2 }, // 780
  { 0x5, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG5EI32_V_MF2_MF2 }, // 781
  { 0x5, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG5EI64_V_M1_M1 }, // 782
  { 0x5, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG5EI64_V_M2_M1 }, // 783
  { 0x5, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG5EI64_V_M4_M1 }, // 784
  { 0x5, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG5EI64_V_M8_M1 }, // 785
  { 0x5, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG5EI64_V_M1_MF8 }, // 786
  { 0x5, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG5EI64_V_M1_MF4 }, // 787
  { 0x5, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG5EI64_V_M2_MF4 }, // 788
  { 0x5, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG5EI64_V_M1_MF2 }, // 789
  { 0x5, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG5EI64_V_M2_MF2 }, // 790
  { 0x5, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG5EI64_V_M4_MF2 }, // 791
  { 0x5, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG5EI8_V_M1_M1_MASK }, // 792
  { 0x5, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG5EI8_V_MF8_M1_MASK }, // 793
  { 0x5, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG5EI8_V_MF4_M1_MASK }, // 794
  { 0x5, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG5EI8_V_MF2_M1_MASK }, // 795
  { 0x5, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG5EI8_V_MF8_MF8_MASK }, // 796
  { 0x5, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG5EI8_V_MF8_MF4_MASK }, // 797
  { 0x5, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG5EI8_V_MF4_MF4_MASK }, // 798
  { 0x5, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG5EI8_V_MF8_MF2_MASK }, // 799
  { 0x5, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG5EI8_V_MF4_MF2_MASK }, // 800
  { 0x5, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG5EI8_V_MF2_MF2_MASK }, // 801
  { 0x5, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG5EI16_V_M1_M1_MASK }, // 802
  { 0x5, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG5EI16_V_M2_M1_MASK }, // 803
  { 0x5, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG5EI16_V_MF4_M1_MASK }, // 804
  { 0x5, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG5EI16_V_MF2_M1_MASK }, // 805
  { 0x5, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG5EI16_V_MF4_MF8_MASK }, // 806
  { 0x5, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG5EI16_V_MF4_MF4_MASK }, // 807
  { 0x5, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG5EI16_V_MF2_MF4_MASK }, // 808
  { 0x5, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG5EI16_V_M1_MF2_MASK }, // 809
  { 0x5, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG5EI16_V_MF4_MF2_MASK }, // 810
  { 0x5, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG5EI16_V_MF2_MF2_MASK }, // 811
  { 0x5, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG5EI32_V_M1_M1_MASK }, // 812
  { 0x5, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG5EI32_V_M2_M1_MASK }, // 813
  { 0x5, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG5EI32_V_M4_M1_MASK }, // 814
  { 0x5, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG5EI32_V_MF2_M1_MASK }, // 815
  { 0x5, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG5EI32_V_MF2_MF8_MASK }, // 816
  { 0x5, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG5EI32_V_M1_MF4_MASK }, // 817
  { 0x5, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG5EI32_V_MF2_MF4_MASK }, // 818
  { 0x5, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG5EI32_V_M1_MF2_MASK }, // 819
  { 0x5, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG5EI32_V_M2_MF2_MASK }, // 820
  { 0x5, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG5EI32_V_MF2_MF2_MASK }, // 821
  { 0x5, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG5EI64_V_M1_M1_MASK }, // 822
  { 0x5, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG5EI64_V_M2_M1_MASK }, // 823
  { 0x5, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG5EI64_V_M4_M1_MASK }, // 824
  { 0x5, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG5EI64_V_M8_M1_MASK }, // 825
  { 0x5, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG5EI64_V_M1_MF8_MASK }, // 826
  { 0x5, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG5EI64_V_M1_MF4_MASK }, // 827
  { 0x5, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG5EI64_V_M2_MF4_MASK }, // 828
  { 0x5, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG5EI64_V_M1_MF2_MASK }, // 829
  { 0x5, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG5EI64_V_M2_MF2_MASK }, // 830
  { 0x5, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG5EI64_V_M4_MF2_MASK }, // 831
  { 0x5, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG5EI8_V_M1_M1_MASK }, // 832
  { 0x5, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG5EI8_V_MF8_M1_MASK }, // 833
  { 0x5, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG5EI8_V_MF4_M1_MASK }, // 834
  { 0x5, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG5EI8_V_MF2_M1_MASK }, // 835
  { 0x5, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG5EI8_V_MF8_MF8_MASK }, // 836
  { 0x5, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG5EI8_V_MF8_MF4_MASK }, // 837
  { 0x5, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG5EI8_V_MF4_MF4_MASK }, // 838
  { 0x5, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG5EI8_V_MF8_MF2_MASK }, // 839
  { 0x5, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG5EI8_V_MF4_MF2_MASK }, // 840
  { 0x5, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG5EI8_V_MF2_MF2_MASK }, // 841
  { 0x5, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG5EI16_V_M1_M1_MASK }, // 842
  { 0x5, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG5EI16_V_M2_M1_MASK }, // 843
  { 0x5, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG5EI16_V_MF4_M1_MASK }, // 844
  { 0x5, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG5EI16_V_MF2_M1_MASK }, // 845
  { 0x5, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG5EI16_V_MF4_MF8_MASK }, // 846
  { 0x5, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG5EI16_V_MF4_MF4_MASK }, // 847
  { 0x5, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG5EI16_V_MF2_MF4_MASK }, // 848
  { 0x5, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG5EI16_V_M1_MF2_MASK }, // 849
  { 0x5, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG5EI16_V_MF4_MF2_MASK }, // 850
  { 0x5, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG5EI16_V_MF2_MF2_MASK }, // 851
  { 0x5, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG5EI32_V_M1_M1_MASK }, // 852
  { 0x5, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG5EI32_V_M2_M1_MASK }, // 853
  { 0x5, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG5EI32_V_M4_M1_MASK }, // 854
  { 0x5, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG5EI32_V_MF2_M1_MASK }, // 855
  { 0x5, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG5EI32_V_MF2_MF8_MASK }, // 856
  { 0x5, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG5EI32_V_M1_MF4_MASK }, // 857
  { 0x5, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG5EI32_V_MF2_MF4_MASK }, // 858
  { 0x5, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG5EI32_V_M1_MF2_MASK }, // 859
  { 0x5, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG5EI32_V_M2_MF2_MASK }, // 860
  { 0x5, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG5EI32_V_MF2_MF2_MASK }, // 861
  { 0x5, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG5EI64_V_M1_M1_MASK }, // 862
  { 0x5, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG5EI64_V_M2_M1_MASK }, // 863
  { 0x5, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG5EI64_V_M4_M1_MASK }, // 864
  { 0x5, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG5EI64_V_M8_M1_MASK }, // 865
  { 0x5, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG5EI64_V_M1_MF8_MASK }, // 866
  { 0x5, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG5EI64_V_M1_MF4_MASK }, // 867
  { 0x5, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG5EI64_V_M2_MF4_MASK }, // 868
  { 0x5, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG5EI64_V_M1_MF2_MASK }, // 869
  { 0x5, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG5EI64_V_M2_MF2_MASK }, // 870
  { 0x5, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG5EI64_V_M4_MF2_MASK }, // 871
  { 0x6, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG6EI8_V_M1_M1 }, // 872
  { 0x6, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG6EI8_V_MF8_M1 }, // 873
  { 0x6, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG6EI8_V_MF4_M1 }, // 874
  { 0x6, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG6EI8_V_MF2_M1 }, // 875
  { 0x6, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG6EI8_V_MF8_MF8 }, // 876
  { 0x6, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG6EI8_V_MF8_MF4 }, // 877
  { 0x6, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG6EI8_V_MF4_MF4 }, // 878
  { 0x6, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG6EI8_V_MF8_MF2 }, // 879
  { 0x6, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG6EI8_V_MF4_MF2 }, // 880
  { 0x6, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG6EI8_V_MF2_MF2 }, // 881
  { 0x6, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG6EI16_V_M1_M1 }, // 882
  { 0x6, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG6EI16_V_M2_M1 }, // 883
  { 0x6, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG6EI16_V_MF4_M1 }, // 884
  { 0x6, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG6EI16_V_MF2_M1 }, // 885
  { 0x6, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG6EI16_V_MF4_MF8 }, // 886
  { 0x6, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG6EI16_V_MF4_MF4 }, // 887
  { 0x6, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG6EI16_V_MF2_MF4 }, // 888
  { 0x6, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG6EI16_V_M1_MF2 }, // 889
  { 0x6, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG6EI16_V_MF4_MF2 }, // 890
  { 0x6, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG6EI16_V_MF2_MF2 }, // 891
  { 0x6, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG6EI32_V_M1_M1 }, // 892
  { 0x6, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG6EI32_V_M2_M1 }, // 893
  { 0x6, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG6EI32_V_M4_M1 }, // 894
  { 0x6, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG6EI32_V_MF2_M1 }, // 895
  { 0x6, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG6EI32_V_MF2_MF8 }, // 896
  { 0x6, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG6EI32_V_M1_MF4 }, // 897
  { 0x6, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG6EI32_V_MF2_MF4 }, // 898
  { 0x6, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG6EI32_V_M1_MF2 }, // 899
  { 0x6, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG6EI32_V_M2_MF2 }, // 900
  { 0x6, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG6EI32_V_MF2_MF2 }, // 901
  { 0x6, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG6EI64_V_M1_M1 }, // 902
  { 0x6, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG6EI64_V_M2_M1 }, // 903
  { 0x6, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG6EI64_V_M4_M1 }, // 904
  { 0x6, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG6EI64_V_M8_M1 }, // 905
  { 0x6, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG6EI64_V_M1_MF8 }, // 906
  { 0x6, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG6EI64_V_M1_MF4 }, // 907
  { 0x6, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG6EI64_V_M2_MF4 }, // 908
  { 0x6, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG6EI64_V_M1_MF2 }, // 909
  { 0x6, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG6EI64_V_M2_MF2 }, // 910
  { 0x6, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG6EI64_V_M4_MF2 }, // 911
  { 0x6, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG6EI8_V_M1_M1 }, // 912
  { 0x6, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG6EI8_V_MF8_M1 }, // 913
  { 0x6, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG6EI8_V_MF4_M1 }, // 914
  { 0x6, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG6EI8_V_MF2_M1 }, // 915
  { 0x6, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG6EI8_V_MF8_MF8 }, // 916
  { 0x6, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG6EI8_V_MF8_MF4 }, // 917
  { 0x6, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG6EI8_V_MF4_MF4 }, // 918
  { 0x6, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG6EI8_V_MF8_MF2 }, // 919
  { 0x6, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG6EI8_V_MF4_MF2 }, // 920
  { 0x6, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG6EI8_V_MF2_MF2 }, // 921
  { 0x6, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG6EI16_V_M1_M1 }, // 922
  { 0x6, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG6EI16_V_M2_M1 }, // 923
  { 0x6, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG6EI16_V_MF4_M1 }, // 924
  { 0x6, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG6EI16_V_MF2_M1 }, // 925
  { 0x6, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG6EI16_V_MF4_MF8 }, // 926
  { 0x6, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG6EI16_V_MF4_MF4 }, // 927
  { 0x6, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG6EI16_V_MF2_MF4 }, // 928
  { 0x6, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG6EI16_V_M1_MF2 }, // 929
  { 0x6, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG6EI16_V_MF4_MF2 }, // 930
  { 0x6, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG6EI16_V_MF2_MF2 }, // 931
  { 0x6, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG6EI32_V_M1_M1 }, // 932
  { 0x6, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG6EI32_V_M2_M1 }, // 933
  { 0x6, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG6EI32_V_M4_M1 }, // 934
  { 0x6, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG6EI32_V_MF2_M1 }, // 935
  { 0x6, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG6EI32_V_MF2_MF8 }, // 936
  { 0x6, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG6EI32_V_M1_MF4 }, // 937
  { 0x6, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG6EI32_V_MF2_MF4 }, // 938
  { 0x6, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG6EI32_V_M1_MF2 }, // 939
  { 0x6, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG6EI32_V_M2_MF2 }, // 940
  { 0x6, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG6EI32_V_MF2_MF2 }, // 941
  { 0x6, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG6EI64_V_M1_M1 }, // 942
  { 0x6, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG6EI64_V_M2_M1 }, // 943
  { 0x6, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG6EI64_V_M4_M1 }, // 944
  { 0x6, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG6EI64_V_M8_M1 }, // 945
  { 0x6, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG6EI64_V_M1_MF8 }, // 946
  { 0x6, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG6EI64_V_M1_MF4 }, // 947
  { 0x6, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG6EI64_V_M2_MF4 }, // 948
  { 0x6, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG6EI64_V_M1_MF2 }, // 949
  { 0x6, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG6EI64_V_M2_MF2 }, // 950
  { 0x6, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG6EI64_V_M4_MF2 }, // 951
  { 0x6, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG6EI8_V_M1_M1_MASK }, // 952
  { 0x6, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG6EI8_V_MF8_M1_MASK }, // 953
  { 0x6, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG6EI8_V_MF4_M1_MASK }, // 954
  { 0x6, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG6EI8_V_MF2_M1_MASK }, // 955
  { 0x6, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG6EI8_V_MF8_MF8_MASK }, // 956
  { 0x6, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG6EI8_V_MF8_MF4_MASK }, // 957
  { 0x6, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG6EI8_V_MF4_MF4_MASK }, // 958
  { 0x6, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG6EI8_V_MF8_MF2_MASK }, // 959
  { 0x6, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG6EI8_V_MF4_MF2_MASK }, // 960
  { 0x6, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG6EI8_V_MF2_MF2_MASK }, // 961
  { 0x6, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG6EI16_V_M1_M1_MASK }, // 962
  { 0x6, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG6EI16_V_M2_M1_MASK }, // 963
  { 0x6, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG6EI16_V_MF4_M1_MASK }, // 964
  { 0x6, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG6EI16_V_MF2_M1_MASK }, // 965
  { 0x6, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG6EI16_V_MF4_MF8_MASK }, // 966
  { 0x6, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG6EI16_V_MF4_MF4_MASK }, // 967
  { 0x6, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG6EI16_V_MF2_MF4_MASK }, // 968
  { 0x6, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG6EI16_V_M1_MF2_MASK }, // 969
  { 0x6, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG6EI16_V_MF4_MF2_MASK }, // 970
  { 0x6, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG6EI16_V_MF2_MF2_MASK }, // 971
  { 0x6, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG6EI32_V_M1_M1_MASK }, // 972
  { 0x6, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG6EI32_V_M2_M1_MASK }, // 973
  { 0x6, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG6EI32_V_M4_M1_MASK }, // 974
  { 0x6, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG6EI32_V_MF2_M1_MASK }, // 975
  { 0x6, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG6EI32_V_MF2_MF8_MASK }, // 976
  { 0x6, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG6EI32_V_M1_MF4_MASK }, // 977
  { 0x6, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG6EI32_V_MF2_MF4_MASK }, // 978
  { 0x6, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG6EI32_V_M1_MF2_MASK }, // 979
  { 0x6, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG6EI32_V_M2_MF2_MASK }, // 980
  { 0x6, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG6EI32_V_MF2_MF2_MASK }, // 981
  { 0x6, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG6EI64_V_M1_M1_MASK }, // 982
  { 0x6, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG6EI64_V_M2_M1_MASK }, // 983
  { 0x6, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG6EI64_V_M4_M1_MASK }, // 984
  { 0x6, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG6EI64_V_M8_M1_MASK }, // 985
  { 0x6, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG6EI64_V_M1_MF8_MASK }, // 986
  { 0x6, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG6EI64_V_M1_MF4_MASK }, // 987
  { 0x6, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG6EI64_V_M2_MF4_MASK }, // 988
  { 0x6, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG6EI64_V_M1_MF2_MASK }, // 989
  { 0x6, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG6EI64_V_M2_MF2_MASK }, // 990
  { 0x6, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG6EI64_V_M4_MF2_MASK }, // 991
  { 0x6, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG6EI8_V_M1_M1_MASK }, // 992
  { 0x6, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG6EI8_V_MF8_M1_MASK }, // 993
  { 0x6, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG6EI8_V_MF4_M1_MASK }, // 994
  { 0x6, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG6EI8_V_MF2_M1_MASK }, // 995
  { 0x6, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG6EI8_V_MF8_MF8_MASK }, // 996
  { 0x6, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG6EI8_V_MF8_MF4_MASK }, // 997
  { 0x6, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG6EI8_V_MF4_MF4_MASK }, // 998
  { 0x6, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG6EI8_V_MF8_MF2_MASK }, // 999
  { 0x6, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG6EI8_V_MF4_MF2_MASK }, // 1000
  { 0x6, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG6EI8_V_MF2_MF2_MASK }, // 1001
  { 0x6, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG6EI16_V_M1_M1_MASK }, // 1002
  { 0x6, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG6EI16_V_M2_M1_MASK }, // 1003
  { 0x6, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG6EI16_V_MF4_M1_MASK }, // 1004
  { 0x6, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG6EI16_V_MF2_M1_MASK }, // 1005
  { 0x6, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG6EI16_V_MF4_MF8_MASK }, // 1006
  { 0x6, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG6EI16_V_MF4_MF4_MASK }, // 1007
  { 0x6, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG6EI16_V_MF2_MF4_MASK }, // 1008
  { 0x6, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG6EI16_V_M1_MF2_MASK }, // 1009
  { 0x6, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG6EI16_V_MF4_MF2_MASK }, // 1010
  { 0x6, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG6EI16_V_MF2_MF2_MASK }, // 1011
  { 0x6, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG6EI32_V_M1_M1_MASK }, // 1012
  { 0x6, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG6EI32_V_M2_M1_MASK }, // 1013
  { 0x6, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG6EI32_V_M4_M1_MASK }, // 1014
  { 0x6, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG6EI32_V_MF2_M1_MASK }, // 1015
  { 0x6, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG6EI32_V_MF2_MF8_MASK }, // 1016
  { 0x6, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG6EI32_V_M1_MF4_MASK }, // 1017
  { 0x6, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG6EI32_V_MF2_MF4_MASK }, // 1018
  { 0x6, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG6EI32_V_M1_MF2_MASK }, // 1019
  { 0x6, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG6EI32_V_M2_MF2_MASK }, // 1020
  { 0x6, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG6EI32_V_MF2_MF2_MASK }, // 1021
  { 0x6, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG6EI64_V_M1_M1_MASK }, // 1022
  { 0x6, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG6EI64_V_M2_M1_MASK }, // 1023
  { 0x6, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG6EI64_V_M4_M1_MASK }, // 1024
  { 0x6, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG6EI64_V_M8_M1_MASK }, // 1025
  { 0x6, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG6EI64_V_M1_MF8_MASK }, // 1026
  { 0x6, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG6EI64_V_M1_MF4_MASK }, // 1027
  { 0x6, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG6EI64_V_M2_MF4_MASK }, // 1028
  { 0x6, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG6EI64_V_M1_MF2_MASK }, // 1029
  { 0x6, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG6EI64_V_M2_MF2_MASK }, // 1030
  { 0x6, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG6EI64_V_M4_MF2_MASK }, // 1031
  { 0x7, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG7EI8_V_M1_M1 }, // 1032
  { 0x7, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG7EI8_V_MF8_M1 }, // 1033
  { 0x7, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG7EI8_V_MF4_M1 }, // 1034
  { 0x7, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG7EI8_V_MF2_M1 }, // 1035
  { 0x7, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG7EI8_V_MF8_MF8 }, // 1036
  { 0x7, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG7EI8_V_MF8_MF4 }, // 1037
  { 0x7, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG7EI8_V_MF4_MF4 }, // 1038
  { 0x7, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG7EI8_V_MF8_MF2 }, // 1039
  { 0x7, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG7EI8_V_MF4_MF2 }, // 1040
  { 0x7, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG7EI8_V_MF2_MF2 }, // 1041
  { 0x7, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG7EI16_V_M1_M1 }, // 1042
  { 0x7, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG7EI16_V_M2_M1 }, // 1043
  { 0x7, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG7EI16_V_MF4_M1 }, // 1044
  { 0x7, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG7EI16_V_MF2_M1 }, // 1045
  { 0x7, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG7EI16_V_MF4_MF8 }, // 1046
  { 0x7, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG7EI16_V_MF4_MF4 }, // 1047
  { 0x7, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG7EI16_V_MF2_MF4 }, // 1048
  { 0x7, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG7EI16_V_M1_MF2 }, // 1049
  { 0x7, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG7EI16_V_MF4_MF2 }, // 1050
  { 0x7, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG7EI16_V_MF2_MF2 }, // 1051
  { 0x7, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG7EI32_V_M1_M1 }, // 1052
  { 0x7, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG7EI32_V_M2_M1 }, // 1053
  { 0x7, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG7EI32_V_M4_M1 }, // 1054
  { 0x7, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG7EI32_V_MF2_M1 }, // 1055
  { 0x7, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG7EI32_V_MF2_MF8 }, // 1056
  { 0x7, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG7EI32_V_M1_MF4 }, // 1057
  { 0x7, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG7EI32_V_MF2_MF4 }, // 1058
  { 0x7, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG7EI32_V_M1_MF2 }, // 1059
  { 0x7, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG7EI32_V_M2_MF2 }, // 1060
  { 0x7, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG7EI32_V_MF2_MF2 }, // 1061
  { 0x7, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG7EI64_V_M1_M1 }, // 1062
  { 0x7, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG7EI64_V_M2_M1 }, // 1063
  { 0x7, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG7EI64_V_M4_M1 }, // 1064
  { 0x7, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG7EI64_V_M8_M1 }, // 1065
  { 0x7, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG7EI64_V_M1_MF8 }, // 1066
  { 0x7, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG7EI64_V_M1_MF4 }, // 1067
  { 0x7, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG7EI64_V_M2_MF4 }, // 1068
  { 0x7, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG7EI64_V_M1_MF2 }, // 1069
  { 0x7, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG7EI64_V_M2_MF2 }, // 1070
  { 0x7, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG7EI64_V_M4_MF2 }, // 1071
  { 0x7, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG7EI8_V_M1_M1 }, // 1072
  { 0x7, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG7EI8_V_MF8_M1 }, // 1073
  { 0x7, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG7EI8_V_MF4_M1 }, // 1074
  { 0x7, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG7EI8_V_MF2_M1 }, // 1075
  { 0x7, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG7EI8_V_MF8_MF8 }, // 1076
  { 0x7, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG7EI8_V_MF8_MF4 }, // 1077
  { 0x7, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG7EI8_V_MF4_MF4 }, // 1078
  { 0x7, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG7EI8_V_MF8_MF2 }, // 1079
  { 0x7, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG7EI8_V_MF4_MF2 }, // 1080
  { 0x7, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG7EI8_V_MF2_MF2 }, // 1081
  { 0x7, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG7EI16_V_M1_M1 }, // 1082
  { 0x7, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG7EI16_V_M2_M1 }, // 1083
  { 0x7, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG7EI16_V_MF4_M1 }, // 1084
  { 0x7, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG7EI16_V_MF2_M1 }, // 1085
  { 0x7, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG7EI16_V_MF4_MF8 }, // 1086
  { 0x7, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG7EI16_V_MF4_MF4 }, // 1087
  { 0x7, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG7EI16_V_MF2_MF4 }, // 1088
  { 0x7, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG7EI16_V_M1_MF2 }, // 1089
  { 0x7, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG7EI16_V_MF4_MF2 }, // 1090
  { 0x7, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG7EI16_V_MF2_MF2 }, // 1091
  { 0x7, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG7EI32_V_M1_M1 }, // 1092
  { 0x7, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG7EI32_V_M2_M1 }, // 1093
  { 0x7, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG7EI32_V_M4_M1 }, // 1094
  { 0x7, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG7EI32_V_MF2_M1 }, // 1095
  { 0x7, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG7EI32_V_MF2_MF8 }, // 1096
  { 0x7, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG7EI32_V_M1_MF4 }, // 1097
  { 0x7, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG7EI32_V_MF2_MF4 }, // 1098
  { 0x7, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG7EI32_V_M1_MF2 }, // 1099
  { 0x7, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG7EI32_V_M2_MF2 }, // 1100
  { 0x7, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG7EI32_V_MF2_MF2 }, // 1101
  { 0x7, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG7EI64_V_M1_M1 }, // 1102
  { 0x7, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG7EI64_V_M2_M1 }, // 1103
  { 0x7, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG7EI64_V_M4_M1 }, // 1104
  { 0x7, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG7EI64_V_M8_M1 }, // 1105
  { 0x7, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG7EI64_V_M1_MF8 }, // 1106
  { 0x7, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG7EI64_V_M1_MF4 }, // 1107
  { 0x7, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG7EI64_V_M2_MF4 }, // 1108
  { 0x7, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG7EI64_V_M1_MF2 }, // 1109
  { 0x7, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG7EI64_V_M2_MF2 }, // 1110
  { 0x7, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG7EI64_V_M4_MF2 }, // 1111
  { 0x7, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG7EI8_V_M1_M1_MASK }, // 1112
  { 0x7, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG7EI8_V_MF8_M1_MASK }, // 1113
  { 0x7, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG7EI8_V_MF4_M1_MASK }, // 1114
  { 0x7, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG7EI8_V_MF2_M1_MASK }, // 1115
  { 0x7, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG7EI8_V_MF8_MF8_MASK }, // 1116
  { 0x7, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG7EI8_V_MF8_MF4_MASK }, // 1117
  { 0x7, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG7EI8_V_MF4_MF4_MASK }, // 1118
  { 0x7, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG7EI8_V_MF8_MF2_MASK }, // 1119
  { 0x7, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG7EI8_V_MF4_MF2_MASK }, // 1120
  { 0x7, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG7EI8_V_MF2_MF2_MASK }, // 1121
  { 0x7, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG7EI16_V_M1_M1_MASK }, // 1122
  { 0x7, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG7EI16_V_M2_M1_MASK }, // 1123
  { 0x7, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG7EI16_V_MF4_M1_MASK }, // 1124
  { 0x7, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG7EI16_V_MF2_M1_MASK }, // 1125
  { 0x7, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG7EI16_V_MF4_MF8_MASK }, // 1126
  { 0x7, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG7EI16_V_MF4_MF4_MASK }, // 1127
  { 0x7, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG7EI16_V_MF2_MF4_MASK }, // 1128
  { 0x7, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG7EI16_V_M1_MF2_MASK }, // 1129
  { 0x7, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG7EI16_V_MF4_MF2_MASK }, // 1130
  { 0x7, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG7EI16_V_MF2_MF2_MASK }, // 1131
  { 0x7, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG7EI32_V_M1_M1_MASK }, // 1132
  { 0x7, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG7EI32_V_M2_M1_MASK }, // 1133
  { 0x7, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG7EI32_V_M4_M1_MASK }, // 1134
  { 0x7, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG7EI32_V_MF2_M1_MASK }, // 1135
  { 0x7, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG7EI32_V_MF2_MF8_MASK }, // 1136
  { 0x7, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG7EI32_V_M1_MF4_MASK }, // 1137
  { 0x7, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG7EI32_V_MF2_MF4_MASK }, // 1138
  { 0x7, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG7EI32_V_M1_MF2_MASK }, // 1139
  { 0x7, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG7EI32_V_M2_MF2_MASK }, // 1140
  { 0x7, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG7EI32_V_MF2_MF2_MASK }, // 1141
  { 0x7, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG7EI64_V_M1_M1_MASK }, // 1142
  { 0x7, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG7EI64_V_M2_M1_MASK }, // 1143
  { 0x7, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG7EI64_V_M4_M1_MASK }, // 1144
  { 0x7, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG7EI64_V_M8_M1_MASK }, // 1145
  { 0x7, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG7EI64_V_M1_MF8_MASK }, // 1146
  { 0x7, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG7EI64_V_M1_MF4_MASK }, // 1147
  { 0x7, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG7EI64_V_M2_MF4_MASK }, // 1148
  { 0x7, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG7EI64_V_M1_MF2_MASK }, // 1149
  { 0x7, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG7EI64_V_M2_MF2_MASK }, // 1150
  { 0x7, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG7EI64_V_M4_MF2_MASK }, // 1151
  { 0x7, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG7EI8_V_M1_M1_MASK }, // 1152
  { 0x7, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG7EI8_V_MF8_M1_MASK }, // 1153
  { 0x7, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG7EI8_V_MF4_M1_MASK }, // 1154
  { 0x7, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG7EI8_V_MF2_M1_MASK }, // 1155
  { 0x7, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG7EI8_V_MF8_MF8_MASK }, // 1156
  { 0x7, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG7EI8_V_MF8_MF4_MASK }, // 1157
  { 0x7, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG7EI8_V_MF4_MF4_MASK }, // 1158
  { 0x7, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG7EI8_V_MF8_MF2_MASK }, // 1159
  { 0x7, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG7EI8_V_MF4_MF2_MASK }, // 1160
  { 0x7, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG7EI8_V_MF2_MF2_MASK }, // 1161
  { 0x7, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG7EI16_V_M1_M1_MASK }, // 1162
  { 0x7, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG7EI16_V_M2_M1_MASK }, // 1163
  { 0x7, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG7EI16_V_MF4_M1_MASK }, // 1164
  { 0x7, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG7EI16_V_MF2_M1_MASK }, // 1165
  { 0x7, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG7EI16_V_MF4_MF8_MASK }, // 1166
  { 0x7, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG7EI16_V_MF4_MF4_MASK }, // 1167
  { 0x7, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG7EI16_V_MF2_MF4_MASK }, // 1168
  { 0x7, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG7EI16_V_M1_MF2_MASK }, // 1169
  { 0x7, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG7EI16_V_MF4_MF2_MASK }, // 1170
  { 0x7, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG7EI16_V_MF2_MF2_MASK }, // 1171
  { 0x7, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG7EI32_V_M1_M1_MASK }, // 1172
  { 0x7, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG7EI32_V_M2_M1_MASK }, // 1173
  { 0x7, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG7EI32_V_M4_M1_MASK }, // 1174
  { 0x7, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG7EI32_V_MF2_M1_MASK }, // 1175
  { 0x7, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG7EI32_V_MF2_MF8_MASK }, // 1176
  { 0x7, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG7EI32_V_M1_MF4_MASK }, // 1177
  { 0x7, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG7EI32_V_MF2_MF4_MASK }, // 1178
  { 0x7, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG7EI32_V_M1_MF2_MASK }, // 1179
  { 0x7, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG7EI32_V_M2_MF2_MASK }, // 1180
  { 0x7, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG7EI32_V_MF2_MF2_MASK }, // 1181
  { 0x7, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG7EI64_V_M1_M1_MASK }, // 1182
  { 0x7, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG7EI64_V_M2_M1_MASK }, // 1183
  { 0x7, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG7EI64_V_M4_M1_MASK }, // 1184
  { 0x7, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG7EI64_V_M8_M1_MASK }, // 1185
  { 0x7, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG7EI64_V_M1_MF8_MASK }, // 1186
  { 0x7, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG7EI64_V_M1_MF4_MASK }, // 1187
  { 0x7, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG7EI64_V_M2_MF4_MASK }, // 1188
  { 0x7, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG7EI64_V_M1_MF2_MASK }, // 1189
  { 0x7, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG7EI64_V_M2_MF2_MASK }, // 1190
  { 0x7, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG7EI64_V_M4_MF2_MASK }, // 1191
  { 0x8, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG8EI8_V_M1_M1 }, // 1192
  { 0x8, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG8EI8_V_MF8_M1 }, // 1193
  { 0x8, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG8EI8_V_MF4_M1 }, // 1194
  { 0x8, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG8EI8_V_MF2_M1 }, // 1195
  { 0x8, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG8EI8_V_MF8_MF8 }, // 1196
  { 0x8, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG8EI8_V_MF8_MF4 }, // 1197
  { 0x8, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG8EI8_V_MF4_MF4 }, // 1198
  { 0x8, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG8EI8_V_MF8_MF2 }, // 1199
  { 0x8, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG8EI8_V_MF4_MF2 }, // 1200
  { 0x8, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG8EI8_V_MF2_MF2 }, // 1201
  { 0x8, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG8EI16_V_M1_M1 }, // 1202
  { 0x8, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG8EI16_V_M2_M1 }, // 1203
  { 0x8, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG8EI16_V_MF4_M1 }, // 1204
  { 0x8, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG8EI16_V_MF2_M1 }, // 1205
  { 0x8, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG8EI16_V_MF4_MF8 }, // 1206
  { 0x8, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG8EI16_V_MF4_MF4 }, // 1207
  { 0x8, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG8EI16_V_MF2_MF4 }, // 1208
  { 0x8, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG8EI16_V_M1_MF2 }, // 1209
  { 0x8, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG8EI16_V_MF4_MF2 }, // 1210
  { 0x8, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG8EI16_V_MF2_MF2 }, // 1211
  { 0x8, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG8EI32_V_M1_M1 }, // 1212
  { 0x8, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG8EI32_V_M2_M1 }, // 1213
  { 0x8, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG8EI32_V_M4_M1 }, // 1214
  { 0x8, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG8EI32_V_MF2_M1 }, // 1215
  { 0x8, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG8EI32_V_MF2_MF8 }, // 1216
  { 0x8, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG8EI32_V_M1_MF4 }, // 1217
  { 0x8, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG8EI32_V_MF2_MF4 }, // 1218
  { 0x8, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG8EI32_V_M1_MF2 }, // 1219
  { 0x8, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG8EI32_V_M2_MF2 }, // 1220
  { 0x8, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG8EI32_V_MF2_MF2 }, // 1221
  { 0x8, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG8EI64_V_M1_M1 }, // 1222
  { 0x8, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG8EI64_V_M2_M1 }, // 1223
  { 0x8, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG8EI64_V_M4_M1 }, // 1224
  { 0x8, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG8EI64_V_M8_M1 }, // 1225
  { 0x8, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG8EI64_V_M1_MF8 }, // 1226
  { 0x8, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG8EI64_V_M1_MF4 }, // 1227
  { 0x8, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG8EI64_V_M2_MF4 }, // 1228
  { 0x8, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG8EI64_V_M1_MF2 }, // 1229
  { 0x8, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG8EI64_V_M2_MF2 }, // 1230
  { 0x8, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG8EI64_V_M4_MF2 }, // 1231
  { 0x8, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG8EI8_V_M1_M1 }, // 1232
  { 0x8, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG8EI8_V_MF8_M1 }, // 1233
  { 0x8, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG8EI8_V_MF4_M1 }, // 1234
  { 0x8, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG8EI8_V_MF2_M1 }, // 1235
  { 0x8, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG8EI8_V_MF8_MF8 }, // 1236
  { 0x8, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG8EI8_V_MF8_MF4 }, // 1237
  { 0x8, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG8EI8_V_MF4_MF4 }, // 1238
  { 0x8, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG8EI8_V_MF8_MF2 }, // 1239
  { 0x8, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG8EI8_V_MF4_MF2 }, // 1240
  { 0x8, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG8EI8_V_MF2_MF2 }, // 1241
  { 0x8, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG8EI16_V_M1_M1 }, // 1242
  { 0x8, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG8EI16_V_M2_M1 }, // 1243
  { 0x8, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG8EI16_V_MF4_M1 }, // 1244
  { 0x8, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG8EI16_V_MF2_M1 }, // 1245
  { 0x8, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG8EI16_V_MF4_MF8 }, // 1246
  { 0x8, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG8EI16_V_MF4_MF4 }, // 1247
  { 0x8, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG8EI16_V_MF2_MF4 }, // 1248
  { 0x8, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG8EI16_V_M1_MF2 }, // 1249
  { 0x8, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG8EI16_V_MF4_MF2 }, // 1250
  { 0x8, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG8EI16_V_MF2_MF2 }, // 1251
  { 0x8, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG8EI32_V_M1_M1 }, // 1252
  { 0x8, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG8EI32_V_M2_M1 }, // 1253
  { 0x8, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG8EI32_V_M4_M1 }, // 1254
  { 0x8, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG8EI32_V_MF2_M1 }, // 1255
  { 0x8, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG8EI32_V_MF2_MF8 }, // 1256
  { 0x8, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG8EI32_V_M1_MF4 }, // 1257
  { 0x8, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG8EI32_V_MF2_MF4 }, // 1258
  { 0x8, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG8EI32_V_M1_MF2 }, // 1259
  { 0x8, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG8EI32_V_M2_MF2 }, // 1260
  { 0x8, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG8EI32_V_MF2_MF2 }, // 1261
  { 0x8, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG8EI64_V_M1_M1 }, // 1262
  { 0x8, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG8EI64_V_M2_M1 }, // 1263
  { 0x8, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG8EI64_V_M4_M1 }, // 1264
  { 0x8, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG8EI64_V_M8_M1 }, // 1265
  { 0x8, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG8EI64_V_M1_MF8 }, // 1266
  { 0x8, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG8EI64_V_M1_MF4 }, // 1267
  { 0x8, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG8EI64_V_M2_MF4 }, // 1268
  { 0x8, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG8EI64_V_M1_MF2 }, // 1269
  { 0x8, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG8EI64_V_M2_MF2 }, // 1270
  { 0x8, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG8EI64_V_M4_MF2 }, // 1271
  { 0x8, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVLUXSEG8EI8_V_M1_M1_MASK }, // 1272
  { 0x8, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVLUXSEG8EI8_V_MF8_M1_MASK }, // 1273
  { 0x8, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVLUXSEG8EI8_V_MF4_M1_MASK }, // 1274
  { 0x8, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVLUXSEG8EI8_V_MF2_M1_MASK }, // 1275
  { 0x8, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVLUXSEG8EI8_V_MF8_MF8_MASK }, // 1276
  { 0x8, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVLUXSEG8EI8_V_MF8_MF4_MASK }, // 1277
  { 0x8, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVLUXSEG8EI8_V_MF4_MF4_MASK }, // 1278
  { 0x8, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVLUXSEG8EI8_V_MF8_MF2_MASK }, // 1279
  { 0x8, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVLUXSEG8EI8_V_MF4_MF2_MASK }, // 1280
  { 0x8, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVLUXSEG8EI8_V_MF2_MF2_MASK }, // 1281
  { 0x8, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVLUXSEG8EI16_V_M1_M1_MASK }, // 1282
  { 0x8, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVLUXSEG8EI16_V_M2_M1_MASK }, // 1283
  { 0x8, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVLUXSEG8EI16_V_MF4_M1_MASK }, // 1284
  { 0x8, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVLUXSEG8EI16_V_MF2_M1_MASK }, // 1285
  { 0x8, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVLUXSEG8EI16_V_MF4_MF8_MASK }, // 1286
  { 0x8, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVLUXSEG8EI16_V_MF4_MF4_MASK }, // 1287
  { 0x8, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVLUXSEG8EI16_V_MF2_MF4_MASK }, // 1288
  { 0x8, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVLUXSEG8EI16_V_M1_MF2_MASK }, // 1289
  { 0x8, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVLUXSEG8EI16_V_MF4_MF2_MASK }, // 1290
  { 0x8, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVLUXSEG8EI16_V_MF2_MF2_MASK }, // 1291
  { 0x8, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVLUXSEG8EI32_V_M1_M1_MASK }, // 1292
  { 0x8, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVLUXSEG8EI32_V_M2_M1_MASK }, // 1293
  { 0x8, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVLUXSEG8EI32_V_M4_M1_MASK }, // 1294
  { 0x8, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVLUXSEG8EI32_V_MF2_M1_MASK }, // 1295
  { 0x8, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVLUXSEG8EI32_V_MF2_MF8_MASK }, // 1296
  { 0x8, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVLUXSEG8EI32_V_M1_MF4_MASK }, // 1297
  { 0x8, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVLUXSEG8EI32_V_MF2_MF4_MASK }, // 1298
  { 0x8, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVLUXSEG8EI32_V_M1_MF2_MASK }, // 1299
  { 0x8, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVLUXSEG8EI32_V_M2_MF2_MASK }, // 1300
  { 0x8, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVLUXSEG8EI32_V_MF2_MF2_MASK }, // 1301
  { 0x8, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVLUXSEG8EI64_V_M1_M1_MASK }, // 1302
  { 0x8, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVLUXSEG8EI64_V_M2_M1_MASK }, // 1303
  { 0x8, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVLUXSEG8EI64_V_M4_M1_MASK }, // 1304
  { 0x8, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVLUXSEG8EI64_V_M8_M1_MASK }, // 1305
  { 0x8, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVLUXSEG8EI64_V_M1_MF8_MASK }, // 1306
  { 0x8, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVLUXSEG8EI64_V_M1_MF4_MASK }, // 1307
  { 0x8, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVLUXSEG8EI64_V_M2_MF4_MASK }, // 1308
  { 0x8, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVLUXSEG8EI64_V_M1_MF2_MASK }, // 1309
  { 0x8, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVLUXSEG8EI64_V_M2_MF2_MASK }, // 1310
  { 0x8, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVLUXSEG8EI64_V_M4_MF2_MASK }, // 1311
  { 0x8, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVLOXSEG8EI8_V_M1_M1_MASK }, // 1312
  { 0x8, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVLOXSEG8EI8_V_MF8_M1_MASK }, // 1313
  { 0x8, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVLOXSEG8EI8_V_MF4_M1_MASK }, // 1314
  { 0x8, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVLOXSEG8EI8_V_MF2_M1_MASK }, // 1315
  { 0x8, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVLOXSEG8EI8_V_MF8_MF8_MASK }, // 1316
  { 0x8, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVLOXSEG8EI8_V_MF8_MF4_MASK }, // 1317
  { 0x8, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVLOXSEG8EI8_V_MF4_MF4_MASK }, // 1318
  { 0x8, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVLOXSEG8EI8_V_MF8_MF2_MASK }, // 1319
  { 0x8, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVLOXSEG8EI8_V_MF4_MF2_MASK }, // 1320
  { 0x8, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVLOXSEG8EI8_V_MF2_MF2_MASK }, // 1321
  { 0x8, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVLOXSEG8EI16_V_M1_M1_MASK }, // 1322
  { 0x8, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVLOXSEG8EI16_V_M2_M1_MASK }, // 1323
  { 0x8, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVLOXSEG8EI16_V_MF4_M1_MASK }, // 1324
  { 0x8, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVLOXSEG8EI16_V_MF2_M1_MASK }, // 1325
  { 0x8, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVLOXSEG8EI16_V_MF4_MF8_MASK }, // 1326
  { 0x8, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVLOXSEG8EI16_V_MF4_MF4_MASK }, // 1327
  { 0x8, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVLOXSEG8EI16_V_MF2_MF4_MASK }, // 1328
  { 0x8, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVLOXSEG8EI16_V_M1_MF2_MASK }, // 1329
  { 0x8, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVLOXSEG8EI16_V_MF4_MF2_MASK }, // 1330
  { 0x8, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVLOXSEG8EI16_V_MF2_MF2_MASK }, // 1331
  { 0x8, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVLOXSEG8EI32_V_M1_M1_MASK }, // 1332
  { 0x8, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVLOXSEG8EI32_V_M2_M1_MASK }, // 1333
  { 0x8, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVLOXSEG8EI32_V_M4_M1_MASK }, // 1334
  { 0x8, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVLOXSEG8EI32_V_MF2_M1_MASK }, // 1335
  { 0x8, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVLOXSEG8EI32_V_MF2_MF8_MASK }, // 1336
  { 0x8, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVLOXSEG8EI32_V_M1_MF4_MASK }, // 1337
  { 0x8, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVLOXSEG8EI32_V_MF2_MF4_MASK }, // 1338
  { 0x8, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVLOXSEG8EI32_V_M1_MF2_MASK }, // 1339
  { 0x8, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVLOXSEG8EI32_V_M2_MF2_MASK }, // 1340
  { 0x8, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVLOXSEG8EI32_V_MF2_MF2_MASK }, // 1341
  { 0x8, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVLOXSEG8EI64_V_M1_M1_MASK }, // 1342
  { 0x8, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVLOXSEG8EI64_V_M2_M1_MASK }, // 1343
  { 0x8, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVLOXSEG8EI64_V_M4_M1_MASK }, // 1344
  { 0x8, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVLOXSEG8EI64_V_M8_M1_MASK }, // 1345
  { 0x8, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVLOXSEG8EI64_V_M1_MF8_MASK }, // 1346
  { 0x8, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVLOXSEG8EI64_V_M1_MF4_MASK }, // 1347
  { 0x8, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVLOXSEG8EI64_V_M2_MF4_MASK }, // 1348
  { 0x8, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVLOXSEG8EI64_V_M1_MF2_MASK }, // 1349
  { 0x8, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVLOXSEG8EI64_V_M2_MF2_MASK }, // 1350
  { 0x8, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVLOXSEG8EI64_V_M4_MF2_MASK }, // 1351
 };

const VLXSEGPseudo *getVLXSEGPseudo(uint8_t NF, uint8_t Masked, uint8_t Ordered, uint8_t Log2SEW, uint8_t LMUL, uint8_t IndexLMUL) {
  struct KeyType {
    uint8_t NF;
    uint8_t Masked;
    uint8_t Ordered;
    uint8_t Log2SEW;
    uint8_t LMUL;
    uint8_t IndexLMUL;
  };
  KeyType Key = {NF, Masked, Ordered, Log2SEW, LMUL, IndexLMUL};
  auto Table = makeArrayRef(RISCVVLXSEGTable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const VLXSEGPseudo &LHS, const KeyType &RHS) {
      if (LHS.NF < RHS.NF)
        return true;
      if (LHS.NF > RHS.NF)
        return false;
      if (LHS.Masked < RHS.Masked)
        return true;
      if (LHS.Masked > RHS.Masked)
        return false;
      if (LHS.Ordered < RHS.Ordered)
        return true;
      if (LHS.Ordered > RHS.Ordered)
        return false;
      if (LHS.Log2SEW < RHS.Log2SEW)
        return true;
      if (LHS.Log2SEW > RHS.Log2SEW)
        return false;
      if (LHS.LMUL < RHS.LMUL)
        return true;
      if (LHS.LMUL > RHS.LMUL)
        return false;
      if (LHS.IndexLMUL < RHS.IndexLMUL)
        return true;
      if (LHS.IndexLMUL > RHS.IndexLMUL)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.NF != Idx->NF ||
      Key.Masked != Idx->Masked ||
      Key.Ordered != Idx->Ordered ||
      Key.Log2SEW != Idx->Log2SEW ||
      Key.LMUL != Idx->LMUL ||
      Key.IndexLMUL != Idx->IndexLMUL)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_RISCVVLXTable_DECL
const VLX_VSXPseudo *getVLXPseudo(uint8_t Masked, uint8_t IsTU, uint8_t Ordered, uint8_t Log2SEW, uint8_t LMUL, uint8_t IndexLMUL);
#endif

#ifdef GET_RISCVVLXTable_IMPL
constexpr VLX_VSXPseudo RISCVVLXTable[] = {
  { 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVLUXEI8_V_M1_M1 }, // 0
  { 0x0, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVLUXEI8_V_MF8_M1 }, // 1
  { 0x0, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVLUXEI8_V_MF4_M1 }, // 2
  { 0x0, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVLUXEI8_V_MF2_M1 }, // 3
  { 0x0, 0x0, 0x0, 0x3, 0x1, 0x0, PseudoVLUXEI8_V_M1_M2 }, // 4
  { 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, PseudoVLUXEI8_V_M2_M2 }, // 5
  { 0x0, 0x0, 0x0, 0x3, 0x1, 0x6, PseudoVLUXEI8_V_MF4_M2 }, // 6
  { 0x0, 0x0, 0x0, 0x3, 0x1, 0x7, PseudoVLUXEI8_V_MF2_M2 }, // 7
  { 0x0, 0x0, 0x0, 0x3, 0x2, 0x0, PseudoVLUXEI8_V_M1_M4 }, // 8
  { 0x0, 0x0, 0x0, 0x3, 0x2, 0x1, PseudoVLUXEI8_V_M2_M4 }, // 9
  { 0x0, 0x0, 0x0, 0x3, 0x2, 0x2, PseudoVLUXEI8_V_M4_M4 }, // 10
  { 0x0, 0x0, 0x0, 0x3, 0x2, 0x7, PseudoVLUXEI8_V_MF2_M4 }, // 11
  { 0x0, 0x0, 0x0, 0x3, 0x3, 0x0, PseudoVLUXEI8_V_M1_M8 }, // 12
  { 0x0, 0x0, 0x0, 0x3, 0x3, 0x1, PseudoVLUXEI8_V_M2_M8 }, // 13
  { 0x0, 0x0, 0x0, 0x3, 0x3, 0x2, PseudoVLUXEI8_V_M4_M8 }, // 14
  { 0x0, 0x0, 0x0, 0x3, 0x3, 0x3, PseudoVLUXEI8_V_M8_M8 }, // 15
  { 0x0, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVLUXEI8_V_MF8_MF8 }, // 16
  { 0x0, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVLUXEI8_V_MF8_MF4 }, // 17
  { 0x0, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVLUXEI8_V_MF4_MF4 }, // 18
  { 0x0, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVLUXEI8_V_MF8_MF2 }, // 19
  { 0x0, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVLUXEI8_V_MF4_MF2 }, // 20
  { 0x0, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVLUXEI8_V_MF2_MF2 }, // 21
  { 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVLUXEI16_V_M1_M1 }, // 22
  { 0x0, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVLUXEI16_V_M2_M1 }, // 23
  { 0x0, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVLUXEI16_V_MF4_M1 }, // 24
  { 0x0, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVLUXEI16_V_MF2_M1 }, // 25
  { 0x0, 0x0, 0x0, 0x4, 0x1, 0x0, PseudoVLUXEI16_V_M1_M2 }, // 26
  { 0x0, 0x0, 0x0, 0x4, 0x1, 0x1, PseudoVLUXEI16_V_M2_M2 }, // 27
  { 0x0, 0x0, 0x0, 0x4, 0x1, 0x2, PseudoVLUXEI16_V_M4_M2 }, // 28
  { 0x0, 0x0, 0x0, 0x4, 0x1, 0x7, PseudoVLUXEI16_V_MF2_M2 }, // 29
  { 0x0, 0x0, 0x0, 0x4, 0x2, 0x0, PseudoVLUXEI16_V_M1_M4 }, // 30
  { 0x0, 0x0, 0x0, 0x4, 0x2, 0x1, PseudoVLUXEI16_V_M2_M4 }, // 31
  { 0x0, 0x0, 0x0, 0x4, 0x2, 0x2, PseudoVLUXEI16_V_M4_M4 }, // 32
  { 0x0, 0x0, 0x0, 0x4, 0x2, 0x3, PseudoVLUXEI16_V_M8_M4 }, // 33
  { 0x0, 0x0, 0x0, 0x4, 0x3, 0x1, PseudoVLUXEI16_V_M2_M8 }, // 34
  { 0x0, 0x0, 0x0, 0x4, 0x3, 0x2, PseudoVLUXEI16_V_M4_M8 }, // 35
  { 0x0, 0x0, 0x0, 0x4, 0x3, 0x3, PseudoVLUXEI16_V_M8_M8 }, // 36
  { 0x0, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVLUXEI16_V_MF4_MF8 }, // 37
  { 0x0, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVLUXEI16_V_MF4_MF4 }, // 38
  { 0x0, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVLUXEI16_V_MF2_MF4 }, // 39
  { 0x0, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVLUXEI16_V_M1_MF2 }, // 40
  { 0x0, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVLUXEI16_V_MF4_MF2 }, // 41
  { 0x0, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVLUXEI16_V_MF2_MF2 }, // 42
  { 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVLUXEI32_V_M1_M1 }, // 43
  { 0x0, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVLUXEI32_V_M2_M1 }, // 44
  { 0x0, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVLUXEI32_V_M4_M1 }, // 45
  { 0x0, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVLUXEI32_V_MF2_M1 }, // 46
  { 0x0, 0x0, 0x0, 0x5, 0x1, 0x0, PseudoVLUXEI32_V_M1_M2 }, // 47
  { 0x0, 0x0, 0x0, 0x5, 0x1, 0x1, PseudoVLUXEI32_V_M2_M2 }, // 48
  { 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, PseudoVLUXEI32_V_M4_M2 }, // 49
  { 0x0, 0x0, 0x0, 0x5, 0x1, 0x3, PseudoVLUXEI32_V_M8_M2 }, // 50
  { 0x0, 0x0, 0x0, 0x5, 0x2, 0x1, PseudoVLUXEI32_V_M2_M4 }, // 51
  { 0x0, 0x0, 0x0, 0x5, 0x2, 0x2, PseudoVLUXEI32_V_M4_M4 }, // 52
  { 0x0, 0x0, 0x0, 0x5, 0x2, 0x3, PseudoVLUXEI32_V_M8_M4 }, // 53
  { 0x0, 0x0, 0x0, 0x5, 0x3, 0x2, PseudoVLUXEI32_V_M4_M8 }, // 54
  { 0x0, 0x0, 0x0, 0x5, 0x3, 0x3, PseudoVLUXEI32_V_M8_M8 }, // 55
  { 0x0, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVLUXEI32_V_MF2_MF8 }, // 56
  { 0x0, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVLUXEI32_V_M1_MF4 }, // 57
  { 0x0, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVLUXEI32_V_MF2_MF4 }, // 58
  { 0x0, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVLUXEI32_V_M1_MF2 }, // 59
  { 0x0, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVLUXEI32_V_M2_MF2 }, // 60
  { 0x0, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVLUXEI32_V_MF2_MF2 }, // 61
  { 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVLUXEI64_V_M1_M1 }, // 62
  { 0x0, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVLUXEI64_V_M2_M1 }, // 63
  { 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVLUXEI64_V_M4_M1 }, // 64
  { 0x0, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVLUXEI64_V_M8_M1 }, // 65
  { 0x0, 0x0, 0x0, 0x6, 0x1, 0x1, PseudoVLUXEI64_V_M2_M2 }, // 66
  { 0x0, 0x0, 0x0, 0x6, 0x1, 0x2, PseudoVLUXEI64_V_M4_M2 }, // 67
  { 0x0, 0x0, 0x0, 0x6, 0x1, 0x3, PseudoVLUXEI64_V_M8_M2 }, // 68
  { 0x0, 0x0, 0x0, 0x6, 0x2, 0x2, PseudoVLUXEI64_V_M4_M4 }, // 69
  { 0x0, 0x0, 0x0, 0x6, 0x2, 0x3, PseudoVLUXEI64_V_M8_M4 }, // 70
  { 0x0, 0x0, 0x0, 0x6, 0x3, 0x3, PseudoVLUXEI64_V_M8_M8 }, // 71
  { 0x0, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVLUXEI64_V_M1_MF8 }, // 72
  { 0x0, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVLUXEI64_V_M1_MF4 }, // 73
  { 0x0, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVLUXEI64_V_M2_MF4 }, // 74
  { 0x0, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVLUXEI64_V_M1_MF2 }, // 75
  { 0x0, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVLUXEI64_V_M2_MF2 }, // 76
  { 0x0, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVLUXEI64_V_M4_MF2 }, // 77
  { 0x0, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVLOXEI8_V_M1_M1 }, // 78
  { 0x0, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVLOXEI8_V_MF8_M1 }, // 79
  { 0x0, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVLOXEI8_V_MF4_M1 }, // 80
  { 0x0, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVLOXEI8_V_MF2_M1 }, // 81
  { 0x0, 0x0, 0x1, 0x3, 0x1, 0x0, PseudoVLOXEI8_V_M1_M2 }, // 82
  { 0x0, 0x0, 0x1, 0x3, 0x1, 0x1, PseudoVLOXEI8_V_M2_M2 }, // 83
  { 0x0, 0x0, 0x1, 0x3, 0x1, 0x6, PseudoVLOXEI8_V_MF4_M2 }, // 84
  { 0x0, 0x0, 0x1, 0x3, 0x1, 0x7, PseudoVLOXEI8_V_MF2_M2 }, // 85
  { 0x0, 0x0, 0x1, 0x3, 0x2, 0x0, PseudoVLOXEI8_V_M1_M4 }, // 86
  { 0x0, 0x0, 0x1, 0x3, 0x2, 0x1, PseudoVLOXEI8_V_M2_M4 }, // 87
  { 0x0, 0x0, 0x1, 0x3, 0x2, 0x2, PseudoVLOXEI8_V_M4_M4 }, // 88
  { 0x0, 0x0, 0x1, 0x3, 0x2, 0x7, PseudoVLOXEI8_V_MF2_M4 }, // 89
  { 0x0, 0x0, 0x1, 0x3, 0x3, 0x0, PseudoVLOXEI8_V_M1_M8 }, // 90
  { 0x0, 0x0, 0x1, 0x3, 0x3, 0x1, PseudoVLOXEI8_V_M2_M8 }, // 91
  { 0x0, 0x0, 0x1, 0x3, 0x3, 0x2, PseudoVLOXEI8_V_M4_M8 }, // 92
  { 0x0, 0x0, 0x1, 0x3, 0x3, 0x3, PseudoVLOXEI8_V_M8_M8 }, // 93
  { 0x0, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVLOXEI8_V_MF8_MF8 }, // 94
  { 0x0, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVLOXEI8_V_MF8_MF4 }, // 95
  { 0x0, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVLOXEI8_V_MF4_MF4 }, // 96
  { 0x0, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVLOXEI8_V_MF8_MF2 }, // 97
  { 0x0, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVLOXEI8_V_MF4_MF2 }, // 98
  { 0x0, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVLOXEI8_V_MF2_MF2 }, // 99
  { 0x0, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVLOXEI16_V_M1_M1 }, // 100
  { 0x0, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVLOXEI16_V_M2_M1 }, // 101
  { 0x0, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVLOXEI16_V_MF4_M1 }, // 102
  { 0x0, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVLOXEI16_V_MF2_M1 }, // 103
  { 0x0, 0x0, 0x1, 0x4, 0x1, 0x0, PseudoVLOXEI16_V_M1_M2 }, // 104
  { 0x0, 0x0, 0x1, 0x4, 0x1, 0x1, PseudoVLOXEI16_V_M2_M2 }, // 105
  { 0x0, 0x0, 0x1, 0x4, 0x1, 0x2, PseudoVLOXEI16_V_M4_M2 }, // 106
  { 0x0, 0x0, 0x1, 0x4, 0x1, 0x7, PseudoVLOXEI16_V_MF2_M2 }, // 107
  { 0x0, 0x0, 0x1, 0x4, 0x2, 0x0, PseudoVLOXEI16_V_M1_M4 }, // 108
  { 0x0, 0x0, 0x1, 0x4, 0x2, 0x1, PseudoVLOXEI16_V_M2_M4 }, // 109
  { 0x0, 0x0, 0x1, 0x4, 0x2, 0x2, PseudoVLOXEI16_V_M4_M4 }, // 110
  { 0x0, 0x0, 0x1, 0x4, 0x2, 0x3, PseudoVLOXEI16_V_M8_M4 }, // 111
  { 0x0, 0x0, 0x1, 0x4, 0x3, 0x1, PseudoVLOXEI16_V_M2_M8 }, // 112
  { 0x0, 0x0, 0x1, 0x4, 0x3, 0x2, PseudoVLOXEI16_V_M4_M8 }, // 113
  { 0x0, 0x0, 0x1, 0x4, 0x3, 0x3, PseudoVLOXEI16_V_M8_M8 }, // 114
  { 0x0, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVLOXEI16_V_MF4_MF8 }, // 115
  { 0x0, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVLOXEI16_V_MF4_MF4 }, // 116
  { 0x0, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVLOXEI16_V_MF2_MF4 }, // 117
  { 0x0, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVLOXEI16_V_M1_MF2 }, // 118
  { 0x0, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVLOXEI16_V_MF4_MF2 }, // 119
  { 0x0, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVLOXEI16_V_MF2_MF2 }, // 120
  { 0x0, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVLOXEI32_V_M1_M1 }, // 121
  { 0x0, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVLOXEI32_V_M2_M1 }, // 122
  { 0x0, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVLOXEI32_V_M4_M1 }, // 123
  { 0x0, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVLOXEI32_V_MF2_M1 }, // 124
  { 0x0, 0x0, 0x1, 0x5, 0x1, 0x0, PseudoVLOXEI32_V_M1_M2 }, // 125
  { 0x0, 0x0, 0x1, 0x5, 0x1, 0x1, PseudoVLOXEI32_V_M2_M2 }, // 126
  { 0x0, 0x0, 0x1, 0x5, 0x1, 0x2, PseudoVLOXEI32_V_M4_M2 }, // 127
  { 0x0, 0x0, 0x1, 0x5, 0x1, 0x3, PseudoVLOXEI32_V_M8_M2 }, // 128
  { 0x0, 0x0, 0x1, 0x5, 0x2, 0x1, PseudoVLOXEI32_V_M2_M4 }, // 129
  { 0x0, 0x0, 0x1, 0x5, 0x2, 0x2, PseudoVLOXEI32_V_M4_M4 }, // 130
  { 0x0, 0x0, 0x1, 0x5, 0x2, 0x3, PseudoVLOXEI32_V_M8_M4 }, // 131
  { 0x0, 0x0, 0x1, 0x5, 0x3, 0x2, PseudoVLOXEI32_V_M4_M8 }, // 132
  { 0x0, 0x0, 0x1, 0x5, 0x3, 0x3, PseudoVLOXEI32_V_M8_M8 }, // 133
  { 0x0, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVLOXEI32_V_MF2_MF8 }, // 134
  { 0x0, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVLOXEI32_V_M1_MF4 }, // 135
  { 0x0, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVLOXEI32_V_MF2_MF4 }, // 136
  { 0x0, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVLOXEI32_V_M1_MF2 }, // 137
  { 0x0, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVLOXEI32_V_M2_MF2 }, // 138
  { 0x0, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVLOXEI32_V_MF2_MF2 }, // 139
  { 0x0, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVLOXEI64_V_M1_M1 }, // 140
  { 0x0, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVLOXEI64_V_M2_M1 }, // 141
  { 0x0, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVLOXEI64_V_M4_M1 }, // 142
  { 0x0, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVLOXEI64_V_M8_M1 }, // 143
  { 0x0, 0x0, 0x1, 0x6, 0x1, 0x1, PseudoVLOXEI64_V_M2_M2 }, // 144
  { 0x0, 0x0, 0x1, 0x6, 0x1, 0x2, PseudoVLOXEI64_V_M4_M2 }, // 145
  { 0x0, 0x0, 0x1, 0x6, 0x1, 0x3, PseudoVLOXEI64_V_M8_M2 }, // 146
  { 0x0, 0x0, 0x1, 0x6, 0x2, 0x2, PseudoVLOXEI64_V_M4_M4 }, // 147
  { 0x0, 0x0, 0x1, 0x6, 0x2, 0x3, PseudoVLOXEI64_V_M8_M4 }, // 148
  { 0x0, 0x0, 0x1, 0x6, 0x3, 0x3, PseudoVLOXEI64_V_M8_M8 }, // 149
  { 0x0, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVLOXEI64_V_M1_MF8 }, // 150
  { 0x0, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVLOXEI64_V_M1_MF4 }, // 151
  { 0x0, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVLOXEI64_V_M2_MF4 }, // 152
  { 0x0, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVLOXEI64_V_M1_MF2 }, // 153
  { 0x0, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVLOXEI64_V_M2_MF2 }, // 154
  { 0x0, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVLOXEI64_V_M4_MF2 }, // 155
  { 0x0, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVLUXEI8_V_M1_M1_TU }, // 156
  { 0x0, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVLUXEI8_V_MF8_M1_TU }, // 157
  { 0x0, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVLUXEI8_V_MF4_M1_TU }, // 158
  { 0x0, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVLUXEI8_V_MF2_M1_TU }, // 159
  { 0x0, 0x1, 0x0, 0x3, 0x1, 0x0, PseudoVLUXEI8_V_M1_M2_TU }, // 160
  { 0x0, 0x1, 0x0, 0x3, 0x1, 0x1, PseudoVLUXEI8_V_M2_M2_TU }, // 161
  { 0x0, 0x1, 0x0, 0x3, 0x1, 0x6, PseudoVLUXEI8_V_MF4_M2_TU }, // 162
  { 0x0, 0x1, 0x0, 0x3, 0x1, 0x7, PseudoVLUXEI8_V_MF2_M2_TU }, // 163
  { 0x0, 0x1, 0x0, 0x3, 0x2, 0x0, PseudoVLUXEI8_V_M1_M4_TU }, // 164
  { 0x0, 0x1, 0x0, 0x3, 0x2, 0x1, PseudoVLUXEI8_V_M2_M4_TU }, // 165
  { 0x0, 0x1, 0x0, 0x3, 0x2, 0x2, PseudoVLUXEI8_V_M4_M4_TU }, // 166
  { 0x0, 0x1, 0x0, 0x3, 0x2, 0x7, PseudoVLUXEI8_V_MF2_M4_TU }, // 167
  { 0x0, 0x1, 0x0, 0x3, 0x3, 0x0, PseudoVLUXEI8_V_M1_M8_TU }, // 168
  { 0x0, 0x1, 0x0, 0x3, 0x3, 0x1, PseudoVLUXEI8_V_M2_M8_TU }, // 169
  { 0x0, 0x1, 0x0, 0x3, 0x3, 0x2, PseudoVLUXEI8_V_M4_M8_TU }, // 170
  { 0x0, 0x1, 0x0, 0x3, 0x3, 0x3, PseudoVLUXEI8_V_M8_M8_TU }, // 171
  { 0x0, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVLUXEI8_V_MF8_MF8_TU }, // 172
  { 0x0, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVLUXEI8_V_MF8_MF4_TU }, // 173
  { 0x0, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVLUXEI8_V_MF4_MF4_TU }, // 174
  { 0x0, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVLUXEI8_V_MF8_MF2_TU }, // 175
  { 0x0, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVLUXEI8_V_MF4_MF2_TU }, // 176
  { 0x0, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVLUXEI8_V_MF2_MF2_TU }, // 177
  { 0x0, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVLUXEI16_V_M1_M1_TU }, // 178
  { 0x0, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVLUXEI16_V_M2_M1_TU }, // 179
  { 0x0, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVLUXEI16_V_MF4_M1_TU }, // 180
  { 0x0, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVLUXEI16_V_MF2_M1_TU }, // 181
  { 0x0, 0x1, 0x0, 0x4, 0x1, 0x0, PseudoVLUXEI16_V_M1_M2_TU }, // 182
  { 0x0, 0x1, 0x0, 0x4, 0x1, 0x1, PseudoVLUXEI16_V_M2_M2_TU }, // 183
  { 0x0, 0x1, 0x0, 0x4, 0x1, 0x2, PseudoVLUXEI16_V_M4_M2_TU }, // 184
  { 0x0, 0x1, 0x0, 0x4, 0x1, 0x7, PseudoVLUXEI16_V_MF2_M2_TU }, // 185
  { 0x0, 0x1, 0x0, 0x4, 0x2, 0x0, PseudoVLUXEI16_V_M1_M4_TU }, // 186
  { 0x0, 0x1, 0x0, 0x4, 0x2, 0x1, PseudoVLUXEI16_V_M2_M4_TU }, // 187
  { 0x0, 0x1, 0x0, 0x4, 0x2, 0x2, PseudoVLUXEI16_V_M4_M4_TU }, // 188
  { 0x0, 0x1, 0x0, 0x4, 0x2, 0x3, PseudoVLUXEI16_V_M8_M4_TU }, // 189
  { 0x0, 0x1, 0x0, 0x4, 0x3, 0x1, PseudoVLUXEI16_V_M2_M8_TU }, // 190
  { 0x0, 0x1, 0x0, 0x4, 0x3, 0x2, PseudoVLUXEI16_V_M4_M8_TU }, // 191
  { 0x0, 0x1, 0x0, 0x4, 0x3, 0x3, PseudoVLUXEI16_V_M8_M8_TU }, // 192
  { 0x0, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVLUXEI16_V_MF4_MF8_TU }, // 193
  { 0x0, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVLUXEI16_V_MF4_MF4_TU }, // 194
  { 0x0, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVLUXEI16_V_MF2_MF4_TU }, // 195
  { 0x0, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVLUXEI16_V_M1_MF2_TU }, // 196
  { 0x0, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVLUXEI16_V_MF4_MF2_TU }, // 197
  { 0x0, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVLUXEI16_V_MF2_MF2_TU }, // 198
  { 0x0, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVLUXEI32_V_M1_M1_TU }, // 199
  { 0x0, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVLUXEI32_V_M2_M1_TU }, // 200
  { 0x0, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVLUXEI32_V_M4_M1_TU }, // 201
  { 0x0, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVLUXEI32_V_MF2_M1_TU }, // 202
  { 0x0, 0x1, 0x0, 0x5, 0x1, 0x0, PseudoVLUXEI32_V_M1_M2_TU }, // 203
  { 0x0, 0x1, 0x0, 0x5, 0x1, 0x1, PseudoVLUXEI32_V_M2_M2_TU }, // 204
  { 0x0, 0x1, 0x0, 0x5, 0x1, 0x2, PseudoVLUXEI32_V_M4_M2_TU }, // 205
  { 0x0, 0x1, 0x0, 0x5, 0x1, 0x3, PseudoVLUXEI32_V_M8_M2_TU }, // 206
  { 0x0, 0x1, 0x0, 0x5, 0x2, 0x1, PseudoVLUXEI32_V_M2_M4_TU }, // 207
  { 0x0, 0x1, 0x0, 0x5, 0x2, 0x2, PseudoVLUXEI32_V_M4_M4_TU }, // 208
  { 0x0, 0x1, 0x0, 0x5, 0x2, 0x3, PseudoVLUXEI32_V_M8_M4_TU }, // 209
  { 0x0, 0x1, 0x0, 0x5, 0x3, 0x2, PseudoVLUXEI32_V_M4_M8_TU }, // 210
  { 0x0, 0x1, 0x0, 0x5, 0x3, 0x3, PseudoVLUXEI32_V_M8_M8_TU }, // 211
  { 0x0, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVLUXEI32_V_MF2_MF8_TU }, // 212
  { 0x0, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVLUXEI32_V_M1_MF4_TU }, // 213
  { 0x0, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVLUXEI32_V_MF2_MF4_TU }, // 214
  { 0x0, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVLUXEI32_V_M1_MF2_TU }, // 215
  { 0x0, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVLUXEI32_V_M2_MF2_TU }, // 216
  { 0x0, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVLUXEI32_V_MF2_MF2_TU }, // 217
  { 0x0, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVLUXEI64_V_M1_M1_TU }, // 218
  { 0x0, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVLUXEI64_V_M2_M1_TU }, // 219
  { 0x0, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVLUXEI64_V_M4_M1_TU }, // 220
  { 0x0, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVLUXEI64_V_M8_M1_TU }, // 221
  { 0x0, 0x1, 0x0, 0x6, 0x1, 0x1, PseudoVLUXEI64_V_M2_M2_TU }, // 222
  { 0x0, 0x1, 0x0, 0x6, 0x1, 0x2, PseudoVLUXEI64_V_M4_M2_TU }, // 223
  { 0x0, 0x1, 0x0, 0x6, 0x1, 0x3, PseudoVLUXEI64_V_M8_M2_TU }, // 224
  { 0x0, 0x1, 0x0, 0x6, 0x2, 0x2, PseudoVLUXEI64_V_M4_M4_TU }, // 225
  { 0x0, 0x1, 0x0, 0x6, 0x2, 0x3, PseudoVLUXEI64_V_M8_M4_TU }, // 226
  { 0x0, 0x1, 0x0, 0x6, 0x3, 0x3, PseudoVLUXEI64_V_M8_M8_TU }, // 227
  { 0x0, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVLUXEI64_V_M1_MF8_TU }, // 228
  { 0x0, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVLUXEI64_V_M1_MF4_TU }, // 229
  { 0x0, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVLUXEI64_V_M2_MF4_TU }, // 230
  { 0x0, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVLUXEI64_V_M1_MF2_TU }, // 231
  { 0x0, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVLUXEI64_V_M2_MF2_TU }, // 232
  { 0x0, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVLUXEI64_V_M4_MF2_TU }, // 233
  { 0x0, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVLOXEI8_V_M1_M1_TU }, // 234
  { 0x0, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVLOXEI8_V_MF8_M1_TU }, // 235
  { 0x0, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVLOXEI8_V_MF4_M1_TU }, // 236
  { 0x0, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVLOXEI8_V_MF2_M1_TU }, // 237
  { 0x0, 0x1, 0x1, 0x3, 0x1, 0x0, PseudoVLOXEI8_V_M1_M2_TU }, // 238
  { 0x0, 0x1, 0x1, 0x3, 0x1, 0x1, PseudoVLOXEI8_V_M2_M2_TU }, // 239
  { 0x0, 0x1, 0x1, 0x3, 0x1, 0x6, PseudoVLOXEI8_V_MF4_M2_TU }, // 240
  { 0x0, 0x1, 0x1, 0x3, 0x1, 0x7, PseudoVLOXEI8_V_MF2_M2_TU }, // 241
  { 0x0, 0x1, 0x1, 0x3, 0x2, 0x0, PseudoVLOXEI8_V_M1_M4_TU }, // 242
  { 0x0, 0x1, 0x1, 0x3, 0x2, 0x1, PseudoVLOXEI8_V_M2_M4_TU }, // 243
  { 0x0, 0x1, 0x1, 0x3, 0x2, 0x2, PseudoVLOXEI8_V_M4_M4_TU }, // 244
  { 0x0, 0x1, 0x1, 0x3, 0x2, 0x7, PseudoVLOXEI8_V_MF2_M4_TU }, // 245
  { 0x0, 0x1, 0x1, 0x3, 0x3, 0x0, PseudoVLOXEI8_V_M1_M8_TU }, // 246
  { 0x0, 0x1, 0x1, 0x3, 0x3, 0x1, PseudoVLOXEI8_V_M2_M8_TU }, // 247
  { 0x0, 0x1, 0x1, 0x3, 0x3, 0x2, PseudoVLOXEI8_V_M4_M8_TU }, // 248
  { 0x0, 0x1, 0x1, 0x3, 0x3, 0x3, PseudoVLOXEI8_V_M8_M8_TU }, // 249
  { 0x0, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVLOXEI8_V_MF8_MF8_TU }, // 250
  { 0x0, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVLOXEI8_V_MF8_MF4_TU }, // 251
  { 0x0, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVLOXEI8_V_MF4_MF4_TU }, // 252
  { 0x0, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVLOXEI8_V_MF8_MF2_TU }, // 253
  { 0x0, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVLOXEI8_V_MF4_MF2_TU }, // 254
  { 0x0, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVLOXEI8_V_MF2_MF2_TU }, // 255
  { 0x0, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVLOXEI16_V_M1_M1_TU }, // 256
  { 0x0, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVLOXEI16_V_M2_M1_TU }, // 257
  { 0x0, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVLOXEI16_V_MF4_M1_TU }, // 258
  { 0x0, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVLOXEI16_V_MF2_M1_TU }, // 259
  { 0x0, 0x1, 0x1, 0x4, 0x1, 0x0, PseudoVLOXEI16_V_M1_M2_TU }, // 260
  { 0x0, 0x1, 0x1, 0x4, 0x1, 0x1, PseudoVLOXEI16_V_M2_M2_TU }, // 261
  { 0x0, 0x1, 0x1, 0x4, 0x1, 0x2, PseudoVLOXEI16_V_M4_M2_TU }, // 262
  { 0x0, 0x1, 0x1, 0x4, 0x1, 0x7, PseudoVLOXEI16_V_MF2_M2_TU }, // 263
  { 0x0, 0x1, 0x1, 0x4, 0x2, 0x0, PseudoVLOXEI16_V_M1_M4_TU }, // 264
  { 0x0, 0x1, 0x1, 0x4, 0x2, 0x1, PseudoVLOXEI16_V_M2_M4_TU }, // 265
  { 0x0, 0x1, 0x1, 0x4, 0x2, 0x2, PseudoVLOXEI16_V_M4_M4_TU }, // 266
  { 0x0, 0x1, 0x1, 0x4, 0x2, 0x3, PseudoVLOXEI16_V_M8_M4_TU }, // 267
  { 0x0, 0x1, 0x1, 0x4, 0x3, 0x1, PseudoVLOXEI16_V_M2_M8_TU }, // 268
  { 0x0, 0x1, 0x1, 0x4, 0x3, 0x2, PseudoVLOXEI16_V_M4_M8_TU }, // 269
  { 0x0, 0x1, 0x1, 0x4, 0x3, 0x3, PseudoVLOXEI16_V_M8_M8_TU }, // 270
  { 0x0, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVLOXEI16_V_MF4_MF8_TU }, // 271
  { 0x0, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVLOXEI16_V_MF4_MF4_TU }, // 272
  { 0x0, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVLOXEI16_V_MF2_MF4_TU }, // 273
  { 0x0, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVLOXEI16_V_M1_MF2_TU }, // 274
  { 0x0, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVLOXEI16_V_MF4_MF2_TU }, // 275
  { 0x0, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVLOXEI16_V_MF2_MF2_TU }, // 276
  { 0x0, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVLOXEI32_V_M1_M1_TU }, // 277
  { 0x0, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVLOXEI32_V_M2_M1_TU }, // 278
  { 0x0, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVLOXEI32_V_M4_M1_TU }, // 279
  { 0x0, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVLOXEI32_V_MF2_M1_TU }, // 280
  { 0x0, 0x1, 0x1, 0x5, 0x1, 0x0, PseudoVLOXEI32_V_M1_M2_TU }, // 281
  { 0x0, 0x1, 0x1, 0x5, 0x1, 0x1, PseudoVLOXEI32_V_M2_M2_TU }, // 282
  { 0x0, 0x1, 0x1, 0x5, 0x1, 0x2, PseudoVLOXEI32_V_M4_M2_TU }, // 283
  { 0x0, 0x1, 0x1, 0x5, 0x1, 0x3, PseudoVLOXEI32_V_M8_M2_TU }, // 284
  { 0x0, 0x1, 0x1, 0x5, 0x2, 0x1, PseudoVLOXEI32_V_M2_M4_TU }, // 285
  { 0x0, 0x1, 0x1, 0x5, 0x2, 0x2, PseudoVLOXEI32_V_M4_M4_TU }, // 286
  { 0x0, 0x1, 0x1, 0x5, 0x2, 0x3, PseudoVLOXEI32_V_M8_M4_TU }, // 287
  { 0x0, 0x1, 0x1, 0x5, 0x3, 0x2, PseudoVLOXEI32_V_M4_M8_TU }, // 288
  { 0x0, 0x1, 0x1, 0x5, 0x3, 0x3, PseudoVLOXEI32_V_M8_M8_TU }, // 289
  { 0x0, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVLOXEI32_V_MF2_MF8_TU }, // 290
  { 0x0, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVLOXEI32_V_M1_MF4_TU }, // 291
  { 0x0, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVLOXEI32_V_MF2_MF4_TU }, // 292
  { 0x0, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVLOXEI32_V_M1_MF2_TU }, // 293
  { 0x0, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVLOXEI32_V_M2_MF2_TU }, // 294
  { 0x0, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVLOXEI32_V_MF2_MF2_TU }, // 295
  { 0x0, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVLOXEI64_V_M1_M1_TU }, // 296
  { 0x0, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVLOXEI64_V_M2_M1_TU }, // 297
  { 0x0, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVLOXEI64_V_M4_M1_TU }, // 298
  { 0x0, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVLOXEI64_V_M8_M1_TU }, // 299
  { 0x0, 0x1, 0x1, 0x6, 0x1, 0x1, PseudoVLOXEI64_V_M2_M2_TU }, // 300
  { 0x0, 0x1, 0x1, 0x6, 0x1, 0x2, PseudoVLOXEI64_V_M4_M2_TU }, // 301
  { 0x0, 0x1, 0x1, 0x6, 0x1, 0x3, PseudoVLOXEI64_V_M8_M2_TU }, // 302
  { 0x0, 0x1, 0x1, 0x6, 0x2, 0x2, PseudoVLOXEI64_V_M4_M4_TU }, // 303
  { 0x0, 0x1, 0x1, 0x6, 0x2, 0x3, PseudoVLOXEI64_V_M8_M4_TU }, // 304
  { 0x0, 0x1, 0x1, 0x6, 0x3, 0x3, PseudoVLOXEI64_V_M8_M8_TU }, // 305
  { 0x0, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVLOXEI64_V_M1_MF8_TU }, // 306
  { 0x0, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVLOXEI64_V_M1_MF4_TU }, // 307
  { 0x0, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVLOXEI64_V_M2_MF4_TU }, // 308
  { 0x0, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVLOXEI64_V_M1_MF2_TU }, // 309
  { 0x0, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVLOXEI64_V_M2_MF2_TU }, // 310
  { 0x0, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVLOXEI64_V_M4_MF2_TU }, // 311
  { 0x1, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVLUXEI8_V_M1_M1_MASK }, // 312
  { 0x1, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVLUXEI8_V_MF8_M1_MASK }, // 313
  { 0x1, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVLUXEI8_V_MF4_M1_MASK }, // 314
  { 0x1, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVLUXEI8_V_MF2_M1_MASK }, // 315
  { 0x1, 0x1, 0x0, 0x3, 0x1, 0x0, PseudoVLUXEI8_V_M1_M2_MASK }, // 316
  { 0x1, 0x1, 0x0, 0x3, 0x1, 0x1, PseudoVLUXEI8_V_M2_M2_MASK }, // 317
  { 0x1, 0x1, 0x0, 0x3, 0x1, 0x6, PseudoVLUXEI8_V_MF4_M2_MASK }, // 318
  { 0x1, 0x1, 0x0, 0x3, 0x1, 0x7, PseudoVLUXEI8_V_MF2_M2_MASK }, // 319
  { 0x1, 0x1, 0x0, 0x3, 0x2, 0x0, PseudoVLUXEI8_V_M1_M4_MASK }, // 320
  { 0x1, 0x1, 0x0, 0x3, 0x2, 0x1, PseudoVLUXEI8_V_M2_M4_MASK }, // 321
  { 0x1, 0x1, 0x0, 0x3, 0x2, 0x2, PseudoVLUXEI8_V_M4_M4_MASK }, // 322
  { 0x1, 0x1, 0x0, 0x3, 0x2, 0x7, PseudoVLUXEI8_V_MF2_M4_MASK }, // 323
  { 0x1, 0x1, 0x0, 0x3, 0x3, 0x0, PseudoVLUXEI8_V_M1_M8_MASK }, // 324
  { 0x1, 0x1, 0x0, 0x3, 0x3, 0x1, PseudoVLUXEI8_V_M2_M8_MASK }, // 325
  { 0x1, 0x1, 0x0, 0x3, 0x3, 0x2, PseudoVLUXEI8_V_M4_M8_MASK }, // 326
  { 0x1, 0x1, 0x0, 0x3, 0x3, 0x3, PseudoVLUXEI8_V_M8_M8_MASK }, // 327
  { 0x1, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVLUXEI8_V_MF8_MF8_MASK }, // 328
  { 0x1, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVLUXEI8_V_MF8_MF4_MASK }, // 329
  { 0x1, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVLUXEI8_V_MF4_MF4_MASK }, // 330
  { 0x1, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVLUXEI8_V_MF8_MF2_MASK }, // 331
  { 0x1, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVLUXEI8_V_MF4_MF2_MASK }, // 332
  { 0x1, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVLUXEI8_V_MF2_MF2_MASK }, // 333
  { 0x1, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVLUXEI16_V_M1_M1_MASK }, // 334
  { 0x1, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVLUXEI16_V_M2_M1_MASK }, // 335
  { 0x1, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVLUXEI16_V_MF4_M1_MASK }, // 336
  { 0x1, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVLUXEI16_V_MF2_M1_MASK }, // 337
  { 0x1, 0x1, 0x0, 0x4, 0x1, 0x0, PseudoVLUXEI16_V_M1_M2_MASK }, // 338
  { 0x1, 0x1, 0x0, 0x4, 0x1, 0x1, PseudoVLUXEI16_V_M2_M2_MASK }, // 339
  { 0x1, 0x1, 0x0, 0x4, 0x1, 0x2, PseudoVLUXEI16_V_M4_M2_MASK }, // 340
  { 0x1, 0x1, 0x0, 0x4, 0x1, 0x7, PseudoVLUXEI16_V_MF2_M2_MASK }, // 341
  { 0x1, 0x1, 0x0, 0x4, 0x2, 0x0, PseudoVLUXEI16_V_M1_M4_MASK }, // 342
  { 0x1, 0x1, 0x0, 0x4, 0x2, 0x1, PseudoVLUXEI16_V_M2_M4_MASK }, // 343
  { 0x1, 0x1, 0x0, 0x4, 0x2, 0x2, PseudoVLUXEI16_V_M4_M4_MASK }, // 344
  { 0x1, 0x1, 0x0, 0x4, 0x2, 0x3, PseudoVLUXEI16_V_M8_M4_MASK }, // 345
  { 0x1, 0x1, 0x0, 0x4, 0x3, 0x1, PseudoVLUXEI16_V_M2_M8_MASK }, // 346
  { 0x1, 0x1, 0x0, 0x4, 0x3, 0x2, PseudoVLUXEI16_V_M4_M8_MASK }, // 347
  { 0x1, 0x1, 0x0, 0x4, 0x3, 0x3, PseudoVLUXEI16_V_M8_M8_MASK }, // 348
  { 0x1, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVLUXEI16_V_MF4_MF8_MASK }, // 349
  { 0x1, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVLUXEI16_V_MF4_MF4_MASK }, // 350
  { 0x1, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVLUXEI16_V_MF2_MF4_MASK }, // 351
  { 0x1, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVLUXEI16_V_M1_MF2_MASK }, // 352
  { 0x1, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVLUXEI16_V_MF4_MF2_MASK }, // 353
  { 0x1, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVLUXEI16_V_MF2_MF2_MASK }, // 354
  { 0x1, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVLUXEI32_V_M1_M1_MASK }, // 355
  { 0x1, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVLUXEI32_V_M2_M1_MASK }, // 356
  { 0x1, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVLUXEI32_V_M4_M1_MASK }, // 357
  { 0x1, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVLUXEI32_V_MF2_M1_MASK }, // 358
  { 0x1, 0x1, 0x0, 0x5, 0x1, 0x0, PseudoVLUXEI32_V_M1_M2_MASK }, // 359
  { 0x1, 0x1, 0x0, 0x5, 0x1, 0x1, PseudoVLUXEI32_V_M2_M2_MASK }, // 360
  { 0x1, 0x1, 0x0, 0x5, 0x1, 0x2, PseudoVLUXEI32_V_M4_M2_MASK }, // 361
  { 0x1, 0x1, 0x0, 0x5, 0x1, 0x3, PseudoVLUXEI32_V_M8_M2_MASK }, // 362
  { 0x1, 0x1, 0x0, 0x5, 0x2, 0x1, PseudoVLUXEI32_V_M2_M4_MASK }, // 363
  { 0x1, 0x1, 0x0, 0x5, 0x2, 0x2, PseudoVLUXEI32_V_M4_M4_MASK }, // 364
  { 0x1, 0x1, 0x0, 0x5, 0x2, 0x3, PseudoVLUXEI32_V_M8_M4_MASK }, // 365
  { 0x1, 0x1, 0x0, 0x5, 0x3, 0x2, PseudoVLUXEI32_V_M4_M8_MASK }, // 366
  { 0x1, 0x1, 0x0, 0x5, 0x3, 0x3, PseudoVLUXEI32_V_M8_M8_MASK }, // 367
  { 0x1, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVLUXEI32_V_MF2_MF8_MASK }, // 368
  { 0x1, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVLUXEI32_V_M1_MF4_MASK }, // 369
  { 0x1, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVLUXEI32_V_MF2_MF4_MASK }, // 370
  { 0x1, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVLUXEI32_V_M1_MF2_MASK }, // 371
  { 0x1, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVLUXEI32_V_M2_MF2_MASK }, // 372
  { 0x1, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVLUXEI32_V_MF2_MF2_MASK }, // 373
  { 0x1, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVLUXEI64_V_M1_M1_MASK }, // 374
  { 0x1, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVLUXEI64_V_M2_M1_MASK }, // 375
  { 0x1, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVLUXEI64_V_M4_M1_MASK }, // 376
  { 0x1, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVLUXEI64_V_M8_M1_MASK }, // 377
  { 0x1, 0x1, 0x0, 0x6, 0x1, 0x1, PseudoVLUXEI64_V_M2_M2_MASK }, // 378
  { 0x1, 0x1, 0x0, 0x6, 0x1, 0x2, PseudoVLUXEI64_V_M4_M2_MASK }, // 379
  { 0x1, 0x1, 0x0, 0x6, 0x1, 0x3, PseudoVLUXEI64_V_M8_M2_MASK }, // 380
  { 0x1, 0x1, 0x0, 0x6, 0x2, 0x2, PseudoVLUXEI64_V_M4_M4_MASK }, // 381
  { 0x1, 0x1, 0x0, 0x6, 0x2, 0x3, PseudoVLUXEI64_V_M8_M4_MASK }, // 382
  { 0x1, 0x1, 0x0, 0x6, 0x3, 0x3, PseudoVLUXEI64_V_M8_M8_MASK }, // 383
  { 0x1, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVLUXEI64_V_M1_MF8_MASK }, // 384
  { 0x1, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVLUXEI64_V_M1_MF4_MASK }, // 385
  { 0x1, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVLUXEI64_V_M2_MF4_MASK }, // 386
  { 0x1, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVLUXEI64_V_M1_MF2_MASK }, // 387
  { 0x1, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVLUXEI64_V_M2_MF2_MASK }, // 388
  { 0x1, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVLUXEI64_V_M4_MF2_MASK }, // 389
  { 0x1, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVLOXEI8_V_M1_M1_MASK }, // 390
  { 0x1, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVLOXEI8_V_MF8_M1_MASK }, // 391
  { 0x1, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVLOXEI8_V_MF4_M1_MASK }, // 392
  { 0x1, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVLOXEI8_V_MF2_M1_MASK }, // 393
  { 0x1, 0x1, 0x1, 0x3, 0x1, 0x0, PseudoVLOXEI8_V_M1_M2_MASK }, // 394
  { 0x1, 0x1, 0x1, 0x3, 0x1, 0x1, PseudoVLOXEI8_V_M2_M2_MASK }, // 395
  { 0x1, 0x1, 0x1, 0x3, 0x1, 0x6, PseudoVLOXEI8_V_MF4_M2_MASK }, // 396
  { 0x1, 0x1, 0x1, 0x3, 0x1, 0x7, PseudoVLOXEI8_V_MF2_M2_MASK }, // 397
  { 0x1, 0x1, 0x1, 0x3, 0x2, 0x0, PseudoVLOXEI8_V_M1_M4_MASK }, // 398
  { 0x1, 0x1, 0x1, 0x3, 0x2, 0x1, PseudoVLOXEI8_V_M2_M4_MASK }, // 399
  { 0x1, 0x1, 0x1, 0x3, 0x2, 0x2, PseudoVLOXEI8_V_M4_M4_MASK }, // 400
  { 0x1, 0x1, 0x1, 0x3, 0x2, 0x7, PseudoVLOXEI8_V_MF2_M4_MASK }, // 401
  { 0x1, 0x1, 0x1, 0x3, 0x3, 0x0, PseudoVLOXEI8_V_M1_M8_MASK }, // 402
  { 0x1, 0x1, 0x1, 0x3, 0x3, 0x1, PseudoVLOXEI8_V_M2_M8_MASK }, // 403
  { 0x1, 0x1, 0x1, 0x3, 0x3, 0x2, PseudoVLOXEI8_V_M4_M8_MASK }, // 404
  { 0x1, 0x1, 0x1, 0x3, 0x3, 0x3, PseudoVLOXEI8_V_M8_M8_MASK }, // 405
  { 0x1, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVLOXEI8_V_MF8_MF8_MASK }, // 406
  { 0x1, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVLOXEI8_V_MF8_MF4_MASK }, // 407
  { 0x1, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVLOXEI8_V_MF4_MF4_MASK }, // 408
  { 0x1, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVLOXEI8_V_MF8_MF2_MASK }, // 409
  { 0x1, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVLOXEI8_V_MF4_MF2_MASK }, // 410
  { 0x1, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVLOXEI8_V_MF2_MF2_MASK }, // 411
  { 0x1, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVLOXEI16_V_M1_M1_MASK }, // 412
  { 0x1, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVLOXEI16_V_M2_M1_MASK }, // 413
  { 0x1, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVLOXEI16_V_MF4_M1_MASK }, // 414
  { 0x1, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVLOXEI16_V_MF2_M1_MASK }, // 415
  { 0x1, 0x1, 0x1, 0x4, 0x1, 0x0, PseudoVLOXEI16_V_M1_M2_MASK }, // 416
  { 0x1, 0x1, 0x1, 0x4, 0x1, 0x1, PseudoVLOXEI16_V_M2_M2_MASK }, // 417
  { 0x1, 0x1, 0x1, 0x4, 0x1, 0x2, PseudoVLOXEI16_V_M4_M2_MASK }, // 418
  { 0x1, 0x1, 0x1, 0x4, 0x1, 0x7, PseudoVLOXEI16_V_MF2_M2_MASK }, // 419
  { 0x1, 0x1, 0x1, 0x4, 0x2, 0x0, PseudoVLOXEI16_V_M1_M4_MASK }, // 420
  { 0x1, 0x1, 0x1, 0x4, 0x2, 0x1, PseudoVLOXEI16_V_M2_M4_MASK }, // 421
  { 0x1, 0x1, 0x1, 0x4, 0x2, 0x2, PseudoVLOXEI16_V_M4_M4_MASK }, // 422
  { 0x1, 0x1, 0x1, 0x4, 0x2, 0x3, PseudoVLOXEI16_V_M8_M4_MASK }, // 423
  { 0x1, 0x1, 0x1, 0x4, 0x3, 0x1, PseudoVLOXEI16_V_M2_M8_MASK }, // 424
  { 0x1, 0x1, 0x1, 0x4, 0x3, 0x2, PseudoVLOXEI16_V_M4_M8_MASK }, // 425
  { 0x1, 0x1, 0x1, 0x4, 0x3, 0x3, PseudoVLOXEI16_V_M8_M8_MASK }, // 426
  { 0x1, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVLOXEI16_V_MF4_MF8_MASK }, // 427
  { 0x1, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVLOXEI16_V_MF4_MF4_MASK }, // 428
  { 0x1, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVLOXEI16_V_MF2_MF4_MASK }, // 429
  { 0x1, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVLOXEI16_V_M1_MF2_MASK }, // 430
  { 0x1, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVLOXEI16_V_MF4_MF2_MASK }, // 431
  { 0x1, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVLOXEI16_V_MF2_MF2_MASK }, // 432
  { 0x1, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVLOXEI32_V_M1_M1_MASK }, // 433
  { 0x1, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVLOXEI32_V_M2_M1_MASK }, // 434
  { 0x1, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVLOXEI32_V_M4_M1_MASK }, // 435
  { 0x1, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVLOXEI32_V_MF2_M1_MASK }, // 436
  { 0x1, 0x1, 0x1, 0x5, 0x1, 0x0, PseudoVLOXEI32_V_M1_M2_MASK }, // 437
  { 0x1, 0x1, 0x1, 0x5, 0x1, 0x1, PseudoVLOXEI32_V_M2_M2_MASK }, // 438
  { 0x1, 0x1, 0x1, 0x5, 0x1, 0x2, PseudoVLOXEI32_V_M4_M2_MASK }, // 439
  { 0x1, 0x1, 0x1, 0x5, 0x1, 0x3, PseudoVLOXEI32_V_M8_M2_MASK }, // 440
  { 0x1, 0x1, 0x1, 0x5, 0x2, 0x1, PseudoVLOXEI32_V_M2_M4_MASK }, // 441
  { 0x1, 0x1, 0x1, 0x5, 0x2, 0x2, PseudoVLOXEI32_V_M4_M4_MASK }, // 442
  { 0x1, 0x1, 0x1, 0x5, 0x2, 0x3, PseudoVLOXEI32_V_M8_M4_MASK }, // 443
  { 0x1, 0x1, 0x1, 0x5, 0x3, 0x2, PseudoVLOXEI32_V_M4_M8_MASK }, // 444
  { 0x1, 0x1, 0x1, 0x5, 0x3, 0x3, PseudoVLOXEI32_V_M8_M8_MASK }, // 445
  { 0x1, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVLOXEI32_V_MF2_MF8_MASK }, // 446
  { 0x1, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVLOXEI32_V_M1_MF4_MASK }, // 447
  { 0x1, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVLOXEI32_V_MF2_MF4_MASK }, // 448
  { 0x1, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVLOXEI32_V_M1_MF2_MASK }, // 449
  { 0x1, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVLOXEI32_V_M2_MF2_MASK }, // 450
  { 0x1, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVLOXEI32_V_MF2_MF2_MASK }, // 451
  { 0x1, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVLOXEI64_V_M1_M1_MASK }, // 452
  { 0x1, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVLOXEI64_V_M2_M1_MASK }, // 453
  { 0x1, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVLOXEI64_V_M4_M1_MASK }, // 454
  { 0x1, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVLOXEI64_V_M8_M1_MASK }, // 455
  { 0x1, 0x1, 0x1, 0x6, 0x1, 0x1, PseudoVLOXEI64_V_M2_M2_MASK }, // 456
  { 0x1, 0x1, 0x1, 0x6, 0x1, 0x2, PseudoVLOXEI64_V_M4_M2_MASK }, // 457
  { 0x1, 0x1, 0x1, 0x6, 0x1, 0x3, PseudoVLOXEI64_V_M8_M2_MASK }, // 458
  { 0x1, 0x1, 0x1, 0x6, 0x2, 0x2, PseudoVLOXEI64_V_M4_M4_MASK }, // 459
  { 0x1, 0x1, 0x1, 0x6, 0x2, 0x3, PseudoVLOXEI64_V_M8_M4_MASK }, // 460
  { 0x1, 0x1, 0x1, 0x6, 0x3, 0x3, PseudoVLOXEI64_V_M8_M8_MASK }, // 461
  { 0x1, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVLOXEI64_V_M1_MF8_MASK }, // 462
  { 0x1, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVLOXEI64_V_M1_MF4_MASK }, // 463
  { 0x1, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVLOXEI64_V_M2_MF4_MASK }, // 464
  { 0x1, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVLOXEI64_V_M1_MF2_MASK }, // 465
  { 0x1, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVLOXEI64_V_M2_MF2_MASK }, // 466
  { 0x1, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVLOXEI64_V_M4_MF2_MASK }, // 467
 };

const VLX_VSXPseudo *getVLXPseudo(uint8_t Masked, uint8_t IsTU, uint8_t Ordered, uint8_t Log2SEW, uint8_t LMUL, uint8_t IndexLMUL) {
  struct KeyType {
    uint8_t Masked;
    uint8_t IsTU;
    uint8_t Ordered;
    uint8_t Log2SEW;
    uint8_t LMUL;
    uint8_t IndexLMUL;
  };
  KeyType Key = {Masked, IsTU, Ordered, Log2SEW, LMUL, IndexLMUL};
  auto Table = makeArrayRef(RISCVVLXTable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const VLX_VSXPseudo &LHS, const KeyType &RHS) {
      if (LHS.Masked < RHS.Masked)
        return true;
      if (LHS.Masked > RHS.Masked)
        return false;
      if (LHS.IsTU < RHS.IsTU)
        return true;
      if (LHS.IsTU > RHS.IsTU)
        return false;
      if (LHS.Ordered < RHS.Ordered)
        return true;
      if (LHS.Ordered > RHS.Ordered)
        return false;
      if (LHS.Log2SEW < RHS.Log2SEW)
        return true;
      if (LHS.Log2SEW > RHS.Log2SEW)
        return false;
      if (LHS.LMUL < RHS.LMUL)
        return true;
      if (LHS.LMUL > RHS.LMUL)
        return false;
      if (LHS.IndexLMUL < RHS.IndexLMUL)
        return true;
      if (LHS.IndexLMUL > RHS.IndexLMUL)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.Masked != Idx->Masked ||
      Key.IsTU != Idx->IsTU ||
      Key.Ordered != Idx->Ordered ||
      Key.Log2SEW != Idx->Log2SEW ||
      Key.LMUL != Idx->LMUL ||
      Key.IndexLMUL != Idx->IndexLMUL)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_RISCVVPseudosTable_DECL
const PseudoInfo *getPseudoInfo(unsigned Pseudo);
#endif

#ifdef GET_RISCVVPseudosTable_IMPL
constexpr PseudoInfo RISCVVPseudosTable[] = {
  { PseudoVAADDU_VV_M1, VAADDU_VV }, // 0
  { PseudoVAADDU_VV_M1_MASK, VAADDU_VV }, // 1
  { PseudoVAADDU_VV_M2, VAADDU_VV }, // 2
  { PseudoVAADDU_VV_M2_MASK, VAADDU_VV }, // 3
  { PseudoVAADDU_VV_M4, VAADDU_VV }, // 4
  { PseudoVAADDU_VV_M4_MASK, VAADDU_VV }, // 5
  { PseudoVAADDU_VV_M8, VAADDU_VV }, // 6
  { PseudoVAADDU_VV_M8_MASK, VAADDU_VV }, // 7
  { PseudoVAADDU_VV_MF2, VAADDU_VV }, // 8
  { PseudoVAADDU_VV_MF2_MASK, VAADDU_VV }, // 9
  { PseudoVAADDU_VV_MF4, VAADDU_VV }, // 10
  { PseudoVAADDU_VV_MF4_MASK, VAADDU_VV }, // 11
  { PseudoVAADDU_VV_MF8, VAADDU_VV }, // 12
  { PseudoVAADDU_VV_MF8_MASK, VAADDU_VV }, // 13
  { PseudoVAADDU_VX_M1, VAADDU_VX }, // 14
  { PseudoVAADDU_VX_M1_MASK, VAADDU_VX }, // 15
  { PseudoVAADDU_VX_M2, VAADDU_VX }, // 16
  { PseudoVAADDU_VX_M2_MASK, VAADDU_VX }, // 17
  { PseudoVAADDU_VX_M4, VAADDU_VX }, // 18
  { PseudoVAADDU_VX_M4_MASK, VAADDU_VX }, // 19
  { PseudoVAADDU_VX_M8, VAADDU_VX }, // 20
  { PseudoVAADDU_VX_M8_MASK, VAADDU_VX }, // 21
  { PseudoVAADDU_VX_MF2, VAADDU_VX }, // 22
  { PseudoVAADDU_VX_MF2_MASK, VAADDU_VX }, // 23
  { PseudoVAADDU_VX_MF4, VAADDU_VX }, // 24
  { PseudoVAADDU_VX_MF4_MASK, VAADDU_VX }, // 25
  { PseudoVAADDU_VX_MF8, VAADDU_VX }, // 26
  { PseudoVAADDU_VX_MF8_MASK, VAADDU_VX }, // 27
  { PseudoVAADD_VV_M1, VAADD_VV }, // 28
  { PseudoVAADD_VV_M1_MASK, VAADD_VV }, // 29
  { PseudoVAADD_VV_M2, VAADD_VV }, // 30
  { PseudoVAADD_VV_M2_MASK, VAADD_VV }, // 31
  { PseudoVAADD_VV_M4, VAADD_VV }, // 32
  { PseudoVAADD_VV_M4_MASK, VAADD_VV }, // 33
  { PseudoVAADD_VV_M8, VAADD_VV }, // 34
  { PseudoVAADD_VV_M8_MASK, VAADD_VV }, // 35
  { PseudoVAADD_VV_MF2, VAADD_VV }, // 36
  { PseudoVAADD_VV_MF2_MASK, VAADD_VV }, // 37
  { PseudoVAADD_VV_MF4, VAADD_VV }, // 38
  { PseudoVAADD_VV_MF4_MASK, VAADD_VV }, // 39
  { PseudoVAADD_VV_MF8, VAADD_VV }, // 40
  { PseudoVAADD_VV_MF8_MASK, VAADD_VV }, // 41
  { PseudoVAADD_VX_M1, VAADD_VX }, // 42
  { PseudoVAADD_VX_M1_MASK, VAADD_VX }, // 43
  { PseudoVAADD_VX_M2, VAADD_VX }, // 44
  { PseudoVAADD_VX_M2_MASK, VAADD_VX }, // 45
  { PseudoVAADD_VX_M4, VAADD_VX }, // 46
  { PseudoVAADD_VX_M4_MASK, VAADD_VX }, // 47
  { PseudoVAADD_VX_M8, VAADD_VX }, // 48
  { PseudoVAADD_VX_M8_MASK, VAADD_VX }, // 49
  { PseudoVAADD_VX_MF2, VAADD_VX }, // 50
  { PseudoVAADD_VX_MF2_MASK, VAADD_VX }, // 51
  { PseudoVAADD_VX_MF4, VAADD_VX }, // 52
  { PseudoVAADD_VX_MF4_MASK, VAADD_VX }, // 53
  { PseudoVAADD_VX_MF8, VAADD_VX }, // 54
  { PseudoVAADD_VX_MF8_MASK, VAADD_VX }, // 55
  { PseudoVADC_VIM_M1, VADC_VIM }, // 56
  { PseudoVADC_VIM_M2, VADC_VIM }, // 57
  { PseudoVADC_VIM_M4, VADC_VIM }, // 58
  { PseudoVADC_VIM_M8, VADC_VIM }, // 59
  { PseudoVADC_VIM_MF2, VADC_VIM }, // 60
  { PseudoVADC_VIM_MF4, VADC_VIM }, // 61
  { PseudoVADC_VIM_MF8, VADC_VIM }, // 62
  { PseudoVADC_VVM_M1, VADC_VVM }, // 63
  { PseudoVADC_VVM_M2, VADC_VVM }, // 64
  { PseudoVADC_VVM_M4, VADC_VVM }, // 65
  { PseudoVADC_VVM_M8, VADC_VVM }, // 66
  { PseudoVADC_VVM_MF2, VADC_VVM }, // 67
  { PseudoVADC_VVM_MF4, VADC_VVM }, // 68
  { PseudoVADC_VVM_MF8, VADC_VVM }, // 69
  { PseudoVADC_VXM_M1, VADC_VXM }, // 70
  { PseudoVADC_VXM_M2, VADC_VXM }, // 71
  { PseudoVADC_VXM_M4, VADC_VXM }, // 72
  { PseudoVADC_VXM_M8, VADC_VXM }, // 73
  { PseudoVADC_VXM_MF2, VADC_VXM }, // 74
  { PseudoVADC_VXM_MF4, VADC_VXM }, // 75
  { PseudoVADC_VXM_MF8, VADC_VXM }, // 76
  { PseudoVADD_VI_M1, VADD_VI }, // 77
  { PseudoVADD_VI_M1_MASK, VADD_VI }, // 78
  { PseudoVADD_VI_M2, VADD_VI }, // 79
  { PseudoVADD_VI_M2_MASK, VADD_VI }, // 80
  { PseudoVADD_VI_M4, VADD_VI }, // 81
  { PseudoVADD_VI_M4_MASK, VADD_VI }, // 82
  { PseudoVADD_VI_M8, VADD_VI }, // 83
  { PseudoVADD_VI_M8_MASK, VADD_VI }, // 84
  { PseudoVADD_VI_MF2, VADD_VI }, // 85
  { PseudoVADD_VI_MF2_MASK, VADD_VI }, // 86
  { PseudoVADD_VI_MF4, VADD_VI }, // 87
  { PseudoVADD_VI_MF4_MASK, VADD_VI }, // 88
  { PseudoVADD_VI_MF8, VADD_VI }, // 89
  { PseudoVADD_VI_MF8_MASK, VADD_VI }, // 90
  { PseudoVADD_VV_M1, VADD_VV }, // 91
  { PseudoVADD_VV_M1_MASK, VADD_VV }, // 92
  { PseudoVADD_VV_M2, VADD_VV }, // 93
  { PseudoVADD_VV_M2_MASK, VADD_VV }, // 94
  { PseudoVADD_VV_M4, VADD_VV }, // 95
  { PseudoVADD_VV_M4_MASK, VADD_VV }, // 96
  { PseudoVADD_VV_M8, VADD_VV }, // 97
  { PseudoVADD_VV_M8_MASK, VADD_VV }, // 98
  { PseudoVADD_VV_MF2, VADD_VV }, // 99
  { PseudoVADD_VV_MF2_MASK, VADD_VV }, // 100
  { PseudoVADD_VV_MF4, VADD_VV }, // 101
  { PseudoVADD_VV_MF4_MASK, VADD_VV }, // 102
  { PseudoVADD_VV_MF8, VADD_VV }, // 103
  { PseudoVADD_VV_MF8_MASK, VADD_VV }, // 104
  { PseudoVADD_VX_M1, VADD_VX }, // 105
  { PseudoVADD_VX_M1_MASK, VADD_VX }, // 106
  { PseudoVADD_VX_M2, VADD_VX }, // 107
  { PseudoVADD_VX_M2_MASK, VADD_VX }, // 108
  { PseudoVADD_VX_M4, VADD_VX }, // 109
  { PseudoVADD_VX_M4_MASK, VADD_VX }, // 110
  { PseudoVADD_VX_M8, VADD_VX }, // 111
  { PseudoVADD_VX_M8_MASK, VADD_VX }, // 112
  { PseudoVADD_VX_MF2, VADD_VX }, // 113
  { PseudoVADD_VX_MF2_MASK, VADD_VX }, // 114
  { PseudoVADD_VX_MF4, VADD_VX }, // 115
  { PseudoVADD_VX_MF4_MASK, VADD_VX }, // 116
  { PseudoVADD_VX_MF8, VADD_VX }, // 117
  { PseudoVADD_VX_MF8_MASK, VADD_VX }, // 118
  { PseudoVAND_VI_M1, VAND_VI }, // 119
  { PseudoVAND_VI_M1_MASK, VAND_VI }, // 120
  { PseudoVAND_VI_M2, VAND_VI }, // 121
  { PseudoVAND_VI_M2_MASK, VAND_VI }, // 122
  { PseudoVAND_VI_M4, VAND_VI }, // 123
  { PseudoVAND_VI_M4_MASK, VAND_VI }, // 124
  { PseudoVAND_VI_M8, VAND_VI }, // 125
  { PseudoVAND_VI_M8_MASK, VAND_VI }, // 126
  { PseudoVAND_VI_MF2, VAND_VI }, // 127
  { PseudoVAND_VI_MF2_MASK, VAND_VI }, // 128
  { PseudoVAND_VI_MF4, VAND_VI }, // 129
  { PseudoVAND_VI_MF4_MASK, VAND_VI }, // 130
  { PseudoVAND_VI_MF8, VAND_VI }, // 131
  { PseudoVAND_VI_MF8_MASK, VAND_VI }, // 132
  { PseudoVAND_VV_M1, VAND_VV }, // 133
  { PseudoVAND_VV_M1_MASK, VAND_VV }, // 134
  { PseudoVAND_VV_M2, VAND_VV }, // 135
  { PseudoVAND_VV_M2_MASK, VAND_VV }, // 136
  { PseudoVAND_VV_M4, VAND_VV }, // 137
  { PseudoVAND_VV_M4_MASK, VAND_VV }, // 138
  { PseudoVAND_VV_M8, VAND_VV }, // 139
  { PseudoVAND_VV_M8_MASK, VAND_VV }, // 140
  { PseudoVAND_VV_MF2, VAND_VV }, // 141
  { PseudoVAND_VV_MF2_MASK, VAND_VV }, // 142
  { PseudoVAND_VV_MF4, VAND_VV }, // 143
  { PseudoVAND_VV_MF4_MASK, VAND_VV }, // 144
  { PseudoVAND_VV_MF8, VAND_VV }, // 145
  { PseudoVAND_VV_MF8_MASK, VAND_VV }, // 146
  { PseudoVAND_VX_M1, VAND_VX }, // 147
  { PseudoVAND_VX_M1_MASK, VAND_VX }, // 148
  { PseudoVAND_VX_M2, VAND_VX }, // 149
  { PseudoVAND_VX_M2_MASK, VAND_VX }, // 150
  { PseudoVAND_VX_M4, VAND_VX }, // 151
  { PseudoVAND_VX_M4_MASK, VAND_VX }, // 152
  { PseudoVAND_VX_M8, VAND_VX }, // 153
  { PseudoVAND_VX_M8_MASK, VAND_VX }, // 154
  { PseudoVAND_VX_MF2, VAND_VX }, // 155
  { PseudoVAND_VX_MF2_MASK, VAND_VX }, // 156
  { PseudoVAND_VX_MF4, VAND_VX }, // 157
  { PseudoVAND_VX_MF4_MASK, VAND_VX }, // 158
  { PseudoVAND_VX_MF8, VAND_VX }, // 159
  { PseudoVAND_VX_MF8_MASK, VAND_VX }, // 160
  { PseudoVASUBU_VV_M1, VASUBU_VV }, // 161
  { PseudoVASUBU_VV_M1_MASK, VASUBU_VV }, // 162
  { PseudoVASUBU_VV_M2, VASUBU_VV }, // 163
  { PseudoVASUBU_VV_M2_MASK, VASUBU_VV }, // 164
  { PseudoVASUBU_VV_M4, VASUBU_VV }, // 165
  { PseudoVASUBU_VV_M4_MASK, VASUBU_VV }, // 166
  { PseudoVASUBU_VV_M8, VASUBU_VV }, // 167
  { PseudoVASUBU_VV_M8_MASK, VASUBU_VV }, // 168
  { PseudoVASUBU_VV_MF2, VASUBU_VV }, // 169
  { PseudoVASUBU_VV_MF2_MASK, VASUBU_VV }, // 170
  { PseudoVASUBU_VV_MF4, VASUBU_VV }, // 171
  { PseudoVASUBU_VV_MF4_MASK, VASUBU_VV }, // 172
  { PseudoVASUBU_VV_MF8, VASUBU_VV }, // 173
  { PseudoVASUBU_VV_MF8_MASK, VASUBU_VV }, // 174
  { PseudoVASUBU_VX_M1, VASUBU_VX }, // 175
  { PseudoVASUBU_VX_M1_MASK, VASUBU_VX }, // 176
  { PseudoVASUBU_VX_M2, VASUBU_VX }, // 177
  { PseudoVASUBU_VX_M2_MASK, VASUBU_VX }, // 178
  { PseudoVASUBU_VX_M4, VASUBU_VX }, // 179
  { PseudoVASUBU_VX_M4_MASK, VASUBU_VX }, // 180
  { PseudoVASUBU_VX_M8, VASUBU_VX }, // 181
  { PseudoVASUBU_VX_M8_MASK, VASUBU_VX }, // 182
  { PseudoVASUBU_VX_MF2, VASUBU_VX }, // 183
  { PseudoVASUBU_VX_MF2_MASK, VASUBU_VX }, // 184
  { PseudoVASUBU_VX_MF4, VASUBU_VX }, // 185
  { PseudoVASUBU_VX_MF4_MASK, VASUBU_VX }, // 186
  { PseudoVASUBU_VX_MF8, VASUBU_VX }, // 187
  { PseudoVASUBU_VX_MF8_MASK, VASUBU_VX }, // 188
  { PseudoVASUB_VV_M1, VASUB_VV }, // 189
  { PseudoVASUB_VV_M1_MASK, VASUB_VV }, // 190
  { PseudoVASUB_VV_M2, VASUB_VV }, // 191
  { PseudoVASUB_VV_M2_MASK, VASUB_VV }, // 192
  { PseudoVASUB_VV_M4, VASUB_VV }, // 193
  { PseudoVASUB_VV_M4_MASK, VASUB_VV }, // 194
  { PseudoVASUB_VV_M8, VASUB_VV }, // 195
  { PseudoVASUB_VV_M8_MASK, VASUB_VV }, // 196
  { PseudoVASUB_VV_MF2, VASUB_VV }, // 197
  { PseudoVASUB_VV_MF2_MASK, VASUB_VV }, // 198
  { PseudoVASUB_VV_MF4, VASUB_VV }, // 199
  { PseudoVASUB_VV_MF4_MASK, VASUB_VV }, // 200
  { PseudoVASUB_VV_MF8, VASUB_VV }, // 201
  { PseudoVASUB_VV_MF8_MASK, VASUB_VV }, // 202
  { PseudoVASUB_VX_M1, VASUB_VX }, // 203
  { PseudoVASUB_VX_M1_MASK, VASUB_VX }, // 204
  { PseudoVASUB_VX_M2, VASUB_VX }, // 205
  { PseudoVASUB_VX_M2_MASK, VASUB_VX }, // 206
  { PseudoVASUB_VX_M4, VASUB_VX }, // 207
  { PseudoVASUB_VX_M4_MASK, VASUB_VX }, // 208
  { PseudoVASUB_VX_M8, VASUB_VX }, // 209
  { PseudoVASUB_VX_M8_MASK, VASUB_VX }, // 210
  { PseudoVASUB_VX_MF2, VASUB_VX }, // 211
  { PseudoVASUB_VX_MF2_MASK, VASUB_VX }, // 212
  { PseudoVASUB_VX_MF4, VASUB_VX }, // 213
  { PseudoVASUB_VX_MF4_MASK, VASUB_VX }, // 214
  { PseudoVASUB_VX_MF8, VASUB_VX }, // 215
  { PseudoVASUB_VX_MF8_MASK, VASUB_VX }, // 216
  { PseudoVCOMPRESS_VM_M1, VCOMPRESS_VM }, // 217
  { PseudoVCOMPRESS_VM_M2, VCOMPRESS_VM }, // 218
  { PseudoVCOMPRESS_VM_M4, VCOMPRESS_VM }, // 219
  { PseudoVCOMPRESS_VM_M8, VCOMPRESS_VM }, // 220
  { PseudoVCOMPRESS_VM_MF2, VCOMPRESS_VM }, // 221
  { PseudoVCOMPRESS_VM_MF4, VCOMPRESS_VM }, // 222
  { PseudoVCOMPRESS_VM_MF8, VCOMPRESS_VM }, // 223
  { PseudoVCPOP_M_B1, VCPOP_M }, // 224
  { PseudoVCPOP_M_B16, VCPOP_M }, // 225
  { PseudoVCPOP_M_B16_MASK, VCPOP_M }, // 226
  { PseudoVCPOP_M_B1_MASK, VCPOP_M }, // 227
  { PseudoVCPOP_M_B2, VCPOP_M }, // 228
  { PseudoVCPOP_M_B2_MASK, VCPOP_M }, // 229
  { PseudoVCPOP_M_B32, VCPOP_M }, // 230
  { PseudoVCPOP_M_B32_MASK, VCPOP_M }, // 231
  { PseudoVCPOP_M_B4, VCPOP_M }, // 232
  { PseudoVCPOP_M_B4_MASK, VCPOP_M }, // 233
  { PseudoVCPOP_M_B64, VCPOP_M }, // 234
  { PseudoVCPOP_M_B64_MASK, VCPOP_M }, // 235
  { PseudoVCPOP_M_B8, VCPOP_M }, // 236
  { PseudoVCPOP_M_B8_MASK, VCPOP_M }, // 237
  { PseudoVDIVU_VV_M1, VDIVU_VV }, // 238
  { PseudoVDIVU_VV_M1_MASK, VDIVU_VV }, // 239
  { PseudoVDIVU_VV_M2, VDIVU_VV }, // 240
  { PseudoVDIVU_VV_M2_MASK, VDIVU_VV }, // 241
  { PseudoVDIVU_VV_M4, VDIVU_VV }, // 242
  { PseudoVDIVU_VV_M4_MASK, VDIVU_VV }, // 243
  { PseudoVDIVU_VV_M8, VDIVU_VV }, // 244
  { PseudoVDIVU_VV_M8_MASK, VDIVU_VV }, // 245
  { PseudoVDIVU_VV_MF2, VDIVU_VV }, // 246
  { PseudoVDIVU_VV_MF2_MASK, VDIVU_VV }, // 247
  { PseudoVDIVU_VV_MF4, VDIVU_VV }, // 248
  { PseudoVDIVU_VV_MF4_MASK, VDIVU_VV }, // 249
  { PseudoVDIVU_VV_MF8, VDIVU_VV }, // 250
  { PseudoVDIVU_VV_MF8_MASK, VDIVU_VV }, // 251
  { PseudoVDIVU_VX_M1, VDIVU_VX }, // 252
  { PseudoVDIVU_VX_M1_MASK, VDIVU_VX }, // 253
  { PseudoVDIVU_VX_M2, VDIVU_VX }, // 254
  { PseudoVDIVU_VX_M2_MASK, VDIVU_VX }, // 255
  { PseudoVDIVU_VX_M4, VDIVU_VX }, // 256
  { PseudoVDIVU_VX_M4_MASK, VDIVU_VX }, // 257
  { PseudoVDIVU_VX_M8, VDIVU_VX }, // 258
  { PseudoVDIVU_VX_M8_MASK, VDIVU_VX }, // 259
  { PseudoVDIVU_VX_MF2, VDIVU_VX }, // 260
  { PseudoVDIVU_VX_MF2_MASK, VDIVU_VX }, // 261
  { PseudoVDIVU_VX_MF4, VDIVU_VX }, // 262
  { PseudoVDIVU_VX_MF4_MASK, VDIVU_VX }, // 263
  { PseudoVDIVU_VX_MF8, VDIVU_VX }, // 264
  { PseudoVDIVU_VX_MF8_MASK, VDIVU_VX }, // 265
  { PseudoVDIV_VV_M1, VDIV_VV }, // 266
  { PseudoVDIV_VV_M1_MASK, VDIV_VV }, // 267
  { PseudoVDIV_VV_M2, VDIV_VV }, // 268
  { PseudoVDIV_VV_M2_MASK, VDIV_VV }, // 269
  { PseudoVDIV_VV_M4, VDIV_VV }, // 270
  { PseudoVDIV_VV_M4_MASK, VDIV_VV }, // 271
  { PseudoVDIV_VV_M8, VDIV_VV }, // 272
  { PseudoVDIV_VV_M8_MASK, VDIV_VV }, // 273
  { PseudoVDIV_VV_MF2, VDIV_VV }, // 274
  { PseudoVDIV_VV_MF2_MASK, VDIV_VV }, // 275
  { PseudoVDIV_VV_MF4, VDIV_VV }, // 276
  { PseudoVDIV_VV_MF4_MASK, VDIV_VV }, // 277
  { PseudoVDIV_VV_MF8, VDIV_VV }, // 278
  { PseudoVDIV_VV_MF8_MASK, VDIV_VV }, // 279
  { PseudoVDIV_VX_M1, VDIV_VX }, // 280
  { PseudoVDIV_VX_M1_MASK, VDIV_VX }, // 281
  { PseudoVDIV_VX_M2, VDIV_VX }, // 282
  { PseudoVDIV_VX_M2_MASK, VDIV_VX }, // 283
  { PseudoVDIV_VX_M4, VDIV_VX }, // 284
  { PseudoVDIV_VX_M4_MASK, VDIV_VX }, // 285
  { PseudoVDIV_VX_M8, VDIV_VX }, // 286
  { PseudoVDIV_VX_M8_MASK, VDIV_VX }, // 287
  { PseudoVDIV_VX_MF2, VDIV_VX }, // 288
  { PseudoVDIV_VX_MF2_MASK, VDIV_VX }, // 289
  { PseudoVDIV_VX_MF4, VDIV_VX }, // 290
  { PseudoVDIV_VX_MF4_MASK, VDIV_VX }, // 291
  { PseudoVDIV_VX_MF8, VDIV_VX }, // 292
  { PseudoVDIV_VX_MF8_MASK, VDIV_VX }, // 293
  { PseudoVFADD_VF16_M1, VFADD_VF }, // 294
  { PseudoVFADD_VF16_M1_MASK, VFADD_VF }, // 295
  { PseudoVFADD_VF16_M2, VFADD_VF }, // 296
  { PseudoVFADD_VF16_M2_MASK, VFADD_VF }, // 297
  { PseudoVFADD_VF16_M4, VFADD_VF }, // 298
  { PseudoVFADD_VF16_M4_MASK, VFADD_VF }, // 299
  { PseudoVFADD_VF16_M8, VFADD_VF }, // 300
  { PseudoVFADD_VF16_M8_MASK, VFADD_VF }, // 301
  { PseudoVFADD_VF16_MF2, VFADD_VF }, // 302
  { PseudoVFADD_VF16_MF2_MASK, VFADD_VF }, // 303
  { PseudoVFADD_VF16_MF4, VFADD_VF }, // 304
  { PseudoVFADD_VF16_MF4_MASK, VFADD_VF }, // 305
  { PseudoVFADD_VF32_M1, VFADD_VF }, // 306
  { PseudoVFADD_VF32_M1_MASK, VFADD_VF }, // 307
  { PseudoVFADD_VF32_M2, VFADD_VF }, // 308
  { PseudoVFADD_VF32_M2_MASK, VFADD_VF }, // 309
  { PseudoVFADD_VF32_M4, VFADD_VF }, // 310
  { PseudoVFADD_VF32_M4_MASK, VFADD_VF }, // 311
  { PseudoVFADD_VF32_M8, VFADD_VF }, // 312
  { PseudoVFADD_VF32_M8_MASK, VFADD_VF }, // 313
  { PseudoVFADD_VF32_MF2, VFADD_VF }, // 314
  { PseudoVFADD_VF32_MF2_MASK, VFADD_VF }, // 315
  { PseudoVFADD_VF64_M1, VFADD_VF }, // 316
  { PseudoVFADD_VF64_M1_MASK, VFADD_VF }, // 317
  { PseudoVFADD_VF64_M2, VFADD_VF }, // 318
  { PseudoVFADD_VF64_M2_MASK, VFADD_VF }, // 319
  { PseudoVFADD_VF64_M4, VFADD_VF }, // 320
  { PseudoVFADD_VF64_M4_MASK, VFADD_VF }, // 321
  { PseudoVFADD_VF64_M8, VFADD_VF }, // 322
  { PseudoVFADD_VF64_M8_MASK, VFADD_VF }, // 323
  { PseudoVFADD_VV_M1, VFADD_VV }, // 324
  { PseudoVFADD_VV_M1_MASK, VFADD_VV }, // 325
  { PseudoVFADD_VV_M2, VFADD_VV }, // 326
  { PseudoVFADD_VV_M2_MASK, VFADD_VV }, // 327
  { PseudoVFADD_VV_M4, VFADD_VV }, // 328
  { PseudoVFADD_VV_M4_MASK, VFADD_VV }, // 329
  { PseudoVFADD_VV_M8, VFADD_VV }, // 330
  { PseudoVFADD_VV_M8_MASK, VFADD_VV }, // 331
  { PseudoVFADD_VV_MF2, VFADD_VV }, // 332
  { PseudoVFADD_VV_MF2_MASK, VFADD_VV }, // 333
  { PseudoVFADD_VV_MF4, VFADD_VV }, // 334
  { PseudoVFADD_VV_MF4_MASK, VFADD_VV }, // 335
  { PseudoVFCLASS_V_M1, VFCLASS_V }, // 336
  { PseudoVFCLASS_V_M1_MASK, VFCLASS_V }, // 337
  { PseudoVFCLASS_V_M2, VFCLASS_V }, // 338
  { PseudoVFCLASS_V_M2_MASK, VFCLASS_V }, // 339
  { PseudoVFCLASS_V_M4, VFCLASS_V }, // 340
  { PseudoVFCLASS_V_M4_MASK, VFCLASS_V }, // 341
  { PseudoVFCLASS_V_M8, VFCLASS_V }, // 342
  { PseudoVFCLASS_V_M8_MASK, VFCLASS_V }, // 343
  { PseudoVFCLASS_V_MF2, VFCLASS_V }, // 344
  { PseudoVFCLASS_V_MF2_MASK, VFCLASS_V }, // 345
  { PseudoVFCLASS_V_MF4, VFCLASS_V }, // 346
  { PseudoVFCLASS_V_MF4_MASK, VFCLASS_V }, // 347
  { PseudoVFCVT_F_XU_V_M1, VFCVT_F_XU_V }, // 348
  { PseudoVFCVT_F_XU_V_M1_MASK, VFCVT_F_XU_V }, // 349
  { PseudoVFCVT_F_XU_V_M2, VFCVT_F_XU_V }, // 350
  { PseudoVFCVT_F_XU_V_M2_MASK, VFCVT_F_XU_V }, // 351
  { PseudoVFCVT_F_XU_V_M4, VFCVT_F_XU_V }, // 352
  { PseudoVFCVT_F_XU_V_M4_MASK, VFCVT_F_XU_V }, // 353
  { PseudoVFCVT_F_XU_V_M8, VFCVT_F_XU_V }, // 354
  { PseudoVFCVT_F_XU_V_M8_MASK, VFCVT_F_XU_V }, // 355
  { PseudoVFCVT_F_XU_V_MF2, VFCVT_F_XU_V }, // 356
  { PseudoVFCVT_F_XU_V_MF2_MASK, VFCVT_F_XU_V }, // 357
  { PseudoVFCVT_F_XU_V_MF4, VFCVT_F_XU_V }, // 358
  { PseudoVFCVT_F_XU_V_MF4_MASK, VFCVT_F_XU_V }, // 359
  { PseudoVFCVT_F_X_V_M1, VFCVT_F_X_V }, // 360
  { PseudoVFCVT_F_X_V_M1_MASK, VFCVT_F_X_V }, // 361
  { PseudoVFCVT_F_X_V_M2, VFCVT_F_X_V }, // 362
  { PseudoVFCVT_F_X_V_M2_MASK, VFCVT_F_X_V }, // 363
  { PseudoVFCVT_F_X_V_M4, VFCVT_F_X_V }, // 364
  { PseudoVFCVT_F_X_V_M4_MASK, VFCVT_F_X_V }, // 365
  { PseudoVFCVT_F_X_V_M8, VFCVT_F_X_V }, // 366
  { PseudoVFCVT_F_X_V_M8_MASK, VFCVT_F_X_V }, // 367
  { PseudoVFCVT_F_X_V_MF2, VFCVT_F_X_V }, // 368
  { PseudoVFCVT_F_X_V_MF2_MASK, VFCVT_F_X_V }, // 369
  { PseudoVFCVT_F_X_V_MF4, VFCVT_F_X_V }, // 370
  { PseudoVFCVT_F_X_V_MF4_MASK, VFCVT_F_X_V }, // 371
  { PseudoVFCVT_RTZ_XU_F_V_M1, VFCVT_RTZ_XU_F_V }, // 372
  { PseudoVFCVT_RTZ_XU_F_V_M1_MASK, VFCVT_RTZ_XU_F_V }, // 373
  { PseudoVFCVT_RTZ_XU_F_V_M2, VFCVT_RTZ_XU_F_V }, // 374
  { PseudoVFCVT_RTZ_XU_F_V_M2_MASK, VFCVT_RTZ_XU_F_V }, // 375
  { PseudoVFCVT_RTZ_XU_F_V_M4, VFCVT_RTZ_XU_F_V }, // 376
  { PseudoVFCVT_RTZ_XU_F_V_M4_MASK, VFCVT_RTZ_XU_F_V }, // 377
  { PseudoVFCVT_RTZ_XU_F_V_M8, VFCVT_RTZ_XU_F_V }, // 378
  { PseudoVFCVT_RTZ_XU_F_V_M8_MASK, VFCVT_RTZ_XU_F_V }, // 379
  { PseudoVFCVT_RTZ_XU_F_V_MF2, VFCVT_RTZ_XU_F_V }, // 380
  { PseudoVFCVT_RTZ_XU_F_V_MF2_MASK, VFCVT_RTZ_XU_F_V }, // 381
  { PseudoVFCVT_RTZ_XU_F_V_MF4, VFCVT_RTZ_XU_F_V }, // 382
  { PseudoVFCVT_RTZ_XU_F_V_MF4_MASK, VFCVT_RTZ_XU_F_V }, // 383
  { PseudoVFCVT_RTZ_X_F_V_M1, VFCVT_RTZ_X_F_V }, // 384
  { PseudoVFCVT_RTZ_X_F_V_M1_MASK, VFCVT_RTZ_X_F_V }, // 385
  { PseudoVFCVT_RTZ_X_F_V_M2, VFCVT_RTZ_X_F_V }, // 386
  { PseudoVFCVT_RTZ_X_F_V_M2_MASK, VFCVT_RTZ_X_F_V }, // 387
  { PseudoVFCVT_RTZ_X_F_V_M4, VFCVT_RTZ_X_F_V }, // 388
  { PseudoVFCVT_RTZ_X_F_V_M4_MASK, VFCVT_RTZ_X_F_V }, // 389
  { PseudoVFCVT_RTZ_X_F_V_M8, VFCVT_RTZ_X_F_V }, // 390
  { PseudoVFCVT_RTZ_X_F_V_M8_MASK, VFCVT_RTZ_X_F_V }, // 391
  { PseudoVFCVT_RTZ_X_F_V_MF2, VFCVT_RTZ_X_F_V }, // 392
  { PseudoVFCVT_RTZ_X_F_V_MF2_MASK, VFCVT_RTZ_X_F_V }, // 393
  { PseudoVFCVT_RTZ_X_F_V_MF4, VFCVT_RTZ_X_F_V }, // 394
  { PseudoVFCVT_RTZ_X_F_V_MF4_MASK, VFCVT_RTZ_X_F_V }, // 395
  { PseudoVFCVT_XU_F_V_M1, VFCVT_XU_F_V }, // 396
  { PseudoVFCVT_XU_F_V_M1_MASK, VFCVT_XU_F_V }, // 397
  { PseudoVFCVT_XU_F_V_M2, VFCVT_XU_F_V }, // 398
  { PseudoVFCVT_XU_F_V_M2_MASK, VFCVT_XU_F_V }, // 399
  { PseudoVFCVT_XU_F_V_M4, VFCVT_XU_F_V }, // 400
  { PseudoVFCVT_XU_F_V_M4_MASK, VFCVT_XU_F_V }, // 401
  { PseudoVFCVT_XU_F_V_M8, VFCVT_XU_F_V }, // 402
  { PseudoVFCVT_XU_F_V_M8_MASK, VFCVT_XU_F_V }, // 403
  { PseudoVFCVT_XU_F_V_MF2, VFCVT_XU_F_V }, // 404
  { PseudoVFCVT_XU_F_V_MF2_MASK, VFCVT_XU_F_V }, // 405
  { PseudoVFCVT_XU_F_V_MF4, VFCVT_XU_F_V }, // 406
  { PseudoVFCVT_XU_F_V_MF4_MASK, VFCVT_XU_F_V }, // 407
  { PseudoVFCVT_X_F_V_M1, VFCVT_X_F_V }, // 408
  { PseudoVFCVT_X_F_V_M1_MASK, VFCVT_X_F_V }, // 409
  { PseudoVFCVT_X_F_V_M2, VFCVT_X_F_V }, // 410
  { PseudoVFCVT_X_F_V_M2_MASK, VFCVT_X_F_V }, // 411
  { PseudoVFCVT_X_F_V_M4, VFCVT_X_F_V }, // 412
  { PseudoVFCVT_X_F_V_M4_MASK, VFCVT_X_F_V }, // 413
  { PseudoVFCVT_X_F_V_M8, VFCVT_X_F_V }, // 414
  { PseudoVFCVT_X_F_V_M8_MASK, VFCVT_X_F_V }, // 415
  { PseudoVFCVT_X_F_V_MF2, VFCVT_X_F_V }, // 416
  { PseudoVFCVT_X_F_V_MF2_MASK, VFCVT_X_F_V }, // 417
  { PseudoVFCVT_X_F_V_MF4, VFCVT_X_F_V }, // 418
  { PseudoVFCVT_X_F_V_MF4_MASK, VFCVT_X_F_V }, // 419
  { PseudoVFDIV_VF16_M1, VFDIV_VF }, // 420
  { PseudoVFDIV_VF16_M1_MASK, VFDIV_VF }, // 421
  { PseudoVFDIV_VF16_M2, VFDIV_VF }, // 422
  { PseudoVFDIV_VF16_M2_MASK, VFDIV_VF }, // 423
  { PseudoVFDIV_VF16_M4, VFDIV_VF }, // 424
  { PseudoVFDIV_VF16_M4_MASK, VFDIV_VF }, // 425
  { PseudoVFDIV_VF16_M8, VFDIV_VF }, // 426
  { PseudoVFDIV_VF16_M8_MASK, VFDIV_VF }, // 427
  { PseudoVFDIV_VF16_MF2, VFDIV_VF }, // 428
  { PseudoVFDIV_VF16_MF2_MASK, VFDIV_VF }, // 429
  { PseudoVFDIV_VF16_MF4, VFDIV_VF }, // 430
  { PseudoVFDIV_VF16_MF4_MASK, VFDIV_VF }, // 431
  { PseudoVFDIV_VF32_M1, VFDIV_VF }, // 432
  { PseudoVFDIV_VF32_M1_MASK, VFDIV_VF }, // 433
  { PseudoVFDIV_VF32_M2, VFDIV_VF }, // 434
  { PseudoVFDIV_VF32_M2_MASK, VFDIV_VF }, // 435
  { PseudoVFDIV_VF32_M4, VFDIV_VF }, // 436
  { PseudoVFDIV_VF32_M4_MASK, VFDIV_VF }, // 437
  { PseudoVFDIV_VF32_M8, VFDIV_VF }, // 438
  { PseudoVFDIV_VF32_M8_MASK, VFDIV_VF }, // 439
  { PseudoVFDIV_VF32_MF2, VFDIV_VF }, // 440
  { PseudoVFDIV_VF32_MF2_MASK, VFDIV_VF }, // 441
  { PseudoVFDIV_VF64_M1, VFDIV_VF }, // 442
  { PseudoVFDIV_VF64_M1_MASK, VFDIV_VF }, // 443
  { PseudoVFDIV_VF64_M2, VFDIV_VF }, // 444
  { PseudoVFDIV_VF64_M2_MASK, VFDIV_VF }, // 445
  { PseudoVFDIV_VF64_M4, VFDIV_VF }, // 446
  { PseudoVFDIV_VF64_M4_MASK, VFDIV_VF }, // 447
  { PseudoVFDIV_VF64_M8, VFDIV_VF }, // 448
  { PseudoVFDIV_VF64_M8_MASK, VFDIV_VF }, // 449
  { PseudoVFDIV_VV_M1, VFDIV_VV }, // 450
  { PseudoVFDIV_VV_M1_MASK, VFDIV_VV }, // 451
  { PseudoVFDIV_VV_M2, VFDIV_VV }, // 452
  { PseudoVFDIV_VV_M2_MASK, VFDIV_VV }, // 453
  { PseudoVFDIV_VV_M4, VFDIV_VV }, // 454
  { PseudoVFDIV_VV_M4_MASK, VFDIV_VV }, // 455
  { PseudoVFDIV_VV_M8, VFDIV_VV }, // 456
  { PseudoVFDIV_VV_M8_MASK, VFDIV_VV }, // 457
  { PseudoVFDIV_VV_MF2, VFDIV_VV }, // 458
  { PseudoVFDIV_VV_MF2_MASK, VFDIV_VV }, // 459
  { PseudoVFDIV_VV_MF4, VFDIV_VV }, // 460
  { PseudoVFDIV_VV_MF4_MASK, VFDIV_VV }, // 461
  { PseudoVFIRST_M_B1, VFIRST_M }, // 462
  { PseudoVFIRST_M_B16, VFIRST_M }, // 463
  { PseudoVFIRST_M_B16_MASK, VFIRST_M }, // 464
  { PseudoVFIRST_M_B1_MASK, VFIRST_M }, // 465
  { PseudoVFIRST_M_B2, VFIRST_M }, // 466
  { PseudoVFIRST_M_B2_MASK, VFIRST_M }, // 467
  { PseudoVFIRST_M_B32, VFIRST_M }, // 468
  { PseudoVFIRST_M_B32_MASK, VFIRST_M }, // 469
  { PseudoVFIRST_M_B4, VFIRST_M }, // 470
  { PseudoVFIRST_M_B4_MASK, VFIRST_M }, // 471
  { PseudoVFIRST_M_B64, VFIRST_M }, // 472
  { PseudoVFIRST_M_B64_MASK, VFIRST_M }, // 473
  { PseudoVFIRST_M_B8, VFIRST_M }, // 474
  { PseudoVFIRST_M_B8_MASK, VFIRST_M }, // 475
  { PseudoVFMACC_VF16_M1, VFMACC_VF }, // 476
  { PseudoVFMACC_VF16_M1_MASK, VFMACC_VF }, // 477
  { PseudoVFMACC_VF16_M2, VFMACC_VF }, // 478
  { PseudoVFMACC_VF16_M2_MASK, VFMACC_VF }, // 479
  { PseudoVFMACC_VF16_M4, VFMACC_VF }, // 480
  { PseudoVFMACC_VF16_M4_MASK, VFMACC_VF }, // 481
  { PseudoVFMACC_VF16_M8, VFMACC_VF }, // 482
  { PseudoVFMACC_VF16_M8_MASK, VFMACC_VF }, // 483
  { PseudoVFMACC_VF16_MF2, VFMACC_VF }, // 484
  { PseudoVFMACC_VF16_MF2_MASK, VFMACC_VF }, // 485
  { PseudoVFMACC_VF16_MF4, VFMACC_VF }, // 486
  { PseudoVFMACC_VF16_MF4_MASK, VFMACC_VF }, // 487
  { PseudoVFMACC_VF32_M1, VFMACC_VF }, // 488
  { PseudoVFMACC_VF32_M1_MASK, VFMACC_VF }, // 489
  { PseudoVFMACC_VF32_M2, VFMACC_VF }, // 490
  { PseudoVFMACC_VF32_M2_MASK, VFMACC_VF }, // 491
  { PseudoVFMACC_VF32_M4, VFMACC_VF }, // 492
  { PseudoVFMACC_VF32_M4_MASK, VFMACC_VF }, // 493
  { PseudoVFMACC_VF32_M8, VFMACC_VF }, // 494
  { PseudoVFMACC_VF32_M8_MASK, VFMACC_VF }, // 495
  { PseudoVFMACC_VF32_MF2, VFMACC_VF }, // 496
  { PseudoVFMACC_VF32_MF2_MASK, VFMACC_VF }, // 497
  { PseudoVFMACC_VF64_M1, VFMACC_VF }, // 498
  { PseudoVFMACC_VF64_M1_MASK, VFMACC_VF }, // 499
  { PseudoVFMACC_VF64_M2, VFMACC_VF }, // 500
  { PseudoVFMACC_VF64_M2_MASK, VFMACC_VF }, // 501
  { PseudoVFMACC_VF64_M4, VFMACC_VF }, // 502
  { PseudoVFMACC_VF64_M4_MASK, VFMACC_VF }, // 503
  { PseudoVFMACC_VF64_M8, VFMACC_VF }, // 504
  { PseudoVFMACC_VF64_M8_MASK, VFMACC_VF }, // 505
  { PseudoVFMACC_VV_M1, VFMACC_VV }, // 506
  { PseudoVFMACC_VV_M1_MASK, VFMACC_VV }, // 507
  { PseudoVFMACC_VV_M2, VFMACC_VV }, // 508
  { PseudoVFMACC_VV_M2_MASK, VFMACC_VV }, // 509
  { PseudoVFMACC_VV_M4, VFMACC_VV }, // 510
  { PseudoVFMACC_VV_M4_MASK, VFMACC_VV }, // 511
  { PseudoVFMACC_VV_M8, VFMACC_VV }, // 512
  { PseudoVFMACC_VV_M8_MASK, VFMACC_VV }, // 513
  { PseudoVFMACC_VV_MF2, VFMACC_VV }, // 514
  { PseudoVFMACC_VV_MF2_MASK, VFMACC_VV }, // 515
  { PseudoVFMACC_VV_MF4, VFMACC_VV }, // 516
  { PseudoVFMACC_VV_MF4_MASK, VFMACC_VV }, // 517
  { PseudoVFMADD_VF16_M1, VFMADD_VF }, // 518
  { PseudoVFMADD_VF16_M1_MASK, VFMADD_VF }, // 519
  { PseudoVFMADD_VF16_M2, VFMADD_VF }, // 520
  { PseudoVFMADD_VF16_M2_MASK, VFMADD_VF }, // 521
  { PseudoVFMADD_VF16_M4, VFMADD_VF }, // 522
  { PseudoVFMADD_VF16_M4_MASK, VFMADD_VF }, // 523
  { PseudoVFMADD_VF16_M8, VFMADD_VF }, // 524
  { PseudoVFMADD_VF16_M8_MASK, VFMADD_VF }, // 525
  { PseudoVFMADD_VF16_MF2, VFMADD_VF }, // 526
  { PseudoVFMADD_VF16_MF2_MASK, VFMADD_VF }, // 527
  { PseudoVFMADD_VF16_MF4, VFMADD_VF }, // 528
  { PseudoVFMADD_VF16_MF4_MASK, VFMADD_VF }, // 529
  { PseudoVFMADD_VF32_M1, VFMADD_VF }, // 530
  { PseudoVFMADD_VF32_M1_MASK, VFMADD_VF }, // 531
  { PseudoVFMADD_VF32_M2, VFMADD_VF }, // 532
  { PseudoVFMADD_VF32_M2_MASK, VFMADD_VF }, // 533
  { PseudoVFMADD_VF32_M4, VFMADD_VF }, // 534
  { PseudoVFMADD_VF32_M4_MASK, VFMADD_VF }, // 535
  { PseudoVFMADD_VF32_M8, VFMADD_VF }, // 536
  { PseudoVFMADD_VF32_M8_MASK, VFMADD_VF }, // 537
  { PseudoVFMADD_VF32_MF2, VFMADD_VF }, // 538
  { PseudoVFMADD_VF32_MF2_MASK, VFMADD_VF }, // 539
  { PseudoVFMADD_VF64_M1, VFMADD_VF }, // 540
  { PseudoVFMADD_VF64_M1_MASK, VFMADD_VF }, // 541
  { PseudoVFMADD_VF64_M2, VFMADD_VF }, // 542
  { PseudoVFMADD_VF64_M2_MASK, VFMADD_VF }, // 543
  { PseudoVFMADD_VF64_M4, VFMADD_VF }, // 544
  { PseudoVFMADD_VF64_M4_MASK, VFMADD_VF }, // 545
  { PseudoVFMADD_VF64_M8, VFMADD_VF }, // 546
  { PseudoVFMADD_VF64_M8_MASK, VFMADD_VF }, // 547
  { PseudoVFMADD_VV_M1, VFMADD_VV }, // 548
  { PseudoVFMADD_VV_M1_MASK, VFMADD_VV }, // 549
  { PseudoVFMADD_VV_M2, VFMADD_VV }, // 550
  { PseudoVFMADD_VV_M2_MASK, VFMADD_VV }, // 551
  { PseudoVFMADD_VV_M4, VFMADD_VV }, // 552
  { PseudoVFMADD_VV_M4_MASK, VFMADD_VV }, // 553
  { PseudoVFMADD_VV_M8, VFMADD_VV }, // 554
  { PseudoVFMADD_VV_M8_MASK, VFMADD_VV }, // 555
  { PseudoVFMADD_VV_MF2, VFMADD_VV }, // 556
  { PseudoVFMADD_VV_MF2_MASK, VFMADD_VV }, // 557
  { PseudoVFMADD_VV_MF4, VFMADD_VV }, // 558
  { PseudoVFMADD_VV_MF4_MASK, VFMADD_VV }, // 559
  { PseudoVFMAX_VF16_M1, VFMAX_VF }, // 560
  { PseudoVFMAX_VF16_M1_MASK, VFMAX_VF }, // 561
  { PseudoVFMAX_VF16_M2, VFMAX_VF }, // 562
  { PseudoVFMAX_VF16_M2_MASK, VFMAX_VF }, // 563
  { PseudoVFMAX_VF16_M4, VFMAX_VF }, // 564
  { PseudoVFMAX_VF16_M4_MASK, VFMAX_VF }, // 565
  { PseudoVFMAX_VF16_M8, VFMAX_VF }, // 566
  { PseudoVFMAX_VF16_M8_MASK, VFMAX_VF }, // 567
  { PseudoVFMAX_VF16_MF2, VFMAX_VF }, // 568
  { PseudoVFMAX_VF16_MF2_MASK, VFMAX_VF }, // 569
  { PseudoVFMAX_VF16_MF4, VFMAX_VF }, // 570
  { PseudoVFMAX_VF16_MF4_MASK, VFMAX_VF }, // 571
  { PseudoVFMAX_VF32_M1, VFMAX_VF }, // 572
  { PseudoVFMAX_VF32_M1_MASK, VFMAX_VF }, // 573
  { PseudoVFMAX_VF32_M2, VFMAX_VF }, // 574
  { PseudoVFMAX_VF32_M2_MASK, VFMAX_VF }, // 575
  { PseudoVFMAX_VF32_M4, VFMAX_VF }, // 576
  { PseudoVFMAX_VF32_M4_MASK, VFMAX_VF }, // 577
  { PseudoVFMAX_VF32_M8, VFMAX_VF }, // 578
  { PseudoVFMAX_VF32_M8_MASK, VFMAX_VF }, // 579
  { PseudoVFMAX_VF32_MF2, VFMAX_VF }, // 580
  { PseudoVFMAX_VF32_MF2_MASK, VFMAX_VF }, // 581
  { PseudoVFMAX_VF64_M1, VFMAX_VF }, // 582
  { PseudoVFMAX_VF64_M1_MASK, VFMAX_VF }, // 583
  { PseudoVFMAX_VF64_M2, VFMAX_VF }, // 584
  { PseudoVFMAX_VF64_M2_MASK, VFMAX_VF }, // 585
  { PseudoVFMAX_VF64_M4, VFMAX_VF }, // 586
  { PseudoVFMAX_VF64_M4_MASK, VFMAX_VF }, // 587
  { PseudoVFMAX_VF64_M8, VFMAX_VF }, // 588
  { PseudoVFMAX_VF64_M8_MASK, VFMAX_VF }, // 589
  { PseudoVFMAX_VV_M1, VFMAX_VV }, // 590
  { PseudoVFMAX_VV_M1_MASK, VFMAX_VV }, // 591
  { PseudoVFMAX_VV_M2, VFMAX_VV }, // 592
  { PseudoVFMAX_VV_M2_MASK, VFMAX_VV }, // 593
  { PseudoVFMAX_VV_M4, VFMAX_VV }, // 594
  { PseudoVFMAX_VV_M4_MASK, VFMAX_VV }, // 595
  { PseudoVFMAX_VV_M8, VFMAX_VV }, // 596
  { PseudoVFMAX_VV_M8_MASK, VFMAX_VV }, // 597
  { PseudoVFMAX_VV_MF2, VFMAX_VV }, // 598
  { PseudoVFMAX_VV_MF2_MASK, VFMAX_VV }, // 599
  { PseudoVFMAX_VV_MF4, VFMAX_VV }, // 600
  { PseudoVFMAX_VV_MF4_MASK, VFMAX_VV }, // 601
  { PseudoVFMERGE_VF16M_M1, VFMERGE_VFM }, // 602
  { PseudoVFMERGE_VF16M_M1_TU, VFMERGE_VFM }, // 603
  { PseudoVFMERGE_VF16M_M2, VFMERGE_VFM }, // 604
  { PseudoVFMERGE_VF16M_M2_TU, VFMERGE_VFM }, // 605
  { PseudoVFMERGE_VF16M_M4, VFMERGE_VFM }, // 606
  { PseudoVFMERGE_VF16M_M4_TU, VFMERGE_VFM }, // 607
  { PseudoVFMERGE_VF16M_M8, VFMERGE_VFM }, // 608
  { PseudoVFMERGE_VF16M_M8_TU, VFMERGE_VFM }, // 609
  { PseudoVFMERGE_VF16M_MF2, VFMERGE_VFM }, // 610
  { PseudoVFMERGE_VF16M_MF2_TU, VFMERGE_VFM }, // 611
  { PseudoVFMERGE_VF16M_MF4, VFMERGE_VFM }, // 612
  { PseudoVFMERGE_VF16M_MF4_TU, VFMERGE_VFM }, // 613
  { PseudoVFMERGE_VF32M_M1, VFMERGE_VFM }, // 614
  { PseudoVFMERGE_VF32M_M1_TU, VFMERGE_VFM }, // 615
  { PseudoVFMERGE_VF32M_M2, VFMERGE_VFM }, // 616
  { PseudoVFMERGE_VF32M_M2_TU, VFMERGE_VFM }, // 617
  { PseudoVFMERGE_VF32M_M4, VFMERGE_VFM }, // 618
  { PseudoVFMERGE_VF32M_M4_TU, VFMERGE_VFM }, // 619
  { PseudoVFMERGE_VF32M_M8, VFMERGE_VFM }, // 620
  { PseudoVFMERGE_VF32M_M8_TU, VFMERGE_VFM }, // 621
  { PseudoVFMERGE_VF32M_MF2, VFMERGE_VFM }, // 622
  { PseudoVFMERGE_VF32M_MF2_TU, VFMERGE_VFM }, // 623
  { PseudoVFMERGE_VF64M_M1, VFMERGE_VFM }, // 624
  { PseudoVFMERGE_VF64M_M1_TU, VFMERGE_VFM }, // 625
  { PseudoVFMERGE_VF64M_M2, VFMERGE_VFM }, // 626
  { PseudoVFMERGE_VF64M_M2_TU, VFMERGE_VFM }, // 627
  { PseudoVFMERGE_VF64M_M4, VFMERGE_VFM }, // 628
  { PseudoVFMERGE_VF64M_M4_TU, VFMERGE_VFM }, // 629
  { PseudoVFMERGE_VF64M_M8, VFMERGE_VFM }, // 630
  { PseudoVFMERGE_VF64M_M8_TU, VFMERGE_VFM }, // 631
  { PseudoVFMIN_VF16_M1, VFMIN_VF }, // 632
  { PseudoVFMIN_VF16_M1_MASK, VFMIN_VF }, // 633
  { PseudoVFMIN_VF16_M2, VFMIN_VF }, // 634
  { PseudoVFMIN_VF16_M2_MASK, VFMIN_VF }, // 635
  { PseudoVFMIN_VF16_M4, VFMIN_VF }, // 636
  { PseudoVFMIN_VF16_M4_MASK, VFMIN_VF }, // 637
  { PseudoVFMIN_VF16_M8, VFMIN_VF }, // 638
  { PseudoVFMIN_VF16_M8_MASK, VFMIN_VF }, // 639
  { PseudoVFMIN_VF16_MF2, VFMIN_VF }, // 640
  { PseudoVFMIN_VF16_MF2_MASK, VFMIN_VF }, // 641
  { PseudoVFMIN_VF16_MF4, VFMIN_VF }, // 642
  { PseudoVFMIN_VF16_MF4_MASK, VFMIN_VF }, // 643
  { PseudoVFMIN_VF32_M1, VFMIN_VF }, // 644
  { PseudoVFMIN_VF32_M1_MASK, VFMIN_VF }, // 645
  { PseudoVFMIN_VF32_M2, VFMIN_VF }, // 646
  { PseudoVFMIN_VF32_M2_MASK, VFMIN_VF }, // 647
  { PseudoVFMIN_VF32_M4, VFMIN_VF }, // 648
  { PseudoVFMIN_VF32_M4_MASK, VFMIN_VF }, // 649
  { PseudoVFMIN_VF32_M8, VFMIN_VF }, // 650
  { PseudoVFMIN_VF32_M8_MASK, VFMIN_VF }, // 651
  { PseudoVFMIN_VF32_MF2, VFMIN_VF }, // 652
  { PseudoVFMIN_VF32_MF2_MASK, VFMIN_VF }, // 653
  { PseudoVFMIN_VF64_M1, VFMIN_VF }, // 654
  { PseudoVFMIN_VF64_M1_MASK, VFMIN_VF }, // 655
  { PseudoVFMIN_VF64_M2, VFMIN_VF }, // 656
  { PseudoVFMIN_VF64_M2_MASK, VFMIN_VF }, // 657
  { PseudoVFMIN_VF64_M4, VFMIN_VF }, // 658
  { PseudoVFMIN_VF64_M4_MASK, VFMIN_VF }, // 659
  { PseudoVFMIN_VF64_M8, VFMIN_VF }, // 660
  { PseudoVFMIN_VF64_M8_MASK, VFMIN_VF }, // 661
  { PseudoVFMIN_VV_M1, VFMIN_VV }, // 662
  { PseudoVFMIN_VV_M1_MASK, VFMIN_VV }, // 663
  { PseudoVFMIN_VV_M2, VFMIN_VV }, // 664
  { PseudoVFMIN_VV_M2_MASK, VFMIN_VV }, // 665
  { PseudoVFMIN_VV_M4, VFMIN_VV }, // 666
  { PseudoVFMIN_VV_M4_MASK, VFMIN_VV }, // 667
  { PseudoVFMIN_VV_M8, VFMIN_VV }, // 668
  { PseudoVFMIN_VV_M8_MASK, VFMIN_VV }, // 669
  { PseudoVFMIN_VV_MF2, VFMIN_VV }, // 670
  { PseudoVFMIN_VV_MF2_MASK, VFMIN_VV }, // 671
  { PseudoVFMIN_VV_MF4, VFMIN_VV }, // 672
  { PseudoVFMIN_VV_MF4_MASK, VFMIN_VV }, // 673
  { PseudoVFMSAC_VF16_M1, VFMSAC_VF }, // 674
  { PseudoVFMSAC_VF16_M1_MASK, VFMSAC_VF }, // 675
  { PseudoVFMSAC_VF16_M2, VFMSAC_VF }, // 676
  { PseudoVFMSAC_VF16_M2_MASK, VFMSAC_VF }, // 677
  { PseudoVFMSAC_VF16_M4, VFMSAC_VF }, // 678
  { PseudoVFMSAC_VF16_M4_MASK, VFMSAC_VF }, // 679
  { PseudoVFMSAC_VF16_M8, VFMSAC_VF }, // 680
  { PseudoVFMSAC_VF16_M8_MASK, VFMSAC_VF }, // 681
  { PseudoVFMSAC_VF16_MF2, VFMSAC_VF }, // 682
  { PseudoVFMSAC_VF16_MF2_MASK, VFMSAC_VF }, // 683
  { PseudoVFMSAC_VF16_MF4, VFMSAC_VF }, // 684
  { PseudoVFMSAC_VF16_MF4_MASK, VFMSAC_VF }, // 685
  { PseudoVFMSAC_VF32_M1, VFMSAC_VF }, // 686
  { PseudoVFMSAC_VF32_M1_MASK, VFMSAC_VF }, // 687
  { PseudoVFMSAC_VF32_M2, VFMSAC_VF }, // 688
  { PseudoVFMSAC_VF32_M2_MASK, VFMSAC_VF }, // 689
  { PseudoVFMSAC_VF32_M4, VFMSAC_VF }, // 690
  { PseudoVFMSAC_VF32_M4_MASK, VFMSAC_VF }, // 691
  { PseudoVFMSAC_VF32_M8, VFMSAC_VF }, // 692
  { PseudoVFMSAC_VF32_M8_MASK, VFMSAC_VF }, // 693
  { PseudoVFMSAC_VF32_MF2, VFMSAC_VF }, // 694
  { PseudoVFMSAC_VF32_MF2_MASK, VFMSAC_VF }, // 695
  { PseudoVFMSAC_VF64_M1, VFMSAC_VF }, // 696
  { PseudoVFMSAC_VF64_M1_MASK, VFMSAC_VF }, // 697
  { PseudoVFMSAC_VF64_M2, VFMSAC_VF }, // 698
  { PseudoVFMSAC_VF64_M2_MASK, VFMSAC_VF }, // 699
  { PseudoVFMSAC_VF64_M4, VFMSAC_VF }, // 700
  { PseudoVFMSAC_VF64_M4_MASK, VFMSAC_VF }, // 701
  { PseudoVFMSAC_VF64_M8, VFMSAC_VF }, // 702
  { PseudoVFMSAC_VF64_M8_MASK, VFMSAC_VF }, // 703
  { PseudoVFMSAC_VV_M1, VFMSAC_VV }, // 704
  { PseudoVFMSAC_VV_M1_MASK, VFMSAC_VV }, // 705
  { PseudoVFMSAC_VV_M2, VFMSAC_VV }, // 706
  { PseudoVFMSAC_VV_M2_MASK, VFMSAC_VV }, // 707
  { PseudoVFMSAC_VV_M4, VFMSAC_VV }, // 708
  { PseudoVFMSAC_VV_M4_MASK, VFMSAC_VV }, // 709
  { PseudoVFMSAC_VV_M8, VFMSAC_VV }, // 710
  { PseudoVFMSAC_VV_M8_MASK, VFMSAC_VV }, // 711
  { PseudoVFMSAC_VV_MF2, VFMSAC_VV }, // 712
  { PseudoVFMSAC_VV_MF2_MASK, VFMSAC_VV }, // 713
  { PseudoVFMSAC_VV_MF4, VFMSAC_VV }, // 714
  { PseudoVFMSAC_VV_MF4_MASK, VFMSAC_VV }, // 715
  { PseudoVFMSUB_VF16_M1, VFMSUB_VF }, // 716
  { PseudoVFMSUB_VF16_M1_MASK, VFMSUB_VF }, // 717
  { PseudoVFMSUB_VF16_M2, VFMSUB_VF }, // 718
  { PseudoVFMSUB_VF16_M2_MASK, VFMSUB_VF }, // 719
  { PseudoVFMSUB_VF16_M4, VFMSUB_VF }, // 720
  { PseudoVFMSUB_VF16_M4_MASK, VFMSUB_VF }, // 721
  { PseudoVFMSUB_VF16_M8, VFMSUB_VF }, // 722
  { PseudoVFMSUB_VF16_M8_MASK, VFMSUB_VF }, // 723
  { PseudoVFMSUB_VF16_MF2, VFMSUB_VF }, // 724
  { PseudoVFMSUB_VF16_MF2_MASK, VFMSUB_VF }, // 725
  { PseudoVFMSUB_VF16_MF4, VFMSUB_VF }, // 726
  { PseudoVFMSUB_VF16_MF4_MASK, VFMSUB_VF }, // 727
  { PseudoVFMSUB_VF32_M1, VFMSUB_VF }, // 728
  { PseudoVFMSUB_VF32_M1_MASK, VFMSUB_VF }, // 729
  { PseudoVFMSUB_VF32_M2, VFMSUB_VF }, // 730
  { PseudoVFMSUB_VF32_M2_MASK, VFMSUB_VF }, // 731
  { PseudoVFMSUB_VF32_M4, VFMSUB_VF }, // 732
  { PseudoVFMSUB_VF32_M4_MASK, VFMSUB_VF }, // 733
  { PseudoVFMSUB_VF32_M8, VFMSUB_VF }, // 734
  { PseudoVFMSUB_VF32_M8_MASK, VFMSUB_VF }, // 735
  { PseudoVFMSUB_VF32_MF2, VFMSUB_VF }, // 736
  { PseudoVFMSUB_VF32_MF2_MASK, VFMSUB_VF }, // 737
  { PseudoVFMSUB_VF64_M1, VFMSUB_VF }, // 738
  { PseudoVFMSUB_VF64_M1_MASK, VFMSUB_VF }, // 739
  { PseudoVFMSUB_VF64_M2, VFMSUB_VF }, // 740
  { PseudoVFMSUB_VF64_M2_MASK, VFMSUB_VF }, // 741
  { PseudoVFMSUB_VF64_M4, VFMSUB_VF }, // 742
  { PseudoVFMSUB_VF64_M4_MASK, VFMSUB_VF }, // 743
  { PseudoVFMSUB_VF64_M8, VFMSUB_VF }, // 744
  { PseudoVFMSUB_VF64_M8_MASK, VFMSUB_VF }, // 745
  { PseudoVFMSUB_VV_M1, VFMSUB_VV }, // 746
  { PseudoVFMSUB_VV_M1_MASK, VFMSUB_VV }, // 747
  { PseudoVFMSUB_VV_M2, VFMSUB_VV }, // 748
  { PseudoVFMSUB_VV_M2_MASK, VFMSUB_VV }, // 749
  { PseudoVFMSUB_VV_M4, VFMSUB_VV }, // 750
  { PseudoVFMSUB_VV_M4_MASK, VFMSUB_VV }, // 751
  { PseudoVFMSUB_VV_M8, VFMSUB_VV }, // 752
  { PseudoVFMSUB_VV_M8_MASK, VFMSUB_VV }, // 753
  { PseudoVFMSUB_VV_MF2, VFMSUB_VV }, // 754
  { PseudoVFMSUB_VV_MF2_MASK, VFMSUB_VV }, // 755
  { PseudoVFMSUB_VV_MF4, VFMSUB_VV }, // 756
  { PseudoVFMSUB_VV_MF4_MASK, VFMSUB_VV }, // 757
  { PseudoVFMUL_VF16_M1, VFMUL_VF }, // 758
  { PseudoVFMUL_VF16_M1_MASK, VFMUL_VF }, // 759
  { PseudoVFMUL_VF16_M2, VFMUL_VF }, // 760
  { PseudoVFMUL_VF16_M2_MASK, VFMUL_VF }, // 761
  { PseudoVFMUL_VF16_M4, VFMUL_VF }, // 762
  { PseudoVFMUL_VF16_M4_MASK, VFMUL_VF }, // 763
  { PseudoVFMUL_VF16_M8, VFMUL_VF }, // 764
  { PseudoVFMUL_VF16_M8_MASK, VFMUL_VF }, // 765
  { PseudoVFMUL_VF16_MF2, VFMUL_VF }, // 766
  { PseudoVFMUL_VF16_MF2_MASK, VFMUL_VF }, // 767
  { PseudoVFMUL_VF16_MF4, VFMUL_VF }, // 768
  { PseudoVFMUL_VF16_MF4_MASK, VFMUL_VF }, // 769
  { PseudoVFMUL_VF32_M1, VFMUL_VF }, // 770
  { PseudoVFMUL_VF32_M1_MASK, VFMUL_VF }, // 771
  { PseudoVFMUL_VF32_M2, VFMUL_VF }, // 772
  { PseudoVFMUL_VF32_M2_MASK, VFMUL_VF }, // 773
  { PseudoVFMUL_VF32_M4, VFMUL_VF }, // 774
  { PseudoVFMUL_VF32_M4_MASK, VFMUL_VF }, // 775
  { PseudoVFMUL_VF32_M8, VFMUL_VF }, // 776
  { PseudoVFMUL_VF32_M8_MASK, VFMUL_VF }, // 777
  { PseudoVFMUL_VF32_MF2, VFMUL_VF }, // 778
  { PseudoVFMUL_VF32_MF2_MASK, VFMUL_VF }, // 779
  { PseudoVFMUL_VF64_M1, VFMUL_VF }, // 780
  { PseudoVFMUL_VF64_M1_MASK, VFMUL_VF }, // 781
  { PseudoVFMUL_VF64_M2, VFMUL_VF }, // 782
  { PseudoVFMUL_VF64_M2_MASK, VFMUL_VF }, // 783
  { PseudoVFMUL_VF64_M4, VFMUL_VF }, // 784
  { PseudoVFMUL_VF64_M4_MASK, VFMUL_VF }, // 785
  { PseudoVFMUL_VF64_M8, VFMUL_VF }, // 786
  { PseudoVFMUL_VF64_M8_MASK, VFMUL_VF }, // 787
  { PseudoVFMUL_VV_M1, VFMUL_VV }, // 788
  { PseudoVFMUL_VV_M1_MASK, VFMUL_VV }, // 789
  { PseudoVFMUL_VV_M2, VFMUL_VV }, // 790
  { PseudoVFMUL_VV_M2_MASK, VFMUL_VV }, // 791
  { PseudoVFMUL_VV_M4, VFMUL_VV }, // 792
  { PseudoVFMUL_VV_M4_MASK, VFMUL_VV }, // 793
  { PseudoVFMUL_VV_M8, VFMUL_VV }, // 794
  { PseudoVFMUL_VV_M8_MASK, VFMUL_VV }, // 795
  { PseudoVFMUL_VV_MF2, VFMUL_VV }, // 796
  { PseudoVFMUL_VV_MF2_MASK, VFMUL_VV }, // 797
  { PseudoVFMUL_VV_MF4, VFMUL_VV }, // 798
  { PseudoVFMUL_VV_MF4_MASK, VFMUL_VV }, // 799
  { PseudoVFMV_F16_S_M1, VFMV_F_S }, // 800
  { PseudoVFMV_F16_S_M2, VFMV_F_S }, // 801
  { PseudoVFMV_F16_S_M4, VFMV_F_S }, // 802
  { PseudoVFMV_F16_S_M8, VFMV_F_S }, // 803
  { PseudoVFMV_F16_S_MF2, VFMV_F_S }, // 804
  { PseudoVFMV_F16_S_MF4, VFMV_F_S }, // 805
  { PseudoVFMV_F32_S_M1, VFMV_F_S }, // 806
  { PseudoVFMV_F32_S_M2, VFMV_F_S }, // 807
  { PseudoVFMV_F32_S_M4, VFMV_F_S }, // 808
  { PseudoVFMV_F32_S_M8, VFMV_F_S }, // 809
  { PseudoVFMV_F32_S_MF2, VFMV_F_S }, // 810
  { PseudoVFMV_F64_S_M1, VFMV_F_S }, // 811
  { PseudoVFMV_F64_S_M2, VFMV_F_S }, // 812
  { PseudoVFMV_F64_S_M4, VFMV_F_S }, // 813
  { PseudoVFMV_F64_S_M8, VFMV_F_S }, // 814
  { PseudoVFMV_S_F16_M1, VFMV_S_F }, // 815
  { PseudoVFMV_S_F16_M2, VFMV_S_F }, // 816
  { PseudoVFMV_S_F16_M4, VFMV_S_F }, // 817
  { PseudoVFMV_S_F16_M8, VFMV_S_F }, // 818
  { PseudoVFMV_S_F16_MF2, VFMV_S_F }, // 819
  { PseudoVFMV_S_F16_MF4, VFMV_S_F }, // 820
  { PseudoVFMV_S_F32_M1, VFMV_S_F }, // 821
  { PseudoVFMV_S_F32_M2, VFMV_S_F }, // 822
  { PseudoVFMV_S_F32_M4, VFMV_S_F }, // 823
  { PseudoVFMV_S_F32_M8, VFMV_S_F }, // 824
  { PseudoVFMV_S_F32_MF2, VFMV_S_F }, // 825
  { PseudoVFMV_S_F64_M1, VFMV_S_F }, // 826
  { PseudoVFMV_S_F64_M2, VFMV_S_F }, // 827
  { PseudoVFMV_S_F64_M4, VFMV_S_F }, // 828
  { PseudoVFMV_S_F64_M8, VFMV_S_F }, // 829
  { PseudoVFMV_V_F16_M1, VFMV_V_F }, // 830
  { PseudoVFMV_V_F16_M2, VFMV_V_F }, // 831
  { PseudoVFMV_V_F16_M4, VFMV_V_F }, // 832
  { PseudoVFMV_V_F16_M8, VFMV_V_F }, // 833
  { PseudoVFMV_V_F16_MF2, VFMV_V_F }, // 834
  { PseudoVFMV_V_F16_MF4, VFMV_V_F }, // 835
  { PseudoVFMV_V_F32_M1, VFMV_V_F }, // 836
  { PseudoVFMV_V_F32_M2, VFMV_V_F }, // 837
  { PseudoVFMV_V_F32_M4, VFMV_V_F }, // 838
  { PseudoVFMV_V_F32_M8, VFMV_V_F }, // 839
  { PseudoVFMV_V_F32_MF2, VFMV_V_F }, // 840
  { PseudoVFMV_V_F64_M1, VFMV_V_F }, // 841
  { PseudoVFMV_V_F64_M2, VFMV_V_F }, // 842
  { PseudoVFMV_V_F64_M4, VFMV_V_F }, // 843
  { PseudoVFMV_V_F64_M8, VFMV_V_F }, // 844
  { PseudoVFNCVT_F_F_W_M1, VFNCVT_F_F_W }, // 845
  { PseudoVFNCVT_F_F_W_M1_MASK, VFNCVT_F_F_W }, // 846
  { PseudoVFNCVT_F_F_W_M2, VFNCVT_F_F_W }, // 847
  { PseudoVFNCVT_F_F_W_M2_MASK, VFNCVT_F_F_W }, // 848
  { PseudoVFNCVT_F_F_W_M4, VFNCVT_F_F_W }, // 849
  { PseudoVFNCVT_F_F_W_M4_MASK, VFNCVT_F_F_W }, // 850
  { PseudoVFNCVT_F_F_W_MF2, VFNCVT_F_F_W }, // 851
  { PseudoVFNCVT_F_F_W_MF2_MASK, VFNCVT_F_F_W }, // 852
  { PseudoVFNCVT_F_F_W_MF4, VFNCVT_F_F_W }, // 853
  { PseudoVFNCVT_F_F_W_MF4_MASK, VFNCVT_F_F_W }, // 854
  { PseudoVFNCVT_F_XU_W_M1, VFNCVT_F_XU_W }, // 855
  { PseudoVFNCVT_F_XU_W_M1_MASK, VFNCVT_F_XU_W }, // 856
  { PseudoVFNCVT_F_XU_W_M2, VFNCVT_F_XU_W }, // 857
  { PseudoVFNCVT_F_XU_W_M2_MASK, VFNCVT_F_XU_W }, // 858
  { PseudoVFNCVT_F_XU_W_M4, VFNCVT_F_XU_W }, // 859
  { PseudoVFNCVT_F_XU_W_M4_MASK, VFNCVT_F_XU_W }, // 860
  { PseudoVFNCVT_F_XU_W_MF2, VFNCVT_F_XU_W }, // 861
  { PseudoVFNCVT_F_XU_W_MF2_MASK, VFNCVT_F_XU_W }, // 862
  { PseudoVFNCVT_F_XU_W_MF4, VFNCVT_F_XU_W }, // 863
  { PseudoVFNCVT_F_XU_W_MF4_MASK, VFNCVT_F_XU_W }, // 864
  { PseudoVFNCVT_F_X_W_M1, VFNCVT_F_X_W }, // 865
  { PseudoVFNCVT_F_X_W_M1_MASK, VFNCVT_F_X_W }, // 866
  { PseudoVFNCVT_F_X_W_M2, VFNCVT_F_X_W }, // 867
  { PseudoVFNCVT_F_X_W_M2_MASK, VFNCVT_F_X_W }, // 868
  { PseudoVFNCVT_F_X_W_M4, VFNCVT_F_X_W }, // 869
  { PseudoVFNCVT_F_X_W_M4_MASK, VFNCVT_F_X_W }, // 870
  { PseudoVFNCVT_F_X_W_MF2, VFNCVT_F_X_W }, // 871
  { PseudoVFNCVT_F_X_W_MF2_MASK, VFNCVT_F_X_W }, // 872
  { PseudoVFNCVT_F_X_W_MF4, VFNCVT_F_X_W }, // 873
  { PseudoVFNCVT_F_X_W_MF4_MASK, VFNCVT_F_X_W }, // 874
  { PseudoVFNCVT_ROD_F_F_W_M1, VFNCVT_ROD_F_F_W }, // 875
  { PseudoVFNCVT_ROD_F_F_W_M1_MASK, VFNCVT_ROD_F_F_W }, // 876
  { PseudoVFNCVT_ROD_F_F_W_M2, VFNCVT_ROD_F_F_W }, // 877
  { PseudoVFNCVT_ROD_F_F_W_M2_MASK, VFNCVT_ROD_F_F_W }, // 878
  { PseudoVFNCVT_ROD_F_F_W_M4, VFNCVT_ROD_F_F_W }, // 879
  { PseudoVFNCVT_ROD_F_F_W_M4_MASK, VFNCVT_ROD_F_F_W }, // 880
  { PseudoVFNCVT_ROD_F_F_W_MF2, VFNCVT_ROD_F_F_W }, // 881
  { PseudoVFNCVT_ROD_F_F_W_MF2_MASK, VFNCVT_ROD_F_F_W }, // 882
  { PseudoVFNCVT_ROD_F_F_W_MF4, VFNCVT_ROD_F_F_W }, // 883
  { PseudoVFNCVT_ROD_F_F_W_MF4_MASK, VFNCVT_ROD_F_F_W }, // 884
  { PseudoVFNCVT_RTZ_XU_F_W_M1, VFNCVT_RTZ_XU_F_W }, // 885
  { PseudoVFNCVT_RTZ_XU_F_W_M1_MASK, VFNCVT_RTZ_XU_F_W }, // 886
  { PseudoVFNCVT_RTZ_XU_F_W_M2, VFNCVT_RTZ_XU_F_W }, // 887
  { PseudoVFNCVT_RTZ_XU_F_W_M2_MASK, VFNCVT_RTZ_XU_F_W }, // 888
  { PseudoVFNCVT_RTZ_XU_F_W_M4, VFNCVT_RTZ_XU_F_W }, // 889
  { PseudoVFNCVT_RTZ_XU_F_W_M4_MASK, VFNCVT_RTZ_XU_F_W }, // 890
  { PseudoVFNCVT_RTZ_XU_F_W_MF2, VFNCVT_RTZ_XU_F_W }, // 891
  { PseudoVFNCVT_RTZ_XU_F_W_MF2_MASK, VFNCVT_RTZ_XU_F_W }, // 892
  { PseudoVFNCVT_RTZ_XU_F_W_MF4, VFNCVT_RTZ_XU_F_W }, // 893
  { PseudoVFNCVT_RTZ_XU_F_W_MF4_MASK, VFNCVT_RTZ_XU_F_W }, // 894
  { PseudoVFNCVT_RTZ_XU_F_W_MF8, VFNCVT_RTZ_XU_F_W }, // 895
  { PseudoVFNCVT_RTZ_XU_F_W_MF8_MASK, VFNCVT_RTZ_XU_F_W }, // 896
  { PseudoVFNCVT_RTZ_X_F_W_M1, VFNCVT_RTZ_X_F_W }, // 897
  { PseudoVFNCVT_RTZ_X_F_W_M1_MASK, VFNCVT_RTZ_X_F_W }, // 898
  { PseudoVFNCVT_RTZ_X_F_W_M2, VFNCVT_RTZ_X_F_W }, // 899
  { PseudoVFNCVT_RTZ_X_F_W_M2_MASK, VFNCVT_RTZ_X_F_W }, // 900
  { PseudoVFNCVT_RTZ_X_F_W_M4, VFNCVT_RTZ_X_F_W }, // 901
  { PseudoVFNCVT_RTZ_X_F_W_M4_MASK, VFNCVT_RTZ_X_F_W }, // 902
  { PseudoVFNCVT_RTZ_X_F_W_MF2, VFNCVT_RTZ_X_F_W }, // 903
  { PseudoVFNCVT_RTZ_X_F_W_MF2_MASK, VFNCVT_RTZ_X_F_W }, // 904
  { PseudoVFNCVT_RTZ_X_F_W_MF4, VFNCVT_RTZ_X_F_W }, // 905
  { PseudoVFNCVT_RTZ_X_F_W_MF4_MASK, VFNCVT_RTZ_X_F_W }, // 906
  { PseudoVFNCVT_RTZ_X_F_W_MF8, VFNCVT_RTZ_X_F_W }, // 907
  { PseudoVFNCVT_RTZ_X_F_W_MF8_MASK, VFNCVT_RTZ_X_F_W }, // 908
  { PseudoVFNCVT_XU_F_W_M1, VFNCVT_XU_F_W }, // 909
  { PseudoVFNCVT_XU_F_W_M1_MASK, VFNCVT_XU_F_W }, // 910
  { PseudoVFNCVT_XU_F_W_M2, VFNCVT_XU_F_W }, // 911
  { PseudoVFNCVT_XU_F_W_M2_MASK, VFNCVT_XU_F_W }, // 912
  { PseudoVFNCVT_XU_F_W_M4, VFNCVT_XU_F_W }, // 913
  { PseudoVFNCVT_XU_F_W_M4_MASK, VFNCVT_XU_F_W }, // 914
  { PseudoVFNCVT_XU_F_W_MF2, VFNCVT_XU_F_W }, // 915
  { PseudoVFNCVT_XU_F_W_MF2_MASK, VFNCVT_XU_F_W }, // 916
  { PseudoVFNCVT_XU_F_W_MF4, VFNCVT_XU_F_W }, // 917
  { PseudoVFNCVT_XU_F_W_MF4_MASK, VFNCVT_XU_F_W }, // 918
  { PseudoVFNCVT_XU_F_W_MF8, VFNCVT_XU_F_W }, // 919
  { PseudoVFNCVT_XU_F_W_MF8_MASK, VFNCVT_XU_F_W }, // 920
  { PseudoVFNCVT_X_F_W_M1, VFNCVT_X_F_W }, // 921
  { PseudoVFNCVT_X_F_W_M1_MASK, VFNCVT_X_F_W }, // 922
  { PseudoVFNCVT_X_F_W_M2, VFNCVT_X_F_W }, // 923
  { PseudoVFNCVT_X_F_W_M2_MASK, VFNCVT_X_F_W }, // 924
  { PseudoVFNCVT_X_F_W_M4, VFNCVT_X_F_W }, // 925
  { PseudoVFNCVT_X_F_W_M4_MASK, VFNCVT_X_F_W }, // 926
  { PseudoVFNCVT_X_F_W_MF2, VFNCVT_X_F_W }, // 927
  { PseudoVFNCVT_X_F_W_MF2_MASK, VFNCVT_X_F_W }, // 928
  { PseudoVFNCVT_X_F_W_MF4, VFNCVT_X_F_W }, // 929
  { PseudoVFNCVT_X_F_W_MF4_MASK, VFNCVT_X_F_W }, // 930
  { PseudoVFNCVT_X_F_W_MF8, VFNCVT_X_F_W }, // 931
  { PseudoVFNCVT_X_F_W_MF8_MASK, VFNCVT_X_F_W }, // 932
  { PseudoVFNMACC_VF16_M1, VFNMACC_VF }, // 933
  { PseudoVFNMACC_VF16_M1_MASK, VFNMACC_VF }, // 934
  { PseudoVFNMACC_VF16_M2, VFNMACC_VF }, // 935
  { PseudoVFNMACC_VF16_M2_MASK, VFNMACC_VF }, // 936
  { PseudoVFNMACC_VF16_M4, VFNMACC_VF }, // 937
  { PseudoVFNMACC_VF16_M4_MASK, VFNMACC_VF }, // 938
  { PseudoVFNMACC_VF16_M8, VFNMACC_VF }, // 939
  { PseudoVFNMACC_VF16_M8_MASK, VFNMACC_VF }, // 940
  { PseudoVFNMACC_VF16_MF2, VFNMACC_VF }, // 941
  { PseudoVFNMACC_VF16_MF2_MASK, VFNMACC_VF }, // 942
  { PseudoVFNMACC_VF16_MF4, VFNMACC_VF }, // 943
  { PseudoVFNMACC_VF16_MF4_MASK, VFNMACC_VF }, // 944
  { PseudoVFNMACC_VF32_M1, VFNMACC_VF }, // 945
  { PseudoVFNMACC_VF32_M1_MASK, VFNMACC_VF }, // 946
  { PseudoVFNMACC_VF32_M2, VFNMACC_VF }, // 947
  { PseudoVFNMACC_VF32_M2_MASK, VFNMACC_VF }, // 948
  { PseudoVFNMACC_VF32_M4, VFNMACC_VF }, // 949
  { PseudoVFNMACC_VF32_M4_MASK, VFNMACC_VF }, // 950
  { PseudoVFNMACC_VF32_M8, VFNMACC_VF }, // 951
  { PseudoVFNMACC_VF32_M8_MASK, VFNMACC_VF }, // 952
  { PseudoVFNMACC_VF32_MF2, VFNMACC_VF }, // 953
  { PseudoVFNMACC_VF32_MF2_MASK, VFNMACC_VF }, // 954
  { PseudoVFNMACC_VF64_M1, VFNMACC_VF }, // 955
  { PseudoVFNMACC_VF64_M1_MASK, VFNMACC_VF }, // 956
  { PseudoVFNMACC_VF64_M2, VFNMACC_VF }, // 957
  { PseudoVFNMACC_VF64_M2_MASK, VFNMACC_VF }, // 958
  { PseudoVFNMACC_VF64_M4, VFNMACC_VF }, // 959
  { PseudoVFNMACC_VF64_M4_MASK, VFNMACC_VF }, // 960
  { PseudoVFNMACC_VF64_M8, VFNMACC_VF }, // 961
  { PseudoVFNMACC_VF64_M8_MASK, VFNMACC_VF }, // 962
  { PseudoVFNMACC_VV_M1, VFNMACC_VV }, // 963
  { PseudoVFNMACC_VV_M1_MASK, VFNMACC_VV }, // 964
  { PseudoVFNMACC_VV_M2, VFNMACC_VV }, // 965
  { PseudoVFNMACC_VV_M2_MASK, VFNMACC_VV }, // 966
  { PseudoVFNMACC_VV_M4, VFNMACC_VV }, // 967
  { PseudoVFNMACC_VV_M4_MASK, VFNMACC_VV }, // 968
  { PseudoVFNMACC_VV_M8, VFNMACC_VV }, // 969
  { PseudoVFNMACC_VV_M8_MASK, VFNMACC_VV }, // 970
  { PseudoVFNMACC_VV_MF2, VFNMACC_VV }, // 971
  { PseudoVFNMACC_VV_MF2_MASK, VFNMACC_VV }, // 972
  { PseudoVFNMACC_VV_MF4, VFNMACC_VV }, // 973
  { PseudoVFNMACC_VV_MF4_MASK, VFNMACC_VV }, // 974
  { PseudoVFNMADD_VF16_M1, VFNMADD_VF }, // 975
  { PseudoVFNMADD_VF16_M1_MASK, VFNMADD_VF }, // 976
  { PseudoVFNMADD_VF16_M2, VFNMADD_VF }, // 977
  { PseudoVFNMADD_VF16_M2_MASK, VFNMADD_VF }, // 978
  { PseudoVFNMADD_VF16_M4, VFNMADD_VF }, // 979
  { PseudoVFNMADD_VF16_M4_MASK, VFNMADD_VF }, // 980
  { PseudoVFNMADD_VF16_M8, VFNMADD_VF }, // 981
  { PseudoVFNMADD_VF16_M8_MASK, VFNMADD_VF }, // 982
  { PseudoVFNMADD_VF16_MF2, VFNMADD_VF }, // 983
  { PseudoVFNMADD_VF16_MF2_MASK, VFNMADD_VF }, // 984
  { PseudoVFNMADD_VF16_MF4, VFNMADD_VF }, // 985
  { PseudoVFNMADD_VF16_MF4_MASK, VFNMADD_VF }, // 986
  { PseudoVFNMADD_VF32_M1, VFNMADD_VF }, // 987
  { PseudoVFNMADD_VF32_M1_MASK, VFNMADD_VF }, // 988
  { PseudoVFNMADD_VF32_M2, VFNMADD_VF }, // 989
  { PseudoVFNMADD_VF32_M2_MASK, VFNMADD_VF }, // 990
  { PseudoVFNMADD_VF32_M4, VFNMADD_VF }, // 991
  { PseudoVFNMADD_VF32_M4_MASK, VFNMADD_VF }, // 992
  { PseudoVFNMADD_VF32_M8, VFNMADD_VF }, // 993
  { PseudoVFNMADD_VF32_M8_MASK, VFNMADD_VF }, // 994
  { PseudoVFNMADD_VF32_MF2, VFNMADD_VF }, // 995
  { PseudoVFNMADD_VF32_MF2_MASK, VFNMADD_VF }, // 996
  { PseudoVFNMADD_VF64_M1, VFNMADD_VF }, // 997
  { PseudoVFNMADD_VF64_M1_MASK, VFNMADD_VF }, // 998
  { PseudoVFNMADD_VF64_M2, VFNMADD_VF }, // 999
  { PseudoVFNMADD_VF64_M2_MASK, VFNMADD_VF }, // 1000
  { PseudoVFNMADD_VF64_M4, VFNMADD_VF }, // 1001
  { PseudoVFNMADD_VF64_M4_MASK, VFNMADD_VF }, // 1002
  { PseudoVFNMADD_VF64_M8, VFNMADD_VF }, // 1003
  { PseudoVFNMADD_VF64_M8_MASK, VFNMADD_VF }, // 1004
  { PseudoVFNMADD_VV_M1, VFNMADD_VV }, // 1005
  { PseudoVFNMADD_VV_M1_MASK, VFNMADD_VV }, // 1006
  { PseudoVFNMADD_VV_M2, VFNMADD_VV }, // 1007
  { PseudoVFNMADD_VV_M2_MASK, VFNMADD_VV }, // 1008
  { PseudoVFNMADD_VV_M4, VFNMADD_VV }, // 1009
  { PseudoVFNMADD_VV_M4_MASK, VFNMADD_VV }, // 1010
  { PseudoVFNMADD_VV_M8, VFNMADD_VV }, // 1011
  { PseudoVFNMADD_VV_M8_MASK, VFNMADD_VV }, // 1012
  { PseudoVFNMADD_VV_MF2, VFNMADD_VV }, // 1013
  { PseudoVFNMADD_VV_MF2_MASK, VFNMADD_VV }, // 1014
  { PseudoVFNMADD_VV_MF4, VFNMADD_VV }, // 1015
  { PseudoVFNMADD_VV_MF4_MASK, VFNMADD_VV }, // 1016
  { PseudoVFNMSAC_VF16_M1, VFNMSAC_VF }, // 1017
  { PseudoVFNMSAC_VF16_M1_MASK, VFNMSAC_VF }, // 1018
  { PseudoVFNMSAC_VF16_M2, VFNMSAC_VF }, // 1019
  { PseudoVFNMSAC_VF16_M2_MASK, VFNMSAC_VF }, // 1020
  { PseudoVFNMSAC_VF16_M4, VFNMSAC_VF }, // 1021
  { PseudoVFNMSAC_VF16_M4_MASK, VFNMSAC_VF }, // 1022
  { PseudoVFNMSAC_VF16_M8, VFNMSAC_VF }, // 1023
  { PseudoVFNMSAC_VF16_M8_MASK, VFNMSAC_VF }, // 1024
  { PseudoVFNMSAC_VF16_MF2, VFNMSAC_VF }, // 1025
  { PseudoVFNMSAC_VF16_MF2_MASK, VFNMSAC_VF }, // 1026
  { PseudoVFNMSAC_VF16_MF4, VFNMSAC_VF }, // 1027
  { PseudoVFNMSAC_VF16_MF4_MASK, VFNMSAC_VF }, // 1028
  { PseudoVFNMSAC_VF32_M1, VFNMSAC_VF }, // 1029
  { PseudoVFNMSAC_VF32_M1_MASK, VFNMSAC_VF }, // 1030
  { PseudoVFNMSAC_VF32_M2, VFNMSAC_VF }, // 1031
  { PseudoVFNMSAC_VF32_M2_MASK, VFNMSAC_VF }, // 1032
  { PseudoVFNMSAC_VF32_M4, VFNMSAC_VF }, // 1033
  { PseudoVFNMSAC_VF32_M4_MASK, VFNMSAC_VF }, // 1034
  { PseudoVFNMSAC_VF32_M8, VFNMSAC_VF }, // 1035
  { PseudoVFNMSAC_VF32_M8_MASK, VFNMSAC_VF }, // 1036
  { PseudoVFNMSAC_VF32_MF2, VFNMSAC_VF }, // 1037
  { PseudoVFNMSAC_VF32_MF2_MASK, VFNMSAC_VF }, // 1038
  { PseudoVFNMSAC_VF64_M1, VFNMSAC_VF }, // 1039
  { PseudoVFNMSAC_VF64_M1_MASK, VFNMSAC_VF }, // 1040
  { PseudoVFNMSAC_VF64_M2, VFNMSAC_VF }, // 1041
  { PseudoVFNMSAC_VF64_M2_MASK, VFNMSAC_VF }, // 1042
  { PseudoVFNMSAC_VF64_M4, VFNMSAC_VF }, // 1043
  { PseudoVFNMSAC_VF64_M4_MASK, VFNMSAC_VF }, // 1044
  { PseudoVFNMSAC_VF64_M8, VFNMSAC_VF }, // 1045
  { PseudoVFNMSAC_VF64_M8_MASK, VFNMSAC_VF }, // 1046
  { PseudoVFNMSAC_VV_M1, VFNMSAC_VV }, // 1047
  { PseudoVFNMSAC_VV_M1_MASK, VFNMSAC_VV }, // 1048
  { PseudoVFNMSAC_VV_M2, VFNMSAC_VV }, // 1049
  { PseudoVFNMSAC_VV_M2_MASK, VFNMSAC_VV }, // 1050
  { PseudoVFNMSAC_VV_M4, VFNMSAC_VV }, // 1051
  { PseudoVFNMSAC_VV_M4_MASK, VFNMSAC_VV }, // 1052
  { PseudoVFNMSAC_VV_M8, VFNMSAC_VV }, // 1053
  { PseudoVFNMSAC_VV_M8_MASK, VFNMSAC_VV }, // 1054
  { PseudoVFNMSAC_VV_MF2, VFNMSAC_VV }, // 1055
  { PseudoVFNMSAC_VV_MF2_MASK, VFNMSAC_VV }, // 1056
  { PseudoVFNMSAC_VV_MF4, VFNMSAC_VV }, // 1057
  { PseudoVFNMSAC_VV_MF4_MASK, VFNMSAC_VV }, // 1058
  { PseudoVFNMSUB_VF16_M1, VFNMSUB_VF }, // 1059
  { PseudoVFNMSUB_VF16_M1_MASK, VFNMSUB_VF }, // 1060
  { PseudoVFNMSUB_VF16_M2, VFNMSUB_VF }, // 1061
  { PseudoVFNMSUB_VF16_M2_MASK, VFNMSUB_VF }, // 1062
  { PseudoVFNMSUB_VF16_M4, VFNMSUB_VF }, // 1063
  { PseudoVFNMSUB_VF16_M4_MASK, VFNMSUB_VF }, // 1064
  { PseudoVFNMSUB_VF16_M8, VFNMSUB_VF }, // 1065
  { PseudoVFNMSUB_VF16_M8_MASK, VFNMSUB_VF }, // 1066
  { PseudoVFNMSUB_VF16_MF2, VFNMSUB_VF }, // 1067
  { PseudoVFNMSUB_VF16_MF2_MASK, VFNMSUB_VF }, // 1068
  { PseudoVFNMSUB_VF16_MF4, VFNMSUB_VF }, // 1069
  { PseudoVFNMSUB_VF16_MF4_MASK, VFNMSUB_VF }, // 1070
  { PseudoVFNMSUB_VF32_M1, VFNMSUB_VF }, // 1071
  { PseudoVFNMSUB_VF32_M1_MASK, VFNMSUB_VF }, // 1072
  { PseudoVFNMSUB_VF32_M2, VFNMSUB_VF }, // 1073
  { PseudoVFNMSUB_VF32_M2_MASK, VFNMSUB_VF }, // 1074
  { PseudoVFNMSUB_VF32_M4, VFNMSUB_VF }, // 1075
  { PseudoVFNMSUB_VF32_M4_MASK, VFNMSUB_VF }, // 1076
  { PseudoVFNMSUB_VF32_M8, VFNMSUB_VF }, // 1077
  { PseudoVFNMSUB_VF32_M8_MASK, VFNMSUB_VF }, // 1078
  { PseudoVFNMSUB_VF32_MF2, VFNMSUB_VF }, // 1079
  { PseudoVFNMSUB_VF32_MF2_MASK, VFNMSUB_VF }, // 1080
  { PseudoVFNMSUB_VF64_M1, VFNMSUB_VF }, // 1081
  { PseudoVFNMSUB_VF64_M1_MASK, VFNMSUB_VF }, // 1082
  { PseudoVFNMSUB_VF64_M2, VFNMSUB_VF }, // 1083
  { PseudoVFNMSUB_VF64_M2_MASK, VFNMSUB_VF }, // 1084
  { PseudoVFNMSUB_VF64_M4, VFNMSUB_VF }, // 1085
  { PseudoVFNMSUB_VF64_M4_MASK, VFNMSUB_VF }, // 1086
  { PseudoVFNMSUB_VF64_M8, VFNMSUB_VF }, // 1087
  { PseudoVFNMSUB_VF64_M8_MASK, VFNMSUB_VF }, // 1088
  { PseudoVFNMSUB_VV_M1, VFNMSUB_VV }, // 1089
  { PseudoVFNMSUB_VV_M1_MASK, VFNMSUB_VV }, // 1090
  { PseudoVFNMSUB_VV_M2, VFNMSUB_VV }, // 1091
  { PseudoVFNMSUB_VV_M2_MASK, VFNMSUB_VV }, // 1092
  { PseudoVFNMSUB_VV_M4, VFNMSUB_VV }, // 1093
  { PseudoVFNMSUB_VV_M4_MASK, VFNMSUB_VV }, // 1094
  { PseudoVFNMSUB_VV_M8, VFNMSUB_VV }, // 1095
  { PseudoVFNMSUB_VV_M8_MASK, VFNMSUB_VV }, // 1096
  { PseudoVFNMSUB_VV_MF2, VFNMSUB_VV }, // 1097
  { PseudoVFNMSUB_VV_MF2_MASK, VFNMSUB_VV }, // 1098
  { PseudoVFNMSUB_VV_MF4, VFNMSUB_VV }, // 1099
  { PseudoVFNMSUB_VV_MF4_MASK, VFNMSUB_VV }, // 1100
  { PseudoVFRDIV_VF16_M1, VFRDIV_VF }, // 1101
  { PseudoVFRDIV_VF16_M1_MASK, VFRDIV_VF }, // 1102
  { PseudoVFRDIV_VF16_M2, VFRDIV_VF }, // 1103
  { PseudoVFRDIV_VF16_M2_MASK, VFRDIV_VF }, // 1104
  { PseudoVFRDIV_VF16_M4, VFRDIV_VF }, // 1105
  { PseudoVFRDIV_VF16_M4_MASK, VFRDIV_VF }, // 1106
  { PseudoVFRDIV_VF16_M8, VFRDIV_VF }, // 1107
  { PseudoVFRDIV_VF16_M8_MASK, VFRDIV_VF }, // 1108
  { PseudoVFRDIV_VF16_MF2, VFRDIV_VF }, // 1109
  { PseudoVFRDIV_VF16_MF2_MASK, VFRDIV_VF }, // 1110
  { PseudoVFRDIV_VF16_MF4, VFRDIV_VF }, // 1111
  { PseudoVFRDIV_VF16_MF4_MASK, VFRDIV_VF }, // 1112
  { PseudoVFRDIV_VF32_M1, VFRDIV_VF }, // 1113
  { PseudoVFRDIV_VF32_M1_MASK, VFRDIV_VF }, // 1114
  { PseudoVFRDIV_VF32_M2, VFRDIV_VF }, // 1115
  { PseudoVFRDIV_VF32_M2_MASK, VFRDIV_VF }, // 1116
  { PseudoVFRDIV_VF32_M4, VFRDIV_VF }, // 1117
  { PseudoVFRDIV_VF32_M4_MASK, VFRDIV_VF }, // 1118
  { PseudoVFRDIV_VF32_M8, VFRDIV_VF }, // 1119
  { PseudoVFRDIV_VF32_M8_MASK, VFRDIV_VF }, // 1120
  { PseudoVFRDIV_VF32_MF2, VFRDIV_VF }, // 1121
  { PseudoVFRDIV_VF32_MF2_MASK, VFRDIV_VF }, // 1122
  { PseudoVFRDIV_VF64_M1, VFRDIV_VF }, // 1123
  { PseudoVFRDIV_VF64_M1_MASK, VFRDIV_VF }, // 1124
  { PseudoVFRDIV_VF64_M2, VFRDIV_VF }, // 1125
  { PseudoVFRDIV_VF64_M2_MASK, VFRDIV_VF }, // 1126
  { PseudoVFRDIV_VF64_M4, VFRDIV_VF }, // 1127
  { PseudoVFRDIV_VF64_M4_MASK, VFRDIV_VF }, // 1128
  { PseudoVFRDIV_VF64_M8, VFRDIV_VF }, // 1129
  { PseudoVFRDIV_VF64_M8_MASK, VFRDIV_VF }, // 1130
  { PseudoVFREC7_V_M1, VFREC7_V }, // 1131
  { PseudoVFREC7_V_M1_MASK, VFREC7_V }, // 1132
  { PseudoVFREC7_V_M2, VFREC7_V }, // 1133
  { PseudoVFREC7_V_M2_MASK, VFREC7_V }, // 1134
  { PseudoVFREC7_V_M4, VFREC7_V }, // 1135
  { PseudoVFREC7_V_M4_MASK, VFREC7_V }, // 1136
  { PseudoVFREC7_V_M8, VFREC7_V }, // 1137
  { PseudoVFREC7_V_M8_MASK, VFREC7_V }, // 1138
  { PseudoVFREC7_V_MF2, VFREC7_V }, // 1139
  { PseudoVFREC7_V_MF2_MASK, VFREC7_V }, // 1140
  { PseudoVFREC7_V_MF4, VFREC7_V }, // 1141
  { PseudoVFREC7_V_MF4_MASK, VFREC7_V }, // 1142
  { PseudoVFREDMAX_VS_M1, VFREDMAX_VS }, // 1143
  { PseudoVFREDMAX_VS_M1_MASK, VFREDMAX_VS }, // 1144
  { PseudoVFREDMAX_VS_M2, VFREDMAX_VS }, // 1145
  { PseudoVFREDMAX_VS_M2_MASK, VFREDMAX_VS }, // 1146
  { PseudoVFREDMAX_VS_M4, VFREDMAX_VS }, // 1147
  { PseudoVFREDMAX_VS_M4_MASK, VFREDMAX_VS }, // 1148
  { PseudoVFREDMAX_VS_M8, VFREDMAX_VS }, // 1149
  { PseudoVFREDMAX_VS_M8_MASK, VFREDMAX_VS }, // 1150
  { PseudoVFREDMAX_VS_MF2, VFREDMAX_VS }, // 1151
  { PseudoVFREDMAX_VS_MF2_MASK, VFREDMAX_VS }, // 1152
  { PseudoVFREDMAX_VS_MF4, VFREDMAX_VS }, // 1153
  { PseudoVFREDMAX_VS_MF4_MASK, VFREDMAX_VS }, // 1154
  { PseudoVFREDMIN_VS_M1, VFREDMIN_VS }, // 1155
  { PseudoVFREDMIN_VS_M1_MASK, VFREDMIN_VS }, // 1156
  { PseudoVFREDMIN_VS_M2, VFREDMIN_VS }, // 1157
  { PseudoVFREDMIN_VS_M2_MASK, VFREDMIN_VS }, // 1158
  { PseudoVFREDMIN_VS_M4, VFREDMIN_VS }, // 1159
  { PseudoVFREDMIN_VS_M4_MASK, VFREDMIN_VS }, // 1160
  { PseudoVFREDMIN_VS_M8, VFREDMIN_VS }, // 1161
  { PseudoVFREDMIN_VS_M8_MASK, VFREDMIN_VS }, // 1162
  { PseudoVFREDMIN_VS_MF2, VFREDMIN_VS }, // 1163
  { PseudoVFREDMIN_VS_MF2_MASK, VFREDMIN_VS }, // 1164
  { PseudoVFREDMIN_VS_MF4, VFREDMIN_VS }, // 1165
  { PseudoVFREDMIN_VS_MF4_MASK, VFREDMIN_VS }, // 1166
  { PseudoVFREDOSUM_VS_M1, VFREDOSUM_VS }, // 1167
  { PseudoVFREDOSUM_VS_M1_MASK, VFREDOSUM_VS }, // 1168
  { PseudoVFREDOSUM_VS_M2, VFREDOSUM_VS }, // 1169
  { PseudoVFREDOSUM_VS_M2_MASK, VFREDOSUM_VS }, // 1170
  { PseudoVFREDOSUM_VS_M4, VFREDOSUM_VS }, // 1171
  { PseudoVFREDOSUM_VS_M4_MASK, VFREDOSUM_VS }, // 1172
  { PseudoVFREDOSUM_VS_M8, VFREDOSUM_VS }, // 1173
  { PseudoVFREDOSUM_VS_M8_MASK, VFREDOSUM_VS }, // 1174
  { PseudoVFREDOSUM_VS_MF2, VFREDOSUM_VS }, // 1175
  { PseudoVFREDOSUM_VS_MF2_MASK, VFREDOSUM_VS }, // 1176
  { PseudoVFREDOSUM_VS_MF4, VFREDOSUM_VS }, // 1177
  { PseudoVFREDOSUM_VS_MF4_MASK, VFREDOSUM_VS }, // 1178
  { PseudoVFREDUSUM_VS_M1, VFREDUSUM_VS }, // 1179
  { PseudoVFREDUSUM_VS_M1_MASK, VFREDUSUM_VS }, // 1180
  { PseudoVFREDUSUM_VS_M2, VFREDUSUM_VS }, // 1181
  { PseudoVFREDUSUM_VS_M2_MASK, VFREDUSUM_VS }, // 1182
  { PseudoVFREDUSUM_VS_M4, VFREDUSUM_VS }, // 1183
  { PseudoVFREDUSUM_VS_M4_MASK, VFREDUSUM_VS }, // 1184
  { PseudoVFREDUSUM_VS_M8, VFREDUSUM_VS }, // 1185
  { PseudoVFREDUSUM_VS_M8_MASK, VFREDUSUM_VS }, // 1186
  { PseudoVFREDUSUM_VS_MF2, VFREDUSUM_VS }, // 1187
  { PseudoVFREDUSUM_VS_MF2_MASK, VFREDUSUM_VS }, // 1188
  { PseudoVFREDUSUM_VS_MF4, VFREDUSUM_VS }, // 1189
  { PseudoVFREDUSUM_VS_MF4_MASK, VFREDUSUM_VS }, // 1190
  { PseudoVFRSQRT7_V_M1, VFRSQRT7_V }, // 1191
  { PseudoVFRSQRT7_V_M1_MASK, VFRSQRT7_V }, // 1192
  { PseudoVFRSQRT7_V_M2, VFRSQRT7_V }, // 1193
  { PseudoVFRSQRT7_V_M2_MASK, VFRSQRT7_V }, // 1194
  { PseudoVFRSQRT7_V_M4, VFRSQRT7_V }, // 1195
  { PseudoVFRSQRT7_V_M4_MASK, VFRSQRT7_V }, // 1196
  { PseudoVFRSQRT7_V_M8, VFRSQRT7_V }, // 1197
  { PseudoVFRSQRT7_V_M8_MASK, VFRSQRT7_V }, // 1198
  { PseudoVFRSQRT7_V_MF2, VFRSQRT7_V }, // 1199
  { PseudoVFRSQRT7_V_MF2_MASK, VFRSQRT7_V }, // 1200
  { PseudoVFRSQRT7_V_MF4, VFRSQRT7_V }, // 1201
  { PseudoVFRSQRT7_V_MF4_MASK, VFRSQRT7_V }, // 1202
  { PseudoVFRSUB_VF16_M1, VFRSUB_VF }, // 1203
  { PseudoVFRSUB_VF16_M1_MASK, VFRSUB_VF }, // 1204
  { PseudoVFRSUB_VF16_M2, VFRSUB_VF }, // 1205
  { PseudoVFRSUB_VF16_M2_MASK, VFRSUB_VF }, // 1206
  { PseudoVFRSUB_VF16_M4, VFRSUB_VF }, // 1207
  { PseudoVFRSUB_VF16_M4_MASK, VFRSUB_VF }, // 1208
  { PseudoVFRSUB_VF16_M8, VFRSUB_VF }, // 1209
  { PseudoVFRSUB_VF16_M8_MASK, VFRSUB_VF }, // 1210
  { PseudoVFRSUB_VF16_MF2, VFRSUB_VF }, // 1211
  { PseudoVFRSUB_VF16_MF2_MASK, VFRSUB_VF }, // 1212
  { PseudoVFRSUB_VF16_MF4, VFRSUB_VF }, // 1213
  { PseudoVFRSUB_VF16_MF4_MASK, VFRSUB_VF }, // 1214
  { PseudoVFRSUB_VF32_M1, VFRSUB_VF }, // 1215
  { PseudoVFRSUB_VF32_M1_MASK, VFRSUB_VF }, // 1216
  { PseudoVFRSUB_VF32_M2, VFRSUB_VF }, // 1217
  { PseudoVFRSUB_VF32_M2_MASK, VFRSUB_VF }, // 1218
  { PseudoVFRSUB_VF32_M4, VFRSUB_VF }, // 1219
  { PseudoVFRSUB_VF32_M4_MASK, VFRSUB_VF }, // 1220
  { PseudoVFRSUB_VF32_M8, VFRSUB_VF }, // 1221
  { PseudoVFRSUB_VF32_M8_MASK, VFRSUB_VF }, // 1222
  { PseudoVFRSUB_VF32_MF2, VFRSUB_VF }, // 1223
  { PseudoVFRSUB_VF32_MF2_MASK, VFRSUB_VF }, // 1224
  { PseudoVFRSUB_VF64_M1, VFRSUB_VF }, // 1225
  { PseudoVFRSUB_VF64_M1_MASK, VFRSUB_VF }, // 1226
  { PseudoVFRSUB_VF64_M2, VFRSUB_VF }, // 1227
  { PseudoVFRSUB_VF64_M2_MASK, VFRSUB_VF }, // 1228
  { PseudoVFRSUB_VF64_M4, VFRSUB_VF }, // 1229
  { PseudoVFRSUB_VF64_M4_MASK, VFRSUB_VF }, // 1230
  { PseudoVFRSUB_VF64_M8, VFRSUB_VF }, // 1231
  { PseudoVFRSUB_VF64_M8_MASK, VFRSUB_VF }, // 1232
  { PseudoVFSGNJN_VF16_M1, VFSGNJN_VF }, // 1233
  { PseudoVFSGNJN_VF16_M1_MASK, VFSGNJN_VF }, // 1234
  { PseudoVFSGNJN_VF16_M2, VFSGNJN_VF }, // 1235
  { PseudoVFSGNJN_VF16_M2_MASK, VFSGNJN_VF }, // 1236
  { PseudoVFSGNJN_VF16_M4, VFSGNJN_VF }, // 1237
  { PseudoVFSGNJN_VF16_M4_MASK, VFSGNJN_VF }, // 1238
  { PseudoVFSGNJN_VF16_M8, VFSGNJN_VF }, // 1239
  { PseudoVFSGNJN_VF16_M8_MASK, VFSGNJN_VF }, // 1240
  { PseudoVFSGNJN_VF16_MF2, VFSGNJN_VF }, // 1241
  { PseudoVFSGNJN_VF16_MF2_MASK, VFSGNJN_VF }, // 1242
  { PseudoVFSGNJN_VF16_MF4, VFSGNJN_VF }, // 1243
  { PseudoVFSGNJN_VF16_MF4_MASK, VFSGNJN_VF }, // 1244
  { PseudoVFSGNJN_VF32_M1, VFSGNJN_VF }, // 1245
  { PseudoVFSGNJN_VF32_M1_MASK, VFSGNJN_VF }, // 1246
  { PseudoVFSGNJN_VF32_M2, VFSGNJN_VF }, // 1247
  { PseudoVFSGNJN_VF32_M2_MASK, VFSGNJN_VF }, // 1248
  { PseudoVFSGNJN_VF32_M4, VFSGNJN_VF }, // 1249
  { PseudoVFSGNJN_VF32_M4_MASK, VFSGNJN_VF }, // 1250
  { PseudoVFSGNJN_VF32_M8, VFSGNJN_VF }, // 1251
  { PseudoVFSGNJN_VF32_M8_MASK, VFSGNJN_VF }, // 1252
  { PseudoVFSGNJN_VF32_MF2, VFSGNJN_VF }, // 1253
  { PseudoVFSGNJN_VF32_MF2_MASK, VFSGNJN_VF }, // 1254
  { PseudoVFSGNJN_VF64_M1, VFSGNJN_VF }, // 1255
  { PseudoVFSGNJN_VF64_M1_MASK, VFSGNJN_VF }, // 1256
  { PseudoVFSGNJN_VF64_M2, VFSGNJN_VF }, // 1257
  { PseudoVFSGNJN_VF64_M2_MASK, VFSGNJN_VF }, // 1258
  { PseudoVFSGNJN_VF64_M4, VFSGNJN_VF }, // 1259
  { PseudoVFSGNJN_VF64_M4_MASK, VFSGNJN_VF }, // 1260
  { PseudoVFSGNJN_VF64_M8, VFSGNJN_VF }, // 1261
  { PseudoVFSGNJN_VF64_M8_MASK, VFSGNJN_VF }, // 1262
  { PseudoVFSGNJN_VV_M1, VFSGNJN_VV }, // 1263
  { PseudoVFSGNJN_VV_M1_MASK, VFSGNJN_VV }, // 1264
  { PseudoVFSGNJN_VV_M2, VFSGNJN_VV }, // 1265
  { PseudoVFSGNJN_VV_M2_MASK, VFSGNJN_VV }, // 1266
  { PseudoVFSGNJN_VV_M4, VFSGNJN_VV }, // 1267
  { PseudoVFSGNJN_VV_M4_MASK, VFSGNJN_VV }, // 1268
  { PseudoVFSGNJN_VV_M8, VFSGNJN_VV }, // 1269
  { PseudoVFSGNJN_VV_M8_MASK, VFSGNJN_VV }, // 1270
  { PseudoVFSGNJN_VV_MF2, VFSGNJN_VV }, // 1271
  { PseudoVFSGNJN_VV_MF2_MASK, VFSGNJN_VV }, // 1272
  { PseudoVFSGNJN_VV_MF4, VFSGNJN_VV }, // 1273
  { PseudoVFSGNJN_VV_MF4_MASK, VFSGNJN_VV }, // 1274
  { PseudoVFSGNJX_VF16_M1, VFSGNJX_VF }, // 1275
  { PseudoVFSGNJX_VF16_M1_MASK, VFSGNJX_VF }, // 1276
  { PseudoVFSGNJX_VF16_M2, VFSGNJX_VF }, // 1277
  { PseudoVFSGNJX_VF16_M2_MASK, VFSGNJX_VF }, // 1278
  { PseudoVFSGNJX_VF16_M4, VFSGNJX_VF }, // 1279
  { PseudoVFSGNJX_VF16_M4_MASK, VFSGNJX_VF }, // 1280
  { PseudoVFSGNJX_VF16_M8, VFSGNJX_VF }, // 1281
  { PseudoVFSGNJX_VF16_M8_MASK, VFSGNJX_VF }, // 1282
  { PseudoVFSGNJX_VF16_MF2, VFSGNJX_VF }, // 1283
  { PseudoVFSGNJX_VF16_MF2_MASK, VFSGNJX_VF }, // 1284
  { PseudoVFSGNJX_VF16_MF4, VFSGNJX_VF }, // 1285
  { PseudoVFSGNJX_VF16_MF4_MASK, VFSGNJX_VF }, // 1286
  { PseudoVFSGNJX_VF32_M1, VFSGNJX_VF }, // 1287
  { PseudoVFSGNJX_VF32_M1_MASK, VFSGNJX_VF }, // 1288
  { PseudoVFSGNJX_VF32_M2, VFSGNJX_VF }, // 1289
  { PseudoVFSGNJX_VF32_M2_MASK, VFSGNJX_VF }, // 1290
  { PseudoVFSGNJX_VF32_M4, VFSGNJX_VF }, // 1291
  { PseudoVFSGNJX_VF32_M4_MASK, VFSGNJX_VF }, // 1292
  { PseudoVFSGNJX_VF32_M8, VFSGNJX_VF }, // 1293
  { PseudoVFSGNJX_VF32_M8_MASK, VFSGNJX_VF }, // 1294
  { PseudoVFSGNJX_VF32_MF2, VFSGNJX_VF }, // 1295
  { PseudoVFSGNJX_VF32_MF2_MASK, VFSGNJX_VF }, // 1296
  { PseudoVFSGNJX_VF64_M1, VFSGNJX_VF }, // 1297
  { PseudoVFSGNJX_VF64_M1_MASK, VFSGNJX_VF }, // 1298
  { PseudoVFSGNJX_VF64_M2, VFSGNJX_VF }, // 1299
  { PseudoVFSGNJX_VF64_M2_MASK, VFSGNJX_VF }, // 1300
  { PseudoVFSGNJX_VF64_M4, VFSGNJX_VF }, // 1301
  { PseudoVFSGNJX_VF64_M4_MASK, VFSGNJX_VF }, // 1302
  { PseudoVFSGNJX_VF64_M8, VFSGNJX_VF }, // 1303
  { PseudoVFSGNJX_VF64_M8_MASK, VFSGNJX_VF }, // 1304
  { PseudoVFSGNJX_VV_M1, VFSGNJX_VV }, // 1305
  { PseudoVFSGNJX_VV_M1_MASK, VFSGNJX_VV }, // 1306
  { PseudoVFSGNJX_VV_M2, VFSGNJX_VV }, // 1307
  { PseudoVFSGNJX_VV_M2_MASK, VFSGNJX_VV }, // 1308
  { PseudoVFSGNJX_VV_M4, VFSGNJX_VV }, // 1309
  { PseudoVFSGNJX_VV_M4_MASK, VFSGNJX_VV }, // 1310
  { PseudoVFSGNJX_VV_M8, VFSGNJX_VV }, // 1311
  { PseudoVFSGNJX_VV_M8_MASK, VFSGNJX_VV }, // 1312
  { PseudoVFSGNJX_VV_MF2, VFSGNJX_VV }, // 1313
  { PseudoVFSGNJX_VV_MF2_MASK, VFSGNJX_VV }, // 1314
  { PseudoVFSGNJX_VV_MF4, VFSGNJX_VV }, // 1315
  { PseudoVFSGNJX_VV_MF4_MASK, VFSGNJX_VV }, // 1316
  { PseudoVFSGNJ_VF16_M1, VFSGNJ_VF }, // 1317
  { PseudoVFSGNJ_VF16_M1_MASK, VFSGNJ_VF }, // 1318
  { PseudoVFSGNJ_VF16_M2, VFSGNJ_VF }, // 1319
  { PseudoVFSGNJ_VF16_M2_MASK, VFSGNJ_VF }, // 1320
  { PseudoVFSGNJ_VF16_M4, VFSGNJ_VF }, // 1321
  { PseudoVFSGNJ_VF16_M4_MASK, VFSGNJ_VF }, // 1322
  { PseudoVFSGNJ_VF16_M8, VFSGNJ_VF }, // 1323
  { PseudoVFSGNJ_VF16_M8_MASK, VFSGNJ_VF }, // 1324
  { PseudoVFSGNJ_VF16_MF2, VFSGNJ_VF }, // 1325
  { PseudoVFSGNJ_VF16_MF2_MASK, VFSGNJ_VF }, // 1326
  { PseudoVFSGNJ_VF16_MF4, VFSGNJ_VF }, // 1327
  { PseudoVFSGNJ_VF16_MF4_MASK, VFSGNJ_VF }, // 1328
  { PseudoVFSGNJ_VF32_M1, VFSGNJ_VF }, // 1329
  { PseudoVFSGNJ_VF32_M1_MASK, VFSGNJ_VF }, // 1330
  { PseudoVFSGNJ_VF32_M2, VFSGNJ_VF }, // 1331
  { PseudoVFSGNJ_VF32_M2_MASK, VFSGNJ_VF }, // 1332
  { PseudoVFSGNJ_VF32_M4, VFSGNJ_VF }, // 1333
  { PseudoVFSGNJ_VF32_M4_MASK, VFSGNJ_VF }, // 1334
  { PseudoVFSGNJ_VF32_M8, VFSGNJ_VF }, // 1335
  { PseudoVFSGNJ_VF32_M8_MASK, VFSGNJ_VF }, // 1336
  { PseudoVFSGNJ_VF32_MF2, VFSGNJ_VF }, // 1337
  { PseudoVFSGNJ_VF32_MF2_MASK, VFSGNJ_VF }, // 1338
  { PseudoVFSGNJ_VF64_M1, VFSGNJ_VF }, // 1339
  { PseudoVFSGNJ_VF64_M1_MASK, VFSGNJ_VF }, // 1340
  { PseudoVFSGNJ_VF64_M2, VFSGNJ_VF }, // 1341
  { PseudoVFSGNJ_VF64_M2_MASK, VFSGNJ_VF }, // 1342
  { PseudoVFSGNJ_VF64_M4, VFSGNJ_VF }, // 1343
  { PseudoVFSGNJ_VF64_M4_MASK, VFSGNJ_VF }, // 1344
  { PseudoVFSGNJ_VF64_M8, VFSGNJ_VF }, // 1345
  { PseudoVFSGNJ_VF64_M8_MASK, VFSGNJ_VF }, // 1346
  { PseudoVFSGNJ_VV_M1, VFSGNJ_VV }, // 1347
  { PseudoVFSGNJ_VV_M1_MASK, VFSGNJ_VV }, // 1348
  { PseudoVFSGNJ_VV_M2, VFSGNJ_VV }, // 1349
  { PseudoVFSGNJ_VV_M2_MASK, VFSGNJ_VV }, // 1350
  { PseudoVFSGNJ_VV_M4, VFSGNJ_VV }, // 1351
  { PseudoVFSGNJ_VV_M4_MASK, VFSGNJ_VV }, // 1352
  { PseudoVFSGNJ_VV_M8, VFSGNJ_VV }, // 1353
  { PseudoVFSGNJ_VV_M8_MASK, VFSGNJ_VV }, // 1354
  { PseudoVFSGNJ_VV_MF2, VFSGNJ_VV }, // 1355
  { PseudoVFSGNJ_VV_MF2_MASK, VFSGNJ_VV }, // 1356
  { PseudoVFSGNJ_VV_MF4, VFSGNJ_VV }, // 1357
  { PseudoVFSGNJ_VV_MF4_MASK, VFSGNJ_VV }, // 1358
  { PseudoVFSLIDE1DOWN_VF16_M1, VFSLIDE1DOWN_VF }, // 1359
  { PseudoVFSLIDE1DOWN_VF16_M1_MASK, VFSLIDE1DOWN_VF }, // 1360
  { PseudoVFSLIDE1DOWN_VF16_M2, VFSLIDE1DOWN_VF }, // 1361
  { PseudoVFSLIDE1DOWN_VF16_M2_MASK, VFSLIDE1DOWN_VF }, // 1362
  { PseudoVFSLIDE1DOWN_VF16_M4, VFSLIDE1DOWN_VF }, // 1363
  { PseudoVFSLIDE1DOWN_VF16_M4_MASK, VFSLIDE1DOWN_VF }, // 1364
  { PseudoVFSLIDE1DOWN_VF16_M8, VFSLIDE1DOWN_VF }, // 1365
  { PseudoVFSLIDE1DOWN_VF16_M8_MASK, VFSLIDE1DOWN_VF }, // 1366
  { PseudoVFSLIDE1DOWN_VF16_MF2, VFSLIDE1DOWN_VF }, // 1367
  { PseudoVFSLIDE1DOWN_VF16_MF2_MASK, VFSLIDE1DOWN_VF }, // 1368
  { PseudoVFSLIDE1DOWN_VF16_MF4, VFSLIDE1DOWN_VF }, // 1369
  { PseudoVFSLIDE1DOWN_VF16_MF4_MASK, VFSLIDE1DOWN_VF }, // 1370
  { PseudoVFSLIDE1DOWN_VF32_M1, VFSLIDE1DOWN_VF }, // 1371
  { PseudoVFSLIDE1DOWN_VF32_M1_MASK, VFSLIDE1DOWN_VF }, // 1372
  { PseudoVFSLIDE1DOWN_VF32_M2, VFSLIDE1DOWN_VF }, // 1373
  { PseudoVFSLIDE1DOWN_VF32_M2_MASK, VFSLIDE1DOWN_VF }, // 1374
  { PseudoVFSLIDE1DOWN_VF32_M4, VFSLIDE1DOWN_VF }, // 1375
  { PseudoVFSLIDE1DOWN_VF32_M4_MASK, VFSLIDE1DOWN_VF }, // 1376
  { PseudoVFSLIDE1DOWN_VF32_M8, VFSLIDE1DOWN_VF }, // 1377
  { PseudoVFSLIDE1DOWN_VF32_M8_MASK, VFSLIDE1DOWN_VF }, // 1378
  { PseudoVFSLIDE1DOWN_VF32_MF2, VFSLIDE1DOWN_VF }, // 1379
  { PseudoVFSLIDE1DOWN_VF32_MF2_MASK, VFSLIDE1DOWN_VF }, // 1380
  { PseudoVFSLIDE1DOWN_VF64_M1, VFSLIDE1DOWN_VF }, // 1381
  { PseudoVFSLIDE1DOWN_VF64_M1_MASK, VFSLIDE1DOWN_VF }, // 1382
  { PseudoVFSLIDE1DOWN_VF64_M2, VFSLIDE1DOWN_VF }, // 1383
  { PseudoVFSLIDE1DOWN_VF64_M2_MASK, VFSLIDE1DOWN_VF }, // 1384
  { PseudoVFSLIDE1DOWN_VF64_M4, VFSLIDE1DOWN_VF }, // 1385
  { PseudoVFSLIDE1DOWN_VF64_M4_MASK, VFSLIDE1DOWN_VF }, // 1386
  { PseudoVFSLIDE1DOWN_VF64_M8, VFSLIDE1DOWN_VF }, // 1387
  { PseudoVFSLIDE1DOWN_VF64_M8_MASK, VFSLIDE1DOWN_VF }, // 1388
  { PseudoVFSLIDE1UP_VF16_M1, VFSLIDE1UP_VF }, // 1389
  { PseudoVFSLIDE1UP_VF16_M1_MASK, VFSLIDE1UP_VF }, // 1390
  { PseudoVFSLIDE1UP_VF16_M2, VFSLIDE1UP_VF }, // 1391
  { PseudoVFSLIDE1UP_VF16_M2_MASK, VFSLIDE1UP_VF }, // 1392
  { PseudoVFSLIDE1UP_VF16_M4, VFSLIDE1UP_VF }, // 1393
  { PseudoVFSLIDE1UP_VF16_M4_MASK, VFSLIDE1UP_VF }, // 1394
  { PseudoVFSLIDE1UP_VF16_M8, VFSLIDE1UP_VF }, // 1395
  { PseudoVFSLIDE1UP_VF16_M8_MASK, VFSLIDE1UP_VF }, // 1396
  { PseudoVFSLIDE1UP_VF16_MF2, VFSLIDE1UP_VF }, // 1397
  { PseudoVFSLIDE1UP_VF16_MF2_MASK, VFSLIDE1UP_VF }, // 1398
  { PseudoVFSLIDE1UP_VF16_MF4, VFSLIDE1UP_VF }, // 1399
  { PseudoVFSLIDE1UP_VF16_MF4_MASK, VFSLIDE1UP_VF }, // 1400
  { PseudoVFSLIDE1UP_VF32_M1, VFSLIDE1UP_VF }, // 1401
  { PseudoVFSLIDE1UP_VF32_M1_MASK, VFSLIDE1UP_VF }, // 1402
  { PseudoVFSLIDE1UP_VF32_M2, VFSLIDE1UP_VF }, // 1403
  { PseudoVFSLIDE1UP_VF32_M2_MASK, VFSLIDE1UP_VF }, // 1404
  { PseudoVFSLIDE1UP_VF32_M4, VFSLIDE1UP_VF }, // 1405
  { PseudoVFSLIDE1UP_VF32_M4_MASK, VFSLIDE1UP_VF }, // 1406
  { PseudoVFSLIDE1UP_VF32_M8, VFSLIDE1UP_VF }, // 1407
  { PseudoVFSLIDE1UP_VF32_M8_MASK, VFSLIDE1UP_VF }, // 1408
  { PseudoVFSLIDE1UP_VF32_MF2, VFSLIDE1UP_VF }, // 1409
  { PseudoVFSLIDE1UP_VF32_MF2_MASK, VFSLIDE1UP_VF }, // 1410
  { PseudoVFSLIDE1UP_VF64_M1, VFSLIDE1UP_VF }, // 1411
  { PseudoVFSLIDE1UP_VF64_M1_MASK, VFSLIDE1UP_VF }, // 1412
  { PseudoVFSLIDE1UP_VF64_M2, VFSLIDE1UP_VF }, // 1413
  { PseudoVFSLIDE1UP_VF64_M2_MASK, VFSLIDE1UP_VF }, // 1414
  { PseudoVFSLIDE1UP_VF64_M4, VFSLIDE1UP_VF }, // 1415
  { PseudoVFSLIDE1UP_VF64_M4_MASK, VFSLIDE1UP_VF }, // 1416
  { PseudoVFSLIDE1UP_VF64_M8, VFSLIDE1UP_VF }, // 1417
  { PseudoVFSLIDE1UP_VF64_M8_MASK, VFSLIDE1UP_VF }, // 1418
  { PseudoVFSQRT_V_M1, VFSQRT_V }, // 1419
  { PseudoVFSQRT_V_M1_MASK, VFSQRT_V }, // 1420
  { PseudoVFSQRT_V_M2, VFSQRT_V }, // 1421
  { PseudoVFSQRT_V_M2_MASK, VFSQRT_V }, // 1422
  { PseudoVFSQRT_V_M4, VFSQRT_V }, // 1423
  { PseudoVFSQRT_V_M4_MASK, VFSQRT_V }, // 1424
  { PseudoVFSQRT_V_M8, VFSQRT_V }, // 1425
  { PseudoVFSQRT_V_M8_MASK, VFSQRT_V }, // 1426
  { PseudoVFSQRT_V_MF2, VFSQRT_V }, // 1427
  { PseudoVFSQRT_V_MF2_MASK, VFSQRT_V }, // 1428
  { PseudoVFSQRT_V_MF4, VFSQRT_V }, // 1429
  { PseudoVFSQRT_V_MF4_MASK, VFSQRT_V }, // 1430
  { PseudoVFSUB_VF16_M1, VFSUB_VF }, // 1431
  { PseudoVFSUB_VF16_M1_MASK, VFSUB_VF }, // 1432
  { PseudoVFSUB_VF16_M2, VFSUB_VF }, // 1433
  { PseudoVFSUB_VF16_M2_MASK, VFSUB_VF }, // 1434
  { PseudoVFSUB_VF16_M4, VFSUB_VF }, // 1435
  { PseudoVFSUB_VF16_M4_MASK, VFSUB_VF }, // 1436
  { PseudoVFSUB_VF16_M8, VFSUB_VF }, // 1437
  { PseudoVFSUB_VF16_M8_MASK, VFSUB_VF }, // 1438
  { PseudoVFSUB_VF16_MF2, VFSUB_VF }, // 1439
  { PseudoVFSUB_VF16_MF2_MASK, VFSUB_VF }, // 1440
  { PseudoVFSUB_VF16_MF4, VFSUB_VF }, // 1441
  { PseudoVFSUB_VF16_MF4_MASK, VFSUB_VF }, // 1442
  { PseudoVFSUB_VF32_M1, VFSUB_VF }, // 1443
  { PseudoVFSUB_VF32_M1_MASK, VFSUB_VF }, // 1444
  { PseudoVFSUB_VF32_M2, VFSUB_VF }, // 1445
  { PseudoVFSUB_VF32_M2_MASK, VFSUB_VF }, // 1446
  { PseudoVFSUB_VF32_M4, VFSUB_VF }, // 1447
  { PseudoVFSUB_VF32_M4_MASK, VFSUB_VF }, // 1448
  { PseudoVFSUB_VF32_M8, VFSUB_VF }, // 1449
  { PseudoVFSUB_VF32_M8_MASK, VFSUB_VF }, // 1450
  { PseudoVFSUB_VF32_MF2, VFSUB_VF }, // 1451
  { PseudoVFSUB_VF32_MF2_MASK, VFSUB_VF }, // 1452
  { PseudoVFSUB_VF64_M1, VFSUB_VF }, // 1453
  { PseudoVFSUB_VF64_M1_MASK, VFSUB_VF }, // 1454
  { PseudoVFSUB_VF64_M2, VFSUB_VF }, // 1455
  { PseudoVFSUB_VF64_M2_MASK, VFSUB_VF }, // 1456
  { PseudoVFSUB_VF64_M4, VFSUB_VF }, // 1457
  { PseudoVFSUB_VF64_M4_MASK, VFSUB_VF }, // 1458
  { PseudoVFSUB_VF64_M8, VFSUB_VF }, // 1459
  { PseudoVFSUB_VF64_M8_MASK, VFSUB_VF }, // 1460
  { PseudoVFSUB_VV_M1, VFSUB_VV }, // 1461
  { PseudoVFSUB_VV_M1_MASK, VFSUB_VV }, // 1462
  { PseudoVFSUB_VV_M2, VFSUB_VV }, // 1463
  { PseudoVFSUB_VV_M2_MASK, VFSUB_VV }, // 1464
  { PseudoVFSUB_VV_M4, VFSUB_VV }, // 1465
  { PseudoVFSUB_VV_M4_MASK, VFSUB_VV }, // 1466
  { PseudoVFSUB_VV_M8, VFSUB_VV }, // 1467
  { PseudoVFSUB_VV_M8_MASK, VFSUB_VV }, // 1468
  { PseudoVFSUB_VV_MF2, VFSUB_VV }, // 1469
  { PseudoVFSUB_VV_MF2_MASK, VFSUB_VV }, // 1470
  { PseudoVFSUB_VV_MF4, VFSUB_VV }, // 1471
  { PseudoVFSUB_VV_MF4_MASK, VFSUB_VV }, // 1472
  { PseudoVFWADD_VF16_M1, VFWADD_VF }, // 1473
  { PseudoVFWADD_VF16_M1_MASK, VFWADD_VF }, // 1474
  { PseudoVFWADD_VF16_M2, VFWADD_VF }, // 1475
  { PseudoVFWADD_VF16_M2_MASK, VFWADD_VF }, // 1476
  { PseudoVFWADD_VF16_M4, VFWADD_VF }, // 1477
  { PseudoVFWADD_VF16_M4_MASK, VFWADD_VF }, // 1478
  { PseudoVFWADD_VF16_M8, VFWADD_VF }, // 1479
  { PseudoVFWADD_VF16_M8_MASK, VFWADD_VF }, // 1480
  { PseudoVFWADD_VF16_MF2, VFWADD_VF }, // 1481
  { PseudoVFWADD_VF16_MF2_MASK, VFWADD_VF }, // 1482
  { PseudoVFWADD_VF16_MF4, VFWADD_VF }, // 1483
  { PseudoVFWADD_VF16_MF4_MASK, VFWADD_VF }, // 1484
  { PseudoVFWADD_VF32_M1, VFWADD_VF }, // 1485
  { PseudoVFWADD_VF32_M1_MASK, VFWADD_VF }, // 1486
  { PseudoVFWADD_VF32_M2, VFWADD_VF }, // 1487
  { PseudoVFWADD_VF32_M2_MASK, VFWADD_VF }, // 1488
  { PseudoVFWADD_VF32_M4, VFWADD_VF }, // 1489
  { PseudoVFWADD_VF32_M4_MASK, VFWADD_VF }, // 1490
  { PseudoVFWADD_VF32_M8, VFWADD_VF }, // 1491
  { PseudoVFWADD_VF32_M8_MASK, VFWADD_VF }, // 1492
  { PseudoVFWADD_VF32_MF2, VFWADD_VF }, // 1493
  { PseudoVFWADD_VF32_MF2_MASK, VFWADD_VF }, // 1494
  { PseudoVFWADD_VV_M1, VFWADD_VV }, // 1495
  { PseudoVFWADD_VV_M1_MASK, VFWADD_VV }, // 1496
  { PseudoVFWADD_VV_M2, VFWADD_VV }, // 1497
  { PseudoVFWADD_VV_M2_MASK, VFWADD_VV }, // 1498
  { PseudoVFWADD_VV_M4, VFWADD_VV }, // 1499
  { PseudoVFWADD_VV_M4_MASK, VFWADD_VV }, // 1500
  { PseudoVFWADD_VV_MF2, VFWADD_VV }, // 1501
  { PseudoVFWADD_VV_MF2_MASK, VFWADD_VV }, // 1502
  { PseudoVFWADD_VV_MF4, VFWADD_VV }, // 1503
  { PseudoVFWADD_VV_MF4_MASK, VFWADD_VV }, // 1504
  { PseudoVFWADD_WF16_M1, VFWADD_WF }, // 1505
  { PseudoVFWADD_WF16_M1_MASK, VFWADD_WF }, // 1506
  { PseudoVFWADD_WF16_M2, VFWADD_WF }, // 1507
  { PseudoVFWADD_WF16_M2_MASK, VFWADD_WF }, // 1508
  { PseudoVFWADD_WF16_M4, VFWADD_WF }, // 1509
  { PseudoVFWADD_WF16_M4_MASK, VFWADD_WF }, // 1510
  { PseudoVFWADD_WF16_M8, VFWADD_WF }, // 1511
  { PseudoVFWADD_WF16_M8_MASK, VFWADD_WF }, // 1512
  { PseudoVFWADD_WF16_MF2, VFWADD_WF }, // 1513
  { PseudoVFWADD_WF16_MF2_MASK, VFWADD_WF }, // 1514
  { PseudoVFWADD_WF16_MF4, VFWADD_WF }, // 1515
  { PseudoVFWADD_WF16_MF4_MASK, VFWADD_WF }, // 1516
  { PseudoVFWADD_WF32_M1, VFWADD_WF }, // 1517
  { PseudoVFWADD_WF32_M1_MASK, VFWADD_WF }, // 1518
  { PseudoVFWADD_WF32_M2, VFWADD_WF }, // 1519
  { PseudoVFWADD_WF32_M2_MASK, VFWADD_WF }, // 1520
  { PseudoVFWADD_WF32_M4, VFWADD_WF }, // 1521
  { PseudoVFWADD_WF32_M4_MASK, VFWADD_WF }, // 1522
  { PseudoVFWADD_WF32_M8, VFWADD_WF }, // 1523
  { PseudoVFWADD_WF32_M8_MASK, VFWADD_WF }, // 1524
  { PseudoVFWADD_WF32_MF2, VFWADD_WF }, // 1525
  { PseudoVFWADD_WF32_MF2_MASK, VFWADD_WF }, // 1526
  { PseudoVFWADD_WV_M1, VFWADD_WV }, // 1527
  { PseudoVFWADD_WV_M1_MASK, VFWADD_WV }, // 1528
  { PseudoVFWADD_WV_M1_MASK_TIED, VFWADD_WV }, // 1529
  { PseudoVFWADD_WV_M1_TIED, VFWADD_WV }, // 1530
  { PseudoVFWADD_WV_M2, VFWADD_WV }, // 1531
  { PseudoVFWADD_WV_M2_MASK, VFWADD_WV }, // 1532
  { PseudoVFWADD_WV_M2_MASK_TIED, VFWADD_WV }, // 1533
  { PseudoVFWADD_WV_M2_TIED, VFWADD_WV }, // 1534
  { PseudoVFWADD_WV_M4, VFWADD_WV }, // 1535
  { PseudoVFWADD_WV_M4_MASK, VFWADD_WV }, // 1536
  { PseudoVFWADD_WV_M4_MASK_TIED, VFWADD_WV }, // 1537
  { PseudoVFWADD_WV_M4_TIED, VFWADD_WV }, // 1538
  { PseudoVFWADD_WV_MF2, VFWADD_WV }, // 1539
  { PseudoVFWADD_WV_MF2_MASK, VFWADD_WV }, // 1540
  { PseudoVFWADD_WV_MF2_MASK_TIED, VFWADD_WV }, // 1541
  { PseudoVFWADD_WV_MF2_TIED, VFWADD_WV }, // 1542
  { PseudoVFWADD_WV_MF4, VFWADD_WV }, // 1543
  { PseudoVFWADD_WV_MF4_MASK, VFWADD_WV }, // 1544
  { PseudoVFWADD_WV_MF4_MASK_TIED, VFWADD_WV }, // 1545
  { PseudoVFWADD_WV_MF4_TIED, VFWADD_WV }, // 1546
  { PseudoVFWCVT_F_F_V_M1, VFWCVT_F_F_V }, // 1547
  { PseudoVFWCVT_F_F_V_M1_MASK, VFWCVT_F_F_V }, // 1548
  { PseudoVFWCVT_F_F_V_M2, VFWCVT_F_F_V }, // 1549
  { PseudoVFWCVT_F_F_V_M2_MASK, VFWCVT_F_F_V }, // 1550
  { PseudoVFWCVT_F_F_V_M4, VFWCVT_F_F_V }, // 1551
  { PseudoVFWCVT_F_F_V_M4_MASK, VFWCVT_F_F_V }, // 1552
  { PseudoVFWCVT_F_F_V_MF2, VFWCVT_F_F_V }, // 1553
  { PseudoVFWCVT_F_F_V_MF2_MASK, VFWCVT_F_F_V }, // 1554
  { PseudoVFWCVT_F_F_V_MF4, VFWCVT_F_F_V }, // 1555
  { PseudoVFWCVT_F_F_V_MF4_MASK, VFWCVT_F_F_V }, // 1556
  { PseudoVFWCVT_F_XU_V_M1, VFWCVT_F_XU_V }, // 1557
  { PseudoVFWCVT_F_XU_V_M1_MASK, VFWCVT_F_XU_V }, // 1558
  { PseudoVFWCVT_F_XU_V_M2, VFWCVT_F_XU_V }, // 1559
  { PseudoVFWCVT_F_XU_V_M2_MASK, VFWCVT_F_XU_V }, // 1560
  { PseudoVFWCVT_F_XU_V_M4, VFWCVT_F_XU_V }, // 1561
  { PseudoVFWCVT_F_XU_V_M4_MASK, VFWCVT_F_XU_V }, // 1562
  { PseudoVFWCVT_F_XU_V_MF2, VFWCVT_F_XU_V }, // 1563
  { PseudoVFWCVT_F_XU_V_MF2_MASK, VFWCVT_F_XU_V }, // 1564
  { PseudoVFWCVT_F_XU_V_MF4, VFWCVT_F_XU_V }, // 1565
  { PseudoVFWCVT_F_XU_V_MF4_MASK, VFWCVT_F_XU_V }, // 1566
  { PseudoVFWCVT_F_XU_V_MF8, VFWCVT_F_XU_V }, // 1567
  { PseudoVFWCVT_F_XU_V_MF8_MASK, VFWCVT_F_XU_V }, // 1568
  { PseudoVFWCVT_F_X_V_M1, VFWCVT_F_X_V }, // 1569
  { PseudoVFWCVT_F_X_V_M1_MASK, VFWCVT_F_X_V }, // 1570
  { PseudoVFWCVT_F_X_V_M2, VFWCVT_F_X_V }, // 1571
  { PseudoVFWCVT_F_X_V_M2_MASK, VFWCVT_F_X_V }, // 1572
  { PseudoVFWCVT_F_X_V_M4, VFWCVT_F_X_V }, // 1573
  { PseudoVFWCVT_F_X_V_M4_MASK, VFWCVT_F_X_V }, // 1574
  { PseudoVFWCVT_F_X_V_MF2, VFWCVT_F_X_V }, // 1575
  { PseudoVFWCVT_F_X_V_MF2_MASK, VFWCVT_F_X_V }, // 1576
  { PseudoVFWCVT_F_X_V_MF4, VFWCVT_F_X_V }, // 1577
  { PseudoVFWCVT_F_X_V_MF4_MASK, VFWCVT_F_X_V }, // 1578
  { PseudoVFWCVT_F_X_V_MF8, VFWCVT_F_X_V }, // 1579
  { PseudoVFWCVT_F_X_V_MF8_MASK, VFWCVT_F_X_V }, // 1580
  { PseudoVFWCVT_RTZ_XU_F_V_M1, VFWCVT_RTZ_XU_F_V }, // 1581
  { PseudoVFWCVT_RTZ_XU_F_V_M1_MASK, VFWCVT_RTZ_XU_F_V }, // 1582
  { PseudoVFWCVT_RTZ_XU_F_V_M2, VFWCVT_RTZ_XU_F_V }, // 1583
  { PseudoVFWCVT_RTZ_XU_F_V_M2_MASK, VFWCVT_RTZ_XU_F_V }, // 1584
  { PseudoVFWCVT_RTZ_XU_F_V_M4, VFWCVT_RTZ_XU_F_V }, // 1585
  { PseudoVFWCVT_RTZ_XU_F_V_M4_MASK, VFWCVT_RTZ_XU_F_V }, // 1586
  { PseudoVFWCVT_RTZ_XU_F_V_MF2, VFWCVT_RTZ_XU_F_V }, // 1587
  { PseudoVFWCVT_RTZ_XU_F_V_MF2_MASK, VFWCVT_RTZ_XU_F_V }, // 1588
  { PseudoVFWCVT_RTZ_XU_F_V_MF4, VFWCVT_RTZ_XU_F_V }, // 1589
  { PseudoVFWCVT_RTZ_XU_F_V_MF4_MASK, VFWCVT_RTZ_XU_F_V }, // 1590
  { PseudoVFWCVT_RTZ_X_F_V_M1, VFWCVT_RTZ_X_F_V }, // 1591
  { PseudoVFWCVT_RTZ_X_F_V_M1_MASK, VFWCVT_RTZ_X_F_V }, // 1592
  { PseudoVFWCVT_RTZ_X_F_V_M2, VFWCVT_RTZ_X_F_V }, // 1593
  { PseudoVFWCVT_RTZ_X_F_V_M2_MASK, VFWCVT_RTZ_X_F_V }, // 1594
  { PseudoVFWCVT_RTZ_X_F_V_M4, VFWCVT_RTZ_X_F_V }, // 1595
  { PseudoVFWCVT_RTZ_X_F_V_M4_MASK, VFWCVT_RTZ_X_F_V }, // 1596
  { PseudoVFWCVT_RTZ_X_F_V_MF2, VFWCVT_RTZ_X_F_V }, // 1597
  { PseudoVFWCVT_RTZ_X_F_V_MF2_MASK, VFWCVT_RTZ_X_F_V }, // 1598
  { PseudoVFWCVT_RTZ_X_F_V_MF4, VFWCVT_RTZ_X_F_V }, // 1599
  { PseudoVFWCVT_RTZ_X_F_V_MF4_MASK, VFWCVT_RTZ_X_F_V }, // 1600
  { PseudoVFWCVT_XU_F_V_M1, VFWCVT_XU_F_V }, // 1601
  { PseudoVFWCVT_XU_F_V_M1_MASK, VFWCVT_XU_F_V }, // 1602
  { PseudoVFWCVT_XU_F_V_M2, VFWCVT_XU_F_V }, // 1603
  { PseudoVFWCVT_XU_F_V_M2_MASK, VFWCVT_XU_F_V }, // 1604
  { PseudoVFWCVT_XU_F_V_M4, VFWCVT_XU_F_V }, // 1605
  { PseudoVFWCVT_XU_F_V_M4_MASK, VFWCVT_XU_F_V }, // 1606
  { PseudoVFWCVT_XU_F_V_MF2, VFWCVT_XU_F_V }, // 1607
  { PseudoVFWCVT_XU_F_V_MF2_MASK, VFWCVT_XU_F_V }, // 1608
  { PseudoVFWCVT_XU_F_V_MF4, VFWCVT_XU_F_V }, // 1609
  { PseudoVFWCVT_XU_F_V_MF4_MASK, VFWCVT_XU_F_V }, // 1610
  { PseudoVFWCVT_X_F_V_M1, VFWCVT_X_F_V }, // 1611
  { PseudoVFWCVT_X_F_V_M1_MASK, VFWCVT_X_F_V }, // 1612
  { PseudoVFWCVT_X_F_V_M2, VFWCVT_X_F_V }, // 1613
  { PseudoVFWCVT_X_F_V_M2_MASK, VFWCVT_X_F_V }, // 1614
  { PseudoVFWCVT_X_F_V_M4, VFWCVT_X_F_V }, // 1615
  { PseudoVFWCVT_X_F_V_M4_MASK, VFWCVT_X_F_V }, // 1616
  { PseudoVFWCVT_X_F_V_MF2, VFWCVT_X_F_V }, // 1617
  { PseudoVFWCVT_X_F_V_MF2_MASK, VFWCVT_X_F_V }, // 1618
  { PseudoVFWCVT_X_F_V_MF4, VFWCVT_X_F_V }, // 1619
  { PseudoVFWCVT_X_F_V_MF4_MASK, VFWCVT_X_F_V }, // 1620
  { PseudoVFWMACC_VF16_M1, VFWMACC_VF }, // 1621
  { PseudoVFWMACC_VF16_M1_MASK, VFWMACC_VF }, // 1622
  { PseudoVFWMACC_VF16_M2, VFWMACC_VF }, // 1623
  { PseudoVFWMACC_VF16_M2_MASK, VFWMACC_VF }, // 1624
  { PseudoVFWMACC_VF16_M4, VFWMACC_VF }, // 1625
  { PseudoVFWMACC_VF16_M4_MASK, VFWMACC_VF }, // 1626
  { PseudoVFWMACC_VF16_M8, VFWMACC_VF }, // 1627
  { PseudoVFWMACC_VF16_M8_MASK, VFWMACC_VF }, // 1628
  { PseudoVFWMACC_VF16_MF2, VFWMACC_VF }, // 1629
  { PseudoVFWMACC_VF16_MF2_MASK, VFWMACC_VF }, // 1630
  { PseudoVFWMACC_VF16_MF4, VFWMACC_VF }, // 1631
  { PseudoVFWMACC_VF16_MF4_MASK, VFWMACC_VF }, // 1632
  { PseudoVFWMACC_VF32_M1, VFWMACC_VF }, // 1633
  { PseudoVFWMACC_VF32_M1_MASK, VFWMACC_VF }, // 1634
  { PseudoVFWMACC_VF32_M2, VFWMACC_VF }, // 1635
  { PseudoVFWMACC_VF32_M2_MASK, VFWMACC_VF }, // 1636
  { PseudoVFWMACC_VF32_M4, VFWMACC_VF }, // 1637
  { PseudoVFWMACC_VF32_M4_MASK, VFWMACC_VF }, // 1638
  { PseudoVFWMACC_VF32_M8, VFWMACC_VF }, // 1639
  { PseudoVFWMACC_VF32_M8_MASK, VFWMACC_VF }, // 1640
  { PseudoVFWMACC_VF32_MF2, VFWMACC_VF }, // 1641
  { PseudoVFWMACC_VF32_MF2_MASK, VFWMACC_VF }, // 1642
  { PseudoVFWMACC_VV_M1, VFWMACC_VV }, // 1643
  { PseudoVFWMACC_VV_M1_MASK, VFWMACC_VV }, // 1644
  { PseudoVFWMACC_VV_M2, VFWMACC_VV }, // 1645
  { PseudoVFWMACC_VV_M2_MASK, VFWMACC_VV }, // 1646
  { PseudoVFWMACC_VV_M4, VFWMACC_VV }, // 1647
  { PseudoVFWMACC_VV_M4_MASK, VFWMACC_VV }, // 1648
  { PseudoVFWMACC_VV_MF2, VFWMACC_VV }, // 1649
  { PseudoVFWMACC_VV_MF2_MASK, VFWMACC_VV }, // 1650
  { PseudoVFWMACC_VV_MF4, VFWMACC_VV }, // 1651
  { PseudoVFWMACC_VV_MF4_MASK, VFWMACC_VV }, // 1652
  { PseudoVFWMSAC_VF16_M1, VFWMSAC_VF }, // 1653
  { PseudoVFWMSAC_VF16_M1_MASK, VFWMSAC_VF }, // 1654
  { PseudoVFWMSAC_VF16_M2, VFWMSAC_VF }, // 1655
  { PseudoVFWMSAC_VF16_M2_MASK, VFWMSAC_VF }, // 1656
  { PseudoVFWMSAC_VF16_M4, VFWMSAC_VF }, // 1657
  { PseudoVFWMSAC_VF16_M4_MASK, VFWMSAC_VF }, // 1658
  { PseudoVFWMSAC_VF16_M8, VFWMSAC_VF }, // 1659
  { PseudoVFWMSAC_VF16_M8_MASK, VFWMSAC_VF }, // 1660
  { PseudoVFWMSAC_VF16_MF2, VFWMSAC_VF }, // 1661
  { PseudoVFWMSAC_VF16_MF2_MASK, VFWMSAC_VF }, // 1662
  { PseudoVFWMSAC_VF16_MF4, VFWMSAC_VF }, // 1663
  { PseudoVFWMSAC_VF16_MF4_MASK, VFWMSAC_VF }, // 1664
  { PseudoVFWMSAC_VF32_M1, VFWMSAC_VF }, // 1665
  { PseudoVFWMSAC_VF32_M1_MASK, VFWMSAC_VF }, // 1666
  { PseudoVFWMSAC_VF32_M2, VFWMSAC_VF }, // 1667
  { PseudoVFWMSAC_VF32_M2_MASK, VFWMSAC_VF }, // 1668
  { PseudoVFWMSAC_VF32_M4, VFWMSAC_VF }, // 1669
  { PseudoVFWMSAC_VF32_M4_MASK, VFWMSAC_VF }, // 1670
  { PseudoVFWMSAC_VF32_M8, VFWMSAC_VF }, // 1671
  { PseudoVFWMSAC_VF32_M8_MASK, VFWMSAC_VF }, // 1672
  { PseudoVFWMSAC_VF32_MF2, VFWMSAC_VF }, // 1673
  { PseudoVFWMSAC_VF32_MF2_MASK, VFWMSAC_VF }, // 1674
  { PseudoVFWMSAC_VV_M1, VFWMSAC_VV }, // 1675
  { PseudoVFWMSAC_VV_M1_MASK, VFWMSAC_VV }, // 1676
  { PseudoVFWMSAC_VV_M2, VFWMSAC_VV }, // 1677
  { PseudoVFWMSAC_VV_M2_MASK, VFWMSAC_VV }, // 1678
  { PseudoVFWMSAC_VV_M4, VFWMSAC_VV }, // 1679
  { PseudoVFWMSAC_VV_M4_MASK, VFWMSAC_VV }, // 1680
  { PseudoVFWMSAC_VV_MF2, VFWMSAC_VV }, // 1681
  { PseudoVFWMSAC_VV_MF2_MASK, VFWMSAC_VV }, // 1682
  { PseudoVFWMSAC_VV_MF4, VFWMSAC_VV }, // 1683
  { PseudoVFWMSAC_VV_MF4_MASK, VFWMSAC_VV }, // 1684
  { PseudoVFWMUL_VF16_M1, VFWMUL_VF }, // 1685
  { PseudoVFWMUL_VF16_M1_MASK, VFWMUL_VF }, // 1686
  { PseudoVFWMUL_VF16_M2, VFWMUL_VF }, // 1687
  { PseudoVFWMUL_VF16_M2_MASK, VFWMUL_VF }, // 1688
  { PseudoVFWMUL_VF16_M4, VFWMUL_VF }, // 1689
  { PseudoVFWMUL_VF16_M4_MASK, VFWMUL_VF }, // 1690
  { PseudoVFWMUL_VF16_M8, VFWMUL_VF }, // 1691
  { PseudoVFWMUL_VF16_M8_MASK, VFWMUL_VF }, // 1692
  { PseudoVFWMUL_VF16_MF2, VFWMUL_VF }, // 1693
  { PseudoVFWMUL_VF16_MF2_MASK, VFWMUL_VF }, // 1694
  { PseudoVFWMUL_VF16_MF4, VFWMUL_VF }, // 1695
  { PseudoVFWMUL_VF16_MF4_MASK, VFWMUL_VF }, // 1696
  { PseudoVFWMUL_VF32_M1, VFWMUL_VF }, // 1697
  { PseudoVFWMUL_VF32_M1_MASK, VFWMUL_VF }, // 1698
  { PseudoVFWMUL_VF32_M2, VFWMUL_VF }, // 1699
  { PseudoVFWMUL_VF32_M2_MASK, VFWMUL_VF }, // 1700
  { PseudoVFWMUL_VF32_M4, VFWMUL_VF }, // 1701
  { PseudoVFWMUL_VF32_M4_MASK, VFWMUL_VF }, // 1702
  { PseudoVFWMUL_VF32_M8, VFWMUL_VF }, // 1703
  { PseudoVFWMUL_VF32_M8_MASK, VFWMUL_VF }, // 1704
  { PseudoVFWMUL_VF32_MF2, VFWMUL_VF }, // 1705
  { PseudoVFWMUL_VF32_MF2_MASK, VFWMUL_VF }, // 1706
  { PseudoVFWMUL_VV_M1, VFWMUL_VV }, // 1707
  { PseudoVFWMUL_VV_M1_MASK, VFWMUL_VV }, // 1708
  { PseudoVFWMUL_VV_M2, VFWMUL_VV }, // 1709
  { PseudoVFWMUL_VV_M2_MASK, VFWMUL_VV }, // 1710
  { PseudoVFWMUL_VV_M4, VFWMUL_VV }, // 1711
  { PseudoVFWMUL_VV_M4_MASK, VFWMUL_VV }, // 1712
  { PseudoVFWMUL_VV_MF2, VFWMUL_VV }, // 1713
  { PseudoVFWMUL_VV_MF2_MASK, VFWMUL_VV }, // 1714
  { PseudoVFWMUL_VV_MF4, VFWMUL_VV }, // 1715
  { PseudoVFWMUL_VV_MF4_MASK, VFWMUL_VV }, // 1716
  { PseudoVFWNMACC_VF16_M1, VFWNMACC_VF }, // 1717
  { PseudoVFWNMACC_VF16_M1_MASK, VFWNMACC_VF }, // 1718
  { PseudoVFWNMACC_VF16_M2, VFWNMACC_VF }, // 1719
  { PseudoVFWNMACC_VF16_M2_MASK, VFWNMACC_VF }, // 1720
  { PseudoVFWNMACC_VF16_M4, VFWNMACC_VF }, // 1721
  { PseudoVFWNMACC_VF16_M4_MASK, VFWNMACC_VF }, // 1722
  { PseudoVFWNMACC_VF16_M8, VFWNMACC_VF }, // 1723
  { PseudoVFWNMACC_VF16_M8_MASK, VFWNMACC_VF }, // 1724
  { PseudoVFWNMACC_VF16_MF2, VFWNMACC_VF }, // 1725
  { PseudoVFWNMACC_VF16_MF2_MASK, VFWNMACC_VF }, // 1726
  { PseudoVFWNMACC_VF16_MF4, VFWNMACC_VF }, // 1727
  { PseudoVFWNMACC_VF16_MF4_MASK, VFWNMACC_VF }, // 1728
  { PseudoVFWNMACC_VF32_M1, VFWNMACC_VF }, // 1729
  { PseudoVFWNMACC_VF32_M1_MASK, VFWNMACC_VF }, // 1730
  { PseudoVFWNMACC_VF32_M2, VFWNMACC_VF }, // 1731
  { PseudoVFWNMACC_VF32_M2_MASK, VFWNMACC_VF }, // 1732
  { PseudoVFWNMACC_VF32_M4, VFWNMACC_VF }, // 1733
  { PseudoVFWNMACC_VF32_M4_MASK, VFWNMACC_VF }, // 1734
  { PseudoVFWNMACC_VF32_M8, VFWNMACC_VF }, // 1735
  { PseudoVFWNMACC_VF32_M8_MASK, VFWNMACC_VF }, // 1736
  { PseudoVFWNMACC_VF32_MF2, VFWNMACC_VF }, // 1737
  { PseudoVFWNMACC_VF32_MF2_MASK, VFWNMACC_VF }, // 1738
  { PseudoVFWNMACC_VV_M1, VFWNMACC_VV }, // 1739
  { PseudoVFWNMACC_VV_M1_MASK, VFWNMACC_VV }, // 1740
  { PseudoVFWNMACC_VV_M2, VFWNMACC_VV }, // 1741
  { PseudoVFWNMACC_VV_M2_MASK, VFWNMACC_VV }, // 1742
  { PseudoVFWNMACC_VV_M4, VFWNMACC_VV }, // 1743
  { PseudoVFWNMACC_VV_M4_MASK, VFWNMACC_VV }, // 1744
  { PseudoVFWNMACC_VV_MF2, VFWNMACC_VV }, // 1745
  { PseudoVFWNMACC_VV_MF2_MASK, VFWNMACC_VV }, // 1746
  { PseudoVFWNMACC_VV_MF4, VFWNMACC_VV }, // 1747
  { PseudoVFWNMACC_VV_MF4_MASK, VFWNMACC_VV }, // 1748
  { PseudoVFWNMSAC_VF16_M1, VFWNMSAC_VF }, // 1749
  { PseudoVFWNMSAC_VF16_M1_MASK, VFWNMSAC_VF }, // 1750
  { PseudoVFWNMSAC_VF16_M2, VFWNMSAC_VF }, // 1751
  { PseudoVFWNMSAC_VF16_M2_MASK, VFWNMSAC_VF }, // 1752
  { PseudoVFWNMSAC_VF16_M4, VFWNMSAC_VF }, // 1753
  { PseudoVFWNMSAC_VF16_M4_MASK, VFWNMSAC_VF }, // 1754
  { PseudoVFWNMSAC_VF16_M8, VFWNMSAC_VF }, // 1755
  { PseudoVFWNMSAC_VF16_M8_MASK, VFWNMSAC_VF }, // 1756
  { PseudoVFWNMSAC_VF16_MF2, VFWNMSAC_VF }, // 1757
  { PseudoVFWNMSAC_VF16_MF2_MASK, VFWNMSAC_VF }, // 1758
  { PseudoVFWNMSAC_VF16_MF4, VFWNMSAC_VF }, // 1759
  { PseudoVFWNMSAC_VF16_MF4_MASK, VFWNMSAC_VF }, // 1760
  { PseudoVFWNMSAC_VF32_M1, VFWNMSAC_VF }, // 1761
  { PseudoVFWNMSAC_VF32_M1_MASK, VFWNMSAC_VF }, // 1762
  { PseudoVFWNMSAC_VF32_M2, VFWNMSAC_VF }, // 1763
  { PseudoVFWNMSAC_VF32_M2_MASK, VFWNMSAC_VF }, // 1764
  { PseudoVFWNMSAC_VF32_M4, VFWNMSAC_VF }, // 1765
  { PseudoVFWNMSAC_VF32_M4_MASK, VFWNMSAC_VF }, // 1766
  { PseudoVFWNMSAC_VF32_M8, VFWNMSAC_VF }, // 1767
  { PseudoVFWNMSAC_VF32_M8_MASK, VFWNMSAC_VF }, // 1768
  { PseudoVFWNMSAC_VF32_MF2, VFWNMSAC_VF }, // 1769
  { PseudoVFWNMSAC_VF32_MF2_MASK, VFWNMSAC_VF }, // 1770
  { PseudoVFWNMSAC_VV_M1, VFWNMSAC_VV }, // 1771
  { PseudoVFWNMSAC_VV_M1_MASK, VFWNMSAC_VV }, // 1772
  { PseudoVFWNMSAC_VV_M2, VFWNMSAC_VV }, // 1773
  { PseudoVFWNMSAC_VV_M2_MASK, VFWNMSAC_VV }, // 1774
  { PseudoVFWNMSAC_VV_M4, VFWNMSAC_VV }, // 1775
  { PseudoVFWNMSAC_VV_M4_MASK, VFWNMSAC_VV }, // 1776
  { PseudoVFWNMSAC_VV_MF2, VFWNMSAC_VV }, // 1777
  { PseudoVFWNMSAC_VV_MF2_MASK, VFWNMSAC_VV }, // 1778
  { PseudoVFWNMSAC_VV_MF4, VFWNMSAC_VV }, // 1779
  { PseudoVFWNMSAC_VV_MF4_MASK, VFWNMSAC_VV }, // 1780
  { PseudoVFWREDOSUM_VS_M1, VFWREDOSUM_VS }, // 1781
  { PseudoVFWREDOSUM_VS_M1_MASK, VFWREDOSUM_VS }, // 1782
  { PseudoVFWREDOSUM_VS_M2, VFWREDOSUM_VS }, // 1783
  { PseudoVFWREDOSUM_VS_M2_MASK, VFWREDOSUM_VS }, // 1784
  { PseudoVFWREDOSUM_VS_M4, VFWREDOSUM_VS }, // 1785
  { PseudoVFWREDOSUM_VS_M4_MASK, VFWREDOSUM_VS }, // 1786
  { PseudoVFWREDOSUM_VS_M8, VFWREDOSUM_VS }, // 1787
  { PseudoVFWREDOSUM_VS_M8_MASK, VFWREDOSUM_VS }, // 1788
  { PseudoVFWREDOSUM_VS_MF2, VFWREDOSUM_VS }, // 1789
  { PseudoVFWREDOSUM_VS_MF2_MASK, VFWREDOSUM_VS }, // 1790
  { PseudoVFWREDOSUM_VS_MF4, VFWREDOSUM_VS }, // 1791
  { PseudoVFWREDOSUM_VS_MF4_MASK, VFWREDOSUM_VS }, // 1792
  { PseudoVFWREDUSUM_VS_M1, VFWREDUSUM_VS }, // 1793
  { PseudoVFWREDUSUM_VS_M1_MASK, VFWREDUSUM_VS }, // 1794
  { PseudoVFWREDUSUM_VS_M2, VFWREDUSUM_VS }, // 1795
  { PseudoVFWREDUSUM_VS_M2_MASK, VFWREDUSUM_VS }, // 1796
  { PseudoVFWREDUSUM_VS_M4, VFWREDUSUM_VS }, // 1797
  { PseudoVFWREDUSUM_VS_M4_MASK, VFWREDUSUM_VS }, // 1798
  { PseudoVFWREDUSUM_VS_M8, VFWREDUSUM_VS }, // 1799
  { PseudoVFWREDUSUM_VS_M8_MASK, VFWREDUSUM_VS }, // 1800
  { PseudoVFWREDUSUM_VS_MF2, VFWREDUSUM_VS }, // 1801
  { PseudoVFWREDUSUM_VS_MF2_MASK, VFWREDUSUM_VS }, // 1802
  { PseudoVFWREDUSUM_VS_MF4, VFWREDUSUM_VS }, // 1803
  { PseudoVFWREDUSUM_VS_MF4_MASK, VFWREDUSUM_VS }, // 1804
  { PseudoVFWSUB_VF16_M1, VFWSUB_VF }, // 1805
  { PseudoVFWSUB_VF16_M1_MASK, VFWSUB_VF }, // 1806
  { PseudoVFWSUB_VF16_M2, VFWSUB_VF }, // 1807
  { PseudoVFWSUB_VF16_M2_MASK, VFWSUB_VF }, // 1808
  { PseudoVFWSUB_VF16_M4, VFWSUB_VF }, // 1809
  { PseudoVFWSUB_VF16_M4_MASK, VFWSUB_VF }, // 1810
  { PseudoVFWSUB_VF16_M8, VFWSUB_VF }, // 1811
  { PseudoVFWSUB_VF16_M8_MASK, VFWSUB_VF }, // 1812
  { PseudoVFWSUB_VF16_MF2, VFWSUB_VF }, // 1813
  { PseudoVFWSUB_VF16_MF2_MASK, VFWSUB_VF }, // 1814
  { PseudoVFWSUB_VF16_MF4, VFWSUB_VF }, // 1815
  { PseudoVFWSUB_VF16_MF4_MASK, VFWSUB_VF }, // 1816
  { PseudoVFWSUB_VF32_M1, VFWSUB_VF }, // 1817
  { PseudoVFWSUB_VF32_M1_MASK, VFWSUB_VF }, // 1818
  { PseudoVFWSUB_VF32_M2, VFWSUB_VF }, // 1819
  { PseudoVFWSUB_VF32_M2_MASK, VFWSUB_VF }, // 1820
  { PseudoVFWSUB_VF32_M4, VFWSUB_VF }, // 1821
  { PseudoVFWSUB_VF32_M4_MASK, VFWSUB_VF }, // 1822
  { PseudoVFWSUB_VF32_M8, VFWSUB_VF }, // 1823
  { PseudoVFWSUB_VF32_M8_MASK, VFWSUB_VF }, // 1824
  { PseudoVFWSUB_VF32_MF2, VFWSUB_VF }, // 1825
  { PseudoVFWSUB_VF32_MF2_MASK, VFWSUB_VF }, // 1826
  { PseudoVFWSUB_VV_M1, VFWSUB_VV }, // 1827
  { PseudoVFWSUB_VV_M1_MASK, VFWSUB_VV }, // 1828
  { PseudoVFWSUB_VV_M2, VFWSUB_VV }, // 1829
  { PseudoVFWSUB_VV_M2_MASK, VFWSUB_VV }, // 1830
  { PseudoVFWSUB_VV_M4, VFWSUB_VV }, // 1831
  { PseudoVFWSUB_VV_M4_MASK, VFWSUB_VV }, // 1832
  { PseudoVFWSUB_VV_MF2, VFWSUB_VV }, // 1833
  { PseudoVFWSUB_VV_MF2_MASK, VFWSUB_VV }, // 1834
  { PseudoVFWSUB_VV_MF4, VFWSUB_VV }, // 1835
  { PseudoVFWSUB_VV_MF4_MASK, VFWSUB_VV }, // 1836
  { PseudoVFWSUB_WF16_M1, VFWSUB_WF }, // 1837
  { PseudoVFWSUB_WF16_M1_MASK, VFWSUB_WF }, // 1838
  { PseudoVFWSUB_WF16_M2, VFWSUB_WF }, // 1839
  { PseudoVFWSUB_WF16_M2_MASK, VFWSUB_WF }, // 1840
  { PseudoVFWSUB_WF16_M4, VFWSUB_WF }, // 1841
  { PseudoVFWSUB_WF16_M4_MASK, VFWSUB_WF }, // 1842
  { PseudoVFWSUB_WF16_M8, VFWSUB_WF }, // 1843
  { PseudoVFWSUB_WF16_M8_MASK, VFWSUB_WF }, // 1844
  { PseudoVFWSUB_WF16_MF2, VFWSUB_WF }, // 1845
  { PseudoVFWSUB_WF16_MF2_MASK, VFWSUB_WF }, // 1846
  { PseudoVFWSUB_WF16_MF4, VFWSUB_WF }, // 1847
  { PseudoVFWSUB_WF16_MF4_MASK, VFWSUB_WF }, // 1848
  { PseudoVFWSUB_WF32_M1, VFWSUB_WF }, // 1849
  { PseudoVFWSUB_WF32_M1_MASK, VFWSUB_WF }, // 1850
  { PseudoVFWSUB_WF32_M2, VFWSUB_WF }, // 1851
  { PseudoVFWSUB_WF32_M2_MASK, VFWSUB_WF }, // 1852
  { PseudoVFWSUB_WF32_M4, VFWSUB_WF }, // 1853
  { PseudoVFWSUB_WF32_M4_MASK, VFWSUB_WF }, // 1854
  { PseudoVFWSUB_WF32_M8, VFWSUB_WF }, // 1855
  { PseudoVFWSUB_WF32_M8_MASK, VFWSUB_WF }, // 1856
  { PseudoVFWSUB_WF32_MF2, VFWSUB_WF }, // 1857
  { PseudoVFWSUB_WF32_MF2_MASK, VFWSUB_WF }, // 1858
  { PseudoVFWSUB_WV_M1, VFWSUB_WV }, // 1859
  { PseudoVFWSUB_WV_M1_MASK, VFWSUB_WV }, // 1860
  { PseudoVFWSUB_WV_M1_MASK_TIED, VFWSUB_WV }, // 1861
  { PseudoVFWSUB_WV_M1_TIED, VFWSUB_WV }, // 1862
  { PseudoVFWSUB_WV_M2, VFWSUB_WV }, // 1863
  { PseudoVFWSUB_WV_M2_MASK, VFWSUB_WV }, // 1864
  { PseudoVFWSUB_WV_M2_MASK_TIED, VFWSUB_WV }, // 1865
  { PseudoVFWSUB_WV_M2_TIED, VFWSUB_WV }, // 1866
  { PseudoVFWSUB_WV_M4, VFWSUB_WV }, // 1867
  { PseudoVFWSUB_WV_M4_MASK, VFWSUB_WV }, // 1868
  { PseudoVFWSUB_WV_M4_MASK_TIED, VFWSUB_WV }, // 1869
  { PseudoVFWSUB_WV_M4_TIED, VFWSUB_WV }, // 1870
  { PseudoVFWSUB_WV_MF2, VFWSUB_WV }, // 1871
  { PseudoVFWSUB_WV_MF2_MASK, VFWSUB_WV }, // 1872
  { PseudoVFWSUB_WV_MF2_MASK_TIED, VFWSUB_WV }, // 1873
  { PseudoVFWSUB_WV_MF2_TIED, VFWSUB_WV }, // 1874
  { PseudoVFWSUB_WV_MF4, VFWSUB_WV }, // 1875
  { PseudoVFWSUB_WV_MF4_MASK, VFWSUB_WV }, // 1876
  { PseudoVFWSUB_WV_MF4_MASK_TIED, VFWSUB_WV }, // 1877
  { PseudoVFWSUB_WV_MF4_TIED, VFWSUB_WV }, // 1878
  { PseudoVID_V_M1, VID_V }, // 1879
  { PseudoVID_V_M1_MASK, VID_V }, // 1880
  { PseudoVID_V_M2, VID_V }, // 1881
  { PseudoVID_V_M2_MASK, VID_V }, // 1882
  { PseudoVID_V_M4, VID_V }, // 1883
  { PseudoVID_V_M4_MASK, VID_V }, // 1884
  { PseudoVID_V_M8, VID_V }, // 1885
  { PseudoVID_V_M8_MASK, VID_V }, // 1886
  { PseudoVID_V_MF2, VID_V }, // 1887
  { PseudoVID_V_MF2_MASK, VID_V }, // 1888
  { PseudoVID_V_MF4, VID_V }, // 1889
  { PseudoVID_V_MF4_MASK, VID_V }, // 1890
  { PseudoVID_V_MF8, VID_V }, // 1891
  { PseudoVID_V_MF8_MASK, VID_V }, // 1892
  { PseudoVIOTA_M_M1, VIOTA_M }, // 1893
  { PseudoVIOTA_M_M1_MASK, VIOTA_M }, // 1894
  { PseudoVIOTA_M_M2, VIOTA_M }, // 1895
  { PseudoVIOTA_M_M2_MASK, VIOTA_M }, // 1896
  { PseudoVIOTA_M_M4, VIOTA_M }, // 1897
  { PseudoVIOTA_M_M4_MASK, VIOTA_M }, // 1898
  { PseudoVIOTA_M_M8, VIOTA_M }, // 1899
  { PseudoVIOTA_M_M8_MASK, VIOTA_M }, // 1900
  { PseudoVIOTA_M_MF2, VIOTA_M }, // 1901
  { PseudoVIOTA_M_MF2_MASK, VIOTA_M }, // 1902
  { PseudoVIOTA_M_MF4, VIOTA_M }, // 1903
  { PseudoVIOTA_M_MF4_MASK, VIOTA_M }, // 1904
  { PseudoVIOTA_M_MF8, VIOTA_M }, // 1905
  { PseudoVIOTA_M_MF8_MASK, VIOTA_M }, // 1906
  { PseudoVLE16FF_V_M1, VLE16FF_V }, // 1907
  { PseudoVLE16FF_V_M1_MASK, VLE16FF_V }, // 1908
  { PseudoVLE16FF_V_M1_TU, VLE16FF_V }, // 1909
  { PseudoVLE16FF_V_M2, VLE16FF_V }, // 1910
  { PseudoVLE16FF_V_M2_MASK, VLE16FF_V }, // 1911
  { PseudoVLE16FF_V_M2_TU, VLE16FF_V }, // 1912
  { PseudoVLE16FF_V_M4, VLE16FF_V }, // 1913
  { PseudoVLE16FF_V_M4_MASK, VLE16FF_V }, // 1914
  { PseudoVLE16FF_V_M4_TU, VLE16FF_V }, // 1915
  { PseudoVLE16FF_V_M8, VLE16FF_V }, // 1916
  { PseudoVLE16FF_V_M8_MASK, VLE16FF_V }, // 1917
  { PseudoVLE16FF_V_M8_TU, VLE16FF_V }, // 1918
  { PseudoVLE16FF_V_MF2, VLE16FF_V }, // 1919
  { PseudoVLE16FF_V_MF2_MASK, VLE16FF_V }, // 1920
  { PseudoVLE16FF_V_MF2_TU, VLE16FF_V }, // 1921
  { PseudoVLE16FF_V_MF4, VLE16FF_V }, // 1922
  { PseudoVLE16FF_V_MF4_MASK, VLE16FF_V }, // 1923
  { PseudoVLE16FF_V_MF4_TU, VLE16FF_V }, // 1924
  { PseudoVLE16_V_M1, VLE16_V }, // 1925
  { PseudoVLE16_V_M1_MASK, VLE16_V }, // 1926
  { PseudoVLE16_V_M1_TU, VLE16_V }, // 1927
  { PseudoVLE16_V_M2, VLE16_V }, // 1928
  { PseudoVLE16_V_M2_MASK, VLE16_V }, // 1929
  { PseudoVLE16_V_M2_TU, VLE16_V }, // 1930
  { PseudoVLE16_V_M4, VLE16_V }, // 1931
  { PseudoVLE16_V_M4_MASK, VLE16_V }, // 1932
  { PseudoVLE16_V_M4_TU, VLE16_V }, // 1933
  { PseudoVLE16_V_M8, VLE16_V }, // 1934
  { PseudoVLE16_V_M8_MASK, VLE16_V }, // 1935
  { PseudoVLE16_V_M8_TU, VLE16_V }, // 1936
  { PseudoVLE16_V_MF2, VLE16_V }, // 1937
  { PseudoVLE16_V_MF2_MASK, VLE16_V }, // 1938
  { PseudoVLE16_V_MF2_TU, VLE16_V }, // 1939
  { PseudoVLE16_V_MF4, VLE16_V }, // 1940
  { PseudoVLE16_V_MF4_MASK, VLE16_V }, // 1941
  { PseudoVLE16_V_MF4_TU, VLE16_V }, // 1942
  { PseudoVLE32FF_V_M1, VLE32FF_V }, // 1943
  { PseudoVLE32FF_V_M1_MASK, VLE32FF_V }, // 1944
  { PseudoVLE32FF_V_M1_TU, VLE32FF_V }, // 1945
  { PseudoVLE32FF_V_M2, VLE32FF_V }, // 1946
  { PseudoVLE32FF_V_M2_MASK, VLE32FF_V }, // 1947
  { PseudoVLE32FF_V_M2_TU, VLE32FF_V }, // 1948
  { PseudoVLE32FF_V_M4, VLE32FF_V }, // 1949
  { PseudoVLE32FF_V_M4_MASK, VLE32FF_V }, // 1950
  { PseudoVLE32FF_V_M4_TU, VLE32FF_V }, // 1951
  { PseudoVLE32FF_V_M8, VLE32FF_V }, // 1952
  { PseudoVLE32FF_V_M8_MASK, VLE32FF_V }, // 1953
  { PseudoVLE32FF_V_M8_TU, VLE32FF_V }, // 1954
  { PseudoVLE32FF_V_MF2, VLE32FF_V }, // 1955
  { PseudoVLE32FF_V_MF2_MASK, VLE32FF_V }, // 1956
  { PseudoVLE32FF_V_MF2_TU, VLE32FF_V }, // 1957
  { PseudoVLE32_V_M1, VLE32_V }, // 1958
  { PseudoVLE32_V_M1_MASK, VLE32_V }, // 1959
  { PseudoVLE32_V_M1_TU, VLE32_V }, // 1960
  { PseudoVLE32_V_M2, VLE32_V }, // 1961
  { PseudoVLE32_V_M2_MASK, VLE32_V }, // 1962
  { PseudoVLE32_V_M2_TU, VLE32_V }, // 1963
  { PseudoVLE32_V_M4, VLE32_V }, // 1964
  { PseudoVLE32_V_M4_MASK, VLE32_V }, // 1965
  { PseudoVLE32_V_M4_TU, VLE32_V }, // 1966
  { PseudoVLE32_V_M8, VLE32_V }, // 1967
  { PseudoVLE32_V_M8_MASK, VLE32_V }, // 1968
  { PseudoVLE32_V_M8_TU, VLE32_V }, // 1969
  { PseudoVLE32_V_MF2, VLE32_V }, // 1970
  { PseudoVLE32_V_MF2_MASK, VLE32_V }, // 1971
  { PseudoVLE32_V_MF2_TU, VLE32_V }, // 1972
  { PseudoVLE64FF_V_M1, VLE64FF_V }, // 1973
  { PseudoVLE64FF_V_M1_MASK, VLE64FF_V }, // 1974
  { PseudoVLE64FF_V_M1_TU, VLE64FF_V }, // 1975
  { PseudoVLE64FF_V_M2, VLE64FF_V }, // 1976
  { PseudoVLE64FF_V_M2_MASK, VLE64FF_V }, // 1977
  { PseudoVLE64FF_V_M2_TU, VLE64FF_V }, // 1978
  { PseudoVLE64FF_V_M4, VLE64FF_V }, // 1979
  { PseudoVLE64FF_V_M4_MASK, VLE64FF_V }, // 1980
  { PseudoVLE64FF_V_M4_TU, VLE64FF_V }, // 1981
  { PseudoVLE64FF_V_M8, VLE64FF_V }, // 1982
  { PseudoVLE64FF_V_M8_MASK, VLE64FF_V }, // 1983
  { PseudoVLE64FF_V_M8_TU, VLE64FF_V }, // 1984
  { PseudoVLE64_V_M1, VLE64_V }, // 1985
  { PseudoVLE64_V_M1_MASK, VLE64_V }, // 1986
  { PseudoVLE64_V_M1_TU, VLE64_V }, // 1987
  { PseudoVLE64_V_M2, VLE64_V }, // 1988
  { PseudoVLE64_V_M2_MASK, VLE64_V }, // 1989
  { PseudoVLE64_V_M2_TU, VLE64_V }, // 1990
  { PseudoVLE64_V_M4, VLE64_V }, // 1991
  { PseudoVLE64_V_M4_MASK, VLE64_V }, // 1992
  { PseudoVLE64_V_M4_TU, VLE64_V }, // 1993
  { PseudoVLE64_V_M8, VLE64_V }, // 1994
  { PseudoVLE64_V_M8_MASK, VLE64_V }, // 1995
  { PseudoVLE64_V_M8_TU, VLE64_V }, // 1996
  { PseudoVLE8FF_V_M1, VLE8FF_V }, // 1997
  { PseudoVLE8FF_V_M1_MASK, VLE8FF_V }, // 1998
  { PseudoVLE8FF_V_M1_TU, VLE8FF_V }, // 1999
  { PseudoVLE8FF_V_M2, VLE8FF_V }, // 2000
  { PseudoVLE8FF_V_M2_MASK, VLE8FF_V }, // 2001
  { PseudoVLE8FF_V_M2_TU, VLE8FF_V }, // 2002
  { PseudoVLE8FF_V_M4, VLE8FF_V }, // 2003
  { PseudoVLE8FF_V_M4_MASK, VLE8FF_V }, // 2004
  { PseudoVLE8FF_V_M4_TU, VLE8FF_V }, // 2005
  { PseudoVLE8FF_V_M8, VLE8FF_V }, // 2006
  { PseudoVLE8FF_V_M8_MASK, VLE8FF_V }, // 2007
  { PseudoVLE8FF_V_M8_TU, VLE8FF_V }, // 2008
  { PseudoVLE8FF_V_MF2, VLE8FF_V }, // 2009
  { PseudoVLE8FF_V_MF2_MASK, VLE8FF_V }, // 2010
  { PseudoVLE8FF_V_MF2_TU, VLE8FF_V }, // 2011
  { PseudoVLE8FF_V_MF4, VLE8FF_V }, // 2012
  { PseudoVLE8FF_V_MF4_MASK, VLE8FF_V }, // 2013
  { PseudoVLE8FF_V_MF4_TU, VLE8FF_V }, // 2014
  { PseudoVLE8FF_V_MF8, VLE8FF_V }, // 2015
  { PseudoVLE8FF_V_MF8_MASK, VLE8FF_V }, // 2016
  { PseudoVLE8FF_V_MF8_TU, VLE8FF_V }, // 2017
  { PseudoVLE8_V_M1, VLE8_V }, // 2018
  { PseudoVLE8_V_M1_MASK, VLE8_V }, // 2019
  { PseudoVLE8_V_M1_TU, VLE8_V }, // 2020
  { PseudoVLE8_V_M2, VLE8_V }, // 2021
  { PseudoVLE8_V_M2_MASK, VLE8_V }, // 2022
  { PseudoVLE8_V_M2_TU, VLE8_V }, // 2023
  { PseudoVLE8_V_M4, VLE8_V }, // 2024
  { PseudoVLE8_V_M4_MASK, VLE8_V }, // 2025
  { PseudoVLE8_V_M4_TU, VLE8_V }, // 2026
  { PseudoVLE8_V_M8, VLE8_V }, // 2027
  { PseudoVLE8_V_M8_MASK, VLE8_V }, // 2028
  { PseudoVLE8_V_M8_TU, VLE8_V }, // 2029
  { PseudoVLE8_V_MF2, VLE8_V }, // 2030
  { PseudoVLE8_V_MF2_MASK, VLE8_V }, // 2031
  { PseudoVLE8_V_MF2_TU, VLE8_V }, // 2032
  { PseudoVLE8_V_MF4, VLE8_V }, // 2033
  { PseudoVLE8_V_MF4_MASK, VLE8_V }, // 2034
  { PseudoVLE8_V_MF4_TU, VLE8_V }, // 2035
  { PseudoVLE8_V_MF8, VLE8_V }, // 2036
  { PseudoVLE8_V_MF8_MASK, VLE8_V }, // 2037
  { PseudoVLE8_V_MF8_TU, VLE8_V }, // 2038
  { PseudoVLM_V_B1, VLM_V }, // 2039
  { PseudoVLM_V_B16, VLM_V }, // 2040
  { PseudoVLM_V_B2, VLM_V }, // 2041
  { PseudoVLM_V_B32, VLM_V }, // 2042
  { PseudoVLM_V_B4, VLM_V }, // 2043
  { PseudoVLM_V_B64, VLM_V }, // 2044
  { PseudoVLM_V_B8, VLM_V }, // 2045
  { PseudoVLOXEI16_V_M1_M1, VLOXEI16_V }, // 2046
  { PseudoVLOXEI16_V_M1_M1_MASK, VLOXEI16_V }, // 2047
  { PseudoVLOXEI16_V_M1_M1_TU, VLOXEI16_V }, // 2048
  { PseudoVLOXEI16_V_M1_M2, VLOXEI16_V }, // 2049
  { PseudoVLOXEI16_V_M1_M2_MASK, VLOXEI16_V }, // 2050
  { PseudoVLOXEI16_V_M1_M2_TU, VLOXEI16_V }, // 2051
  { PseudoVLOXEI16_V_M1_M4, VLOXEI16_V }, // 2052
  { PseudoVLOXEI16_V_M1_M4_MASK, VLOXEI16_V }, // 2053
  { PseudoVLOXEI16_V_M1_M4_TU, VLOXEI16_V }, // 2054
  { PseudoVLOXEI16_V_M1_MF2, VLOXEI16_V }, // 2055
  { PseudoVLOXEI16_V_M1_MF2_MASK, VLOXEI16_V }, // 2056
  { PseudoVLOXEI16_V_M1_MF2_TU, VLOXEI16_V }, // 2057
  { PseudoVLOXEI16_V_M2_M1, VLOXEI16_V }, // 2058
  { PseudoVLOXEI16_V_M2_M1_MASK, VLOXEI16_V }, // 2059
  { PseudoVLOXEI16_V_M2_M1_TU, VLOXEI16_V }, // 2060
  { PseudoVLOXEI16_V_M2_M2, VLOXEI16_V }, // 2061
  { PseudoVLOXEI16_V_M2_M2_MASK, VLOXEI16_V }, // 2062
  { PseudoVLOXEI16_V_M2_M2_TU, VLOXEI16_V }, // 2063
  { PseudoVLOXEI16_V_M2_M4, VLOXEI16_V }, // 2064
  { PseudoVLOXEI16_V_M2_M4_MASK, VLOXEI16_V }, // 2065
  { PseudoVLOXEI16_V_M2_M4_TU, VLOXEI16_V }, // 2066
  { PseudoVLOXEI16_V_M2_M8, VLOXEI16_V }, // 2067
  { PseudoVLOXEI16_V_M2_M8_MASK, VLOXEI16_V }, // 2068
  { PseudoVLOXEI16_V_M2_M8_TU, VLOXEI16_V }, // 2069
  { PseudoVLOXEI16_V_M4_M2, VLOXEI16_V }, // 2070
  { PseudoVLOXEI16_V_M4_M2_MASK, VLOXEI16_V }, // 2071
  { PseudoVLOXEI16_V_M4_M2_TU, VLOXEI16_V }, // 2072
  { PseudoVLOXEI16_V_M4_M4, VLOXEI16_V }, // 2073
  { PseudoVLOXEI16_V_M4_M4_MASK, VLOXEI16_V }, // 2074
  { PseudoVLOXEI16_V_M4_M4_TU, VLOXEI16_V }, // 2075
  { PseudoVLOXEI16_V_M4_M8, VLOXEI16_V }, // 2076
  { PseudoVLOXEI16_V_M4_M8_MASK, VLOXEI16_V }, // 2077
  { PseudoVLOXEI16_V_M4_M8_TU, VLOXEI16_V }, // 2078
  { PseudoVLOXEI16_V_M8_M4, VLOXEI16_V }, // 2079
  { PseudoVLOXEI16_V_M8_M4_MASK, VLOXEI16_V }, // 2080
  { PseudoVLOXEI16_V_M8_M4_TU, VLOXEI16_V }, // 2081
  { PseudoVLOXEI16_V_M8_M8, VLOXEI16_V }, // 2082
  { PseudoVLOXEI16_V_M8_M8_MASK, VLOXEI16_V }, // 2083
  { PseudoVLOXEI16_V_M8_M8_TU, VLOXEI16_V }, // 2084
  { PseudoVLOXEI16_V_MF2_M1, VLOXEI16_V }, // 2085
  { PseudoVLOXEI16_V_MF2_M1_MASK, VLOXEI16_V }, // 2086
  { PseudoVLOXEI16_V_MF2_M1_TU, VLOXEI16_V }, // 2087
  { PseudoVLOXEI16_V_MF2_M2, VLOXEI16_V }, // 2088
  { PseudoVLOXEI16_V_MF2_M2_MASK, VLOXEI16_V }, // 2089
  { PseudoVLOXEI16_V_MF2_M2_TU, VLOXEI16_V }, // 2090
  { PseudoVLOXEI16_V_MF2_MF2, VLOXEI16_V }, // 2091
  { PseudoVLOXEI16_V_MF2_MF2_MASK, VLOXEI16_V }, // 2092
  { PseudoVLOXEI16_V_MF2_MF2_TU, VLOXEI16_V }, // 2093
  { PseudoVLOXEI16_V_MF2_MF4, VLOXEI16_V }, // 2094
  { PseudoVLOXEI16_V_MF2_MF4_MASK, VLOXEI16_V }, // 2095
  { PseudoVLOXEI16_V_MF2_MF4_TU, VLOXEI16_V }, // 2096
  { PseudoVLOXEI16_V_MF4_M1, VLOXEI16_V }, // 2097
  { PseudoVLOXEI16_V_MF4_M1_MASK, VLOXEI16_V }, // 2098
  { PseudoVLOXEI16_V_MF4_M1_TU, VLOXEI16_V }, // 2099
  { PseudoVLOXEI16_V_MF4_MF2, VLOXEI16_V }, // 2100
  { PseudoVLOXEI16_V_MF4_MF2_MASK, VLOXEI16_V }, // 2101
  { PseudoVLOXEI16_V_MF4_MF2_TU, VLOXEI16_V }, // 2102
  { PseudoVLOXEI16_V_MF4_MF4, VLOXEI16_V }, // 2103
  { PseudoVLOXEI16_V_MF4_MF4_MASK, VLOXEI16_V }, // 2104
  { PseudoVLOXEI16_V_MF4_MF4_TU, VLOXEI16_V }, // 2105
  { PseudoVLOXEI16_V_MF4_MF8, VLOXEI16_V }, // 2106
  { PseudoVLOXEI16_V_MF4_MF8_MASK, VLOXEI16_V }, // 2107
  { PseudoVLOXEI16_V_MF4_MF8_TU, VLOXEI16_V }, // 2108
  { PseudoVLOXEI32_V_M1_M1, VLOXEI32_V }, // 2109
  { PseudoVLOXEI32_V_M1_M1_MASK, VLOXEI32_V }, // 2110
  { PseudoVLOXEI32_V_M1_M1_TU, VLOXEI32_V }, // 2111
  { PseudoVLOXEI32_V_M1_M2, VLOXEI32_V }, // 2112
  { PseudoVLOXEI32_V_M1_M2_MASK, VLOXEI32_V }, // 2113
  { PseudoVLOXEI32_V_M1_M2_TU, VLOXEI32_V }, // 2114
  { PseudoVLOXEI32_V_M1_MF2, VLOXEI32_V }, // 2115
  { PseudoVLOXEI32_V_M1_MF2_MASK, VLOXEI32_V }, // 2116
  { PseudoVLOXEI32_V_M1_MF2_TU, VLOXEI32_V }, // 2117
  { PseudoVLOXEI32_V_M1_MF4, VLOXEI32_V }, // 2118
  { PseudoVLOXEI32_V_M1_MF4_MASK, VLOXEI32_V }, // 2119
  { PseudoVLOXEI32_V_M1_MF4_TU, VLOXEI32_V }, // 2120
  { PseudoVLOXEI32_V_M2_M1, VLOXEI32_V }, // 2121
  { PseudoVLOXEI32_V_M2_M1_MASK, VLOXEI32_V }, // 2122
  { PseudoVLOXEI32_V_M2_M1_TU, VLOXEI32_V }, // 2123
  { PseudoVLOXEI32_V_M2_M2, VLOXEI32_V }, // 2124
  { PseudoVLOXEI32_V_M2_M2_MASK, VLOXEI32_V }, // 2125
  { PseudoVLOXEI32_V_M2_M2_TU, VLOXEI32_V }, // 2126
  { PseudoVLOXEI32_V_M2_M4, VLOXEI32_V }, // 2127
  { PseudoVLOXEI32_V_M2_M4_MASK, VLOXEI32_V }, // 2128
  { PseudoVLOXEI32_V_M2_M4_TU, VLOXEI32_V }, // 2129
  { PseudoVLOXEI32_V_M2_MF2, VLOXEI32_V }, // 2130
  { PseudoVLOXEI32_V_M2_MF2_MASK, VLOXEI32_V }, // 2131
  { PseudoVLOXEI32_V_M2_MF2_TU, VLOXEI32_V }, // 2132
  { PseudoVLOXEI32_V_M4_M1, VLOXEI32_V }, // 2133
  { PseudoVLOXEI32_V_M4_M1_MASK, VLOXEI32_V }, // 2134
  { PseudoVLOXEI32_V_M4_M1_TU, VLOXEI32_V }, // 2135
  { PseudoVLOXEI32_V_M4_M2, VLOXEI32_V }, // 2136
  { PseudoVLOXEI32_V_M4_M2_MASK, VLOXEI32_V }, // 2137
  { PseudoVLOXEI32_V_M4_M2_TU, VLOXEI32_V }, // 2138
  { PseudoVLOXEI32_V_M4_M4, VLOXEI32_V }, // 2139
  { PseudoVLOXEI32_V_M4_M4_MASK, VLOXEI32_V }, // 2140
  { PseudoVLOXEI32_V_M4_M4_TU, VLOXEI32_V }, // 2141
  { PseudoVLOXEI32_V_M4_M8, VLOXEI32_V }, // 2142
  { PseudoVLOXEI32_V_M4_M8_MASK, VLOXEI32_V }, // 2143
  { PseudoVLOXEI32_V_M4_M8_TU, VLOXEI32_V }, // 2144
  { PseudoVLOXEI32_V_M8_M2, VLOXEI32_V }, // 2145
  { PseudoVLOXEI32_V_M8_M2_MASK, VLOXEI32_V }, // 2146
  { PseudoVLOXEI32_V_M8_M2_TU, VLOXEI32_V }, // 2147
  { PseudoVLOXEI32_V_M8_M4, VLOXEI32_V }, // 2148
  { PseudoVLOXEI32_V_M8_M4_MASK, VLOXEI32_V }, // 2149
  { PseudoVLOXEI32_V_M8_M4_TU, VLOXEI32_V }, // 2150
  { PseudoVLOXEI32_V_M8_M8, VLOXEI32_V }, // 2151
  { PseudoVLOXEI32_V_M8_M8_MASK, VLOXEI32_V }, // 2152
  { PseudoVLOXEI32_V_M8_M8_TU, VLOXEI32_V }, // 2153
  { PseudoVLOXEI32_V_MF2_M1, VLOXEI32_V }, // 2154
  { PseudoVLOXEI32_V_MF2_M1_MASK, VLOXEI32_V }, // 2155
  { PseudoVLOXEI32_V_MF2_M1_TU, VLOXEI32_V }, // 2156
  { PseudoVLOXEI32_V_MF2_MF2, VLOXEI32_V }, // 2157
  { PseudoVLOXEI32_V_MF2_MF2_MASK, VLOXEI32_V }, // 2158
  { PseudoVLOXEI32_V_MF2_MF2_TU, VLOXEI32_V }, // 2159
  { PseudoVLOXEI32_V_MF2_MF4, VLOXEI32_V }, // 2160
  { PseudoVLOXEI32_V_MF2_MF4_MASK, VLOXEI32_V }, // 2161
  { PseudoVLOXEI32_V_MF2_MF4_TU, VLOXEI32_V }, // 2162
  { PseudoVLOXEI32_V_MF2_MF8, VLOXEI32_V }, // 2163
  { PseudoVLOXEI32_V_MF2_MF8_MASK, VLOXEI32_V }, // 2164
  { PseudoVLOXEI32_V_MF2_MF8_TU, VLOXEI32_V }, // 2165
  { PseudoVLOXEI64_V_M1_M1, VLOXEI64_V }, // 2166
  { PseudoVLOXEI64_V_M1_M1_MASK, VLOXEI64_V }, // 2167
  { PseudoVLOXEI64_V_M1_M1_TU, VLOXEI64_V }, // 2168
  { PseudoVLOXEI64_V_M1_MF2, VLOXEI64_V }, // 2169
  { PseudoVLOXEI64_V_M1_MF2_MASK, VLOXEI64_V }, // 2170
  { PseudoVLOXEI64_V_M1_MF2_TU, VLOXEI64_V }, // 2171
  { PseudoVLOXEI64_V_M1_MF4, VLOXEI64_V }, // 2172
  { PseudoVLOXEI64_V_M1_MF4_MASK, VLOXEI64_V }, // 2173
  { PseudoVLOXEI64_V_M1_MF4_TU, VLOXEI64_V }, // 2174
  { PseudoVLOXEI64_V_M1_MF8, VLOXEI64_V }, // 2175
  { PseudoVLOXEI64_V_M1_MF8_MASK, VLOXEI64_V }, // 2176
  { PseudoVLOXEI64_V_M1_MF8_TU, VLOXEI64_V }, // 2177
  { PseudoVLOXEI64_V_M2_M1, VLOXEI64_V }, // 2178
  { PseudoVLOXEI64_V_M2_M1_MASK, VLOXEI64_V }, // 2179
  { PseudoVLOXEI64_V_M2_M1_TU, VLOXEI64_V }, // 2180
  { PseudoVLOXEI64_V_M2_M2, VLOXEI64_V }, // 2181
  { PseudoVLOXEI64_V_M2_M2_MASK, VLOXEI64_V }, // 2182
  { PseudoVLOXEI64_V_M2_M2_TU, VLOXEI64_V }, // 2183
  { PseudoVLOXEI64_V_M2_MF2, VLOXEI64_V }, // 2184
  { PseudoVLOXEI64_V_M2_MF2_MASK, VLOXEI64_V }, // 2185
  { PseudoVLOXEI64_V_M2_MF2_TU, VLOXEI64_V }, // 2186
  { PseudoVLOXEI64_V_M2_MF4, VLOXEI64_V }, // 2187
  { PseudoVLOXEI64_V_M2_MF4_MASK, VLOXEI64_V }, // 2188
  { PseudoVLOXEI64_V_M2_MF4_TU, VLOXEI64_V }, // 2189
  { PseudoVLOXEI64_V_M4_M1, VLOXEI64_V }, // 2190
  { PseudoVLOXEI64_V_M4_M1_MASK, VLOXEI64_V }, // 2191
  { PseudoVLOXEI64_V_M4_M1_TU, VLOXEI64_V }, // 2192
  { PseudoVLOXEI64_V_M4_M2, VLOXEI64_V }, // 2193
  { PseudoVLOXEI64_V_M4_M2_MASK, VLOXEI64_V }, // 2194
  { PseudoVLOXEI64_V_M4_M2_TU, VLOXEI64_V }, // 2195
  { PseudoVLOXEI64_V_M4_M4, VLOXEI64_V }, // 2196
  { PseudoVLOXEI64_V_M4_M4_MASK, VLOXEI64_V }, // 2197
  { PseudoVLOXEI64_V_M4_M4_TU, VLOXEI64_V }, // 2198
  { PseudoVLOXEI64_V_M4_MF2, VLOXEI64_V }, // 2199
  { PseudoVLOXEI64_V_M4_MF2_MASK, VLOXEI64_V }, // 2200
  { PseudoVLOXEI64_V_M4_MF2_TU, VLOXEI64_V }, // 2201
  { PseudoVLOXEI64_V_M8_M1, VLOXEI64_V }, // 2202
  { PseudoVLOXEI64_V_M8_M1_MASK, VLOXEI64_V }, // 2203
  { PseudoVLOXEI64_V_M8_M1_TU, VLOXEI64_V }, // 2204
  { PseudoVLOXEI64_V_M8_M2, VLOXEI64_V }, // 2205
  { PseudoVLOXEI64_V_M8_M2_MASK, VLOXEI64_V }, // 2206
  { PseudoVLOXEI64_V_M8_M2_TU, VLOXEI64_V }, // 2207
  { PseudoVLOXEI64_V_M8_M4, VLOXEI64_V }, // 2208
  { PseudoVLOXEI64_V_M8_M4_MASK, VLOXEI64_V }, // 2209
  { PseudoVLOXEI64_V_M8_M4_TU, VLOXEI64_V }, // 2210
  { PseudoVLOXEI64_V_M8_M8, VLOXEI64_V }, // 2211
  { PseudoVLOXEI64_V_M8_M8_MASK, VLOXEI64_V }, // 2212
  { PseudoVLOXEI64_V_M8_M8_TU, VLOXEI64_V }, // 2213
  { PseudoVLOXEI8_V_M1_M1, VLOXEI8_V }, // 2214
  { PseudoVLOXEI8_V_M1_M1_MASK, VLOXEI8_V }, // 2215
  { PseudoVLOXEI8_V_M1_M1_TU, VLOXEI8_V }, // 2216
  { PseudoVLOXEI8_V_M1_M2, VLOXEI8_V }, // 2217
  { PseudoVLOXEI8_V_M1_M2_MASK, VLOXEI8_V }, // 2218
  { PseudoVLOXEI8_V_M1_M2_TU, VLOXEI8_V }, // 2219
  { PseudoVLOXEI8_V_M1_M4, VLOXEI8_V }, // 2220
  { PseudoVLOXEI8_V_M1_M4_MASK, VLOXEI8_V }, // 2221
  { PseudoVLOXEI8_V_M1_M4_TU, VLOXEI8_V }, // 2222
  { PseudoVLOXEI8_V_M1_M8, VLOXEI8_V }, // 2223
  { PseudoVLOXEI8_V_M1_M8_MASK, VLOXEI8_V }, // 2224
  { PseudoVLOXEI8_V_M1_M8_TU, VLOXEI8_V }, // 2225
  { PseudoVLOXEI8_V_M2_M2, VLOXEI8_V }, // 2226
  { PseudoVLOXEI8_V_M2_M2_MASK, VLOXEI8_V }, // 2227
  { PseudoVLOXEI8_V_M2_M2_TU, VLOXEI8_V }, // 2228
  { PseudoVLOXEI8_V_M2_M4, VLOXEI8_V }, // 2229
  { PseudoVLOXEI8_V_M2_M4_MASK, VLOXEI8_V }, // 2230
  { PseudoVLOXEI8_V_M2_M4_TU, VLOXEI8_V }, // 2231
  { PseudoVLOXEI8_V_M2_M8, VLOXEI8_V }, // 2232
  { PseudoVLOXEI8_V_M2_M8_MASK, VLOXEI8_V }, // 2233
  { PseudoVLOXEI8_V_M2_M8_TU, VLOXEI8_V }, // 2234
  { PseudoVLOXEI8_V_M4_M4, VLOXEI8_V }, // 2235
  { PseudoVLOXEI8_V_M4_M4_MASK, VLOXEI8_V }, // 2236
  { PseudoVLOXEI8_V_M4_M4_TU, VLOXEI8_V }, // 2237
  { PseudoVLOXEI8_V_M4_M8, VLOXEI8_V }, // 2238
  { PseudoVLOXEI8_V_M4_M8_MASK, VLOXEI8_V }, // 2239
  { PseudoVLOXEI8_V_M4_M8_TU, VLOXEI8_V }, // 2240
  { PseudoVLOXEI8_V_M8_M8, VLOXEI8_V }, // 2241
  { PseudoVLOXEI8_V_M8_M8_MASK, VLOXEI8_V }, // 2242
  { PseudoVLOXEI8_V_M8_M8_TU, VLOXEI8_V }, // 2243
  { PseudoVLOXEI8_V_MF2_M1, VLOXEI8_V }, // 2244
  { PseudoVLOXEI8_V_MF2_M1_MASK, VLOXEI8_V }, // 2245
  { PseudoVLOXEI8_V_MF2_M1_TU, VLOXEI8_V }, // 2246
  { PseudoVLOXEI8_V_MF2_M2, VLOXEI8_V }, // 2247
  { PseudoVLOXEI8_V_MF2_M2_MASK, VLOXEI8_V }, // 2248
  { PseudoVLOXEI8_V_MF2_M2_TU, VLOXEI8_V }, // 2249
  { PseudoVLOXEI8_V_MF2_M4, VLOXEI8_V }, // 2250
  { PseudoVLOXEI8_V_MF2_M4_MASK, VLOXEI8_V }, // 2251
  { PseudoVLOXEI8_V_MF2_M4_TU, VLOXEI8_V }, // 2252
  { PseudoVLOXEI8_V_MF2_MF2, VLOXEI8_V }, // 2253
  { PseudoVLOXEI8_V_MF2_MF2_MASK, VLOXEI8_V }, // 2254
  { PseudoVLOXEI8_V_MF2_MF2_TU, VLOXEI8_V }, // 2255
  { PseudoVLOXEI8_V_MF4_M1, VLOXEI8_V }, // 2256
  { PseudoVLOXEI8_V_MF4_M1_MASK, VLOXEI8_V }, // 2257
  { PseudoVLOXEI8_V_MF4_M1_TU, VLOXEI8_V }, // 2258
  { PseudoVLOXEI8_V_MF4_M2, VLOXEI8_V }, // 2259
  { PseudoVLOXEI8_V_MF4_M2_MASK, VLOXEI8_V }, // 2260
  { PseudoVLOXEI8_V_MF4_M2_TU, VLOXEI8_V }, // 2261
  { PseudoVLOXEI8_V_MF4_MF2, VLOXEI8_V }, // 2262
  { PseudoVLOXEI8_V_MF4_MF2_MASK, VLOXEI8_V }, // 2263
  { PseudoVLOXEI8_V_MF4_MF2_TU, VLOXEI8_V }, // 2264
  { PseudoVLOXEI8_V_MF4_MF4, VLOXEI8_V }, // 2265
  { PseudoVLOXEI8_V_MF4_MF4_MASK, VLOXEI8_V }, // 2266
  { PseudoVLOXEI8_V_MF4_MF4_TU, VLOXEI8_V }, // 2267
  { PseudoVLOXEI8_V_MF8_M1, VLOXEI8_V }, // 2268
  { PseudoVLOXEI8_V_MF8_M1_MASK, VLOXEI8_V }, // 2269
  { PseudoVLOXEI8_V_MF8_M1_TU, VLOXEI8_V }, // 2270
  { PseudoVLOXEI8_V_MF8_MF2, VLOXEI8_V }, // 2271
  { PseudoVLOXEI8_V_MF8_MF2_MASK, VLOXEI8_V }, // 2272
  { PseudoVLOXEI8_V_MF8_MF2_TU, VLOXEI8_V }, // 2273
  { PseudoVLOXEI8_V_MF8_MF4, VLOXEI8_V }, // 2274
  { PseudoVLOXEI8_V_MF8_MF4_MASK, VLOXEI8_V }, // 2275
  { PseudoVLOXEI8_V_MF8_MF4_TU, VLOXEI8_V }, // 2276
  { PseudoVLOXEI8_V_MF8_MF8, VLOXEI8_V }, // 2277
  { PseudoVLOXEI8_V_MF8_MF8_MASK, VLOXEI8_V }, // 2278
  { PseudoVLOXEI8_V_MF8_MF8_TU, VLOXEI8_V }, // 2279
  { PseudoVLOXSEG2EI16_V_M1_M1, VLOXSEG2EI16_V }, // 2280
  { PseudoVLOXSEG2EI16_V_M1_M1_MASK, VLOXSEG2EI16_V }, // 2281
  { PseudoVLOXSEG2EI16_V_M1_M2, VLOXSEG2EI16_V }, // 2282
  { PseudoVLOXSEG2EI16_V_M1_M2_MASK, VLOXSEG2EI16_V }, // 2283
  { PseudoVLOXSEG2EI16_V_M1_M4, VLOXSEG2EI16_V }, // 2284
  { PseudoVLOXSEG2EI16_V_M1_M4_MASK, VLOXSEG2EI16_V }, // 2285
  { PseudoVLOXSEG2EI16_V_M1_MF2, VLOXSEG2EI16_V }, // 2286
  { PseudoVLOXSEG2EI16_V_M1_MF2_MASK, VLOXSEG2EI16_V }, // 2287
  { PseudoVLOXSEG2EI16_V_M2_M1, VLOXSEG2EI16_V }, // 2288
  { PseudoVLOXSEG2EI16_V_M2_M1_MASK, VLOXSEG2EI16_V }, // 2289
  { PseudoVLOXSEG2EI16_V_M2_M2, VLOXSEG2EI16_V }, // 2290
  { PseudoVLOXSEG2EI16_V_M2_M2_MASK, VLOXSEG2EI16_V }, // 2291
  { PseudoVLOXSEG2EI16_V_M2_M4, VLOXSEG2EI16_V }, // 2292
  { PseudoVLOXSEG2EI16_V_M2_M4_MASK, VLOXSEG2EI16_V }, // 2293
  { PseudoVLOXSEG2EI16_V_M4_M2, VLOXSEG2EI16_V }, // 2294
  { PseudoVLOXSEG2EI16_V_M4_M2_MASK, VLOXSEG2EI16_V }, // 2295
  { PseudoVLOXSEG2EI16_V_M4_M4, VLOXSEG2EI16_V }, // 2296
  { PseudoVLOXSEG2EI16_V_M4_M4_MASK, VLOXSEG2EI16_V }, // 2297
  { PseudoVLOXSEG2EI16_V_M8_M4, VLOXSEG2EI16_V }, // 2298
  { PseudoVLOXSEG2EI16_V_M8_M4_MASK, VLOXSEG2EI16_V }, // 2299
  { PseudoVLOXSEG2EI16_V_MF2_M1, VLOXSEG2EI16_V }, // 2300
  { PseudoVLOXSEG2EI16_V_MF2_M1_MASK, VLOXSEG2EI16_V }, // 2301
  { PseudoVLOXSEG2EI16_V_MF2_M2, VLOXSEG2EI16_V }, // 2302
  { PseudoVLOXSEG2EI16_V_MF2_M2_MASK, VLOXSEG2EI16_V }, // 2303
  { PseudoVLOXSEG2EI16_V_MF2_MF2, VLOXSEG2EI16_V }, // 2304
  { PseudoVLOXSEG2EI16_V_MF2_MF2_MASK, VLOXSEG2EI16_V }, // 2305
  { PseudoVLOXSEG2EI16_V_MF2_MF4, VLOXSEG2EI16_V }, // 2306
  { PseudoVLOXSEG2EI16_V_MF2_MF4_MASK, VLOXSEG2EI16_V }, // 2307
  { PseudoVLOXSEG2EI16_V_MF4_M1, VLOXSEG2EI16_V }, // 2308
  { PseudoVLOXSEG2EI16_V_MF4_M1_MASK, VLOXSEG2EI16_V }, // 2309
  { PseudoVLOXSEG2EI16_V_MF4_MF2, VLOXSEG2EI16_V }, // 2310
  { PseudoVLOXSEG2EI16_V_MF4_MF2_MASK, VLOXSEG2EI16_V }, // 2311
  { PseudoVLOXSEG2EI16_V_MF4_MF4, VLOXSEG2EI16_V }, // 2312
  { PseudoVLOXSEG2EI16_V_MF4_MF4_MASK, VLOXSEG2EI16_V }, // 2313
  { PseudoVLOXSEG2EI16_V_MF4_MF8, VLOXSEG2EI16_V }, // 2314
  { PseudoVLOXSEG2EI16_V_MF4_MF8_MASK, VLOXSEG2EI16_V }, // 2315
  { PseudoVLOXSEG2EI32_V_M1_M1, VLOXSEG2EI32_V }, // 2316
  { PseudoVLOXSEG2EI32_V_M1_M1_MASK, VLOXSEG2EI32_V }, // 2317
  { PseudoVLOXSEG2EI32_V_M1_M2, VLOXSEG2EI32_V }, // 2318
  { PseudoVLOXSEG2EI32_V_M1_M2_MASK, VLOXSEG2EI32_V }, // 2319
  { PseudoVLOXSEG2EI32_V_M1_MF2, VLOXSEG2EI32_V }, // 2320
  { PseudoVLOXSEG2EI32_V_M1_MF2_MASK, VLOXSEG2EI32_V }, // 2321
  { PseudoVLOXSEG2EI32_V_M1_MF4, VLOXSEG2EI32_V }, // 2322
  { PseudoVLOXSEG2EI32_V_M1_MF4_MASK, VLOXSEG2EI32_V }, // 2323
  { PseudoVLOXSEG2EI32_V_M2_M1, VLOXSEG2EI32_V }, // 2324
  { PseudoVLOXSEG2EI32_V_M2_M1_MASK, VLOXSEG2EI32_V }, // 2325
  { PseudoVLOXSEG2EI32_V_M2_M2, VLOXSEG2EI32_V }, // 2326
  { PseudoVLOXSEG2EI32_V_M2_M2_MASK, VLOXSEG2EI32_V }, // 2327
  { PseudoVLOXSEG2EI32_V_M2_M4, VLOXSEG2EI32_V }, // 2328
  { PseudoVLOXSEG2EI32_V_M2_M4_MASK, VLOXSEG2EI32_V }, // 2329
  { PseudoVLOXSEG2EI32_V_M2_MF2, VLOXSEG2EI32_V }, // 2330
  { PseudoVLOXSEG2EI32_V_M2_MF2_MASK, VLOXSEG2EI32_V }, // 2331
  { PseudoVLOXSEG2EI32_V_M4_M1, VLOXSEG2EI32_V }, // 2332
  { PseudoVLOXSEG2EI32_V_M4_M1_MASK, VLOXSEG2EI32_V }, // 2333
  { PseudoVLOXSEG2EI32_V_M4_M2, VLOXSEG2EI32_V }, // 2334
  { PseudoVLOXSEG2EI32_V_M4_M2_MASK, VLOXSEG2EI32_V }, // 2335
  { PseudoVLOXSEG2EI32_V_M4_M4, VLOXSEG2EI32_V }, // 2336
  { PseudoVLOXSEG2EI32_V_M4_M4_MASK, VLOXSEG2EI32_V }, // 2337
  { PseudoVLOXSEG2EI32_V_M8_M2, VLOXSEG2EI32_V }, // 2338
  { PseudoVLOXSEG2EI32_V_M8_M2_MASK, VLOXSEG2EI32_V }, // 2339
  { PseudoVLOXSEG2EI32_V_M8_M4, VLOXSEG2EI32_V }, // 2340
  { PseudoVLOXSEG2EI32_V_M8_M4_MASK, VLOXSEG2EI32_V }, // 2341
  { PseudoVLOXSEG2EI32_V_MF2_M1, VLOXSEG2EI32_V }, // 2342
  { PseudoVLOXSEG2EI32_V_MF2_M1_MASK, VLOXSEG2EI32_V }, // 2343
  { PseudoVLOXSEG2EI32_V_MF2_MF2, VLOXSEG2EI32_V }, // 2344
  { PseudoVLOXSEG2EI32_V_MF2_MF2_MASK, VLOXSEG2EI32_V }, // 2345
  { PseudoVLOXSEG2EI32_V_MF2_MF4, VLOXSEG2EI32_V }, // 2346
  { PseudoVLOXSEG2EI32_V_MF2_MF4_MASK, VLOXSEG2EI32_V }, // 2347
  { PseudoVLOXSEG2EI32_V_MF2_MF8, VLOXSEG2EI32_V }, // 2348
  { PseudoVLOXSEG2EI32_V_MF2_MF8_MASK, VLOXSEG2EI32_V }, // 2349
  { PseudoVLOXSEG2EI64_V_M1_M1, VLOXSEG2EI64_V }, // 2350
  { PseudoVLOXSEG2EI64_V_M1_M1_MASK, VLOXSEG2EI64_V }, // 2351
  { PseudoVLOXSEG2EI64_V_M1_MF2, VLOXSEG2EI64_V }, // 2352
  { PseudoVLOXSEG2EI64_V_M1_MF2_MASK, VLOXSEG2EI64_V }, // 2353
  { PseudoVLOXSEG2EI64_V_M1_MF4, VLOXSEG2EI64_V }, // 2354
  { PseudoVLOXSEG2EI64_V_M1_MF4_MASK, VLOXSEG2EI64_V }, // 2355
  { PseudoVLOXSEG2EI64_V_M1_MF8, VLOXSEG2EI64_V }, // 2356
  { PseudoVLOXSEG2EI64_V_M1_MF8_MASK, VLOXSEG2EI64_V }, // 2357
  { PseudoVLOXSEG2EI64_V_M2_M1, VLOXSEG2EI64_V }, // 2358
  { PseudoVLOXSEG2EI64_V_M2_M1_MASK, VLOXSEG2EI64_V }, // 2359
  { PseudoVLOXSEG2EI64_V_M2_M2, VLOXSEG2EI64_V }, // 2360
  { PseudoVLOXSEG2EI64_V_M2_M2_MASK, VLOXSEG2EI64_V }, // 2361
  { PseudoVLOXSEG2EI64_V_M2_MF2, VLOXSEG2EI64_V }, // 2362
  { PseudoVLOXSEG2EI64_V_M2_MF2_MASK, VLOXSEG2EI64_V }, // 2363
  { PseudoVLOXSEG2EI64_V_M2_MF4, VLOXSEG2EI64_V }, // 2364
  { PseudoVLOXSEG2EI64_V_M2_MF4_MASK, VLOXSEG2EI64_V }, // 2365
  { PseudoVLOXSEG2EI64_V_M4_M1, VLOXSEG2EI64_V }, // 2366
  { PseudoVLOXSEG2EI64_V_M4_M1_MASK, VLOXSEG2EI64_V }, // 2367
  { PseudoVLOXSEG2EI64_V_M4_M2, VLOXSEG2EI64_V }, // 2368
  { PseudoVLOXSEG2EI64_V_M4_M2_MASK, VLOXSEG2EI64_V }, // 2369
  { PseudoVLOXSEG2EI64_V_M4_M4, VLOXSEG2EI64_V }, // 2370
  { PseudoVLOXSEG2EI64_V_M4_M4_MASK, VLOXSEG2EI64_V }, // 2371
  { PseudoVLOXSEG2EI64_V_M4_MF2, VLOXSEG2EI64_V }, // 2372
  { PseudoVLOXSEG2EI64_V_M4_MF2_MASK, VLOXSEG2EI64_V }, // 2373
  { PseudoVLOXSEG2EI64_V_M8_M1, VLOXSEG2EI64_V }, // 2374
  { PseudoVLOXSEG2EI64_V_M8_M1_MASK, VLOXSEG2EI64_V }, // 2375
  { PseudoVLOXSEG2EI64_V_M8_M2, VLOXSEG2EI64_V }, // 2376
  { PseudoVLOXSEG2EI64_V_M8_M2_MASK, VLOXSEG2EI64_V }, // 2377
  { PseudoVLOXSEG2EI64_V_M8_M4, VLOXSEG2EI64_V }, // 2378
  { PseudoVLOXSEG2EI64_V_M8_M4_MASK, VLOXSEG2EI64_V }, // 2379
  { PseudoVLOXSEG2EI8_V_M1_M1, VLOXSEG2EI8_V }, // 2380
  { PseudoVLOXSEG2EI8_V_M1_M1_MASK, VLOXSEG2EI8_V }, // 2381
  { PseudoVLOXSEG2EI8_V_M1_M2, VLOXSEG2EI8_V }, // 2382
  { PseudoVLOXSEG2EI8_V_M1_M2_MASK, VLOXSEG2EI8_V }, // 2383
  { PseudoVLOXSEG2EI8_V_M1_M4, VLOXSEG2EI8_V }, // 2384
  { PseudoVLOXSEG2EI8_V_M1_M4_MASK, VLOXSEG2EI8_V }, // 2385
  { PseudoVLOXSEG2EI8_V_M2_M2, VLOXSEG2EI8_V }, // 2386
  { PseudoVLOXSEG2EI8_V_M2_M2_MASK, VLOXSEG2EI8_V }, // 2387
  { PseudoVLOXSEG2EI8_V_M2_M4, VLOXSEG2EI8_V }, // 2388
  { PseudoVLOXSEG2EI8_V_M2_M4_MASK, VLOXSEG2EI8_V }, // 2389
  { PseudoVLOXSEG2EI8_V_M4_M4, VLOXSEG2EI8_V }, // 2390
  { PseudoVLOXSEG2EI8_V_M4_M4_MASK, VLOXSEG2EI8_V }, // 2391
  { PseudoVLOXSEG2EI8_V_MF2_M1, VLOXSEG2EI8_V }, // 2392
  { PseudoVLOXSEG2EI8_V_MF2_M1_MASK, VLOXSEG2EI8_V }, // 2393
  { PseudoVLOXSEG2EI8_V_MF2_M2, VLOXSEG2EI8_V }, // 2394
  { PseudoVLOXSEG2EI8_V_MF2_M2_MASK, VLOXSEG2EI8_V }, // 2395
  { PseudoVLOXSEG2EI8_V_MF2_M4, VLOXSEG2EI8_V }, // 2396
  { PseudoVLOXSEG2EI8_V_MF2_M4_MASK, VLOXSEG2EI8_V }, // 2397
  { PseudoVLOXSEG2EI8_V_MF2_MF2, VLOXSEG2EI8_V }, // 2398
  { PseudoVLOXSEG2EI8_V_MF2_MF2_MASK, VLOXSEG2EI8_V }, // 2399
  { PseudoVLOXSEG2EI8_V_MF4_M1, VLOXSEG2EI8_V }, // 2400
  { PseudoVLOXSEG2EI8_V_MF4_M1_MASK, VLOXSEG2EI8_V }, // 2401
  { PseudoVLOXSEG2EI8_V_MF4_M2, VLOXSEG2EI8_V }, // 2402
  { PseudoVLOXSEG2EI8_V_MF4_M2_MASK, VLOXSEG2EI8_V }, // 2403
  { PseudoVLOXSEG2EI8_V_MF4_MF2, VLOXSEG2EI8_V }, // 2404
  { PseudoVLOXSEG2EI8_V_MF4_MF2_MASK, VLOXSEG2EI8_V }, // 2405
  { PseudoVLOXSEG2EI8_V_MF4_MF4, VLOXSEG2EI8_V }, // 2406
  { PseudoVLOXSEG2EI8_V_MF4_MF4_MASK, VLOXSEG2EI8_V }, // 2407
  { PseudoVLOXSEG2EI8_V_MF8_M1, VLOXSEG2EI8_V }, // 2408
  { PseudoVLOXSEG2EI8_V_MF8_M1_MASK, VLOXSEG2EI8_V }, // 2409
  { PseudoVLOXSEG2EI8_V_MF8_MF2, VLOXSEG2EI8_V }, // 2410
  { PseudoVLOXSEG2EI8_V_MF8_MF2_MASK, VLOXSEG2EI8_V }, // 2411
  { PseudoVLOXSEG2EI8_V_MF8_MF4, VLOXSEG2EI8_V }, // 2412
  { PseudoVLOXSEG2EI8_V_MF8_MF4_MASK, VLOXSEG2EI8_V }, // 2413
  { PseudoVLOXSEG2EI8_V_MF8_MF8, VLOXSEG2EI8_V }, // 2414
  { PseudoVLOXSEG2EI8_V_MF8_MF8_MASK, VLOXSEG2EI8_V }, // 2415
  { PseudoVLOXSEG3EI16_V_M1_M1, VLOXSEG3EI16_V }, // 2416
  { PseudoVLOXSEG3EI16_V_M1_M1_MASK, VLOXSEG3EI16_V }, // 2417
  { PseudoVLOXSEG3EI16_V_M1_M2, VLOXSEG3EI16_V }, // 2418
  { PseudoVLOXSEG3EI16_V_M1_M2_MASK, VLOXSEG3EI16_V }, // 2419
  { PseudoVLOXSEG3EI16_V_M1_MF2, VLOXSEG3EI16_V }, // 2420
  { PseudoVLOXSEG3EI16_V_M1_MF2_MASK, VLOXSEG3EI16_V }, // 2421
  { PseudoVLOXSEG3EI16_V_M2_M1, VLOXSEG3EI16_V }, // 2422
  { PseudoVLOXSEG3EI16_V_M2_M1_MASK, VLOXSEG3EI16_V }, // 2423
  { PseudoVLOXSEG3EI16_V_M2_M2, VLOXSEG3EI16_V }, // 2424
  { PseudoVLOXSEG3EI16_V_M2_M2_MASK, VLOXSEG3EI16_V }, // 2425
  { PseudoVLOXSEG3EI16_V_M4_M2, VLOXSEG3EI16_V }, // 2426
  { PseudoVLOXSEG3EI16_V_M4_M2_MASK, VLOXSEG3EI16_V }, // 2427
  { PseudoVLOXSEG3EI16_V_MF2_M1, VLOXSEG3EI16_V }, // 2428
  { PseudoVLOXSEG3EI16_V_MF2_M1_MASK, VLOXSEG3EI16_V }, // 2429
  { PseudoVLOXSEG3EI16_V_MF2_M2, VLOXSEG3EI16_V }, // 2430
  { PseudoVLOXSEG3EI16_V_MF2_M2_MASK, VLOXSEG3EI16_V }, // 2431
  { PseudoVLOXSEG3EI16_V_MF2_MF2, VLOXSEG3EI16_V }, // 2432
  { PseudoVLOXSEG3EI16_V_MF2_MF2_MASK, VLOXSEG3EI16_V }, // 2433
  { PseudoVLOXSEG3EI16_V_MF2_MF4, VLOXSEG3EI16_V }, // 2434
  { PseudoVLOXSEG3EI16_V_MF2_MF4_MASK, VLOXSEG3EI16_V }, // 2435
  { PseudoVLOXSEG3EI16_V_MF4_M1, VLOXSEG3EI16_V }, // 2436
  { PseudoVLOXSEG3EI16_V_MF4_M1_MASK, VLOXSEG3EI16_V }, // 2437
  { PseudoVLOXSEG3EI16_V_MF4_MF2, VLOXSEG3EI16_V }, // 2438
  { PseudoVLOXSEG3EI16_V_MF4_MF2_MASK, VLOXSEG3EI16_V }, // 2439
  { PseudoVLOXSEG3EI16_V_MF4_MF4, VLOXSEG3EI16_V }, // 2440
  { PseudoVLOXSEG3EI16_V_MF4_MF4_MASK, VLOXSEG3EI16_V }, // 2441
  { PseudoVLOXSEG3EI16_V_MF4_MF8, VLOXSEG3EI16_V }, // 2442
  { PseudoVLOXSEG3EI16_V_MF4_MF8_MASK, VLOXSEG3EI16_V }, // 2443
  { PseudoVLOXSEG3EI32_V_M1_M1, VLOXSEG3EI32_V }, // 2444
  { PseudoVLOXSEG3EI32_V_M1_M1_MASK, VLOXSEG3EI32_V }, // 2445
  { PseudoVLOXSEG3EI32_V_M1_M2, VLOXSEG3EI32_V }, // 2446
  { PseudoVLOXSEG3EI32_V_M1_M2_MASK, VLOXSEG3EI32_V }, // 2447
  { PseudoVLOXSEG3EI32_V_M1_MF2, VLOXSEG3EI32_V }, // 2448
  { PseudoVLOXSEG3EI32_V_M1_MF2_MASK, VLOXSEG3EI32_V }, // 2449
  { PseudoVLOXSEG3EI32_V_M1_MF4, VLOXSEG3EI32_V }, // 2450
  { PseudoVLOXSEG3EI32_V_M1_MF4_MASK, VLOXSEG3EI32_V }, // 2451
  { PseudoVLOXSEG3EI32_V_M2_M1, VLOXSEG3EI32_V }, // 2452
  { PseudoVLOXSEG3EI32_V_M2_M1_MASK, VLOXSEG3EI32_V }, // 2453
  { PseudoVLOXSEG3EI32_V_M2_M2, VLOXSEG3EI32_V }, // 2454
  { PseudoVLOXSEG3EI32_V_M2_M2_MASK, VLOXSEG3EI32_V }, // 2455
  { PseudoVLOXSEG3EI32_V_M2_MF2, VLOXSEG3EI32_V }, // 2456
  { PseudoVLOXSEG3EI32_V_M2_MF2_MASK, VLOXSEG3EI32_V }, // 2457
  { PseudoVLOXSEG3EI32_V_M4_M1, VLOXSEG3EI32_V }, // 2458
  { PseudoVLOXSEG3EI32_V_M4_M1_MASK, VLOXSEG3EI32_V }, // 2459
  { PseudoVLOXSEG3EI32_V_M4_M2, VLOXSEG3EI32_V }, // 2460
  { PseudoVLOXSEG3EI32_V_M4_M2_MASK, VLOXSEG3EI32_V }, // 2461
  { PseudoVLOXSEG3EI32_V_M8_M2, VLOXSEG3EI32_V }, // 2462
  { PseudoVLOXSEG3EI32_V_M8_M2_MASK, VLOXSEG3EI32_V }, // 2463
  { PseudoVLOXSEG3EI32_V_MF2_M1, VLOXSEG3EI32_V }, // 2464
  { PseudoVLOXSEG3EI32_V_MF2_M1_MASK, VLOXSEG3EI32_V }, // 2465
  { PseudoVLOXSEG3EI32_V_MF2_MF2, VLOXSEG3EI32_V }, // 2466
  { PseudoVLOXSEG3EI32_V_MF2_MF2_MASK, VLOXSEG3EI32_V }, // 2467
  { PseudoVLOXSEG3EI32_V_MF2_MF4, VLOXSEG3EI32_V }, // 2468
  { PseudoVLOXSEG3EI32_V_MF2_MF4_MASK, VLOXSEG3EI32_V }, // 2469
  { PseudoVLOXSEG3EI32_V_MF2_MF8, VLOXSEG3EI32_V }, // 2470
  { PseudoVLOXSEG3EI32_V_MF2_MF8_MASK, VLOXSEG3EI32_V }, // 2471
  { PseudoVLOXSEG3EI64_V_M1_M1, VLOXSEG3EI64_V }, // 2472
  { PseudoVLOXSEG3EI64_V_M1_M1_MASK, VLOXSEG3EI64_V }, // 2473
  { PseudoVLOXSEG3EI64_V_M1_MF2, VLOXSEG3EI64_V }, // 2474
  { PseudoVLOXSEG3EI64_V_M1_MF2_MASK, VLOXSEG3EI64_V }, // 2475
  { PseudoVLOXSEG3EI64_V_M1_MF4, VLOXSEG3EI64_V }, // 2476
  { PseudoVLOXSEG3EI64_V_M1_MF4_MASK, VLOXSEG3EI64_V }, // 2477
  { PseudoVLOXSEG3EI64_V_M1_MF8, VLOXSEG3EI64_V }, // 2478
  { PseudoVLOXSEG3EI64_V_M1_MF8_MASK, VLOXSEG3EI64_V }, // 2479
  { PseudoVLOXSEG3EI64_V_M2_M1, VLOXSEG3EI64_V }, // 2480
  { PseudoVLOXSEG3EI64_V_M2_M1_MASK, VLOXSEG3EI64_V }, // 2481
  { PseudoVLOXSEG3EI64_V_M2_M2, VLOXSEG3EI64_V }, // 2482
  { PseudoVLOXSEG3EI64_V_M2_M2_MASK, VLOXSEG3EI64_V }, // 2483
  { PseudoVLOXSEG3EI64_V_M2_MF2, VLOXSEG3EI64_V }, // 2484
  { PseudoVLOXSEG3EI64_V_M2_MF2_MASK, VLOXSEG3EI64_V }, // 2485
  { PseudoVLOXSEG3EI64_V_M2_MF4, VLOXSEG3EI64_V }, // 2486
  { PseudoVLOXSEG3EI64_V_M2_MF4_MASK, VLOXSEG3EI64_V }, // 2487
  { PseudoVLOXSEG3EI64_V_M4_M1, VLOXSEG3EI64_V }, // 2488
  { PseudoVLOXSEG3EI64_V_M4_M1_MASK, VLOXSEG3EI64_V }, // 2489
  { PseudoVLOXSEG3EI64_V_M4_M2, VLOXSEG3EI64_V }, // 2490
  { PseudoVLOXSEG3EI64_V_M4_M2_MASK, VLOXSEG3EI64_V }, // 2491
  { PseudoVLOXSEG3EI64_V_M4_MF2, VLOXSEG3EI64_V }, // 2492
  { PseudoVLOXSEG3EI64_V_M4_MF2_MASK, VLOXSEG3EI64_V }, // 2493
  { PseudoVLOXSEG3EI64_V_M8_M1, VLOXSEG3EI64_V }, // 2494
  { PseudoVLOXSEG3EI64_V_M8_M1_MASK, VLOXSEG3EI64_V }, // 2495
  { PseudoVLOXSEG3EI64_V_M8_M2, VLOXSEG3EI64_V }, // 2496
  { PseudoVLOXSEG3EI64_V_M8_M2_MASK, VLOXSEG3EI64_V }, // 2497
  { PseudoVLOXSEG3EI8_V_M1_M1, VLOXSEG3EI8_V }, // 2498
  { PseudoVLOXSEG3EI8_V_M1_M1_MASK, VLOXSEG3EI8_V }, // 2499
  { PseudoVLOXSEG3EI8_V_M1_M2, VLOXSEG3EI8_V }, // 2500
  { PseudoVLOXSEG3EI8_V_M1_M2_MASK, VLOXSEG3EI8_V }, // 2501
  { PseudoVLOXSEG3EI8_V_M2_M2, VLOXSEG3EI8_V }, // 2502
  { PseudoVLOXSEG3EI8_V_M2_M2_MASK, VLOXSEG3EI8_V }, // 2503
  { PseudoVLOXSEG3EI8_V_MF2_M1, VLOXSEG3EI8_V }, // 2504
  { PseudoVLOXSEG3EI8_V_MF2_M1_MASK, VLOXSEG3EI8_V }, // 2505
  { PseudoVLOXSEG3EI8_V_MF2_M2, VLOXSEG3EI8_V }, // 2506
  { PseudoVLOXSEG3EI8_V_MF2_M2_MASK, VLOXSEG3EI8_V }, // 2507
  { PseudoVLOXSEG3EI8_V_MF2_MF2, VLOXSEG3EI8_V }, // 2508
  { PseudoVLOXSEG3EI8_V_MF2_MF2_MASK, VLOXSEG3EI8_V }, // 2509
  { PseudoVLOXSEG3EI8_V_MF4_M1, VLOXSEG3EI8_V }, // 2510
  { PseudoVLOXSEG3EI8_V_MF4_M1_MASK, VLOXSEG3EI8_V }, // 2511
  { PseudoVLOXSEG3EI8_V_MF4_M2, VLOXSEG3EI8_V }, // 2512
  { PseudoVLOXSEG3EI8_V_MF4_M2_MASK, VLOXSEG3EI8_V }, // 2513
  { PseudoVLOXSEG3EI8_V_MF4_MF2, VLOXSEG3EI8_V }, // 2514
  { PseudoVLOXSEG3EI8_V_MF4_MF2_MASK, VLOXSEG3EI8_V }, // 2515
  { PseudoVLOXSEG3EI8_V_MF4_MF4, VLOXSEG3EI8_V }, // 2516
  { PseudoVLOXSEG3EI8_V_MF4_MF4_MASK, VLOXSEG3EI8_V }, // 2517
  { PseudoVLOXSEG3EI8_V_MF8_M1, VLOXSEG3EI8_V }, // 2518
  { PseudoVLOXSEG3EI8_V_MF8_M1_MASK, VLOXSEG3EI8_V }, // 2519
  { PseudoVLOXSEG3EI8_V_MF8_MF2, VLOXSEG3EI8_V }, // 2520
  { PseudoVLOXSEG3EI8_V_MF8_MF2_MASK, VLOXSEG3EI8_V }, // 2521
  { PseudoVLOXSEG3EI8_V_MF8_MF4, VLOXSEG3EI8_V }, // 2522
  { PseudoVLOXSEG3EI8_V_MF8_MF4_MASK, VLOXSEG3EI8_V }, // 2523
  { PseudoVLOXSEG3EI8_V_MF8_MF8, VLOXSEG3EI8_V }, // 2524
  { PseudoVLOXSEG3EI8_V_MF8_MF8_MASK, VLOXSEG3EI8_V }, // 2525
  { PseudoVLOXSEG4EI16_V_M1_M1, VLOXSEG4EI16_V }, // 2526
  { PseudoVLOXSEG4EI16_V_M1_M1_MASK, VLOXSEG4EI16_V }, // 2527
  { PseudoVLOXSEG4EI16_V_M1_M2, VLOXSEG4EI16_V }, // 2528
  { PseudoVLOXSEG4EI16_V_M1_M2_MASK, VLOXSEG4EI16_V }, // 2529
  { PseudoVLOXSEG4EI16_V_M1_MF2, VLOXSEG4EI16_V }, // 2530
  { PseudoVLOXSEG4EI16_V_M1_MF2_MASK, VLOXSEG4EI16_V }, // 2531
  { PseudoVLOXSEG4EI16_V_M2_M1, VLOXSEG4EI16_V }, // 2532
  { PseudoVLOXSEG4EI16_V_M2_M1_MASK, VLOXSEG4EI16_V }, // 2533
  { PseudoVLOXSEG4EI16_V_M2_M2, VLOXSEG4EI16_V }, // 2534
  { PseudoVLOXSEG4EI16_V_M2_M2_MASK, VLOXSEG4EI16_V }, // 2535
  { PseudoVLOXSEG4EI16_V_M4_M2, VLOXSEG4EI16_V }, // 2536
  { PseudoVLOXSEG4EI16_V_M4_M2_MASK, VLOXSEG4EI16_V }, // 2537
  { PseudoVLOXSEG4EI16_V_MF2_M1, VLOXSEG4EI16_V }, // 2538
  { PseudoVLOXSEG4EI16_V_MF2_M1_MASK, VLOXSEG4EI16_V }, // 2539
  { PseudoVLOXSEG4EI16_V_MF2_M2, VLOXSEG4EI16_V }, // 2540
  { PseudoVLOXSEG4EI16_V_MF2_M2_MASK, VLOXSEG4EI16_V }, // 2541
  { PseudoVLOXSEG4EI16_V_MF2_MF2, VLOXSEG4EI16_V }, // 2542
  { PseudoVLOXSEG4EI16_V_MF2_MF2_MASK, VLOXSEG4EI16_V }, // 2543
  { PseudoVLOXSEG4EI16_V_MF2_MF4, VLOXSEG4EI16_V }, // 2544
  { PseudoVLOXSEG4EI16_V_MF2_MF4_MASK, VLOXSEG4EI16_V }, // 2545
  { PseudoVLOXSEG4EI16_V_MF4_M1, VLOXSEG4EI16_V }, // 2546
  { PseudoVLOXSEG4EI16_V_MF4_M1_MASK, VLOXSEG4EI16_V }, // 2547
  { PseudoVLOXSEG4EI16_V_MF4_MF2, VLOXSEG4EI16_V }, // 2548
  { PseudoVLOXSEG4EI16_V_MF4_MF2_MASK, VLOXSEG4EI16_V }, // 2549
  { PseudoVLOXSEG4EI16_V_MF4_MF4, VLOXSEG4EI16_V }, // 2550
  { PseudoVLOXSEG4EI16_V_MF4_MF4_MASK, VLOXSEG4EI16_V }, // 2551
  { PseudoVLOXSEG4EI16_V_MF4_MF8, VLOXSEG4EI16_V }, // 2552
  { PseudoVLOXSEG4EI16_V_MF4_MF8_MASK, VLOXSEG4EI16_V }, // 2553
  { PseudoVLOXSEG4EI32_V_M1_M1, VLOXSEG4EI32_V }, // 2554
  { PseudoVLOXSEG4EI32_V_M1_M1_MASK, VLOXSEG4EI32_V }, // 2555
  { PseudoVLOXSEG4EI32_V_M1_M2, VLOXSEG4EI32_V }, // 2556
  { PseudoVLOXSEG4EI32_V_M1_M2_MASK, VLOXSEG4EI32_V }, // 2557
  { PseudoVLOXSEG4EI32_V_M1_MF2, VLOXSEG4EI32_V }, // 2558
  { PseudoVLOXSEG4EI32_V_M1_MF2_MASK, VLOXSEG4EI32_V }, // 2559
  { PseudoVLOXSEG4EI32_V_M1_MF4, VLOXSEG4EI32_V }, // 2560
  { PseudoVLOXSEG4EI32_V_M1_MF4_MASK, VLOXSEG4EI32_V }, // 2561
  { PseudoVLOXSEG4EI32_V_M2_M1, VLOXSEG4EI32_V }, // 2562
  { PseudoVLOXSEG4EI32_V_M2_M1_MASK, VLOXSEG4EI32_V }, // 2563
  { PseudoVLOXSEG4EI32_V_M2_M2, VLOXSEG4EI32_V }, // 2564
  { PseudoVLOXSEG4EI32_V_M2_M2_MASK, VLOXSEG4EI32_V }, // 2565
  { PseudoVLOXSEG4EI32_V_M2_MF2, VLOXSEG4EI32_V }, // 2566
  { PseudoVLOXSEG4EI32_V_M2_MF2_MASK, VLOXSEG4EI32_V }, // 2567
  { PseudoVLOXSEG4EI32_V_M4_M1, VLOXSEG4EI32_V }, // 2568
  { PseudoVLOXSEG4EI32_V_M4_M1_MASK, VLOXSEG4EI32_V }, // 2569
  { PseudoVLOXSEG4EI32_V_M4_M2, VLOXSEG4EI32_V }, // 2570
  { PseudoVLOXSEG4EI32_V_M4_M2_MASK, VLOXSEG4EI32_V }, // 2571
  { PseudoVLOXSEG4EI32_V_M8_M2, VLOXSEG4EI32_V }, // 2572
  { PseudoVLOXSEG4EI32_V_M8_M2_MASK, VLOXSEG4EI32_V }, // 2573
  { PseudoVLOXSEG4EI32_V_MF2_M1, VLOXSEG4EI32_V }, // 2574
  { PseudoVLOXSEG4EI32_V_MF2_M1_MASK, VLOXSEG4EI32_V }, // 2575
  { PseudoVLOXSEG4EI32_V_MF2_MF2, VLOXSEG4EI32_V }, // 2576
  { PseudoVLOXSEG4EI32_V_MF2_MF2_MASK, VLOXSEG4EI32_V }, // 2577
  { PseudoVLOXSEG4EI32_V_MF2_MF4, VLOXSEG4EI32_V }, // 2578
  { PseudoVLOXSEG4EI32_V_MF2_MF4_MASK, VLOXSEG4EI32_V }, // 2579
  { PseudoVLOXSEG4EI32_V_MF2_MF8, VLOXSEG4EI32_V }, // 2580
  { PseudoVLOXSEG4EI32_V_MF2_MF8_MASK, VLOXSEG4EI32_V }, // 2581
  { PseudoVLOXSEG4EI64_V_M1_M1, VLOXSEG4EI64_V }, // 2582
  { PseudoVLOXSEG4EI64_V_M1_M1_MASK, VLOXSEG4EI64_V }, // 2583
  { PseudoVLOXSEG4EI64_V_M1_MF2, VLOXSEG4EI64_V }, // 2584
  { PseudoVLOXSEG4EI64_V_M1_MF2_MASK, VLOXSEG4EI64_V }, // 2585
  { PseudoVLOXSEG4EI64_V_M1_MF4, VLOXSEG4EI64_V }, // 2586
  { PseudoVLOXSEG4EI64_V_M1_MF4_MASK, VLOXSEG4EI64_V }, // 2587
  { PseudoVLOXSEG4EI64_V_M1_MF8, VLOXSEG4EI64_V }, // 2588
  { PseudoVLOXSEG4EI64_V_M1_MF8_MASK, VLOXSEG4EI64_V }, // 2589
  { PseudoVLOXSEG4EI64_V_M2_M1, VLOXSEG4EI64_V }, // 2590
  { PseudoVLOXSEG4EI64_V_M2_M1_MASK, VLOXSEG4EI64_V }, // 2591
  { PseudoVLOXSEG4EI64_V_M2_M2, VLOXSEG4EI64_V }, // 2592
  { PseudoVLOXSEG4EI64_V_M2_M2_MASK, VLOXSEG4EI64_V }, // 2593
  { PseudoVLOXSEG4EI64_V_M2_MF2, VLOXSEG4EI64_V }, // 2594
  { PseudoVLOXSEG4EI64_V_M2_MF2_MASK, VLOXSEG4EI64_V }, // 2595
  { PseudoVLOXSEG4EI64_V_M2_MF4, VLOXSEG4EI64_V }, // 2596
  { PseudoVLOXSEG4EI64_V_M2_MF4_MASK, VLOXSEG4EI64_V }, // 2597
  { PseudoVLOXSEG4EI64_V_M4_M1, VLOXSEG4EI64_V }, // 2598
  { PseudoVLOXSEG4EI64_V_M4_M1_MASK, VLOXSEG4EI64_V }, // 2599
  { PseudoVLOXSEG4EI64_V_M4_M2, VLOXSEG4EI64_V }, // 2600
  { PseudoVLOXSEG4EI64_V_M4_M2_MASK, VLOXSEG4EI64_V }, // 2601
  { PseudoVLOXSEG4EI64_V_M4_MF2, VLOXSEG4EI64_V }, // 2602
  { PseudoVLOXSEG4EI64_V_M4_MF2_MASK, VLOXSEG4EI64_V }, // 2603
  { PseudoVLOXSEG4EI64_V_M8_M1, VLOXSEG4EI64_V }, // 2604
  { PseudoVLOXSEG4EI64_V_M8_M1_MASK, VLOXSEG4EI64_V }, // 2605
  { PseudoVLOXSEG4EI64_V_M8_M2, VLOXSEG4EI64_V }, // 2606
  { PseudoVLOXSEG4EI64_V_M8_M2_MASK, VLOXSEG4EI64_V }, // 2607
  { PseudoVLOXSEG4EI8_V_M1_M1, VLOXSEG4EI8_V }, // 2608
  { PseudoVLOXSEG4EI8_V_M1_M1_MASK, VLOXSEG4EI8_V }, // 2609
  { PseudoVLOXSEG4EI8_V_M1_M2, VLOXSEG4EI8_V }, // 2610
  { PseudoVLOXSEG4EI8_V_M1_M2_MASK, VLOXSEG4EI8_V }, // 2611
  { PseudoVLOXSEG4EI8_V_M2_M2, VLOXSEG4EI8_V }, // 2612
  { PseudoVLOXSEG4EI8_V_M2_M2_MASK, VLOXSEG4EI8_V }, // 2613
  { PseudoVLOXSEG4EI8_V_MF2_M1, VLOXSEG4EI8_V }, // 2614
  { PseudoVLOXSEG4EI8_V_MF2_M1_MASK, VLOXSEG4EI8_V }, // 2615
  { PseudoVLOXSEG4EI8_V_MF2_M2, VLOXSEG4EI8_V }, // 2616
  { PseudoVLOXSEG4EI8_V_MF2_M2_MASK, VLOXSEG4EI8_V }, // 2617
  { PseudoVLOXSEG4EI8_V_MF2_MF2, VLOXSEG4EI8_V }, // 2618
  { PseudoVLOXSEG4EI8_V_MF2_MF2_MASK, VLOXSEG4EI8_V }, // 2619
  { PseudoVLOXSEG4EI8_V_MF4_M1, VLOXSEG4EI8_V }, // 2620
  { PseudoVLOXSEG4EI8_V_MF4_M1_MASK, VLOXSEG4EI8_V }, // 2621
  { PseudoVLOXSEG4EI8_V_MF4_M2, VLOXSEG4EI8_V }, // 2622
  { PseudoVLOXSEG4EI8_V_MF4_M2_MASK, VLOXSEG4EI8_V }, // 2623
  { PseudoVLOXSEG4EI8_V_MF4_MF2, VLOXSEG4EI8_V }, // 2624
  { PseudoVLOXSEG4EI8_V_MF4_MF2_MASK, VLOXSEG4EI8_V }, // 2625
  { PseudoVLOXSEG4EI8_V_MF4_MF4, VLOXSEG4EI8_V }, // 2626
  { PseudoVLOXSEG4EI8_V_MF4_MF4_MASK, VLOXSEG4EI8_V }, // 2627
  { PseudoVLOXSEG4EI8_V_MF8_M1, VLOXSEG4EI8_V }, // 2628
  { PseudoVLOXSEG4EI8_V_MF8_M1_MASK, VLOXSEG4EI8_V }, // 2629
  { PseudoVLOXSEG4EI8_V_MF8_MF2, VLOXSEG4EI8_V }, // 2630
  { PseudoVLOXSEG4EI8_V_MF8_MF2_MASK, VLOXSEG4EI8_V }, // 2631
  { PseudoVLOXSEG4EI8_V_MF8_MF4, VLOXSEG4EI8_V }, // 2632
  { PseudoVLOXSEG4EI8_V_MF8_MF4_MASK, VLOXSEG4EI8_V }, // 2633
  { PseudoVLOXSEG4EI8_V_MF8_MF8, VLOXSEG4EI8_V }, // 2634
  { PseudoVLOXSEG4EI8_V_MF8_MF8_MASK, VLOXSEG4EI8_V }, // 2635
  { PseudoVLOXSEG5EI16_V_M1_M1, VLOXSEG5EI16_V }, // 2636
  { PseudoVLOXSEG5EI16_V_M1_M1_MASK, VLOXSEG5EI16_V }, // 2637
  { PseudoVLOXSEG5EI16_V_M1_MF2, VLOXSEG5EI16_V }, // 2638
  { PseudoVLOXSEG5EI16_V_M1_MF2_MASK, VLOXSEG5EI16_V }, // 2639
  { PseudoVLOXSEG5EI16_V_M2_M1, VLOXSEG5EI16_V }, // 2640
  { PseudoVLOXSEG5EI16_V_M2_M1_MASK, VLOXSEG5EI16_V }, // 2641
  { PseudoVLOXSEG5EI16_V_MF2_M1, VLOXSEG5EI16_V }, // 2642
  { PseudoVLOXSEG5EI16_V_MF2_M1_MASK, VLOXSEG5EI16_V }, // 2643
  { PseudoVLOXSEG5EI16_V_MF2_MF2, VLOXSEG5EI16_V }, // 2644
  { PseudoVLOXSEG5EI16_V_MF2_MF2_MASK, VLOXSEG5EI16_V }, // 2645
  { PseudoVLOXSEG5EI16_V_MF2_MF4, VLOXSEG5EI16_V }, // 2646
  { PseudoVLOXSEG5EI16_V_MF2_MF4_MASK, VLOXSEG5EI16_V }, // 2647
  { PseudoVLOXSEG5EI16_V_MF4_M1, VLOXSEG5EI16_V }, // 2648
  { PseudoVLOXSEG5EI16_V_MF4_M1_MASK, VLOXSEG5EI16_V }, // 2649
  { PseudoVLOXSEG5EI16_V_MF4_MF2, VLOXSEG5EI16_V }, // 2650
  { PseudoVLOXSEG5EI16_V_MF4_MF2_MASK, VLOXSEG5EI16_V }, // 2651
  { PseudoVLOXSEG5EI16_V_MF4_MF4, VLOXSEG5EI16_V }, // 2652
  { PseudoVLOXSEG5EI16_V_MF4_MF4_MASK, VLOXSEG5EI16_V }, // 2653
  { PseudoVLOXSEG5EI16_V_MF4_MF8, VLOXSEG5EI16_V }, // 2654
  { PseudoVLOXSEG5EI16_V_MF4_MF8_MASK, VLOXSEG5EI16_V }, // 2655
  { PseudoVLOXSEG5EI32_V_M1_M1, VLOXSEG5EI32_V }, // 2656
  { PseudoVLOXSEG5EI32_V_M1_M1_MASK, VLOXSEG5EI32_V }, // 2657
  { PseudoVLOXSEG5EI32_V_M1_MF2, VLOXSEG5EI32_V }, // 2658
  { PseudoVLOXSEG5EI32_V_M1_MF2_MASK, VLOXSEG5EI32_V }, // 2659
  { PseudoVLOXSEG5EI32_V_M1_MF4, VLOXSEG5EI32_V }, // 2660
  { PseudoVLOXSEG5EI32_V_M1_MF4_MASK, VLOXSEG5EI32_V }, // 2661
  { PseudoVLOXSEG5EI32_V_M2_M1, VLOXSEG5EI32_V }, // 2662
  { PseudoVLOXSEG5EI32_V_M2_M1_MASK, VLOXSEG5EI32_V }, // 2663
  { PseudoVLOXSEG5EI32_V_M2_MF2, VLOXSEG5EI32_V }, // 2664
  { PseudoVLOXSEG5EI32_V_M2_MF2_MASK, VLOXSEG5EI32_V }, // 2665
  { PseudoVLOXSEG5EI32_V_M4_M1, VLOXSEG5EI32_V }, // 2666
  { PseudoVLOXSEG5EI32_V_M4_M1_MASK, VLOXSEG5EI32_V }, // 2667
  { PseudoVLOXSEG5EI32_V_MF2_M1, VLOXSEG5EI32_V }, // 2668
  { PseudoVLOXSEG5EI32_V_MF2_M1_MASK, VLOXSEG5EI32_V }, // 2669
  { PseudoVLOXSEG5EI32_V_MF2_MF2, VLOXSEG5EI32_V }, // 2670
  { PseudoVLOXSEG5EI32_V_MF2_MF2_MASK, VLOXSEG5EI32_V }, // 2671
  { PseudoVLOXSEG5EI32_V_MF2_MF4, VLOXSEG5EI32_V }, // 2672
  { PseudoVLOXSEG5EI32_V_MF2_MF4_MASK, VLOXSEG5EI32_V }, // 2673
  { PseudoVLOXSEG5EI32_V_MF2_MF8, VLOXSEG5EI32_V }, // 2674
  { PseudoVLOXSEG5EI32_V_MF2_MF8_MASK, VLOXSEG5EI32_V }, // 2675
  { PseudoVLOXSEG5EI64_V_M1_M1, VLOXSEG5EI64_V }, // 2676
  { PseudoVLOXSEG5EI64_V_M1_M1_MASK, VLOXSEG5EI64_V }, // 2677
  { PseudoVLOXSEG5EI64_V_M1_MF2, VLOXSEG5EI64_V }, // 2678
  { PseudoVLOXSEG5EI64_V_M1_MF2_MASK, VLOXSEG5EI64_V }, // 2679
  { PseudoVLOXSEG5EI64_V_M1_MF4, VLOXSEG5EI64_V }, // 2680
  { PseudoVLOXSEG5EI64_V_M1_MF4_MASK, VLOXSEG5EI64_V }, // 2681
  { PseudoVLOXSEG5EI64_V_M1_MF8, VLOXSEG5EI64_V }, // 2682
  { PseudoVLOXSEG5EI64_V_M1_MF8_MASK, VLOXSEG5EI64_V }, // 2683
  { PseudoVLOXSEG5EI64_V_M2_M1, VLOXSEG5EI64_V }, // 2684
  { PseudoVLOXSEG5EI64_V_M2_M1_MASK, VLOXSEG5EI64_V }, // 2685
  { PseudoVLOXSEG5EI64_V_M2_MF2, VLOXSEG5EI64_V }, // 2686
  { PseudoVLOXSEG5EI64_V_M2_MF2_MASK, VLOXSEG5EI64_V }, // 2687
  { PseudoVLOXSEG5EI64_V_M2_MF4, VLOXSEG5EI64_V }, // 2688
  { PseudoVLOXSEG5EI64_V_M2_MF4_MASK, VLOXSEG5EI64_V }, // 2689
  { PseudoVLOXSEG5EI64_V_M4_M1, VLOXSEG5EI64_V }, // 2690
  { PseudoVLOXSEG5EI64_V_M4_M1_MASK, VLOXSEG5EI64_V }, // 2691
  { PseudoVLOXSEG5EI64_V_M4_MF2, VLOXSEG5EI64_V }, // 2692
  { PseudoVLOXSEG5EI64_V_M4_MF2_MASK, VLOXSEG5EI64_V }, // 2693
  { PseudoVLOXSEG5EI64_V_M8_M1, VLOXSEG5EI64_V }, // 2694
  { PseudoVLOXSEG5EI64_V_M8_M1_MASK, VLOXSEG5EI64_V }, // 2695
  { PseudoVLOXSEG5EI8_V_M1_M1, VLOXSEG5EI8_V }, // 2696
  { PseudoVLOXSEG5EI8_V_M1_M1_MASK, VLOXSEG5EI8_V }, // 2697
  { PseudoVLOXSEG5EI8_V_MF2_M1, VLOXSEG5EI8_V }, // 2698
  { PseudoVLOXSEG5EI8_V_MF2_M1_MASK, VLOXSEG5EI8_V }, // 2699
  { PseudoVLOXSEG5EI8_V_MF2_MF2, VLOXSEG5EI8_V }, // 2700
  { PseudoVLOXSEG5EI8_V_MF2_MF2_MASK, VLOXSEG5EI8_V }, // 2701
  { PseudoVLOXSEG5EI8_V_MF4_M1, VLOXSEG5EI8_V }, // 2702
  { PseudoVLOXSEG5EI8_V_MF4_M1_MASK, VLOXSEG5EI8_V }, // 2703
  { PseudoVLOXSEG5EI8_V_MF4_MF2, VLOXSEG5EI8_V }, // 2704
  { PseudoVLOXSEG5EI8_V_MF4_MF2_MASK, VLOXSEG5EI8_V }, // 2705
  { PseudoVLOXSEG5EI8_V_MF4_MF4, VLOXSEG5EI8_V }, // 2706
  { PseudoVLOXSEG5EI8_V_MF4_MF4_MASK, VLOXSEG5EI8_V }, // 2707
  { PseudoVLOXSEG5EI8_V_MF8_M1, VLOXSEG5EI8_V }, // 2708
  { PseudoVLOXSEG5EI8_V_MF8_M1_MASK, VLOXSEG5EI8_V }, // 2709
  { PseudoVLOXSEG5EI8_V_MF8_MF2, VLOXSEG5EI8_V }, // 2710
  { PseudoVLOXSEG5EI8_V_MF8_MF2_MASK, VLOXSEG5EI8_V }, // 2711
  { PseudoVLOXSEG5EI8_V_MF8_MF4, VLOXSEG5EI8_V }, // 2712
  { PseudoVLOXSEG5EI8_V_MF8_MF4_MASK, VLOXSEG5EI8_V }, // 2713
  { PseudoVLOXSEG5EI8_V_MF8_MF8, VLOXSEG5EI8_V }, // 2714
  { PseudoVLOXSEG5EI8_V_MF8_MF8_MASK, VLOXSEG5EI8_V }, // 2715
  { PseudoVLOXSEG6EI16_V_M1_M1, VLOXSEG6EI16_V }, // 2716
  { PseudoVLOXSEG6EI16_V_M1_M1_MASK, VLOXSEG6EI16_V }, // 2717
  { PseudoVLOXSEG6EI16_V_M1_MF2, VLOXSEG6EI16_V }, // 2718
  { PseudoVLOXSEG6EI16_V_M1_MF2_MASK, VLOXSEG6EI16_V }, // 2719
  { PseudoVLOXSEG6EI16_V_M2_M1, VLOXSEG6EI16_V }, // 2720
  { PseudoVLOXSEG6EI16_V_M2_M1_MASK, VLOXSEG6EI16_V }, // 2721
  { PseudoVLOXSEG6EI16_V_MF2_M1, VLOXSEG6EI16_V }, // 2722
  { PseudoVLOXSEG6EI16_V_MF2_M1_MASK, VLOXSEG6EI16_V }, // 2723
  { PseudoVLOXSEG6EI16_V_MF2_MF2, VLOXSEG6EI16_V }, // 2724
  { PseudoVLOXSEG6EI16_V_MF2_MF2_MASK, VLOXSEG6EI16_V }, // 2725
  { PseudoVLOXSEG6EI16_V_MF2_MF4, VLOXSEG6EI16_V }, // 2726
  { PseudoVLOXSEG6EI16_V_MF2_MF4_MASK, VLOXSEG6EI16_V }, // 2727
  { PseudoVLOXSEG6EI16_V_MF4_M1, VLOXSEG6EI16_V }, // 2728
  { PseudoVLOXSEG6EI16_V_MF4_M1_MASK, VLOXSEG6EI16_V }, // 2729
  { PseudoVLOXSEG6EI16_V_MF4_MF2, VLOXSEG6EI16_V }, // 2730
  { PseudoVLOXSEG6EI16_V_MF4_MF2_MASK, VLOXSEG6EI16_V }, // 2731
  { PseudoVLOXSEG6EI16_V_MF4_MF4, VLOXSEG6EI16_V }, // 2732
  { PseudoVLOXSEG6EI16_V_MF4_MF4_MASK, VLOXSEG6EI16_V }, // 2733
  { PseudoVLOXSEG6EI16_V_MF4_MF8, VLOXSEG6EI16_V }, // 2734
  { PseudoVLOXSEG6EI16_V_MF4_MF8_MASK, VLOXSEG6EI16_V }, // 2735
  { PseudoVLOXSEG6EI32_V_M1_M1, VLOXSEG6EI32_V }, // 2736
  { PseudoVLOXSEG6EI32_V_M1_M1_MASK, VLOXSEG6EI32_V }, // 2737
  { PseudoVLOXSEG6EI32_V_M1_MF2, VLOXSEG6EI32_V }, // 2738
  { PseudoVLOXSEG6EI32_V_M1_MF2_MASK, VLOXSEG6EI32_V }, // 2739
  { PseudoVLOXSEG6EI32_V_M1_MF4, VLOXSEG6EI32_V }, // 2740
  { PseudoVLOXSEG6EI32_V_M1_MF4_MASK, VLOXSEG6EI32_V }, // 2741
  { PseudoVLOXSEG6EI32_V_M2_M1, VLOXSEG6EI32_V }, // 2742
  { PseudoVLOXSEG6EI32_V_M2_M1_MASK, VLOXSEG6EI32_V }, // 2743
  { PseudoVLOXSEG6EI32_V_M2_MF2, VLOXSEG6EI32_V }, // 2744
  { PseudoVLOXSEG6EI32_V_M2_MF2_MASK, VLOXSEG6EI32_V }, // 2745
  { PseudoVLOXSEG6EI32_V_M4_M1, VLOXSEG6EI32_V }, // 2746
  { PseudoVLOXSEG6EI32_V_M4_M1_MASK, VLOXSEG6EI32_V }, // 2747
  { PseudoVLOXSEG6EI32_V_MF2_M1, VLOXSEG6EI32_V }, // 2748
  { PseudoVLOXSEG6EI32_V_MF2_M1_MASK, VLOXSEG6EI32_V }, // 2749
  { PseudoVLOXSEG6EI32_V_MF2_MF2, VLOXSEG6EI32_V }, // 2750
  { PseudoVLOXSEG6EI32_V_MF2_MF2_MASK, VLOXSEG6EI32_V }, // 2751
  { PseudoVLOXSEG6EI32_V_MF2_MF4, VLOXSEG6EI32_V }, // 2752
  { PseudoVLOXSEG6EI32_V_MF2_MF4_MASK, VLOXSEG6EI32_V }, // 2753
  { PseudoVLOXSEG6EI32_V_MF2_MF8, VLOXSEG6EI32_V }, // 2754
  { PseudoVLOXSEG6EI32_V_MF2_MF8_MASK, VLOXSEG6EI32_V }, // 2755
  { PseudoVLOXSEG6EI64_V_M1_M1, VLOXSEG6EI64_V }, // 2756
  { PseudoVLOXSEG6EI64_V_M1_M1_MASK, VLOXSEG6EI64_V }, // 2757
  { PseudoVLOXSEG6EI64_V_M1_MF2, VLOXSEG6EI64_V }, // 2758
  { PseudoVLOXSEG6EI64_V_M1_MF2_MASK, VLOXSEG6EI64_V }, // 2759
  { PseudoVLOXSEG6EI64_V_M1_MF4, VLOXSEG6EI64_V }, // 2760
  { PseudoVLOXSEG6EI64_V_M1_MF4_MASK, VLOXSEG6EI64_V }, // 2761
  { PseudoVLOXSEG6EI64_V_M1_MF8, VLOXSEG6EI64_V }, // 2762
  { PseudoVLOXSEG6EI64_V_M1_MF8_MASK, VLOXSEG6EI64_V }, // 2763
  { PseudoVLOXSEG6EI64_V_M2_M1, VLOXSEG6EI64_V }, // 2764
  { PseudoVLOXSEG6EI64_V_M2_M1_MASK, VLOXSEG6EI64_V }, // 2765
  { PseudoVLOXSEG6EI64_V_M2_MF2, VLOXSEG6EI64_V }, // 2766
  { PseudoVLOXSEG6EI64_V_M2_MF2_MASK, VLOXSEG6EI64_V }, // 2767
  { PseudoVLOXSEG6EI64_V_M2_MF4, VLOXSEG6EI64_V }, // 2768
  { PseudoVLOXSEG6EI64_V_M2_MF4_MASK, VLOXSEG6EI64_V }, // 2769
  { PseudoVLOXSEG6EI64_V_M4_M1, VLOXSEG6EI64_V }, // 2770
  { PseudoVLOXSEG6EI64_V_M4_M1_MASK, VLOXSEG6EI64_V }, // 2771
  { PseudoVLOXSEG6EI64_V_M4_MF2, VLOXSEG6EI64_V }, // 2772
  { PseudoVLOXSEG6EI64_V_M4_MF2_MASK, VLOXSEG6EI64_V }, // 2773
  { PseudoVLOXSEG6EI64_V_M8_M1, VLOXSEG6EI64_V }, // 2774
  { PseudoVLOXSEG6EI64_V_M8_M1_MASK, VLOXSEG6EI64_V }, // 2775
  { PseudoVLOXSEG6EI8_V_M1_M1, VLOXSEG6EI8_V }, // 2776
  { PseudoVLOXSEG6EI8_V_M1_M1_MASK, VLOXSEG6EI8_V }, // 2777
  { PseudoVLOXSEG6EI8_V_MF2_M1, VLOXSEG6EI8_V }, // 2778
  { PseudoVLOXSEG6EI8_V_MF2_M1_MASK, VLOXSEG6EI8_V }, // 2779
  { PseudoVLOXSEG6EI8_V_MF2_MF2, VLOXSEG6EI8_V }, // 2780
  { PseudoVLOXSEG6EI8_V_MF2_MF2_MASK, VLOXSEG6EI8_V }, // 2781
  { PseudoVLOXSEG6EI8_V_MF4_M1, VLOXSEG6EI8_V }, // 2782
  { PseudoVLOXSEG6EI8_V_MF4_M1_MASK, VLOXSEG6EI8_V }, // 2783
  { PseudoVLOXSEG6EI8_V_MF4_MF2, VLOXSEG6EI8_V }, // 2784
  { PseudoVLOXSEG6EI8_V_MF4_MF2_MASK, VLOXSEG6EI8_V }, // 2785
  { PseudoVLOXSEG6EI8_V_MF4_MF4, VLOXSEG6EI8_V }, // 2786
  { PseudoVLOXSEG6EI8_V_MF4_MF4_MASK, VLOXSEG6EI8_V }, // 2787
  { PseudoVLOXSEG6EI8_V_MF8_M1, VLOXSEG6EI8_V }, // 2788
  { PseudoVLOXSEG6EI8_V_MF8_M1_MASK, VLOXSEG6EI8_V }, // 2789
  { PseudoVLOXSEG6EI8_V_MF8_MF2, VLOXSEG6EI8_V }, // 2790
  { PseudoVLOXSEG6EI8_V_MF8_MF2_MASK, VLOXSEG6EI8_V }, // 2791
  { PseudoVLOXSEG6EI8_V_MF8_MF4, VLOXSEG6EI8_V }, // 2792
  { PseudoVLOXSEG6EI8_V_MF8_MF4_MASK, VLOXSEG6EI8_V }, // 2793
  { PseudoVLOXSEG6EI8_V_MF8_MF8, VLOXSEG6EI8_V }, // 2794
  { PseudoVLOXSEG6EI8_V_MF8_MF8_MASK, VLOXSEG6EI8_V }, // 2795
  { PseudoVLOXSEG7EI16_V_M1_M1, VLOXSEG7EI16_V }, // 2796
  { PseudoVLOXSEG7EI16_V_M1_M1_MASK, VLOXSEG7EI16_V }, // 2797
  { PseudoVLOXSEG7EI16_V_M1_MF2, VLOXSEG7EI16_V }, // 2798
  { PseudoVLOXSEG7EI16_V_M1_MF2_MASK, VLOXSEG7EI16_V }, // 2799
  { PseudoVLOXSEG7EI16_V_M2_M1, VLOXSEG7EI16_V }, // 2800
  { PseudoVLOXSEG7EI16_V_M2_M1_MASK, VLOXSEG7EI16_V }, // 2801
  { PseudoVLOXSEG7EI16_V_MF2_M1, VLOXSEG7EI16_V }, // 2802
  { PseudoVLOXSEG7EI16_V_MF2_M1_MASK, VLOXSEG7EI16_V }, // 2803
  { PseudoVLOXSEG7EI16_V_MF2_MF2, VLOXSEG7EI16_V }, // 2804
  { PseudoVLOXSEG7EI16_V_MF2_MF2_MASK, VLOXSEG7EI16_V }, // 2805
  { PseudoVLOXSEG7EI16_V_MF2_MF4, VLOXSEG7EI16_V }, // 2806
  { PseudoVLOXSEG7EI16_V_MF2_MF4_MASK, VLOXSEG7EI16_V }, // 2807
  { PseudoVLOXSEG7EI16_V_MF4_M1, VLOXSEG7EI16_V }, // 2808
  { PseudoVLOXSEG7EI16_V_MF4_M1_MASK, VLOXSEG7EI16_V }, // 2809
  { PseudoVLOXSEG7EI16_V_MF4_MF2, VLOXSEG7EI16_V }, // 2810
  { PseudoVLOXSEG7EI16_V_MF4_MF2_MASK, VLOXSEG7EI16_V }, // 2811
  { PseudoVLOXSEG7EI16_V_MF4_MF4, VLOXSEG7EI16_V }, // 2812
  { PseudoVLOXSEG7EI16_V_MF4_MF4_MASK, VLOXSEG7EI16_V }, // 2813
  { PseudoVLOXSEG7EI16_V_MF4_MF8, VLOXSEG7EI16_V }, // 2814
  { PseudoVLOXSEG7EI16_V_MF4_MF8_MASK, VLOXSEG7EI16_V }, // 2815
  { PseudoVLOXSEG7EI32_V_M1_M1, VLOXSEG7EI32_V }, // 2816
  { PseudoVLOXSEG7EI32_V_M1_M1_MASK, VLOXSEG7EI32_V }, // 2817
  { PseudoVLOXSEG7EI32_V_M1_MF2, VLOXSEG7EI32_V }, // 2818
  { PseudoVLOXSEG7EI32_V_M1_MF2_MASK, VLOXSEG7EI32_V }, // 2819
  { PseudoVLOXSEG7EI32_V_M1_MF4, VLOXSEG7EI32_V }, // 2820
  { PseudoVLOXSEG7EI32_V_M1_MF4_MASK, VLOXSEG7EI32_V }, // 2821
  { PseudoVLOXSEG7EI32_V_M2_M1, VLOXSEG7EI32_V }, // 2822
  { PseudoVLOXSEG7EI32_V_M2_M1_MASK, VLOXSEG7EI32_V }, // 2823
  { PseudoVLOXSEG7EI32_V_M2_MF2, VLOXSEG7EI32_V }, // 2824
  { PseudoVLOXSEG7EI32_V_M2_MF2_MASK, VLOXSEG7EI32_V }, // 2825
  { PseudoVLOXSEG7EI32_V_M4_M1, VLOXSEG7EI32_V }, // 2826
  { PseudoVLOXSEG7EI32_V_M4_M1_MASK, VLOXSEG7EI32_V }, // 2827
  { PseudoVLOXSEG7EI32_V_MF2_M1, VLOXSEG7EI32_V }, // 2828
  { PseudoVLOXSEG7EI32_V_MF2_M1_MASK, VLOXSEG7EI32_V }, // 2829
  { PseudoVLOXSEG7EI32_V_MF2_MF2, VLOXSEG7EI32_V }, // 2830
  { PseudoVLOXSEG7EI32_V_MF2_MF2_MASK, VLOXSEG7EI32_V }, // 2831
  { PseudoVLOXSEG7EI32_V_MF2_MF4, VLOXSEG7EI32_V }, // 2832
  { PseudoVLOXSEG7EI32_V_MF2_MF4_MASK, VLOXSEG7EI32_V }, // 2833
  { PseudoVLOXSEG7EI32_V_MF2_MF8, VLOXSEG7EI32_V }, // 2834
  { PseudoVLOXSEG7EI32_V_MF2_MF8_MASK, VLOXSEG7EI32_V }, // 2835
  { PseudoVLOXSEG7EI64_V_M1_M1, VLOXSEG7EI64_V }, // 2836
  { PseudoVLOXSEG7EI64_V_M1_M1_MASK, VLOXSEG7EI64_V }, // 2837
  { PseudoVLOXSEG7EI64_V_M1_MF2, VLOXSEG7EI64_V }, // 2838
  { PseudoVLOXSEG7EI64_V_M1_MF2_MASK, VLOXSEG7EI64_V }, // 2839
  { PseudoVLOXSEG7EI64_V_M1_MF4, VLOXSEG7EI64_V }, // 2840
  { PseudoVLOXSEG7EI64_V_M1_MF4_MASK, VLOXSEG7EI64_V }, // 2841
  { PseudoVLOXSEG7EI64_V_M1_MF8, VLOXSEG7EI64_V }, // 2842
  { PseudoVLOXSEG7EI64_V_M1_MF8_MASK, VLOXSEG7EI64_V }, // 2843
  { PseudoVLOXSEG7EI64_V_M2_M1, VLOXSEG7EI64_V }, // 2844
  { PseudoVLOXSEG7EI64_V_M2_M1_MASK, VLOXSEG7EI64_V }, // 2845
  { PseudoVLOXSEG7EI64_V_M2_MF2, VLOXSEG7EI64_V }, // 2846
  { PseudoVLOXSEG7EI64_V_M2_MF2_MASK, VLOXSEG7EI64_V }, // 2847
  { PseudoVLOXSEG7EI64_V_M2_MF4, VLOXSEG7EI64_V }, // 2848
  { PseudoVLOXSEG7EI64_V_M2_MF4_MASK, VLOXSEG7EI64_V }, // 2849
  { PseudoVLOXSEG7EI64_V_M4_M1, VLOXSEG7EI64_V }, // 2850
  { PseudoVLOXSEG7EI64_V_M4_M1_MASK, VLOXSEG7EI64_V }, // 2851
  { PseudoVLOXSEG7EI64_V_M4_MF2, VLOXSEG7EI64_V }, // 2852
  { PseudoVLOXSEG7EI64_V_M4_MF2_MASK, VLOXSEG7EI64_V }, // 2853
  { PseudoVLOXSEG7EI64_V_M8_M1, VLOXSEG7EI64_V }, // 2854
  { PseudoVLOXSEG7EI64_V_M8_M1_MASK, VLOXSEG7EI64_V }, // 2855
  { PseudoVLOXSEG7EI8_V_M1_M1, VLOXSEG7EI8_V }, // 2856
  { PseudoVLOXSEG7EI8_V_M1_M1_MASK, VLOXSEG7EI8_V }, // 2857
  { PseudoVLOXSEG7EI8_V_MF2_M1, VLOXSEG7EI8_V }, // 2858
  { PseudoVLOXSEG7EI8_V_MF2_M1_MASK, VLOXSEG7EI8_V }, // 2859
  { PseudoVLOXSEG7EI8_V_MF2_MF2, VLOXSEG7EI8_V }, // 2860
  { PseudoVLOXSEG7EI8_V_MF2_MF2_MASK, VLOXSEG7EI8_V }, // 2861
  { PseudoVLOXSEG7EI8_V_MF4_M1, VLOXSEG7EI8_V }, // 2862
  { PseudoVLOXSEG7EI8_V_MF4_M1_MASK, VLOXSEG7EI8_V }, // 2863
  { PseudoVLOXSEG7EI8_V_MF4_MF2, VLOXSEG7EI8_V }, // 2864
  { PseudoVLOXSEG7EI8_V_MF4_MF2_MASK, VLOXSEG7EI8_V }, // 2865
  { PseudoVLOXSEG7EI8_V_MF4_MF4, VLOXSEG7EI8_V }, // 2866
  { PseudoVLOXSEG7EI8_V_MF4_MF4_MASK, VLOXSEG7EI8_V }, // 2867
  { PseudoVLOXSEG7EI8_V_MF8_M1, VLOXSEG7EI8_V }, // 2868
  { PseudoVLOXSEG7EI8_V_MF8_M1_MASK, VLOXSEG7EI8_V }, // 2869
  { PseudoVLOXSEG7EI8_V_MF8_MF2, VLOXSEG7EI8_V }, // 2870
  { PseudoVLOXSEG7EI8_V_MF8_MF2_MASK, VLOXSEG7EI8_V }, // 2871
  { PseudoVLOXSEG7EI8_V_MF8_MF4, VLOXSEG7EI8_V }, // 2872
  { PseudoVLOXSEG7EI8_V_MF8_MF4_MASK, VLOXSEG7EI8_V }, // 2873
  { PseudoVLOXSEG7EI8_V_MF8_MF8, VLOXSEG7EI8_V }, // 2874
  { PseudoVLOXSEG7EI8_V_MF8_MF8_MASK, VLOXSEG7EI8_V }, // 2875
  { PseudoVLOXSEG8EI16_V_M1_M1, VLOXSEG8EI16_V }, // 2876
  { PseudoVLOXSEG8EI16_V_M1_M1_MASK, VLOXSEG8EI16_V }, // 2877
  { PseudoVLOXSEG8EI16_V_M1_MF2, VLOXSEG8EI16_V }, // 2878
  { PseudoVLOXSEG8EI16_V_M1_MF2_MASK, VLOXSEG8EI16_V }, // 2879
  { PseudoVLOXSEG8EI16_V_M2_M1, VLOXSEG8EI16_V }, // 2880
  { PseudoVLOXSEG8EI16_V_M2_M1_MASK, VLOXSEG8EI16_V }, // 2881
  { PseudoVLOXSEG8EI16_V_MF2_M1, VLOXSEG8EI16_V }, // 2882
  { PseudoVLOXSEG8EI16_V_MF2_M1_MASK, VLOXSEG8EI16_V }, // 2883
  { PseudoVLOXSEG8EI16_V_MF2_MF2, VLOXSEG8EI16_V }, // 2884
  { PseudoVLOXSEG8EI16_V_MF2_MF2_MASK, VLOXSEG8EI16_V }, // 2885
  { PseudoVLOXSEG8EI16_V_MF2_MF4, VLOXSEG8EI16_V }, // 2886
  { PseudoVLOXSEG8EI16_V_MF2_MF4_MASK, VLOXSEG8EI16_V }, // 2887
  { PseudoVLOXSEG8EI16_V_MF4_M1, VLOXSEG8EI16_V }, // 2888
  { PseudoVLOXSEG8EI16_V_MF4_M1_MASK, VLOXSEG8EI16_V }, // 2889
  { PseudoVLOXSEG8EI16_V_MF4_MF2, VLOXSEG8EI16_V }, // 2890
  { PseudoVLOXSEG8EI16_V_MF4_MF2_MASK, VLOXSEG8EI16_V }, // 2891
  { PseudoVLOXSEG8EI16_V_MF4_MF4, VLOXSEG8EI16_V }, // 2892
  { PseudoVLOXSEG8EI16_V_MF4_MF4_MASK, VLOXSEG8EI16_V }, // 2893
  { PseudoVLOXSEG8EI16_V_MF4_MF8, VLOXSEG8EI16_V }, // 2894
  { PseudoVLOXSEG8EI16_V_MF4_MF8_MASK, VLOXSEG8EI16_V }, // 2895
  { PseudoVLOXSEG8EI32_V_M1_M1, VLOXSEG8EI32_V }, // 2896
  { PseudoVLOXSEG8EI32_V_M1_M1_MASK, VLOXSEG8EI32_V }, // 2897
  { PseudoVLOXSEG8EI32_V_M1_MF2, VLOXSEG8EI32_V }, // 2898
  { PseudoVLOXSEG8EI32_V_M1_MF2_MASK, VLOXSEG8EI32_V }, // 2899
  { PseudoVLOXSEG8EI32_V_M1_MF4, VLOXSEG8EI32_V }, // 2900
  { PseudoVLOXSEG8EI32_V_M1_MF4_MASK, VLOXSEG8EI32_V }, // 2901
  { PseudoVLOXSEG8EI32_V_M2_M1, VLOXSEG8EI32_V }, // 2902
  { PseudoVLOXSEG8EI32_V_M2_M1_MASK, VLOXSEG8EI32_V }, // 2903
  { PseudoVLOXSEG8EI32_V_M2_MF2, VLOXSEG8EI32_V }, // 2904
  { PseudoVLOXSEG8EI32_V_M2_MF2_MASK, VLOXSEG8EI32_V }, // 2905
  { PseudoVLOXSEG8EI32_V_M4_M1, VLOXSEG8EI32_V }, // 2906
  { PseudoVLOXSEG8EI32_V_M4_M1_MASK, VLOXSEG8EI32_V }, // 2907
  { PseudoVLOXSEG8EI32_V_MF2_M1, VLOXSEG8EI32_V }, // 2908
  { PseudoVLOXSEG8EI32_V_MF2_M1_MASK, VLOXSEG8EI32_V }, // 2909
  { PseudoVLOXSEG8EI32_V_MF2_MF2, VLOXSEG8EI32_V }, // 2910
  { PseudoVLOXSEG8EI32_V_MF2_MF2_MASK, VLOXSEG8EI32_V }, // 2911
  { PseudoVLOXSEG8EI32_V_MF2_MF4, VLOXSEG8EI32_V }, // 2912
  { PseudoVLOXSEG8EI32_V_MF2_MF4_MASK, VLOXSEG8EI32_V }, // 2913
  { PseudoVLOXSEG8EI32_V_MF2_MF8, VLOXSEG8EI32_V }, // 2914
  { PseudoVLOXSEG8EI32_V_MF2_MF8_MASK, VLOXSEG8EI32_V }, // 2915
  { PseudoVLOXSEG8EI64_V_M1_M1, VLOXSEG8EI64_V }, // 2916
  { PseudoVLOXSEG8EI64_V_M1_M1_MASK, VLOXSEG8EI64_V }, // 2917
  { PseudoVLOXSEG8EI64_V_M1_MF2, VLOXSEG8EI64_V }, // 2918
  { PseudoVLOXSEG8EI64_V_M1_MF2_MASK, VLOXSEG8EI64_V }, // 2919
  { PseudoVLOXSEG8EI64_V_M1_MF4, VLOXSEG8EI64_V }, // 2920
  { PseudoVLOXSEG8EI64_V_M1_MF4_MASK, VLOXSEG8EI64_V }, // 2921
  { PseudoVLOXSEG8EI64_V_M1_MF8, VLOXSEG8EI64_V }, // 2922
  { PseudoVLOXSEG8EI64_V_M1_MF8_MASK, VLOXSEG8EI64_V }, // 2923
  { PseudoVLOXSEG8EI64_V_M2_M1, VLOXSEG8EI64_V }, // 2924
  { PseudoVLOXSEG8EI64_V_M2_M1_MASK, VLOXSEG8EI64_V }, // 2925
  { PseudoVLOXSEG8EI64_V_M2_MF2, VLOXSEG8EI64_V }, // 2926
  { PseudoVLOXSEG8EI64_V_M2_MF2_MASK, VLOXSEG8EI64_V }, // 2927
  { PseudoVLOXSEG8EI64_V_M2_MF4, VLOXSEG8EI64_V }, // 2928
  { PseudoVLOXSEG8EI64_V_M2_MF4_MASK, VLOXSEG8EI64_V }, // 2929
  { PseudoVLOXSEG8EI64_V_M4_M1, VLOXSEG8EI64_V }, // 2930
  { PseudoVLOXSEG8EI64_V_M4_M1_MASK, VLOXSEG8EI64_V }, // 2931
  { PseudoVLOXSEG8EI64_V_M4_MF2, VLOXSEG8EI64_V }, // 2932
  { PseudoVLOXSEG8EI64_V_M4_MF2_MASK, VLOXSEG8EI64_V }, // 2933
  { PseudoVLOXSEG8EI64_V_M8_M1, VLOXSEG8EI64_V }, // 2934
  { PseudoVLOXSEG8EI64_V_M8_M1_MASK, VLOXSEG8EI64_V }, // 2935
  { PseudoVLOXSEG8EI8_V_M1_M1, VLOXSEG8EI8_V }, // 2936
  { PseudoVLOXSEG8EI8_V_M1_M1_MASK, VLOXSEG8EI8_V }, // 2937
  { PseudoVLOXSEG8EI8_V_MF2_M1, VLOXSEG8EI8_V }, // 2938
  { PseudoVLOXSEG8EI8_V_MF2_M1_MASK, VLOXSEG8EI8_V }, // 2939
  { PseudoVLOXSEG8EI8_V_MF2_MF2, VLOXSEG8EI8_V }, // 2940
  { PseudoVLOXSEG8EI8_V_MF2_MF2_MASK, VLOXSEG8EI8_V }, // 2941
  { PseudoVLOXSEG8EI8_V_MF4_M1, VLOXSEG8EI8_V }, // 2942
  { PseudoVLOXSEG8EI8_V_MF4_M1_MASK, VLOXSEG8EI8_V }, // 2943
  { PseudoVLOXSEG8EI8_V_MF4_MF2, VLOXSEG8EI8_V }, // 2944
  { PseudoVLOXSEG8EI8_V_MF4_MF2_MASK, VLOXSEG8EI8_V }, // 2945
  { PseudoVLOXSEG8EI8_V_MF4_MF4, VLOXSEG8EI8_V }, // 2946
  { PseudoVLOXSEG8EI8_V_MF4_MF4_MASK, VLOXSEG8EI8_V }, // 2947
  { PseudoVLOXSEG8EI8_V_MF8_M1, VLOXSEG8EI8_V }, // 2948
  { PseudoVLOXSEG8EI8_V_MF8_M1_MASK, VLOXSEG8EI8_V }, // 2949
  { PseudoVLOXSEG8EI8_V_MF8_MF2, VLOXSEG8EI8_V }, // 2950
  { PseudoVLOXSEG8EI8_V_MF8_MF2_MASK, VLOXSEG8EI8_V }, // 2951
  { PseudoVLOXSEG8EI8_V_MF8_MF4, VLOXSEG8EI8_V }, // 2952
  { PseudoVLOXSEG8EI8_V_MF8_MF4_MASK, VLOXSEG8EI8_V }, // 2953
  { PseudoVLOXSEG8EI8_V_MF8_MF8, VLOXSEG8EI8_V }, // 2954
  { PseudoVLOXSEG8EI8_V_MF8_MF8_MASK, VLOXSEG8EI8_V }, // 2955
  { PseudoVLSE16_V_M1, VLSE16_V }, // 2956
  { PseudoVLSE16_V_M1_MASK, VLSE16_V }, // 2957
  { PseudoVLSE16_V_M1_TU, VLSE16_V }, // 2958
  { PseudoVLSE16_V_M2, VLSE16_V }, // 2959
  { PseudoVLSE16_V_M2_MASK, VLSE16_V }, // 2960
  { PseudoVLSE16_V_M2_TU, VLSE16_V }, // 2961
  { PseudoVLSE16_V_M4, VLSE16_V }, // 2962
  { PseudoVLSE16_V_M4_MASK, VLSE16_V }, // 2963
  { PseudoVLSE16_V_M4_TU, VLSE16_V }, // 2964
  { PseudoVLSE16_V_M8, VLSE16_V }, // 2965
  { PseudoVLSE16_V_M8_MASK, VLSE16_V }, // 2966
  { PseudoVLSE16_V_M8_TU, VLSE16_V }, // 2967
  { PseudoVLSE16_V_MF2, VLSE16_V }, // 2968
  { PseudoVLSE16_V_MF2_MASK, VLSE16_V }, // 2969
  { PseudoVLSE16_V_MF2_TU, VLSE16_V }, // 2970
  { PseudoVLSE16_V_MF4, VLSE16_V }, // 2971
  { PseudoVLSE16_V_MF4_MASK, VLSE16_V }, // 2972
  { PseudoVLSE16_V_MF4_TU, VLSE16_V }, // 2973
  { PseudoVLSE32_V_M1, VLSE32_V }, // 2974
  { PseudoVLSE32_V_M1_MASK, VLSE32_V }, // 2975
  { PseudoVLSE32_V_M1_TU, VLSE32_V }, // 2976
  { PseudoVLSE32_V_M2, VLSE32_V }, // 2977
  { PseudoVLSE32_V_M2_MASK, VLSE32_V }, // 2978
  { PseudoVLSE32_V_M2_TU, VLSE32_V }, // 2979
  { PseudoVLSE32_V_M4, VLSE32_V }, // 2980
  { PseudoVLSE32_V_M4_MASK, VLSE32_V }, // 2981
  { PseudoVLSE32_V_M4_TU, VLSE32_V }, // 2982
  { PseudoVLSE32_V_M8, VLSE32_V }, // 2983
  { PseudoVLSE32_V_M8_MASK, VLSE32_V }, // 2984
  { PseudoVLSE32_V_M8_TU, VLSE32_V }, // 2985
  { PseudoVLSE32_V_MF2, VLSE32_V }, // 2986
  { PseudoVLSE32_V_MF2_MASK, VLSE32_V }, // 2987
  { PseudoVLSE32_V_MF2_TU, VLSE32_V }, // 2988
  { PseudoVLSE64_V_M1, VLSE64_V }, // 2989
  { PseudoVLSE64_V_M1_MASK, VLSE64_V }, // 2990
  { PseudoVLSE64_V_M1_TU, VLSE64_V }, // 2991
  { PseudoVLSE64_V_M2, VLSE64_V }, // 2992
  { PseudoVLSE64_V_M2_MASK, VLSE64_V }, // 2993
  { PseudoVLSE64_V_M2_TU, VLSE64_V }, // 2994
  { PseudoVLSE64_V_M4, VLSE64_V }, // 2995
  { PseudoVLSE64_V_M4_MASK, VLSE64_V }, // 2996
  { PseudoVLSE64_V_M4_TU, VLSE64_V }, // 2997
  { PseudoVLSE64_V_M8, VLSE64_V }, // 2998
  { PseudoVLSE64_V_M8_MASK, VLSE64_V }, // 2999
  { PseudoVLSE64_V_M8_TU, VLSE64_V }, // 3000
  { PseudoVLSE8_V_M1, VLSE8_V }, // 3001
  { PseudoVLSE8_V_M1_MASK, VLSE8_V }, // 3002
  { PseudoVLSE8_V_M1_TU, VLSE8_V }, // 3003
  { PseudoVLSE8_V_M2, VLSE8_V }, // 3004
  { PseudoVLSE8_V_M2_MASK, VLSE8_V }, // 3005
  { PseudoVLSE8_V_M2_TU, VLSE8_V }, // 3006
  { PseudoVLSE8_V_M4, VLSE8_V }, // 3007
  { PseudoVLSE8_V_M4_MASK, VLSE8_V }, // 3008
  { PseudoVLSE8_V_M4_TU, VLSE8_V }, // 3009
  { PseudoVLSE8_V_M8, VLSE8_V }, // 3010
  { PseudoVLSE8_V_M8_MASK, VLSE8_V }, // 3011
  { PseudoVLSE8_V_M8_TU, VLSE8_V }, // 3012
  { PseudoVLSE8_V_MF2, VLSE8_V }, // 3013
  { PseudoVLSE8_V_MF2_MASK, VLSE8_V }, // 3014
  { PseudoVLSE8_V_MF2_TU, VLSE8_V }, // 3015
  { PseudoVLSE8_V_MF4, VLSE8_V }, // 3016
  { PseudoVLSE8_V_MF4_MASK, VLSE8_V }, // 3017
  { PseudoVLSE8_V_MF4_TU, VLSE8_V }, // 3018
  { PseudoVLSE8_V_MF8, VLSE8_V }, // 3019
  { PseudoVLSE8_V_MF8_MASK, VLSE8_V }, // 3020
  { PseudoVLSE8_V_MF8_TU, VLSE8_V }, // 3021
  { PseudoVLSEG2E16FF_V_M1, VLSEG2E16FF_V }, // 3022
  { PseudoVLSEG2E16FF_V_M1_MASK, VLSEG2E16FF_V }, // 3023
  { PseudoVLSEG2E16FF_V_M2, VLSEG2E16FF_V }, // 3024
  { PseudoVLSEG2E16FF_V_M2_MASK, VLSEG2E16FF_V }, // 3025
  { PseudoVLSEG2E16FF_V_M4, VLSEG2E16FF_V }, // 3026
  { PseudoVLSEG2E16FF_V_M4_MASK, VLSEG2E16FF_V }, // 3027
  { PseudoVLSEG2E16FF_V_MF2, VLSEG2E16FF_V }, // 3028
  { PseudoVLSEG2E16FF_V_MF2_MASK, VLSEG2E16FF_V }, // 3029
  { PseudoVLSEG2E16FF_V_MF4, VLSEG2E16FF_V }, // 3030
  { PseudoVLSEG2E16FF_V_MF4_MASK, VLSEG2E16FF_V }, // 3031
  { PseudoVLSEG2E16_V_M1, VLSEG2E16_V }, // 3032
  { PseudoVLSEG2E16_V_M1_MASK, VLSEG2E16_V }, // 3033
  { PseudoVLSEG2E16_V_M2, VLSEG2E16_V }, // 3034
  { PseudoVLSEG2E16_V_M2_MASK, VLSEG2E16_V }, // 3035
  { PseudoVLSEG2E16_V_M4, VLSEG2E16_V }, // 3036
  { PseudoVLSEG2E16_V_M4_MASK, VLSEG2E16_V }, // 3037
  { PseudoVLSEG2E16_V_MF2, VLSEG2E16_V }, // 3038
  { PseudoVLSEG2E16_V_MF2_MASK, VLSEG2E16_V }, // 3039
  { PseudoVLSEG2E16_V_MF4, VLSEG2E16_V }, // 3040
  { PseudoVLSEG2E16_V_MF4_MASK, VLSEG2E16_V }, // 3041
  { PseudoVLSEG2E32FF_V_M1, VLSEG2E32FF_V }, // 3042
  { PseudoVLSEG2E32FF_V_M1_MASK, VLSEG2E32FF_V }, // 3043
  { PseudoVLSEG2E32FF_V_M2, VLSEG2E32FF_V }, // 3044
  { PseudoVLSEG2E32FF_V_M2_MASK, VLSEG2E32FF_V }, // 3045
  { PseudoVLSEG2E32FF_V_M4, VLSEG2E32FF_V }, // 3046
  { PseudoVLSEG2E32FF_V_M4_MASK, VLSEG2E32FF_V }, // 3047
  { PseudoVLSEG2E32FF_V_MF2, VLSEG2E32FF_V }, // 3048
  { PseudoVLSEG2E32FF_V_MF2_MASK, VLSEG2E32FF_V }, // 3049
  { PseudoVLSEG2E32_V_M1, VLSEG2E32_V }, // 3050
  { PseudoVLSEG2E32_V_M1_MASK, VLSEG2E32_V }, // 3051
  { PseudoVLSEG2E32_V_M2, VLSEG2E32_V }, // 3052
  { PseudoVLSEG2E32_V_M2_MASK, VLSEG2E32_V }, // 3053
  { PseudoVLSEG2E32_V_M4, VLSEG2E32_V }, // 3054
  { PseudoVLSEG2E32_V_M4_MASK, VLSEG2E32_V }, // 3055
  { PseudoVLSEG2E32_V_MF2, VLSEG2E32_V }, // 3056
  { PseudoVLSEG2E32_V_MF2_MASK, VLSEG2E32_V }, // 3057
  { PseudoVLSEG2E64FF_V_M1, VLSEG2E64FF_V }, // 3058
  { PseudoVLSEG2E64FF_V_M1_MASK, VLSEG2E64FF_V }, // 3059
  { PseudoVLSEG2E64FF_V_M2, VLSEG2E64FF_V }, // 3060
  { PseudoVLSEG2E64FF_V_M2_MASK, VLSEG2E64FF_V }, // 3061
  { PseudoVLSEG2E64FF_V_M4, VLSEG2E64FF_V }, // 3062
  { PseudoVLSEG2E64FF_V_M4_MASK, VLSEG2E64FF_V }, // 3063
  { PseudoVLSEG2E64_V_M1, VLSEG2E64_V }, // 3064
  { PseudoVLSEG2E64_V_M1_MASK, VLSEG2E64_V }, // 3065
  { PseudoVLSEG2E64_V_M2, VLSEG2E64_V }, // 3066
  { PseudoVLSEG2E64_V_M2_MASK, VLSEG2E64_V }, // 3067
  { PseudoVLSEG2E64_V_M4, VLSEG2E64_V }, // 3068
  { PseudoVLSEG2E64_V_M4_MASK, VLSEG2E64_V }, // 3069
  { PseudoVLSEG2E8FF_V_M1, VLSEG2E8FF_V }, // 3070
  { PseudoVLSEG2E8FF_V_M1_MASK, VLSEG2E8FF_V }, // 3071
  { PseudoVLSEG2E8FF_V_M2, VLSEG2E8FF_V }, // 3072
  { PseudoVLSEG2E8FF_V_M2_MASK, VLSEG2E8FF_V }, // 3073
  { PseudoVLSEG2E8FF_V_M4, VLSEG2E8FF_V }, // 3074
  { PseudoVLSEG2E8FF_V_M4_MASK, VLSEG2E8FF_V }, // 3075
  { PseudoVLSEG2E8FF_V_MF2, VLSEG2E8FF_V }, // 3076
  { PseudoVLSEG2E8FF_V_MF2_MASK, VLSEG2E8FF_V }, // 3077
  { PseudoVLSEG2E8FF_V_MF4, VLSEG2E8FF_V }, // 3078
  { PseudoVLSEG2E8FF_V_MF4_MASK, VLSEG2E8FF_V }, // 3079
  { PseudoVLSEG2E8FF_V_MF8, VLSEG2E8FF_V }, // 3080
  { PseudoVLSEG2E8FF_V_MF8_MASK, VLSEG2E8FF_V }, // 3081
  { PseudoVLSEG2E8_V_M1, VLSEG2E8_V }, // 3082
  { PseudoVLSEG2E8_V_M1_MASK, VLSEG2E8_V }, // 3083
  { PseudoVLSEG2E8_V_M2, VLSEG2E8_V }, // 3084
  { PseudoVLSEG2E8_V_M2_MASK, VLSEG2E8_V }, // 3085
  { PseudoVLSEG2E8_V_M4, VLSEG2E8_V }, // 3086
  { PseudoVLSEG2E8_V_M4_MASK, VLSEG2E8_V }, // 3087
  { PseudoVLSEG2E8_V_MF2, VLSEG2E8_V }, // 3088
  { PseudoVLSEG2E8_V_MF2_MASK, VLSEG2E8_V }, // 3089
  { PseudoVLSEG2E8_V_MF4, VLSEG2E8_V }, // 3090
  { PseudoVLSEG2E8_V_MF4_MASK, VLSEG2E8_V }, // 3091
  { PseudoVLSEG2E8_V_MF8, VLSEG2E8_V }, // 3092
  { PseudoVLSEG2E8_V_MF8_MASK, VLSEG2E8_V }, // 3093
  { PseudoVLSEG3E16FF_V_M1, VLSEG3E16FF_V }, // 3094
  { PseudoVLSEG3E16FF_V_M1_MASK, VLSEG3E16FF_V }, // 3095
  { PseudoVLSEG3E16FF_V_M2, VLSEG3E16FF_V }, // 3096
  { PseudoVLSEG3E16FF_V_M2_MASK, VLSEG3E16FF_V }, // 3097
  { PseudoVLSEG3E16FF_V_MF2, VLSEG3E16FF_V }, // 3098
  { PseudoVLSEG3E16FF_V_MF2_MASK, VLSEG3E16FF_V }, // 3099
  { PseudoVLSEG3E16FF_V_MF4, VLSEG3E16FF_V }, // 3100
  { PseudoVLSEG3E16FF_V_MF4_MASK, VLSEG3E16FF_V }, // 3101
  { PseudoVLSEG3E16_V_M1, VLSEG3E16_V }, // 3102
  { PseudoVLSEG3E16_V_M1_MASK, VLSEG3E16_V }, // 3103
  { PseudoVLSEG3E16_V_M2, VLSEG3E16_V }, // 3104
  { PseudoVLSEG3E16_V_M2_MASK, VLSEG3E16_V }, // 3105
  { PseudoVLSEG3E16_V_MF2, VLSEG3E16_V }, // 3106
  { PseudoVLSEG3E16_V_MF2_MASK, VLSEG3E16_V }, // 3107
  { PseudoVLSEG3E16_V_MF4, VLSEG3E16_V }, // 3108
  { PseudoVLSEG3E16_V_MF4_MASK, VLSEG3E16_V }, // 3109
  { PseudoVLSEG3E32FF_V_M1, VLSEG3E32FF_V }, // 3110
  { PseudoVLSEG3E32FF_V_M1_MASK, VLSEG3E32FF_V }, // 3111
  { PseudoVLSEG3E32FF_V_M2, VLSEG3E32FF_V }, // 3112
  { PseudoVLSEG3E32FF_V_M2_MASK, VLSEG3E32FF_V }, // 3113
  { PseudoVLSEG3E32FF_V_MF2, VLSEG3E32FF_V }, // 3114
  { PseudoVLSEG3E32FF_V_MF2_MASK, VLSEG3E32FF_V }, // 3115
  { PseudoVLSEG3E32_V_M1, VLSEG3E32_V }, // 3116
  { PseudoVLSEG3E32_V_M1_MASK, VLSEG3E32_V }, // 3117
  { PseudoVLSEG3E32_V_M2, VLSEG3E32_V }, // 3118
  { PseudoVLSEG3E32_V_M2_MASK, VLSEG3E32_V }, // 3119
  { PseudoVLSEG3E32_V_MF2, VLSEG3E32_V }, // 3120
  { PseudoVLSEG3E32_V_MF2_MASK, VLSEG3E32_V }, // 3121
  { PseudoVLSEG3E64FF_V_M1, VLSEG3E64FF_V }, // 3122
  { PseudoVLSEG3E64FF_V_M1_MASK, VLSEG3E64FF_V }, // 3123
  { PseudoVLSEG3E64FF_V_M2, VLSEG3E64FF_V }, // 3124
  { PseudoVLSEG3E64FF_V_M2_MASK, VLSEG3E64FF_V }, // 3125
  { PseudoVLSEG3E64_V_M1, VLSEG3E64_V }, // 3126
  { PseudoVLSEG3E64_V_M1_MASK, VLSEG3E64_V }, // 3127
  { PseudoVLSEG3E64_V_M2, VLSEG3E64_V }, // 3128
  { PseudoVLSEG3E64_V_M2_MASK, VLSEG3E64_V }, // 3129
  { PseudoVLSEG3E8FF_V_M1, VLSEG3E8FF_V }, // 3130
  { PseudoVLSEG3E8FF_V_M1_MASK, VLSEG3E8FF_V }, // 3131
  { PseudoVLSEG3E8FF_V_M2, VLSEG3E8FF_V }, // 3132
  { PseudoVLSEG3E8FF_V_M2_MASK, VLSEG3E8FF_V }, // 3133
  { PseudoVLSEG3E8FF_V_MF2, VLSEG3E8FF_V }, // 3134
  { PseudoVLSEG3E8FF_V_MF2_MASK, VLSEG3E8FF_V }, // 3135
  { PseudoVLSEG3E8FF_V_MF4, VLSEG3E8FF_V }, // 3136
  { PseudoVLSEG3E8FF_V_MF4_MASK, VLSEG3E8FF_V }, // 3137
  { PseudoVLSEG3E8FF_V_MF8, VLSEG3E8FF_V }, // 3138
  { PseudoVLSEG3E8FF_V_MF8_MASK, VLSEG3E8FF_V }, // 3139
  { PseudoVLSEG3E8_V_M1, VLSEG3E8_V }, // 3140
  { PseudoVLSEG3E8_V_M1_MASK, VLSEG3E8_V }, // 3141
  { PseudoVLSEG3E8_V_M2, VLSEG3E8_V }, // 3142
  { PseudoVLSEG3E8_V_M2_MASK, VLSEG3E8_V }, // 3143
  { PseudoVLSEG3E8_V_MF2, VLSEG3E8_V }, // 3144
  { PseudoVLSEG3E8_V_MF2_MASK, VLSEG3E8_V }, // 3145
  { PseudoVLSEG3E8_V_MF4, VLSEG3E8_V }, // 3146
  { PseudoVLSEG3E8_V_MF4_MASK, VLSEG3E8_V }, // 3147
  { PseudoVLSEG3E8_V_MF8, VLSEG3E8_V }, // 3148
  { PseudoVLSEG3E8_V_MF8_MASK, VLSEG3E8_V }, // 3149
  { PseudoVLSEG4E16FF_V_M1, VLSEG4E16FF_V }, // 3150
  { PseudoVLSEG4E16FF_V_M1_MASK, VLSEG4E16FF_V }, // 3151
  { PseudoVLSEG4E16FF_V_M2, VLSEG4E16FF_V }, // 3152
  { PseudoVLSEG4E16FF_V_M2_MASK, VLSEG4E16FF_V }, // 3153
  { PseudoVLSEG4E16FF_V_MF2, VLSEG4E16FF_V }, // 3154
  { PseudoVLSEG4E16FF_V_MF2_MASK, VLSEG4E16FF_V }, // 3155
  { PseudoVLSEG4E16FF_V_MF4, VLSEG4E16FF_V }, // 3156
  { PseudoVLSEG4E16FF_V_MF4_MASK, VLSEG4E16FF_V }, // 3157
  { PseudoVLSEG4E16_V_M1, VLSEG4E16_V }, // 3158
  { PseudoVLSEG4E16_V_M1_MASK, VLSEG4E16_V }, // 3159
  { PseudoVLSEG4E16_V_M2, VLSEG4E16_V }, // 3160
  { PseudoVLSEG4E16_V_M2_MASK, VLSEG4E16_V }, // 3161
  { PseudoVLSEG4E16_V_MF2, VLSEG4E16_V }, // 3162
  { PseudoVLSEG4E16_V_MF2_MASK, VLSEG4E16_V }, // 3163
  { PseudoVLSEG4E16_V_MF4, VLSEG4E16_V }, // 3164
  { PseudoVLSEG4E16_V_MF4_MASK, VLSEG4E16_V }, // 3165
  { PseudoVLSEG4E32FF_V_M1, VLSEG4E32FF_V }, // 3166
  { PseudoVLSEG4E32FF_V_M1_MASK, VLSEG4E32FF_V }, // 3167
  { PseudoVLSEG4E32FF_V_M2, VLSEG4E32FF_V }, // 3168
  { PseudoVLSEG4E32FF_V_M2_MASK, VLSEG4E32FF_V }, // 3169
  { PseudoVLSEG4E32FF_V_MF2, VLSEG4E32FF_V }, // 3170
  { PseudoVLSEG4E32FF_V_MF2_MASK, VLSEG4E32FF_V }, // 3171
  { PseudoVLSEG4E32_V_M1, VLSEG4E32_V }, // 3172
  { PseudoVLSEG4E32_V_M1_MASK, VLSEG4E32_V }, // 3173
  { PseudoVLSEG4E32_V_M2, VLSEG4E32_V }, // 3174
  { PseudoVLSEG4E32_V_M2_MASK, VLSEG4E32_V }, // 3175
  { PseudoVLSEG4E32_V_MF2, VLSEG4E32_V }, // 3176
  { PseudoVLSEG4E32_V_MF2_MASK, VLSEG4E32_V }, // 3177
  { PseudoVLSEG4E64FF_V_M1, VLSEG4E64FF_V }, // 3178
  { PseudoVLSEG4E64FF_V_M1_MASK, VLSEG4E64FF_V }, // 3179
  { PseudoVLSEG4E64FF_V_M2, VLSEG4E64FF_V }, // 3180
  { PseudoVLSEG4E64FF_V_M2_MASK, VLSEG4E64FF_V }, // 3181
  { PseudoVLSEG4E64_V_M1, VLSEG4E64_V }, // 3182
  { PseudoVLSEG4E64_V_M1_MASK, VLSEG4E64_V }, // 3183
  { PseudoVLSEG4E64_V_M2, VLSEG4E64_V }, // 3184
  { PseudoVLSEG4E64_V_M2_MASK, VLSEG4E64_V }, // 3185
  { PseudoVLSEG4E8FF_V_M1, VLSEG4E8FF_V }, // 3186
  { PseudoVLSEG4E8FF_V_M1_MASK, VLSEG4E8FF_V }, // 3187
  { PseudoVLSEG4E8FF_V_M2, VLSEG4E8FF_V }, // 3188
  { PseudoVLSEG4E8FF_V_M2_MASK, VLSEG4E8FF_V }, // 3189
  { PseudoVLSEG4E8FF_V_MF2, VLSEG4E8FF_V }, // 3190
  { PseudoVLSEG4E8FF_V_MF2_MASK, VLSEG4E8FF_V }, // 3191
  { PseudoVLSEG4E8FF_V_MF4, VLSEG4E8FF_V }, // 3192
  { PseudoVLSEG4E8FF_V_MF4_MASK, VLSEG4E8FF_V }, // 3193
  { PseudoVLSEG4E8FF_V_MF8, VLSEG4E8FF_V }, // 3194
  { PseudoVLSEG4E8FF_V_MF8_MASK, VLSEG4E8FF_V }, // 3195
  { PseudoVLSEG4E8_V_M1, VLSEG4E8_V }, // 3196
  { PseudoVLSEG4E8_V_M1_MASK, VLSEG4E8_V }, // 3197
  { PseudoVLSEG4E8_V_M2, VLSEG4E8_V }, // 3198
  { PseudoVLSEG4E8_V_M2_MASK, VLSEG4E8_V }, // 3199
  { PseudoVLSEG4E8_V_MF2, VLSEG4E8_V }, // 3200
  { PseudoVLSEG4E8_V_MF2_MASK, VLSEG4E8_V }, // 3201
  { PseudoVLSEG4E8_V_MF4, VLSEG4E8_V }, // 3202
  { PseudoVLSEG4E8_V_MF4_MASK, VLSEG4E8_V }, // 3203
  { PseudoVLSEG4E8_V_MF8, VLSEG4E8_V }, // 3204
  { PseudoVLSEG4E8_V_MF8_MASK, VLSEG4E8_V }, // 3205
  { PseudoVLSEG5E16FF_V_M1, VLSEG5E16FF_V }, // 3206
  { PseudoVLSEG5E16FF_V_M1_MASK, VLSEG5E16FF_V }, // 3207
  { PseudoVLSEG5E16FF_V_MF2, VLSEG5E16FF_V }, // 3208
  { PseudoVLSEG5E16FF_V_MF2_MASK, VLSEG5E16FF_V }, // 3209
  { PseudoVLSEG5E16FF_V_MF4, VLSEG5E16FF_V }, // 3210
  { PseudoVLSEG5E16FF_V_MF4_MASK, VLSEG5E16FF_V }, // 3211
  { PseudoVLSEG5E16_V_M1, VLSEG5E16_V }, // 3212
  { PseudoVLSEG5E16_V_M1_MASK, VLSEG5E16_V }, // 3213
  { PseudoVLSEG5E16_V_MF2, VLSEG5E16_V }, // 3214
  { PseudoVLSEG5E16_V_MF2_MASK, VLSEG5E16_V }, // 3215
  { PseudoVLSEG5E16_V_MF4, VLSEG5E16_V }, // 3216
  { PseudoVLSEG5E16_V_MF4_MASK, VLSEG5E16_V }, // 3217
  { PseudoVLSEG5E32FF_V_M1, VLSEG5E32FF_V }, // 3218
  { PseudoVLSEG5E32FF_V_M1_MASK, VLSEG5E32FF_V }, // 3219
  { PseudoVLSEG5E32FF_V_MF2, VLSEG5E32FF_V }, // 3220
  { PseudoVLSEG5E32FF_V_MF2_MASK, VLSEG5E32FF_V }, // 3221
  { PseudoVLSEG5E32_V_M1, VLSEG5E32_V }, // 3222
  { PseudoVLSEG5E32_V_M1_MASK, VLSEG5E32_V }, // 3223
  { PseudoVLSEG5E32_V_MF2, VLSEG5E32_V }, // 3224
  { PseudoVLSEG5E32_V_MF2_MASK, VLSEG5E32_V }, // 3225
  { PseudoVLSEG5E64FF_V_M1, VLSEG5E64FF_V }, // 3226
  { PseudoVLSEG5E64FF_V_M1_MASK, VLSEG5E64FF_V }, // 3227
  { PseudoVLSEG5E64_V_M1, VLSEG5E64_V }, // 3228
  { PseudoVLSEG5E64_V_M1_MASK, VLSEG5E64_V }, // 3229
  { PseudoVLSEG5E8FF_V_M1, VLSEG5E8FF_V }, // 3230
  { PseudoVLSEG5E8FF_V_M1_MASK, VLSEG5E8FF_V }, // 3231
  { PseudoVLSEG5E8FF_V_MF2, VLSEG5E8FF_V }, // 3232
  { PseudoVLSEG5E8FF_V_MF2_MASK, VLSEG5E8FF_V }, // 3233
  { PseudoVLSEG5E8FF_V_MF4, VLSEG5E8FF_V }, // 3234
  { PseudoVLSEG5E8FF_V_MF4_MASK, VLSEG5E8FF_V }, // 3235
  { PseudoVLSEG5E8FF_V_MF8, VLSEG5E8FF_V }, // 3236
  { PseudoVLSEG5E8FF_V_MF8_MASK, VLSEG5E8FF_V }, // 3237
  { PseudoVLSEG5E8_V_M1, VLSEG5E8_V }, // 3238
  { PseudoVLSEG5E8_V_M1_MASK, VLSEG5E8_V }, // 3239
  { PseudoVLSEG5E8_V_MF2, VLSEG5E8_V }, // 3240
  { PseudoVLSEG5E8_V_MF2_MASK, VLSEG5E8_V }, // 3241
  { PseudoVLSEG5E8_V_MF4, VLSEG5E8_V }, // 3242
  { PseudoVLSEG5E8_V_MF4_MASK, VLSEG5E8_V }, // 3243
  { PseudoVLSEG5E8_V_MF8, VLSEG5E8_V }, // 3244
  { PseudoVLSEG5E8_V_MF8_MASK, VLSEG5E8_V }, // 3245
  { PseudoVLSEG6E16FF_V_M1, VLSEG6E16FF_V }, // 3246
  { PseudoVLSEG6E16FF_V_M1_MASK, VLSEG6E16FF_V }, // 3247
  { PseudoVLSEG6E16FF_V_MF2, VLSEG6E16FF_V }, // 3248
  { PseudoVLSEG6E16FF_V_MF2_MASK, VLSEG6E16FF_V }, // 3249
  { PseudoVLSEG6E16FF_V_MF4, VLSEG6E16FF_V }, // 3250
  { PseudoVLSEG6E16FF_V_MF4_MASK, VLSEG6E16FF_V }, // 3251
  { PseudoVLSEG6E16_V_M1, VLSEG6E16_V }, // 3252
  { PseudoVLSEG6E16_V_M1_MASK, VLSEG6E16_V }, // 3253
  { PseudoVLSEG6E16_V_MF2, VLSEG6E16_V }, // 3254
  { PseudoVLSEG6E16_V_MF2_MASK, VLSEG6E16_V }, // 3255
  { PseudoVLSEG6E16_V_MF4, VLSEG6E16_V }, // 3256
  { PseudoVLSEG6E16_V_MF4_MASK, VLSEG6E16_V }, // 3257
  { PseudoVLSEG6E32FF_V_M1, VLSEG6E32FF_V }, // 3258
  { PseudoVLSEG6E32FF_V_M1_MASK, VLSEG6E32FF_V }, // 3259
  { PseudoVLSEG6E32FF_V_MF2, VLSEG6E32FF_V }, // 3260
  { PseudoVLSEG6E32FF_V_MF2_MASK, VLSEG6E32FF_V }, // 3261
  { PseudoVLSEG6E32_V_M1, VLSEG6E32_V }, // 3262
  { PseudoVLSEG6E32_V_M1_MASK, VLSEG6E32_V }, // 3263
  { PseudoVLSEG6E32_V_MF2, VLSEG6E32_V }, // 3264
  { PseudoVLSEG6E32_V_MF2_MASK, VLSEG6E32_V }, // 3265
  { PseudoVLSEG6E64FF_V_M1, VLSEG6E64FF_V }, // 3266
  { PseudoVLSEG6E64FF_V_M1_MASK, VLSEG6E64FF_V }, // 3267
  { PseudoVLSEG6E64_V_M1, VLSEG6E64_V }, // 3268
  { PseudoVLSEG6E64_V_M1_MASK, VLSEG6E64_V }, // 3269
  { PseudoVLSEG6E8FF_V_M1, VLSEG6E8FF_V }, // 3270
  { PseudoVLSEG6E8FF_V_M1_MASK, VLSEG6E8FF_V }, // 3271
  { PseudoVLSEG6E8FF_V_MF2, VLSEG6E8FF_V }, // 3272
  { PseudoVLSEG6E8FF_V_MF2_MASK, VLSEG6E8FF_V }, // 3273
  { PseudoVLSEG6E8FF_V_MF4, VLSEG6E8FF_V }, // 3274
  { PseudoVLSEG6E8FF_V_MF4_MASK, VLSEG6E8FF_V }, // 3275
  { PseudoVLSEG6E8FF_V_MF8, VLSEG6E8FF_V }, // 3276
  { PseudoVLSEG6E8FF_V_MF8_MASK, VLSEG6E8FF_V }, // 3277
  { PseudoVLSEG6E8_V_M1, VLSEG6E8_V }, // 3278
  { PseudoVLSEG6E8_V_M1_MASK, VLSEG6E8_V }, // 3279
  { PseudoVLSEG6E8_V_MF2, VLSEG6E8_V }, // 3280
  { PseudoVLSEG6E8_V_MF2_MASK, VLSEG6E8_V }, // 3281
  { PseudoVLSEG6E8_V_MF4, VLSEG6E8_V }, // 3282
  { PseudoVLSEG6E8_V_MF4_MASK, VLSEG6E8_V }, // 3283
  { PseudoVLSEG6E8_V_MF8, VLSEG6E8_V }, // 3284
  { PseudoVLSEG6E8_V_MF8_MASK, VLSEG6E8_V }, // 3285
  { PseudoVLSEG7E16FF_V_M1, VLSEG7E16FF_V }, // 3286
  { PseudoVLSEG7E16FF_V_M1_MASK, VLSEG7E16FF_V }, // 3287
  { PseudoVLSEG7E16FF_V_MF2, VLSEG7E16FF_V }, // 3288
  { PseudoVLSEG7E16FF_V_MF2_MASK, VLSEG7E16FF_V }, // 3289
  { PseudoVLSEG7E16FF_V_MF4, VLSEG7E16FF_V }, // 3290
  { PseudoVLSEG7E16FF_V_MF4_MASK, VLSEG7E16FF_V }, // 3291
  { PseudoVLSEG7E16_V_M1, VLSEG7E16_V }, // 3292
  { PseudoVLSEG7E16_V_M1_MASK, VLSEG7E16_V }, // 3293
  { PseudoVLSEG7E16_V_MF2, VLSEG7E16_V }, // 3294
  { PseudoVLSEG7E16_V_MF2_MASK, VLSEG7E16_V }, // 3295
  { PseudoVLSEG7E16_V_MF4, VLSEG7E16_V }, // 3296
  { PseudoVLSEG7E16_V_MF4_MASK, VLSEG7E16_V }, // 3297
  { PseudoVLSEG7E32FF_V_M1, VLSEG7E32FF_V }, // 3298
  { PseudoVLSEG7E32FF_V_M1_MASK, VLSEG7E32FF_V }, // 3299
  { PseudoVLSEG7E32FF_V_MF2, VLSEG7E32FF_V }, // 3300
  { PseudoVLSEG7E32FF_V_MF2_MASK, VLSEG7E32FF_V }, // 3301
  { PseudoVLSEG7E32_V_M1, VLSEG7E32_V }, // 3302
  { PseudoVLSEG7E32_V_M1_MASK, VLSEG7E32_V }, // 3303
  { PseudoVLSEG7E32_V_MF2, VLSEG7E32_V }, // 3304
  { PseudoVLSEG7E32_V_MF2_MASK, VLSEG7E32_V }, // 3305
  { PseudoVLSEG7E64FF_V_M1, VLSEG7E64FF_V }, // 3306
  { PseudoVLSEG7E64FF_V_M1_MASK, VLSEG7E64FF_V }, // 3307
  { PseudoVLSEG7E64_V_M1, VLSEG7E64_V }, // 3308
  { PseudoVLSEG7E64_V_M1_MASK, VLSEG7E64_V }, // 3309
  { PseudoVLSEG7E8FF_V_M1, VLSEG7E8FF_V }, // 3310
  { PseudoVLSEG7E8FF_V_M1_MASK, VLSEG7E8FF_V }, // 3311
  { PseudoVLSEG7E8FF_V_MF2, VLSEG7E8FF_V }, // 3312
  { PseudoVLSEG7E8FF_V_MF2_MASK, VLSEG7E8FF_V }, // 3313
  { PseudoVLSEG7E8FF_V_MF4, VLSEG7E8FF_V }, // 3314
  { PseudoVLSEG7E8FF_V_MF4_MASK, VLSEG7E8FF_V }, // 3315
  { PseudoVLSEG7E8FF_V_MF8, VLSEG7E8FF_V }, // 3316
  { PseudoVLSEG7E8FF_V_MF8_MASK, VLSEG7E8FF_V }, // 3317
  { PseudoVLSEG7E8_V_M1, VLSEG7E8_V }, // 3318
  { PseudoVLSEG7E8_V_M1_MASK, VLSEG7E8_V }, // 3319
  { PseudoVLSEG7E8_V_MF2, VLSEG7E8_V }, // 3320
  { PseudoVLSEG7E8_V_MF2_MASK, VLSEG7E8_V }, // 3321
  { PseudoVLSEG7E8_V_MF4, VLSEG7E8_V }, // 3322
  { PseudoVLSEG7E8_V_MF4_MASK, VLSEG7E8_V }, // 3323
  { PseudoVLSEG7E8_V_MF8, VLSEG7E8_V }, // 3324
  { PseudoVLSEG7E8_V_MF8_MASK, VLSEG7E8_V }, // 3325
  { PseudoVLSEG8E16FF_V_M1, VLSEG8E16FF_V }, // 3326
  { PseudoVLSEG8E16FF_V_M1_MASK, VLSEG8E16FF_V }, // 3327
  { PseudoVLSEG8E16FF_V_MF2, VLSEG8E16FF_V }, // 3328
  { PseudoVLSEG8E16FF_V_MF2_MASK, VLSEG8E16FF_V }, // 3329
  { PseudoVLSEG8E16FF_V_MF4, VLSEG8E16FF_V }, // 3330
  { PseudoVLSEG8E16FF_V_MF4_MASK, VLSEG8E16FF_V }, // 3331
  { PseudoVLSEG8E16_V_M1, VLSEG8E16_V }, // 3332
  { PseudoVLSEG8E16_V_M1_MASK, VLSEG8E16_V }, // 3333
  { PseudoVLSEG8E16_V_MF2, VLSEG8E16_V }, // 3334
  { PseudoVLSEG8E16_V_MF2_MASK, VLSEG8E16_V }, // 3335
  { PseudoVLSEG8E16_V_MF4, VLSEG8E16_V }, // 3336
  { PseudoVLSEG8E16_V_MF4_MASK, VLSEG8E16_V }, // 3337
  { PseudoVLSEG8E32FF_V_M1, VLSEG8E32FF_V }, // 3338
  { PseudoVLSEG8E32FF_V_M1_MASK, VLSEG8E32FF_V }, // 3339
  { PseudoVLSEG8E32FF_V_MF2, VLSEG8E32FF_V }, // 3340
  { PseudoVLSEG8E32FF_V_MF2_MASK, VLSEG8E32FF_V }, // 3341
  { PseudoVLSEG8E32_V_M1, VLSEG8E32_V }, // 3342
  { PseudoVLSEG8E32_V_M1_MASK, VLSEG8E32_V }, // 3343
  { PseudoVLSEG8E32_V_MF2, VLSEG8E32_V }, // 3344
  { PseudoVLSEG8E32_V_MF2_MASK, VLSEG8E32_V }, // 3345
  { PseudoVLSEG8E64FF_V_M1, VLSEG8E64FF_V }, // 3346
  { PseudoVLSEG8E64FF_V_M1_MASK, VLSEG8E64FF_V }, // 3347
  { PseudoVLSEG8E64_V_M1, VLSEG8E64_V }, // 3348
  { PseudoVLSEG8E64_V_M1_MASK, VLSEG8E64_V }, // 3349
  { PseudoVLSEG8E8FF_V_M1, VLSEG8E8FF_V }, // 3350
  { PseudoVLSEG8E8FF_V_M1_MASK, VLSEG8E8FF_V }, // 3351
  { PseudoVLSEG8E8FF_V_MF2, VLSEG8E8FF_V }, // 3352
  { PseudoVLSEG8E8FF_V_MF2_MASK, VLSEG8E8FF_V }, // 3353
  { PseudoVLSEG8E8FF_V_MF4, VLSEG8E8FF_V }, // 3354
  { PseudoVLSEG8E8FF_V_MF4_MASK, VLSEG8E8FF_V }, // 3355
  { PseudoVLSEG8E8FF_V_MF8, VLSEG8E8FF_V }, // 3356
  { PseudoVLSEG8E8FF_V_MF8_MASK, VLSEG8E8FF_V }, // 3357
  { PseudoVLSEG8E8_V_M1, VLSEG8E8_V }, // 3358
  { PseudoVLSEG8E8_V_M1_MASK, VLSEG8E8_V }, // 3359
  { PseudoVLSEG8E8_V_MF2, VLSEG8E8_V }, // 3360
  { PseudoVLSEG8E8_V_MF2_MASK, VLSEG8E8_V }, // 3361
  { PseudoVLSEG8E8_V_MF4, VLSEG8E8_V }, // 3362
  { PseudoVLSEG8E8_V_MF4_MASK, VLSEG8E8_V }, // 3363
  { PseudoVLSEG8E8_V_MF8, VLSEG8E8_V }, // 3364
  { PseudoVLSEG8E8_V_MF8_MASK, VLSEG8E8_V }, // 3365
  { PseudoVLSSEG2E16_V_M1, VLSSEG2E16_V }, // 3366
  { PseudoVLSSEG2E16_V_M1_MASK, VLSSEG2E16_V }, // 3367
  { PseudoVLSSEG2E16_V_M2, VLSSEG2E16_V }, // 3368
  { PseudoVLSSEG2E16_V_M2_MASK, VLSSEG2E16_V }, // 3369
  { PseudoVLSSEG2E16_V_M4, VLSSEG2E16_V }, // 3370
  { PseudoVLSSEG2E16_V_M4_MASK, VLSSEG2E16_V }, // 3371
  { PseudoVLSSEG2E16_V_MF2, VLSSEG2E16_V }, // 3372
  { PseudoVLSSEG2E16_V_MF2_MASK, VLSSEG2E16_V }, // 3373
  { PseudoVLSSEG2E16_V_MF4, VLSSEG2E16_V }, // 3374
  { PseudoVLSSEG2E16_V_MF4_MASK, VLSSEG2E16_V }, // 3375
  { PseudoVLSSEG2E32_V_M1, VLSSEG2E32_V }, // 3376
  { PseudoVLSSEG2E32_V_M1_MASK, VLSSEG2E32_V }, // 3377
  { PseudoVLSSEG2E32_V_M2, VLSSEG2E32_V }, // 3378
  { PseudoVLSSEG2E32_V_M2_MASK, VLSSEG2E32_V }, // 3379
  { PseudoVLSSEG2E32_V_M4, VLSSEG2E32_V }, // 3380
  { PseudoVLSSEG2E32_V_M4_MASK, VLSSEG2E32_V }, // 3381
  { PseudoVLSSEG2E32_V_MF2, VLSSEG2E32_V }, // 3382
  { PseudoVLSSEG2E32_V_MF2_MASK, VLSSEG2E32_V }, // 3383
  { PseudoVLSSEG2E64_V_M1, VLSSEG2E64_V }, // 3384
  { PseudoVLSSEG2E64_V_M1_MASK, VLSSEG2E64_V }, // 3385
  { PseudoVLSSEG2E64_V_M2, VLSSEG2E64_V }, // 3386
  { PseudoVLSSEG2E64_V_M2_MASK, VLSSEG2E64_V }, // 3387
  { PseudoVLSSEG2E64_V_M4, VLSSEG2E64_V }, // 3388
  { PseudoVLSSEG2E64_V_M4_MASK, VLSSEG2E64_V }, // 3389
  { PseudoVLSSEG2E8_V_M1, VLSSEG2E8_V }, // 3390
  { PseudoVLSSEG2E8_V_M1_MASK, VLSSEG2E8_V }, // 3391
  { PseudoVLSSEG2E8_V_M2, VLSSEG2E8_V }, // 3392
  { PseudoVLSSEG2E8_V_M2_MASK, VLSSEG2E8_V }, // 3393
  { PseudoVLSSEG2E8_V_M4, VLSSEG2E8_V }, // 3394
  { PseudoVLSSEG2E8_V_M4_MASK, VLSSEG2E8_V }, // 3395
  { PseudoVLSSEG2E8_V_MF2, VLSSEG2E8_V }, // 3396
  { PseudoVLSSEG2E8_V_MF2_MASK, VLSSEG2E8_V }, // 3397
  { PseudoVLSSEG2E8_V_MF4, VLSSEG2E8_V }, // 3398
  { PseudoVLSSEG2E8_V_MF4_MASK, VLSSEG2E8_V }, // 3399
  { PseudoVLSSEG2E8_V_MF8, VLSSEG2E8_V }, // 3400
  { PseudoVLSSEG2E8_V_MF8_MASK, VLSSEG2E8_V }, // 3401
  { PseudoVLSSEG3E16_V_M1, VLSSEG3E16_V }, // 3402
  { PseudoVLSSEG3E16_V_M1_MASK, VLSSEG3E16_V }, // 3403
  { PseudoVLSSEG3E16_V_M2, VLSSEG3E16_V }, // 3404
  { PseudoVLSSEG3E16_V_M2_MASK, VLSSEG3E16_V }, // 3405
  { PseudoVLSSEG3E16_V_MF2, VLSSEG3E16_V }, // 3406
  { PseudoVLSSEG3E16_V_MF2_MASK, VLSSEG3E16_V }, // 3407
  { PseudoVLSSEG3E16_V_MF4, VLSSEG3E16_V }, // 3408
  { PseudoVLSSEG3E16_V_MF4_MASK, VLSSEG3E16_V }, // 3409
  { PseudoVLSSEG3E32_V_M1, VLSSEG3E32_V }, // 3410
  { PseudoVLSSEG3E32_V_M1_MASK, VLSSEG3E32_V }, // 3411
  { PseudoVLSSEG3E32_V_M2, VLSSEG3E32_V }, // 3412
  { PseudoVLSSEG3E32_V_M2_MASK, VLSSEG3E32_V }, // 3413
  { PseudoVLSSEG3E32_V_MF2, VLSSEG3E32_V }, // 3414
  { PseudoVLSSEG3E32_V_MF2_MASK, VLSSEG3E32_V }, // 3415
  { PseudoVLSSEG3E64_V_M1, VLSSEG3E64_V }, // 3416
  { PseudoVLSSEG3E64_V_M1_MASK, VLSSEG3E64_V }, // 3417
  { PseudoVLSSEG3E64_V_M2, VLSSEG3E64_V }, // 3418
  { PseudoVLSSEG3E64_V_M2_MASK, VLSSEG3E64_V }, // 3419
  { PseudoVLSSEG3E8_V_M1, VLSSEG3E8_V }, // 3420
  { PseudoVLSSEG3E8_V_M1_MASK, VLSSEG3E8_V }, // 3421
  { PseudoVLSSEG3E8_V_M2, VLSSEG3E8_V }, // 3422
  { PseudoVLSSEG3E8_V_M2_MASK, VLSSEG3E8_V }, // 3423
  { PseudoVLSSEG3E8_V_MF2, VLSSEG3E8_V }, // 3424
  { PseudoVLSSEG3E8_V_MF2_MASK, VLSSEG3E8_V }, // 3425
  { PseudoVLSSEG3E8_V_MF4, VLSSEG3E8_V }, // 3426
  { PseudoVLSSEG3E8_V_MF4_MASK, VLSSEG3E8_V }, // 3427
  { PseudoVLSSEG3E8_V_MF8, VLSSEG3E8_V }, // 3428
  { PseudoVLSSEG3E8_V_MF8_MASK, VLSSEG3E8_V }, // 3429
  { PseudoVLSSEG4E16_V_M1, VLSSEG4E16_V }, // 3430
  { PseudoVLSSEG4E16_V_M1_MASK, VLSSEG4E16_V }, // 3431
  { PseudoVLSSEG4E16_V_M2, VLSSEG4E16_V }, // 3432
  { PseudoVLSSEG4E16_V_M2_MASK, VLSSEG4E16_V }, // 3433
  { PseudoVLSSEG4E16_V_MF2, VLSSEG4E16_V }, // 3434
  { PseudoVLSSEG4E16_V_MF2_MASK, VLSSEG4E16_V }, // 3435
  { PseudoVLSSEG4E16_V_MF4, VLSSEG4E16_V }, // 3436
  { PseudoVLSSEG4E16_V_MF4_MASK, VLSSEG4E16_V }, // 3437
  { PseudoVLSSEG4E32_V_M1, VLSSEG4E32_V }, // 3438
  { PseudoVLSSEG4E32_V_M1_MASK, VLSSEG4E32_V }, // 3439
  { PseudoVLSSEG4E32_V_M2, VLSSEG4E32_V }, // 3440
  { PseudoVLSSEG4E32_V_M2_MASK, VLSSEG4E32_V }, // 3441
  { PseudoVLSSEG4E32_V_MF2, VLSSEG4E32_V }, // 3442
  { PseudoVLSSEG4E32_V_MF2_MASK, VLSSEG4E32_V }, // 3443
  { PseudoVLSSEG4E64_V_M1, VLSSEG4E64_V }, // 3444
  { PseudoVLSSEG4E64_V_M1_MASK, VLSSEG4E64_V }, // 3445
  { PseudoVLSSEG4E64_V_M2, VLSSEG4E64_V }, // 3446
  { PseudoVLSSEG4E64_V_M2_MASK, VLSSEG4E64_V }, // 3447
  { PseudoVLSSEG4E8_V_M1, VLSSEG4E8_V }, // 3448
  { PseudoVLSSEG4E8_V_M1_MASK, VLSSEG4E8_V }, // 3449
  { PseudoVLSSEG4E8_V_M2, VLSSEG4E8_V }, // 3450
  { PseudoVLSSEG4E8_V_M2_MASK, VLSSEG4E8_V }, // 3451
  { PseudoVLSSEG4E8_V_MF2, VLSSEG4E8_V }, // 3452
  { PseudoVLSSEG4E8_V_MF2_MASK, VLSSEG4E8_V }, // 3453
  { PseudoVLSSEG4E8_V_MF4, VLSSEG4E8_V }, // 3454
  { PseudoVLSSEG4E8_V_MF4_MASK, VLSSEG4E8_V }, // 3455
  { PseudoVLSSEG4E8_V_MF8, VLSSEG4E8_V }, // 3456
  { PseudoVLSSEG4E8_V_MF8_MASK, VLSSEG4E8_V }, // 3457
  { PseudoVLSSEG5E16_V_M1, VLSSEG5E16_V }, // 3458
  { PseudoVLSSEG5E16_V_M1_MASK, VLSSEG5E16_V }, // 3459
  { PseudoVLSSEG5E16_V_MF2, VLSSEG5E16_V }, // 3460
  { PseudoVLSSEG5E16_V_MF2_MASK, VLSSEG5E16_V }, // 3461
  { PseudoVLSSEG5E16_V_MF4, VLSSEG5E16_V }, // 3462
  { PseudoVLSSEG5E16_V_MF4_MASK, VLSSEG5E16_V }, // 3463
  { PseudoVLSSEG5E32_V_M1, VLSSEG5E32_V }, // 3464
  { PseudoVLSSEG5E32_V_M1_MASK, VLSSEG5E32_V }, // 3465
  { PseudoVLSSEG5E32_V_MF2, VLSSEG5E32_V }, // 3466
  { PseudoVLSSEG5E32_V_MF2_MASK, VLSSEG5E32_V }, // 3467
  { PseudoVLSSEG5E64_V_M1, VLSSEG5E64_V }, // 3468
  { PseudoVLSSEG5E64_V_M1_MASK, VLSSEG5E64_V }, // 3469
  { PseudoVLSSEG5E8_V_M1, VLSSEG5E8_V }, // 3470
  { PseudoVLSSEG5E8_V_M1_MASK, VLSSEG5E8_V }, // 3471
  { PseudoVLSSEG5E8_V_MF2, VLSSEG5E8_V }, // 3472
  { PseudoVLSSEG5E8_V_MF2_MASK, VLSSEG5E8_V }, // 3473
  { PseudoVLSSEG5E8_V_MF4, VLSSEG5E8_V }, // 3474
  { PseudoVLSSEG5E8_V_MF4_MASK, VLSSEG5E8_V }, // 3475
  { PseudoVLSSEG5E8_V_MF8, VLSSEG5E8_V }, // 3476
  { PseudoVLSSEG5E8_V_MF8_MASK, VLSSEG5E8_V }, // 3477
  { PseudoVLSSEG6E16_V_M1, VLSSEG6E16_V }, // 3478
  { PseudoVLSSEG6E16_V_M1_MASK, VLSSEG6E16_V }, // 3479
  { PseudoVLSSEG6E16_V_MF2, VLSSEG6E16_V }, // 3480
  { PseudoVLSSEG6E16_V_MF2_MASK, VLSSEG6E16_V }, // 3481
  { PseudoVLSSEG6E16_V_MF4, VLSSEG6E16_V }, // 3482
  { PseudoVLSSEG6E16_V_MF4_MASK, VLSSEG6E16_V }, // 3483
  { PseudoVLSSEG6E32_V_M1, VLSSEG6E32_V }, // 3484
  { PseudoVLSSEG6E32_V_M1_MASK, VLSSEG6E32_V }, // 3485
  { PseudoVLSSEG6E32_V_MF2, VLSSEG6E32_V }, // 3486
  { PseudoVLSSEG6E32_V_MF2_MASK, VLSSEG6E32_V }, // 3487
  { PseudoVLSSEG6E64_V_M1, VLSSEG6E64_V }, // 3488
  { PseudoVLSSEG6E64_V_M1_MASK, VLSSEG6E64_V }, // 3489
  { PseudoVLSSEG6E8_V_M1, VLSSEG6E8_V }, // 3490
  { PseudoVLSSEG6E8_V_M1_MASK, VLSSEG6E8_V }, // 3491
  { PseudoVLSSEG6E8_V_MF2, VLSSEG6E8_V }, // 3492
  { PseudoVLSSEG6E8_V_MF2_MASK, VLSSEG6E8_V }, // 3493
  { PseudoVLSSEG6E8_V_MF4, VLSSEG6E8_V }, // 3494
  { PseudoVLSSEG6E8_V_MF4_MASK, VLSSEG6E8_V }, // 3495
  { PseudoVLSSEG6E8_V_MF8, VLSSEG6E8_V }, // 3496
  { PseudoVLSSEG6E8_V_MF8_MASK, VLSSEG6E8_V }, // 3497
  { PseudoVLSSEG7E16_V_M1, VLSSEG7E16_V }, // 3498
  { PseudoVLSSEG7E16_V_M1_MASK, VLSSEG7E16_V }, // 3499
  { PseudoVLSSEG7E16_V_MF2, VLSSEG7E16_V }, // 3500
  { PseudoVLSSEG7E16_V_MF2_MASK, VLSSEG7E16_V }, // 3501
  { PseudoVLSSEG7E16_V_MF4, VLSSEG7E16_V }, // 3502
  { PseudoVLSSEG7E16_V_MF4_MASK, VLSSEG7E16_V }, // 3503
  { PseudoVLSSEG7E32_V_M1, VLSSEG7E32_V }, // 3504
  { PseudoVLSSEG7E32_V_M1_MASK, VLSSEG7E32_V }, // 3505
  { PseudoVLSSEG7E32_V_MF2, VLSSEG7E32_V }, // 3506
  { PseudoVLSSEG7E32_V_MF2_MASK, VLSSEG7E32_V }, // 3507
  { PseudoVLSSEG7E64_V_M1, VLSSEG7E64_V }, // 3508
  { PseudoVLSSEG7E64_V_M1_MASK, VLSSEG7E64_V }, // 3509
  { PseudoVLSSEG7E8_V_M1, VLSSEG7E8_V }, // 3510
  { PseudoVLSSEG7E8_V_M1_MASK, VLSSEG7E8_V }, // 3511
  { PseudoVLSSEG7E8_V_MF2, VLSSEG7E8_V }, // 3512
  { PseudoVLSSEG7E8_V_MF2_MASK, VLSSEG7E8_V }, // 3513
  { PseudoVLSSEG7E8_V_MF4, VLSSEG7E8_V }, // 3514
  { PseudoVLSSEG7E8_V_MF4_MASK, VLSSEG7E8_V }, // 3515
  { PseudoVLSSEG7E8_V_MF8, VLSSEG7E8_V }, // 3516
  { PseudoVLSSEG7E8_V_MF8_MASK, VLSSEG7E8_V }, // 3517
  { PseudoVLSSEG8E16_V_M1, VLSSEG8E16_V }, // 3518
  { PseudoVLSSEG8E16_V_M1_MASK, VLSSEG8E16_V }, // 3519
  { PseudoVLSSEG8E16_V_MF2, VLSSEG8E16_V }, // 3520
  { PseudoVLSSEG8E16_V_MF2_MASK, VLSSEG8E16_V }, // 3521
  { PseudoVLSSEG8E16_V_MF4, VLSSEG8E16_V }, // 3522
  { PseudoVLSSEG8E16_V_MF4_MASK, VLSSEG8E16_V }, // 3523
  { PseudoVLSSEG8E32_V_M1, VLSSEG8E32_V }, // 3524
  { PseudoVLSSEG8E32_V_M1_MASK, VLSSEG8E32_V }, // 3525
  { PseudoVLSSEG8E32_V_MF2, VLSSEG8E32_V }, // 3526
  { PseudoVLSSEG8E32_V_MF2_MASK, VLSSEG8E32_V }, // 3527
  { PseudoVLSSEG8E64_V_M1, VLSSEG8E64_V }, // 3528
  { PseudoVLSSEG8E64_V_M1_MASK, VLSSEG8E64_V }, // 3529
  { PseudoVLSSEG8E8_V_M1, VLSSEG8E8_V }, // 3530
  { PseudoVLSSEG8E8_V_M1_MASK, VLSSEG8E8_V }, // 3531
  { PseudoVLSSEG8E8_V_MF2, VLSSEG8E8_V }, // 3532
  { PseudoVLSSEG8E8_V_MF2_MASK, VLSSEG8E8_V }, // 3533
  { PseudoVLSSEG8E8_V_MF4, VLSSEG8E8_V }, // 3534
  { PseudoVLSSEG8E8_V_MF4_MASK, VLSSEG8E8_V }, // 3535
  { PseudoVLSSEG8E8_V_MF8, VLSSEG8E8_V }, // 3536
  { PseudoVLSSEG8E8_V_MF8_MASK, VLSSEG8E8_V }, // 3537
  { PseudoVLUXEI16_V_M1_M1, VLUXEI16_V }, // 3538
  { PseudoVLUXEI16_V_M1_M1_MASK, VLUXEI16_V }, // 3539
  { PseudoVLUXEI16_V_M1_M1_TU, VLUXEI16_V }, // 3540
  { PseudoVLUXEI16_V_M1_M2, VLUXEI16_V }, // 3541
  { PseudoVLUXEI16_V_M1_M2_MASK, VLUXEI16_V }, // 3542
  { PseudoVLUXEI16_V_M1_M2_TU, VLUXEI16_V }, // 3543
  { PseudoVLUXEI16_V_M1_M4, VLUXEI16_V }, // 3544
  { PseudoVLUXEI16_V_M1_M4_MASK, VLUXEI16_V }, // 3545
  { PseudoVLUXEI16_V_M1_M4_TU, VLUXEI16_V }, // 3546
  { PseudoVLUXEI16_V_M1_MF2, VLUXEI16_V }, // 3547
  { PseudoVLUXEI16_V_M1_MF2_MASK, VLUXEI16_V }, // 3548
  { PseudoVLUXEI16_V_M1_MF2_TU, VLUXEI16_V }, // 3549
  { PseudoVLUXEI16_V_M2_M1, VLUXEI16_V }, // 3550
  { PseudoVLUXEI16_V_M2_M1_MASK, VLUXEI16_V }, // 3551
  { PseudoVLUXEI16_V_M2_M1_TU, VLUXEI16_V }, // 3552
  { PseudoVLUXEI16_V_M2_M2, VLUXEI16_V }, // 3553
  { PseudoVLUXEI16_V_M2_M2_MASK, VLUXEI16_V }, // 3554
  { PseudoVLUXEI16_V_M2_M2_TU, VLUXEI16_V }, // 3555
  { PseudoVLUXEI16_V_M2_M4, VLUXEI16_V }, // 3556
  { PseudoVLUXEI16_V_M2_M4_MASK, VLUXEI16_V }, // 3557
  { PseudoVLUXEI16_V_M2_M4_TU, VLUXEI16_V }, // 3558
  { PseudoVLUXEI16_V_M2_M8, VLUXEI16_V }, // 3559
  { PseudoVLUXEI16_V_M2_M8_MASK, VLUXEI16_V }, // 3560
  { PseudoVLUXEI16_V_M2_M8_TU, VLUXEI16_V }, // 3561
  { PseudoVLUXEI16_V_M4_M2, VLUXEI16_V }, // 3562
  { PseudoVLUXEI16_V_M4_M2_MASK, VLUXEI16_V }, // 3563
  { PseudoVLUXEI16_V_M4_M2_TU, VLUXEI16_V }, // 3564
  { PseudoVLUXEI16_V_M4_M4, VLUXEI16_V }, // 3565
  { PseudoVLUXEI16_V_M4_M4_MASK, VLUXEI16_V }, // 3566
  { PseudoVLUXEI16_V_M4_M4_TU, VLUXEI16_V }, // 3567
  { PseudoVLUXEI16_V_M4_M8, VLUXEI16_V }, // 3568
  { PseudoVLUXEI16_V_M4_M8_MASK, VLUXEI16_V }, // 3569
  { PseudoVLUXEI16_V_M4_M8_TU, VLUXEI16_V }, // 3570
  { PseudoVLUXEI16_V_M8_M4, VLUXEI16_V }, // 3571
  { PseudoVLUXEI16_V_M8_M4_MASK, VLUXEI16_V }, // 3572
  { PseudoVLUXEI16_V_M8_M4_TU, VLUXEI16_V }, // 3573
  { PseudoVLUXEI16_V_M8_M8, VLUXEI16_V }, // 3574
  { PseudoVLUXEI16_V_M8_M8_MASK, VLUXEI16_V }, // 3575
  { PseudoVLUXEI16_V_M8_M8_TU, VLUXEI16_V }, // 3576
  { PseudoVLUXEI16_V_MF2_M1, VLUXEI16_V }, // 3577
  { PseudoVLUXEI16_V_MF2_M1_MASK, VLUXEI16_V }, // 3578
  { PseudoVLUXEI16_V_MF2_M1_TU, VLUXEI16_V }, // 3579
  { PseudoVLUXEI16_V_MF2_M2, VLUXEI16_V }, // 3580
  { PseudoVLUXEI16_V_MF2_M2_MASK, VLUXEI16_V }, // 3581
  { PseudoVLUXEI16_V_MF2_M2_TU, VLUXEI16_V }, // 3582
  { PseudoVLUXEI16_V_MF2_MF2, VLUXEI16_V }, // 3583
  { PseudoVLUXEI16_V_MF2_MF2_MASK, VLUXEI16_V }, // 3584
  { PseudoVLUXEI16_V_MF2_MF2_TU, VLUXEI16_V }, // 3585
  { PseudoVLUXEI16_V_MF2_MF4, VLUXEI16_V }, // 3586
  { PseudoVLUXEI16_V_MF2_MF4_MASK, VLUXEI16_V }, // 3587
  { PseudoVLUXEI16_V_MF2_MF4_TU, VLUXEI16_V }, // 3588
  { PseudoVLUXEI16_V_MF4_M1, VLUXEI16_V }, // 3589
  { PseudoVLUXEI16_V_MF4_M1_MASK, VLUXEI16_V }, // 3590
  { PseudoVLUXEI16_V_MF4_M1_TU, VLUXEI16_V }, // 3591
  { PseudoVLUXEI16_V_MF4_MF2, VLUXEI16_V }, // 3592
  { PseudoVLUXEI16_V_MF4_MF2_MASK, VLUXEI16_V }, // 3593
  { PseudoVLUXEI16_V_MF4_MF2_TU, VLUXEI16_V }, // 3594
  { PseudoVLUXEI16_V_MF4_MF4, VLUXEI16_V }, // 3595
  { PseudoVLUXEI16_V_MF4_MF4_MASK, VLUXEI16_V }, // 3596
  { PseudoVLUXEI16_V_MF4_MF4_TU, VLUXEI16_V }, // 3597
  { PseudoVLUXEI16_V_MF4_MF8, VLUXEI16_V }, // 3598
  { PseudoVLUXEI16_V_MF4_MF8_MASK, VLUXEI16_V }, // 3599
  { PseudoVLUXEI16_V_MF4_MF8_TU, VLUXEI16_V }, // 3600
  { PseudoVLUXEI32_V_M1_M1, VLUXEI32_V }, // 3601
  { PseudoVLUXEI32_V_M1_M1_MASK, VLUXEI32_V }, // 3602
  { PseudoVLUXEI32_V_M1_M1_TU, VLUXEI32_V }, // 3603
  { PseudoVLUXEI32_V_M1_M2, VLUXEI32_V }, // 3604
  { PseudoVLUXEI32_V_M1_M2_MASK, VLUXEI32_V }, // 3605
  { PseudoVLUXEI32_V_M1_M2_TU, VLUXEI32_V }, // 3606
  { PseudoVLUXEI32_V_M1_MF2, VLUXEI32_V }, // 3607
  { PseudoVLUXEI32_V_M1_MF2_MASK, VLUXEI32_V }, // 3608
  { PseudoVLUXEI32_V_M1_MF2_TU, VLUXEI32_V }, // 3609
  { PseudoVLUXEI32_V_M1_MF4, VLUXEI32_V }, // 3610
  { PseudoVLUXEI32_V_M1_MF4_MASK, VLUXEI32_V }, // 3611
  { PseudoVLUXEI32_V_M1_MF4_TU, VLUXEI32_V }, // 3612
  { PseudoVLUXEI32_V_M2_M1, VLUXEI32_V }, // 3613
  { PseudoVLUXEI32_V_M2_M1_MASK, VLUXEI32_V }, // 3614
  { PseudoVLUXEI32_V_M2_M1_TU, VLUXEI32_V }, // 3615
  { PseudoVLUXEI32_V_M2_M2, VLUXEI32_V }, // 3616
  { PseudoVLUXEI32_V_M2_M2_MASK, VLUXEI32_V }, // 3617
  { PseudoVLUXEI32_V_M2_M2_TU, VLUXEI32_V }, // 3618
  { PseudoVLUXEI32_V_M2_M4, VLUXEI32_V }, // 3619
  { PseudoVLUXEI32_V_M2_M4_MASK, VLUXEI32_V }, // 3620
  { PseudoVLUXEI32_V_M2_M4_TU, VLUXEI32_V }, // 3621
  { PseudoVLUXEI32_V_M2_MF2, VLUXEI32_V }, // 3622
  { PseudoVLUXEI32_V_M2_MF2_MASK, VLUXEI32_V }, // 3623
  { PseudoVLUXEI32_V_M2_MF2_TU, VLUXEI32_V }, // 3624
  { PseudoVLUXEI32_V_M4_M1, VLUXEI32_V }, // 3625
  { PseudoVLUXEI32_V_M4_M1_MASK, VLUXEI32_V }, // 3626
  { PseudoVLUXEI32_V_M4_M1_TU, VLUXEI32_V }, // 3627
  { PseudoVLUXEI32_V_M4_M2, VLUXEI32_V }, // 3628
  { PseudoVLUXEI32_V_M4_M2_MASK, VLUXEI32_V }, // 3629
  { PseudoVLUXEI32_V_M4_M2_TU, VLUXEI32_V }, // 3630
  { PseudoVLUXEI32_V_M4_M4, VLUXEI32_V }, // 3631
  { PseudoVLUXEI32_V_M4_M4_MASK, VLUXEI32_V }, // 3632
  { PseudoVLUXEI32_V_M4_M4_TU, VLUXEI32_V }, // 3633
  { PseudoVLUXEI32_V_M4_M8, VLUXEI32_V }, // 3634
  { PseudoVLUXEI32_V_M4_M8_MASK, VLUXEI32_V }, // 3635
  { PseudoVLUXEI32_V_M4_M8_TU, VLUXEI32_V }, // 3636
  { PseudoVLUXEI32_V_M8_M2, VLUXEI32_V }, // 3637
  { PseudoVLUXEI32_V_M8_M2_MASK, VLUXEI32_V }, // 3638
  { PseudoVLUXEI32_V_M8_M2_TU, VLUXEI32_V }, // 3639
  { PseudoVLUXEI32_V_M8_M4, VLUXEI32_V }, // 3640
  { PseudoVLUXEI32_V_M8_M4_MASK, VLUXEI32_V }, // 3641
  { PseudoVLUXEI32_V_M8_M4_TU, VLUXEI32_V }, // 3642
  { PseudoVLUXEI32_V_M8_M8, VLUXEI32_V }, // 3643
  { PseudoVLUXEI32_V_M8_M8_MASK, VLUXEI32_V }, // 3644
  { PseudoVLUXEI32_V_M8_M8_TU, VLUXEI32_V }, // 3645
  { PseudoVLUXEI32_V_MF2_M1, VLUXEI32_V }, // 3646
  { PseudoVLUXEI32_V_MF2_M1_MASK, VLUXEI32_V }, // 3647
  { PseudoVLUXEI32_V_MF2_M1_TU, VLUXEI32_V }, // 3648
  { PseudoVLUXEI32_V_MF2_MF2, VLUXEI32_V }, // 3649
  { PseudoVLUXEI32_V_MF2_MF2_MASK, VLUXEI32_V }, // 3650
  { PseudoVLUXEI32_V_MF2_MF2_TU, VLUXEI32_V }, // 3651
  { PseudoVLUXEI32_V_MF2_MF4, VLUXEI32_V }, // 3652
  { PseudoVLUXEI32_V_MF2_MF4_MASK, VLUXEI32_V }, // 3653
  { PseudoVLUXEI32_V_MF2_MF4_TU, VLUXEI32_V }, // 3654
  { PseudoVLUXEI32_V_MF2_MF8, VLUXEI32_V }, // 3655
  { PseudoVLUXEI32_V_MF2_MF8_MASK, VLUXEI32_V }, // 3656
  { PseudoVLUXEI32_V_MF2_MF8_TU, VLUXEI32_V }, // 3657
  { PseudoVLUXEI64_V_M1_M1, VLUXEI64_V }, // 3658
  { PseudoVLUXEI64_V_M1_M1_MASK, VLUXEI64_V }, // 3659
  { PseudoVLUXEI64_V_M1_M1_TU, VLUXEI64_V }, // 3660
  { PseudoVLUXEI64_V_M1_MF2, VLUXEI64_V }, // 3661
  { PseudoVLUXEI64_V_M1_MF2_MASK, VLUXEI64_V }, // 3662
  { PseudoVLUXEI64_V_M1_MF2_TU, VLUXEI64_V }, // 3663
  { PseudoVLUXEI64_V_M1_MF4, VLUXEI64_V }, // 3664
  { PseudoVLUXEI64_V_M1_MF4_MASK, VLUXEI64_V }, // 3665
  { PseudoVLUXEI64_V_M1_MF4_TU, VLUXEI64_V }, // 3666
  { PseudoVLUXEI64_V_M1_MF8, VLUXEI64_V }, // 3667
  { PseudoVLUXEI64_V_M1_MF8_MASK, VLUXEI64_V }, // 3668
  { PseudoVLUXEI64_V_M1_MF8_TU, VLUXEI64_V }, // 3669
  { PseudoVLUXEI64_V_M2_M1, VLUXEI64_V }, // 3670
  { PseudoVLUXEI64_V_M2_M1_MASK, VLUXEI64_V }, // 3671
  { PseudoVLUXEI64_V_M2_M1_TU, VLUXEI64_V }, // 3672
  { PseudoVLUXEI64_V_M2_M2, VLUXEI64_V }, // 3673
  { PseudoVLUXEI64_V_M2_M2_MASK, VLUXEI64_V }, // 3674
  { PseudoVLUXEI64_V_M2_M2_TU, VLUXEI64_V }, // 3675
  { PseudoVLUXEI64_V_M2_MF2, VLUXEI64_V }, // 3676
  { PseudoVLUXEI64_V_M2_MF2_MASK, VLUXEI64_V }, // 3677
  { PseudoVLUXEI64_V_M2_MF2_TU, VLUXEI64_V }, // 3678
  { PseudoVLUXEI64_V_M2_MF4, VLUXEI64_V }, // 3679
  { PseudoVLUXEI64_V_M2_MF4_MASK, VLUXEI64_V }, // 3680
  { PseudoVLUXEI64_V_M2_MF4_TU, VLUXEI64_V }, // 3681
  { PseudoVLUXEI64_V_M4_M1, VLUXEI64_V }, // 3682
  { PseudoVLUXEI64_V_M4_M1_MASK, VLUXEI64_V }, // 3683
  { PseudoVLUXEI64_V_M4_M1_TU, VLUXEI64_V }, // 3684
  { PseudoVLUXEI64_V_M4_M2, VLUXEI64_V }, // 3685
  { PseudoVLUXEI64_V_M4_M2_MASK, VLUXEI64_V }, // 3686
  { PseudoVLUXEI64_V_M4_M2_TU, VLUXEI64_V }, // 3687
  { PseudoVLUXEI64_V_M4_M4, VLUXEI64_V }, // 3688
  { PseudoVLUXEI64_V_M4_M4_MASK, VLUXEI64_V }, // 3689
  { PseudoVLUXEI64_V_M4_M4_TU, VLUXEI64_V }, // 3690
  { PseudoVLUXEI64_V_M4_MF2, VLUXEI64_V }, // 3691
  { PseudoVLUXEI64_V_M4_MF2_MASK, VLUXEI64_V }, // 3692
  { PseudoVLUXEI64_V_M4_MF2_TU, VLUXEI64_V }, // 3693
  { PseudoVLUXEI64_V_M8_M1, VLUXEI64_V }, // 3694
  { PseudoVLUXEI64_V_M8_M1_MASK, VLUXEI64_V }, // 3695
  { PseudoVLUXEI64_V_M8_M1_TU, VLUXEI64_V }, // 3696
  { PseudoVLUXEI64_V_M8_M2, VLUXEI64_V }, // 3697
  { PseudoVLUXEI64_V_M8_M2_MASK, VLUXEI64_V }, // 3698
  { PseudoVLUXEI64_V_M8_M2_TU, VLUXEI64_V }, // 3699
  { PseudoVLUXEI64_V_M8_M4, VLUXEI64_V }, // 3700
  { PseudoVLUXEI64_V_M8_M4_MASK, VLUXEI64_V }, // 3701
  { PseudoVLUXEI64_V_M8_M4_TU, VLUXEI64_V }, // 3702
  { PseudoVLUXEI64_V_M8_M8, VLUXEI64_V }, // 3703
  { PseudoVLUXEI64_V_M8_M8_MASK, VLUXEI64_V }, // 3704
  { PseudoVLUXEI64_V_M8_M8_TU, VLUXEI64_V }, // 3705
  { PseudoVLUXEI8_V_M1_M1, VLUXEI8_V }, // 3706
  { PseudoVLUXEI8_V_M1_M1_MASK, VLUXEI8_V }, // 3707
  { PseudoVLUXEI8_V_M1_M1_TU, VLUXEI8_V }, // 3708
  { PseudoVLUXEI8_V_M1_M2, VLUXEI8_V }, // 3709
  { PseudoVLUXEI8_V_M1_M2_MASK, VLUXEI8_V }, // 3710
  { PseudoVLUXEI8_V_M1_M2_TU, VLUXEI8_V }, // 3711
  { PseudoVLUXEI8_V_M1_M4, VLUXEI8_V }, // 3712
  { PseudoVLUXEI8_V_M1_M4_MASK, VLUXEI8_V }, // 3713
  { PseudoVLUXEI8_V_M1_M4_TU, VLUXEI8_V }, // 3714
  { PseudoVLUXEI8_V_M1_M8, VLUXEI8_V }, // 3715
  { PseudoVLUXEI8_V_M1_M8_MASK, VLUXEI8_V }, // 3716
  { PseudoVLUXEI8_V_M1_M8_TU, VLUXEI8_V }, // 3717
  { PseudoVLUXEI8_V_M2_M2, VLUXEI8_V }, // 3718
  { PseudoVLUXEI8_V_M2_M2_MASK, VLUXEI8_V }, // 3719
  { PseudoVLUXEI8_V_M2_M2_TU, VLUXEI8_V }, // 3720
  { PseudoVLUXEI8_V_M2_M4, VLUXEI8_V }, // 3721
  { PseudoVLUXEI8_V_M2_M4_MASK, VLUXEI8_V }, // 3722
  { PseudoVLUXEI8_V_M2_M4_TU, VLUXEI8_V }, // 3723
  { PseudoVLUXEI8_V_M2_M8, VLUXEI8_V }, // 3724
  { PseudoVLUXEI8_V_M2_M8_MASK, VLUXEI8_V }, // 3725
  { PseudoVLUXEI8_V_M2_M8_TU, VLUXEI8_V }, // 3726
  { PseudoVLUXEI8_V_M4_M4, VLUXEI8_V }, // 3727
  { PseudoVLUXEI8_V_M4_M4_MASK, VLUXEI8_V }, // 3728
  { PseudoVLUXEI8_V_M4_M4_TU, VLUXEI8_V }, // 3729
  { PseudoVLUXEI8_V_M4_M8, VLUXEI8_V }, // 3730
  { PseudoVLUXEI8_V_M4_M8_MASK, VLUXEI8_V }, // 3731
  { PseudoVLUXEI8_V_M4_M8_TU, VLUXEI8_V }, // 3732
  { PseudoVLUXEI8_V_M8_M8, VLUXEI8_V }, // 3733
  { PseudoVLUXEI8_V_M8_M8_MASK, VLUXEI8_V }, // 3734
  { PseudoVLUXEI8_V_M8_M8_TU, VLUXEI8_V }, // 3735
  { PseudoVLUXEI8_V_MF2_M1, VLUXEI8_V }, // 3736
  { PseudoVLUXEI8_V_MF2_M1_MASK, VLUXEI8_V }, // 3737
  { PseudoVLUXEI8_V_MF2_M1_TU, VLUXEI8_V }, // 3738
  { PseudoVLUXEI8_V_MF2_M2, VLUXEI8_V }, // 3739
  { PseudoVLUXEI8_V_MF2_M2_MASK, VLUXEI8_V }, // 3740
  { PseudoVLUXEI8_V_MF2_M2_TU, VLUXEI8_V }, // 3741
  { PseudoVLUXEI8_V_MF2_M4, VLUXEI8_V }, // 3742
  { PseudoVLUXEI8_V_MF2_M4_MASK, VLUXEI8_V }, // 3743
  { PseudoVLUXEI8_V_MF2_M4_TU, VLUXEI8_V }, // 3744
  { PseudoVLUXEI8_V_MF2_MF2, VLUXEI8_V }, // 3745
  { PseudoVLUXEI8_V_MF2_MF2_MASK, VLUXEI8_V }, // 3746
  { PseudoVLUXEI8_V_MF2_MF2_TU, VLUXEI8_V }, // 3747
  { PseudoVLUXEI8_V_MF4_M1, VLUXEI8_V }, // 3748
  { PseudoVLUXEI8_V_MF4_M1_MASK, VLUXEI8_V }, // 3749
  { PseudoVLUXEI8_V_MF4_M1_TU, VLUXEI8_V }, // 3750
  { PseudoVLUXEI8_V_MF4_M2, VLUXEI8_V }, // 3751
  { PseudoVLUXEI8_V_MF4_M2_MASK, VLUXEI8_V }, // 3752
  { PseudoVLUXEI8_V_MF4_M2_TU, VLUXEI8_V }, // 3753
  { PseudoVLUXEI8_V_MF4_MF2, VLUXEI8_V }, // 3754
  { PseudoVLUXEI8_V_MF4_MF2_MASK, VLUXEI8_V }, // 3755
  { PseudoVLUXEI8_V_MF4_MF2_TU, VLUXEI8_V }, // 3756
  { PseudoVLUXEI8_V_MF4_MF4, VLUXEI8_V }, // 3757
  { PseudoVLUXEI8_V_MF4_MF4_MASK, VLUXEI8_V }, // 3758
  { PseudoVLUXEI8_V_MF4_MF4_TU, VLUXEI8_V }, // 3759
  { PseudoVLUXEI8_V_MF8_M1, VLUXEI8_V }, // 3760
  { PseudoVLUXEI8_V_MF8_M1_MASK, VLUXEI8_V }, // 3761
  { PseudoVLUXEI8_V_MF8_M1_TU, VLUXEI8_V }, // 3762
  { PseudoVLUXEI8_V_MF8_MF2, VLUXEI8_V }, // 3763
  { PseudoVLUXEI8_V_MF8_MF2_MASK, VLUXEI8_V }, // 3764
  { PseudoVLUXEI8_V_MF8_MF2_TU, VLUXEI8_V }, // 3765
  { PseudoVLUXEI8_V_MF8_MF4, VLUXEI8_V }, // 3766
  { PseudoVLUXEI8_V_MF8_MF4_MASK, VLUXEI8_V }, // 3767
  { PseudoVLUXEI8_V_MF8_MF4_TU, VLUXEI8_V }, // 3768
  { PseudoVLUXEI8_V_MF8_MF8, VLUXEI8_V }, // 3769
  { PseudoVLUXEI8_V_MF8_MF8_MASK, VLUXEI8_V }, // 3770
  { PseudoVLUXEI8_V_MF8_MF8_TU, VLUXEI8_V }, // 3771
  { PseudoVLUXSEG2EI16_V_M1_M1, VLUXSEG2EI16_V }, // 3772
  { PseudoVLUXSEG2EI16_V_M1_M1_MASK, VLUXSEG2EI16_V }, // 3773
  { PseudoVLUXSEG2EI16_V_M1_M2, VLUXSEG2EI16_V }, // 3774
  { PseudoVLUXSEG2EI16_V_M1_M2_MASK, VLUXSEG2EI16_V }, // 3775
  { PseudoVLUXSEG2EI16_V_M1_M4, VLUXSEG2EI16_V }, // 3776
  { PseudoVLUXSEG2EI16_V_M1_M4_MASK, VLUXSEG2EI16_V }, // 3777
  { PseudoVLUXSEG2EI16_V_M1_MF2, VLUXSEG2EI16_V }, // 3778
  { PseudoVLUXSEG2EI16_V_M1_MF2_MASK, VLUXSEG2EI16_V }, // 3779
  { PseudoVLUXSEG2EI16_V_M2_M1, VLUXSEG2EI16_V }, // 3780
  { PseudoVLUXSEG2EI16_V_M2_M1_MASK, VLUXSEG2EI16_V }, // 3781
  { PseudoVLUXSEG2EI16_V_M2_M2, VLUXSEG2EI16_V }, // 3782
  { PseudoVLUXSEG2EI16_V_M2_M2_MASK, VLUXSEG2EI16_V }, // 3783
  { PseudoVLUXSEG2EI16_V_M2_M4, VLUXSEG2EI16_V }, // 3784
  { PseudoVLUXSEG2EI16_V_M2_M4_MASK, VLUXSEG2EI16_V }, // 3785
  { PseudoVLUXSEG2EI16_V_M4_M2, VLUXSEG2EI16_V }, // 3786
  { PseudoVLUXSEG2EI16_V_M4_M2_MASK, VLUXSEG2EI16_V }, // 3787
  { PseudoVLUXSEG2EI16_V_M4_M4, VLUXSEG2EI16_V }, // 3788
  { PseudoVLUXSEG2EI16_V_M4_M4_MASK, VLUXSEG2EI16_V }, // 3789
  { PseudoVLUXSEG2EI16_V_M8_M4, VLUXSEG2EI16_V }, // 3790
  { PseudoVLUXSEG2EI16_V_M8_M4_MASK, VLUXSEG2EI16_V }, // 3791
  { PseudoVLUXSEG2EI16_V_MF2_M1, VLUXSEG2EI16_V }, // 3792
  { PseudoVLUXSEG2EI16_V_MF2_M1_MASK, VLUXSEG2EI16_V }, // 3793
  { PseudoVLUXSEG2EI16_V_MF2_M2, VLUXSEG2EI16_V }, // 3794
  { PseudoVLUXSEG2EI16_V_MF2_M2_MASK, VLUXSEG2EI16_V }, // 3795
  { PseudoVLUXSEG2EI16_V_MF2_MF2, VLUXSEG2EI16_V }, // 3796
  { PseudoVLUXSEG2EI16_V_MF2_MF2_MASK, VLUXSEG2EI16_V }, // 3797
  { PseudoVLUXSEG2EI16_V_MF2_MF4, VLUXSEG2EI16_V }, // 3798
  { PseudoVLUXSEG2EI16_V_MF2_MF4_MASK, VLUXSEG2EI16_V }, // 3799
  { PseudoVLUXSEG2EI16_V_MF4_M1, VLUXSEG2EI16_V }, // 3800
  { PseudoVLUXSEG2EI16_V_MF4_M1_MASK, VLUXSEG2EI16_V }, // 3801
  { PseudoVLUXSEG2EI16_V_MF4_MF2, VLUXSEG2EI16_V }, // 3802
  { PseudoVLUXSEG2EI16_V_MF4_MF2_MASK, VLUXSEG2EI16_V }, // 3803
  { PseudoVLUXSEG2EI16_V_MF4_MF4, VLUXSEG2EI16_V }, // 3804
  { PseudoVLUXSEG2EI16_V_MF4_MF4_MASK, VLUXSEG2EI16_V }, // 3805
  { PseudoVLUXSEG2EI16_V_MF4_MF8, VLUXSEG2EI16_V }, // 3806
  { PseudoVLUXSEG2EI16_V_MF4_MF8_MASK, VLUXSEG2EI16_V }, // 3807
  { PseudoVLUXSEG2EI32_V_M1_M1, VLUXSEG2EI32_V }, // 3808
  { PseudoVLUXSEG2EI32_V_M1_M1_MASK, VLUXSEG2EI32_V }, // 3809
  { PseudoVLUXSEG2EI32_V_M1_M2, VLUXSEG2EI32_V }, // 3810
  { PseudoVLUXSEG2EI32_V_M1_M2_MASK, VLUXSEG2EI32_V }, // 3811
  { PseudoVLUXSEG2EI32_V_M1_MF2, VLUXSEG2EI32_V }, // 3812
  { PseudoVLUXSEG2EI32_V_M1_MF2_MASK, VLUXSEG2EI32_V }, // 3813
  { PseudoVLUXSEG2EI32_V_M1_MF4, VLUXSEG2EI32_V }, // 3814
  { PseudoVLUXSEG2EI32_V_M1_MF4_MASK, VLUXSEG2EI32_V }, // 3815
  { PseudoVLUXSEG2EI32_V_M2_M1, VLUXSEG2EI32_V }, // 3816
  { PseudoVLUXSEG2EI32_V_M2_M1_MASK, VLUXSEG2EI32_V }, // 3817
  { PseudoVLUXSEG2EI32_V_M2_M2, VLUXSEG2EI32_V }, // 3818
  { PseudoVLUXSEG2EI32_V_M2_M2_MASK, VLUXSEG2EI32_V }, // 3819
  { PseudoVLUXSEG2EI32_V_M2_M4, VLUXSEG2EI32_V }, // 3820
  { PseudoVLUXSEG2EI32_V_M2_M4_MASK, VLUXSEG2EI32_V }, // 3821
  { PseudoVLUXSEG2EI32_V_M2_MF2, VLUXSEG2EI32_V }, // 3822
  { PseudoVLUXSEG2EI32_V_M2_MF2_MASK, VLUXSEG2EI32_V }, // 3823
  { PseudoVLUXSEG2EI32_V_M4_M1, VLUXSEG2EI32_V }, // 3824
  { PseudoVLUXSEG2EI32_V_M4_M1_MASK, VLUXSEG2EI32_V }, // 3825
  { PseudoVLUXSEG2EI32_V_M4_M2, VLUXSEG2EI32_V }, // 3826
  { PseudoVLUXSEG2EI32_V_M4_M2_MASK, VLUXSEG2EI32_V }, // 3827
  { PseudoVLUXSEG2EI32_V_M4_M4, VLUXSEG2EI32_V }, // 3828
  { PseudoVLUXSEG2EI32_V_M4_M4_MASK, VLUXSEG2EI32_V }, // 3829
  { PseudoVLUXSEG2EI32_V_M8_M2, VLUXSEG2EI32_V }, // 3830
  { PseudoVLUXSEG2EI32_V_M8_M2_MASK, VLUXSEG2EI32_V }, // 3831
  { PseudoVLUXSEG2EI32_V_M8_M4, VLUXSEG2EI32_V }, // 3832
  { PseudoVLUXSEG2EI32_V_M8_M4_MASK, VLUXSEG2EI32_V }, // 3833
  { PseudoVLUXSEG2EI32_V_MF2_M1, VLUXSEG2EI32_V }, // 3834
  { PseudoVLUXSEG2EI32_V_MF2_M1_MASK, VLUXSEG2EI32_V }, // 3835
  { PseudoVLUXSEG2EI32_V_MF2_MF2, VLUXSEG2EI32_V }, // 3836
  { PseudoVLUXSEG2EI32_V_MF2_MF2_MASK, VLUXSEG2EI32_V }, // 3837
  { PseudoVLUXSEG2EI32_V_MF2_MF4, VLUXSEG2EI32_V }, // 3838
  { PseudoVLUXSEG2EI32_V_MF2_MF4_MASK, VLUXSEG2EI32_V }, // 3839
  { PseudoVLUXSEG2EI32_V_MF2_MF8, VLUXSEG2EI32_V }, // 3840
  { PseudoVLUXSEG2EI32_V_MF2_MF8_MASK, VLUXSEG2EI32_V }, // 3841
  { PseudoVLUXSEG2EI64_V_M1_M1, VLUXSEG2EI64_V }, // 3842
  { PseudoVLUXSEG2EI64_V_M1_M1_MASK, VLUXSEG2EI64_V }, // 3843
  { PseudoVLUXSEG2EI64_V_M1_MF2, VLUXSEG2EI64_V }, // 3844
  { PseudoVLUXSEG2EI64_V_M1_MF2_MASK, VLUXSEG2EI64_V }, // 3845
  { PseudoVLUXSEG2EI64_V_M1_MF4, VLUXSEG2EI64_V }, // 3846
  { PseudoVLUXSEG2EI64_V_M1_MF4_MASK, VLUXSEG2EI64_V }, // 3847
  { PseudoVLUXSEG2EI64_V_M1_MF8, VLUXSEG2EI64_V }, // 3848
  { PseudoVLUXSEG2EI64_V_M1_MF8_MASK, VLUXSEG2EI64_V }, // 3849
  { PseudoVLUXSEG2EI64_V_M2_M1, VLUXSEG2EI64_V }, // 3850
  { PseudoVLUXSEG2EI64_V_M2_M1_MASK, VLUXSEG2EI64_V }, // 3851
  { PseudoVLUXSEG2EI64_V_M2_M2, VLUXSEG2EI64_V }, // 3852
  { PseudoVLUXSEG2EI64_V_M2_M2_MASK, VLUXSEG2EI64_V }, // 3853
  { PseudoVLUXSEG2EI64_V_M2_MF2, VLUXSEG2EI64_V }, // 3854
  { PseudoVLUXSEG2EI64_V_M2_MF2_MASK, VLUXSEG2EI64_V }, // 3855
  { PseudoVLUXSEG2EI64_V_M2_MF4, VLUXSEG2EI64_V }, // 3856
  { PseudoVLUXSEG2EI64_V_M2_MF4_MASK, VLUXSEG2EI64_V }, // 3857
  { PseudoVLUXSEG2EI64_V_M4_M1, VLUXSEG2EI64_V }, // 3858
  { PseudoVLUXSEG2EI64_V_M4_M1_MASK, VLUXSEG2EI64_V }, // 3859
  { PseudoVLUXSEG2EI64_V_M4_M2, VLUXSEG2EI64_V }, // 3860
  { PseudoVLUXSEG2EI64_V_M4_M2_MASK, VLUXSEG2EI64_V }, // 3861
  { PseudoVLUXSEG2EI64_V_M4_M4, VLUXSEG2EI64_V }, // 3862
  { PseudoVLUXSEG2EI64_V_M4_M4_MASK, VLUXSEG2EI64_V }, // 3863
  { PseudoVLUXSEG2EI64_V_M4_MF2, VLUXSEG2EI64_V }, // 3864
  { PseudoVLUXSEG2EI64_V_M4_MF2_MASK, VLUXSEG2EI64_V }, // 3865
  { PseudoVLUXSEG2EI64_V_M8_M1, VLUXSEG2EI64_V }, // 3866
  { PseudoVLUXSEG2EI64_V_M8_M1_MASK, VLUXSEG2EI64_V }, // 3867
  { PseudoVLUXSEG2EI64_V_M8_M2, VLUXSEG2EI64_V }, // 3868
  { PseudoVLUXSEG2EI64_V_M8_M2_MASK, VLUXSEG2EI64_V }, // 3869
  { PseudoVLUXSEG2EI64_V_M8_M4, VLUXSEG2EI64_V }, // 3870
  { PseudoVLUXSEG2EI64_V_M8_M4_MASK, VLUXSEG2EI64_V }, // 3871
  { PseudoVLUXSEG2EI8_V_M1_M1, VLUXSEG2EI8_V }, // 3872
  { PseudoVLUXSEG2EI8_V_M1_M1_MASK, VLUXSEG2EI8_V }, // 3873
  { PseudoVLUXSEG2EI8_V_M1_M2, VLUXSEG2EI8_V }, // 3874
  { PseudoVLUXSEG2EI8_V_M1_M2_MASK, VLUXSEG2EI8_V }, // 3875
  { PseudoVLUXSEG2EI8_V_M1_M4, VLUXSEG2EI8_V }, // 3876
  { PseudoVLUXSEG2EI8_V_M1_M4_MASK, VLUXSEG2EI8_V }, // 3877
  { PseudoVLUXSEG2EI8_V_M2_M2, VLUXSEG2EI8_V }, // 3878
  { PseudoVLUXSEG2EI8_V_M2_M2_MASK, VLUXSEG2EI8_V }, // 3879
  { PseudoVLUXSEG2EI8_V_M2_M4, VLUXSEG2EI8_V }, // 3880
  { PseudoVLUXSEG2EI8_V_M2_M4_MASK, VLUXSEG2EI8_V }, // 3881
  { PseudoVLUXSEG2EI8_V_M4_M4, VLUXSEG2EI8_V }, // 3882
  { PseudoVLUXSEG2EI8_V_M4_M4_MASK, VLUXSEG2EI8_V }, // 3883
  { PseudoVLUXSEG2EI8_V_MF2_M1, VLUXSEG2EI8_V }, // 3884
  { PseudoVLUXSEG2EI8_V_MF2_M1_MASK, VLUXSEG2EI8_V }, // 3885
  { PseudoVLUXSEG2EI8_V_MF2_M2, VLUXSEG2EI8_V }, // 3886
  { PseudoVLUXSEG2EI8_V_MF2_M2_MASK, VLUXSEG2EI8_V }, // 3887
  { PseudoVLUXSEG2EI8_V_MF2_M4, VLUXSEG2EI8_V }, // 3888
  { PseudoVLUXSEG2EI8_V_MF2_M4_MASK, VLUXSEG2EI8_V }, // 3889
  { PseudoVLUXSEG2EI8_V_MF2_MF2, VLUXSEG2EI8_V }, // 3890
  { PseudoVLUXSEG2EI8_V_MF2_MF2_MASK, VLUXSEG2EI8_V }, // 3891
  { PseudoVLUXSEG2EI8_V_MF4_M1, VLUXSEG2EI8_V }, // 3892
  { PseudoVLUXSEG2EI8_V_MF4_M1_MASK, VLUXSEG2EI8_V }, // 3893
  { PseudoVLUXSEG2EI8_V_MF4_M2, VLUXSEG2EI8_V }, // 3894
  { PseudoVLUXSEG2EI8_V_MF4_M2_MASK, VLUXSEG2EI8_V }, // 3895
  { PseudoVLUXSEG2EI8_V_MF4_MF2, VLUXSEG2EI8_V }, // 3896
  { PseudoVLUXSEG2EI8_V_MF4_MF2_MASK, VLUXSEG2EI8_V }, // 3897
  { PseudoVLUXSEG2EI8_V_MF4_MF4, VLUXSEG2EI8_V }, // 3898
  { PseudoVLUXSEG2EI8_V_MF4_MF4_MASK, VLUXSEG2EI8_V }, // 3899
  { PseudoVLUXSEG2EI8_V_MF8_M1, VLUXSEG2EI8_V }, // 3900
  { PseudoVLUXSEG2EI8_V_MF8_M1_MASK, VLUXSEG2EI8_V }, // 3901
  { PseudoVLUXSEG2EI8_V_MF8_MF2, VLUXSEG2EI8_V }, // 3902
  { PseudoVLUXSEG2EI8_V_MF8_MF2_MASK, VLUXSEG2EI8_V }, // 3903
  { PseudoVLUXSEG2EI8_V_MF8_MF4, VLUXSEG2EI8_V }, // 3904
  { PseudoVLUXSEG2EI8_V_MF8_MF4_MASK, VLUXSEG2EI8_V }, // 3905
  { PseudoVLUXSEG2EI8_V_MF8_MF8, VLUXSEG2EI8_V }, // 3906
  { PseudoVLUXSEG2EI8_V_MF8_MF8_MASK, VLUXSEG2EI8_V }, // 3907
  { PseudoVLUXSEG3EI16_V_M1_M1, VLUXSEG3EI16_V }, // 3908
  { PseudoVLUXSEG3EI16_V_M1_M1_MASK, VLUXSEG3EI16_V }, // 3909
  { PseudoVLUXSEG3EI16_V_M1_M2, VLUXSEG3EI16_V }, // 3910
  { PseudoVLUXSEG3EI16_V_M1_M2_MASK, VLUXSEG3EI16_V }, // 3911
  { PseudoVLUXSEG3EI16_V_M1_MF2, VLUXSEG3EI16_V }, // 3912
  { PseudoVLUXSEG3EI16_V_M1_MF2_MASK, VLUXSEG3EI16_V }, // 3913
  { PseudoVLUXSEG3EI16_V_M2_M1, VLUXSEG3EI16_V }, // 3914
  { PseudoVLUXSEG3EI16_V_M2_M1_MASK, VLUXSEG3EI16_V }, // 3915
  { PseudoVLUXSEG3EI16_V_M2_M2, VLUXSEG3EI16_V }, // 3916
  { PseudoVLUXSEG3EI16_V_M2_M2_MASK, VLUXSEG3EI16_V }, // 3917
  { PseudoVLUXSEG3EI16_V_M4_M2, VLUXSEG3EI16_V }, // 3918
  { PseudoVLUXSEG3EI16_V_M4_M2_MASK, VLUXSEG3EI16_V }, // 3919
  { PseudoVLUXSEG3EI16_V_MF2_M1, VLUXSEG3EI16_V }, // 3920
  { PseudoVLUXSEG3EI16_V_MF2_M1_MASK, VLUXSEG3EI16_V }, // 3921
  { PseudoVLUXSEG3EI16_V_MF2_M2, VLUXSEG3EI16_V }, // 3922
  { PseudoVLUXSEG3EI16_V_MF2_M2_MASK, VLUXSEG3EI16_V }, // 3923
  { PseudoVLUXSEG3EI16_V_MF2_MF2, VLUXSEG3EI16_V }, // 3924
  { PseudoVLUXSEG3EI16_V_MF2_MF2_MASK, VLUXSEG3EI16_V }, // 3925
  { PseudoVLUXSEG3EI16_V_MF2_MF4, VLUXSEG3EI16_V }, // 3926
  { PseudoVLUXSEG3EI16_V_MF2_MF4_MASK, VLUXSEG3EI16_V }, // 3927
  { PseudoVLUXSEG3EI16_V_MF4_M1, VLUXSEG3EI16_V }, // 3928
  { PseudoVLUXSEG3EI16_V_MF4_M1_MASK, VLUXSEG3EI16_V }, // 3929
  { PseudoVLUXSEG3EI16_V_MF4_MF2, VLUXSEG3EI16_V }, // 3930
  { PseudoVLUXSEG3EI16_V_MF4_MF2_MASK, VLUXSEG3EI16_V }, // 3931
  { PseudoVLUXSEG3EI16_V_MF4_MF4, VLUXSEG3EI16_V }, // 3932
  { PseudoVLUXSEG3EI16_V_MF4_MF4_MASK, VLUXSEG3EI16_V }, // 3933
  { PseudoVLUXSEG3EI16_V_MF4_MF8, VLUXSEG3EI16_V }, // 3934
  { PseudoVLUXSEG3EI16_V_MF4_MF8_MASK, VLUXSEG3EI16_V }, // 3935
  { PseudoVLUXSEG3EI32_V_M1_M1, VLUXSEG3EI32_V }, // 3936
  { PseudoVLUXSEG3EI32_V_M1_M1_MASK, VLUXSEG3EI32_V }, // 3937
  { PseudoVLUXSEG3EI32_V_M1_M2, VLUXSEG3EI32_V }, // 3938
  { PseudoVLUXSEG3EI32_V_M1_M2_MASK, VLUXSEG3EI32_V }, // 3939
  { PseudoVLUXSEG3EI32_V_M1_MF2, VLUXSEG3EI32_V }, // 3940
  { PseudoVLUXSEG3EI32_V_M1_MF2_MASK, VLUXSEG3EI32_V }, // 3941
  { PseudoVLUXSEG3EI32_V_M1_MF4, VLUXSEG3EI32_V }, // 3942
  { PseudoVLUXSEG3EI32_V_M1_MF4_MASK, VLUXSEG3EI32_V }, // 3943
  { PseudoVLUXSEG3EI32_V_M2_M1, VLUXSEG3EI32_V }, // 3944
  { PseudoVLUXSEG3EI32_V_M2_M1_MASK, VLUXSEG3EI32_V }, // 3945
  { PseudoVLUXSEG3EI32_V_M2_M2, VLUXSEG3EI32_V }, // 3946
  { PseudoVLUXSEG3EI32_V_M2_M2_MASK, VLUXSEG3EI32_V }, // 3947
  { PseudoVLUXSEG3EI32_V_M2_MF2, VLUXSEG3EI32_V }, // 3948
  { PseudoVLUXSEG3EI32_V_M2_MF2_MASK, VLUXSEG3EI32_V }, // 3949
  { PseudoVLUXSEG3EI32_V_M4_M1, VLUXSEG3EI32_V }, // 3950
  { PseudoVLUXSEG3EI32_V_M4_M1_MASK, VLUXSEG3EI32_V }, // 3951
  { PseudoVLUXSEG3EI32_V_M4_M2, VLUXSEG3EI32_V }, // 3952
  { PseudoVLUXSEG3EI32_V_M4_M2_MASK, VLUXSEG3EI32_V }, // 3953
  { PseudoVLUXSEG3EI32_V_M8_M2, VLUXSEG3EI32_V }, // 3954
  { PseudoVLUXSEG3EI32_V_M8_M2_MASK, VLUXSEG3EI32_V }, // 3955
  { PseudoVLUXSEG3EI32_V_MF2_M1, VLUXSEG3EI32_V }, // 3956
  { PseudoVLUXSEG3EI32_V_MF2_M1_MASK, VLUXSEG3EI32_V }, // 3957
  { PseudoVLUXSEG3EI32_V_MF2_MF2, VLUXSEG3EI32_V }, // 3958
  { PseudoVLUXSEG3EI32_V_MF2_MF2_MASK, VLUXSEG3EI32_V }, // 3959
  { PseudoVLUXSEG3EI32_V_MF2_MF4, VLUXSEG3EI32_V }, // 3960
  { PseudoVLUXSEG3EI32_V_MF2_MF4_MASK, VLUXSEG3EI32_V }, // 3961
  { PseudoVLUXSEG3EI32_V_MF2_MF8, VLUXSEG3EI32_V }, // 3962
  { PseudoVLUXSEG3EI32_V_MF2_MF8_MASK, VLUXSEG3EI32_V }, // 3963
  { PseudoVLUXSEG3EI64_V_M1_M1, VLUXSEG3EI64_V }, // 3964
  { PseudoVLUXSEG3EI64_V_M1_M1_MASK, VLUXSEG3EI64_V }, // 3965
  { PseudoVLUXSEG3EI64_V_M1_MF2, VLUXSEG3EI64_V }, // 3966
  { PseudoVLUXSEG3EI64_V_M1_MF2_MASK, VLUXSEG3EI64_V }, // 3967
  { PseudoVLUXSEG3EI64_V_M1_MF4, VLUXSEG3EI64_V }, // 3968
  { PseudoVLUXSEG3EI64_V_M1_MF4_MASK, VLUXSEG3EI64_V }, // 3969
  { PseudoVLUXSEG3EI64_V_M1_MF8, VLUXSEG3EI64_V }, // 3970
  { PseudoVLUXSEG3EI64_V_M1_MF8_MASK, VLUXSEG3EI64_V }, // 3971
  { PseudoVLUXSEG3EI64_V_M2_M1, VLUXSEG3EI64_V }, // 3972
  { PseudoVLUXSEG3EI64_V_M2_M1_MASK, VLUXSEG3EI64_V }, // 3973
  { PseudoVLUXSEG3EI64_V_M2_M2, VLUXSEG3EI64_V }, // 3974
  { PseudoVLUXSEG3EI64_V_M2_M2_MASK, VLUXSEG3EI64_V }, // 3975
  { PseudoVLUXSEG3EI64_V_M2_MF2, VLUXSEG3EI64_V }, // 3976
  { PseudoVLUXSEG3EI64_V_M2_MF2_MASK, VLUXSEG3EI64_V }, // 3977
  { PseudoVLUXSEG3EI64_V_M2_MF4, VLUXSEG3EI64_V }, // 3978
  { PseudoVLUXSEG3EI64_V_M2_MF4_MASK, VLUXSEG3EI64_V }, // 3979
  { PseudoVLUXSEG3EI64_V_M4_M1, VLUXSEG3EI64_V }, // 3980
  { PseudoVLUXSEG3EI64_V_M4_M1_MASK, VLUXSEG3EI64_V }, // 3981
  { PseudoVLUXSEG3EI64_V_M4_M2, VLUXSEG3EI64_V }, // 3982
  { PseudoVLUXSEG3EI64_V_M4_M2_MASK, VLUXSEG3EI64_V }, // 3983
  { PseudoVLUXSEG3EI64_V_M4_MF2, VLUXSEG3EI64_V }, // 3984
  { PseudoVLUXSEG3EI64_V_M4_MF2_MASK, VLUXSEG3EI64_V }, // 3985
  { PseudoVLUXSEG3EI64_V_M8_M1, VLUXSEG3EI64_V }, // 3986
  { PseudoVLUXSEG3EI64_V_M8_M1_MASK, VLUXSEG3EI64_V }, // 3987
  { PseudoVLUXSEG3EI64_V_M8_M2, VLUXSEG3EI64_V }, // 3988
  { PseudoVLUXSEG3EI64_V_M8_M2_MASK, VLUXSEG3EI64_V }, // 3989
  { PseudoVLUXSEG3EI8_V_M1_M1, VLUXSEG3EI8_V }, // 3990
  { PseudoVLUXSEG3EI8_V_M1_M1_MASK, VLUXSEG3EI8_V }, // 3991
  { PseudoVLUXSEG3EI8_V_M1_M2, VLUXSEG3EI8_V }, // 3992
  { PseudoVLUXSEG3EI8_V_M1_M2_MASK, VLUXSEG3EI8_V }, // 3993
  { PseudoVLUXSEG3EI8_V_M2_M2, VLUXSEG3EI8_V }, // 3994
  { PseudoVLUXSEG3EI8_V_M2_M2_MASK, VLUXSEG3EI8_V }, // 3995
  { PseudoVLUXSEG3EI8_V_MF2_M1, VLUXSEG3EI8_V }, // 3996
  { PseudoVLUXSEG3EI8_V_MF2_M1_MASK, VLUXSEG3EI8_V }, // 3997
  { PseudoVLUXSEG3EI8_V_MF2_M2, VLUXSEG3EI8_V }, // 3998
  { PseudoVLUXSEG3EI8_V_MF2_M2_MASK, VLUXSEG3EI8_V }, // 3999
  { PseudoVLUXSEG3EI8_V_MF2_MF2, VLUXSEG3EI8_V }, // 4000
  { PseudoVLUXSEG3EI8_V_MF2_MF2_MASK, VLUXSEG3EI8_V }, // 4001
  { PseudoVLUXSEG3EI8_V_MF4_M1, VLUXSEG3EI8_V }, // 4002
  { PseudoVLUXSEG3EI8_V_MF4_M1_MASK, VLUXSEG3EI8_V }, // 4003
  { PseudoVLUXSEG3EI8_V_MF4_M2, VLUXSEG3EI8_V }, // 4004
  { PseudoVLUXSEG3EI8_V_MF4_M2_MASK, VLUXSEG3EI8_V }, // 4005
  { PseudoVLUXSEG3EI8_V_MF4_MF2, VLUXSEG3EI8_V }, // 4006
  { PseudoVLUXSEG3EI8_V_MF4_MF2_MASK, VLUXSEG3EI8_V }, // 4007
  { PseudoVLUXSEG3EI8_V_MF4_MF4, VLUXSEG3EI8_V }, // 4008
  { PseudoVLUXSEG3EI8_V_MF4_MF4_MASK, VLUXSEG3EI8_V }, // 4009
  { PseudoVLUXSEG3EI8_V_MF8_M1, VLUXSEG3EI8_V }, // 4010
  { PseudoVLUXSEG3EI8_V_MF8_M1_MASK, VLUXSEG3EI8_V }, // 4011
  { PseudoVLUXSEG3EI8_V_MF8_MF2, VLUXSEG3EI8_V }, // 4012
  { PseudoVLUXSEG3EI8_V_MF8_MF2_MASK, VLUXSEG3EI8_V }, // 4013
  { PseudoVLUXSEG3EI8_V_MF8_MF4, VLUXSEG3EI8_V }, // 4014
  { PseudoVLUXSEG3EI8_V_MF8_MF4_MASK, VLUXSEG3EI8_V }, // 4015
  { PseudoVLUXSEG3EI8_V_MF8_MF8, VLUXSEG3EI8_V }, // 4016
  { PseudoVLUXSEG3EI8_V_MF8_MF8_MASK, VLUXSEG3EI8_V }, // 4017
  { PseudoVLUXSEG4EI16_V_M1_M1, VLUXSEG4EI16_V }, // 4018
  { PseudoVLUXSEG4EI16_V_M1_M1_MASK, VLUXSEG4EI16_V }, // 4019
  { PseudoVLUXSEG4EI16_V_M1_M2, VLUXSEG4EI16_V }, // 4020
  { PseudoVLUXSEG4EI16_V_M1_M2_MASK, VLUXSEG4EI16_V }, // 4021
  { PseudoVLUXSEG4EI16_V_M1_MF2, VLUXSEG4EI16_V }, // 4022
  { PseudoVLUXSEG4EI16_V_M1_MF2_MASK, VLUXSEG4EI16_V }, // 4023
  { PseudoVLUXSEG4EI16_V_M2_M1, VLUXSEG4EI16_V }, // 4024
  { PseudoVLUXSEG4EI16_V_M2_M1_MASK, VLUXSEG4EI16_V }, // 4025
  { PseudoVLUXSEG4EI16_V_M2_M2, VLUXSEG4EI16_V }, // 4026
  { PseudoVLUXSEG4EI16_V_M2_M2_MASK, VLUXSEG4EI16_V }, // 4027
  { PseudoVLUXSEG4EI16_V_M4_M2, VLUXSEG4EI16_V }, // 4028
  { PseudoVLUXSEG4EI16_V_M4_M2_MASK, VLUXSEG4EI16_V }, // 4029
  { PseudoVLUXSEG4EI16_V_MF2_M1, VLUXSEG4EI16_V }, // 4030
  { PseudoVLUXSEG4EI16_V_MF2_M1_MASK, VLUXSEG4EI16_V }, // 4031
  { PseudoVLUXSEG4EI16_V_MF2_M2, VLUXSEG4EI16_V }, // 4032
  { PseudoVLUXSEG4EI16_V_MF2_M2_MASK, VLUXSEG4EI16_V }, // 4033
  { PseudoVLUXSEG4EI16_V_MF2_MF2, VLUXSEG4EI16_V }, // 4034
  { PseudoVLUXSEG4EI16_V_MF2_MF2_MASK, VLUXSEG4EI16_V }, // 4035
  { PseudoVLUXSEG4EI16_V_MF2_MF4, VLUXSEG4EI16_V }, // 4036
  { PseudoVLUXSEG4EI16_V_MF2_MF4_MASK, VLUXSEG4EI16_V }, // 4037
  { PseudoVLUXSEG4EI16_V_MF4_M1, VLUXSEG4EI16_V }, // 4038
  { PseudoVLUXSEG4EI16_V_MF4_M1_MASK, VLUXSEG4EI16_V }, // 4039
  { PseudoVLUXSEG4EI16_V_MF4_MF2, VLUXSEG4EI16_V }, // 4040
  { PseudoVLUXSEG4EI16_V_MF4_MF2_MASK, VLUXSEG4EI16_V }, // 4041
  { PseudoVLUXSEG4EI16_V_MF4_MF4, VLUXSEG4EI16_V }, // 4042
  { PseudoVLUXSEG4EI16_V_MF4_MF4_MASK, VLUXSEG4EI16_V }, // 4043
  { PseudoVLUXSEG4EI16_V_MF4_MF8, VLUXSEG4EI16_V }, // 4044
  { PseudoVLUXSEG4EI16_V_MF4_MF8_MASK, VLUXSEG4EI16_V }, // 4045
  { PseudoVLUXSEG4EI32_V_M1_M1, VLUXSEG4EI32_V }, // 4046
  { PseudoVLUXSEG4EI32_V_M1_M1_MASK, VLUXSEG4EI32_V }, // 4047
  { PseudoVLUXSEG4EI32_V_M1_M2, VLUXSEG4EI32_V }, // 4048
  { PseudoVLUXSEG4EI32_V_M1_M2_MASK, VLUXSEG4EI32_V }, // 4049
  { PseudoVLUXSEG4EI32_V_M1_MF2, VLUXSEG4EI32_V }, // 4050
  { PseudoVLUXSEG4EI32_V_M1_MF2_MASK, VLUXSEG4EI32_V }, // 4051
  { PseudoVLUXSEG4EI32_V_M1_MF4, VLUXSEG4EI32_V }, // 4052
  { PseudoVLUXSEG4EI32_V_M1_MF4_MASK, VLUXSEG4EI32_V }, // 4053
  { PseudoVLUXSEG4EI32_V_M2_M1, VLUXSEG4EI32_V }, // 4054
  { PseudoVLUXSEG4EI32_V_M2_M1_MASK, VLUXSEG4EI32_V }, // 4055
  { PseudoVLUXSEG4EI32_V_M2_M2, VLUXSEG4EI32_V }, // 4056
  { PseudoVLUXSEG4EI32_V_M2_M2_MASK, VLUXSEG4EI32_V }, // 4057
  { PseudoVLUXSEG4EI32_V_M2_MF2, VLUXSEG4EI32_V }, // 4058
  { PseudoVLUXSEG4EI32_V_M2_MF2_MASK, VLUXSEG4EI32_V }, // 4059
  { PseudoVLUXSEG4EI32_V_M4_M1, VLUXSEG4EI32_V }, // 4060
  { PseudoVLUXSEG4EI32_V_M4_M1_MASK, VLUXSEG4EI32_V }, // 4061
  { PseudoVLUXSEG4EI32_V_M4_M2, VLUXSEG4EI32_V }, // 4062
  { PseudoVLUXSEG4EI32_V_M4_M2_MASK, VLUXSEG4EI32_V }, // 4063
  { PseudoVLUXSEG4EI32_V_M8_M2, VLUXSEG4EI32_V }, // 4064
  { PseudoVLUXSEG4EI32_V_M8_M2_MASK, VLUXSEG4EI32_V }, // 4065
  { PseudoVLUXSEG4EI32_V_MF2_M1, VLUXSEG4EI32_V }, // 4066
  { PseudoVLUXSEG4EI32_V_MF2_M1_MASK, VLUXSEG4EI32_V }, // 4067
  { PseudoVLUXSEG4EI32_V_MF2_MF2, VLUXSEG4EI32_V }, // 4068
  { PseudoVLUXSEG4EI32_V_MF2_MF2_MASK, VLUXSEG4EI32_V }, // 4069
  { PseudoVLUXSEG4EI32_V_MF2_MF4, VLUXSEG4EI32_V }, // 4070
  { PseudoVLUXSEG4EI32_V_MF2_MF4_MASK, VLUXSEG4EI32_V }, // 4071
  { PseudoVLUXSEG4EI32_V_MF2_MF8, VLUXSEG4EI32_V }, // 4072
  { PseudoVLUXSEG4EI32_V_MF2_MF8_MASK, VLUXSEG4EI32_V }, // 4073
  { PseudoVLUXSEG4EI64_V_M1_M1, VLUXSEG4EI64_V }, // 4074
  { PseudoVLUXSEG4EI64_V_M1_M1_MASK, VLUXSEG4EI64_V }, // 4075
  { PseudoVLUXSEG4EI64_V_M1_MF2, VLUXSEG4EI64_V }, // 4076
  { PseudoVLUXSEG4EI64_V_M1_MF2_MASK, VLUXSEG4EI64_V }, // 4077
  { PseudoVLUXSEG4EI64_V_M1_MF4, VLUXSEG4EI64_V }, // 4078
  { PseudoVLUXSEG4EI64_V_M1_MF4_MASK, VLUXSEG4EI64_V }, // 4079
  { PseudoVLUXSEG4EI64_V_M1_MF8, VLUXSEG4EI64_V }, // 4080
  { PseudoVLUXSEG4EI64_V_M1_MF8_MASK, VLUXSEG4EI64_V }, // 4081
  { PseudoVLUXSEG4EI64_V_M2_M1, VLUXSEG4EI64_V }, // 4082
  { PseudoVLUXSEG4EI64_V_M2_M1_MASK, VLUXSEG4EI64_V }, // 4083
  { PseudoVLUXSEG4EI64_V_M2_M2, VLUXSEG4EI64_V }, // 4084
  { PseudoVLUXSEG4EI64_V_M2_M2_MASK, VLUXSEG4EI64_V }, // 4085
  { PseudoVLUXSEG4EI64_V_M2_MF2, VLUXSEG4EI64_V }, // 4086
  { PseudoVLUXSEG4EI64_V_M2_MF2_MASK, VLUXSEG4EI64_V }, // 4087
  { PseudoVLUXSEG4EI64_V_M2_MF4, VLUXSEG4EI64_V }, // 4088
  { PseudoVLUXSEG4EI64_V_M2_MF4_MASK, VLUXSEG4EI64_V }, // 4089
  { PseudoVLUXSEG4EI64_V_M4_M1, VLUXSEG4EI64_V }, // 4090
  { PseudoVLUXSEG4EI64_V_M4_M1_MASK, VLUXSEG4EI64_V }, // 4091
  { PseudoVLUXSEG4EI64_V_M4_M2, VLUXSEG4EI64_V }, // 4092
  { PseudoVLUXSEG4EI64_V_M4_M2_MASK, VLUXSEG4EI64_V }, // 4093
  { PseudoVLUXSEG4EI64_V_M4_MF2, VLUXSEG4EI64_V }, // 4094
  { PseudoVLUXSEG4EI64_V_M4_MF2_MASK, VLUXSEG4EI64_V }, // 4095
  { PseudoVLUXSEG4EI64_V_M8_M1, VLUXSEG4EI64_V }, // 4096
  { PseudoVLUXSEG4EI64_V_M8_M1_MASK, VLUXSEG4EI64_V }, // 4097
  { PseudoVLUXSEG4EI64_V_M8_M2, VLUXSEG4EI64_V }, // 4098
  { PseudoVLUXSEG4EI64_V_M8_M2_MASK, VLUXSEG4EI64_V }, // 4099
  { PseudoVLUXSEG4EI8_V_M1_M1, VLUXSEG4EI8_V }, // 4100
  { PseudoVLUXSEG4EI8_V_M1_M1_MASK, VLUXSEG4EI8_V }, // 4101
  { PseudoVLUXSEG4EI8_V_M1_M2, VLUXSEG4EI8_V }, // 4102
  { PseudoVLUXSEG4EI8_V_M1_M2_MASK, VLUXSEG4EI8_V }, // 4103
  { PseudoVLUXSEG4EI8_V_M2_M2, VLUXSEG4EI8_V }, // 4104
  { PseudoVLUXSEG4EI8_V_M2_M2_MASK, VLUXSEG4EI8_V }, // 4105
  { PseudoVLUXSEG4EI8_V_MF2_M1, VLUXSEG4EI8_V }, // 4106
  { PseudoVLUXSEG4EI8_V_MF2_M1_MASK, VLUXSEG4EI8_V }, // 4107
  { PseudoVLUXSEG4EI8_V_MF2_M2, VLUXSEG4EI8_V }, // 4108
  { PseudoVLUXSEG4EI8_V_MF2_M2_MASK, VLUXSEG4EI8_V }, // 4109
  { PseudoVLUXSEG4EI8_V_MF2_MF2, VLUXSEG4EI8_V }, // 4110
  { PseudoVLUXSEG4EI8_V_MF2_MF2_MASK, VLUXSEG4EI8_V }, // 4111
  { PseudoVLUXSEG4EI8_V_MF4_M1, VLUXSEG4EI8_V }, // 4112
  { PseudoVLUXSEG4EI8_V_MF4_M1_MASK, VLUXSEG4EI8_V }, // 4113
  { PseudoVLUXSEG4EI8_V_MF4_M2, VLUXSEG4EI8_V }, // 4114
  { PseudoVLUXSEG4EI8_V_MF4_M2_MASK, VLUXSEG4EI8_V }, // 4115
  { PseudoVLUXSEG4EI8_V_MF4_MF2, VLUXSEG4EI8_V }, // 4116
  { PseudoVLUXSEG4EI8_V_MF4_MF2_MASK, VLUXSEG4EI8_V }, // 4117
  { PseudoVLUXSEG4EI8_V_MF4_MF4, VLUXSEG4EI8_V }, // 4118
  { PseudoVLUXSEG4EI8_V_MF4_MF4_MASK, VLUXSEG4EI8_V }, // 4119
  { PseudoVLUXSEG4EI8_V_MF8_M1, VLUXSEG4EI8_V }, // 4120
  { PseudoVLUXSEG4EI8_V_MF8_M1_MASK, VLUXSEG4EI8_V }, // 4121
  { PseudoVLUXSEG4EI8_V_MF8_MF2, VLUXSEG4EI8_V }, // 4122
  { PseudoVLUXSEG4EI8_V_MF8_MF2_MASK, VLUXSEG4EI8_V }, // 4123
  { PseudoVLUXSEG4EI8_V_MF8_MF4, VLUXSEG4EI8_V }, // 4124
  { PseudoVLUXSEG4EI8_V_MF8_MF4_MASK, VLUXSEG4EI8_V }, // 4125
  { PseudoVLUXSEG4EI8_V_MF8_MF8, VLUXSEG4EI8_V }, // 4126
  { PseudoVLUXSEG4EI8_V_MF8_MF8_MASK, VLUXSEG4EI8_V }, // 4127
  { PseudoVLUXSEG5EI16_V_M1_M1, VLUXSEG5EI16_V }, // 4128
  { PseudoVLUXSEG5EI16_V_M1_M1_MASK, VLUXSEG5EI16_V }, // 4129
  { PseudoVLUXSEG5EI16_V_M1_MF2, VLUXSEG5EI16_V }, // 4130
  { PseudoVLUXSEG5EI16_V_M1_MF2_MASK, VLUXSEG5EI16_V }, // 4131
  { PseudoVLUXSEG5EI16_V_M2_M1, VLUXSEG5EI16_V }, // 4132
  { PseudoVLUXSEG5EI16_V_M2_M1_MASK, VLUXSEG5EI16_V }, // 4133
  { PseudoVLUXSEG5EI16_V_MF2_M1, VLUXSEG5EI16_V }, // 4134
  { PseudoVLUXSEG5EI16_V_MF2_M1_MASK, VLUXSEG5EI16_V }, // 4135
  { PseudoVLUXSEG5EI16_V_MF2_MF2, VLUXSEG5EI16_V }, // 4136
  { PseudoVLUXSEG5EI16_V_MF2_MF2_MASK, VLUXSEG5EI16_V }, // 4137
  { PseudoVLUXSEG5EI16_V_MF2_MF4, VLUXSEG5EI16_V }, // 4138
  { PseudoVLUXSEG5EI16_V_MF2_MF4_MASK, VLUXSEG5EI16_V }, // 4139
  { PseudoVLUXSEG5EI16_V_MF4_M1, VLUXSEG5EI16_V }, // 4140
  { PseudoVLUXSEG5EI16_V_MF4_M1_MASK, VLUXSEG5EI16_V }, // 4141
  { PseudoVLUXSEG5EI16_V_MF4_MF2, VLUXSEG5EI16_V }, // 4142
  { PseudoVLUXSEG5EI16_V_MF4_MF2_MASK, VLUXSEG5EI16_V }, // 4143
  { PseudoVLUXSEG5EI16_V_MF4_MF4, VLUXSEG5EI16_V }, // 4144
  { PseudoVLUXSEG5EI16_V_MF4_MF4_MASK, VLUXSEG5EI16_V }, // 4145
  { PseudoVLUXSEG5EI16_V_MF4_MF8, VLUXSEG5EI16_V }, // 4146
  { PseudoVLUXSEG5EI16_V_MF4_MF8_MASK, VLUXSEG5EI16_V }, // 4147
  { PseudoVLUXSEG5EI32_V_M1_M1, VLUXSEG5EI32_V }, // 4148
  { PseudoVLUXSEG5EI32_V_M1_M1_MASK, VLUXSEG5EI32_V }, // 4149
  { PseudoVLUXSEG5EI32_V_M1_MF2, VLUXSEG5EI32_V }, // 4150
  { PseudoVLUXSEG5EI32_V_M1_MF2_MASK, VLUXSEG5EI32_V }, // 4151
  { PseudoVLUXSEG5EI32_V_M1_MF4, VLUXSEG5EI32_V }, // 4152
  { PseudoVLUXSEG5EI32_V_M1_MF4_MASK, VLUXSEG5EI32_V }, // 4153
  { PseudoVLUXSEG5EI32_V_M2_M1, VLUXSEG5EI32_V }, // 4154
  { PseudoVLUXSEG5EI32_V_M2_M1_MASK, VLUXSEG5EI32_V }, // 4155
  { PseudoVLUXSEG5EI32_V_M2_MF2, VLUXSEG5EI32_V }, // 4156
  { PseudoVLUXSEG5EI32_V_M2_MF2_MASK, VLUXSEG5EI32_V }, // 4157
  { PseudoVLUXSEG5EI32_V_M4_M1, VLUXSEG5EI32_V }, // 4158
  { PseudoVLUXSEG5EI32_V_M4_M1_MASK, VLUXSEG5EI32_V }, // 4159
  { PseudoVLUXSEG5EI32_V_MF2_M1, VLUXSEG5EI32_V }, // 4160
  { PseudoVLUXSEG5EI32_V_MF2_M1_MASK, VLUXSEG5EI32_V }, // 4161
  { PseudoVLUXSEG5EI32_V_MF2_MF2, VLUXSEG5EI32_V }, // 4162
  { PseudoVLUXSEG5EI32_V_MF2_MF2_MASK, VLUXSEG5EI32_V }, // 4163
  { PseudoVLUXSEG5EI32_V_MF2_MF4, VLUXSEG5EI32_V }, // 4164
  { PseudoVLUXSEG5EI32_V_MF2_MF4_MASK, VLUXSEG5EI32_V }, // 4165
  { PseudoVLUXSEG5EI32_V_MF2_MF8, VLUXSEG5EI32_V }, // 4166
  { PseudoVLUXSEG5EI32_V_MF2_MF8_MASK, VLUXSEG5EI32_V }, // 4167
  { PseudoVLUXSEG5EI64_V_M1_M1, VLUXSEG5EI64_V }, // 4168
  { PseudoVLUXSEG5EI64_V_M1_M1_MASK, VLUXSEG5EI64_V }, // 4169
  { PseudoVLUXSEG5EI64_V_M1_MF2, VLUXSEG5EI64_V }, // 4170
  { PseudoVLUXSEG5EI64_V_M1_MF2_MASK, VLUXSEG5EI64_V }, // 4171
  { PseudoVLUXSEG5EI64_V_M1_MF4, VLUXSEG5EI64_V }, // 4172
  { PseudoVLUXSEG5EI64_V_M1_MF4_MASK, VLUXSEG5EI64_V }, // 4173
  { PseudoVLUXSEG5EI64_V_M1_MF8, VLUXSEG5EI64_V }, // 4174
  { PseudoVLUXSEG5EI64_V_M1_MF8_MASK, VLUXSEG5EI64_V }, // 4175
  { PseudoVLUXSEG5EI64_V_M2_M1, VLUXSEG5EI64_V }, // 4176
  { PseudoVLUXSEG5EI64_V_M2_M1_MASK, VLUXSEG5EI64_V }, // 4177
  { PseudoVLUXSEG5EI64_V_M2_MF2, VLUXSEG5EI64_V }, // 4178
  { PseudoVLUXSEG5EI64_V_M2_MF2_MASK, VLUXSEG5EI64_V }, // 4179
  { PseudoVLUXSEG5EI64_V_M2_MF4, VLUXSEG5EI64_V }, // 4180
  { PseudoVLUXSEG5EI64_V_M2_MF4_MASK, VLUXSEG5EI64_V }, // 4181
  { PseudoVLUXSEG5EI64_V_M4_M1, VLUXSEG5EI64_V }, // 4182
  { PseudoVLUXSEG5EI64_V_M4_M1_MASK, VLUXSEG5EI64_V }, // 4183
  { PseudoVLUXSEG5EI64_V_M4_MF2, VLUXSEG5EI64_V }, // 4184
  { PseudoVLUXSEG5EI64_V_M4_MF2_MASK, VLUXSEG5EI64_V }, // 4185
  { PseudoVLUXSEG5EI64_V_M8_M1, VLUXSEG5EI64_V }, // 4186
  { PseudoVLUXSEG5EI64_V_M8_M1_MASK, VLUXSEG5EI64_V }, // 4187
  { PseudoVLUXSEG5EI8_V_M1_M1, VLUXSEG5EI8_V }, // 4188
  { PseudoVLUXSEG5EI8_V_M1_M1_MASK, VLUXSEG5EI8_V }, // 4189
  { PseudoVLUXSEG5EI8_V_MF2_M1, VLUXSEG5EI8_V }, // 4190
  { PseudoVLUXSEG5EI8_V_MF2_M1_MASK, VLUXSEG5EI8_V }, // 4191
  { PseudoVLUXSEG5EI8_V_MF2_MF2, VLUXSEG5EI8_V }, // 4192
  { PseudoVLUXSEG5EI8_V_MF2_MF2_MASK, VLUXSEG5EI8_V }, // 4193
  { PseudoVLUXSEG5EI8_V_MF4_M1, VLUXSEG5EI8_V }, // 4194
  { PseudoVLUXSEG5EI8_V_MF4_M1_MASK, VLUXSEG5EI8_V }, // 4195
  { PseudoVLUXSEG5EI8_V_MF4_MF2, VLUXSEG5EI8_V }, // 4196
  { PseudoVLUXSEG5EI8_V_MF4_MF2_MASK, VLUXSEG5EI8_V }, // 4197
  { PseudoVLUXSEG5EI8_V_MF4_MF4, VLUXSEG5EI8_V }, // 4198
  { PseudoVLUXSEG5EI8_V_MF4_MF4_MASK, VLUXSEG5EI8_V }, // 4199
  { PseudoVLUXSEG5EI8_V_MF8_M1, VLUXSEG5EI8_V }, // 4200
  { PseudoVLUXSEG5EI8_V_MF8_M1_MASK, VLUXSEG5EI8_V }, // 4201
  { PseudoVLUXSEG5EI8_V_MF8_MF2, VLUXSEG5EI8_V }, // 4202
  { PseudoVLUXSEG5EI8_V_MF8_MF2_MASK, VLUXSEG5EI8_V }, // 4203
  { PseudoVLUXSEG5EI8_V_MF8_MF4, VLUXSEG5EI8_V }, // 4204
  { PseudoVLUXSEG5EI8_V_MF8_MF4_MASK, VLUXSEG5EI8_V }, // 4205
  { PseudoVLUXSEG5EI8_V_MF8_MF8, VLUXSEG5EI8_V }, // 4206
  { PseudoVLUXSEG5EI8_V_MF8_MF8_MASK, VLUXSEG5EI8_V }, // 4207
  { PseudoVLUXSEG6EI16_V_M1_M1, VLUXSEG6EI16_V }, // 4208
  { PseudoVLUXSEG6EI16_V_M1_M1_MASK, VLUXSEG6EI16_V }, // 4209
  { PseudoVLUXSEG6EI16_V_M1_MF2, VLUXSEG6EI16_V }, // 4210
  { PseudoVLUXSEG6EI16_V_M1_MF2_MASK, VLUXSEG6EI16_V }, // 4211
  { PseudoVLUXSEG6EI16_V_M2_M1, VLUXSEG6EI16_V }, // 4212
  { PseudoVLUXSEG6EI16_V_M2_M1_MASK, VLUXSEG6EI16_V }, // 4213
  { PseudoVLUXSEG6EI16_V_MF2_M1, VLUXSEG6EI16_V }, // 4214
  { PseudoVLUXSEG6EI16_V_MF2_M1_MASK, VLUXSEG6EI16_V }, // 4215
  { PseudoVLUXSEG6EI16_V_MF2_MF2, VLUXSEG6EI16_V }, // 4216
  { PseudoVLUXSEG6EI16_V_MF2_MF2_MASK, VLUXSEG6EI16_V }, // 4217
  { PseudoVLUXSEG6EI16_V_MF2_MF4, VLUXSEG6EI16_V }, // 4218
  { PseudoVLUXSEG6EI16_V_MF2_MF4_MASK, VLUXSEG6EI16_V }, // 4219
  { PseudoVLUXSEG6EI16_V_MF4_M1, VLUXSEG6EI16_V }, // 4220
  { PseudoVLUXSEG6EI16_V_MF4_M1_MASK, VLUXSEG6EI16_V }, // 4221
  { PseudoVLUXSEG6EI16_V_MF4_MF2, VLUXSEG6EI16_V }, // 4222
  { PseudoVLUXSEG6EI16_V_MF4_MF2_MASK, VLUXSEG6EI16_V }, // 4223
  { PseudoVLUXSEG6EI16_V_MF4_MF4, VLUXSEG6EI16_V }, // 4224
  { PseudoVLUXSEG6EI16_V_MF4_MF4_MASK, VLUXSEG6EI16_V }, // 4225
  { PseudoVLUXSEG6EI16_V_MF4_MF8, VLUXSEG6EI16_V }, // 4226
  { PseudoVLUXSEG6EI16_V_MF4_MF8_MASK, VLUXSEG6EI16_V }, // 4227
  { PseudoVLUXSEG6EI32_V_M1_M1, VLUXSEG6EI32_V }, // 4228
  { PseudoVLUXSEG6EI32_V_M1_M1_MASK, VLUXSEG6EI32_V }, // 4229
  { PseudoVLUXSEG6EI32_V_M1_MF2, VLUXSEG6EI32_V }, // 4230
  { PseudoVLUXSEG6EI32_V_M1_MF2_MASK, VLUXSEG6EI32_V }, // 4231
  { PseudoVLUXSEG6EI32_V_M1_MF4, VLUXSEG6EI32_V }, // 4232
  { PseudoVLUXSEG6EI32_V_M1_MF4_MASK, VLUXSEG6EI32_V }, // 4233
  { PseudoVLUXSEG6EI32_V_M2_M1, VLUXSEG6EI32_V }, // 4234
  { PseudoVLUXSEG6EI32_V_M2_M1_MASK, VLUXSEG6EI32_V }, // 4235
  { PseudoVLUXSEG6EI32_V_M2_MF2, VLUXSEG6EI32_V }, // 4236
  { PseudoVLUXSEG6EI32_V_M2_MF2_MASK, VLUXSEG6EI32_V }, // 4237
  { PseudoVLUXSEG6EI32_V_M4_M1, VLUXSEG6EI32_V }, // 4238
  { PseudoVLUXSEG6EI32_V_M4_M1_MASK, VLUXSEG6EI32_V }, // 4239
  { PseudoVLUXSEG6EI32_V_MF2_M1, VLUXSEG6EI32_V }, // 4240
  { PseudoVLUXSEG6EI32_V_MF2_M1_MASK, VLUXSEG6EI32_V }, // 4241
  { PseudoVLUXSEG6EI32_V_MF2_MF2, VLUXSEG6EI32_V }, // 4242
  { PseudoVLUXSEG6EI32_V_MF2_MF2_MASK, VLUXSEG6EI32_V }, // 4243
  { PseudoVLUXSEG6EI32_V_MF2_MF4, VLUXSEG6EI32_V }, // 4244
  { PseudoVLUXSEG6EI32_V_MF2_MF4_MASK, VLUXSEG6EI32_V }, // 4245
  { PseudoVLUXSEG6EI32_V_MF2_MF8, VLUXSEG6EI32_V }, // 4246
  { PseudoVLUXSEG6EI32_V_MF2_MF8_MASK, VLUXSEG6EI32_V }, // 4247
  { PseudoVLUXSEG6EI64_V_M1_M1, VLUXSEG6EI64_V }, // 4248
  { PseudoVLUXSEG6EI64_V_M1_M1_MASK, VLUXSEG6EI64_V }, // 4249
  { PseudoVLUXSEG6EI64_V_M1_MF2, VLUXSEG6EI64_V }, // 4250
  { PseudoVLUXSEG6EI64_V_M1_MF2_MASK, VLUXSEG6EI64_V }, // 4251
  { PseudoVLUXSEG6EI64_V_M1_MF4, VLUXSEG6EI64_V }, // 4252
  { PseudoVLUXSEG6EI64_V_M1_MF4_MASK, VLUXSEG6EI64_V }, // 4253
  { PseudoVLUXSEG6EI64_V_M1_MF8, VLUXSEG6EI64_V }, // 4254
  { PseudoVLUXSEG6EI64_V_M1_MF8_MASK, VLUXSEG6EI64_V }, // 4255
  { PseudoVLUXSEG6EI64_V_M2_M1, VLUXSEG6EI64_V }, // 4256
  { PseudoVLUXSEG6EI64_V_M2_M1_MASK, VLUXSEG6EI64_V }, // 4257
  { PseudoVLUXSEG6EI64_V_M2_MF2, VLUXSEG6EI64_V }, // 4258
  { PseudoVLUXSEG6EI64_V_M2_MF2_MASK, VLUXSEG6EI64_V }, // 4259
  { PseudoVLUXSEG6EI64_V_M2_MF4, VLUXSEG6EI64_V }, // 4260
  { PseudoVLUXSEG6EI64_V_M2_MF4_MASK, VLUXSEG6EI64_V }, // 4261
  { PseudoVLUXSEG6EI64_V_M4_M1, VLUXSEG6EI64_V }, // 4262
  { PseudoVLUXSEG6EI64_V_M4_M1_MASK, VLUXSEG6EI64_V }, // 4263
  { PseudoVLUXSEG6EI64_V_M4_MF2, VLUXSEG6EI64_V }, // 4264
  { PseudoVLUXSEG6EI64_V_M4_MF2_MASK, VLUXSEG6EI64_V }, // 4265
  { PseudoVLUXSEG6EI64_V_M8_M1, VLUXSEG6EI64_V }, // 4266
  { PseudoVLUXSEG6EI64_V_M8_M1_MASK, VLUXSEG6EI64_V }, // 4267
  { PseudoVLUXSEG6EI8_V_M1_M1, VLUXSEG6EI8_V }, // 4268
  { PseudoVLUXSEG6EI8_V_M1_M1_MASK, VLUXSEG6EI8_V }, // 4269
  { PseudoVLUXSEG6EI8_V_MF2_M1, VLUXSEG6EI8_V }, // 4270
  { PseudoVLUXSEG6EI8_V_MF2_M1_MASK, VLUXSEG6EI8_V }, // 4271
  { PseudoVLUXSEG6EI8_V_MF2_MF2, VLUXSEG6EI8_V }, // 4272
  { PseudoVLUXSEG6EI8_V_MF2_MF2_MASK, VLUXSEG6EI8_V }, // 4273
  { PseudoVLUXSEG6EI8_V_MF4_M1, VLUXSEG6EI8_V }, // 4274
  { PseudoVLUXSEG6EI8_V_MF4_M1_MASK, VLUXSEG6EI8_V }, // 4275
  { PseudoVLUXSEG6EI8_V_MF4_MF2, VLUXSEG6EI8_V }, // 4276
  { PseudoVLUXSEG6EI8_V_MF4_MF2_MASK, VLUXSEG6EI8_V }, // 4277
  { PseudoVLUXSEG6EI8_V_MF4_MF4, VLUXSEG6EI8_V }, // 4278
  { PseudoVLUXSEG6EI8_V_MF4_MF4_MASK, VLUXSEG6EI8_V }, // 4279
  { PseudoVLUXSEG6EI8_V_MF8_M1, VLUXSEG6EI8_V }, // 4280
  { PseudoVLUXSEG6EI8_V_MF8_M1_MASK, VLUXSEG6EI8_V }, // 4281
  { PseudoVLUXSEG6EI8_V_MF8_MF2, VLUXSEG6EI8_V }, // 4282
  { PseudoVLUXSEG6EI8_V_MF8_MF2_MASK, VLUXSEG6EI8_V }, // 4283
  { PseudoVLUXSEG6EI8_V_MF8_MF4, VLUXSEG6EI8_V }, // 4284
  { PseudoVLUXSEG6EI8_V_MF8_MF4_MASK, VLUXSEG6EI8_V }, // 4285
  { PseudoVLUXSEG6EI8_V_MF8_MF8, VLUXSEG6EI8_V }, // 4286
  { PseudoVLUXSEG6EI8_V_MF8_MF8_MASK, VLUXSEG6EI8_V }, // 4287
  { PseudoVLUXSEG7EI16_V_M1_M1, VLUXSEG7EI16_V }, // 4288
  { PseudoVLUXSEG7EI16_V_M1_M1_MASK, VLUXSEG7EI16_V }, // 4289
  { PseudoVLUXSEG7EI16_V_M1_MF2, VLUXSEG7EI16_V }, // 4290
  { PseudoVLUXSEG7EI16_V_M1_MF2_MASK, VLUXSEG7EI16_V }, // 4291
  { PseudoVLUXSEG7EI16_V_M2_M1, VLUXSEG7EI16_V }, // 4292
  { PseudoVLUXSEG7EI16_V_M2_M1_MASK, VLUXSEG7EI16_V }, // 4293
  { PseudoVLUXSEG7EI16_V_MF2_M1, VLUXSEG7EI16_V }, // 4294
  { PseudoVLUXSEG7EI16_V_MF2_M1_MASK, VLUXSEG7EI16_V }, // 4295
  { PseudoVLUXSEG7EI16_V_MF2_MF2, VLUXSEG7EI16_V }, // 4296
  { PseudoVLUXSEG7EI16_V_MF2_MF2_MASK, VLUXSEG7EI16_V }, // 4297
  { PseudoVLUXSEG7EI16_V_MF2_MF4, VLUXSEG7EI16_V }, // 4298
  { PseudoVLUXSEG7EI16_V_MF2_MF4_MASK, VLUXSEG7EI16_V }, // 4299
  { PseudoVLUXSEG7EI16_V_MF4_M1, VLUXSEG7EI16_V }, // 4300
  { PseudoVLUXSEG7EI16_V_MF4_M1_MASK, VLUXSEG7EI16_V }, // 4301
  { PseudoVLUXSEG7EI16_V_MF4_MF2, VLUXSEG7EI16_V }, // 4302
  { PseudoVLUXSEG7EI16_V_MF4_MF2_MASK, VLUXSEG7EI16_V }, // 4303
  { PseudoVLUXSEG7EI16_V_MF4_MF4, VLUXSEG7EI16_V }, // 4304
  { PseudoVLUXSEG7EI16_V_MF4_MF4_MASK, VLUXSEG7EI16_V }, // 4305
  { PseudoVLUXSEG7EI16_V_MF4_MF8, VLUXSEG7EI16_V }, // 4306
  { PseudoVLUXSEG7EI16_V_MF4_MF8_MASK, VLUXSEG7EI16_V }, // 4307
  { PseudoVLUXSEG7EI32_V_M1_M1, VLUXSEG7EI32_V }, // 4308
  { PseudoVLUXSEG7EI32_V_M1_M1_MASK, VLUXSEG7EI32_V }, // 4309
  { PseudoVLUXSEG7EI32_V_M1_MF2, VLUXSEG7EI32_V }, // 4310
  { PseudoVLUXSEG7EI32_V_M1_MF2_MASK, VLUXSEG7EI32_V }, // 4311
  { PseudoVLUXSEG7EI32_V_M1_MF4, VLUXSEG7EI32_V }, // 4312
  { PseudoVLUXSEG7EI32_V_M1_MF4_MASK, VLUXSEG7EI32_V }, // 4313
  { PseudoVLUXSEG7EI32_V_M2_M1, VLUXSEG7EI32_V }, // 4314
  { PseudoVLUXSEG7EI32_V_M2_M1_MASK, VLUXSEG7EI32_V }, // 4315
  { PseudoVLUXSEG7EI32_V_M2_MF2, VLUXSEG7EI32_V }, // 4316
  { PseudoVLUXSEG7EI32_V_M2_MF2_MASK, VLUXSEG7EI32_V }, // 4317
  { PseudoVLUXSEG7EI32_V_M4_M1, VLUXSEG7EI32_V }, // 4318
  { PseudoVLUXSEG7EI32_V_M4_M1_MASK, VLUXSEG7EI32_V }, // 4319
  { PseudoVLUXSEG7EI32_V_MF2_M1, VLUXSEG7EI32_V }, // 4320
  { PseudoVLUXSEG7EI32_V_MF2_M1_MASK, VLUXSEG7EI32_V }, // 4321
  { PseudoVLUXSEG7EI32_V_MF2_MF2, VLUXSEG7EI32_V }, // 4322
  { PseudoVLUXSEG7EI32_V_MF2_MF2_MASK, VLUXSEG7EI32_V }, // 4323
  { PseudoVLUXSEG7EI32_V_MF2_MF4, VLUXSEG7EI32_V }, // 4324
  { PseudoVLUXSEG7EI32_V_MF2_MF4_MASK, VLUXSEG7EI32_V }, // 4325
  { PseudoVLUXSEG7EI32_V_MF2_MF8, VLUXSEG7EI32_V }, // 4326
  { PseudoVLUXSEG7EI32_V_MF2_MF8_MASK, VLUXSEG7EI32_V }, // 4327
  { PseudoVLUXSEG7EI64_V_M1_M1, VLUXSEG7EI64_V }, // 4328
  { PseudoVLUXSEG7EI64_V_M1_M1_MASK, VLUXSEG7EI64_V }, // 4329
  { PseudoVLUXSEG7EI64_V_M1_MF2, VLUXSEG7EI64_V }, // 4330
  { PseudoVLUXSEG7EI64_V_M1_MF2_MASK, VLUXSEG7EI64_V }, // 4331
  { PseudoVLUXSEG7EI64_V_M1_MF4, VLUXSEG7EI64_V }, // 4332
  { PseudoVLUXSEG7EI64_V_M1_MF4_MASK, VLUXSEG7EI64_V }, // 4333
  { PseudoVLUXSEG7EI64_V_M1_MF8, VLUXSEG7EI64_V }, // 4334
  { PseudoVLUXSEG7EI64_V_M1_MF8_MASK, VLUXSEG7EI64_V }, // 4335
  { PseudoVLUXSEG7EI64_V_M2_M1, VLUXSEG7EI64_V }, // 4336
  { PseudoVLUXSEG7EI64_V_M2_M1_MASK, VLUXSEG7EI64_V }, // 4337
  { PseudoVLUXSEG7EI64_V_M2_MF2, VLUXSEG7EI64_V }, // 4338
  { PseudoVLUXSEG7EI64_V_M2_MF2_MASK, VLUXSEG7EI64_V }, // 4339
  { PseudoVLUXSEG7EI64_V_M2_MF4, VLUXSEG7EI64_V }, // 4340
  { PseudoVLUXSEG7EI64_V_M2_MF4_MASK, VLUXSEG7EI64_V }, // 4341
  { PseudoVLUXSEG7EI64_V_M4_M1, VLUXSEG7EI64_V }, // 4342
  { PseudoVLUXSEG7EI64_V_M4_M1_MASK, VLUXSEG7EI64_V }, // 4343
  { PseudoVLUXSEG7EI64_V_M4_MF2, VLUXSEG7EI64_V }, // 4344
  { PseudoVLUXSEG7EI64_V_M4_MF2_MASK, VLUXSEG7EI64_V }, // 4345
  { PseudoVLUXSEG7EI64_V_M8_M1, VLUXSEG7EI64_V }, // 4346
  { PseudoVLUXSEG7EI64_V_M8_M1_MASK, VLUXSEG7EI64_V }, // 4347
  { PseudoVLUXSEG7EI8_V_M1_M1, VLUXSEG7EI8_V }, // 4348
  { PseudoVLUXSEG7EI8_V_M1_M1_MASK, VLUXSEG7EI8_V }, // 4349
  { PseudoVLUXSEG7EI8_V_MF2_M1, VLUXSEG7EI8_V }, // 4350
  { PseudoVLUXSEG7EI8_V_MF2_M1_MASK, VLUXSEG7EI8_V }, // 4351
  { PseudoVLUXSEG7EI8_V_MF2_MF2, VLUXSEG7EI8_V }, // 4352
  { PseudoVLUXSEG7EI8_V_MF2_MF2_MASK, VLUXSEG7EI8_V }, // 4353
  { PseudoVLUXSEG7EI8_V_MF4_M1, VLUXSEG7EI8_V }, // 4354
  { PseudoVLUXSEG7EI8_V_MF4_M1_MASK, VLUXSEG7EI8_V }, // 4355
  { PseudoVLUXSEG7EI8_V_MF4_MF2, VLUXSEG7EI8_V }, // 4356
  { PseudoVLUXSEG7EI8_V_MF4_MF2_MASK, VLUXSEG7EI8_V }, // 4357
  { PseudoVLUXSEG7EI8_V_MF4_MF4, VLUXSEG7EI8_V }, // 4358
  { PseudoVLUXSEG7EI8_V_MF4_MF4_MASK, VLUXSEG7EI8_V }, // 4359
  { PseudoVLUXSEG7EI8_V_MF8_M1, VLUXSEG7EI8_V }, // 4360
  { PseudoVLUXSEG7EI8_V_MF8_M1_MASK, VLUXSEG7EI8_V }, // 4361
  { PseudoVLUXSEG7EI8_V_MF8_MF2, VLUXSEG7EI8_V }, // 4362
  { PseudoVLUXSEG7EI8_V_MF8_MF2_MASK, VLUXSEG7EI8_V }, // 4363
  { PseudoVLUXSEG7EI8_V_MF8_MF4, VLUXSEG7EI8_V }, // 4364
  { PseudoVLUXSEG7EI8_V_MF8_MF4_MASK, VLUXSEG7EI8_V }, // 4365
  { PseudoVLUXSEG7EI8_V_MF8_MF8, VLUXSEG7EI8_V }, // 4366
  { PseudoVLUXSEG7EI8_V_MF8_MF8_MASK, VLUXSEG7EI8_V }, // 4367
  { PseudoVLUXSEG8EI16_V_M1_M1, VLUXSEG8EI16_V }, // 4368
  { PseudoVLUXSEG8EI16_V_M1_M1_MASK, VLUXSEG8EI16_V }, // 4369
  { PseudoVLUXSEG8EI16_V_M1_MF2, VLUXSEG8EI16_V }, // 4370
  { PseudoVLUXSEG8EI16_V_M1_MF2_MASK, VLUXSEG8EI16_V }, // 4371
  { PseudoVLUXSEG8EI16_V_M2_M1, VLUXSEG8EI16_V }, // 4372
  { PseudoVLUXSEG8EI16_V_M2_M1_MASK, VLUXSEG8EI16_V }, // 4373
  { PseudoVLUXSEG8EI16_V_MF2_M1, VLUXSEG8EI16_V }, // 4374
  { PseudoVLUXSEG8EI16_V_MF2_M1_MASK, VLUXSEG8EI16_V }, // 4375
  { PseudoVLUXSEG8EI16_V_MF2_MF2, VLUXSEG8EI16_V }, // 4376
  { PseudoVLUXSEG8EI16_V_MF2_MF2_MASK, VLUXSEG8EI16_V }, // 4377
  { PseudoVLUXSEG8EI16_V_MF2_MF4, VLUXSEG8EI16_V }, // 4378
  { PseudoVLUXSEG8EI16_V_MF2_MF4_MASK, VLUXSEG8EI16_V }, // 4379
  { PseudoVLUXSEG8EI16_V_MF4_M1, VLUXSEG8EI16_V }, // 4380
  { PseudoVLUXSEG8EI16_V_MF4_M1_MASK, VLUXSEG8EI16_V }, // 4381
  { PseudoVLUXSEG8EI16_V_MF4_MF2, VLUXSEG8EI16_V }, // 4382
  { PseudoVLUXSEG8EI16_V_MF4_MF2_MASK, VLUXSEG8EI16_V }, // 4383
  { PseudoVLUXSEG8EI16_V_MF4_MF4, VLUXSEG8EI16_V }, // 4384
  { PseudoVLUXSEG8EI16_V_MF4_MF4_MASK, VLUXSEG8EI16_V }, // 4385
  { PseudoVLUXSEG8EI16_V_MF4_MF8, VLUXSEG8EI16_V }, // 4386
  { PseudoVLUXSEG8EI16_V_MF4_MF8_MASK, VLUXSEG8EI16_V }, // 4387
  { PseudoVLUXSEG8EI32_V_M1_M1, VLUXSEG8EI32_V }, // 4388
  { PseudoVLUXSEG8EI32_V_M1_M1_MASK, VLUXSEG8EI32_V }, // 4389
  { PseudoVLUXSEG8EI32_V_M1_MF2, VLUXSEG8EI32_V }, // 4390
  { PseudoVLUXSEG8EI32_V_M1_MF2_MASK, VLUXSEG8EI32_V }, // 4391
  { PseudoVLUXSEG8EI32_V_M1_MF4, VLUXSEG8EI32_V }, // 4392
  { PseudoVLUXSEG8EI32_V_M1_MF4_MASK, VLUXSEG8EI32_V }, // 4393
  { PseudoVLUXSEG8EI32_V_M2_M1, VLUXSEG8EI32_V }, // 4394
  { PseudoVLUXSEG8EI32_V_M2_M1_MASK, VLUXSEG8EI32_V }, // 4395
  { PseudoVLUXSEG8EI32_V_M2_MF2, VLUXSEG8EI32_V }, // 4396
  { PseudoVLUXSEG8EI32_V_M2_MF2_MASK, VLUXSEG8EI32_V }, // 4397
  { PseudoVLUXSEG8EI32_V_M4_M1, VLUXSEG8EI32_V }, // 4398
  { PseudoVLUXSEG8EI32_V_M4_M1_MASK, VLUXSEG8EI32_V }, // 4399
  { PseudoVLUXSEG8EI32_V_MF2_M1, VLUXSEG8EI32_V }, // 4400
  { PseudoVLUXSEG8EI32_V_MF2_M1_MASK, VLUXSEG8EI32_V }, // 4401
  { PseudoVLUXSEG8EI32_V_MF2_MF2, VLUXSEG8EI32_V }, // 4402
  { PseudoVLUXSEG8EI32_V_MF2_MF2_MASK, VLUXSEG8EI32_V }, // 4403
  { PseudoVLUXSEG8EI32_V_MF2_MF4, VLUXSEG8EI32_V }, // 4404
  { PseudoVLUXSEG8EI32_V_MF2_MF4_MASK, VLUXSEG8EI32_V }, // 4405
  { PseudoVLUXSEG8EI32_V_MF2_MF8, VLUXSEG8EI32_V }, // 4406
  { PseudoVLUXSEG8EI32_V_MF2_MF8_MASK, VLUXSEG8EI32_V }, // 4407
  { PseudoVLUXSEG8EI64_V_M1_M1, VLUXSEG8EI64_V }, // 4408
  { PseudoVLUXSEG8EI64_V_M1_M1_MASK, VLUXSEG8EI64_V }, // 4409
  { PseudoVLUXSEG8EI64_V_M1_MF2, VLUXSEG8EI64_V }, // 4410
  { PseudoVLUXSEG8EI64_V_M1_MF2_MASK, VLUXSEG8EI64_V }, // 4411
  { PseudoVLUXSEG8EI64_V_M1_MF4, VLUXSEG8EI64_V }, // 4412
  { PseudoVLUXSEG8EI64_V_M1_MF4_MASK, VLUXSEG8EI64_V }, // 4413
  { PseudoVLUXSEG8EI64_V_M1_MF8, VLUXSEG8EI64_V }, // 4414
  { PseudoVLUXSEG8EI64_V_M1_MF8_MASK, VLUXSEG8EI64_V }, // 4415
  { PseudoVLUXSEG8EI64_V_M2_M1, VLUXSEG8EI64_V }, // 4416
  { PseudoVLUXSEG8EI64_V_M2_M1_MASK, VLUXSEG8EI64_V }, // 4417
  { PseudoVLUXSEG8EI64_V_M2_MF2, VLUXSEG8EI64_V }, // 4418
  { PseudoVLUXSEG8EI64_V_M2_MF2_MASK, VLUXSEG8EI64_V }, // 4419
  { PseudoVLUXSEG8EI64_V_M2_MF4, VLUXSEG8EI64_V }, // 4420
  { PseudoVLUXSEG8EI64_V_M2_MF4_MASK, VLUXSEG8EI64_V }, // 4421
  { PseudoVLUXSEG8EI64_V_M4_M1, VLUXSEG8EI64_V }, // 4422
  { PseudoVLUXSEG8EI64_V_M4_M1_MASK, VLUXSEG8EI64_V }, // 4423
  { PseudoVLUXSEG8EI64_V_M4_MF2, VLUXSEG8EI64_V }, // 4424
  { PseudoVLUXSEG8EI64_V_M4_MF2_MASK, VLUXSEG8EI64_V }, // 4425
  { PseudoVLUXSEG8EI64_V_M8_M1, VLUXSEG8EI64_V }, // 4426
  { PseudoVLUXSEG8EI64_V_M8_M1_MASK, VLUXSEG8EI64_V }, // 4427
  { PseudoVLUXSEG8EI8_V_M1_M1, VLUXSEG8EI8_V }, // 4428
  { PseudoVLUXSEG8EI8_V_M1_M1_MASK, VLUXSEG8EI8_V }, // 4429
  { PseudoVLUXSEG8EI8_V_MF2_M1, VLUXSEG8EI8_V }, // 4430
  { PseudoVLUXSEG8EI8_V_MF2_M1_MASK, VLUXSEG8EI8_V }, // 4431
  { PseudoVLUXSEG8EI8_V_MF2_MF2, VLUXSEG8EI8_V }, // 4432
  { PseudoVLUXSEG8EI8_V_MF2_MF2_MASK, VLUXSEG8EI8_V }, // 4433
  { PseudoVLUXSEG8EI8_V_MF4_M1, VLUXSEG8EI8_V }, // 4434
  { PseudoVLUXSEG8EI8_V_MF4_M1_MASK, VLUXSEG8EI8_V }, // 4435
  { PseudoVLUXSEG8EI8_V_MF4_MF2, VLUXSEG8EI8_V }, // 4436
  { PseudoVLUXSEG8EI8_V_MF4_MF2_MASK, VLUXSEG8EI8_V }, // 4437
  { PseudoVLUXSEG8EI8_V_MF4_MF4, VLUXSEG8EI8_V }, // 4438
  { PseudoVLUXSEG8EI8_V_MF4_MF4_MASK, VLUXSEG8EI8_V }, // 4439
  { PseudoVLUXSEG8EI8_V_MF8_M1, VLUXSEG8EI8_V }, // 4440
  { PseudoVLUXSEG8EI8_V_MF8_M1_MASK, VLUXSEG8EI8_V }, // 4441
  { PseudoVLUXSEG8EI8_V_MF8_MF2, VLUXSEG8EI8_V }, // 4442
  { PseudoVLUXSEG8EI8_V_MF8_MF2_MASK, VLUXSEG8EI8_V }, // 4443
  { PseudoVLUXSEG8EI8_V_MF8_MF4, VLUXSEG8EI8_V }, // 4444
  { PseudoVLUXSEG8EI8_V_MF8_MF4_MASK, VLUXSEG8EI8_V }, // 4445
  { PseudoVLUXSEG8EI8_V_MF8_MF8, VLUXSEG8EI8_V }, // 4446
  { PseudoVLUXSEG8EI8_V_MF8_MF8_MASK, VLUXSEG8EI8_V }, // 4447
  { PseudoVMACC_VV_M1, VMACC_VV }, // 4448
  { PseudoVMACC_VV_M1_MASK, VMACC_VV }, // 4449
  { PseudoVMACC_VV_M2, VMACC_VV }, // 4450
  { PseudoVMACC_VV_M2_MASK, VMACC_VV }, // 4451
  { PseudoVMACC_VV_M4, VMACC_VV }, // 4452
  { PseudoVMACC_VV_M4_MASK, VMACC_VV }, // 4453
  { PseudoVMACC_VV_M8, VMACC_VV }, // 4454
  { PseudoVMACC_VV_M8_MASK, VMACC_VV }, // 4455
  { PseudoVMACC_VV_MF2, VMACC_VV }, // 4456
  { PseudoVMACC_VV_MF2_MASK, VMACC_VV }, // 4457
  { PseudoVMACC_VV_MF4, VMACC_VV }, // 4458
  { PseudoVMACC_VV_MF4_MASK, VMACC_VV }, // 4459
  { PseudoVMACC_VV_MF8, VMACC_VV }, // 4460
  { PseudoVMACC_VV_MF8_MASK, VMACC_VV }, // 4461
  { PseudoVMACC_VX_M1, VMACC_VX }, // 4462
  { PseudoVMACC_VX_M1_MASK, VMACC_VX }, // 4463
  { PseudoVMACC_VX_M2, VMACC_VX }, // 4464
  { PseudoVMACC_VX_M2_MASK, VMACC_VX }, // 4465
  { PseudoVMACC_VX_M4, VMACC_VX }, // 4466
  { PseudoVMACC_VX_M4_MASK, VMACC_VX }, // 4467
  { PseudoVMACC_VX_M8, VMACC_VX }, // 4468
  { PseudoVMACC_VX_M8_MASK, VMACC_VX }, // 4469
  { PseudoVMACC_VX_MF2, VMACC_VX }, // 4470
  { PseudoVMACC_VX_MF2_MASK, VMACC_VX }, // 4471
  { PseudoVMACC_VX_MF4, VMACC_VX }, // 4472
  { PseudoVMACC_VX_MF4_MASK, VMACC_VX }, // 4473
  { PseudoVMACC_VX_MF8, VMACC_VX }, // 4474
  { PseudoVMACC_VX_MF8_MASK, VMACC_VX }, // 4475
  { PseudoVMADC_VIM_M1, VMADC_VIM }, // 4476
  { PseudoVMADC_VIM_M2, VMADC_VIM }, // 4477
  { PseudoVMADC_VIM_M4, VMADC_VIM }, // 4478
  { PseudoVMADC_VIM_M8, VMADC_VIM }, // 4479
  { PseudoVMADC_VIM_MF2, VMADC_VIM }, // 4480
  { PseudoVMADC_VIM_MF4, VMADC_VIM }, // 4481
  { PseudoVMADC_VIM_MF8, VMADC_VIM }, // 4482
  { PseudoVMADC_VI_M1, VMADC_VI }, // 4483
  { PseudoVMADC_VI_M2, VMADC_VI }, // 4484
  { PseudoVMADC_VI_M4, VMADC_VI }, // 4485
  { PseudoVMADC_VI_M8, VMADC_VI }, // 4486
  { PseudoVMADC_VI_MF2, VMADC_VI }, // 4487
  { PseudoVMADC_VI_MF4, VMADC_VI }, // 4488
  { PseudoVMADC_VI_MF8, VMADC_VI }, // 4489
  { PseudoVMADC_VVM_M1, VMADC_VVM }, // 4490
  { PseudoVMADC_VVM_M2, VMADC_VVM }, // 4491
  { PseudoVMADC_VVM_M4, VMADC_VVM }, // 4492
  { PseudoVMADC_VVM_M8, VMADC_VVM }, // 4493
  { PseudoVMADC_VVM_MF2, VMADC_VVM }, // 4494
  { PseudoVMADC_VVM_MF4, VMADC_VVM }, // 4495
  { PseudoVMADC_VVM_MF8, VMADC_VVM }, // 4496
  { PseudoVMADC_VV_M1, VMADC_VV }, // 4497
  { PseudoVMADC_VV_M2, VMADC_VV }, // 4498
  { PseudoVMADC_VV_M4, VMADC_VV }, // 4499
  { PseudoVMADC_VV_M8, VMADC_VV }, // 4500
  { PseudoVMADC_VV_MF2, VMADC_VV }, // 4501
  { PseudoVMADC_VV_MF4, VMADC_VV }, // 4502
  { PseudoVMADC_VV_MF8, VMADC_VV }, // 4503
  { PseudoVMADC_VXM_M1, VMADC_VXM }, // 4504
  { PseudoVMADC_VXM_M2, VMADC_VXM }, // 4505
  { PseudoVMADC_VXM_M4, VMADC_VXM }, // 4506
  { PseudoVMADC_VXM_M8, VMADC_VXM }, // 4507
  { PseudoVMADC_VXM_MF2, VMADC_VXM }, // 4508
  { PseudoVMADC_VXM_MF4, VMADC_VXM }, // 4509
  { PseudoVMADC_VXM_MF8, VMADC_VXM }, // 4510
  { PseudoVMADC_VX_M1, VMADC_VX }, // 4511
  { PseudoVMADC_VX_M2, VMADC_VX }, // 4512
  { PseudoVMADC_VX_M4, VMADC_VX }, // 4513
  { PseudoVMADC_VX_M8, VMADC_VX }, // 4514
  { PseudoVMADC_VX_MF2, VMADC_VX }, // 4515
  { PseudoVMADC_VX_MF4, VMADC_VX }, // 4516
  { PseudoVMADC_VX_MF8, VMADC_VX }, // 4517
  { PseudoVMADD_VV_M1, VMADD_VV }, // 4518
  { PseudoVMADD_VV_M1_MASK, VMADD_VV }, // 4519
  { PseudoVMADD_VV_M2, VMADD_VV }, // 4520
  { PseudoVMADD_VV_M2_MASK, VMADD_VV }, // 4521
  { PseudoVMADD_VV_M4, VMADD_VV }, // 4522
  { PseudoVMADD_VV_M4_MASK, VMADD_VV }, // 4523
  { PseudoVMADD_VV_M8, VMADD_VV }, // 4524
  { PseudoVMADD_VV_M8_MASK, VMADD_VV }, // 4525
  { PseudoVMADD_VV_MF2, VMADD_VV }, // 4526
  { PseudoVMADD_VV_MF2_MASK, VMADD_VV }, // 4527
  { PseudoVMADD_VV_MF4, VMADD_VV }, // 4528
  { PseudoVMADD_VV_MF4_MASK, VMADD_VV }, // 4529
  { PseudoVMADD_VV_MF8, VMADD_VV }, // 4530
  { PseudoVMADD_VV_MF8_MASK, VMADD_VV }, // 4531
  { PseudoVMADD_VX_M1, VMADD_VX }, // 4532
  { PseudoVMADD_VX_M1_MASK, VMADD_VX }, // 4533
  { PseudoVMADD_VX_M2, VMADD_VX }, // 4534
  { PseudoVMADD_VX_M2_MASK, VMADD_VX }, // 4535
  { PseudoVMADD_VX_M4, VMADD_VX }, // 4536
  { PseudoVMADD_VX_M4_MASK, VMADD_VX }, // 4537
  { PseudoVMADD_VX_M8, VMADD_VX }, // 4538
  { PseudoVMADD_VX_M8_MASK, VMADD_VX }, // 4539
  { PseudoVMADD_VX_MF2, VMADD_VX }, // 4540
  { PseudoVMADD_VX_MF2_MASK, VMADD_VX }, // 4541
  { PseudoVMADD_VX_MF4, VMADD_VX }, // 4542
  { PseudoVMADD_VX_MF4_MASK, VMADD_VX }, // 4543
  { PseudoVMADD_VX_MF8, VMADD_VX }, // 4544
  { PseudoVMADD_VX_MF8_MASK, VMADD_VX }, // 4545
  { PseudoVMANDN_MM_M1, VMANDN_MM }, // 4546
  { PseudoVMANDN_MM_M2, VMANDN_MM }, // 4547
  { PseudoVMANDN_MM_M4, VMANDN_MM }, // 4548
  { PseudoVMANDN_MM_M8, VMANDN_MM }, // 4549
  { PseudoVMANDN_MM_MF2, VMANDN_MM }, // 4550
  { PseudoVMANDN_MM_MF4, VMANDN_MM }, // 4551
  { PseudoVMANDN_MM_MF8, VMANDN_MM }, // 4552
  { PseudoVMAND_MM_M1, VMAND_MM }, // 4553
  { PseudoVMAND_MM_M2, VMAND_MM }, // 4554
  { PseudoVMAND_MM_M4, VMAND_MM }, // 4555
  { PseudoVMAND_MM_M8, VMAND_MM }, // 4556
  { PseudoVMAND_MM_MF2, VMAND_MM }, // 4557
  { PseudoVMAND_MM_MF4, VMAND_MM }, // 4558
  { PseudoVMAND_MM_MF8, VMAND_MM }, // 4559
  { PseudoVMAXU_VV_M1, VMAXU_VV }, // 4560
  { PseudoVMAXU_VV_M1_MASK, VMAXU_VV }, // 4561
  { PseudoVMAXU_VV_M2, VMAXU_VV }, // 4562
  { PseudoVMAXU_VV_M2_MASK, VMAXU_VV }, // 4563
  { PseudoVMAXU_VV_M4, VMAXU_VV }, // 4564
  { PseudoVMAXU_VV_M4_MASK, VMAXU_VV }, // 4565
  { PseudoVMAXU_VV_M8, VMAXU_VV }, // 4566
  { PseudoVMAXU_VV_M8_MASK, VMAXU_VV }, // 4567
  { PseudoVMAXU_VV_MF2, VMAXU_VV }, // 4568
  { PseudoVMAXU_VV_MF2_MASK, VMAXU_VV }, // 4569
  { PseudoVMAXU_VV_MF4, VMAXU_VV }, // 4570
  { PseudoVMAXU_VV_MF4_MASK, VMAXU_VV }, // 4571
  { PseudoVMAXU_VV_MF8, VMAXU_VV }, // 4572
  { PseudoVMAXU_VV_MF8_MASK, VMAXU_VV }, // 4573
  { PseudoVMAXU_VX_M1, VMAXU_VX }, // 4574
  { PseudoVMAXU_VX_M1_MASK, VMAXU_VX }, // 4575
  { PseudoVMAXU_VX_M2, VMAXU_VX }, // 4576
  { PseudoVMAXU_VX_M2_MASK, VMAXU_VX }, // 4577
  { PseudoVMAXU_VX_M4, VMAXU_VX }, // 4578
  { PseudoVMAXU_VX_M4_MASK, VMAXU_VX }, // 4579
  { PseudoVMAXU_VX_M8, VMAXU_VX }, // 4580
  { PseudoVMAXU_VX_M8_MASK, VMAXU_VX }, // 4581
  { PseudoVMAXU_VX_MF2, VMAXU_VX }, // 4582
  { PseudoVMAXU_VX_MF2_MASK, VMAXU_VX }, // 4583
  { PseudoVMAXU_VX_MF4, VMAXU_VX }, // 4584
  { PseudoVMAXU_VX_MF4_MASK, VMAXU_VX }, // 4585
  { PseudoVMAXU_VX_MF8, VMAXU_VX }, // 4586
  { PseudoVMAXU_VX_MF8_MASK, VMAXU_VX }, // 4587
  { PseudoVMAX_VV_M1, VMAX_VV }, // 4588
  { PseudoVMAX_VV_M1_MASK, VMAX_VV }, // 4589
  { PseudoVMAX_VV_M2, VMAX_VV }, // 4590
  { PseudoVMAX_VV_M2_MASK, VMAX_VV }, // 4591
  { PseudoVMAX_VV_M4, VMAX_VV }, // 4592
  { PseudoVMAX_VV_M4_MASK, VMAX_VV }, // 4593
  { PseudoVMAX_VV_M8, VMAX_VV }, // 4594
  { PseudoVMAX_VV_M8_MASK, VMAX_VV }, // 4595
  { PseudoVMAX_VV_MF2, VMAX_VV }, // 4596
  { PseudoVMAX_VV_MF2_MASK, VMAX_VV }, // 4597
  { PseudoVMAX_VV_MF4, VMAX_VV }, // 4598
  { PseudoVMAX_VV_MF4_MASK, VMAX_VV }, // 4599
  { PseudoVMAX_VV_MF8, VMAX_VV }, // 4600
  { PseudoVMAX_VV_MF8_MASK, VMAX_VV }, // 4601
  { PseudoVMAX_VX_M1, VMAX_VX }, // 4602
  { PseudoVMAX_VX_M1_MASK, VMAX_VX }, // 4603
  { PseudoVMAX_VX_M2, VMAX_VX }, // 4604
  { PseudoVMAX_VX_M2_MASK, VMAX_VX }, // 4605
  { PseudoVMAX_VX_M4, VMAX_VX }, // 4606
  { PseudoVMAX_VX_M4_MASK, VMAX_VX }, // 4607
  { PseudoVMAX_VX_M8, VMAX_VX }, // 4608
  { PseudoVMAX_VX_M8_MASK, VMAX_VX }, // 4609
  { PseudoVMAX_VX_MF2, VMAX_VX }, // 4610
  { PseudoVMAX_VX_MF2_MASK, VMAX_VX }, // 4611
  { PseudoVMAX_VX_MF4, VMAX_VX }, // 4612
  { PseudoVMAX_VX_MF4_MASK, VMAX_VX }, // 4613
  { PseudoVMAX_VX_MF8, VMAX_VX }, // 4614
  { PseudoVMAX_VX_MF8_MASK, VMAX_VX }, // 4615
  { PseudoVMCLR_M_B1, VMXOR_MM }, // 4616
  { PseudoVMCLR_M_B16, VMXOR_MM }, // 4617
  { PseudoVMCLR_M_B2, VMXOR_MM }, // 4618
  { PseudoVMCLR_M_B32, VMXOR_MM }, // 4619
  { PseudoVMCLR_M_B4, VMXOR_MM }, // 4620
  { PseudoVMCLR_M_B64, VMXOR_MM }, // 4621
  { PseudoVMCLR_M_B8, VMXOR_MM }, // 4622
  { PseudoVMERGE_VIM_M1, VMERGE_VIM }, // 4623
  { PseudoVMERGE_VIM_M1_TU, VMERGE_VIM }, // 4624
  { PseudoVMERGE_VIM_M2, VMERGE_VIM }, // 4625
  { PseudoVMERGE_VIM_M2_TU, VMERGE_VIM }, // 4626
  { PseudoVMERGE_VIM_M4, VMERGE_VIM }, // 4627
  { PseudoVMERGE_VIM_M4_TU, VMERGE_VIM }, // 4628
  { PseudoVMERGE_VIM_M8, VMERGE_VIM }, // 4629
  { PseudoVMERGE_VIM_M8_TU, VMERGE_VIM }, // 4630
  { PseudoVMERGE_VIM_MF2, VMERGE_VIM }, // 4631
  { PseudoVMERGE_VIM_MF2_TU, VMERGE_VIM }, // 4632
  { PseudoVMERGE_VIM_MF4, VMERGE_VIM }, // 4633
  { PseudoVMERGE_VIM_MF4_TU, VMERGE_VIM }, // 4634
  { PseudoVMERGE_VIM_MF8, VMERGE_VIM }, // 4635
  { PseudoVMERGE_VIM_MF8_TU, VMERGE_VIM }, // 4636
  { PseudoVMERGE_VVM_M1, VMERGE_VVM }, // 4637
  { PseudoVMERGE_VVM_M1_TU, VMERGE_VVM }, // 4638
  { PseudoVMERGE_VVM_M2, VMERGE_VVM }, // 4639
  { PseudoVMERGE_VVM_M2_TU, VMERGE_VVM }, // 4640
  { PseudoVMERGE_VVM_M4, VMERGE_VVM }, // 4641
  { PseudoVMERGE_VVM_M4_TU, VMERGE_VVM }, // 4642
  { PseudoVMERGE_VVM_M8, VMERGE_VVM }, // 4643
  { PseudoVMERGE_VVM_M8_TU, VMERGE_VVM }, // 4644
  { PseudoVMERGE_VVM_MF2, VMERGE_VVM }, // 4645
  { PseudoVMERGE_VVM_MF2_TU, VMERGE_VVM }, // 4646
  { PseudoVMERGE_VVM_MF4, VMERGE_VVM }, // 4647
  { PseudoVMERGE_VVM_MF4_TU, VMERGE_VVM }, // 4648
  { PseudoVMERGE_VVM_MF8, VMERGE_VVM }, // 4649
  { PseudoVMERGE_VVM_MF8_TU, VMERGE_VVM }, // 4650
  { PseudoVMERGE_VXM_M1, VMERGE_VXM }, // 4651
  { PseudoVMERGE_VXM_M1_TU, VMERGE_VXM }, // 4652
  { PseudoVMERGE_VXM_M2, VMERGE_VXM }, // 4653
  { PseudoVMERGE_VXM_M2_TU, VMERGE_VXM }, // 4654
  { PseudoVMERGE_VXM_M4, VMERGE_VXM }, // 4655
  { PseudoVMERGE_VXM_M4_TU, VMERGE_VXM }, // 4656
  { PseudoVMERGE_VXM_M8, VMERGE_VXM }, // 4657
  { PseudoVMERGE_VXM_M8_TU, VMERGE_VXM }, // 4658
  { PseudoVMERGE_VXM_MF2, VMERGE_VXM }, // 4659
  { PseudoVMERGE_VXM_MF2_TU, VMERGE_VXM }, // 4660
  { PseudoVMERGE_VXM_MF4, VMERGE_VXM }, // 4661
  { PseudoVMERGE_VXM_MF4_TU, VMERGE_VXM }, // 4662
  { PseudoVMERGE_VXM_MF8, VMERGE_VXM }, // 4663
  { PseudoVMERGE_VXM_MF8_TU, VMERGE_VXM }, // 4664
  { PseudoVMFEQ_VF16_M1, VMFEQ_VF }, // 4665
  { PseudoVMFEQ_VF16_M1_MASK, VMFEQ_VF }, // 4666
  { PseudoVMFEQ_VF16_M2, VMFEQ_VF }, // 4667
  { PseudoVMFEQ_VF16_M2_MASK, VMFEQ_VF }, // 4668
  { PseudoVMFEQ_VF16_M4, VMFEQ_VF }, // 4669
  { PseudoVMFEQ_VF16_M4_MASK, VMFEQ_VF }, // 4670
  { PseudoVMFEQ_VF16_M8, VMFEQ_VF }, // 4671
  { PseudoVMFEQ_VF16_M8_MASK, VMFEQ_VF }, // 4672
  { PseudoVMFEQ_VF16_MF2, VMFEQ_VF }, // 4673
  { PseudoVMFEQ_VF16_MF2_MASK, VMFEQ_VF }, // 4674
  { PseudoVMFEQ_VF16_MF4, VMFEQ_VF }, // 4675
  { PseudoVMFEQ_VF16_MF4_MASK, VMFEQ_VF }, // 4676
  { PseudoVMFEQ_VF32_M1, VMFEQ_VF }, // 4677
  { PseudoVMFEQ_VF32_M1_MASK, VMFEQ_VF }, // 4678
  { PseudoVMFEQ_VF32_M2, VMFEQ_VF }, // 4679
  { PseudoVMFEQ_VF32_M2_MASK, VMFEQ_VF }, // 4680
  { PseudoVMFEQ_VF32_M4, VMFEQ_VF }, // 4681
  { PseudoVMFEQ_VF32_M4_MASK, VMFEQ_VF }, // 4682
  { PseudoVMFEQ_VF32_M8, VMFEQ_VF }, // 4683
  { PseudoVMFEQ_VF32_M8_MASK, VMFEQ_VF }, // 4684
  { PseudoVMFEQ_VF32_MF2, VMFEQ_VF }, // 4685
  { PseudoVMFEQ_VF32_MF2_MASK, VMFEQ_VF }, // 4686
  { PseudoVMFEQ_VF64_M1, VMFEQ_VF }, // 4687
  { PseudoVMFEQ_VF64_M1_MASK, VMFEQ_VF }, // 4688
  { PseudoVMFEQ_VF64_M2, VMFEQ_VF }, // 4689
  { PseudoVMFEQ_VF64_M2_MASK, VMFEQ_VF }, // 4690
  { PseudoVMFEQ_VF64_M4, VMFEQ_VF }, // 4691
  { PseudoVMFEQ_VF64_M4_MASK, VMFEQ_VF }, // 4692
  { PseudoVMFEQ_VF64_M8, VMFEQ_VF }, // 4693
  { PseudoVMFEQ_VF64_M8_MASK, VMFEQ_VF }, // 4694
  { PseudoVMFEQ_VV_M1, VMFEQ_VV }, // 4695
  { PseudoVMFEQ_VV_M1_MASK, VMFEQ_VV }, // 4696
  { PseudoVMFEQ_VV_M2, VMFEQ_VV }, // 4697
  { PseudoVMFEQ_VV_M2_MASK, VMFEQ_VV }, // 4698
  { PseudoVMFEQ_VV_M4, VMFEQ_VV }, // 4699
  { PseudoVMFEQ_VV_M4_MASK, VMFEQ_VV }, // 4700
  { PseudoVMFEQ_VV_M8, VMFEQ_VV }, // 4701
  { PseudoVMFEQ_VV_M8_MASK, VMFEQ_VV }, // 4702
  { PseudoVMFEQ_VV_MF2, VMFEQ_VV }, // 4703
  { PseudoVMFEQ_VV_MF2_MASK, VMFEQ_VV }, // 4704
  { PseudoVMFEQ_VV_MF4, VMFEQ_VV }, // 4705
  { PseudoVMFEQ_VV_MF4_MASK, VMFEQ_VV }, // 4706
  { PseudoVMFGE_VF16_M1, VMFGE_VF }, // 4707
  { PseudoVMFGE_VF16_M1_MASK, VMFGE_VF }, // 4708
  { PseudoVMFGE_VF16_M2, VMFGE_VF }, // 4709
  { PseudoVMFGE_VF16_M2_MASK, VMFGE_VF }, // 4710
  { PseudoVMFGE_VF16_M4, VMFGE_VF }, // 4711
  { PseudoVMFGE_VF16_M4_MASK, VMFGE_VF }, // 4712
  { PseudoVMFGE_VF16_M8, VMFGE_VF }, // 4713
  { PseudoVMFGE_VF16_M8_MASK, VMFGE_VF }, // 4714
  { PseudoVMFGE_VF16_MF2, VMFGE_VF }, // 4715
  { PseudoVMFGE_VF16_MF2_MASK, VMFGE_VF }, // 4716
  { PseudoVMFGE_VF16_MF4, VMFGE_VF }, // 4717
  { PseudoVMFGE_VF16_MF4_MASK, VMFGE_VF }, // 4718
  { PseudoVMFGE_VF32_M1, VMFGE_VF }, // 4719
  { PseudoVMFGE_VF32_M1_MASK, VMFGE_VF }, // 4720
  { PseudoVMFGE_VF32_M2, VMFGE_VF }, // 4721
  { PseudoVMFGE_VF32_M2_MASK, VMFGE_VF }, // 4722
  { PseudoVMFGE_VF32_M4, VMFGE_VF }, // 4723
  { PseudoVMFGE_VF32_M4_MASK, VMFGE_VF }, // 4724
  { PseudoVMFGE_VF32_M8, VMFGE_VF }, // 4725
  { PseudoVMFGE_VF32_M8_MASK, VMFGE_VF }, // 4726
  { PseudoVMFGE_VF32_MF2, VMFGE_VF }, // 4727
  { PseudoVMFGE_VF32_MF2_MASK, VMFGE_VF }, // 4728
  { PseudoVMFGE_VF64_M1, VMFGE_VF }, // 4729
  { PseudoVMFGE_VF64_M1_MASK, VMFGE_VF }, // 4730
  { PseudoVMFGE_VF64_M2, VMFGE_VF }, // 4731
  { PseudoVMFGE_VF64_M2_MASK, VMFGE_VF }, // 4732
  { PseudoVMFGE_VF64_M4, VMFGE_VF }, // 4733
  { PseudoVMFGE_VF64_M4_MASK, VMFGE_VF }, // 4734
  { PseudoVMFGE_VF64_M8, VMFGE_VF }, // 4735
  { PseudoVMFGE_VF64_M8_MASK, VMFGE_VF }, // 4736
  { PseudoVMFGT_VF16_M1, VMFGT_VF }, // 4737
  { PseudoVMFGT_VF16_M1_MASK, VMFGT_VF }, // 4738
  { PseudoVMFGT_VF16_M2, VMFGT_VF }, // 4739
  { PseudoVMFGT_VF16_M2_MASK, VMFGT_VF }, // 4740
  { PseudoVMFGT_VF16_M4, VMFGT_VF }, // 4741
  { PseudoVMFGT_VF16_M4_MASK, VMFGT_VF }, // 4742
  { PseudoVMFGT_VF16_M8, VMFGT_VF }, // 4743
  { PseudoVMFGT_VF16_M8_MASK, VMFGT_VF }, // 4744
  { PseudoVMFGT_VF16_MF2, VMFGT_VF }, // 4745
  { PseudoVMFGT_VF16_MF2_MASK, VMFGT_VF }, // 4746
  { PseudoVMFGT_VF16_MF4, VMFGT_VF }, // 4747
  { PseudoVMFGT_VF16_MF4_MASK, VMFGT_VF }, // 4748
  { PseudoVMFGT_VF32_M1, VMFGT_VF }, // 4749
  { PseudoVMFGT_VF32_M1_MASK, VMFGT_VF }, // 4750
  { PseudoVMFGT_VF32_M2, VMFGT_VF }, // 4751
  { PseudoVMFGT_VF32_M2_MASK, VMFGT_VF }, // 4752
  { PseudoVMFGT_VF32_M4, VMFGT_VF }, // 4753
  { PseudoVMFGT_VF32_M4_MASK, VMFGT_VF }, // 4754
  { PseudoVMFGT_VF32_M8, VMFGT_VF }, // 4755
  { PseudoVMFGT_VF32_M8_MASK, VMFGT_VF }, // 4756
  { PseudoVMFGT_VF32_MF2, VMFGT_VF }, // 4757
  { PseudoVMFGT_VF32_MF2_MASK, VMFGT_VF }, // 4758
  { PseudoVMFGT_VF64_M1, VMFGT_VF }, // 4759
  { PseudoVMFGT_VF64_M1_MASK, VMFGT_VF }, // 4760
  { PseudoVMFGT_VF64_M2, VMFGT_VF }, // 4761
  { PseudoVMFGT_VF64_M2_MASK, VMFGT_VF }, // 4762
  { PseudoVMFGT_VF64_M4, VMFGT_VF }, // 4763
  { PseudoVMFGT_VF64_M4_MASK, VMFGT_VF }, // 4764
  { PseudoVMFGT_VF64_M8, VMFGT_VF }, // 4765
  { PseudoVMFGT_VF64_M8_MASK, VMFGT_VF }, // 4766
  { PseudoVMFLE_VF16_M1, VMFLE_VF }, // 4767
  { PseudoVMFLE_VF16_M1_MASK, VMFLE_VF }, // 4768
  { PseudoVMFLE_VF16_M2, VMFLE_VF }, // 4769
  { PseudoVMFLE_VF16_M2_MASK, VMFLE_VF }, // 4770
  { PseudoVMFLE_VF16_M4, VMFLE_VF }, // 4771
  { PseudoVMFLE_VF16_M4_MASK, VMFLE_VF }, // 4772
  { PseudoVMFLE_VF16_M8, VMFLE_VF }, // 4773
  { PseudoVMFLE_VF16_M8_MASK, VMFLE_VF }, // 4774
  { PseudoVMFLE_VF16_MF2, VMFLE_VF }, // 4775
  { PseudoVMFLE_VF16_MF2_MASK, VMFLE_VF }, // 4776
  { PseudoVMFLE_VF16_MF4, VMFLE_VF }, // 4777
  { PseudoVMFLE_VF16_MF4_MASK, VMFLE_VF }, // 4778
  { PseudoVMFLE_VF32_M1, VMFLE_VF }, // 4779
  { PseudoVMFLE_VF32_M1_MASK, VMFLE_VF }, // 4780
  { PseudoVMFLE_VF32_M2, VMFLE_VF }, // 4781
  { PseudoVMFLE_VF32_M2_MASK, VMFLE_VF }, // 4782
  { PseudoVMFLE_VF32_M4, VMFLE_VF }, // 4783
  { PseudoVMFLE_VF32_M4_MASK, VMFLE_VF }, // 4784
  { PseudoVMFLE_VF32_M8, VMFLE_VF }, // 4785
  { PseudoVMFLE_VF32_M8_MASK, VMFLE_VF }, // 4786
  { PseudoVMFLE_VF32_MF2, VMFLE_VF }, // 4787
  { PseudoVMFLE_VF32_MF2_MASK, VMFLE_VF }, // 4788
  { PseudoVMFLE_VF64_M1, VMFLE_VF }, // 4789
  { PseudoVMFLE_VF64_M1_MASK, VMFLE_VF }, // 4790
  { PseudoVMFLE_VF64_M2, VMFLE_VF }, // 4791
  { PseudoVMFLE_VF64_M2_MASK, VMFLE_VF }, // 4792
  { PseudoVMFLE_VF64_M4, VMFLE_VF }, // 4793
  { PseudoVMFLE_VF64_M4_MASK, VMFLE_VF }, // 4794
  { PseudoVMFLE_VF64_M8, VMFLE_VF }, // 4795
  { PseudoVMFLE_VF64_M8_MASK, VMFLE_VF }, // 4796
  { PseudoVMFLE_VV_M1, VMFLE_VV }, // 4797
  { PseudoVMFLE_VV_M1_MASK, VMFLE_VV }, // 4798
  { PseudoVMFLE_VV_M2, VMFLE_VV }, // 4799
  { PseudoVMFLE_VV_M2_MASK, VMFLE_VV }, // 4800
  { PseudoVMFLE_VV_M4, VMFLE_VV }, // 4801
  { PseudoVMFLE_VV_M4_MASK, VMFLE_VV }, // 4802
  { PseudoVMFLE_VV_M8, VMFLE_VV }, // 4803
  { PseudoVMFLE_VV_M8_MASK, VMFLE_VV }, // 4804
  { PseudoVMFLE_VV_MF2, VMFLE_VV }, // 4805
  { PseudoVMFLE_VV_MF2_MASK, VMFLE_VV }, // 4806
  { PseudoVMFLE_VV_MF4, VMFLE_VV }, // 4807
  { PseudoVMFLE_VV_MF4_MASK, VMFLE_VV }, // 4808
  { PseudoVMFLT_VF16_M1, VMFLT_VF }, // 4809
  { PseudoVMFLT_VF16_M1_MASK, VMFLT_VF }, // 4810
  { PseudoVMFLT_VF16_M2, VMFLT_VF }, // 4811
  { PseudoVMFLT_VF16_M2_MASK, VMFLT_VF }, // 4812
  { PseudoVMFLT_VF16_M4, VMFLT_VF }, // 4813
  { PseudoVMFLT_VF16_M4_MASK, VMFLT_VF }, // 4814
  { PseudoVMFLT_VF16_M8, VMFLT_VF }, // 4815
  { PseudoVMFLT_VF16_M8_MASK, VMFLT_VF }, // 4816
  { PseudoVMFLT_VF16_MF2, VMFLT_VF }, // 4817
  { PseudoVMFLT_VF16_MF2_MASK, VMFLT_VF }, // 4818
  { PseudoVMFLT_VF16_MF4, VMFLT_VF }, // 4819
  { PseudoVMFLT_VF16_MF4_MASK, VMFLT_VF }, // 4820
  { PseudoVMFLT_VF32_M1, VMFLT_VF }, // 4821
  { PseudoVMFLT_VF32_M1_MASK, VMFLT_VF }, // 4822
  { PseudoVMFLT_VF32_M2, VMFLT_VF }, // 4823
  { PseudoVMFLT_VF32_M2_MASK, VMFLT_VF }, // 4824
  { PseudoVMFLT_VF32_M4, VMFLT_VF }, // 4825
  { PseudoVMFLT_VF32_M4_MASK, VMFLT_VF }, // 4826
  { PseudoVMFLT_VF32_M8, VMFLT_VF }, // 4827
  { PseudoVMFLT_VF32_M8_MASK, VMFLT_VF }, // 4828
  { PseudoVMFLT_VF32_MF2, VMFLT_VF }, // 4829
  { PseudoVMFLT_VF32_MF2_MASK, VMFLT_VF }, // 4830
  { PseudoVMFLT_VF64_M1, VMFLT_VF }, // 4831
  { PseudoVMFLT_VF64_M1_MASK, VMFLT_VF }, // 4832
  { PseudoVMFLT_VF64_M2, VMFLT_VF }, // 4833
  { PseudoVMFLT_VF64_M2_MASK, VMFLT_VF }, // 4834
  { PseudoVMFLT_VF64_M4, VMFLT_VF }, // 4835
  { PseudoVMFLT_VF64_M4_MASK, VMFLT_VF }, // 4836
  { PseudoVMFLT_VF64_M8, VMFLT_VF }, // 4837
  { PseudoVMFLT_VF64_M8_MASK, VMFLT_VF }, // 4838
  { PseudoVMFLT_VV_M1, VMFLT_VV }, // 4839
  { PseudoVMFLT_VV_M1_MASK, VMFLT_VV }, // 4840
  { PseudoVMFLT_VV_M2, VMFLT_VV }, // 4841
  { PseudoVMFLT_VV_M2_MASK, VMFLT_VV }, // 4842
  { PseudoVMFLT_VV_M4, VMFLT_VV }, // 4843
  { PseudoVMFLT_VV_M4_MASK, VMFLT_VV }, // 4844
  { PseudoVMFLT_VV_M8, VMFLT_VV }, // 4845
  { PseudoVMFLT_VV_M8_MASK, VMFLT_VV }, // 4846
  { PseudoVMFLT_VV_MF2, VMFLT_VV }, // 4847
  { PseudoVMFLT_VV_MF2_MASK, VMFLT_VV }, // 4848
  { PseudoVMFLT_VV_MF4, VMFLT_VV }, // 4849
  { PseudoVMFLT_VV_MF4_MASK, VMFLT_VV }, // 4850
  { PseudoVMFNE_VF16_M1, VMFNE_VF }, // 4851
  { PseudoVMFNE_VF16_M1_MASK, VMFNE_VF }, // 4852
  { PseudoVMFNE_VF16_M2, VMFNE_VF }, // 4853
  { PseudoVMFNE_VF16_M2_MASK, VMFNE_VF }, // 4854
  { PseudoVMFNE_VF16_M4, VMFNE_VF }, // 4855
  { PseudoVMFNE_VF16_M4_MASK, VMFNE_VF }, // 4856
  { PseudoVMFNE_VF16_M8, VMFNE_VF }, // 4857
  { PseudoVMFNE_VF16_M8_MASK, VMFNE_VF }, // 4858
  { PseudoVMFNE_VF16_MF2, VMFNE_VF }, // 4859
  { PseudoVMFNE_VF16_MF2_MASK, VMFNE_VF }, // 4860
  { PseudoVMFNE_VF16_MF4, VMFNE_VF }, // 4861
  { PseudoVMFNE_VF16_MF4_MASK, VMFNE_VF }, // 4862
  { PseudoVMFNE_VF32_M1, VMFNE_VF }, // 4863
  { PseudoVMFNE_VF32_M1_MASK, VMFNE_VF }, // 4864
  { PseudoVMFNE_VF32_M2, VMFNE_VF }, // 4865
  { PseudoVMFNE_VF32_M2_MASK, VMFNE_VF }, // 4866
  { PseudoVMFNE_VF32_M4, VMFNE_VF }, // 4867
  { PseudoVMFNE_VF32_M4_MASK, VMFNE_VF }, // 4868
  { PseudoVMFNE_VF32_M8, VMFNE_VF }, // 4869
  { PseudoVMFNE_VF32_M8_MASK, VMFNE_VF }, // 4870
  { PseudoVMFNE_VF32_MF2, VMFNE_VF }, // 4871
  { PseudoVMFNE_VF32_MF2_MASK, VMFNE_VF }, // 4872
  { PseudoVMFNE_VF64_M1, VMFNE_VF }, // 4873
  { PseudoVMFNE_VF64_M1_MASK, VMFNE_VF }, // 4874
  { PseudoVMFNE_VF64_M2, VMFNE_VF }, // 4875
  { PseudoVMFNE_VF64_M2_MASK, VMFNE_VF }, // 4876
  { PseudoVMFNE_VF64_M4, VMFNE_VF }, // 4877
  { PseudoVMFNE_VF64_M4_MASK, VMFNE_VF }, // 4878
  { PseudoVMFNE_VF64_M8, VMFNE_VF }, // 4879
  { PseudoVMFNE_VF64_M8_MASK, VMFNE_VF }, // 4880
  { PseudoVMFNE_VV_M1, VMFNE_VV }, // 4881
  { PseudoVMFNE_VV_M1_MASK, VMFNE_VV }, // 4882
  { PseudoVMFNE_VV_M2, VMFNE_VV }, // 4883
  { PseudoVMFNE_VV_M2_MASK, VMFNE_VV }, // 4884
  { PseudoVMFNE_VV_M4, VMFNE_VV }, // 4885
  { PseudoVMFNE_VV_M4_MASK, VMFNE_VV }, // 4886
  { PseudoVMFNE_VV_M8, VMFNE_VV }, // 4887
  { PseudoVMFNE_VV_M8_MASK, VMFNE_VV }, // 4888
  { PseudoVMFNE_VV_MF2, VMFNE_VV }, // 4889
  { PseudoVMFNE_VV_MF2_MASK, VMFNE_VV }, // 4890
  { PseudoVMFNE_VV_MF4, VMFNE_VV }, // 4891
  { PseudoVMFNE_VV_MF4_MASK, VMFNE_VV }, // 4892
  { PseudoVMINU_VV_M1, VMINU_VV }, // 4893
  { PseudoVMINU_VV_M1_MASK, VMINU_VV }, // 4894
  { PseudoVMINU_VV_M2, VMINU_VV }, // 4895
  { PseudoVMINU_VV_M2_MASK, VMINU_VV }, // 4896
  { PseudoVMINU_VV_M4, VMINU_VV }, // 4897
  { PseudoVMINU_VV_M4_MASK, VMINU_VV }, // 4898
  { PseudoVMINU_VV_M8, VMINU_VV }, // 4899
  { PseudoVMINU_VV_M8_MASK, VMINU_VV }, // 4900
  { PseudoVMINU_VV_MF2, VMINU_VV }, // 4901
  { PseudoVMINU_VV_MF2_MASK, VMINU_VV }, // 4902
  { PseudoVMINU_VV_MF4, VMINU_VV }, // 4903
  { PseudoVMINU_VV_MF4_MASK, VMINU_VV }, // 4904
  { PseudoVMINU_VV_MF8, VMINU_VV }, // 4905
  { PseudoVMINU_VV_MF8_MASK, VMINU_VV }, // 4906
  { PseudoVMINU_VX_M1, VMINU_VX }, // 4907
  { PseudoVMINU_VX_M1_MASK, VMINU_VX }, // 4908
  { PseudoVMINU_VX_M2, VMINU_VX }, // 4909
  { PseudoVMINU_VX_M2_MASK, VMINU_VX }, // 4910
  { PseudoVMINU_VX_M4, VMINU_VX }, // 4911
  { PseudoVMINU_VX_M4_MASK, VMINU_VX }, // 4912
  { PseudoVMINU_VX_M8, VMINU_VX }, // 4913
  { PseudoVMINU_VX_M8_MASK, VMINU_VX }, // 4914
  { PseudoVMINU_VX_MF2, VMINU_VX }, // 4915
  { PseudoVMINU_VX_MF2_MASK, VMINU_VX }, // 4916
  { PseudoVMINU_VX_MF4, VMINU_VX }, // 4917
  { PseudoVMINU_VX_MF4_MASK, VMINU_VX }, // 4918
  { PseudoVMINU_VX_MF8, VMINU_VX }, // 4919
  { PseudoVMINU_VX_MF8_MASK, VMINU_VX }, // 4920
  { PseudoVMIN_VV_M1, VMIN_VV }, // 4921
  { PseudoVMIN_VV_M1_MASK, VMIN_VV }, // 4922
  { PseudoVMIN_VV_M2, VMIN_VV }, // 4923
  { PseudoVMIN_VV_M2_MASK, VMIN_VV }, // 4924
  { PseudoVMIN_VV_M4, VMIN_VV }, // 4925
  { PseudoVMIN_VV_M4_MASK, VMIN_VV }, // 4926
  { PseudoVMIN_VV_M8, VMIN_VV }, // 4927
  { PseudoVMIN_VV_M8_MASK, VMIN_VV }, // 4928
  { PseudoVMIN_VV_MF2, VMIN_VV }, // 4929
  { PseudoVMIN_VV_MF2_MASK, VMIN_VV }, // 4930
  { PseudoVMIN_VV_MF4, VMIN_VV }, // 4931
  { PseudoVMIN_VV_MF4_MASK, VMIN_VV }, // 4932
  { PseudoVMIN_VV_MF8, VMIN_VV }, // 4933
  { PseudoVMIN_VV_MF8_MASK, VMIN_VV }, // 4934
  { PseudoVMIN_VX_M1, VMIN_VX }, // 4935
  { PseudoVMIN_VX_M1_MASK, VMIN_VX }, // 4936
  { PseudoVMIN_VX_M2, VMIN_VX }, // 4937
  { PseudoVMIN_VX_M2_MASK, VMIN_VX }, // 4938
  { PseudoVMIN_VX_M4, VMIN_VX }, // 4939
  { PseudoVMIN_VX_M4_MASK, VMIN_VX }, // 4940
  { PseudoVMIN_VX_M8, VMIN_VX }, // 4941
  { PseudoVMIN_VX_M8_MASK, VMIN_VX }, // 4942
  { PseudoVMIN_VX_MF2, VMIN_VX }, // 4943
  { PseudoVMIN_VX_MF2_MASK, VMIN_VX }, // 4944
  { PseudoVMIN_VX_MF4, VMIN_VX }, // 4945
  { PseudoVMIN_VX_MF4_MASK, VMIN_VX }, // 4946
  { PseudoVMIN_VX_MF8, VMIN_VX }, // 4947
  { PseudoVMIN_VX_MF8_MASK, VMIN_VX }, // 4948
  { PseudoVMNAND_MM_M1, VMNAND_MM }, // 4949
  { PseudoVMNAND_MM_M2, VMNAND_MM }, // 4950
  { PseudoVMNAND_MM_M4, VMNAND_MM }, // 4951
  { PseudoVMNAND_MM_M8, VMNAND_MM }, // 4952
  { PseudoVMNAND_MM_MF2, VMNAND_MM }, // 4953
  { PseudoVMNAND_MM_MF4, VMNAND_MM }, // 4954
  { PseudoVMNAND_MM_MF8, VMNAND_MM }, // 4955
  { PseudoVMNOR_MM_M1, VMNOR_MM }, // 4956
  { PseudoVMNOR_MM_M2, VMNOR_MM }, // 4957
  { PseudoVMNOR_MM_M4, VMNOR_MM }, // 4958
  { PseudoVMNOR_MM_M8, VMNOR_MM }, // 4959
  { PseudoVMNOR_MM_MF2, VMNOR_MM }, // 4960
  { PseudoVMNOR_MM_MF4, VMNOR_MM }, // 4961
  { PseudoVMNOR_MM_MF8, VMNOR_MM }, // 4962
  { PseudoVMORN_MM_M1, VMORN_MM }, // 4963
  { PseudoVMORN_MM_M2, VMORN_MM }, // 4964
  { PseudoVMORN_MM_M4, VMORN_MM }, // 4965
  { PseudoVMORN_MM_M8, VMORN_MM }, // 4966
  { PseudoVMORN_MM_MF2, VMORN_MM }, // 4967
  { PseudoVMORN_MM_MF4, VMORN_MM }, // 4968
  { PseudoVMORN_MM_MF8, VMORN_MM }, // 4969
  { PseudoVMOR_MM_M1, VMOR_MM }, // 4970
  { PseudoVMOR_MM_M2, VMOR_MM }, // 4971
  { PseudoVMOR_MM_M4, VMOR_MM }, // 4972
  { PseudoVMOR_MM_M8, VMOR_MM }, // 4973
  { PseudoVMOR_MM_MF2, VMOR_MM }, // 4974
  { PseudoVMOR_MM_MF4, VMOR_MM }, // 4975
  { PseudoVMOR_MM_MF8, VMOR_MM }, // 4976
  { PseudoVMSBC_VVM_M1, VMSBC_VVM }, // 4977
  { PseudoVMSBC_VVM_M2, VMSBC_VVM }, // 4978
  { PseudoVMSBC_VVM_M4, VMSBC_VVM }, // 4979
  { PseudoVMSBC_VVM_M8, VMSBC_VVM }, // 4980
  { PseudoVMSBC_VVM_MF2, VMSBC_VVM }, // 4981
  { PseudoVMSBC_VVM_MF4, VMSBC_VVM }, // 4982
  { PseudoVMSBC_VVM_MF8, VMSBC_VVM }, // 4983
  { PseudoVMSBC_VV_M1, VMSBC_VV }, // 4984
  { PseudoVMSBC_VV_M2, VMSBC_VV }, // 4985
  { PseudoVMSBC_VV_M4, VMSBC_VV }, // 4986
  { PseudoVMSBC_VV_M8, VMSBC_VV }, // 4987
  { PseudoVMSBC_VV_MF2, VMSBC_VV }, // 4988
  { PseudoVMSBC_VV_MF4, VMSBC_VV }, // 4989
  { PseudoVMSBC_VV_MF8, VMSBC_VV }, // 4990
  { PseudoVMSBC_VXM_M1, VMSBC_VXM }, // 4991
  { PseudoVMSBC_VXM_M2, VMSBC_VXM }, // 4992
  { PseudoVMSBC_VXM_M4, VMSBC_VXM }, // 4993
  { PseudoVMSBC_VXM_M8, VMSBC_VXM }, // 4994
  { PseudoVMSBC_VXM_MF2, VMSBC_VXM }, // 4995
  { PseudoVMSBC_VXM_MF4, VMSBC_VXM }, // 4996
  { PseudoVMSBC_VXM_MF8, VMSBC_VXM }, // 4997
  { PseudoVMSBC_VX_M1, VMSBC_VX }, // 4998
  { PseudoVMSBC_VX_M2, VMSBC_VX }, // 4999
  { PseudoVMSBC_VX_M4, VMSBC_VX }, // 5000
  { PseudoVMSBC_VX_M8, VMSBC_VX }, // 5001
  { PseudoVMSBC_VX_MF2, VMSBC_VX }, // 5002
  { PseudoVMSBC_VX_MF4, VMSBC_VX }, // 5003
  { PseudoVMSBC_VX_MF8, VMSBC_VX }, // 5004
  { PseudoVMSBF_M_B1, VMSBF_M }, // 5005
  { PseudoVMSBF_M_B16, VMSBF_M }, // 5006
  { PseudoVMSBF_M_B16_MASK, VMSBF_M }, // 5007
  { PseudoVMSBF_M_B1_MASK, VMSBF_M }, // 5008
  { PseudoVMSBF_M_B2, VMSBF_M }, // 5009
  { PseudoVMSBF_M_B2_MASK, VMSBF_M }, // 5010
  { PseudoVMSBF_M_B32, VMSBF_M }, // 5011
  { PseudoVMSBF_M_B32_MASK, VMSBF_M }, // 5012
  { PseudoVMSBF_M_B4, VMSBF_M }, // 5013
  { PseudoVMSBF_M_B4_MASK, VMSBF_M }, // 5014
  { PseudoVMSBF_M_B64, VMSBF_M }, // 5015
  { PseudoVMSBF_M_B64_MASK, VMSBF_M }, // 5016
  { PseudoVMSBF_M_B8, VMSBF_M }, // 5017
  { PseudoVMSBF_M_B8_MASK, VMSBF_M }, // 5018
  { PseudoVMSEQ_VI_M1, VMSEQ_VI }, // 5019
  { PseudoVMSEQ_VI_M1_MASK, VMSEQ_VI }, // 5020
  { PseudoVMSEQ_VI_M2, VMSEQ_VI }, // 5021
  { PseudoVMSEQ_VI_M2_MASK, VMSEQ_VI }, // 5022
  { PseudoVMSEQ_VI_M4, VMSEQ_VI }, // 5023
  { PseudoVMSEQ_VI_M4_MASK, VMSEQ_VI }, // 5024
  { PseudoVMSEQ_VI_M8, VMSEQ_VI }, // 5025
  { PseudoVMSEQ_VI_M8_MASK, VMSEQ_VI }, // 5026
  { PseudoVMSEQ_VI_MF2, VMSEQ_VI }, // 5027
  { PseudoVMSEQ_VI_MF2_MASK, VMSEQ_VI }, // 5028
  { PseudoVMSEQ_VI_MF4, VMSEQ_VI }, // 5029
  { PseudoVMSEQ_VI_MF4_MASK, VMSEQ_VI }, // 5030
  { PseudoVMSEQ_VI_MF8, VMSEQ_VI }, // 5031
  { PseudoVMSEQ_VI_MF8_MASK, VMSEQ_VI }, // 5032
  { PseudoVMSEQ_VV_M1, VMSEQ_VV }, // 5033
  { PseudoVMSEQ_VV_M1_MASK, VMSEQ_VV }, // 5034
  { PseudoVMSEQ_VV_M2, VMSEQ_VV }, // 5035
  { PseudoVMSEQ_VV_M2_MASK, VMSEQ_VV }, // 5036
  { PseudoVMSEQ_VV_M4, VMSEQ_VV }, // 5037
  { PseudoVMSEQ_VV_M4_MASK, VMSEQ_VV }, // 5038
  { PseudoVMSEQ_VV_M8, VMSEQ_VV }, // 5039
  { PseudoVMSEQ_VV_M8_MASK, VMSEQ_VV }, // 5040
  { PseudoVMSEQ_VV_MF2, VMSEQ_VV }, // 5041
  { PseudoVMSEQ_VV_MF2_MASK, VMSEQ_VV }, // 5042
  { PseudoVMSEQ_VV_MF4, VMSEQ_VV }, // 5043
  { PseudoVMSEQ_VV_MF4_MASK, VMSEQ_VV }, // 5044
  { PseudoVMSEQ_VV_MF8, VMSEQ_VV }, // 5045
  { PseudoVMSEQ_VV_MF8_MASK, VMSEQ_VV }, // 5046
  { PseudoVMSEQ_VX_M1, VMSEQ_VX }, // 5047
  { PseudoVMSEQ_VX_M1_MASK, VMSEQ_VX }, // 5048
  { PseudoVMSEQ_VX_M2, VMSEQ_VX }, // 5049
  { PseudoVMSEQ_VX_M2_MASK, VMSEQ_VX }, // 5050
  { PseudoVMSEQ_VX_M4, VMSEQ_VX }, // 5051
  { PseudoVMSEQ_VX_M4_MASK, VMSEQ_VX }, // 5052
  { PseudoVMSEQ_VX_M8, VMSEQ_VX }, // 5053
  { PseudoVMSEQ_VX_M8_MASK, VMSEQ_VX }, // 5054
  { PseudoVMSEQ_VX_MF2, VMSEQ_VX }, // 5055
  { PseudoVMSEQ_VX_MF2_MASK, VMSEQ_VX }, // 5056
  { PseudoVMSEQ_VX_MF4, VMSEQ_VX }, // 5057
  { PseudoVMSEQ_VX_MF4_MASK, VMSEQ_VX }, // 5058
  { PseudoVMSEQ_VX_MF8, VMSEQ_VX }, // 5059
  { PseudoVMSEQ_VX_MF8_MASK, VMSEQ_VX }, // 5060
  { PseudoVMSET_M_B1, VMXNOR_MM }, // 5061
  { PseudoVMSET_M_B16, VMXNOR_MM }, // 5062
  { PseudoVMSET_M_B2, VMXNOR_MM }, // 5063
  { PseudoVMSET_M_B32, VMXNOR_MM }, // 5064
  { PseudoVMSET_M_B4, VMXNOR_MM }, // 5065
  { PseudoVMSET_M_B64, VMXNOR_MM }, // 5066
  { PseudoVMSET_M_B8, VMXNOR_MM }, // 5067
  { PseudoVMSGTU_VI_M1, VMSGTU_VI }, // 5068
  { PseudoVMSGTU_VI_M1_MASK, VMSGTU_VI }, // 5069
  { PseudoVMSGTU_VI_M2, VMSGTU_VI }, // 5070
  { PseudoVMSGTU_VI_M2_MASK, VMSGTU_VI }, // 5071
  { PseudoVMSGTU_VI_M4, VMSGTU_VI }, // 5072
  { PseudoVMSGTU_VI_M4_MASK, VMSGTU_VI }, // 5073
  { PseudoVMSGTU_VI_M8, VMSGTU_VI }, // 5074
  { PseudoVMSGTU_VI_M8_MASK, VMSGTU_VI }, // 5075
  { PseudoVMSGTU_VI_MF2, VMSGTU_VI }, // 5076
  { PseudoVMSGTU_VI_MF2_MASK, VMSGTU_VI }, // 5077
  { PseudoVMSGTU_VI_MF4, VMSGTU_VI }, // 5078
  { PseudoVMSGTU_VI_MF4_MASK, VMSGTU_VI }, // 5079
  { PseudoVMSGTU_VI_MF8, VMSGTU_VI }, // 5080
  { PseudoVMSGTU_VI_MF8_MASK, VMSGTU_VI }, // 5081
  { PseudoVMSGTU_VX_M1, VMSGTU_VX }, // 5082
  { PseudoVMSGTU_VX_M1_MASK, VMSGTU_VX }, // 5083
  { PseudoVMSGTU_VX_M2, VMSGTU_VX }, // 5084
  { PseudoVMSGTU_VX_M2_MASK, VMSGTU_VX }, // 5085
  { PseudoVMSGTU_VX_M4, VMSGTU_VX }, // 5086
  { PseudoVMSGTU_VX_M4_MASK, VMSGTU_VX }, // 5087
  { PseudoVMSGTU_VX_M8, VMSGTU_VX }, // 5088
  { PseudoVMSGTU_VX_M8_MASK, VMSGTU_VX }, // 5089
  { PseudoVMSGTU_VX_MF2, VMSGTU_VX }, // 5090
  { PseudoVMSGTU_VX_MF2_MASK, VMSGTU_VX }, // 5091
  { PseudoVMSGTU_VX_MF4, VMSGTU_VX }, // 5092
  { PseudoVMSGTU_VX_MF4_MASK, VMSGTU_VX }, // 5093
  { PseudoVMSGTU_VX_MF8, VMSGTU_VX }, // 5094
  { PseudoVMSGTU_VX_MF8_MASK, VMSGTU_VX }, // 5095
  { PseudoVMSGT_VI_M1, VMSGT_VI }, // 5096
  { PseudoVMSGT_VI_M1_MASK, VMSGT_VI }, // 5097
  { PseudoVMSGT_VI_M2, VMSGT_VI }, // 5098
  { PseudoVMSGT_VI_M2_MASK, VMSGT_VI }, // 5099
  { PseudoVMSGT_VI_M4, VMSGT_VI }, // 5100
  { PseudoVMSGT_VI_M4_MASK, VMSGT_VI }, // 5101
  { PseudoVMSGT_VI_M8, VMSGT_VI }, // 5102
  { PseudoVMSGT_VI_M8_MASK, VMSGT_VI }, // 5103
  { PseudoVMSGT_VI_MF2, VMSGT_VI }, // 5104
  { PseudoVMSGT_VI_MF2_MASK, VMSGT_VI }, // 5105
  { PseudoVMSGT_VI_MF4, VMSGT_VI }, // 5106
  { PseudoVMSGT_VI_MF4_MASK, VMSGT_VI }, // 5107
  { PseudoVMSGT_VI_MF8, VMSGT_VI }, // 5108
  { PseudoVMSGT_VI_MF8_MASK, VMSGT_VI }, // 5109
  { PseudoVMSGT_VX_M1, VMSGT_VX }, // 5110
  { PseudoVMSGT_VX_M1_MASK, VMSGT_VX }, // 5111
  { PseudoVMSGT_VX_M2, VMSGT_VX }, // 5112
  { PseudoVMSGT_VX_M2_MASK, VMSGT_VX }, // 5113
  { PseudoVMSGT_VX_M4, VMSGT_VX }, // 5114
  { PseudoVMSGT_VX_M4_MASK, VMSGT_VX }, // 5115
  { PseudoVMSGT_VX_M8, VMSGT_VX }, // 5116
  { PseudoVMSGT_VX_M8_MASK, VMSGT_VX }, // 5117
  { PseudoVMSGT_VX_MF2, VMSGT_VX }, // 5118
  { PseudoVMSGT_VX_MF2_MASK, VMSGT_VX }, // 5119
  { PseudoVMSGT_VX_MF4, VMSGT_VX }, // 5120
  { PseudoVMSGT_VX_MF4_MASK, VMSGT_VX }, // 5121
  { PseudoVMSGT_VX_MF8, VMSGT_VX }, // 5122
  { PseudoVMSGT_VX_MF8_MASK, VMSGT_VX }, // 5123
  { PseudoVMSIF_M_B1, VMSIF_M }, // 5124
  { PseudoVMSIF_M_B16, VMSIF_M }, // 5125
  { PseudoVMSIF_M_B16_MASK, VMSIF_M }, // 5126
  { PseudoVMSIF_M_B1_MASK, VMSIF_M }, // 5127
  { PseudoVMSIF_M_B2, VMSIF_M }, // 5128
  { PseudoVMSIF_M_B2_MASK, VMSIF_M }, // 5129
  { PseudoVMSIF_M_B32, VMSIF_M }, // 5130
  { PseudoVMSIF_M_B32_MASK, VMSIF_M }, // 5131
  { PseudoVMSIF_M_B4, VMSIF_M }, // 5132
  { PseudoVMSIF_M_B4_MASK, VMSIF_M }, // 5133
  { PseudoVMSIF_M_B64, VMSIF_M }, // 5134
  { PseudoVMSIF_M_B64_MASK, VMSIF_M }, // 5135
  { PseudoVMSIF_M_B8, VMSIF_M }, // 5136
  { PseudoVMSIF_M_B8_MASK, VMSIF_M }, // 5137
  { PseudoVMSLEU_VI_M1, VMSLEU_VI }, // 5138
  { PseudoVMSLEU_VI_M1_MASK, VMSLEU_VI }, // 5139
  { PseudoVMSLEU_VI_M2, VMSLEU_VI }, // 5140
  { PseudoVMSLEU_VI_M2_MASK, VMSLEU_VI }, // 5141
  { PseudoVMSLEU_VI_M4, VMSLEU_VI }, // 5142
  { PseudoVMSLEU_VI_M4_MASK, VMSLEU_VI }, // 5143
  { PseudoVMSLEU_VI_M8, VMSLEU_VI }, // 5144
  { PseudoVMSLEU_VI_M8_MASK, VMSLEU_VI }, // 5145
  { PseudoVMSLEU_VI_MF2, VMSLEU_VI }, // 5146
  { PseudoVMSLEU_VI_MF2_MASK, VMSLEU_VI }, // 5147
  { PseudoVMSLEU_VI_MF4, VMSLEU_VI }, // 5148
  { PseudoVMSLEU_VI_MF4_MASK, VMSLEU_VI }, // 5149
  { PseudoVMSLEU_VI_MF8, VMSLEU_VI }, // 5150
  { PseudoVMSLEU_VI_MF8_MASK, VMSLEU_VI }, // 5151
  { PseudoVMSLEU_VV_M1, VMSLEU_VV }, // 5152
  { PseudoVMSLEU_VV_M1_MASK, VMSLEU_VV }, // 5153
  { PseudoVMSLEU_VV_M2, VMSLEU_VV }, // 5154
  { PseudoVMSLEU_VV_M2_MASK, VMSLEU_VV }, // 5155
  { PseudoVMSLEU_VV_M4, VMSLEU_VV }, // 5156
  { PseudoVMSLEU_VV_M4_MASK, VMSLEU_VV }, // 5157
  { PseudoVMSLEU_VV_M8, VMSLEU_VV }, // 5158
  { PseudoVMSLEU_VV_M8_MASK, VMSLEU_VV }, // 5159
  { PseudoVMSLEU_VV_MF2, VMSLEU_VV }, // 5160
  { PseudoVMSLEU_VV_MF2_MASK, VMSLEU_VV }, // 5161
  { PseudoVMSLEU_VV_MF4, VMSLEU_VV }, // 5162
  { PseudoVMSLEU_VV_MF4_MASK, VMSLEU_VV }, // 5163
  { PseudoVMSLEU_VV_MF8, VMSLEU_VV }, // 5164
  { PseudoVMSLEU_VV_MF8_MASK, VMSLEU_VV }, // 5165
  { PseudoVMSLEU_VX_M1, VMSLEU_VX }, // 5166
  { PseudoVMSLEU_VX_M1_MASK, VMSLEU_VX }, // 5167
  { PseudoVMSLEU_VX_M2, VMSLEU_VX }, // 5168
  { PseudoVMSLEU_VX_M2_MASK, VMSLEU_VX }, // 5169
  { PseudoVMSLEU_VX_M4, VMSLEU_VX }, // 5170
  { PseudoVMSLEU_VX_M4_MASK, VMSLEU_VX }, // 5171
  { PseudoVMSLEU_VX_M8, VMSLEU_VX }, // 5172
  { PseudoVMSLEU_VX_M8_MASK, VMSLEU_VX }, // 5173
  { PseudoVMSLEU_VX_MF2, VMSLEU_VX }, // 5174
  { PseudoVMSLEU_VX_MF2_MASK, VMSLEU_VX }, // 5175
  { PseudoVMSLEU_VX_MF4, VMSLEU_VX }, // 5176
  { PseudoVMSLEU_VX_MF4_MASK, VMSLEU_VX }, // 5177
  { PseudoVMSLEU_VX_MF8, VMSLEU_VX }, // 5178
  { PseudoVMSLEU_VX_MF8_MASK, VMSLEU_VX }, // 5179
  { PseudoVMSLE_VI_M1, VMSLE_VI }, // 5180
  { PseudoVMSLE_VI_M1_MASK, VMSLE_VI }, // 5181
  { PseudoVMSLE_VI_M2, VMSLE_VI }, // 5182
  { PseudoVMSLE_VI_M2_MASK, VMSLE_VI }, // 5183
  { PseudoVMSLE_VI_M4, VMSLE_VI }, // 5184
  { PseudoVMSLE_VI_M4_MASK, VMSLE_VI }, // 5185
  { PseudoVMSLE_VI_M8, VMSLE_VI }, // 5186
  { PseudoVMSLE_VI_M8_MASK, VMSLE_VI }, // 5187
  { PseudoVMSLE_VI_MF2, VMSLE_VI }, // 5188
  { PseudoVMSLE_VI_MF2_MASK, VMSLE_VI }, // 5189
  { PseudoVMSLE_VI_MF4, VMSLE_VI }, // 5190
  { PseudoVMSLE_VI_MF4_MASK, VMSLE_VI }, // 5191
  { PseudoVMSLE_VI_MF8, VMSLE_VI }, // 5192
  { PseudoVMSLE_VI_MF8_MASK, VMSLE_VI }, // 5193
  { PseudoVMSLE_VV_M1, VMSLE_VV }, // 5194
  { PseudoVMSLE_VV_M1_MASK, VMSLE_VV }, // 5195
  { PseudoVMSLE_VV_M2, VMSLE_VV }, // 5196
  { PseudoVMSLE_VV_M2_MASK, VMSLE_VV }, // 5197
  { PseudoVMSLE_VV_M4, VMSLE_VV }, // 5198
  { PseudoVMSLE_VV_M4_MASK, VMSLE_VV }, // 5199
  { PseudoVMSLE_VV_M8, VMSLE_VV }, // 5200
  { PseudoVMSLE_VV_M8_MASK, VMSLE_VV }, // 5201
  { PseudoVMSLE_VV_MF2, VMSLE_VV }, // 5202
  { PseudoVMSLE_VV_MF2_MASK, VMSLE_VV }, // 5203
  { PseudoVMSLE_VV_MF4, VMSLE_VV }, // 5204
  { PseudoVMSLE_VV_MF4_MASK, VMSLE_VV }, // 5205
  { PseudoVMSLE_VV_MF8, VMSLE_VV }, // 5206
  { PseudoVMSLE_VV_MF8_MASK, VMSLE_VV }, // 5207
  { PseudoVMSLE_VX_M1, VMSLE_VX }, // 5208
  { PseudoVMSLE_VX_M1_MASK, VMSLE_VX }, // 5209
  { PseudoVMSLE_VX_M2, VMSLE_VX }, // 5210
  { PseudoVMSLE_VX_M2_MASK, VMSLE_VX }, // 5211
  { PseudoVMSLE_VX_M4, VMSLE_VX }, // 5212
  { PseudoVMSLE_VX_M4_MASK, VMSLE_VX }, // 5213
  { PseudoVMSLE_VX_M8, VMSLE_VX }, // 5214
  { PseudoVMSLE_VX_M8_MASK, VMSLE_VX }, // 5215
  { PseudoVMSLE_VX_MF2, VMSLE_VX }, // 5216
  { PseudoVMSLE_VX_MF2_MASK, VMSLE_VX }, // 5217
  { PseudoVMSLE_VX_MF4, VMSLE_VX }, // 5218
  { PseudoVMSLE_VX_MF4_MASK, VMSLE_VX }, // 5219
  { PseudoVMSLE_VX_MF8, VMSLE_VX }, // 5220
  { PseudoVMSLE_VX_MF8_MASK, VMSLE_VX }, // 5221
  { PseudoVMSLTU_VV_M1, VMSLTU_VV }, // 5222
  { PseudoVMSLTU_VV_M1_MASK, VMSLTU_VV }, // 5223
  { PseudoVMSLTU_VV_M2, VMSLTU_VV }, // 5224
  { PseudoVMSLTU_VV_M2_MASK, VMSLTU_VV }, // 5225
  { PseudoVMSLTU_VV_M4, VMSLTU_VV }, // 5226
  { PseudoVMSLTU_VV_M4_MASK, VMSLTU_VV }, // 5227
  { PseudoVMSLTU_VV_M8, VMSLTU_VV }, // 5228
  { PseudoVMSLTU_VV_M8_MASK, VMSLTU_VV }, // 5229
  { PseudoVMSLTU_VV_MF2, VMSLTU_VV }, // 5230
  { PseudoVMSLTU_VV_MF2_MASK, VMSLTU_VV }, // 5231
  { PseudoVMSLTU_VV_MF4, VMSLTU_VV }, // 5232
  { PseudoVMSLTU_VV_MF4_MASK, VMSLTU_VV }, // 5233
  { PseudoVMSLTU_VV_MF8, VMSLTU_VV }, // 5234
  { PseudoVMSLTU_VV_MF8_MASK, VMSLTU_VV }, // 5235
  { PseudoVMSLTU_VX_M1, VMSLTU_VX }, // 5236
  { PseudoVMSLTU_VX_M1_MASK, VMSLTU_VX }, // 5237
  { PseudoVMSLTU_VX_M2, VMSLTU_VX }, // 5238
  { PseudoVMSLTU_VX_M2_MASK, VMSLTU_VX }, // 5239
  { PseudoVMSLTU_VX_M4, VMSLTU_VX }, // 5240
  { PseudoVMSLTU_VX_M4_MASK, VMSLTU_VX }, // 5241
  { PseudoVMSLTU_VX_M8, VMSLTU_VX }, // 5242
  { PseudoVMSLTU_VX_M8_MASK, VMSLTU_VX }, // 5243
  { PseudoVMSLTU_VX_MF2, VMSLTU_VX }, // 5244
  { PseudoVMSLTU_VX_MF2_MASK, VMSLTU_VX }, // 5245
  { PseudoVMSLTU_VX_MF4, VMSLTU_VX }, // 5246
  { PseudoVMSLTU_VX_MF4_MASK, VMSLTU_VX }, // 5247
  { PseudoVMSLTU_VX_MF8, VMSLTU_VX }, // 5248
  { PseudoVMSLTU_VX_MF8_MASK, VMSLTU_VX }, // 5249
  { PseudoVMSLT_VV_M1, VMSLT_VV }, // 5250
  { PseudoVMSLT_VV_M1_MASK, VMSLT_VV }, // 5251
  { PseudoVMSLT_VV_M2, VMSLT_VV }, // 5252
  { PseudoVMSLT_VV_M2_MASK, VMSLT_VV }, // 5253
  { PseudoVMSLT_VV_M4, VMSLT_VV }, // 5254
  { PseudoVMSLT_VV_M4_MASK, VMSLT_VV }, // 5255
  { PseudoVMSLT_VV_M8, VMSLT_VV }, // 5256
  { PseudoVMSLT_VV_M8_MASK, VMSLT_VV }, // 5257
  { PseudoVMSLT_VV_MF2, VMSLT_VV }, // 5258
  { PseudoVMSLT_VV_MF2_MASK, VMSLT_VV }, // 5259
  { PseudoVMSLT_VV_MF4, VMSLT_VV }, // 5260
  { PseudoVMSLT_VV_MF4_MASK, VMSLT_VV }, // 5261
  { PseudoVMSLT_VV_MF8, VMSLT_VV }, // 5262
  { PseudoVMSLT_VV_MF8_MASK, VMSLT_VV }, // 5263
  { PseudoVMSLT_VX_M1, VMSLT_VX }, // 5264
  { PseudoVMSLT_VX_M1_MASK, VMSLT_VX }, // 5265
  { PseudoVMSLT_VX_M2, VMSLT_VX }, // 5266
  { PseudoVMSLT_VX_M2_MASK, VMSLT_VX }, // 5267
  { PseudoVMSLT_VX_M4, VMSLT_VX }, // 5268
  { PseudoVMSLT_VX_M4_MASK, VMSLT_VX }, // 5269
  { PseudoVMSLT_VX_M8, VMSLT_VX }, // 5270
  { PseudoVMSLT_VX_M8_MASK, VMSLT_VX }, // 5271
  { PseudoVMSLT_VX_MF2, VMSLT_VX }, // 5272
  { PseudoVMSLT_VX_MF2_MASK, VMSLT_VX }, // 5273
  { PseudoVMSLT_VX_MF4, VMSLT_VX }, // 5274
  { PseudoVMSLT_VX_MF4_MASK, VMSLT_VX }, // 5275
  { PseudoVMSLT_VX_MF8, VMSLT_VX }, // 5276
  { PseudoVMSLT_VX_MF8_MASK, VMSLT_VX }, // 5277
  { PseudoVMSNE_VI_M1, VMSNE_VI }, // 5278
  { PseudoVMSNE_VI_M1_MASK, VMSNE_VI }, // 5279
  { PseudoVMSNE_VI_M2, VMSNE_VI }, // 5280
  { PseudoVMSNE_VI_M2_MASK, VMSNE_VI }, // 5281
  { PseudoVMSNE_VI_M4, VMSNE_VI }, // 5282
  { PseudoVMSNE_VI_M4_MASK, VMSNE_VI }, // 5283
  { PseudoVMSNE_VI_M8, VMSNE_VI }, // 5284
  { PseudoVMSNE_VI_M8_MASK, VMSNE_VI }, // 5285
  { PseudoVMSNE_VI_MF2, VMSNE_VI }, // 5286
  { PseudoVMSNE_VI_MF2_MASK, VMSNE_VI }, // 5287
  { PseudoVMSNE_VI_MF4, VMSNE_VI }, // 5288
  { PseudoVMSNE_VI_MF4_MASK, VMSNE_VI }, // 5289
  { PseudoVMSNE_VI_MF8, VMSNE_VI }, // 5290
  { PseudoVMSNE_VI_MF8_MASK, VMSNE_VI }, // 5291
  { PseudoVMSNE_VV_M1, VMSNE_VV }, // 5292
  { PseudoVMSNE_VV_M1_MASK, VMSNE_VV }, // 5293
  { PseudoVMSNE_VV_M2, VMSNE_VV }, // 5294
  { PseudoVMSNE_VV_M2_MASK, VMSNE_VV }, // 5295
  { PseudoVMSNE_VV_M4, VMSNE_VV }, // 5296
  { PseudoVMSNE_VV_M4_MASK, VMSNE_VV }, // 5297
  { PseudoVMSNE_VV_M8, VMSNE_VV }, // 5298
  { PseudoVMSNE_VV_M8_MASK, VMSNE_VV }, // 5299
  { PseudoVMSNE_VV_MF2, VMSNE_VV }, // 5300
  { PseudoVMSNE_VV_MF2_MASK, VMSNE_VV }, // 5301
  { PseudoVMSNE_VV_MF4, VMSNE_VV }, // 5302
  { PseudoVMSNE_VV_MF4_MASK, VMSNE_VV }, // 5303
  { PseudoVMSNE_VV_MF8, VMSNE_VV }, // 5304
  { PseudoVMSNE_VV_MF8_MASK, VMSNE_VV }, // 5305
  { PseudoVMSNE_VX_M1, VMSNE_VX }, // 5306
  { PseudoVMSNE_VX_M1_MASK, VMSNE_VX }, // 5307
  { PseudoVMSNE_VX_M2, VMSNE_VX }, // 5308
  { PseudoVMSNE_VX_M2_MASK, VMSNE_VX }, // 5309
  { PseudoVMSNE_VX_M4, VMSNE_VX }, // 5310
  { PseudoVMSNE_VX_M4_MASK, VMSNE_VX }, // 5311
  { PseudoVMSNE_VX_M8, VMSNE_VX }, // 5312
  { PseudoVMSNE_VX_M8_MASK, VMSNE_VX }, // 5313
  { PseudoVMSNE_VX_MF2, VMSNE_VX }, // 5314
  { PseudoVMSNE_VX_MF2_MASK, VMSNE_VX }, // 5315
  { PseudoVMSNE_VX_MF4, VMSNE_VX }, // 5316
  { PseudoVMSNE_VX_MF4_MASK, VMSNE_VX }, // 5317
  { PseudoVMSNE_VX_MF8, VMSNE_VX }, // 5318
  { PseudoVMSNE_VX_MF8_MASK, VMSNE_VX }, // 5319
  { PseudoVMSOF_M_B1, VMSOF_M }, // 5320
  { PseudoVMSOF_M_B16, VMSOF_M }, // 5321
  { PseudoVMSOF_M_B16_MASK, VMSOF_M }, // 5322
  { PseudoVMSOF_M_B1_MASK, VMSOF_M }, // 5323
  { PseudoVMSOF_M_B2, VMSOF_M }, // 5324
  { PseudoVMSOF_M_B2_MASK, VMSOF_M }, // 5325
  { PseudoVMSOF_M_B32, VMSOF_M }, // 5326
  { PseudoVMSOF_M_B32_MASK, VMSOF_M }, // 5327
  { PseudoVMSOF_M_B4, VMSOF_M }, // 5328
  { PseudoVMSOF_M_B4_MASK, VMSOF_M }, // 5329
  { PseudoVMSOF_M_B64, VMSOF_M }, // 5330
  { PseudoVMSOF_M_B64_MASK, VMSOF_M }, // 5331
  { PseudoVMSOF_M_B8, VMSOF_M }, // 5332
  { PseudoVMSOF_M_B8_MASK, VMSOF_M }, // 5333
  { PseudoVMULHSU_VV_M1, VMULHSU_VV }, // 5334
  { PseudoVMULHSU_VV_M1_MASK, VMULHSU_VV }, // 5335
  { PseudoVMULHSU_VV_M2, VMULHSU_VV }, // 5336
  { PseudoVMULHSU_VV_M2_MASK, VMULHSU_VV }, // 5337
  { PseudoVMULHSU_VV_M4, VMULHSU_VV }, // 5338
  { PseudoVMULHSU_VV_M4_MASK, VMULHSU_VV }, // 5339
  { PseudoVMULHSU_VV_M8, VMULHSU_VV }, // 5340
  { PseudoVMULHSU_VV_M8_MASK, VMULHSU_VV }, // 5341
  { PseudoVMULHSU_VV_MF2, VMULHSU_VV }, // 5342
  { PseudoVMULHSU_VV_MF2_MASK, VMULHSU_VV }, // 5343
  { PseudoVMULHSU_VV_MF4, VMULHSU_VV }, // 5344
  { PseudoVMULHSU_VV_MF4_MASK, VMULHSU_VV }, // 5345
  { PseudoVMULHSU_VV_MF8, VMULHSU_VV }, // 5346
  { PseudoVMULHSU_VV_MF8_MASK, VMULHSU_VV }, // 5347
  { PseudoVMULHSU_VX_M1, VMULHSU_VX }, // 5348
  { PseudoVMULHSU_VX_M1_MASK, VMULHSU_VX }, // 5349
  { PseudoVMULHSU_VX_M2, VMULHSU_VX }, // 5350
  { PseudoVMULHSU_VX_M2_MASK, VMULHSU_VX }, // 5351
  { PseudoVMULHSU_VX_M4, VMULHSU_VX }, // 5352
  { PseudoVMULHSU_VX_M4_MASK, VMULHSU_VX }, // 5353
  { PseudoVMULHSU_VX_M8, VMULHSU_VX }, // 5354
  { PseudoVMULHSU_VX_M8_MASK, VMULHSU_VX }, // 5355
  { PseudoVMULHSU_VX_MF2, VMULHSU_VX }, // 5356
  { PseudoVMULHSU_VX_MF2_MASK, VMULHSU_VX }, // 5357
  { PseudoVMULHSU_VX_MF4, VMULHSU_VX }, // 5358
  { PseudoVMULHSU_VX_MF4_MASK, VMULHSU_VX }, // 5359
  { PseudoVMULHSU_VX_MF8, VMULHSU_VX }, // 5360
  { PseudoVMULHSU_VX_MF8_MASK, VMULHSU_VX }, // 5361
  { PseudoVMULHU_VV_M1, VMULHU_VV }, // 5362
  { PseudoVMULHU_VV_M1_MASK, VMULHU_VV }, // 5363
  { PseudoVMULHU_VV_M2, VMULHU_VV }, // 5364
  { PseudoVMULHU_VV_M2_MASK, VMULHU_VV }, // 5365
  { PseudoVMULHU_VV_M4, VMULHU_VV }, // 5366
  { PseudoVMULHU_VV_M4_MASK, VMULHU_VV }, // 5367
  { PseudoVMULHU_VV_M8, VMULHU_VV }, // 5368
  { PseudoVMULHU_VV_M8_MASK, VMULHU_VV }, // 5369
  { PseudoVMULHU_VV_MF2, VMULHU_VV }, // 5370
  { PseudoVMULHU_VV_MF2_MASK, VMULHU_VV }, // 5371
  { PseudoVMULHU_VV_MF4, VMULHU_VV }, // 5372
  { PseudoVMULHU_VV_MF4_MASK, VMULHU_VV }, // 5373
  { PseudoVMULHU_VV_MF8, VMULHU_VV }, // 5374
  { PseudoVMULHU_VV_MF8_MASK, VMULHU_VV }, // 5375
  { PseudoVMULHU_VX_M1, VMULHU_VX }, // 5376
  { PseudoVMULHU_VX_M1_MASK, VMULHU_VX }, // 5377
  { PseudoVMULHU_VX_M2, VMULHU_VX }, // 5378
  { PseudoVMULHU_VX_M2_MASK, VMULHU_VX }, // 5379
  { PseudoVMULHU_VX_M4, VMULHU_VX }, // 5380
  { PseudoVMULHU_VX_M4_MASK, VMULHU_VX }, // 5381
  { PseudoVMULHU_VX_M8, VMULHU_VX }, // 5382
  { PseudoVMULHU_VX_M8_MASK, VMULHU_VX }, // 5383
  { PseudoVMULHU_VX_MF2, VMULHU_VX }, // 5384
  { PseudoVMULHU_VX_MF2_MASK, VMULHU_VX }, // 5385
  { PseudoVMULHU_VX_MF4, VMULHU_VX }, // 5386
  { PseudoVMULHU_VX_MF4_MASK, VMULHU_VX }, // 5387
  { PseudoVMULHU_VX_MF8, VMULHU_VX }, // 5388
  { PseudoVMULHU_VX_MF8_MASK, VMULHU_VX }, // 5389
  { PseudoVMULH_VV_M1, VMULH_VV }, // 5390
  { PseudoVMULH_VV_M1_MASK, VMULH_VV }, // 5391
  { PseudoVMULH_VV_M2, VMULH_VV }, // 5392
  { PseudoVMULH_VV_M2_MASK, VMULH_VV }, // 5393
  { PseudoVMULH_VV_M4, VMULH_VV }, // 5394
  { PseudoVMULH_VV_M4_MASK, VMULH_VV }, // 5395
  { PseudoVMULH_VV_M8, VMULH_VV }, // 5396
  { PseudoVMULH_VV_M8_MASK, VMULH_VV }, // 5397
  { PseudoVMULH_VV_MF2, VMULH_VV }, // 5398
  { PseudoVMULH_VV_MF2_MASK, VMULH_VV }, // 5399
  { PseudoVMULH_VV_MF4, VMULH_VV }, // 5400
  { PseudoVMULH_VV_MF4_MASK, VMULH_VV }, // 5401
  { PseudoVMULH_VV_MF8, VMULH_VV }, // 5402
  { PseudoVMULH_VV_MF8_MASK, VMULH_VV }, // 5403
  { PseudoVMULH_VX_M1, VMULH_VX }, // 5404
  { PseudoVMULH_VX_M1_MASK, VMULH_VX }, // 5405
  { PseudoVMULH_VX_M2, VMULH_VX }, // 5406
  { PseudoVMULH_VX_M2_MASK, VMULH_VX }, // 5407
  { PseudoVMULH_VX_M4, VMULH_VX }, // 5408
  { PseudoVMULH_VX_M4_MASK, VMULH_VX }, // 5409
  { PseudoVMULH_VX_M8, VMULH_VX }, // 5410
  { PseudoVMULH_VX_M8_MASK, VMULH_VX }, // 5411
  { PseudoVMULH_VX_MF2, VMULH_VX }, // 5412
  { PseudoVMULH_VX_MF2_MASK, VMULH_VX }, // 5413
  { PseudoVMULH_VX_MF4, VMULH_VX }, // 5414
  { PseudoVMULH_VX_MF4_MASK, VMULH_VX }, // 5415
  { PseudoVMULH_VX_MF8, VMULH_VX }, // 5416
  { PseudoVMULH_VX_MF8_MASK, VMULH_VX }, // 5417
  { PseudoVMUL_VV_M1, VMUL_VV }, // 5418
  { PseudoVMUL_VV_M1_MASK, VMUL_VV }, // 5419
  { PseudoVMUL_VV_M2, VMUL_VV }, // 5420
  { PseudoVMUL_VV_M2_MASK, VMUL_VV }, // 5421
  { PseudoVMUL_VV_M4, VMUL_VV }, // 5422
  { PseudoVMUL_VV_M4_MASK, VMUL_VV }, // 5423
  { PseudoVMUL_VV_M8, VMUL_VV }, // 5424
  { PseudoVMUL_VV_M8_MASK, VMUL_VV }, // 5425
  { PseudoVMUL_VV_MF2, VMUL_VV }, // 5426
  { PseudoVMUL_VV_MF2_MASK, VMUL_VV }, // 5427
  { PseudoVMUL_VV_MF4, VMUL_VV }, // 5428
  { PseudoVMUL_VV_MF4_MASK, VMUL_VV }, // 5429
  { PseudoVMUL_VV_MF8, VMUL_VV }, // 5430
  { PseudoVMUL_VV_MF8_MASK, VMUL_VV }, // 5431
  { PseudoVMUL_VX_M1, VMUL_VX }, // 5432
  { PseudoVMUL_VX_M1_MASK, VMUL_VX }, // 5433
  { PseudoVMUL_VX_M2, VMUL_VX }, // 5434
  { PseudoVMUL_VX_M2_MASK, VMUL_VX }, // 5435
  { PseudoVMUL_VX_M4, VMUL_VX }, // 5436
  { PseudoVMUL_VX_M4_MASK, VMUL_VX }, // 5437
  { PseudoVMUL_VX_M8, VMUL_VX }, // 5438
  { PseudoVMUL_VX_M8_MASK, VMUL_VX }, // 5439
  { PseudoVMUL_VX_MF2, VMUL_VX }, // 5440
  { PseudoVMUL_VX_MF2_MASK, VMUL_VX }, // 5441
  { PseudoVMUL_VX_MF4, VMUL_VX }, // 5442
  { PseudoVMUL_VX_MF4_MASK, VMUL_VX }, // 5443
  { PseudoVMUL_VX_MF8, VMUL_VX }, // 5444
  { PseudoVMUL_VX_MF8_MASK, VMUL_VX }, // 5445
  { PseudoVMV1R_V, VMV1R_V }, // 5446
  { PseudoVMV2R_V, VMV2R_V }, // 5447
  { PseudoVMV4R_V, VMV4R_V }, // 5448
  { PseudoVMV8R_V, VMV8R_V }, // 5449
  { PseudoVMV_S_X_M1, VMV_S_X }, // 5450
  { PseudoVMV_S_X_M2, VMV_S_X }, // 5451
  { PseudoVMV_S_X_M4, VMV_S_X }, // 5452
  { PseudoVMV_S_X_M8, VMV_S_X }, // 5453
  { PseudoVMV_S_X_MF2, VMV_S_X }, // 5454
  { PseudoVMV_S_X_MF4, VMV_S_X }, // 5455
  { PseudoVMV_S_X_MF8, VMV_S_X }, // 5456
  { PseudoVMV_V_I_M1, VMV_V_I }, // 5457
  { PseudoVMV_V_I_M2, VMV_V_I }, // 5458
  { PseudoVMV_V_I_M4, VMV_V_I }, // 5459
  { PseudoVMV_V_I_M8, VMV_V_I }, // 5460
  { PseudoVMV_V_I_MF2, VMV_V_I }, // 5461
  { PseudoVMV_V_I_MF4, VMV_V_I }, // 5462
  { PseudoVMV_V_I_MF8, VMV_V_I }, // 5463
  { PseudoVMV_V_V_M1, VMV_V_V }, // 5464
  { PseudoVMV_V_V_M2, VMV_V_V }, // 5465
  { PseudoVMV_V_V_M4, VMV_V_V }, // 5466
  { PseudoVMV_V_V_M8, VMV_V_V }, // 5467
  { PseudoVMV_V_V_MF2, VMV_V_V }, // 5468
  { PseudoVMV_V_V_MF4, VMV_V_V }, // 5469
  { PseudoVMV_V_V_MF8, VMV_V_V }, // 5470
  { PseudoVMV_V_X_M1, VMV_V_X }, // 5471
  { PseudoVMV_V_X_M2, VMV_V_X }, // 5472
  { PseudoVMV_V_X_M4, VMV_V_X }, // 5473
  { PseudoVMV_V_X_M8, VMV_V_X }, // 5474
  { PseudoVMV_V_X_MF2, VMV_V_X }, // 5475
  { PseudoVMV_V_X_MF4, VMV_V_X }, // 5476
  { PseudoVMV_V_X_MF8, VMV_V_X }, // 5477
  { PseudoVMV_X_S_M1, VMV_X_S }, // 5478
  { PseudoVMV_X_S_M2, VMV_X_S }, // 5479
  { PseudoVMV_X_S_M4, VMV_X_S }, // 5480
  { PseudoVMV_X_S_M8, VMV_X_S }, // 5481
  { PseudoVMV_X_S_MF2, VMV_X_S }, // 5482
  { PseudoVMV_X_S_MF4, VMV_X_S }, // 5483
  { PseudoVMV_X_S_MF8, VMV_X_S }, // 5484
  { PseudoVMXNOR_MM_M1, VMXNOR_MM }, // 5485
  { PseudoVMXNOR_MM_M2, VMXNOR_MM }, // 5486
  { PseudoVMXNOR_MM_M4, VMXNOR_MM }, // 5487
  { PseudoVMXNOR_MM_M8, VMXNOR_MM }, // 5488
  { PseudoVMXNOR_MM_MF2, VMXNOR_MM }, // 5489
  { PseudoVMXNOR_MM_MF4, VMXNOR_MM }, // 5490
  { PseudoVMXNOR_MM_MF8, VMXNOR_MM }, // 5491
  { PseudoVMXOR_MM_M1, VMXOR_MM }, // 5492
  { PseudoVMXOR_MM_M2, VMXOR_MM }, // 5493
  { PseudoVMXOR_MM_M4, VMXOR_MM }, // 5494
  { PseudoVMXOR_MM_M8, VMXOR_MM }, // 5495
  { PseudoVMXOR_MM_MF2, VMXOR_MM }, // 5496
  { PseudoVMXOR_MM_MF4, VMXOR_MM }, // 5497
  { PseudoVMXOR_MM_MF8, VMXOR_MM }, // 5498
  { PseudoVNCLIPU_WI_M1, VNCLIPU_WI }, // 5499
  { PseudoVNCLIPU_WI_M1_MASK, VNCLIPU_WI }, // 5500
  { PseudoVNCLIPU_WI_M2, VNCLIPU_WI }, // 5501
  { PseudoVNCLIPU_WI_M2_MASK, VNCLIPU_WI }, // 5502
  { PseudoVNCLIPU_WI_M4, VNCLIPU_WI }, // 5503
  { PseudoVNCLIPU_WI_M4_MASK, VNCLIPU_WI }, // 5504
  { PseudoVNCLIPU_WI_MF2, VNCLIPU_WI }, // 5505
  { PseudoVNCLIPU_WI_MF2_MASK, VNCLIPU_WI }, // 5506
  { PseudoVNCLIPU_WI_MF4, VNCLIPU_WI }, // 5507
  { PseudoVNCLIPU_WI_MF4_MASK, VNCLIPU_WI }, // 5508
  { PseudoVNCLIPU_WI_MF8, VNCLIPU_WI }, // 5509
  { PseudoVNCLIPU_WI_MF8_MASK, VNCLIPU_WI }, // 5510
  { PseudoVNCLIPU_WV_M1, VNCLIPU_WV }, // 5511
  { PseudoVNCLIPU_WV_M1_MASK, VNCLIPU_WV }, // 5512
  { PseudoVNCLIPU_WV_M2, VNCLIPU_WV }, // 5513
  { PseudoVNCLIPU_WV_M2_MASK, VNCLIPU_WV }, // 5514
  { PseudoVNCLIPU_WV_M4, VNCLIPU_WV }, // 5515
  { PseudoVNCLIPU_WV_M4_MASK, VNCLIPU_WV }, // 5516
  { PseudoVNCLIPU_WV_MF2, VNCLIPU_WV }, // 5517
  { PseudoVNCLIPU_WV_MF2_MASK, VNCLIPU_WV }, // 5518
  { PseudoVNCLIPU_WV_MF4, VNCLIPU_WV }, // 5519
  { PseudoVNCLIPU_WV_MF4_MASK, VNCLIPU_WV }, // 5520
  { PseudoVNCLIPU_WV_MF8, VNCLIPU_WV }, // 5521
  { PseudoVNCLIPU_WV_MF8_MASK, VNCLIPU_WV }, // 5522
  { PseudoVNCLIPU_WX_M1, VNCLIPU_WX }, // 5523
  { PseudoVNCLIPU_WX_M1_MASK, VNCLIPU_WX }, // 5524
  { PseudoVNCLIPU_WX_M2, VNCLIPU_WX }, // 5525
  { PseudoVNCLIPU_WX_M2_MASK, VNCLIPU_WX }, // 5526
  { PseudoVNCLIPU_WX_M4, VNCLIPU_WX }, // 5527
  { PseudoVNCLIPU_WX_M4_MASK, VNCLIPU_WX }, // 5528
  { PseudoVNCLIPU_WX_MF2, VNCLIPU_WX }, // 5529
  { PseudoVNCLIPU_WX_MF2_MASK, VNCLIPU_WX }, // 5530
  { PseudoVNCLIPU_WX_MF4, VNCLIPU_WX }, // 5531
  { PseudoVNCLIPU_WX_MF4_MASK, VNCLIPU_WX }, // 5532
  { PseudoVNCLIPU_WX_MF8, VNCLIPU_WX }, // 5533
  { PseudoVNCLIPU_WX_MF8_MASK, VNCLIPU_WX }, // 5534
  { PseudoVNCLIP_WI_M1, VNCLIP_WI }, // 5535
  { PseudoVNCLIP_WI_M1_MASK, VNCLIP_WI }, // 5536
  { PseudoVNCLIP_WI_M2, VNCLIP_WI }, // 5537
  { PseudoVNCLIP_WI_M2_MASK, VNCLIP_WI }, // 5538
  { PseudoVNCLIP_WI_M4, VNCLIP_WI }, // 5539
  { PseudoVNCLIP_WI_M4_MASK, VNCLIP_WI }, // 5540
  { PseudoVNCLIP_WI_MF2, VNCLIP_WI }, // 5541
  { PseudoVNCLIP_WI_MF2_MASK, VNCLIP_WI }, // 5542
  { PseudoVNCLIP_WI_MF4, VNCLIP_WI }, // 5543
  { PseudoVNCLIP_WI_MF4_MASK, VNCLIP_WI }, // 5544
  { PseudoVNCLIP_WI_MF8, VNCLIP_WI }, // 5545
  { PseudoVNCLIP_WI_MF8_MASK, VNCLIP_WI }, // 5546
  { PseudoVNCLIP_WV_M1, VNCLIP_WV }, // 5547
  { PseudoVNCLIP_WV_M1_MASK, VNCLIP_WV }, // 5548
  { PseudoVNCLIP_WV_M2, VNCLIP_WV }, // 5549
  { PseudoVNCLIP_WV_M2_MASK, VNCLIP_WV }, // 5550
  { PseudoVNCLIP_WV_M4, VNCLIP_WV }, // 5551
  { PseudoVNCLIP_WV_M4_MASK, VNCLIP_WV }, // 5552
  { PseudoVNCLIP_WV_MF2, VNCLIP_WV }, // 5553
  { PseudoVNCLIP_WV_MF2_MASK, VNCLIP_WV }, // 5554
  { PseudoVNCLIP_WV_MF4, VNCLIP_WV }, // 5555
  { PseudoVNCLIP_WV_MF4_MASK, VNCLIP_WV }, // 5556
  { PseudoVNCLIP_WV_MF8, VNCLIP_WV }, // 5557
  { PseudoVNCLIP_WV_MF8_MASK, VNCLIP_WV }, // 5558
  { PseudoVNCLIP_WX_M1, VNCLIP_WX }, // 5559
  { PseudoVNCLIP_WX_M1_MASK, VNCLIP_WX }, // 5560
  { PseudoVNCLIP_WX_M2, VNCLIP_WX }, // 5561
  { PseudoVNCLIP_WX_M2_MASK, VNCLIP_WX }, // 5562
  { PseudoVNCLIP_WX_M4, VNCLIP_WX }, // 5563
  { PseudoVNCLIP_WX_M4_MASK, VNCLIP_WX }, // 5564
  { PseudoVNCLIP_WX_MF2, VNCLIP_WX }, // 5565
  { PseudoVNCLIP_WX_MF2_MASK, VNCLIP_WX }, // 5566
  { PseudoVNCLIP_WX_MF4, VNCLIP_WX }, // 5567
  { PseudoVNCLIP_WX_MF4_MASK, VNCLIP_WX }, // 5568
  { PseudoVNCLIP_WX_MF8, VNCLIP_WX }, // 5569
  { PseudoVNCLIP_WX_MF8_MASK, VNCLIP_WX }, // 5570
  { PseudoVNMSAC_VV_M1, VNMSAC_VV }, // 5571
  { PseudoVNMSAC_VV_M1_MASK, VNMSAC_VV }, // 5572
  { PseudoVNMSAC_VV_M2, VNMSAC_VV }, // 5573
  { PseudoVNMSAC_VV_M2_MASK, VNMSAC_VV }, // 5574
  { PseudoVNMSAC_VV_M4, VNMSAC_VV }, // 5575
  { PseudoVNMSAC_VV_M4_MASK, VNMSAC_VV }, // 5576
  { PseudoVNMSAC_VV_M8, VNMSAC_VV }, // 5577
  { PseudoVNMSAC_VV_M8_MASK, VNMSAC_VV }, // 5578
  { PseudoVNMSAC_VV_MF2, VNMSAC_VV }, // 5579
  { PseudoVNMSAC_VV_MF2_MASK, VNMSAC_VV }, // 5580
  { PseudoVNMSAC_VV_MF4, VNMSAC_VV }, // 5581
  { PseudoVNMSAC_VV_MF4_MASK, VNMSAC_VV }, // 5582
  { PseudoVNMSAC_VV_MF8, VNMSAC_VV }, // 5583
  { PseudoVNMSAC_VV_MF8_MASK, VNMSAC_VV }, // 5584
  { PseudoVNMSAC_VX_M1, VNMSAC_VX }, // 5585
  { PseudoVNMSAC_VX_M1_MASK, VNMSAC_VX }, // 5586
  { PseudoVNMSAC_VX_M2, VNMSAC_VX }, // 5587
  { PseudoVNMSAC_VX_M2_MASK, VNMSAC_VX }, // 5588
  { PseudoVNMSAC_VX_M4, VNMSAC_VX }, // 5589
  { PseudoVNMSAC_VX_M4_MASK, VNMSAC_VX }, // 5590
  { PseudoVNMSAC_VX_M8, VNMSAC_VX }, // 5591
  { PseudoVNMSAC_VX_M8_MASK, VNMSAC_VX }, // 5592
  { PseudoVNMSAC_VX_MF2, VNMSAC_VX }, // 5593
  { PseudoVNMSAC_VX_MF2_MASK, VNMSAC_VX }, // 5594
  { PseudoVNMSAC_VX_MF4, VNMSAC_VX }, // 5595
  { PseudoVNMSAC_VX_MF4_MASK, VNMSAC_VX }, // 5596
  { PseudoVNMSAC_VX_MF8, VNMSAC_VX }, // 5597
  { PseudoVNMSAC_VX_MF8_MASK, VNMSAC_VX }, // 5598
  { PseudoVNMSUB_VV_M1, VNMSUB_VV }, // 5599
  { PseudoVNMSUB_VV_M1_MASK, VNMSUB_VV }, // 5600
  { PseudoVNMSUB_VV_M2, VNMSUB_VV }, // 5601
  { PseudoVNMSUB_VV_M2_MASK, VNMSUB_VV }, // 5602
  { PseudoVNMSUB_VV_M4, VNMSUB_VV }, // 5603
  { PseudoVNMSUB_VV_M4_MASK, VNMSUB_VV }, // 5604
  { PseudoVNMSUB_VV_M8, VNMSUB_VV }, // 5605
  { PseudoVNMSUB_VV_M8_MASK, VNMSUB_VV }, // 5606
  { PseudoVNMSUB_VV_MF2, VNMSUB_VV }, // 5607
  { PseudoVNMSUB_VV_MF2_MASK, VNMSUB_VV }, // 5608
  { PseudoVNMSUB_VV_MF4, VNMSUB_VV }, // 5609
  { PseudoVNMSUB_VV_MF4_MASK, VNMSUB_VV }, // 5610
  { PseudoVNMSUB_VV_MF8, VNMSUB_VV }, // 5611
  { PseudoVNMSUB_VV_MF8_MASK, VNMSUB_VV }, // 5612
  { PseudoVNMSUB_VX_M1, VNMSUB_VX }, // 5613
  { PseudoVNMSUB_VX_M1_MASK, VNMSUB_VX }, // 5614
  { PseudoVNMSUB_VX_M2, VNMSUB_VX }, // 5615
  { PseudoVNMSUB_VX_M2_MASK, VNMSUB_VX }, // 5616
  { PseudoVNMSUB_VX_M4, VNMSUB_VX }, // 5617
  { PseudoVNMSUB_VX_M4_MASK, VNMSUB_VX }, // 5618
  { PseudoVNMSUB_VX_M8, VNMSUB_VX }, // 5619
  { PseudoVNMSUB_VX_M8_MASK, VNMSUB_VX }, // 5620
  { PseudoVNMSUB_VX_MF2, VNMSUB_VX }, // 5621
  { PseudoVNMSUB_VX_MF2_MASK, VNMSUB_VX }, // 5622
  { PseudoVNMSUB_VX_MF4, VNMSUB_VX }, // 5623
  { PseudoVNMSUB_VX_MF4_MASK, VNMSUB_VX }, // 5624
  { PseudoVNMSUB_VX_MF8, VNMSUB_VX }, // 5625
  { PseudoVNMSUB_VX_MF8_MASK, VNMSUB_VX }, // 5626
  { PseudoVNSRA_WI_M1, VNSRA_WI }, // 5627
  { PseudoVNSRA_WI_M1_MASK, VNSRA_WI }, // 5628
  { PseudoVNSRA_WI_M2, VNSRA_WI }, // 5629
  { PseudoVNSRA_WI_M2_MASK, VNSRA_WI }, // 5630
  { PseudoVNSRA_WI_M4, VNSRA_WI }, // 5631
  { PseudoVNSRA_WI_M4_MASK, VNSRA_WI }, // 5632
  { PseudoVNSRA_WI_MF2, VNSRA_WI }, // 5633
  { PseudoVNSRA_WI_MF2_MASK, VNSRA_WI }, // 5634
  { PseudoVNSRA_WI_MF4, VNSRA_WI }, // 5635
  { PseudoVNSRA_WI_MF4_MASK, VNSRA_WI }, // 5636
  { PseudoVNSRA_WI_MF8, VNSRA_WI }, // 5637
  { PseudoVNSRA_WI_MF8_MASK, VNSRA_WI }, // 5638
  { PseudoVNSRA_WV_M1, VNSRA_WV }, // 5639
  { PseudoVNSRA_WV_M1_MASK, VNSRA_WV }, // 5640
  { PseudoVNSRA_WV_M2, VNSRA_WV }, // 5641
  { PseudoVNSRA_WV_M2_MASK, VNSRA_WV }, // 5642
  { PseudoVNSRA_WV_M4, VNSRA_WV }, // 5643
  { PseudoVNSRA_WV_M4_MASK, VNSRA_WV }, // 5644
  { PseudoVNSRA_WV_MF2, VNSRA_WV }, // 5645
  { PseudoVNSRA_WV_MF2_MASK, VNSRA_WV }, // 5646
  { PseudoVNSRA_WV_MF4, VNSRA_WV }, // 5647
  { PseudoVNSRA_WV_MF4_MASK, VNSRA_WV }, // 5648
  { PseudoVNSRA_WV_MF8, VNSRA_WV }, // 5649
  { PseudoVNSRA_WV_MF8_MASK, VNSRA_WV }, // 5650
  { PseudoVNSRA_WX_M1, VNSRA_WX }, // 5651
  { PseudoVNSRA_WX_M1_MASK, VNSRA_WX }, // 5652
  { PseudoVNSRA_WX_M2, VNSRA_WX }, // 5653
  { PseudoVNSRA_WX_M2_MASK, VNSRA_WX }, // 5654
  { PseudoVNSRA_WX_M4, VNSRA_WX }, // 5655
  { PseudoVNSRA_WX_M4_MASK, VNSRA_WX }, // 5656
  { PseudoVNSRA_WX_MF2, VNSRA_WX }, // 5657
  { PseudoVNSRA_WX_MF2_MASK, VNSRA_WX }, // 5658
  { PseudoVNSRA_WX_MF4, VNSRA_WX }, // 5659
  { PseudoVNSRA_WX_MF4_MASK, VNSRA_WX }, // 5660
  { PseudoVNSRA_WX_MF8, VNSRA_WX }, // 5661
  { PseudoVNSRA_WX_MF8_MASK, VNSRA_WX }, // 5662
  { PseudoVNSRL_WI_M1, VNSRL_WI }, // 5663
  { PseudoVNSRL_WI_M1_MASK, VNSRL_WI }, // 5664
  { PseudoVNSRL_WI_M2, VNSRL_WI }, // 5665
  { PseudoVNSRL_WI_M2_MASK, VNSRL_WI }, // 5666
  { PseudoVNSRL_WI_M4, VNSRL_WI }, // 5667
  { PseudoVNSRL_WI_M4_MASK, VNSRL_WI }, // 5668
  { PseudoVNSRL_WI_MF2, VNSRL_WI }, // 5669
  { PseudoVNSRL_WI_MF2_MASK, VNSRL_WI }, // 5670
  { PseudoVNSRL_WI_MF4, VNSRL_WI }, // 5671
  { PseudoVNSRL_WI_MF4_MASK, VNSRL_WI }, // 5672
  { PseudoVNSRL_WI_MF8, VNSRL_WI }, // 5673
  { PseudoVNSRL_WI_MF8_MASK, VNSRL_WI }, // 5674
  { PseudoVNSRL_WV_M1, VNSRL_WV }, // 5675
  { PseudoVNSRL_WV_M1_MASK, VNSRL_WV }, // 5676
  { PseudoVNSRL_WV_M2, VNSRL_WV }, // 5677
  { PseudoVNSRL_WV_M2_MASK, VNSRL_WV }, // 5678
  { PseudoVNSRL_WV_M4, VNSRL_WV }, // 5679
  { PseudoVNSRL_WV_M4_MASK, VNSRL_WV }, // 5680
  { PseudoVNSRL_WV_MF2, VNSRL_WV }, // 5681
  { PseudoVNSRL_WV_MF2_MASK, VNSRL_WV }, // 5682
  { PseudoVNSRL_WV_MF4, VNSRL_WV }, // 5683
  { PseudoVNSRL_WV_MF4_MASK, VNSRL_WV }, // 5684
  { PseudoVNSRL_WV_MF8, VNSRL_WV }, // 5685
  { PseudoVNSRL_WV_MF8_MASK, VNSRL_WV }, // 5686
  { PseudoVNSRL_WX_M1, VNSRL_WX }, // 5687
  { PseudoVNSRL_WX_M1_MASK, VNSRL_WX }, // 5688
  { PseudoVNSRL_WX_M2, VNSRL_WX }, // 5689
  { PseudoVNSRL_WX_M2_MASK, VNSRL_WX }, // 5690
  { PseudoVNSRL_WX_M4, VNSRL_WX }, // 5691
  { PseudoVNSRL_WX_M4_MASK, VNSRL_WX }, // 5692
  { PseudoVNSRL_WX_MF2, VNSRL_WX }, // 5693
  { PseudoVNSRL_WX_MF2_MASK, VNSRL_WX }, // 5694
  { PseudoVNSRL_WX_MF4, VNSRL_WX }, // 5695
  { PseudoVNSRL_WX_MF4_MASK, VNSRL_WX }, // 5696
  { PseudoVNSRL_WX_MF8, VNSRL_WX }, // 5697
  { PseudoVNSRL_WX_MF8_MASK, VNSRL_WX }, // 5698
  { PseudoVOR_VI_M1, VOR_VI }, // 5699
  { PseudoVOR_VI_M1_MASK, VOR_VI }, // 5700
  { PseudoVOR_VI_M2, VOR_VI }, // 5701
  { PseudoVOR_VI_M2_MASK, VOR_VI }, // 5702
  { PseudoVOR_VI_M4, VOR_VI }, // 5703
  { PseudoVOR_VI_M4_MASK, VOR_VI }, // 5704
  { PseudoVOR_VI_M8, VOR_VI }, // 5705
  { PseudoVOR_VI_M8_MASK, VOR_VI }, // 5706
  { PseudoVOR_VI_MF2, VOR_VI }, // 5707
  { PseudoVOR_VI_MF2_MASK, VOR_VI }, // 5708
  { PseudoVOR_VI_MF4, VOR_VI }, // 5709
  { PseudoVOR_VI_MF4_MASK, VOR_VI }, // 5710
  { PseudoVOR_VI_MF8, VOR_VI }, // 5711
  { PseudoVOR_VI_MF8_MASK, VOR_VI }, // 5712
  { PseudoVOR_VV_M1, VOR_VV }, // 5713
  { PseudoVOR_VV_M1_MASK, VOR_VV }, // 5714
  { PseudoVOR_VV_M2, VOR_VV }, // 5715
  { PseudoVOR_VV_M2_MASK, VOR_VV }, // 5716
  { PseudoVOR_VV_M4, VOR_VV }, // 5717
  { PseudoVOR_VV_M4_MASK, VOR_VV }, // 5718
  { PseudoVOR_VV_M8, VOR_VV }, // 5719
  { PseudoVOR_VV_M8_MASK, VOR_VV }, // 5720
  { PseudoVOR_VV_MF2, VOR_VV }, // 5721
  { PseudoVOR_VV_MF2_MASK, VOR_VV }, // 5722
  { PseudoVOR_VV_MF4, VOR_VV }, // 5723
  { PseudoVOR_VV_MF4_MASK, VOR_VV }, // 5724
  { PseudoVOR_VV_MF8, VOR_VV }, // 5725
  { PseudoVOR_VV_MF8_MASK, VOR_VV }, // 5726
  { PseudoVOR_VX_M1, VOR_VX }, // 5727
  { PseudoVOR_VX_M1_MASK, VOR_VX }, // 5728
  { PseudoVOR_VX_M2, VOR_VX }, // 5729
  { PseudoVOR_VX_M2_MASK, VOR_VX }, // 5730
  { PseudoVOR_VX_M4, VOR_VX }, // 5731
  { PseudoVOR_VX_M4_MASK, VOR_VX }, // 5732
  { PseudoVOR_VX_M8, VOR_VX }, // 5733
  { PseudoVOR_VX_M8_MASK, VOR_VX }, // 5734
  { PseudoVOR_VX_MF2, VOR_VX }, // 5735
  { PseudoVOR_VX_MF2_MASK, VOR_VX }, // 5736
  { PseudoVOR_VX_MF4, VOR_VX }, // 5737
  { PseudoVOR_VX_MF4_MASK, VOR_VX }, // 5738
  { PseudoVOR_VX_MF8, VOR_VX }, // 5739
  { PseudoVOR_VX_MF8_MASK, VOR_VX }, // 5740
  { PseudoVREDAND_VS_M1, VREDAND_VS }, // 5741
  { PseudoVREDAND_VS_M1_MASK, VREDAND_VS }, // 5742
  { PseudoVREDAND_VS_M2, VREDAND_VS }, // 5743
  { PseudoVREDAND_VS_M2_MASK, VREDAND_VS }, // 5744
  { PseudoVREDAND_VS_M4, VREDAND_VS }, // 5745
  { PseudoVREDAND_VS_M4_MASK, VREDAND_VS }, // 5746
  { PseudoVREDAND_VS_M8, VREDAND_VS }, // 5747
  { PseudoVREDAND_VS_M8_MASK, VREDAND_VS }, // 5748
  { PseudoVREDAND_VS_MF2, VREDAND_VS }, // 5749
  { PseudoVREDAND_VS_MF2_MASK, VREDAND_VS }, // 5750
  { PseudoVREDAND_VS_MF4, VREDAND_VS }, // 5751
  { PseudoVREDAND_VS_MF4_MASK, VREDAND_VS }, // 5752
  { PseudoVREDAND_VS_MF8, VREDAND_VS }, // 5753
  { PseudoVREDAND_VS_MF8_MASK, VREDAND_VS }, // 5754
  { PseudoVREDMAXU_VS_M1, VREDMAXU_VS }, // 5755
  { PseudoVREDMAXU_VS_M1_MASK, VREDMAXU_VS }, // 5756
  { PseudoVREDMAXU_VS_M2, VREDMAXU_VS }, // 5757
  { PseudoVREDMAXU_VS_M2_MASK, VREDMAXU_VS }, // 5758
  { PseudoVREDMAXU_VS_M4, VREDMAXU_VS }, // 5759
  { PseudoVREDMAXU_VS_M4_MASK, VREDMAXU_VS }, // 5760
  { PseudoVREDMAXU_VS_M8, VREDMAXU_VS }, // 5761
  { PseudoVREDMAXU_VS_M8_MASK, VREDMAXU_VS }, // 5762
  { PseudoVREDMAXU_VS_MF2, VREDMAXU_VS }, // 5763
  { PseudoVREDMAXU_VS_MF2_MASK, VREDMAXU_VS }, // 5764
  { PseudoVREDMAXU_VS_MF4, VREDMAXU_VS }, // 5765
  { PseudoVREDMAXU_VS_MF4_MASK, VREDMAXU_VS }, // 5766
  { PseudoVREDMAXU_VS_MF8, VREDMAXU_VS }, // 5767
  { PseudoVREDMAXU_VS_MF8_MASK, VREDMAXU_VS }, // 5768
  { PseudoVREDMAX_VS_M1, VREDMAX_VS }, // 5769
  { PseudoVREDMAX_VS_M1_MASK, VREDMAX_VS }, // 5770
  { PseudoVREDMAX_VS_M2, VREDMAX_VS }, // 5771
  { PseudoVREDMAX_VS_M2_MASK, VREDMAX_VS }, // 5772
  { PseudoVREDMAX_VS_M4, VREDMAX_VS }, // 5773
  { PseudoVREDMAX_VS_M4_MASK, VREDMAX_VS }, // 5774
  { PseudoVREDMAX_VS_M8, VREDMAX_VS }, // 5775
  { PseudoVREDMAX_VS_M8_MASK, VREDMAX_VS }, // 5776
  { PseudoVREDMAX_VS_MF2, VREDMAX_VS }, // 5777
  { PseudoVREDMAX_VS_MF2_MASK, VREDMAX_VS }, // 5778
  { PseudoVREDMAX_VS_MF4, VREDMAX_VS }, // 5779
  { PseudoVREDMAX_VS_MF4_MASK, VREDMAX_VS }, // 5780
  { PseudoVREDMAX_VS_MF8, VREDMAX_VS }, // 5781
  { PseudoVREDMAX_VS_MF8_MASK, VREDMAX_VS }, // 5782
  { PseudoVREDMINU_VS_M1, VREDMINU_VS }, // 5783
  { PseudoVREDMINU_VS_M1_MASK, VREDMINU_VS }, // 5784
  { PseudoVREDMINU_VS_M2, VREDMINU_VS }, // 5785
  { PseudoVREDMINU_VS_M2_MASK, VREDMINU_VS }, // 5786
  { PseudoVREDMINU_VS_M4, VREDMINU_VS }, // 5787
  { PseudoVREDMINU_VS_M4_MASK, VREDMINU_VS }, // 5788
  { PseudoVREDMINU_VS_M8, VREDMINU_VS }, // 5789
  { PseudoVREDMINU_VS_M8_MASK, VREDMINU_VS }, // 5790
  { PseudoVREDMINU_VS_MF2, VREDMINU_VS }, // 5791
  { PseudoVREDMINU_VS_MF2_MASK, VREDMINU_VS }, // 5792
  { PseudoVREDMINU_VS_MF4, VREDMINU_VS }, // 5793
  { PseudoVREDMINU_VS_MF4_MASK, VREDMINU_VS }, // 5794
  { PseudoVREDMINU_VS_MF8, VREDMINU_VS }, // 5795
  { PseudoVREDMINU_VS_MF8_MASK, VREDMINU_VS }, // 5796
  { PseudoVREDMIN_VS_M1, VREDMIN_VS }, // 5797
  { PseudoVREDMIN_VS_M1_MASK, VREDMIN_VS }, // 5798
  { PseudoVREDMIN_VS_M2, VREDMIN_VS }, // 5799
  { PseudoVREDMIN_VS_M2_MASK, VREDMIN_VS }, // 5800
  { PseudoVREDMIN_VS_M4, VREDMIN_VS }, // 5801
  { PseudoVREDMIN_VS_M4_MASK, VREDMIN_VS }, // 5802
  { PseudoVREDMIN_VS_M8, VREDMIN_VS }, // 5803
  { PseudoVREDMIN_VS_M8_MASK, VREDMIN_VS }, // 5804
  { PseudoVREDMIN_VS_MF2, VREDMIN_VS }, // 5805
  { PseudoVREDMIN_VS_MF2_MASK, VREDMIN_VS }, // 5806
  { PseudoVREDMIN_VS_MF4, VREDMIN_VS }, // 5807
  { PseudoVREDMIN_VS_MF4_MASK, VREDMIN_VS }, // 5808
  { PseudoVREDMIN_VS_MF8, VREDMIN_VS }, // 5809
  { PseudoVREDMIN_VS_MF8_MASK, VREDMIN_VS }, // 5810
  { PseudoVREDOR_VS_M1, VREDOR_VS }, // 5811
  { PseudoVREDOR_VS_M1_MASK, VREDOR_VS }, // 5812
  { PseudoVREDOR_VS_M2, VREDOR_VS }, // 5813
  { PseudoVREDOR_VS_M2_MASK, VREDOR_VS }, // 5814
  { PseudoVREDOR_VS_M4, VREDOR_VS }, // 5815
  { PseudoVREDOR_VS_M4_MASK, VREDOR_VS }, // 5816
  { PseudoVREDOR_VS_M8, VREDOR_VS }, // 5817
  { PseudoVREDOR_VS_M8_MASK, VREDOR_VS }, // 5818
  { PseudoVREDOR_VS_MF2, VREDOR_VS }, // 5819
  { PseudoVREDOR_VS_MF2_MASK, VREDOR_VS }, // 5820
  { PseudoVREDOR_VS_MF4, VREDOR_VS }, // 5821
  { PseudoVREDOR_VS_MF4_MASK, VREDOR_VS }, // 5822
  { PseudoVREDOR_VS_MF8, VREDOR_VS }, // 5823
  { PseudoVREDOR_VS_MF8_MASK, VREDOR_VS }, // 5824
  { PseudoVREDSUM_VS_M1, VREDSUM_VS }, // 5825
  { PseudoVREDSUM_VS_M1_MASK, VREDSUM_VS }, // 5826
  { PseudoVREDSUM_VS_M2, VREDSUM_VS }, // 5827
  { PseudoVREDSUM_VS_M2_MASK, VREDSUM_VS }, // 5828
  { PseudoVREDSUM_VS_M4, VREDSUM_VS }, // 5829
  { PseudoVREDSUM_VS_M4_MASK, VREDSUM_VS }, // 5830
  { PseudoVREDSUM_VS_M8, VREDSUM_VS }, // 5831
  { PseudoVREDSUM_VS_M8_MASK, VREDSUM_VS }, // 5832
  { PseudoVREDSUM_VS_MF2, VREDSUM_VS }, // 5833
  { PseudoVREDSUM_VS_MF2_MASK, VREDSUM_VS }, // 5834
  { PseudoVREDSUM_VS_MF4, VREDSUM_VS }, // 5835
  { PseudoVREDSUM_VS_MF4_MASK, VREDSUM_VS }, // 5836
  { PseudoVREDSUM_VS_MF8, VREDSUM_VS }, // 5837
  { PseudoVREDSUM_VS_MF8_MASK, VREDSUM_VS }, // 5838
  { PseudoVREDXOR_VS_M1, VREDXOR_VS }, // 5839
  { PseudoVREDXOR_VS_M1_MASK, VREDXOR_VS }, // 5840
  { PseudoVREDXOR_VS_M2, VREDXOR_VS }, // 5841
  { PseudoVREDXOR_VS_M2_MASK, VREDXOR_VS }, // 5842
  { PseudoVREDXOR_VS_M4, VREDXOR_VS }, // 5843
  { PseudoVREDXOR_VS_M4_MASK, VREDXOR_VS }, // 5844
  { PseudoVREDXOR_VS_M8, VREDXOR_VS }, // 5845
  { PseudoVREDXOR_VS_M8_MASK, VREDXOR_VS }, // 5846
  { PseudoVREDXOR_VS_MF2, VREDXOR_VS }, // 5847
  { PseudoVREDXOR_VS_MF2_MASK, VREDXOR_VS }, // 5848
  { PseudoVREDXOR_VS_MF4, VREDXOR_VS }, // 5849
  { PseudoVREDXOR_VS_MF4_MASK, VREDXOR_VS }, // 5850
  { PseudoVREDXOR_VS_MF8, VREDXOR_VS }, // 5851
  { PseudoVREDXOR_VS_MF8_MASK, VREDXOR_VS }, // 5852
  { PseudoVRELOAD_M1, VL1RE8_V }, // 5853
  { PseudoVRELOAD_M2, VL2RE8_V }, // 5854
  { PseudoVRELOAD_M4, VL4RE8_V }, // 5855
  { PseudoVRELOAD_M8, VL8RE8_V }, // 5856
  { PseudoVREMU_VV_M1, VREMU_VV }, // 5857
  { PseudoVREMU_VV_M1_MASK, VREMU_VV }, // 5858
  { PseudoVREMU_VV_M2, VREMU_VV }, // 5859
  { PseudoVREMU_VV_M2_MASK, VREMU_VV }, // 5860
  { PseudoVREMU_VV_M4, VREMU_VV }, // 5861
  { PseudoVREMU_VV_M4_MASK, VREMU_VV }, // 5862
  { PseudoVREMU_VV_M8, VREMU_VV }, // 5863
  { PseudoVREMU_VV_M8_MASK, VREMU_VV }, // 5864
  { PseudoVREMU_VV_MF2, VREMU_VV }, // 5865
  { PseudoVREMU_VV_MF2_MASK, VREMU_VV }, // 5866
  { PseudoVREMU_VV_MF4, VREMU_VV }, // 5867
  { PseudoVREMU_VV_MF4_MASK, VREMU_VV }, // 5868
  { PseudoVREMU_VV_MF8, VREMU_VV }, // 5869
  { PseudoVREMU_VV_MF8_MASK, VREMU_VV }, // 5870
  { PseudoVREMU_VX_M1, VREMU_VX }, // 5871
  { PseudoVREMU_VX_M1_MASK, VREMU_VX }, // 5872
  { PseudoVREMU_VX_M2, VREMU_VX }, // 5873
  { PseudoVREMU_VX_M2_MASK, VREMU_VX }, // 5874
  { PseudoVREMU_VX_M4, VREMU_VX }, // 5875
  { PseudoVREMU_VX_M4_MASK, VREMU_VX }, // 5876
  { PseudoVREMU_VX_M8, VREMU_VX }, // 5877
  { PseudoVREMU_VX_M8_MASK, VREMU_VX }, // 5878
  { PseudoVREMU_VX_MF2, VREMU_VX }, // 5879
  { PseudoVREMU_VX_MF2_MASK, VREMU_VX }, // 5880
  { PseudoVREMU_VX_MF4, VREMU_VX }, // 5881
  { PseudoVREMU_VX_MF4_MASK, VREMU_VX }, // 5882
  { PseudoVREMU_VX_MF8, VREMU_VX }, // 5883
  { PseudoVREMU_VX_MF8_MASK, VREMU_VX }, // 5884
  { PseudoVREM_VV_M1, VREM_VV }, // 5885
  { PseudoVREM_VV_M1_MASK, VREM_VV }, // 5886
  { PseudoVREM_VV_M2, VREM_VV }, // 5887
  { PseudoVREM_VV_M2_MASK, VREM_VV }, // 5888
  { PseudoVREM_VV_M4, VREM_VV }, // 5889
  { PseudoVREM_VV_M4_MASK, VREM_VV }, // 5890
  { PseudoVREM_VV_M8, VREM_VV }, // 5891
  { PseudoVREM_VV_M8_MASK, VREM_VV }, // 5892
  { PseudoVREM_VV_MF2, VREM_VV }, // 5893
  { PseudoVREM_VV_MF2_MASK, VREM_VV }, // 5894
  { PseudoVREM_VV_MF4, VREM_VV }, // 5895
  { PseudoVREM_VV_MF4_MASK, VREM_VV }, // 5896
  { PseudoVREM_VV_MF8, VREM_VV }, // 5897
  { PseudoVREM_VV_MF8_MASK, VREM_VV }, // 5898
  { PseudoVREM_VX_M1, VREM_VX }, // 5899
  { PseudoVREM_VX_M1_MASK, VREM_VX }, // 5900
  { PseudoVREM_VX_M2, VREM_VX }, // 5901
  { PseudoVREM_VX_M2_MASK, VREM_VX }, // 5902
  { PseudoVREM_VX_M4, VREM_VX }, // 5903
  { PseudoVREM_VX_M4_MASK, VREM_VX }, // 5904
  { PseudoVREM_VX_M8, VREM_VX }, // 5905
  { PseudoVREM_VX_M8_MASK, VREM_VX }, // 5906
  { PseudoVREM_VX_MF2, VREM_VX }, // 5907
  { PseudoVREM_VX_MF2_MASK, VREM_VX }, // 5908
  { PseudoVREM_VX_MF4, VREM_VX }, // 5909
  { PseudoVREM_VX_MF4_MASK, VREM_VX }, // 5910
  { PseudoVREM_VX_MF8, VREM_VX }, // 5911
  { PseudoVREM_VX_MF8_MASK, VREM_VX }, // 5912
  { PseudoVRGATHEREI16_VV_M1_M1, VRGATHEREI16_VV }, // 5913
  { PseudoVRGATHEREI16_VV_M1_M1_MASK, VRGATHEREI16_VV }, // 5914
  { PseudoVRGATHEREI16_VV_M1_M2, VRGATHEREI16_VV }, // 5915
  { PseudoVRGATHEREI16_VV_M1_M2_MASK, VRGATHEREI16_VV }, // 5916
  { PseudoVRGATHEREI16_VV_M1_MF2, VRGATHEREI16_VV }, // 5917
  { PseudoVRGATHEREI16_VV_M1_MF2_MASK, VRGATHEREI16_VV }, // 5918
  { PseudoVRGATHEREI16_VV_M1_MF4, VRGATHEREI16_VV }, // 5919
  { PseudoVRGATHEREI16_VV_M1_MF4_MASK, VRGATHEREI16_VV }, // 5920
  { PseudoVRGATHEREI16_VV_M2_M1, VRGATHEREI16_VV }, // 5921
  { PseudoVRGATHEREI16_VV_M2_M1_MASK, VRGATHEREI16_VV }, // 5922
  { PseudoVRGATHEREI16_VV_M2_M2, VRGATHEREI16_VV }, // 5923
  { PseudoVRGATHEREI16_VV_M2_M2_MASK, VRGATHEREI16_VV }, // 5924
  { PseudoVRGATHEREI16_VV_M2_M4, VRGATHEREI16_VV }, // 5925
  { PseudoVRGATHEREI16_VV_M2_M4_MASK, VRGATHEREI16_VV }, // 5926
  { PseudoVRGATHEREI16_VV_M2_MF2, VRGATHEREI16_VV }, // 5927
  { PseudoVRGATHEREI16_VV_M2_MF2_MASK, VRGATHEREI16_VV }, // 5928
  { PseudoVRGATHEREI16_VV_M4_M1, VRGATHEREI16_VV }, // 5929
  { PseudoVRGATHEREI16_VV_M4_M1_MASK, VRGATHEREI16_VV }, // 5930
  { PseudoVRGATHEREI16_VV_M4_M2, VRGATHEREI16_VV }, // 5931
  { PseudoVRGATHEREI16_VV_M4_M2_MASK, VRGATHEREI16_VV }, // 5932
  { PseudoVRGATHEREI16_VV_M4_M4, VRGATHEREI16_VV }, // 5933
  { PseudoVRGATHEREI16_VV_M4_M4_MASK, VRGATHEREI16_VV }, // 5934
  { PseudoVRGATHEREI16_VV_M4_M8, VRGATHEREI16_VV }, // 5935
  { PseudoVRGATHEREI16_VV_M4_M8_MASK, VRGATHEREI16_VV }, // 5936
  { PseudoVRGATHEREI16_VV_M8_M2, VRGATHEREI16_VV }, // 5937
  { PseudoVRGATHEREI16_VV_M8_M2_MASK, VRGATHEREI16_VV }, // 5938
  { PseudoVRGATHEREI16_VV_M8_M4, VRGATHEREI16_VV }, // 5939
  { PseudoVRGATHEREI16_VV_M8_M4_MASK, VRGATHEREI16_VV }, // 5940
  { PseudoVRGATHEREI16_VV_M8_M8, VRGATHEREI16_VV }, // 5941
  { PseudoVRGATHEREI16_VV_M8_M8_MASK, VRGATHEREI16_VV }, // 5942
  { PseudoVRGATHEREI16_VV_MF2_M1, VRGATHEREI16_VV }, // 5943
  { PseudoVRGATHEREI16_VV_MF2_M1_MASK, VRGATHEREI16_VV }, // 5944
  { PseudoVRGATHEREI16_VV_MF2_MF2, VRGATHEREI16_VV }, // 5945
  { PseudoVRGATHEREI16_VV_MF2_MF2_MASK, VRGATHEREI16_VV }, // 5946
  { PseudoVRGATHEREI16_VV_MF2_MF4, VRGATHEREI16_VV }, // 5947
  { PseudoVRGATHEREI16_VV_MF2_MF4_MASK, VRGATHEREI16_VV }, // 5948
  { PseudoVRGATHEREI16_VV_MF2_MF8, VRGATHEREI16_VV }, // 5949
  { PseudoVRGATHEREI16_VV_MF2_MF8_MASK, VRGATHEREI16_VV }, // 5950
  { PseudoVRGATHEREI16_VV_MF4_MF2, VRGATHEREI16_VV }, // 5951
  { PseudoVRGATHEREI16_VV_MF4_MF2_MASK, VRGATHEREI16_VV }, // 5952
  { PseudoVRGATHEREI16_VV_MF4_MF4, VRGATHEREI16_VV }, // 5953
  { PseudoVRGATHEREI16_VV_MF4_MF4_MASK, VRGATHEREI16_VV }, // 5954
  { PseudoVRGATHEREI16_VV_MF4_MF8, VRGATHEREI16_VV }, // 5955
  { PseudoVRGATHEREI16_VV_MF4_MF8_MASK, VRGATHEREI16_VV }, // 5956
  { PseudoVRGATHEREI16_VV_MF8_MF4, VRGATHEREI16_VV }, // 5957
  { PseudoVRGATHEREI16_VV_MF8_MF4_MASK, VRGATHEREI16_VV }, // 5958
  { PseudoVRGATHEREI16_VV_MF8_MF8, VRGATHEREI16_VV }, // 5959
  { PseudoVRGATHEREI16_VV_MF8_MF8_MASK, VRGATHEREI16_VV }, // 5960
  { PseudoVRGATHER_VI_M1, VRGATHER_VI }, // 5961
  { PseudoVRGATHER_VI_M1_MASK, VRGATHER_VI }, // 5962
  { PseudoVRGATHER_VI_M2, VRGATHER_VI }, // 5963
  { PseudoVRGATHER_VI_M2_MASK, VRGATHER_VI }, // 5964
  { PseudoVRGATHER_VI_M4, VRGATHER_VI }, // 5965
  { PseudoVRGATHER_VI_M4_MASK, VRGATHER_VI }, // 5966
  { PseudoVRGATHER_VI_M8, VRGATHER_VI }, // 5967
  { PseudoVRGATHER_VI_M8_MASK, VRGATHER_VI }, // 5968
  { PseudoVRGATHER_VI_MF2, VRGATHER_VI }, // 5969
  { PseudoVRGATHER_VI_MF2_MASK, VRGATHER_VI }, // 5970
  { PseudoVRGATHER_VI_MF4, VRGATHER_VI }, // 5971
  { PseudoVRGATHER_VI_MF4_MASK, VRGATHER_VI }, // 5972
  { PseudoVRGATHER_VI_MF8, VRGATHER_VI }, // 5973
  { PseudoVRGATHER_VI_MF8_MASK, VRGATHER_VI }, // 5974
  { PseudoVRGATHER_VV_M1, VRGATHER_VV }, // 5975
  { PseudoVRGATHER_VV_M1_MASK, VRGATHER_VV }, // 5976
  { PseudoVRGATHER_VV_M2, VRGATHER_VV }, // 5977
  { PseudoVRGATHER_VV_M2_MASK, VRGATHER_VV }, // 5978
  { PseudoVRGATHER_VV_M4, VRGATHER_VV }, // 5979
  { PseudoVRGATHER_VV_M4_MASK, VRGATHER_VV }, // 5980
  { PseudoVRGATHER_VV_M8, VRGATHER_VV }, // 5981
  { PseudoVRGATHER_VV_M8_MASK, VRGATHER_VV }, // 5982
  { PseudoVRGATHER_VV_MF2, VRGATHER_VV }, // 5983
  { PseudoVRGATHER_VV_MF2_MASK, VRGATHER_VV }, // 5984
  { PseudoVRGATHER_VV_MF4, VRGATHER_VV }, // 5985
  { PseudoVRGATHER_VV_MF4_MASK, VRGATHER_VV }, // 5986
  { PseudoVRGATHER_VV_MF8, VRGATHER_VV }, // 5987
  { PseudoVRGATHER_VV_MF8_MASK, VRGATHER_VV }, // 5988
  { PseudoVRGATHER_VX_M1, VRGATHER_VX }, // 5989
  { PseudoVRGATHER_VX_M1_MASK, VRGATHER_VX }, // 5990
  { PseudoVRGATHER_VX_M2, VRGATHER_VX }, // 5991
  { PseudoVRGATHER_VX_M2_MASK, VRGATHER_VX }, // 5992
  { PseudoVRGATHER_VX_M4, VRGATHER_VX }, // 5993
  { PseudoVRGATHER_VX_M4_MASK, VRGATHER_VX }, // 5994
  { PseudoVRGATHER_VX_M8, VRGATHER_VX }, // 5995
  { PseudoVRGATHER_VX_M8_MASK, VRGATHER_VX }, // 5996
  { PseudoVRGATHER_VX_MF2, VRGATHER_VX }, // 5997
  { PseudoVRGATHER_VX_MF2_MASK, VRGATHER_VX }, // 5998
  { PseudoVRGATHER_VX_MF4, VRGATHER_VX }, // 5999
  { PseudoVRGATHER_VX_MF4_MASK, VRGATHER_VX }, // 6000
  { PseudoVRGATHER_VX_MF8, VRGATHER_VX }, // 6001
  { PseudoVRGATHER_VX_MF8_MASK, VRGATHER_VX }, // 6002
  { PseudoVRSUB_VI_M1, VRSUB_VI }, // 6003
  { PseudoVRSUB_VI_M1_MASK, VRSUB_VI }, // 6004
  { PseudoVRSUB_VI_M2, VRSUB_VI }, // 6005
  { PseudoVRSUB_VI_M2_MASK, VRSUB_VI }, // 6006
  { PseudoVRSUB_VI_M4, VRSUB_VI }, // 6007
  { PseudoVRSUB_VI_M4_MASK, VRSUB_VI }, // 6008
  { PseudoVRSUB_VI_M8, VRSUB_VI }, // 6009
  { PseudoVRSUB_VI_M8_MASK, VRSUB_VI }, // 6010
  { PseudoVRSUB_VI_MF2, VRSUB_VI }, // 6011
  { PseudoVRSUB_VI_MF2_MASK, VRSUB_VI }, // 6012
  { PseudoVRSUB_VI_MF4, VRSUB_VI }, // 6013
  { PseudoVRSUB_VI_MF4_MASK, VRSUB_VI }, // 6014
  { PseudoVRSUB_VI_MF8, VRSUB_VI }, // 6015
  { PseudoVRSUB_VI_MF8_MASK, VRSUB_VI }, // 6016
  { PseudoVRSUB_VX_M1, VRSUB_VX }, // 6017
  { PseudoVRSUB_VX_M1_MASK, VRSUB_VX }, // 6018
  { PseudoVRSUB_VX_M2, VRSUB_VX }, // 6019
  { PseudoVRSUB_VX_M2_MASK, VRSUB_VX }, // 6020
  { PseudoVRSUB_VX_M4, VRSUB_VX }, // 6021
  { PseudoVRSUB_VX_M4_MASK, VRSUB_VX }, // 6022
  { PseudoVRSUB_VX_M8, VRSUB_VX }, // 6023
  { PseudoVRSUB_VX_M8_MASK, VRSUB_VX }, // 6024
  { PseudoVRSUB_VX_MF2, VRSUB_VX }, // 6025
  { PseudoVRSUB_VX_MF2_MASK, VRSUB_VX }, // 6026
  { PseudoVRSUB_VX_MF4, VRSUB_VX }, // 6027
  { PseudoVRSUB_VX_MF4_MASK, VRSUB_VX }, // 6028
  { PseudoVRSUB_VX_MF8, VRSUB_VX }, // 6029
  { PseudoVRSUB_VX_MF8_MASK, VRSUB_VX }, // 6030
  { PseudoVSADDU_VI_M1, VSADDU_VI }, // 6031
  { PseudoVSADDU_VI_M1_MASK, VSADDU_VI }, // 6032
  { PseudoVSADDU_VI_M2, VSADDU_VI }, // 6033
  { PseudoVSADDU_VI_M2_MASK, VSADDU_VI }, // 6034
  { PseudoVSADDU_VI_M4, VSADDU_VI }, // 6035
  { PseudoVSADDU_VI_M4_MASK, VSADDU_VI }, // 6036
  { PseudoVSADDU_VI_M8, VSADDU_VI }, // 6037
  { PseudoVSADDU_VI_M8_MASK, VSADDU_VI }, // 6038
  { PseudoVSADDU_VI_MF2, VSADDU_VI }, // 6039
  { PseudoVSADDU_VI_MF2_MASK, VSADDU_VI }, // 6040
  { PseudoVSADDU_VI_MF4, VSADDU_VI }, // 6041
  { PseudoVSADDU_VI_MF4_MASK, VSADDU_VI }, // 6042
  { PseudoVSADDU_VI_MF8, VSADDU_VI }, // 6043
  { PseudoVSADDU_VI_MF8_MASK, VSADDU_VI }, // 6044
  { PseudoVSADDU_VV_M1, VSADDU_VV }, // 6045
  { PseudoVSADDU_VV_M1_MASK, VSADDU_VV }, // 6046
  { PseudoVSADDU_VV_M2, VSADDU_VV }, // 6047
  { PseudoVSADDU_VV_M2_MASK, VSADDU_VV }, // 6048
  { PseudoVSADDU_VV_M4, VSADDU_VV }, // 6049
  { PseudoVSADDU_VV_M4_MASK, VSADDU_VV }, // 6050
  { PseudoVSADDU_VV_M8, VSADDU_VV }, // 6051
  { PseudoVSADDU_VV_M8_MASK, VSADDU_VV }, // 6052
  { PseudoVSADDU_VV_MF2, VSADDU_VV }, // 6053
  { PseudoVSADDU_VV_MF2_MASK, VSADDU_VV }, // 6054
  { PseudoVSADDU_VV_MF4, VSADDU_VV }, // 6055
  { PseudoVSADDU_VV_MF4_MASK, VSADDU_VV }, // 6056
  { PseudoVSADDU_VV_MF8, VSADDU_VV }, // 6057
  { PseudoVSADDU_VV_MF8_MASK, VSADDU_VV }, // 6058
  { PseudoVSADDU_VX_M1, VSADDU_VX }, // 6059
  { PseudoVSADDU_VX_M1_MASK, VSADDU_VX }, // 6060
  { PseudoVSADDU_VX_M2, VSADDU_VX }, // 6061
  { PseudoVSADDU_VX_M2_MASK, VSADDU_VX }, // 6062
  { PseudoVSADDU_VX_M4, VSADDU_VX }, // 6063
  { PseudoVSADDU_VX_M4_MASK, VSADDU_VX }, // 6064
  { PseudoVSADDU_VX_M8, VSADDU_VX }, // 6065
  { PseudoVSADDU_VX_M8_MASK, VSADDU_VX }, // 6066
  { PseudoVSADDU_VX_MF2, VSADDU_VX }, // 6067
  { PseudoVSADDU_VX_MF2_MASK, VSADDU_VX }, // 6068
  { PseudoVSADDU_VX_MF4, VSADDU_VX }, // 6069
  { PseudoVSADDU_VX_MF4_MASK, VSADDU_VX }, // 6070
  { PseudoVSADDU_VX_MF8, VSADDU_VX }, // 6071
  { PseudoVSADDU_VX_MF8_MASK, VSADDU_VX }, // 6072
  { PseudoVSADD_VI_M1, VSADD_VI }, // 6073
  { PseudoVSADD_VI_M1_MASK, VSADD_VI }, // 6074
  { PseudoVSADD_VI_M2, VSADD_VI }, // 6075
  { PseudoVSADD_VI_M2_MASK, VSADD_VI }, // 6076
  { PseudoVSADD_VI_M4, VSADD_VI }, // 6077
  { PseudoVSADD_VI_M4_MASK, VSADD_VI }, // 6078
  { PseudoVSADD_VI_M8, VSADD_VI }, // 6079
  { PseudoVSADD_VI_M8_MASK, VSADD_VI }, // 6080
  { PseudoVSADD_VI_MF2, VSADD_VI }, // 6081
  { PseudoVSADD_VI_MF2_MASK, VSADD_VI }, // 6082
  { PseudoVSADD_VI_MF4, VSADD_VI }, // 6083
  { PseudoVSADD_VI_MF4_MASK, VSADD_VI }, // 6084
  { PseudoVSADD_VI_MF8, VSADD_VI }, // 6085
  { PseudoVSADD_VI_MF8_MASK, VSADD_VI }, // 6086
  { PseudoVSADD_VV_M1, VSADD_VV }, // 6087
  { PseudoVSADD_VV_M1_MASK, VSADD_VV }, // 6088
  { PseudoVSADD_VV_M2, VSADD_VV }, // 6089
  { PseudoVSADD_VV_M2_MASK, VSADD_VV }, // 6090
  { PseudoVSADD_VV_M4, VSADD_VV }, // 6091
  { PseudoVSADD_VV_M4_MASK, VSADD_VV }, // 6092
  { PseudoVSADD_VV_M8, VSADD_VV }, // 6093
  { PseudoVSADD_VV_M8_MASK, VSADD_VV }, // 6094
  { PseudoVSADD_VV_MF2, VSADD_VV }, // 6095
  { PseudoVSADD_VV_MF2_MASK, VSADD_VV }, // 6096
  { PseudoVSADD_VV_MF4, VSADD_VV }, // 6097
  { PseudoVSADD_VV_MF4_MASK, VSADD_VV }, // 6098
  { PseudoVSADD_VV_MF8, VSADD_VV }, // 6099
  { PseudoVSADD_VV_MF8_MASK, VSADD_VV }, // 6100
  { PseudoVSADD_VX_M1, VSADD_VX }, // 6101
  { PseudoVSADD_VX_M1_MASK, VSADD_VX }, // 6102
  { PseudoVSADD_VX_M2, VSADD_VX }, // 6103
  { PseudoVSADD_VX_M2_MASK, VSADD_VX }, // 6104
  { PseudoVSADD_VX_M4, VSADD_VX }, // 6105
  { PseudoVSADD_VX_M4_MASK, VSADD_VX }, // 6106
  { PseudoVSADD_VX_M8, VSADD_VX }, // 6107
  { PseudoVSADD_VX_M8_MASK, VSADD_VX }, // 6108
  { PseudoVSADD_VX_MF2, VSADD_VX }, // 6109
  { PseudoVSADD_VX_MF2_MASK, VSADD_VX }, // 6110
  { PseudoVSADD_VX_MF4, VSADD_VX }, // 6111
  { PseudoVSADD_VX_MF4_MASK, VSADD_VX }, // 6112
  { PseudoVSADD_VX_MF8, VSADD_VX }, // 6113
  { PseudoVSADD_VX_MF8_MASK, VSADD_VX }, // 6114
  { PseudoVSBC_VVM_M1, VSBC_VVM }, // 6115
  { PseudoVSBC_VVM_M2, VSBC_VVM }, // 6116
  { PseudoVSBC_VVM_M4, VSBC_VVM }, // 6117
  { PseudoVSBC_VVM_M8, VSBC_VVM }, // 6118
  { PseudoVSBC_VVM_MF2, VSBC_VVM }, // 6119
  { PseudoVSBC_VVM_MF4, VSBC_VVM }, // 6120
  { PseudoVSBC_VVM_MF8, VSBC_VVM }, // 6121
  { PseudoVSBC_VXM_M1, VSBC_VXM }, // 6122
  { PseudoVSBC_VXM_M2, VSBC_VXM }, // 6123
  { PseudoVSBC_VXM_M4, VSBC_VXM }, // 6124
  { PseudoVSBC_VXM_M8, VSBC_VXM }, // 6125
  { PseudoVSBC_VXM_MF2, VSBC_VXM }, // 6126
  { PseudoVSBC_VXM_MF4, VSBC_VXM }, // 6127
  { PseudoVSBC_VXM_MF8, VSBC_VXM }, // 6128
  { PseudoVSE16_V_M1, VSE16_V }, // 6129
  { PseudoVSE16_V_M1_MASK, VSE16_V }, // 6130
  { PseudoVSE16_V_M2, VSE16_V }, // 6131
  { PseudoVSE16_V_M2_MASK, VSE16_V }, // 6132
  { PseudoVSE16_V_M4, VSE16_V }, // 6133
  { PseudoVSE16_V_M4_MASK, VSE16_V }, // 6134
  { PseudoVSE16_V_M8, VSE16_V }, // 6135
  { PseudoVSE16_V_M8_MASK, VSE16_V }, // 6136
  { PseudoVSE16_V_MF2, VSE16_V }, // 6137
  { PseudoVSE16_V_MF2_MASK, VSE16_V }, // 6138
  { PseudoVSE16_V_MF4, VSE16_V }, // 6139
  { PseudoVSE16_V_MF4_MASK, VSE16_V }, // 6140
  { PseudoVSE32_V_M1, VSE32_V }, // 6141
  { PseudoVSE32_V_M1_MASK, VSE32_V }, // 6142
  { PseudoVSE32_V_M2, VSE32_V }, // 6143
  { PseudoVSE32_V_M2_MASK, VSE32_V }, // 6144
  { PseudoVSE32_V_M4, VSE32_V }, // 6145
  { PseudoVSE32_V_M4_MASK, VSE32_V }, // 6146
  { PseudoVSE32_V_M8, VSE32_V }, // 6147
  { PseudoVSE32_V_M8_MASK, VSE32_V }, // 6148
  { PseudoVSE32_V_MF2, VSE32_V }, // 6149
  { PseudoVSE32_V_MF2_MASK, VSE32_V }, // 6150
  { PseudoVSE64_V_M1, VSE64_V }, // 6151
  { PseudoVSE64_V_M1_MASK, VSE64_V }, // 6152
  { PseudoVSE64_V_M2, VSE64_V }, // 6153
  { PseudoVSE64_V_M2_MASK, VSE64_V }, // 6154
  { PseudoVSE64_V_M4, VSE64_V }, // 6155
  { PseudoVSE64_V_M4_MASK, VSE64_V }, // 6156
  { PseudoVSE64_V_M8, VSE64_V }, // 6157
  { PseudoVSE64_V_M8_MASK, VSE64_V }, // 6158
  { PseudoVSE8_V_M1, VSE8_V }, // 6159
  { PseudoVSE8_V_M1_MASK, VSE8_V }, // 6160
  { PseudoVSE8_V_M2, VSE8_V }, // 6161
  { PseudoVSE8_V_M2_MASK, VSE8_V }, // 6162
  { PseudoVSE8_V_M4, VSE8_V }, // 6163
  { PseudoVSE8_V_M4_MASK, VSE8_V }, // 6164
  { PseudoVSE8_V_M8, VSE8_V }, // 6165
  { PseudoVSE8_V_M8_MASK, VSE8_V }, // 6166
  { PseudoVSE8_V_MF2, VSE8_V }, // 6167
  { PseudoVSE8_V_MF2_MASK, VSE8_V }, // 6168
  { PseudoVSE8_V_MF4, VSE8_V }, // 6169
  { PseudoVSE8_V_MF4_MASK, VSE8_V }, // 6170
  { PseudoVSE8_V_MF8, VSE8_V }, // 6171
  { PseudoVSE8_V_MF8_MASK, VSE8_V }, // 6172
  { PseudoVSEXT_VF2_M1, VSEXT_VF2 }, // 6173
  { PseudoVSEXT_VF2_M1_MASK, VSEXT_VF2 }, // 6174
  { PseudoVSEXT_VF2_M2, VSEXT_VF2 }, // 6175
  { PseudoVSEXT_VF2_M2_MASK, VSEXT_VF2 }, // 6176
  { PseudoVSEXT_VF2_M4, VSEXT_VF2 }, // 6177
  { PseudoVSEXT_VF2_M4_MASK, VSEXT_VF2 }, // 6178
  { PseudoVSEXT_VF2_M8, VSEXT_VF2 }, // 6179
  { PseudoVSEXT_VF2_M8_MASK, VSEXT_VF2 }, // 6180
  { PseudoVSEXT_VF2_MF2, VSEXT_VF2 }, // 6181
  { PseudoVSEXT_VF2_MF2_MASK, VSEXT_VF2 }, // 6182
  { PseudoVSEXT_VF2_MF4, VSEXT_VF2 }, // 6183
  { PseudoVSEXT_VF2_MF4_MASK, VSEXT_VF2 }, // 6184
  { PseudoVSEXT_VF4_M1, VSEXT_VF4 }, // 6185
  { PseudoVSEXT_VF4_M1_MASK, VSEXT_VF4 }, // 6186
  { PseudoVSEXT_VF4_M2, VSEXT_VF4 }, // 6187
  { PseudoVSEXT_VF4_M2_MASK, VSEXT_VF4 }, // 6188
  { PseudoVSEXT_VF4_M4, VSEXT_VF4 }, // 6189
  { PseudoVSEXT_VF4_M4_MASK, VSEXT_VF4 }, // 6190
  { PseudoVSEXT_VF4_M8, VSEXT_VF4 }, // 6191
  { PseudoVSEXT_VF4_M8_MASK, VSEXT_VF4 }, // 6192
  { PseudoVSEXT_VF4_MF2, VSEXT_VF4 }, // 6193
  { PseudoVSEXT_VF4_MF2_MASK, VSEXT_VF4 }, // 6194
  { PseudoVSEXT_VF8_M1, VSEXT_VF8 }, // 6195
  { PseudoVSEXT_VF8_M1_MASK, VSEXT_VF8 }, // 6196
  { PseudoVSEXT_VF8_M2, VSEXT_VF8 }, // 6197
  { PseudoVSEXT_VF8_M2_MASK, VSEXT_VF8 }, // 6198
  { PseudoVSEXT_VF8_M4, VSEXT_VF8 }, // 6199
  { PseudoVSEXT_VF8_M4_MASK, VSEXT_VF8 }, // 6200
  { PseudoVSEXT_VF8_M8, VSEXT_VF8 }, // 6201
  { PseudoVSEXT_VF8_M8_MASK, VSEXT_VF8 }, // 6202
  { PseudoVSLIDE1DOWN_VX_M1, VSLIDE1DOWN_VX }, // 6203
  { PseudoVSLIDE1DOWN_VX_M1_MASK, VSLIDE1DOWN_VX }, // 6204
  { PseudoVSLIDE1DOWN_VX_M2, VSLIDE1DOWN_VX }, // 6205
  { PseudoVSLIDE1DOWN_VX_M2_MASK, VSLIDE1DOWN_VX }, // 6206
  { PseudoVSLIDE1DOWN_VX_M4, VSLIDE1DOWN_VX }, // 6207
  { PseudoVSLIDE1DOWN_VX_M4_MASK, VSLIDE1DOWN_VX }, // 6208
  { PseudoVSLIDE1DOWN_VX_M8, VSLIDE1DOWN_VX }, // 6209
  { PseudoVSLIDE1DOWN_VX_M8_MASK, VSLIDE1DOWN_VX }, // 6210
  { PseudoVSLIDE1DOWN_VX_MF2, VSLIDE1DOWN_VX }, // 6211
  { PseudoVSLIDE1DOWN_VX_MF2_MASK, VSLIDE1DOWN_VX }, // 6212
  { PseudoVSLIDE1DOWN_VX_MF4, VSLIDE1DOWN_VX }, // 6213
  { PseudoVSLIDE1DOWN_VX_MF4_MASK, VSLIDE1DOWN_VX }, // 6214
  { PseudoVSLIDE1DOWN_VX_MF8, VSLIDE1DOWN_VX }, // 6215
  { PseudoVSLIDE1DOWN_VX_MF8_MASK, VSLIDE1DOWN_VX }, // 6216
  { PseudoVSLIDE1UP_VX_M1, VSLIDE1UP_VX }, // 6217
  { PseudoVSLIDE1UP_VX_M1_MASK, VSLIDE1UP_VX }, // 6218
  { PseudoVSLIDE1UP_VX_M2, VSLIDE1UP_VX }, // 6219
  { PseudoVSLIDE1UP_VX_M2_MASK, VSLIDE1UP_VX }, // 6220
  { PseudoVSLIDE1UP_VX_M4, VSLIDE1UP_VX }, // 6221
  { PseudoVSLIDE1UP_VX_M4_MASK, VSLIDE1UP_VX }, // 6222
  { PseudoVSLIDE1UP_VX_M8, VSLIDE1UP_VX }, // 6223
  { PseudoVSLIDE1UP_VX_M8_MASK, VSLIDE1UP_VX }, // 6224
  { PseudoVSLIDE1UP_VX_MF2, VSLIDE1UP_VX }, // 6225
  { PseudoVSLIDE1UP_VX_MF2_MASK, VSLIDE1UP_VX }, // 6226
  { PseudoVSLIDE1UP_VX_MF4, VSLIDE1UP_VX }, // 6227
  { PseudoVSLIDE1UP_VX_MF4_MASK, VSLIDE1UP_VX }, // 6228
  { PseudoVSLIDE1UP_VX_MF8, VSLIDE1UP_VX }, // 6229
  { PseudoVSLIDE1UP_VX_MF8_MASK, VSLIDE1UP_VX }, // 6230
  { PseudoVSLIDEDOWN_VI_M1, VSLIDEDOWN_VI }, // 6231
  { PseudoVSLIDEDOWN_VI_M1_MASK, VSLIDEDOWN_VI }, // 6232
  { PseudoVSLIDEDOWN_VI_M2, VSLIDEDOWN_VI }, // 6233
  { PseudoVSLIDEDOWN_VI_M2_MASK, VSLIDEDOWN_VI }, // 6234
  { PseudoVSLIDEDOWN_VI_M4, VSLIDEDOWN_VI }, // 6235
  { PseudoVSLIDEDOWN_VI_M4_MASK, VSLIDEDOWN_VI }, // 6236
  { PseudoVSLIDEDOWN_VI_M8, VSLIDEDOWN_VI }, // 6237
  { PseudoVSLIDEDOWN_VI_M8_MASK, VSLIDEDOWN_VI }, // 6238
  { PseudoVSLIDEDOWN_VI_MF2, VSLIDEDOWN_VI }, // 6239
  { PseudoVSLIDEDOWN_VI_MF2_MASK, VSLIDEDOWN_VI }, // 6240
  { PseudoVSLIDEDOWN_VI_MF4, VSLIDEDOWN_VI }, // 6241
  { PseudoVSLIDEDOWN_VI_MF4_MASK, VSLIDEDOWN_VI }, // 6242
  { PseudoVSLIDEDOWN_VI_MF8, VSLIDEDOWN_VI }, // 6243
  { PseudoVSLIDEDOWN_VI_MF8_MASK, VSLIDEDOWN_VI }, // 6244
  { PseudoVSLIDEDOWN_VX_M1, VSLIDEDOWN_VX }, // 6245
  { PseudoVSLIDEDOWN_VX_M1_MASK, VSLIDEDOWN_VX }, // 6246
  { PseudoVSLIDEDOWN_VX_M2, VSLIDEDOWN_VX }, // 6247
  { PseudoVSLIDEDOWN_VX_M2_MASK, VSLIDEDOWN_VX }, // 6248
  { PseudoVSLIDEDOWN_VX_M4, VSLIDEDOWN_VX }, // 6249
  { PseudoVSLIDEDOWN_VX_M4_MASK, VSLIDEDOWN_VX }, // 6250
  { PseudoVSLIDEDOWN_VX_M8, VSLIDEDOWN_VX }, // 6251
  { PseudoVSLIDEDOWN_VX_M8_MASK, VSLIDEDOWN_VX }, // 6252
  { PseudoVSLIDEDOWN_VX_MF2, VSLIDEDOWN_VX }, // 6253
  { PseudoVSLIDEDOWN_VX_MF2_MASK, VSLIDEDOWN_VX }, // 6254
  { PseudoVSLIDEDOWN_VX_MF4, VSLIDEDOWN_VX }, // 6255
  { PseudoVSLIDEDOWN_VX_MF4_MASK, VSLIDEDOWN_VX }, // 6256
  { PseudoVSLIDEDOWN_VX_MF8, VSLIDEDOWN_VX }, // 6257
  { PseudoVSLIDEDOWN_VX_MF8_MASK, VSLIDEDOWN_VX }, // 6258
  { PseudoVSLIDEUP_VI_M1, VSLIDEUP_VI }, // 6259
  { PseudoVSLIDEUP_VI_M1_MASK, VSLIDEUP_VI }, // 6260
  { PseudoVSLIDEUP_VI_M2, VSLIDEUP_VI }, // 6261
  { PseudoVSLIDEUP_VI_M2_MASK, VSLIDEUP_VI }, // 6262
  { PseudoVSLIDEUP_VI_M4, VSLIDEUP_VI }, // 6263
  { PseudoVSLIDEUP_VI_M4_MASK, VSLIDEUP_VI }, // 6264
  { PseudoVSLIDEUP_VI_M8, VSLIDEUP_VI }, // 6265
  { PseudoVSLIDEUP_VI_M8_MASK, VSLIDEUP_VI }, // 6266
  { PseudoVSLIDEUP_VI_MF2, VSLIDEUP_VI }, // 6267
  { PseudoVSLIDEUP_VI_MF2_MASK, VSLIDEUP_VI }, // 6268
  { PseudoVSLIDEUP_VI_MF4, VSLIDEUP_VI }, // 6269
  { PseudoVSLIDEUP_VI_MF4_MASK, VSLIDEUP_VI }, // 6270
  { PseudoVSLIDEUP_VI_MF8, VSLIDEUP_VI }, // 6271
  { PseudoVSLIDEUP_VI_MF8_MASK, VSLIDEUP_VI }, // 6272
  { PseudoVSLIDEUP_VX_M1, VSLIDEUP_VX }, // 6273
  { PseudoVSLIDEUP_VX_M1_MASK, VSLIDEUP_VX }, // 6274
  { PseudoVSLIDEUP_VX_M2, VSLIDEUP_VX }, // 6275
  { PseudoVSLIDEUP_VX_M2_MASK, VSLIDEUP_VX }, // 6276
  { PseudoVSLIDEUP_VX_M4, VSLIDEUP_VX }, // 6277
  { PseudoVSLIDEUP_VX_M4_MASK, VSLIDEUP_VX }, // 6278
  { PseudoVSLIDEUP_VX_M8, VSLIDEUP_VX }, // 6279
  { PseudoVSLIDEUP_VX_M8_MASK, VSLIDEUP_VX }, // 6280
  { PseudoVSLIDEUP_VX_MF2, VSLIDEUP_VX }, // 6281
  { PseudoVSLIDEUP_VX_MF2_MASK, VSLIDEUP_VX }, // 6282
  { PseudoVSLIDEUP_VX_MF4, VSLIDEUP_VX }, // 6283
  { PseudoVSLIDEUP_VX_MF4_MASK, VSLIDEUP_VX }, // 6284
  { PseudoVSLIDEUP_VX_MF8, VSLIDEUP_VX }, // 6285
  { PseudoVSLIDEUP_VX_MF8_MASK, VSLIDEUP_VX }, // 6286
  { PseudoVSLL_VI_M1, VSLL_VI }, // 6287
  { PseudoVSLL_VI_M1_MASK, VSLL_VI }, // 6288
  { PseudoVSLL_VI_M2, VSLL_VI }, // 6289
  { PseudoVSLL_VI_M2_MASK, VSLL_VI }, // 6290
  { PseudoVSLL_VI_M4, VSLL_VI }, // 6291
  { PseudoVSLL_VI_M4_MASK, VSLL_VI }, // 6292
  { PseudoVSLL_VI_M8, VSLL_VI }, // 6293
  { PseudoVSLL_VI_M8_MASK, VSLL_VI }, // 6294
  { PseudoVSLL_VI_MF2, VSLL_VI }, // 6295
  { PseudoVSLL_VI_MF2_MASK, VSLL_VI }, // 6296
  { PseudoVSLL_VI_MF4, VSLL_VI }, // 6297
  { PseudoVSLL_VI_MF4_MASK, VSLL_VI }, // 6298
  { PseudoVSLL_VI_MF8, VSLL_VI }, // 6299
  { PseudoVSLL_VI_MF8_MASK, VSLL_VI }, // 6300
  { PseudoVSLL_VV_M1, VSLL_VV }, // 6301
  { PseudoVSLL_VV_M1_MASK, VSLL_VV }, // 6302
  { PseudoVSLL_VV_M2, VSLL_VV }, // 6303
  { PseudoVSLL_VV_M2_MASK, VSLL_VV }, // 6304
  { PseudoVSLL_VV_M4, VSLL_VV }, // 6305
  { PseudoVSLL_VV_M4_MASK, VSLL_VV }, // 6306
  { PseudoVSLL_VV_M8, VSLL_VV }, // 6307
  { PseudoVSLL_VV_M8_MASK, VSLL_VV }, // 6308
  { PseudoVSLL_VV_MF2, VSLL_VV }, // 6309
  { PseudoVSLL_VV_MF2_MASK, VSLL_VV }, // 6310
  { PseudoVSLL_VV_MF4, VSLL_VV }, // 6311
  { PseudoVSLL_VV_MF4_MASK, VSLL_VV }, // 6312
  { PseudoVSLL_VV_MF8, VSLL_VV }, // 6313
  { PseudoVSLL_VV_MF8_MASK, VSLL_VV }, // 6314
  { PseudoVSLL_VX_M1, VSLL_VX }, // 6315
  { PseudoVSLL_VX_M1_MASK, VSLL_VX }, // 6316
  { PseudoVSLL_VX_M2, VSLL_VX }, // 6317
  { PseudoVSLL_VX_M2_MASK, VSLL_VX }, // 6318
  { PseudoVSLL_VX_M4, VSLL_VX }, // 6319
  { PseudoVSLL_VX_M4_MASK, VSLL_VX }, // 6320
  { PseudoVSLL_VX_M8, VSLL_VX }, // 6321
  { PseudoVSLL_VX_M8_MASK, VSLL_VX }, // 6322
  { PseudoVSLL_VX_MF2, VSLL_VX }, // 6323
  { PseudoVSLL_VX_MF2_MASK, VSLL_VX }, // 6324
  { PseudoVSLL_VX_MF4, VSLL_VX }, // 6325
  { PseudoVSLL_VX_MF4_MASK, VSLL_VX }, // 6326
  { PseudoVSLL_VX_MF8, VSLL_VX }, // 6327
  { PseudoVSLL_VX_MF8_MASK, VSLL_VX }, // 6328
  { PseudoVSMUL_VV_M1, VSMUL_VV }, // 6329
  { PseudoVSMUL_VV_M1_MASK, VSMUL_VV }, // 6330
  { PseudoVSMUL_VV_M2, VSMUL_VV }, // 6331
  { PseudoVSMUL_VV_M2_MASK, VSMUL_VV }, // 6332
  { PseudoVSMUL_VV_M4, VSMUL_VV }, // 6333
  { PseudoVSMUL_VV_M4_MASK, VSMUL_VV }, // 6334
  { PseudoVSMUL_VV_M8, VSMUL_VV }, // 6335
  { PseudoVSMUL_VV_M8_MASK, VSMUL_VV }, // 6336
  { PseudoVSMUL_VV_MF2, VSMUL_VV }, // 6337
  { PseudoVSMUL_VV_MF2_MASK, VSMUL_VV }, // 6338
  { PseudoVSMUL_VV_MF4, VSMUL_VV }, // 6339
  { PseudoVSMUL_VV_MF4_MASK, VSMUL_VV }, // 6340
  { PseudoVSMUL_VV_MF8, VSMUL_VV }, // 6341
  { PseudoVSMUL_VV_MF8_MASK, VSMUL_VV }, // 6342
  { PseudoVSMUL_VX_M1, VSMUL_VX }, // 6343
  { PseudoVSMUL_VX_M1_MASK, VSMUL_VX }, // 6344
  { PseudoVSMUL_VX_M2, VSMUL_VX }, // 6345
  { PseudoVSMUL_VX_M2_MASK, VSMUL_VX }, // 6346
  { PseudoVSMUL_VX_M4, VSMUL_VX }, // 6347
  { PseudoVSMUL_VX_M4_MASK, VSMUL_VX }, // 6348
  { PseudoVSMUL_VX_M8, VSMUL_VX }, // 6349
  { PseudoVSMUL_VX_M8_MASK, VSMUL_VX }, // 6350
  { PseudoVSMUL_VX_MF2, VSMUL_VX }, // 6351
  { PseudoVSMUL_VX_MF2_MASK, VSMUL_VX }, // 6352
  { PseudoVSMUL_VX_MF4, VSMUL_VX }, // 6353
  { PseudoVSMUL_VX_MF4_MASK, VSMUL_VX }, // 6354
  { PseudoVSMUL_VX_MF8, VSMUL_VX }, // 6355
  { PseudoVSMUL_VX_MF8_MASK, VSMUL_VX }, // 6356
  { PseudoVSM_V_B1, VSM_V }, // 6357
  { PseudoVSM_V_B16, VSM_V }, // 6358
  { PseudoVSM_V_B2, VSM_V }, // 6359
  { PseudoVSM_V_B32, VSM_V }, // 6360
  { PseudoVSM_V_B4, VSM_V }, // 6361
  { PseudoVSM_V_B64, VSM_V }, // 6362
  { PseudoVSM_V_B8, VSM_V }, // 6363
  { PseudoVSOXEI16_V_M1_M1, VSOXEI16_V }, // 6364
  { PseudoVSOXEI16_V_M1_M1_MASK, VSOXEI16_V }, // 6365
  { PseudoVSOXEI16_V_M1_M2, VSOXEI16_V }, // 6366
  { PseudoVSOXEI16_V_M1_M2_MASK, VSOXEI16_V }, // 6367
  { PseudoVSOXEI16_V_M1_M4, VSOXEI16_V }, // 6368
  { PseudoVSOXEI16_V_M1_M4_MASK, VSOXEI16_V }, // 6369
  { PseudoVSOXEI16_V_M1_MF2, VSOXEI16_V }, // 6370
  { PseudoVSOXEI16_V_M1_MF2_MASK, VSOXEI16_V }, // 6371
  { PseudoVSOXEI16_V_M2_M1, VSOXEI16_V }, // 6372
  { PseudoVSOXEI16_V_M2_M1_MASK, VSOXEI16_V }, // 6373
  { PseudoVSOXEI16_V_M2_M2, VSOXEI16_V }, // 6374
  { PseudoVSOXEI16_V_M2_M2_MASK, VSOXEI16_V }, // 6375
  { PseudoVSOXEI16_V_M2_M4, VSOXEI16_V }, // 6376
  { PseudoVSOXEI16_V_M2_M4_MASK, VSOXEI16_V }, // 6377
  { PseudoVSOXEI16_V_M2_M8, VSOXEI16_V }, // 6378
  { PseudoVSOXEI16_V_M2_M8_MASK, VSOXEI16_V }, // 6379
  { PseudoVSOXEI16_V_M4_M2, VSOXEI16_V }, // 6380
  { PseudoVSOXEI16_V_M4_M2_MASK, VSOXEI16_V }, // 6381
  { PseudoVSOXEI16_V_M4_M4, VSOXEI16_V }, // 6382
  { PseudoVSOXEI16_V_M4_M4_MASK, VSOXEI16_V }, // 6383
  { PseudoVSOXEI16_V_M4_M8, VSOXEI16_V }, // 6384
  { PseudoVSOXEI16_V_M4_M8_MASK, VSOXEI16_V }, // 6385
  { PseudoVSOXEI16_V_M8_M4, VSOXEI16_V }, // 6386
  { PseudoVSOXEI16_V_M8_M4_MASK, VSOXEI16_V }, // 6387
  { PseudoVSOXEI16_V_M8_M8, VSOXEI16_V }, // 6388
  { PseudoVSOXEI16_V_M8_M8_MASK, VSOXEI16_V }, // 6389
  { PseudoVSOXEI16_V_MF2_M1, VSOXEI16_V }, // 6390
  { PseudoVSOXEI16_V_MF2_M1_MASK, VSOXEI16_V }, // 6391
  { PseudoVSOXEI16_V_MF2_M2, VSOXEI16_V }, // 6392
  { PseudoVSOXEI16_V_MF2_M2_MASK, VSOXEI16_V }, // 6393
  { PseudoVSOXEI16_V_MF2_MF2, VSOXEI16_V }, // 6394
  { PseudoVSOXEI16_V_MF2_MF2_MASK, VSOXEI16_V }, // 6395
  { PseudoVSOXEI16_V_MF2_MF4, VSOXEI16_V }, // 6396
  { PseudoVSOXEI16_V_MF2_MF4_MASK, VSOXEI16_V }, // 6397
  { PseudoVSOXEI16_V_MF4_M1, VSOXEI16_V }, // 6398
  { PseudoVSOXEI16_V_MF4_M1_MASK, VSOXEI16_V }, // 6399
  { PseudoVSOXEI16_V_MF4_MF2, VSOXEI16_V }, // 6400
  { PseudoVSOXEI16_V_MF4_MF2_MASK, VSOXEI16_V }, // 6401
  { PseudoVSOXEI16_V_MF4_MF4, VSOXEI16_V }, // 6402
  { PseudoVSOXEI16_V_MF4_MF4_MASK, VSOXEI16_V }, // 6403
  { PseudoVSOXEI16_V_MF4_MF8, VSOXEI16_V }, // 6404
  { PseudoVSOXEI16_V_MF4_MF8_MASK, VSOXEI16_V }, // 6405
  { PseudoVSOXEI32_V_M1_M1, VSOXEI32_V }, // 6406
  { PseudoVSOXEI32_V_M1_M1_MASK, VSOXEI32_V }, // 6407
  { PseudoVSOXEI32_V_M1_M2, VSOXEI32_V }, // 6408
  { PseudoVSOXEI32_V_M1_M2_MASK, VSOXEI32_V }, // 6409
  { PseudoVSOXEI32_V_M1_MF2, VSOXEI32_V }, // 6410
  { PseudoVSOXEI32_V_M1_MF2_MASK, VSOXEI32_V }, // 6411
  { PseudoVSOXEI32_V_M1_MF4, VSOXEI32_V }, // 6412
  { PseudoVSOXEI32_V_M1_MF4_MASK, VSOXEI32_V }, // 6413
  { PseudoVSOXEI32_V_M2_M1, VSOXEI32_V }, // 6414
  { PseudoVSOXEI32_V_M2_M1_MASK, VSOXEI32_V }, // 6415
  { PseudoVSOXEI32_V_M2_M2, VSOXEI32_V }, // 6416
  { PseudoVSOXEI32_V_M2_M2_MASK, VSOXEI32_V }, // 6417
  { PseudoVSOXEI32_V_M2_M4, VSOXEI32_V }, // 6418
  { PseudoVSOXEI32_V_M2_M4_MASK, VSOXEI32_V }, // 6419
  { PseudoVSOXEI32_V_M2_MF2, VSOXEI32_V }, // 6420
  { PseudoVSOXEI32_V_M2_MF2_MASK, VSOXEI32_V }, // 6421
  { PseudoVSOXEI32_V_M4_M1, VSOXEI32_V }, // 6422
  { PseudoVSOXEI32_V_M4_M1_MASK, VSOXEI32_V }, // 6423
  { PseudoVSOXEI32_V_M4_M2, VSOXEI32_V }, // 6424
  { PseudoVSOXEI32_V_M4_M2_MASK, VSOXEI32_V }, // 6425
  { PseudoVSOXEI32_V_M4_M4, VSOXEI32_V }, // 6426
  { PseudoVSOXEI32_V_M4_M4_MASK, VSOXEI32_V }, // 6427
  { PseudoVSOXEI32_V_M4_M8, VSOXEI32_V }, // 6428
  { PseudoVSOXEI32_V_M4_M8_MASK, VSOXEI32_V }, // 6429
  { PseudoVSOXEI32_V_M8_M2, VSOXEI32_V }, // 6430
  { PseudoVSOXEI32_V_M8_M2_MASK, VSOXEI32_V }, // 6431
  { PseudoVSOXEI32_V_M8_M4, VSOXEI32_V }, // 6432
  { PseudoVSOXEI32_V_M8_M4_MASK, VSOXEI32_V }, // 6433
  { PseudoVSOXEI32_V_M8_M8, VSOXEI32_V }, // 6434
  { PseudoVSOXEI32_V_M8_M8_MASK, VSOXEI32_V }, // 6435
  { PseudoVSOXEI32_V_MF2_M1, VSOXEI32_V }, // 6436
  { PseudoVSOXEI32_V_MF2_M1_MASK, VSOXEI32_V }, // 6437
  { PseudoVSOXEI32_V_MF2_MF2, VSOXEI32_V }, // 6438
  { PseudoVSOXEI32_V_MF2_MF2_MASK, VSOXEI32_V }, // 6439
  { PseudoVSOXEI32_V_MF2_MF4, VSOXEI32_V }, // 6440
  { PseudoVSOXEI32_V_MF2_MF4_MASK, VSOXEI32_V }, // 6441
  { PseudoVSOXEI32_V_MF2_MF8, VSOXEI32_V }, // 6442
  { PseudoVSOXEI32_V_MF2_MF8_MASK, VSOXEI32_V }, // 6443
  { PseudoVSOXEI64_V_M1_M1, VSOXEI64_V }, // 6444
  { PseudoVSOXEI64_V_M1_M1_MASK, VSOXEI64_V }, // 6445
  { PseudoVSOXEI64_V_M1_MF2, VSOXEI64_V }, // 6446
  { PseudoVSOXEI64_V_M1_MF2_MASK, VSOXEI64_V }, // 6447
  { PseudoVSOXEI64_V_M1_MF4, VSOXEI64_V }, // 6448
  { PseudoVSOXEI64_V_M1_MF4_MASK, VSOXEI64_V }, // 6449
  { PseudoVSOXEI64_V_M1_MF8, VSOXEI64_V }, // 6450
  { PseudoVSOXEI64_V_M1_MF8_MASK, VSOXEI64_V }, // 6451
  { PseudoVSOXEI64_V_M2_M1, VSOXEI64_V }, // 6452
  { PseudoVSOXEI64_V_M2_M1_MASK, VSOXEI64_V }, // 6453
  { PseudoVSOXEI64_V_M2_M2, VSOXEI64_V }, // 6454
  { PseudoVSOXEI64_V_M2_M2_MASK, VSOXEI64_V }, // 6455
  { PseudoVSOXEI64_V_M2_MF2, VSOXEI64_V }, // 6456
  { PseudoVSOXEI64_V_M2_MF2_MASK, VSOXEI64_V }, // 6457
  { PseudoVSOXEI64_V_M2_MF4, VSOXEI64_V }, // 6458
  { PseudoVSOXEI64_V_M2_MF4_MASK, VSOXEI64_V }, // 6459
  { PseudoVSOXEI64_V_M4_M1, VSOXEI64_V }, // 6460
  { PseudoVSOXEI64_V_M4_M1_MASK, VSOXEI64_V }, // 6461
  { PseudoVSOXEI64_V_M4_M2, VSOXEI64_V }, // 6462
  { PseudoVSOXEI64_V_M4_M2_MASK, VSOXEI64_V }, // 6463
  { PseudoVSOXEI64_V_M4_M4, VSOXEI64_V }, // 6464
  { PseudoVSOXEI64_V_M4_M4_MASK, VSOXEI64_V }, // 6465
  { PseudoVSOXEI64_V_M4_MF2, VSOXEI64_V }, // 6466
  { PseudoVSOXEI64_V_M4_MF2_MASK, VSOXEI64_V }, // 6467
  { PseudoVSOXEI64_V_M8_M1, VSOXEI64_V }, // 6468
  { PseudoVSOXEI64_V_M8_M1_MASK, VSOXEI64_V }, // 6469
  { PseudoVSOXEI64_V_M8_M2, VSOXEI64_V }, // 6470
  { PseudoVSOXEI64_V_M8_M2_MASK, VSOXEI64_V }, // 6471
  { PseudoVSOXEI64_V_M8_M4, VSOXEI64_V }, // 6472
  { PseudoVSOXEI64_V_M8_M4_MASK, VSOXEI64_V }, // 6473
  { PseudoVSOXEI64_V_M8_M8, VSOXEI64_V }, // 6474
  { PseudoVSOXEI64_V_M8_M8_MASK, VSOXEI64_V }, // 6475
  { PseudoVSOXEI8_V_M1_M1, VSOXEI8_V }, // 6476
  { PseudoVSOXEI8_V_M1_M1_MASK, VSOXEI8_V }, // 6477
  { PseudoVSOXEI8_V_M1_M2, VSOXEI8_V }, // 6478
  { PseudoVSOXEI8_V_M1_M2_MASK, VSOXEI8_V }, // 6479
  { PseudoVSOXEI8_V_M1_M4, VSOXEI8_V }, // 6480
  { PseudoVSOXEI8_V_M1_M4_MASK, VSOXEI8_V }, // 6481
  { PseudoVSOXEI8_V_M1_M8, VSOXEI8_V }, // 6482
  { PseudoVSOXEI8_V_M1_M8_MASK, VSOXEI8_V }, // 6483
  { PseudoVSOXEI8_V_M2_M2, VSOXEI8_V }, // 6484
  { PseudoVSOXEI8_V_M2_M2_MASK, VSOXEI8_V }, // 6485
  { PseudoVSOXEI8_V_M2_M4, VSOXEI8_V }, // 6486
  { PseudoVSOXEI8_V_M2_M4_MASK, VSOXEI8_V }, // 6487
  { PseudoVSOXEI8_V_M2_M8, VSOXEI8_V }, // 6488
  { PseudoVSOXEI8_V_M2_M8_MASK, VSOXEI8_V }, // 6489
  { PseudoVSOXEI8_V_M4_M4, VSOXEI8_V }, // 6490
  { PseudoVSOXEI8_V_M4_M4_MASK, VSOXEI8_V }, // 6491
  { PseudoVSOXEI8_V_M4_M8, VSOXEI8_V }, // 6492
  { PseudoVSOXEI8_V_M4_M8_MASK, VSOXEI8_V }, // 6493
  { PseudoVSOXEI8_V_M8_M8, VSOXEI8_V }, // 6494
  { PseudoVSOXEI8_V_M8_M8_MASK, VSOXEI8_V }, // 6495
  { PseudoVSOXEI8_V_MF2_M1, VSOXEI8_V }, // 6496
  { PseudoVSOXEI8_V_MF2_M1_MASK, VSOXEI8_V }, // 6497
  { PseudoVSOXEI8_V_MF2_M2, VSOXEI8_V }, // 6498
  { PseudoVSOXEI8_V_MF2_M2_MASK, VSOXEI8_V }, // 6499
  { PseudoVSOXEI8_V_MF2_M4, VSOXEI8_V }, // 6500
  { PseudoVSOXEI8_V_MF2_M4_MASK, VSOXEI8_V }, // 6501
  { PseudoVSOXEI8_V_MF2_MF2, VSOXEI8_V }, // 6502
  { PseudoVSOXEI8_V_MF2_MF2_MASK, VSOXEI8_V }, // 6503
  { PseudoVSOXEI8_V_MF4_M1, VSOXEI8_V }, // 6504
  { PseudoVSOXEI8_V_MF4_M1_MASK, VSOXEI8_V }, // 6505
  { PseudoVSOXEI8_V_MF4_M2, VSOXEI8_V }, // 6506
  { PseudoVSOXEI8_V_MF4_M2_MASK, VSOXEI8_V }, // 6507
  { PseudoVSOXEI8_V_MF4_MF2, VSOXEI8_V }, // 6508
  { PseudoVSOXEI8_V_MF4_MF2_MASK, VSOXEI8_V }, // 6509
  { PseudoVSOXEI8_V_MF4_MF4, VSOXEI8_V }, // 6510
  { PseudoVSOXEI8_V_MF4_MF4_MASK, VSOXEI8_V }, // 6511
  { PseudoVSOXEI8_V_MF8_M1, VSOXEI8_V }, // 6512
  { PseudoVSOXEI8_V_MF8_M1_MASK, VSOXEI8_V }, // 6513
  { PseudoVSOXEI8_V_MF8_MF2, VSOXEI8_V }, // 6514
  { PseudoVSOXEI8_V_MF8_MF2_MASK, VSOXEI8_V }, // 6515
  { PseudoVSOXEI8_V_MF8_MF4, VSOXEI8_V }, // 6516
  { PseudoVSOXEI8_V_MF8_MF4_MASK, VSOXEI8_V }, // 6517
  { PseudoVSOXEI8_V_MF8_MF8, VSOXEI8_V }, // 6518
  { PseudoVSOXEI8_V_MF8_MF8_MASK, VSOXEI8_V }, // 6519
  { PseudoVSOXSEG2EI16_V_M1_M1, VSOXSEG2EI16_V }, // 6520
  { PseudoVSOXSEG2EI16_V_M1_M1_MASK, VSOXSEG2EI16_V }, // 6521
  { PseudoVSOXSEG2EI16_V_M1_M2, VSOXSEG2EI16_V }, // 6522
  { PseudoVSOXSEG2EI16_V_M1_M2_MASK, VSOXSEG2EI16_V }, // 6523
  { PseudoVSOXSEG2EI16_V_M1_M4, VSOXSEG2EI16_V }, // 6524
  { PseudoVSOXSEG2EI16_V_M1_M4_MASK, VSOXSEG2EI16_V }, // 6525
  { PseudoVSOXSEG2EI16_V_M1_MF2, VSOXSEG2EI16_V }, // 6526
  { PseudoVSOXSEG2EI16_V_M1_MF2_MASK, VSOXSEG2EI16_V }, // 6527
  { PseudoVSOXSEG2EI16_V_M2_M1, VSOXSEG2EI16_V }, // 6528
  { PseudoVSOXSEG2EI16_V_M2_M1_MASK, VSOXSEG2EI16_V }, // 6529
  { PseudoVSOXSEG2EI16_V_M2_M2, VSOXSEG2EI16_V }, // 6530
  { PseudoVSOXSEG2EI16_V_M2_M2_MASK, VSOXSEG2EI16_V }, // 6531
  { PseudoVSOXSEG2EI16_V_M2_M4, VSOXSEG2EI16_V }, // 6532
  { PseudoVSOXSEG2EI16_V_M2_M4_MASK, VSOXSEG2EI16_V }, // 6533
  { PseudoVSOXSEG2EI16_V_M4_M2, VSOXSEG2EI16_V }, // 6534
  { PseudoVSOXSEG2EI16_V_M4_M2_MASK, VSOXSEG2EI16_V }, // 6535
  { PseudoVSOXSEG2EI16_V_M4_M4, VSOXSEG2EI16_V }, // 6536
  { PseudoVSOXSEG2EI16_V_M4_M4_MASK, VSOXSEG2EI16_V }, // 6537
  { PseudoVSOXSEG2EI16_V_M8_M4, VSOXSEG2EI16_V }, // 6538
  { PseudoVSOXSEG2EI16_V_M8_M4_MASK, VSOXSEG2EI16_V }, // 6539
  { PseudoVSOXSEG2EI16_V_MF2_M1, VSOXSEG2EI16_V }, // 6540
  { PseudoVSOXSEG2EI16_V_MF2_M1_MASK, VSOXSEG2EI16_V }, // 6541
  { PseudoVSOXSEG2EI16_V_MF2_M2, VSOXSEG2EI16_V }, // 6542
  { PseudoVSOXSEG2EI16_V_MF2_M2_MASK, VSOXSEG2EI16_V }, // 6543
  { PseudoVSOXSEG2EI16_V_MF2_MF2, VSOXSEG2EI16_V }, // 6544
  { PseudoVSOXSEG2EI16_V_MF2_MF2_MASK, VSOXSEG2EI16_V }, // 6545
  { PseudoVSOXSEG2EI16_V_MF2_MF4, VSOXSEG2EI16_V }, // 6546
  { PseudoVSOXSEG2EI16_V_MF2_MF4_MASK, VSOXSEG2EI16_V }, // 6547
  { PseudoVSOXSEG2EI16_V_MF4_M1, VSOXSEG2EI16_V }, // 6548
  { PseudoVSOXSEG2EI16_V_MF4_M1_MASK, VSOXSEG2EI16_V }, // 6549
  { PseudoVSOXSEG2EI16_V_MF4_MF2, VSOXSEG2EI16_V }, // 6550
  { PseudoVSOXSEG2EI16_V_MF4_MF2_MASK, VSOXSEG2EI16_V }, // 6551
  { PseudoVSOXSEG2EI16_V_MF4_MF4, VSOXSEG2EI16_V }, // 6552
  { PseudoVSOXSEG2EI16_V_MF4_MF4_MASK, VSOXSEG2EI16_V }, // 6553
  { PseudoVSOXSEG2EI16_V_MF4_MF8, VSOXSEG2EI16_V }, // 6554
  { PseudoVSOXSEG2EI16_V_MF4_MF8_MASK, VSOXSEG2EI16_V }, // 6555
  { PseudoVSOXSEG2EI32_V_M1_M1, VSOXSEG2EI32_V }, // 6556
  { PseudoVSOXSEG2EI32_V_M1_M1_MASK, VSOXSEG2EI32_V }, // 6557
  { PseudoVSOXSEG2EI32_V_M1_M2, VSOXSEG2EI32_V }, // 6558
  { PseudoVSOXSEG2EI32_V_M1_M2_MASK, VSOXSEG2EI32_V }, // 6559
  { PseudoVSOXSEG2EI32_V_M1_MF2, VSOXSEG2EI32_V }, // 6560
  { PseudoVSOXSEG2EI32_V_M1_MF2_MASK, VSOXSEG2EI32_V }, // 6561
  { PseudoVSOXSEG2EI32_V_M1_MF4, VSOXSEG2EI32_V }, // 6562
  { PseudoVSOXSEG2EI32_V_M1_MF4_MASK, VSOXSEG2EI32_V }, // 6563
  { PseudoVSOXSEG2EI32_V_M2_M1, VSOXSEG2EI32_V }, // 6564
  { PseudoVSOXSEG2EI32_V_M2_M1_MASK, VSOXSEG2EI32_V }, // 6565
  { PseudoVSOXSEG2EI32_V_M2_M2, VSOXSEG2EI32_V }, // 6566
  { PseudoVSOXSEG2EI32_V_M2_M2_MASK, VSOXSEG2EI32_V }, // 6567
  { PseudoVSOXSEG2EI32_V_M2_M4, VSOXSEG2EI32_V }, // 6568
  { PseudoVSOXSEG2EI32_V_M2_M4_MASK, VSOXSEG2EI32_V }, // 6569
  { PseudoVSOXSEG2EI32_V_M2_MF2, VSOXSEG2EI32_V }, // 6570
  { PseudoVSOXSEG2EI32_V_M2_MF2_MASK, VSOXSEG2EI32_V }, // 6571
  { PseudoVSOXSEG2EI32_V_M4_M1, VSOXSEG2EI32_V }, // 6572
  { PseudoVSOXSEG2EI32_V_M4_M1_MASK, VSOXSEG2EI32_V }, // 6573
  { PseudoVSOXSEG2EI32_V_M4_M2, VSOXSEG2EI32_V }, // 6574
  { PseudoVSOXSEG2EI32_V_M4_M2_MASK, VSOXSEG2EI32_V }, // 6575
  { PseudoVSOXSEG2EI32_V_M4_M4, VSOXSEG2EI32_V }, // 6576
  { PseudoVSOXSEG2EI32_V_M4_M4_MASK, VSOXSEG2EI32_V }, // 6577
  { PseudoVSOXSEG2EI32_V_M8_M2, VSOXSEG2EI32_V }, // 6578
  { PseudoVSOXSEG2EI32_V_M8_M2_MASK, VSOXSEG2EI32_V }, // 6579
  { PseudoVSOXSEG2EI32_V_M8_M4, VSOXSEG2EI32_V }, // 6580
  { PseudoVSOXSEG2EI32_V_M8_M4_MASK, VSOXSEG2EI32_V }, // 6581
  { PseudoVSOXSEG2EI32_V_MF2_M1, VSOXSEG2EI32_V }, // 6582
  { PseudoVSOXSEG2EI32_V_MF2_M1_MASK, VSOXSEG2EI32_V }, // 6583
  { PseudoVSOXSEG2EI32_V_MF2_MF2, VSOXSEG2EI32_V }, // 6584
  { PseudoVSOXSEG2EI32_V_MF2_MF2_MASK, VSOXSEG2EI32_V }, // 6585
  { PseudoVSOXSEG2EI32_V_MF2_MF4, VSOXSEG2EI32_V }, // 6586
  { PseudoVSOXSEG2EI32_V_MF2_MF4_MASK, VSOXSEG2EI32_V }, // 6587
  { PseudoVSOXSEG2EI32_V_MF2_MF8, VSOXSEG2EI32_V }, // 6588
  { PseudoVSOXSEG2EI32_V_MF2_MF8_MASK, VSOXSEG2EI32_V }, // 6589
  { PseudoVSOXSEG2EI64_V_M1_M1, VSOXSEG2EI64_V }, // 6590
  { PseudoVSOXSEG2EI64_V_M1_M1_MASK, VSOXSEG2EI64_V }, // 6591
  { PseudoVSOXSEG2EI64_V_M1_MF2, VSOXSEG2EI64_V }, // 6592
  { PseudoVSOXSEG2EI64_V_M1_MF2_MASK, VSOXSEG2EI64_V }, // 6593
  { PseudoVSOXSEG2EI64_V_M1_MF4, VSOXSEG2EI64_V }, // 6594
  { PseudoVSOXSEG2EI64_V_M1_MF4_MASK, VSOXSEG2EI64_V }, // 6595
  { PseudoVSOXSEG2EI64_V_M1_MF8, VSOXSEG2EI64_V }, // 6596
  { PseudoVSOXSEG2EI64_V_M1_MF8_MASK, VSOXSEG2EI64_V }, // 6597
  { PseudoVSOXSEG2EI64_V_M2_M1, VSOXSEG2EI64_V }, // 6598
  { PseudoVSOXSEG2EI64_V_M2_M1_MASK, VSOXSEG2EI64_V }, // 6599
  { PseudoVSOXSEG2EI64_V_M2_M2, VSOXSEG2EI64_V }, // 6600
  { PseudoVSOXSEG2EI64_V_M2_M2_MASK, VSOXSEG2EI64_V }, // 6601
  { PseudoVSOXSEG2EI64_V_M2_MF2, VSOXSEG2EI64_V }, // 6602
  { PseudoVSOXSEG2EI64_V_M2_MF2_MASK, VSOXSEG2EI64_V }, // 6603
  { PseudoVSOXSEG2EI64_V_M2_MF4, VSOXSEG2EI64_V }, // 6604
  { PseudoVSOXSEG2EI64_V_M2_MF4_MASK, VSOXSEG2EI64_V }, // 6605
  { PseudoVSOXSEG2EI64_V_M4_M1, VSOXSEG2EI64_V }, // 6606
  { PseudoVSOXSEG2EI64_V_M4_M1_MASK, VSOXSEG2EI64_V }, // 6607
  { PseudoVSOXSEG2EI64_V_M4_M2, VSOXSEG2EI64_V }, // 6608
  { PseudoVSOXSEG2EI64_V_M4_M2_MASK, VSOXSEG2EI64_V }, // 6609
  { PseudoVSOXSEG2EI64_V_M4_M4, VSOXSEG2EI64_V }, // 6610
  { PseudoVSOXSEG2EI64_V_M4_M4_MASK, VSOXSEG2EI64_V }, // 6611
  { PseudoVSOXSEG2EI64_V_M4_MF2, VSOXSEG2EI64_V }, // 6612
  { PseudoVSOXSEG2EI64_V_M4_MF2_MASK, VSOXSEG2EI64_V }, // 6613
  { PseudoVSOXSEG2EI64_V_M8_M1, VSOXSEG2EI64_V }, // 6614
  { PseudoVSOXSEG2EI64_V_M8_M1_MASK, VSOXSEG2EI64_V }, // 6615
  { PseudoVSOXSEG2EI64_V_M8_M2, VSOXSEG2EI64_V }, // 6616
  { PseudoVSOXSEG2EI64_V_M8_M2_MASK, VSOXSEG2EI64_V }, // 6617
  { PseudoVSOXSEG2EI64_V_M8_M4, VSOXSEG2EI64_V }, // 6618
  { PseudoVSOXSEG2EI64_V_M8_M4_MASK, VSOXSEG2EI64_V }, // 6619
  { PseudoVSOXSEG2EI8_V_M1_M1, VSOXSEG2EI8_V }, // 6620
  { PseudoVSOXSEG2EI8_V_M1_M1_MASK, VSOXSEG2EI8_V }, // 6621
  { PseudoVSOXSEG2EI8_V_M1_M2, VSOXSEG2EI8_V }, // 6622
  { PseudoVSOXSEG2EI8_V_M1_M2_MASK, VSOXSEG2EI8_V }, // 6623
  { PseudoVSOXSEG2EI8_V_M1_M4, VSOXSEG2EI8_V }, // 6624
  { PseudoVSOXSEG2EI8_V_M1_M4_MASK, VSOXSEG2EI8_V }, // 6625
  { PseudoVSOXSEG2EI8_V_M2_M2, VSOXSEG2EI8_V }, // 6626
  { PseudoVSOXSEG2EI8_V_M2_M2_MASK, VSOXSEG2EI8_V }, // 6627
  { PseudoVSOXSEG2EI8_V_M2_M4, VSOXSEG2EI8_V }, // 6628
  { PseudoVSOXSEG2EI8_V_M2_M4_MASK, VSOXSEG2EI8_V }, // 6629
  { PseudoVSOXSEG2EI8_V_M4_M4, VSOXSEG2EI8_V }, // 6630
  { PseudoVSOXSEG2EI8_V_M4_M4_MASK, VSOXSEG2EI8_V }, // 6631
  { PseudoVSOXSEG2EI8_V_MF2_M1, VSOXSEG2EI8_V }, // 6632
  { PseudoVSOXSEG2EI8_V_MF2_M1_MASK, VSOXSEG2EI8_V }, // 6633
  { PseudoVSOXSEG2EI8_V_MF2_M2, VSOXSEG2EI8_V }, // 6634
  { PseudoVSOXSEG2EI8_V_MF2_M2_MASK, VSOXSEG2EI8_V }, // 6635
  { PseudoVSOXSEG2EI8_V_MF2_M4, VSOXSEG2EI8_V }, // 6636
  { PseudoVSOXSEG2EI8_V_MF2_M4_MASK, VSOXSEG2EI8_V }, // 6637
  { PseudoVSOXSEG2EI8_V_MF2_MF2, VSOXSEG2EI8_V }, // 6638
  { PseudoVSOXSEG2EI8_V_MF2_MF2_MASK, VSOXSEG2EI8_V }, // 6639
  { PseudoVSOXSEG2EI8_V_MF4_M1, VSOXSEG2EI8_V }, // 6640
  { PseudoVSOXSEG2EI8_V_MF4_M1_MASK, VSOXSEG2EI8_V }, // 6641
  { PseudoVSOXSEG2EI8_V_MF4_M2, VSOXSEG2EI8_V }, // 6642
  { PseudoVSOXSEG2EI8_V_MF4_M2_MASK, VSOXSEG2EI8_V }, // 6643
  { PseudoVSOXSEG2EI8_V_MF4_MF2, VSOXSEG2EI8_V }, // 6644
  { PseudoVSOXSEG2EI8_V_MF4_MF2_MASK, VSOXSEG2EI8_V }, // 6645
  { PseudoVSOXSEG2EI8_V_MF4_MF4, VSOXSEG2EI8_V }, // 6646
  { PseudoVSOXSEG2EI8_V_MF4_MF4_MASK, VSOXSEG2EI8_V }, // 6647
  { PseudoVSOXSEG2EI8_V_MF8_M1, VSOXSEG2EI8_V }, // 6648
  { PseudoVSOXSEG2EI8_V_MF8_M1_MASK, VSOXSEG2EI8_V }, // 6649
  { PseudoVSOXSEG2EI8_V_MF8_MF2, VSOXSEG2EI8_V }, // 6650
  { PseudoVSOXSEG2EI8_V_MF8_MF2_MASK, VSOXSEG2EI8_V }, // 6651
  { PseudoVSOXSEG2EI8_V_MF8_MF4, VSOXSEG2EI8_V }, // 6652
  { PseudoVSOXSEG2EI8_V_MF8_MF4_MASK, VSOXSEG2EI8_V }, // 6653
  { PseudoVSOXSEG2EI8_V_MF8_MF8, VSOXSEG2EI8_V }, // 6654
  { PseudoVSOXSEG2EI8_V_MF8_MF8_MASK, VSOXSEG2EI8_V }, // 6655
  { PseudoVSOXSEG3EI16_V_M1_M1, VSOXSEG3EI16_V }, // 6656
  { PseudoVSOXSEG3EI16_V_M1_M1_MASK, VSOXSEG3EI16_V }, // 6657
  { PseudoVSOXSEG3EI16_V_M1_M2, VSOXSEG3EI16_V }, // 6658
  { PseudoVSOXSEG3EI16_V_M1_M2_MASK, VSOXSEG3EI16_V }, // 6659
  { PseudoVSOXSEG3EI16_V_M1_MF2, VSOXSEG3EI16_V }, // 6660
  { PseudoVSOXSEG3EI16_V_M1_MF2_MASK, VSOXSEG3EI16_V }, // 6661
  { PseudoVSOXSEG3EI16_V_M2_M1, VSOXSEG3EI16_V }, // 6662
  { PseudoVSOXSEG3EI16_V_M2_M1_MASK, VSOXSEG3EI16_V }, // 6663
  { PseudoVSOXSEG3EI16_V_M2_M2, VSOXSEG3EI16_V }, // 6664
  { PseudoVSOXSEG3EI16_V_M2_M2_MASK, VSOXSEG3EI16_V }, // 6665
  { PseudoVSOXSEG3EI16_V_M4_M2, VSOXSEG3EI16_V }, // 6666
  { PseudoVSOXSEG3EI16_V_M4_M2_MASK, VSOXSEG3EI16_V }, // 6667
  { PseudoVSOXSEG3EI16_V_MF2_M1, VSOXSEG3EI16_V }, // 6668
  { PseudoVSOXSEG3EI16_V_MF2_M1_MASK, VSOXSEG3EI16_V }, // 6669
  { PseudoVSOXSEG3EI16_V_MF2_M2, VSOXSEG3EI16_V }, // 6670
  { PseudoVSOXSEG3EI16_V_MF2_M2_MASK, VSOXSEG3EI16_V }, // 6671
  { PseudoVSOXSEG3EI16_V_MF2_MF2, VSOXSEG3EI16_V }, // 6672
  { PseudoVSOXSEG3EI16_V_MF2_MF2_MASK, VSOXSEG3EI16_V }, // 6673
  { PseudoVSOXSEG3EI16_V_MF2_MF4, VSOXSEG3EI16_V }, // 6674
  { PseudoVSOXSEG3EI16_V_MF2_MF4_MASK, VSOXSEG3EI16_V }, // 6675
  { PseudoVSOXSEG3EI16_V_MF4_M1, VSOXSEG3EI16_V }, // 6676
  { PseudoVSOXSEG3EI16_V_MF4_M1_MASK, VSOXSEG3EI16_V }, // 6677
  { PseudoVSOXSEG3EI16_V_MF4_MF2, VSOXSEG3EI16_V }, // 6678
  { PseudoVSOXSEG3EI16_V_MF4_MF2_MASK, VSOXSEG3EI16_V }, // 6679
  { PseudoVSOXSEG3EI16_V_MF4_MF4, VSOXSEG3EI16_V }, // 6680
  { PseudoVSOXSEG3EI16_V_MF4_MF4_MASK, VSOXSEG3EI16_V }, // 6681
  { PseudoVSOXSEG3EI16_V_MF4_MF8, VSOXSEG3EI16_V }, // 6682
  { PseudoVSOXSEG3EI16_V_MF4_MF8_MASK, VSOXSEG3EI16_V }, // 6683
  { PseudoVSOXSEG3EI32_V_M1_M1, VSOXSEG3EI32_V }, // 6684
  { PseudoVSOXSEG3EI32_V_M1_M1_MASK, VSOXSEG3EI32_V }, // 6685
  { PseudoVSOXSEG3EI32_V_M1_M2, VSOXSEG3EI32_V }, // 6686
  { PseudoVSOXSEG3EI32_V_M1_M2_MASK, VSOXSEG3EI32_V }, // 6687
  { PseudoVSOXSEG3EI32_V_M1_MF2, VSOXSEG3EI32_V }, // 6688
  { PseudoVSOXSEG3EI32_V_M1_MF2_MASK, VSOXSEG3EI32_V }, // 6689
  { PseudoVSOXSEG3EI32_V_M1_MF4, VSOXSEG3EI32_V }, // 6690
  { PseudoVSOXSEG3EI32_V_M1_MF4_MASK, VSOXSEG3EI32_V }, // 6691
  { PseudoVSOXSEG3EI32_V_M2_M1, VSOXSEG3EI32_V }, // 6692
  { PseudoVSOXSEG3EI32_V_M2_M1_MASK, VSOXSEG3EI32_V }, // 6693
  { PseudoVSOXSEG3EI32_V_M2_M2, VSOXSEG3EI32_V }, // 6694
  { PseudoVSOXSEG3EI32_V_M2_M2_MASK, VSOXSEG3EI32_V }, // 6695
  { PseudoVSOXSEG3EI32_V_M2_MF2, VSOXSEG3EI32_V }, // 6696
  { PseudoVSOXSEG3EI32_V_M2_MF2_MASK, VSOXSEG3EI32_V }, // 6697
  { PseudoVSOXSEG3EI32_V_M4_M1, VSOXSEG3EI32_V }, // 6698
  { PseudoVSOXSEG3EI32_V_M4_M1_MASK, VSOXSEG3EI32_V }, // 6699
  { PseudoVSOXSEG3EI32_V_M4_M2, VSOXSEG3EI32_V }, // 6700
  { PseudoVSOXSEG3EI32_V_M4_M2_MASK, VSOXSEG3EI32_V }, // 6701
  { PseudoVSOXSEG3EI32_V_M8_M2, VSOXSEG3EI32_V }, // 6702
  { PseudoVSOXSEG3EI32_V_M8_M2_MASK, VSOXSEG3EI32_V }, // 6703
  { PseudoVSOXSEG3EI32_V_MF2_M1, VSOXSEG3EI32_V }, // 6704
  { PseudoVSOXSEG3EI32_V_MF2_M1_MASK, VSOXSEG3EI32_V }, // 6705
  { PseudoVSOXSEG3EI32_V_MF2_MF2, VSOXSEG3EI32_V }, // 6706
  { PseudoVSOXSEG3EI32_V_MF2_MF2_MASK, VSOXSEG3EI32_V }, // 6707
  { PseudoVSOXSEG3EI32_V_MF2_MF4, VSOXSEG3EI32_V }, // 6708
  { PseudoVSOXSEG3EI32_V_MF2_MF4_MASK, VSOXSEG3EI32_V }, // 6709
  { PseudoVSOXSEG3EI32_V_MF2_MF8, VSOXSEG3EI32_V }, // 6710
  { PseudoVSOXSEG3EI32_V_MF2_MF8_MASK, VSOXSEG3EI32_V }, // 6711
  { PseudoVSOXSEG3EI64_V_M1_M1, VSOXSEG3EI64_V }, // 6712
  { PseudoVSOXSEG3EI64_V_M1_M1_MASK, VSOXSEG3EI64_V }, // 6713
  { PseudoVSOXSEG3EI64_V_M1_MF2, VSOXSEG3EI64_V }, // 6714
  { PseudoVSOXSEG3EI64_V_M1_MF2_MASK, VSOXSEG3EI64_V }, // 6715
  { PseudoVSOXSEG3EI64_V_M1_MF4, VSOXSEG3EI64_V }, // 6716
  { PseudoVSOXSEG3EI64_V_M1_MF4_MASK, VSOXSEG3EI64_V }, // 6717
  { PseudoVSOXSEG3EI64_V_M1_MF8, VSOXSEG3EI64_V }, // 6718
  { PseudoVSOXSEG3EI64_V_M1_MF8_MASK, VSOXSEG3EI64_V }, // 6719
  { PseudoVSOXSEG3EI64_V_M2_M1, VSOXSEG3EI64_V }, // 6720
  { PseudoVSOXSEG3EI64_V_M2_M1_MASK, VSOXSEG3EI64_V }, // 6721
  { PseudoVSOXSEG3EI64_V_M2_M2, VSOXSEG3EI64_V }, // 6722
  { PseudoVSOXSEG3EI64_V_M2_M2_MASK, VSOXSEG3EI64_V }, // 6723
  { PseudoVSOXSEG3EI64_V_M2_MF2, VSOXSEG3EI64_V }, // 6724
  { PseudoVSOXSEG3EI64_V_M2_MF2_MASK, VSOXSEG3EI64_V }, // 6725
  { PseudoVSOXSEG3EI64_V_M2_MF4, VSOXSEG3EI64_V }, // 6726
  { PseudoVSOXSEG3EI64_V_M2_MF4_MASK, VSOXSEG3EI64_V }, // 6727
  { PseudoVSOXSEG3EI64_V_M4_M1, VSOXSEG3EI64_V }, // 6728
  { PseudoVSOXSEG3EI64_V_M4_M1_MASK, VSOXSEG3EI64_V }, // 6729
  { PseudoVSOXSEG3EI64_V_M4_M2, VSOXSEG3EI64_V }, // 6730
  { PseudoVSOXSEG3EI64_V_M4_M2_MASK, VSOXSEG3EI64_V }, // 6731
  { PseudoVSOXSEG3EI64_V_M4_MF2, VSOXSEG3EI64_V }, // 6732
  { PseudoVSOXSEG3EI64_V_M4_MF2_MASK, VSOXSEG3EI64_V }, // 6733
  { PseudoVSOXSEG3EI64_V_M8_M1, VSOXSEG3EI64_V }, // 6734
  { PseudoVSOXSEG3EI64_V_M8_M1_MASK, VSOXSEG3EI64_V }, // 6735
  { PseudoVSOXSEG3EI64_V_M8_M2, VSOXSEG3EI64_V }, // 6736
  { PseudoVSOXSEG3EI64_V_M8_M2_MASK, VSOXSEG3EI64_V }, // 6737
  { PseudoVSOXSEG3EI8_V_M1_M1, VSOXSEG3EI8_V }, // 6738
  { PseudoVSOXSEG3EI8_V_M1_M1_MASK, VSOXSEG3EI8_V }, // 6739
  { PseudoVSOXSEG3EI8_V_M1_M2, VSOXSEG3EI8_V }, // 6740
  { PseudoVSOXSEG3EI8_V_M1_M2_MASK, VSOXSEG3EI8_V }, // 6741
  { PseudoVSOXSEG3EI8_V_M2_M2, VSOXSEG3EI8_V }, // 6742
  { PseudoVSOXSEG3EI8_V_M2_M2_MASK, VSOXSEG3EI8_V }, // 6743
  { PseudoVSOXSEG3EI8_V_MF2_M1, VSOXSEG3EI8_V }, // 6744
  { PseudoVSOXSEG3EI8_V_MF2_M1_MASK, VSOXSEG3EI8_V }, // 6745
  { PseudoVSOXSEG3EI8_V_MF2_M2, VSOXSEG3EI8_V }, // 6746
  { PseudoVSOXSEG3EI8_V_MF2_M2_MASK, VSOXSEG3EI8_V }, // 6747
  { PseudoVSOXSEG3EI8_V_MF2_MF2, VSOXSEG3EI8_V }, // 6748
  { PseudoVSOXSEG3EI8_V_MF2_MF2_MASK, VSOXSEG3EI8_V }, // 6749
  { PseudoVSOXSEG3EI8_V_MF4_M1, VSOXSEG3EI8_V }, // 6750
  { PseudoVSOXSEG3EI8_V_MF4_M1_MASK, VSOXSEG3EI8_V }, // 6751
  { PseudoVSOXSEG3EI8_V_MF4_M2, VSOXSEG3EI8_V }, // 6752
  { PseudoVSOXSEG3EI8_V_MF4_M2_MASK, VSOXSEG3EI8_V }, // 6753
  { PseudoVSOXSEG3EI8_V_MF4_MF2, VSOXSEG3EI8_V }, // 6754
  { PseudoVSOXSEG3EI8_V_MF4_MF2_MASK, VSOXSEG3EI8_V }, // 6755
  { PseudoVSOXSEG3EI8_V_MF4_MF4, VSOXSEG3EI8_V }, // 6756
  { PseudoVSOXSEG3EI8_V_MF4_MF4_MASK, VSOXSEG3EI8_V }, // 6757
  { PseudoVSOXSEG3EI8_V_MF8_M1, VSOXSEG3EI8_V }, // 6758
  { PseudoVSOXSEG3EI8_V_MF8_M1_MASK, VSOXSEG3EI8_V }, // 6759
  { PseudoVSOXSEG3EI8_V_MF8_MF2, VSOXSEG3EI8_V }, // 6760
  { PseudoVSOXSEG3EI8_V_MF8_MF2_MASK, VSOXSEG3EI8_V }, // 6761
  { PseudoVSOXSEG3EI8_V_MF8_MF4, VSOXSEG3EI8_V }, // 6762
  { PseudoVSOXSEG3EI8_V_MF8_MF4_MASK, VSOXSEG3EI8_V }, // 6763
  { PseudoVSOXSEG3EI8_V_MF8_MF8, VSOXSEG3EI8_V }, // 6764
  { PseudoVSOXSEG3EI8_V_MF8_MF8_MASK, VSOXSEG3EI8_V }, // 6765
  { PseudoVSOXSEG4EI16_V_M1_M1, VSOXSEG4EI16_V }, // 6766
  { PseudoVSOXSEG4EI16_V_M1_M1_MASK, VSOXSEG4EI16_V }, // 6767
  { PseudoVSOXSEG4EI16_V_M1_M2, VSOXSEG4EI16_V }, // 6768
  { PseudoVSOXSEG4EI16_V_M1_M2_MASK, VSOXSEG4EI16_V }, // 6769
  { PseudoVSOXSEG4EI16_V_M1_MF2, VSOXSEG4EI16_V }, // 6770
  { PseudoVSOXSEG4EI16_V_M1_MF2_MASK, VSOXSEG4EI16_V }, // 6771
  { PseudoVSOXSEG4EI16_V_M2_M1, VSOXSEG4EI16_V }, // 6772
  { PseudoVSOXSEG4EI16_V_M2_M1_MASK, VSOXSEG4EI16_V }, // 6773
  { PseudoVSOXSEG4EI16_V_M2_M2, VSOXSEG4EI16_V }, // 6774
  { PseudoVSOXSEG4EI16_V_M2_M2_MASK, VSOXSEG4EI16_V }, // 6775
  { PseudoVSOXSEG4EI16_V_M4_M2, VSOXSEG4EI16_V }, // 6776
  { PseudoVSOXSEG4EI16_V_M4_M2_MASK, VSOXSEG4EI16_V }, // 6777
  { PseudoVSOXSEG4EI16_V_MF2_M1, VSOXSEG4EI16_V }, // 6778
  { PseudoVSOXSEG4EI16_V_MF2_M1_MASK, VSOXSEG4EI16_V }, // 6779
  { PseudoVSOXSEG4EI16_V_MF2_M2, VSOXSEG4EI16_V }, // 6780
  { PseudoVSOXSEG4EI16_V_MF2_M2_MASK, VSOXSEG4EI16_V }, // 6781
  { PseudoVSOXSEG4EI16_V_MF2_MF2, VSOXSEG4EI16_V }, // 6782
  { PseudoVSOXSEG4EI16_V_MF2_MF2_MASK, VSOXSEG4EI16_V }, // 6783
  { PseudoVSOXSEG4EI16_V_MF2_MF4, VSOXSEG4EI16_V }, // 6784
  { PseudoVSOXSEG4EI16_V_MF2_MF4_MASK, VSOXSEG4EI16_V }, // 6785
  { PseudoVSOXSEG4EI16_V_MF4_M1, VSOXSEG4EI16_V }, // 6786
  { PseudoVSOXSEG4EI16_V_MF4_M1_MASK, VSOXSEG4EI16_V }, // 6787
  { PseudoVSOXSEG4EI16_V_MF4_MF2, VSOXSEG4EI16_V }, // 6788
  { PseudoVSOXSEG4EI16_V_MF4_MF2_MASK, VSOXSEG4EI16_V }, // 6789
  { PseudoVSOXSEG4EI16_V_MF4_MF4, VSOXSEG4EI16_V }, // 6790
  { PseudoVSOXSEG4EI16_V_MF4_MF4_MASK, VSOXSEG4EI16_V }, // 6791
  { PseudoVSOXSEG4EI16_V_MF4_MF8, VSOXSEG4EI16_V }, // 6792
  { PseudoVSOXSEG4EI16_V_MF4_MF8_MASK, VSOXSEG4EI16_V }, // 6793
  { PseudoVSOXSEG4EI32_V_M1_M1, VSOXSEG4EI32_V }, // 6794
  { PseudoVSOXSEG4EI32_V_M1_M1_MASK, VSOXSEG4EI32_V }, // 6795
  { PseudoVSOXSEG4EI32_V_M1_M2, VSOXSEG4EI32_V }, // 6796
  { PseudoVSOXSEG4EI32_V_M1_M2_MASK, VSOXSEG4EI32_V }, // 6797
  { PseudoVSOXSEG4EI32_V_M1_MF2, VSOXSEG4EI32_V }, // 6798
  { PseudoVSOXSEG4EI32_V_M1_MF2_MASK, VSOXSEG4EI32_V }, // 6799
  { PseudoVSOXSEG4EI32_V_M1_MF4, VSOXSEG4EI32_V }, // 6800
  { PseudoVSOXSEG4EI32_V_M1_MF4_MASK, VSOXSEG4EI32_V }, // 6801
  { PseudoVSOXSEG4EI32_V_M2_M1, VSOXSEG4EI32_V }, // 6802
  { PseudoVSOXSEG4EI32_V_M2_M1_MASK, VSOXSEG4EI32_V }, // 6803
  { PseudoVSOXSEG4EI32_V_M2_M2, VSOXSEG4EI32_V }, // 6804
  { PseudoVSOXSEG4EI32_V_M2_M2_MASK, VSOXSEG4EI32_V }, // 6805
  { PseudoVSOXSEG4EI32_V_M2_MF2, VSOXSEG4EI32_V }, // 6806
  { PseudoVSOXSEG4EI32_V_M2_MF2_MASK, VSOXSEG4EI32_V }, // 6807
  { PseudoVSOXSEG4EI32_V_M4_M1, VSOXSEG4EI32_V }, // 6808
  { PseudoVSOXSEG4EI32_V_M4_M1_MASK, VSOXSEG4EI32_V }, // 6809
  { PseudoVSOXSEG4EI32_V_M4_M2, VSOXSEG4EI32_V }, // 6810
  { PseudoVSOXSEG4EI32_V_M4_M2_MASK, VSOXSEG4EI32_V }, // 6811
  { PseudoVSOXSEG4EI32_V_M8_M2, VSOXSEG4EI32_V }, // 6812
  { PseudoVSOXSEG4EI32_V_M8_M2_MASK, VSOXSEG4EI32_V }, // 6813
  { PseudoVSOXSEG4EI32_V_MF2_M1, VSOXSEG4EI32_V }, // 6814
  { PseudoVSOXSEG4EI32_V_MF2_M1_MASK, VSOXSEG4EI32_V }, // 6815
  { PseudoVSOXSEG4EI32_V_MF2_MF2, VSOXSEG4EI32_V }, // 6816
  { PseudoVSOXSEG4EI32_V_MF2_MF2_MASK, VSOXSEG4EI32_V }, // 6817
  { PseudoVSOXSEG4EI32_V_MF2_MF4, VSOXSEG4EI32_V }, // 6818
  { PseudoVSOXSEG4EI32_V_MF2_MF4_MASK, VSOXSEG4EI32_V }, // 6819
  { PseudoVSOXSEG4EI32_V_MF2_MF8, VSOXSEG4EI32_V }, // 6820
  { PseudoVSOXSEG4EI32_V_MF2_MF8_MASK, VSOXSEG4EI32_V }, // 6821
  { PseudoVSOXSEG4EI64_V_M1_M1, VSOXSEG4EI64_V }, // 6822
  { PseudoVSOXSEG4EI64_V_M1_M1_MASK, VSOXSEG4EI64_V }, // 6823
  { PseudoVSOXSEG4EI64_V_M1_MF2, VSOXSEG4EI64_V }, // 6824
  { PseudoVSOXSEG4EI64_V_M1_MF2_MASK, VSOXSEG4EI64_V }, // 6825
  { PseudoVSOXSEG4EI64_V_M1_MF4, VSOXSEG4EI64_V }, // 6826
  { PseudoVSOXSEG4EI64_V_M1_MF4_MASK, VSOXSEG4EI64_V }, // 6827
  { PseudoVSOXSEG4EI64_V_M1_MF8, VSOXSEG4EI64_V }, // 6828
  { PseudoVSOXSEG4EI64_V_M1_MF8_MASK, VSOXSEG4EI64_V }, // 6829
  { PseudoVSOXSEG4EI64_V_M2_M1, VSOXSEG4EI64_V }, // 6830
  { PseudoVSOXSEG4EI64_V_M2_M1_MASK, VSOXSEG4EI64_V }, // 6831
  { PseudoVSOXSEG4EI64_V_M2_M2, VSOXSEG4EI64_V }, // 6832
  { PseudoVSOXSEG4EI64_V_M2_M2_MASK, VSOXSEG4EI64_V }, // 6833
  { PseudoVSOXSEG4EI64_V_M2_MF2, VSOXSEG4EI64_V }, // 6834
  { PseudoVSOXSEG4EI64_V_M2_MF2_MASK, VSOXSEG4EI64_V }, // 6835
  { PseudoVSOXSEG4EI64_V_M2_MF4, VSOXSEG4EI64_V }, // 6836
  { PseudoVSOXSEG4EI64_V_M2_MF4_MASK, VSOXSEG4EI64_V }, // 6837
  { PseudoVSOXSEG4EI64_V_M4_M1, VSOXSEG4EI64_V }, // 6838
  { PseudoVSOXSEG4EI64_V_M4_M1_MASK, VSOXSEG4EI64_V }, // 6839
  { PseudoVSOXSEG4EI64_V_M4_M2, VSOXSEG4EI64_V }, // 6840
  { PseudoVSOXSEG4EI64_V_M4_M2_MASK, VSOXSEG4EI64_V }, // 6841
  { PseudoVSOXSEG4EI64_V_M4_MF2, VSOXSEG4EI64_V }, // 6842
  { PseudoVSOXSEG4EI64_V_M4_MF2_MASK, VSOXSEG4EI64_V }, // 6843
  { PseudoVSOXSEG4EI64_V_M8_M1, VSOXSEG4EI64_V }, // 6844
  { PseudoVSOXSEG4EI64_V_M8_M1_MASK, VSOXSEG4EI64_V }, // 6845
  { PseudoVSOXSEG4EI64_V_M8_M2, VSOXSEG4EI64_V }, // 6846
  { PseudoVSOXSEG4EI64_V_M8_M2_MASK, VSOXSEG4EI64_V }, // 6847
  { PseudoVSOXSEG4EI8_V_M1_M1, VSOXSEG4EI8_V }, // 6848
  { PseudoVSOXSEG4EI8_V_M1_M1_MASK, VSOXSEG4EI8_V }, // 6849
  { PseudoVSOXSEG4EI8_V_M1_M2, VSOXSEG4EI8_V }, // 6850
  { PseudoVSOXSEG4EI8_V_M1_M2_MASK, VSOXSEG4EI8_V }, // 6851
  { PseudoVSOXSEG4EI8_V_M2_M2, VSOXSEG4EI8_V }, // 6852
  { PseudoVSOXSEG4EI8_V_M2_M2_MASK, VSOXSEG4EI8_V }, // 6853
  { PseudoVSOXSEG4EI8_V_MF2_M1, VSOXSEG4EI8_V }, // 6854
  { PseudoVSOXSEG4EI8_V_MF2_M1_MASK, VSOXSEG4EI8_V }, // 6855
  { PseudoVSOXSEG4EI8_V_MF2_M2, VSOXSEG4EI8_V }, // 6856
  { PseudoVSOXSEG4EI8_V_MF2_M2_MASK, VSOXSEG4EI8_V }, // 6857
  { PseudoVSOXSEG4EI8_V_MF2_MF2, VSOXSEG4EI8_V }, // 6858
  { PseudoVSOXSEG4EI8_V_MF2_MF2_MASK, VSOXSEG4EI8_V }, // 6859
  { PseudoVSOXSEG4EI8_V_MF4_M1, VSOXSEG4EI8_V }, // 6860
  { PseudoVSOXSEG4EI8_V_MF4_M1_MASK, VSOXSEG4EI8_V }, // 6861
  { PseudoVSOXSEG4EI8_V_MF4_M2, VSOXSEG4EI8_V }, // 6862
  { PseudoVSOXSEG4EI8_V_MF4_M2_MASK, VSOXSEG4EI8_V }, // 6863
  { PseudoVSOXSEG4EI8_V_MF4_MF2, VSOXSEG4EI8_V }, // 6864
  { PseudoVSOXSEG4EI8_V_MF4_MF2_MASK, VSOXSEG4EI8_V }, // 6865
  { PseudoVSOXSEG4EI8_V_MF4_MF4, VSOXSEG4EI8_V }, // 6866
  { PseudoVSOXSEG4EI8_V_MF4_MF4_MASK, VSOXSEG4EI8_V }, // 6867
  { PseudoVSOXSEG4EI8_V_MF8_M1, VSOXSEG4EI8_V }, // 6868
  { PseudoVSOXSEG4EI8_V_MF8_M1_MASK, VSOXSEG4EI8_V }, // 6869
  { PseudoVSOXSEG4EI8_V_MF8_MF2, VSOXSEG4EI8_V }, // 6870
  { PseudoVSOXSEG4EI8_V_MF8_MF2_MASK, VSOXSEG4EI8_V }, // 6871
  { PseudoVSOXSEG4EI8_V_MF8_MF4, VSOXSEG4EI8_V }, // 6872
  { PseudoVSOXSEG4EI8_V_MF8_MF4_MASK, VSOXSEG4EI8_V }, // 6873
  { PseudoVSOXSEG4EI8_V_MF8_MF8, VSOXSEG4EI8_V }, // 6874
  { PseudoVSOXSEG4EI8_V_MF8_MF8_MASK, VSOXSEG4EI8_V }, // 6875
  { PseudoVSOXSEG5EI16_V_M1_M1, VSOXSEG5EI16_V }, // 6876
  { PseudoVSOXSEG5EI16_V_M1_M1_MASK, VSOXSEG5EI16_V }, // 6877
  { PseudoVSOXSEG5EI16_V_M1_MF2, VSOXSEG5EI16_V }, // 6878
  { PseudoVSOXSEG5EI16_V_M1_MF2_MASK, VSOXSEG5EI16_V }, // 6879
  { PseudoVSOXSEG5EI16_V_M2_M1, VSOXSEG5EI16_V }, // 6880
  { PseudoVSOXSEG5EI16_V_M2_M1_MASK, VSOXSEG5EI16_V }, // 6881
  { PseudoVSOXSEG5EI16_V_MF2_M1, VSOXSEG5EI16_V }, // 6882
  { PseudoVSOXSEG5EI16_V_MF2_M1_MASK, VSOXSEG5EI16_V }, // 6883
  { PseudoVSOXSEG5EI16_V_MF2_MF2, VSOXSEG5EI16_V }, // 6884
  { PseudoVSOXSEG5EI16_V_MF2_MF2_MASK, VSOXSEG5EI16_V }, // 6885
  { PseudoVSOXSEG5EI16_V_MF2_MF4, VSOXSEG5EI16_V }, // 6886
  { PseudoVSOXSEG5EI16_V_MF2_MF4_MASK, VSOXSEG5EI16_V }, // 6887
  { PseudoVSOXSEG5EI16_V_MF4_M1, VSOXSEG5EI16_V }, // 6888
  { PseudoVSOXSEG5EI16_V_MF4_M1_MASK, VSOXSEG5EI16_V }, // 6889
  { PseudoVSOXSEG5EI16_V_MF4_MF2, VSOXSEG5EI16_V }, // 6890
  { PseudoVSOXSEG5EI16_V_MF4_MF2_MASK, VSOXSEG5EI16_V }, // 6891
  { PseudoVSOXSEG5EI16_V_MF4_MF4, VSOXSEG5EI16_V }, // 6892
  { PseudoVSOXSEG5EI16_V_MF4_MF4_MASK, VSOXSEG5EI16_V }, // 6893
  { PseudoVSOXSEG5EI16_V_MF4_MF8, VSOXSEG5EI16_V }, // 6894
  { PseudoVSOXSEG5EI16_V_MF4_MF8_MASK, VSOXSEG5EI16_V }, // 6895
  { PseudoVSOXSEG5EI32_V_M1_M1, VSOXSEG5EI32_V }, // 6896
  { PseudoVSOXSEG5EI32_V_M1_M1_MASK, VSOXSEG5EI32_V }, // 6897
  { PseudoVSOXSEG5EI32_V_M1_MF2, VSOXSEG5EI32_V }, // 6898
  { PseudoVSOXSEG5EI32_V_M1_MF2_MASK, VSOXSEG5EI32_V }, // 6899
  { PseudoVSOXSEG5EI32_V_M1_MF4, VSOXSEG5EI32_V }, // 6900
  { PseudoVSOXSEG5EI32_V_M1_MF4_MASK, VSOXSEG5EI32_V }, // 6901
  { PseudoVSOXSEG5EI32_V_M2_M1, VSOXSEG5EI32_V }, // 6902
  { PseudoVSOXSEG5EI32_V_M2_M1_MASK, VSOXSEG5EI32_V }, // 6903
  { PseudoVSOXSEG5EI32_V_M2_MF2, VSOXSEG5EI32_V }, // 6904
  { PseudoVSOXSEG5EI32_V_M2_MF2_MASK, VSOXSEG5EI32_V }, // 6905
  { PseudoVSOXSEG5EI32_V_M4_M1, VSOXSEG5EI32_V }, // 6906
  { PseudoVSOXSEG5EI32_V_M4_M1_MASK, VSOXSEG5EI32_V }, // 6907
  { PseudoVSOXSEG5EI32_V_MF2_M1, VSOXSEG5EI32_V }, // 6908
  { PseudoVSOXSEG5EI32_V_MF2_M1_MASK, VSOXSEG5EI32_V }, // 6909
  { PseudoVSOXSEG5EI32_V_MF2_MF2, VSOXSEG5EI32_V }, // 6910
  { PseudoVSOXSEG5EI32_V_MF2_MF2_MASK, VSOXSEG5EI32_V }, // 6911
  { PseudoVSOXSEG5EI32_V_MF2_MF4, VSOXSEG5EI32_V }, // 6912
  { PseudoVSOXSEG5EI32_V_MF2_MF4_MASK, VSOXSEG5EI32_V }, // 6913
  { PseudoVSOXSEG5EI32_V_MF2_MF8, VSOXSEG5EI32_V }, // 6914
  { PseudoVSOXSEG5EI32_V_MF2_MF8_MASK, VSOXSEG5EI32_V }, // 6915
  { PseudoVSOXSEG5EI64_V_M1_M1, VSOXSEG5EI64_V }, // 6916
  { PseudoVSOXSEG5EI64_V_M1_M1_MASK, VSOXSEG5EI64_V }, // 6917
  { PseudoVSOXSEG5EI64_V_M1_MF2, VSOXSEG5EI64_V }, // 6918
  { PseudoVSOXSEG5EI64_V_M1_MF2_MASK, VSOXSEG5EI64_V }, // 6919
  { PseudoVSOXSEG5EI64_V_M1_MF4, VSOXSEG5EI64_V }, // 6920
  { PseudoVSOXSEG5EI64_V_M1_MF4_MASK, VSOXSEG5EI64_V }, // 6921
  { PseudoVSOXSEG5EI64_V_M1_MF8, VSOXSEG5EI64_V }, // 6922
  { PseudoVSOXSEG5EI64_V_M1_MF8_MASK, VSOXSEG5EI64_V }, // 6923
  { PseudoVSOXSEG5EI64_V_M2_M1, VSOXSEG5EI64_V }, // 6924
  { PseudoVSOXSEG5EI64_V_M2_M1_MASK, VSOXSEG5EI64_V }, // 6925
  { PseudoVSOXSEG5EI64_V_M2_MF2, VSOXSEG5EI64_V }, // 6926
  { PseudoVSOXSEG5EI64_V_M2_MF2_MASK, VSOXSEG5EI64_V }, // 6927
  { PseudoVSOXSEG5EI64_V_M2_MF4, VSOXSEG5EI64_V }, // 6928
  { PseudoVSOXSEG5EI64_V_M2_MF4_MASK, VSOXSEG5EI64_V }, // 6929
  { PseudoVSOXSEG5EI64_V_M4_M1, VSOXSEG5EI64_V }, // 6930
  { PseudoVSOXSEG5EI64_V_M4_M1_MASK, VSOXSEG5EI64_V }, // 6931
  { PseudoVSOXSEG5EI64_V_M4_MF2, VSOXSEG5EI64_V }, // 6932
  { PseudoVSOXSEG5EI64_V_M4_MF2_MASK, VSOXSEG5EI64_V }, // 6933
  { PseudoVSOXSEG5EI64_V_M8_M1, VSOXSEG5EI64_V }, // 6934
  { PseudoVSOXSEG5EI64_V_M8_M1_MASK, VSOXSEG5EI64_V }, // 6935
  { PseudoVSOXSEG5EI8_V_M1_M1, VSOXSEG5EI8_V }, // 6936
  { PseudoVSOXSEG5EI8_V_M1_M1_MASK, VSOXSEG5EI8_V }, // 6937
  { PseudoVSOXSEG5EI8_V_MF2_M1, VSOXSEG5EI8_V }, // 6938
  { PseudoVSOXSEG5EI8_V_MF2_M1_MASK, VSOXSEG5EI8_V }, // 6939
  { PseudoVSOXSEG5EI8_V_MF2_MF2, VSOXSEG5EI8_V }, // 6940
  { PseudoVSOXSEG5EI8_V_MF2_MF2_MASK, VSOXSEG5EI8_V }, // 6941
  { PseudoVSOXSEG5EI8_V_MF4_M1, VSOXSEG5EI8_V }, // 6942
  { PseudoVSOXSEG5EI8_V_MF4_M1_MASK, VSOXSEG5EI8_V }, // 6943
  { PseudoVSOXSEG5EI8_V_MF4_MF2, VSOXSEG5EI8_V }, // 6944
  { PseudoVSOXSEG5EI8_V_MF4_MF2_MASK, VSOXSEG5EI8_V }, // 6945
  { PseudoVSOXSEG5EI8_V_MF4_MF4, VSOXSEG5EI8_V }, // 6946
  { PseudoVSOXSEG5EI8_V_MF4_MF4_MASK, VSOXSEG5EI8_V }, // 6947
  { PseudoVSOXSEG5EI8_V_MF8_M1, VSOXSEG5EI8_V }, // 6948
  { PseudoVSOXSEG5EI8_V_MF8_M1_MASK, VSOXSEG5EI8_V }, // 6949
  { PseudoVSOXSEG5EI8_V_MF8_MF2, VSOXSEG5EI8_V }, // 6950
  { PseudoVSOXSEG5EI8_V_MF8_MF2_MASK, VSOXSEG5EI8_V }, // 6951
  { PseudoVSOXSEG5EI8_V_MF8_MF4, VSOXSEG5EI8_V }, // 6952
  { PseudoVSOXSEG5EI8_V_MF8_MF4_MASK, VSOXSEG5EI8_V }, // 6953
  { PseudoVSOXSEG5EI8_V_MF8_MF8, VSOXSEG5EI8_V }, // 6954
  { PseudoVSOXSEG5EI8_V_MF8_MF8_MASK, VSOXSEG5EI8_V }, // 6955
  { PseudoVSOXSEG6EI16_V_M1_M1, VSOXSEG6EI16_V }, // 6956
  { PseudoVSOXSEG6EI16_V_M1_M1_MASK, VSOXSEG6EI16_V }, // 6957
  { PseudoVSOXSEG6EI16_V_M1_MF2, VSOXSEG6EI16_V }, // 6958
  { PseudoVSOXSEG6EI16_V_M1_MF2_MASK, VSOXSEG6EI16_V }, // 6959
  { PseudoVSOXSEG6EI16_V_M2_M1, VSOXSEG6EI16_V }, // 6960
  { PseudoVSOXSEG6EI16_V_M2_M1_MASK, VSOXSEG6EI16_V }, // 6961
  { PseudoVSOXSEG6EI16_V_MF2_M1, VSOXSEG6EI16_V }, // 6962
  { PseudoVSOXSEG6EI16_V_MF2_M1_MASK, VSOXSEG6EI16_V }, // 6963
  { PseudoVSOXSEG6EI16_V_MF2_MF2, VSOXSEG6EI16_V }, // 6964
  { PseudoVSOXSEG6EI16_V_MF2_MF2_MASK, VSOXSEG6EI16_V }, // 6965
  { PseudoVSOXSEG6EI16_V_MF2_MF4, VSOXSEG6EI16_V }, // 6966
  { PseudoVSOXSEG6EI16_V_MF2_MF4_MASK, VSOXSEG6EI16_V }, // 6967
  { PseudoVSOXSEG6EI16_V_MF4_M1, VSOXSEG6EI16_V }, // 6968
  { PseudoVSOXSEG6EI16_V_MF4_M1_MASK, VSOXSEG6EI16_V }, // 6969
  { PseudoVSOXSEG6EI16_V_MF4_MF2, VSOXSEG6EI16_V }, // 6970
  { PseudoVSOXSEG6EI16_V_MF4_MF2_MASK, VSOXSEG6EI16_V }, // 6971
  { PseudoVSOXSEG6EI16_V_MF4_MF4, VSOXSEG6EI16_V }, // 6972
  { PseudoVSOXSEG6EI16_V_MF4_MF4_MASK, VSOXSEG6EI16_V }, // 6973
  { PseudoVSOXSEG6EI16_V_MF4_MF8, VSOXSEG6EI16_V }, // 6974
  { PseudoVSOXSEG6EI16_V_MF4_MF8_MASK, VSOXSEG6EI16_V }, // 6975
  { PseudoVSOXSEG6EI32_V_M1_M1, VSOXSEG6EI32_V }, // 6976
  { PseudoVSOXSEG6EI32_V_M1_M1_MASK, VSOXSEG6EI32_V }, // 6977
  { PseudoVSOXSEG6EI32_V_M1_MF2, VSOXSEG6EI32_V }, // 6978
  { PseudoVSOXSEG6EI32_V_M1_MF2_MASK, VSOXSEG6EI32_V }, // 6979
  { PseudoVSOXSEG6EI32_V_M1_MF4, VSOXSEG6EI32_V }, // 6980
  { PseudoVSOXSEG6EI32_V_M1_MF4_MASK, VSOXSEG6EI32_V }, // 6981
  { PseudoVSOXSEG6EI32_V_M2_M1, VSOXSEG6EI32_V }, // 6982
  { PseudoVSOXSEG6EI32_V_M2_M1_MASK, VSOXSEG6EI32_V }, // 6983
  { PseudoVSOXSEG6EI32_V_M2_MF2, VSOXSEG6EI32_V }, // 6984
  { PseudoVSOXSEG6EI32_V_M2_MF2_MASK, VSOXSEG6EI32_V }, // 6985
  { PseudoVSOXSEG6EI32_V_M4_M1, VSOXSEG6EI32_V }, // 6986
  { PseudoVSOXSEG6EI32_V_M4_M1_MASK, VSOXSEG6EI32_V }, // 6987
  { PseudoVSOXSEG6EI32_V_MF2_M1, VSOXSEG6EI32_V }, // 6988
  { PseudoVSOXSEG6EI32_V_MF2_M1_MASK, VSOXSEG6EI32_V }, // 6989
  { PseudoVSOXSEG6EI32_V_MF2_MF2, VSOXSEG6EI32_V }, // 6990
  { PseudoVSOXSEG6EI32_V_MF2_MF2_MASK, VSOXSEG6EI32_V }, // 6991
  { PseudoVSOXSEG6EI32_V_MF2_MF4, VSOXSEG6EI32_V }, // 6992
  { PseudoVSOXSEG6EI32_V_MF2_MF4_MASK, VSOXSEG6EI32_V }, // 6993
  { PseudoVSOXSEG6EI32_V_MF2_MF8, VSOXSEG6EI32_V }, // 6994
  { PseudoVSOXSEG6EI32_V_MF2_MF8_MASK, VSOXSEG6EI32_V }, // 6995
  { PseudoVSOXSEG6EI64_V_M1_M1, VSOXSEG6EI64_V }, // 6996
  { PseudoVSOXSEG6EI64_V_M1_M1_MASK, VSOXSEG6EI64_V }, // 6997
  { PseudoVSOXSEG6EI64_V_M1_MF2, VSOXSEG6EI64_V }, // 6998
  { PseudoVSOXSEG6EI64_V_M1_MF2_MASK, VSOXSEG6EI64_V }, // 6999
  { PseudoVSOXSEG6EI64_V_M1_MF4, VSOXSEG6EI64_V }, // 7000
  { PseudoVSOXSEG6EI64_V_M1_MF4_MASK, VSOXSEG6EI64_V }, // 7001
  { PseudoVSOXSEG6EI64_V_M1_MF8, VSOXSEG6EI64_V }, // 7002
  { PseudoVSOXSEG6EI64_V_M1_MF8_MASK, VSOXSEG6EI64_V }, // 7003
  { PseudoVSOXSEG6EI64_V_M2_M1, VSOXSEG6EI64_V }, // 7004
  { PseudoVSOXSEG6EI64_V_M2_M1_MASK, VSOXSEG6EI64_V }, // 7005
  { PseudoVSOXSEG6EI64_V_M2_MF2, VSOXSEG6EI64_V }, // 7006
  { PseudoVSOXSEG6EI64_V_M2_MF2_MASK, VSOXSEG6EI64_V }, // 7007
  { PseudoVSOXSEG6EI64_V_M2_MF4, VSOXSEG6EI64_V }, // 7008
  { PseudoVSOXSEG6EI64_V_M2_MF4_MASK, VSOXSEG6EI64_V }, // 7009
  { PseudoVSOXSEG6EI64_V_M4_M1, VSOXSEG6EI64_V }, // 7010
  { PseudoVSOXSEG6EI64_V_M4_M1_MASK, VSOXSEG6EI64_V }, // 7011
  { PseudoVSOXSEG6EI64_V_M4_MF2, VSOXSEG6EI64_V }, // 7012
  { PseudoVSOXSEG6EI64_V_M4_MF2_MASK, VSOXSEG6EI64_V }, // 7013
  { PseudoVSOXSEG6EI64_V_M8_M1, VSOXSEG6EI64_V }, // 7014
  { PseudoVSOXSEG6EI64_V_M8_M1_MASK, VSOXSEG6EI64_V }, // 7015
  { PseudoVSOXSEG6EI8_V_M1_M1, VSOXSEG6EI8_V }, // 7016
  { PseudoVSOXSEG6EI8_V_M1_M1_MASK, VSOXSEG6EI8_V }, // 7017
  { PseudoVSOXSEG6EI8_V_MF2_M1, VSOXSEG6EI8_V }, // 7018
  { PseudoVSOXSEG6EI8_V_MF2_M1_MASK, VSOXSEG6EI8_V }, // 7019
  { PseudoVSOXSEG6EI8_V_MF2_MF2, VSOXSEG6EI8_V }, // 7020
  { PseudoVSOXSEG6EI8_V_MF2_MF2_MASK, VSOXSEG6EI8_V }, // 7021
  { PseudoVSOXSEG6EI8_V_MF4_M1, VSOXSEG6EI8_V }, // 7022
  { PseudoVSOXSEG6EI8_V_MF4_M1_MASK, VSOXSEG6EI8_V }, // 7023
  { PseudoVSOXSEG6EI8_V_MF4_MF2, VSOXSEG6EI8_V }, // 7024
  { PseudoVSOXSEG6EI8_V_MF4_MF2_MASK, VSOXSEG6EI8_V }, // 7025
  { PseudoVSOXSEG6EI8_V_MF4_MF4, VSOXSEG6EI8_V }, // 7026
  { PseudoVSOXSEG6EI8_V_MF4_MF4_MASK, VSOXSEG6EI8_V }, // 7027
  { PseudoVSOXSEG6EI8_V_MF8_M1, VSOXSEG6EI8_V }, // 7028
  { PseudoVSOXSEG6EI8_V_MF8_M1_MASK, VSOXSEG6EI8_V }, // 7029
  { PseudoVSOXSEG6EI8_V_MF8_MF2, VSOXSEG6EI8_V }, // 7030
  { PseudoVSOXSEG6EI8_V_MF8_MF2_MASK, VSOXSEG6EI8_V }, // 7031
  { PseudoVSOXSEG6EI8_V_MF8_MF4, VSOXSEG6EI8_V }, // 7032
  { PseudoVSOXSEG6EI8_V_MF8_MF4_MASK, VSOXSEG6EI8_V }, // 7033
  { PseudoVSOXSEG6EI8_V_MF8_MF8, VSOXSEG6EI8_V }, // 7034
  { PseudoVSOXSEG6EI8_V_MF8_MF8_MASK, VSOXSEG6EI8_V }, // 7035
  { PseudoVSOXSEG7EI16_V_M1_M1, VSOXSEG7EI16_V }, // 7036
  { PseudoVSOXSEG7EI16_V_M1_M1_MASK, VSOXSEG7EI16_V }, // 7037
  { PseudoVSOXSEG7EI16_V_M1_MF2, VSOXSEG7EI16_V }, // 7038
  { PseudoVSOXSEG7EI16_V_M1_MF2_MASK, VSOXSEG7EI16_V }, // 7039
  { PseudoVSOXSEG7EI16_V_M2_M1, VSOXSEG7EI16_V }, // 7040
  { PseudoVSOXSEG7EI16_V_M2_M1_MASK, VSOXSEG7EI16_V }, // 7041
  { PseudoVSOXSEG7EI16_V_MF2_M1, VSOXSEG7EI16_V }, // 7042
  { PseudoVSOXSEG7EI16_V_MF2_M1_MASK, VSOXSEG7EI16_V }, // 7043
  { PseudoVSOXSEG7EI16_V_MF2_MF2, VSOXSEG7EI16_V }, // 7044
  { PseudoVSOXSEG7EI16_V_MF2_MF2_MASK, VSOXSEG7EI16_V }, // 7045
  { PseudoVSOXSEG7EI16_V_MF2_MF4, VSOXSEG7EI16_V }, // 7046
  { PseudoVSOXSEG7EI16_V_MF2_MF4_MASK, VSOXSEG7EI16_V }, // 7047
  { PseudoVSOXSEG7EI16_V_MF4_M1, VSOXSEG7EI16_V }, // 7048
  { PseudoVSOXSEG7EI16_V_MF4_M1_MASK, VSOXSEG7EI16_V }, // 7049
  { PseudoVSOXSEG7EI16_V_MF4_MF2, VSOXSEG7EI16_V }, // 7050
  { PseudoVSOXSEG7EI16_V_MF4_MF2_MASK, VSOXSEG7EI16_V }, // 7051
  { PseudoVSOXSEG7EI16_V_MF4_MF4, VSOXSEG7EI16_V }, // 7052
  { PseudoVSOXSEG7EI16_V_MF4_MF4_MASK, VSOXSEG7EI16_V }, // 7053
  { PseudoVSOXSEG7EI16_V_MF4_MF8, VSOXSEG7EI16_V }, // 7054
  { PseudoVSOXSEG7EI16_V_MF4_MF8_MASK, VSOXSEG7EI16_V }, // 7055
  { PseudoVSOXSEG7EI32_V_M1_M1, VSOXSEG7EI32_V }, // 7056
  { PseudoVSOXSEG7EI32_V_M1_M1_MASK, VSOXSEG7EI32_V }, // 7057
  { PseudoVSOXSEG7EI32_V_M1_MF2, VSOXSEG7EI32_V }, // 7058
  { PseudoVSOXSEG7EI32_V_M1_MF2_MASK, VSOXSEG7EI32_V }, // 7059
  { PseudoVSOXSEG7EI32_V_M1_MF4, VSOXSEG7EI32_V }, // 7060
  { PseudoVSOXSEG7EI32_V_M1_MF4_MASK, VSOXSEG7EI32_V }, // 7061
  { PseudoVSOXSEG7EI32_V_M2_M1, VSOXSEG7EI32_V }, // 7062
  { PseudoVSOXSEG7EI32_V_M2_M1_MASK, VSOXSEG7EI32_V }, // 7063
  { PseudoVSOXSEG7EI32_V_M2_MF2, VSOXSEG7EI32_V }, // 7064
  { PseudoVSOXSEG7EI32_V_M2_MF2_MASK, VSOXSEG7EI32_V }, // 7065
  { PseudoVSOXSEG7EI32_V_M4_M1, VSOXSEG7EI32_V }, // 7066
  { PseudoVSOXSEG7EI32_V_M4_M1_MASK, VSOXSEG7EI32_V }, // 7067
  { PseudoVSOXSEG7EI32_V_MF2_M1, VSOXSEG7EI32_V }, // 7068
  { PseudoVSOXSEG7EI32_V_MF2_M1_MASK, VSOXSEG7EI32_V }, // 7069
  { PseudoVSOXSEG7EI32_V_MF2_MF2, VSOXSEG7EI32_V }, // 7070
  { PseudoVSOXSEG7EI32_V_MF2_MF2_MASK, VSOXSEG7EI32_V }, // 7071
  { PseudoVSOXSEG7EI32_V_MF2_MF4, VSOXSEG7EI32_V }, // 7072
  { PseudoVSOXSEG7EI32_V_MF2_MF4_MASK, VSOXSEG7EI32_V }, // 7073
  { PseudoVSOXSEG7EI32_V_MF2_MF8, VSOXSEG7EI32_V }, // 7074
  { PseudoVSOXSEG7EI32_V_MF2_MF8_MASK, VSOXSEG7EI32_V }, // 7075
  { PseudoVSOXSEG7EI64_V_M1_M1, VSOXSEG7EI64_V }, // 7076
  { PseudoVSOXSEG7EI64_V_M1_M1_MASK, VSOXSEG7EI64_V }, // 7077
  { PseudoVSOXSEG7EI64_V_M1_MF2, VSOXSEG7EI64_V }, // 7078
  { PseudoVSOXSEG7EI64_V_M1_MF2_MASK, VSOXSEG7EI64_V }, // 7079
  { PseudoVSOXSEG7EI64_V_M1_MF4, VSOXSEG7EI64_V }, // 7080
  { PseudoVSOXSEG7EI64_V_M1_MF4_MASK, VSOXSEG7EI64_V }, // 7081
  { PseudoVSOXSEG7EI64_V_M1_MF8, VSOXSEG7EI64_V }, // 7082
  { PseudoVSOXSEG7EI64_V_M1_MF8_MASK, VSOXSEG7EI64_V }, // 7083
  { PseudoVSOXSEG7EI64_V_M2_M1, VSOXSEG7EI64_V }, // 7084
  { PseudoVSOXSEG7EI64_V_M2_M1_MASK, VSOXSEG7EI64_V }, // 7085
  { PseudoVSOXSEG7EI64_V_M2_MF2, VSOXSEG7EI64_V }, // 7086
  { PseudoVSOXSEG7EI64_V_M2_MF2_MASK, VSOXSEG7EI64_V }, // 7087
  { PseudoVSOXSEG7EI64_V_M2_MF4, VSOXSEG7EI64_V }, // 7088
  { PseudoVSOXSEG7EI64_V_M2_MF4_MASK, VSOXSEG7EI64_V }, // 7089
  { PseudoVSOXSEG7EI64_V_M4_M1, VSOXSEG7EI64_V }, // 7090
  { PseudoVSOXSEG7EI64_V_M4_M1_MASK, VSOXSEG7EI64_V }, // 7091
  { PseudoVSOXSEG7EI64_V_M4_MF2, VSOXSEG7EI64_V }, // 7092
  { PseudoVSOXSEG7EI64_V_M4_MF2_MASK, VSOXSEG7EI64_V }, // 7093
  { PseudoVSOXSEG7EI64_V_M8_M1, VSOXSEG7EI64_V }, // 7094
  { PseudoVSOXSEG7EI64_V_M8_M1_MASK, VSOXSEG7EI64_V }, // 7095
  { PseudoVSOXSEG7EI8_V_M1_M1, VSOXSEG7EI8_V }, // 7096
  { PseudoVSOXSEG7EI8_V_M1_M1_MASK, VSOXSEG7EI8_V }, // 7097
  { PseudoVSOXSEG7EI8_V_MF2_M1, VSOXSEG7EI8_V }, // 7098
  { PseudoVSOXSEG7EI8_V_MF2_M1_MASK, VSOXSEG7EI8_V }, // 7099
  { PseudoVSOXSEG7EI8_V_MF2_MF2, VSOXSEG7EI8_V }, // 7100
  { PseudoVSOXSEG7EI8_V_MF2_MF2_MASK, VSOXSEG7EI8_V }, // 7101
  { PseudoVSOXSEG7EI8_V_MF4_M1, VSOXSEG7EI8_V }, // 7102
  { PseudoVSOXSEG7EI8_V_MF4_M1_MASK, VSOXSEG7EI8_V }, // 7103
  { PseudoVSOXSEG7EI8_V_MF4_MF2, VSOXSEG7EI8_V }, // 7104
  { PseudoVSOXSEG7EI8_V_MF4_MF2_MASK, VSOXSEG7EI8_V }, // 7105
  { PseudoVSOXSEG7EI8_V_MF4_MF4, VSOXSEG7EI8_V }, // 7106
  { PseudoVSOXSEG7EI8_V_MF4_MF4_MASK, VSOXSEG7EI8_V }, // 7107
  { PseudoVSOXSEG7EI8_V_MF8_M1, VSOXSEG7EI8_V }, // 7108
  { PseudoVSOXSEG7EI8_V_MF8_M1_MASK, VSOXSEG7EI8_V }, // 7109
  { PseudoVSOXSEG7EI8_V_MF8_MF2, VSOXSEG7EI8_V }, // 7110
  { PseudoVSOXSEG7EI8_V_MF8_MF2_MASK, VSOXSEG7EI8_V }, // 7111
  { PseudoVSOXSEG7EI8_V_MF8_MF4, VSOXSEG7EI8_V }, // 7112
  { PseudoVSOXSEG7EI8_V_MF8_MF4_MASK, VSOXSEG7EI8_V }, // 7113
  { PseudoVSOXSEG7EI8_V_MF8_MF8, VSOXSEG7EI8_V }, // 7114
  { PseudoVSOXSEG7EI8_V_MF8_MF8_MASK, VSOXSEG7EI8_V }, // 7115
  { PseudoVSOXSEG8EI16_V_M1_M1, VSOXSEG8EI16_V }, // 7116
  { PseudoVSOXSEG8EI16_V_M1_M1_MASK, VSOXSEG8EI16_V }, // 7117
  { PseudoVSOXSEG8EI16_V_M1_MF2, VSOXSEG8EI16_V }, // 7118
  { PseudoVSOXSEG8EI16_V_M1_MF2_MASK, VSOXSEG8EI16_V }, // 7119
  { PseudoVSOXSEG8EI16_V_M2_M1, VSOXSEG8EI16_V }, // 7120
  { PseudoVSOXSEG8EI16_V_M2_M1_MASK, VSOXSEG8EI16_V }, // 7121
  { PseudoVSOXSEG8EI16_V_MF2_M1, VSOXSEG8EI16_V }, // 7122
  { PseudoVSOXSEG8EI16_V_MF2_M1_MASK, VSOXSEG8EI16_V }, // 7123
  { PseudoVSOXSEG8EI16_V_MF2_MF2, VSOXSEG8EI16_V }, // 7124
  { PseudoVSOXSEG8EI16_V_MF2_MF2_MASK, VSOXSEG8EI16_V }, // 7125
  { PseudoVSOXSEG8EI16_V_MF2_MF4, VSOXSEG8EI16_V }, // 7126
  { PseudoVSOXSEG8EI16_V_MF2_MF4_MASK, VSOXSEG8EI16_V }, // 7127
  { PseudoVSOXSEG8EI16_V_MF4_M1, VSOXSEG8EI16_V }, // 7128
  { PseudoVSOXSEG8EI16_V_MF4_M1_MASK, VSOXSEG8EI16_V }, // 7129
  { PseudoVSOXSEG8EI16_V_MF4_MF2, VSOXSEG8EI16_V }, // 7130
  { PseudoVSOXSEG8EI16_V_MF4_MF2_MASK, VSOXSEG8EI16_V }, // 7131
  { PseudoVSOXSEG8EI16_V_MF4_MF4, VSOXSEG8EI16_V }, // 7132
  { PseudoVSOXSEG8EI16_V_MF4_MF4_MASK, VSOXSEG8EI16_V }, // 7133
  { PseudoVSOXSEG8EI16_V_MF4_MF8, VSOXSEG8EI16_V }, // 7134
  { PseudoVSOXSEG8EI16_V_MF4_MF8_MASK, VSOXSEG8EI16_V }, // 7135
  { PseudoVSOXSEG8EI32_V_M1_M1, VSOXSEG8EI32_V }, // 7136
  { PseudoVSOXSEG8EI32_V_M1_M1_MASK, VSOXSEG8EI32_V }, // 7137
  { PseudoVSOXSEG8EI32_V_M1_MF2, VSOXSEG8EI32_V }, // 7138
  { PseudoVSOXSEG8EI32_V_M1_MF2_MASK, VSOXSEG8EI32_V }, // 7139
  { PseudoVSOXSEG8EI32_V_M1_MF4, VSOXSEG8EI32_V }, // 7140
  { PseudoVSOXSEG8EI32_V_M1_MF4_MASK, VSOXSEG8EI32_V }, // 7141
  { PseudoVSOXSEG8EI32_V_M2_M1, VSOXSEG8EI32_V }, // 7142
  { PseudoVSOXSEG8EI32_V_M2_M1_MASK, VSOXSEG8EI32_V }, // 7143
  { PseudoVSOXSEG8EI32_V_M2_MF2, VSOXSEG8EI32_V }, // 7144
  { PseudoVSOXSEG8EI32_V_M2_MF2_MASK, VSOXSEG8EI32_V }, // 7145
  { PseudoVSOXSEG8EI32_V_M4_M1, VSOXSEG8EI32_V }, // 7146
  { PseudoVSOXSEG8EI32_V_M4_M1_MASK, VSOXSEG8EI32_V }, // 7147
  { PseudoVSOXSEG8EI32_V_MF2_M1, VSOXSEG8EI32_V }, // 7148
  { PseudoVSOXSEG8EI32_V_MF2_M1_MASK, VSOXSEG8EI32_V }, // 7149
  { PseudoVSOXSEG8EI32_V_MF2_MF2, VSOXSEG8EI32_V }, // 7150
  { PseudoVSOXSEG8EI32_V_MF2_MF2_MASK, VSOXSEG8EI32_V }, // 7151
  { PseudoVSOXSEG8EI32_V_MF2_MF4, VSOXSEG8EI32_V }, // 7152
  { PseudoVSOXSEG8EI32_V_MF2_MF4_MASK, VSOXSEG8EI32_V }, // 7153
  { PseudoVSOXSEG8EI32_V_MF2_MF8, VSOXSEG8EI32_V }, // 7154
  { PseudoVSOXSEG8EI32_V_MF2_MF8_MASK, VSOXSEG8EI32_V }, // 7155
  { PseudoVSOXSEG8EI64_V_M1_M1, VSOXSEG8EI64_V }, // 7156
  { PseudoVSOXSEG8EI64_V_M1_M1_MASK, VSOXSEG8EI64_V }, // 7157
  { PseudoVSOXSEG8EI64_V_M1_MF2, VSOXSEG8EI64_V }, // 7158
  { PseudoVSOXSEG8EI64_V_M1_MF2_MASK, VSOXSEG8EI64_V }, // 7159
  { PseudoVSOXSEG8EI64_V_M1_MF4, VSOXSEG8EI64_V }, // 7160
  { PseudoVSOXSEG8EI64_V_M1_MF4_MASK, VSOXSEG8EI64_V }, // 7161
  { PseudoVSOXSEG8EI64_V_M1_MF8, VSOXSEG8EI64_V }, // 7162
  { PseudoVSOXSEG8EI64_V_M1_MF8_MASK, VSOXSEG8EI64_V }, // 7163
  { PseudoVSOXSEG8EI64_V_M2_M1, VSOXSEG8EI64_V }, // 7164
  { PseudoVSOXSEG8EI64_V_M2_M1_MASK, VSOXSEG8EI64_V }, // 7165
  { PseudoVSOXSEG8EI64_V_M2_MF2, VSOXSEG8EI64_V }, // 7166
  { PseudoVSOXSEG8EI64_V_M2_MF2_MASK, VSOXSEG8EI64_V }, // 7167
  { PseudoVSOXSEG8EI64_V_M2_MF4, VSOXSEG8EI64_V }, // 7168
  { PseudoVSOXSEG8EI64_V_M2_MF4_MASK, VSOXSEG8EI64_V }, // 7169
  { PseudoVSOXSEG8EI64_V_M4_M1, VSOXSEG8EI64_V }, // 7170
  { PseudoVSOXSEG8EI64_V_M4_M1_MASK, VSOXSEG8EI64_V }, // 7171
  { PseudoVSOXSEG8EI64_V_M4_MF2, VSOXSEG8EI64_V }, // 7172
  { PseudoVSOXSEG8EI64_V_M4_MF2_MASK, VSOXSEG8EI64_V }, // 7173
  { PseudoVSOXSEG8EI64_V_M8_M1, VSOXSEG8EI64_V }, // 7174
  { PseudoVSOXSEG8EI64_V_M8_M1_MASK, VSOXSEG8EI64_V }, // 7175
  { PseudoVSOXSEG8EI8_V_M1_M1, VSOXSEG8EI8_V }, // 7176
  { PseudoVSOXSEG8EI8_V_M1_M1_MASK, VSOXSEG8EI8_V }, // 7177
  { PseudoVSOXSEG8EI8_V_MF2_M1, VSOXSEG8EI8_V }, // 7178
  { PseudoVSOXSEG8EI8_V_MF2_M1_MASK, VSOXSEG8EI8_V }, // 7179
  { PseudoVSOXSEG8EI8_V_MF2_MF2, VSOXSEG8EI8_V }, // 7180
  { PseudoVSOXSEG8EI8_V_MF2_MF2_MASK, VSOXSEG8EI8_V }, // 7181
  { PseudoVSOXSEG8EI8_V_MF4_M1, VSOXSEG8EI8_V }, // 7182
  { PseudoVSOXSEG8EI8_V_MF4_M1_MASK, VSOXSEG8EI8_V }, // 7183
  { PseudoVSOXSEG8EI8_V_MF4_MF2, VSOXSEG8EI8_V }, // 7184
  { PseudoVSOXSEG8EI8_V_MF4_MF2_MASK, VSOXSEG8EI8_V }, // 7185
  { PseudoVSOXSEG8EI8_V_MF4_MF4, VSOXSEG8EI8_V }, // 7186
  { PseudoVSOXSEG8EI8_V_MF4_MF4_MASK, VSOXSEG8EI8_V }, // 7187
  { PseudoVSOXSEG8EI8_V_MF8_M1, VSOXSEG8EI8_V }, // 7188
  { PseudoVSOXSEG8EI8_V_MF8_M1_MASK, VSOXSEG8EI8_V }, // 7189
  { PseudoVSOXSEG8EI8_V_MF8_MF2, VSOXSEG8EI8_V }, // 7190
  { PseudoVSOXSEG8EI8_V_MF8_MF2_MASK, VSOXSEG8EI8_V }, // 7191
  { PseudoVSOXSEG8EI8_V_MF8_MF4, VSOXSEG8EI8_V }, // 7192
  { PseudoVSOXSEG8EI8_V_MF8_MF4_MASK, VSOXSEG8EI8_V }, // 7193
  { PseudoVSOXSEG8EI8_V_MF8_MF8, VSOXSEG8EI8_V }, // 7194
  { PseudoVSOXSEG8EI8_V_MF8_MF8_MASK, VSOXSEG8EI8_V }, // 7195
  { PseudoVSPILL_M1, VS1R_V }, // 7196
  { PseudoVSPILL_M2, VS2R_V }, // 7197
  { PseudoVSPILL_M4, VS4R_V }, // 7198
  { PseudoVSPILL_M8, VS8R_V }, // 7199
  { PseudoVSRA_VI_M1, VSRA_VI }, // 7200
  { PseudoVSRA_VI_M1_MASK, VSRA_VI }, // 7201
  { PseudoVSRA_VI_M2, VSRA_VI }, // 7202
  { PseudoVSRA_VI_M2_MASK, VSRA_VI }, // 7203
  { PseudoVSRA_VI_M4, VSRA_VI }, // 7204
  { PseudoVSRA_VI_M4_MASK, VSRA_VI }, // 7205
  { PseudoVSRA_VI_M8, VSRA_VI }, // 7206
  { PseudoVSRA_VI_M8_MASK, VSRA_VI }, // 7207
  { PseudoVSRA_VI_MF2, VSRA_VI }, // 7208
  { PseudoVSRA_VI_MF2_MASK, VSRA_VI }, // 7209
  { PseudoVSRA_VI_MF4, VSRA_VI }, // 7210
  { PseudoVSRA_VI_MF4_MASK, VSRA_VI }, // 7211
  { PseudoVSRA_VI_MF8, VSRA_VI }, // 7212
  { PseudoVSRA_VI_MF8_MASK, VSRA_VI }, // 7213
  { PseudoVSRA_VV_M1, VSRA_VV }, // 7214
  { PseudoVSRA_VV_M1_MASK, VSRA_VV }, // 7215
  { PseudoVSRA_VV_M2, VSRA_VV }, // 7216
  { PseudoVSRA_VV_M2_MASK, VSRA_VV }, // 7217
  { PseudoVSRA_VV_M4, VSRA_VV }, // 7218
  { PseudoVSRA_VV_M4_MASK, VSRA_VV }, // 7219
  { PseudoVSRA_VV_M8, VSRA_VV }, // 7220
  { PseudoVSRA_VV_M8_MASK, VSRA_VV }, // 7221
  { PseudoVSRA_VV_MF2, VSRA_VV }, // 7222
  { PseudoVSRA_VV_MF2_MASK, VSRA_VV }, // 7223
  { PseudoVSRA_VV_MF4, VSRA_VV }, // 7224
  { PseudoVSRA_VV_MF4_MASK, VSRA_VV }, // 7225
  { PseudoVSRA_VV_MF8, VSRA_VV }, // 7226
  { PseudoVSRA_VV_MF8_MASK, VSRA_VV }, // 7227
  { PseudoVSRA_VX_M1, VSRA_VX }, // 7228
  { PseudoVSRA_VX_M1_MASK, VSRA_VX }, // 7229
  { PseudoVSRA_VX_M2, VSRA_VX }, // 7230
  { PseudoVSRA_VX_M2_MASK, VSRA_VX }, // 7231
  { PseudoVSRA_VX_M4, VSRA_VX }, // 7232
  { PseudoVSRA_VX_M4_MASK, VSRA_VX }, // 7233
  { PseudoVSRA_VX_M8, VSRA_VX }, // 7234
  { PseudoVSRA_VX_M8_MASK, VSRA_VX }, // 7235
  { PseudoVSRA_VX_MF2, VSRA_VX }, // 7236
  { PseudoVSRA_VX_MF2_MASK, VSRA_VX }, // 7237
  { PseudoVSRA_VX_MF4, VSRA_VX }, // 7238
  { PseudoVSRA_VX_MF4_MASK, VSRA_VX }, // 7239
  { PseudoVSRA_VX_MF8, VSRA_VX }, // 7240
  { PseudoVSRA_VX_MF8_MASK, VSRA_VX }, // 7241
  { PseudoVSRL_VI_M1, VSRL_VI }, // 7242
  { PseudoVSRL_VI_M1_MASK, VSRL_VI }, // 7243
  { PseudoVSRL_VI_M2, VSRL_VI }, // 7244
  { PseudoVSRL_VI_M2_MASK, VSRL_VI }, // 7245
  { PseudoVSRL_VI_M4, VSRL_VI }, // 7246
  { PseudoVSRL_VI_M4_MASK, VSRL_VI }, // 7247
  { PseudoVSRL_VI_M8, VSRL_VI }, // 7248
  { PseudoVSRL_VI_M8_MASK, VSRL_VI }, // 7249
  { PseudoVSRL_VI_MF2, VSRL_VI }, // 7250
  { PseudoVSRL_VI_MF2_MASK, VSRL_VI }, // 7251
  { PseudoVSRL_VI_MF4, VSRL_VI }, // 7252
  { PseudoVSRL_VI_MF4_MASK, VSRL_VI }, // 7253
  { PseudoVSRL_VI_MF8, VSRL_VI }, // 7254
  { PseudoVSRL_VI_MF8_MASK, VSRL_VI }, // 7255
  { PseudoVSRL_VV_M1, VSRL_VV }, // 7256
  { PseudoVSRL_VV_M1_MASK, VSRL_VV }, // 7257
  { PseudoVSRL_VV_M2, VSRL_VV }, // 7258
  { PseudoVSRL_VV_M2_MASK, VSRL_VV }, // 7259
  { PseudoVSRL_VV_M4, VSRL_VV }, // 7260
  { PseudoVSRL_VV_M4_MASK, VSRL_VV }, // 7261
  { PseudoVSRL_VV_M8, VSRL_VV }, // 7262
  { PseudoVSRL_VV_M8_MASK, VSRL_VV }, // 7263
  { PseudoVSRL_VV_MF2, VSRL_VV }, // 7264
  { PseudoVSRL_VV_MF2_MASK, VSRL_VV }, // 7265
  { PseudoVSRL_VV_MF4, VSRL_VV }, // 7266
  { PseudoVSRL_VV_MF4_MASK, VSRL_VV }, // 7267
  { PseudoVSRL_VV_MF8, VSRL_VV }, // 7268
  { PseudoVSRL_VV_MF8_MASK, VSRL_VV }, // 7269
  { PseudoVSRL_VX_M1, VSRL_VX }, // 7270
  { PseudoVSRL_VX_M1_MASK, VSRL_VX }, // 7271
  { PseudoVSRL_VX_M2, VSRL_VX }, // 7272
  { PseudoVSRL_VX_M2_MASK, VSRL_VX }, // 7273
  { PseudoVSRL_VX_M4, VSRL_VX }, // 7274
  { PseudoVSRL_VX_M4_MASK, VSRL_VX }, // 7275
  { PseudoVSRL_VX_M8, VSRL_VX }, // 7276
  { PseudoVSRL_VX_M8_MASK, VSRL_VX }, // 7277
  { PseudoVSRL_VX_MF2, VSRL_VX }, // 7278
  { PseudoVSRL_VX_MF2_MASK, VSRL_VX }, // 7279
  { PseudoVSRL_VX_MF4, VSRL_VX }, // 7280
  { PseudoVSRL_VX_MF4_MASK, VSRL_VX }, // 7281
  { PseudoVSRL_VX_MF8, VSRL_VX }, // 7282
  { PseudoVSRL_VX_MF8_MASK, VSRL_VX }, // 7283
  { PseudoVSSE16_V_M1, VSSE16_V }, // 7284
  { PseudoVSSE16_V_M1_MASK, VSSE16_V }, // 7285
  { PseudoVSSE16_V_M2, VSSE16_V }, // 7286
  { PseudoVSSE16_V_M2_MASK, VSSE16_V }, // 7287
  { PseudoVSSE16_V_M4, VSSE16_V }, // 7288
  { PseudoVSSE16_V_M4_MASK, VSSE16_V }, // 7289
  { PseudoVSSE16_V_M8, VSSE16_V }, // 7290
  { PseudoVSSE16_V_M8_MASK, VSSE16_V }, // 7291
  { PseudoVSSE16_V_MF2, VSSE16_V }, // 7292
  { PseudoVSSE16_V_MF2_MASK, VSSE16_V }, // 7293
  { PseudoVSSE16_V_MF4, VSSE16_V }, // 7294
  { PseudoVSSE16_V_MF4_MASK, VSSE16_V }, // 7295
  { PseudoVSSE32_V_M1, VSSE32_V }, // 7296
  { PseudoVSSE32_V_M1_MASK, VSSE32_V }, // 7297
  { PseudoVSSE32_V_M2, VSSE32_V }, // 7298
  { PseudoVSSE32_V_M2_MASK, VSSE32_V }, // 7299
  { PseudoVSSE32_V_M4, VSSE32_V }, // 7300
  { PseudoVSSE32_V_M4_MASK, VSSE32_V }, // 7301
  { PseudoVSSE32_V_M8, VSSE32_V }, // 7302
  { PseudoVSSE32_V_M8_MASK, VSSE32_V }, // 7303
  { PseudoVSSE32_V_MF2, VSSE32_V }, // 7304
  { PseudoVSSE32_V_MF2_MASK, VSSE32_V }, // 7305
  { PseudoVSSE64_V_M1, VSSE64_V }, // 7306
  { PseudoVSSE64_V_M1_MASK, VSSE64_V }, // 7307
  { PseudoVSSE64_V_M2, VSSE64_V }, // 7308
  { PseudoVSSE64_V_M2_MASK, VSSE64_V }, // 7309
  { PseudoVSSE64_V_M4, VSSE64_V }, // 7310
  { PseudoVSSE64_V_M4_MASK, VSSE64_V }, // 7311
  { PseudoVSSE64_V_M8, VSSE64_V }, // 7312
  { PseudoVSSE64_V_M8_MASK, VSSE64_V }, // 7313
  { PseudoVSSE8_V_M1, VSSE8_V }, // 7314
  { PseudoVSSE8_V_M1_MASK, VSSE8_V }, // 7315
  { PseudoVSSE8_V_M2, VSSE8_V }, // 7316
  { PseudoVSSE8_V_M2_MASK, VSSE8_V }, // 7317
  { PseudoVSSE8_V_M4, VSSE8_V }, // 7318
  { PseudoVSSE8_V_M4_MASK, VSSE8_V }, // 7319
  { PseudoVSSE8_V_M8, VSSE8_V }, // 7320
  { PseudoVSSE8_V_M8_MASK, VSSE8_V }, // 7321
  { PseudoVSSE8_V_MF2, VSSE8_V }, // 7322
  { PseudoVSSE8_V_MF2_MASK, VSSE8_V }, // 7323
  { PseudoVSSE8_V_MF4, VSSE8_V }, // 7324
  { PseudoVSSE8_V_MF4_MASK, VSSE8_V }, // 7325
  { PseudoVSSE8_V_MF8, VSSE8_V }, // 7326
  { PseudoVSSE8_V_MF8_MASK, VSSE8_V }, // 7327
  { PseudoVSSEG2E16_V_M1, VSSEG2E16_V }, // 7328
  { PseudoVSSEG2E16_V_M1_MASK, VSSEG2E16_V }, // 7329
  { PseudoVSSEG2E16_V_M2, VSSEG2E16_V }, // 7330
  { PseudoVSSEG2E16_V_M2_MASK, VSSEG2E16_V }, // 7331
  { PseudoVSSEG2E16_V_M4, VSSEG2E16_V }, // 7332
  { PseudoVSSEG2E16_V_M4_MASK, VSSEG2E16_V }, // 7333
  { PseudoVSSEG2E16_V_MF2, VSSEG2E16_V }, // 7334
  { PseudoVSSEG2E16_V_MF2_MASK, VSSEG2E16_V }, // 7335
  { PseudoVSSEG2E16_V_MF4, VSSEG2E16_V }, // 7336
  { PseudoVSSEG2E16_V_MF4_MASK, VSSEG2E16_V }, // 7337
  { PseudoVSSEG2E32_V_M1, VSSEG2E32_V }, // 7338
  { PseudoVSSEG2E32_V_M1_MASK, VSSEG2E32_V }, // 7339
  { PseudoVSSEG2E32_V_M2, VSSEG2E32_V }, // 7340
  { PseudoVSSEG2E32_V_M2_MASK, VSSEG2E32_V }, // 7341
  { PseudoVSSEG2E32_V_M4, VSSEG2E32_V }, // 7342
  { PseudoVSSEG2E32_V_M4_MASK, VSSEG2E32_V }, // 7343
  { PseudoVSSEG2E32_V_MF2, VSSEG2E32_V }, // 7344
  { PseudoVSSEG2E32_V_MF2_MASK, VSSEG2E32_V }, // 7345
  { PseudoVSSEG2E64_V_M1, VSSEG2E64_V }, // 7346
  { PseudoVSSEG2E64_V_M1_MASK, VSSEG2E64_V }, // 7347
  { PseudoVSSEG2E64_V_M2, VSSEG2E64_V }, // 7348
  { PseudoVSSEG2E64_V_M2_MASK, VSSEG2E64_V }, // 7349
  { PseudoVSSEG2E64_V_M4, VSSEG2E64_V }, // 7350
  { PseudoVSSEG2E64_V_M4_MASK, VSSEG2E64_V }, // 7351
  { PseudoVSSEG2E8_V_M1, VSSEG2E8_V }, // 7352
  { PseudoVSSEG2E8_V_M1_MASK, VSSEG2E8_V }, // 7353
  { PseudoVSSEG2E8_V_M2, VSSEG2E8_V }, // 7354
  { PseudoVSSEG2E8_V_M2_MASK, VSSEG2E8_V }, // 7355
  { PseudoVSSEG2E8_V_M4, VSSEG2E8_V }, // 7356
  { PseudoVSSEG2E8_V_M4_MASK, VSSEG2E8_V }, // 7357
  { PseudoVSSEG2E8_V_MF2, VSSEG2E8_V }, // 7358
  { PseudoVSSEG2E8_V_MF2_MASK, VSSEG2E8_V }, // 7359
  { PseudoVSSEG2E8_V_MF4, VSSEG2E8_V }, // 7360
  { PseudoVSSEG2E8_V_MF4_MASK, VSSEG2E8_V }, // 7361
  { PseudoVSSEG2E8_V_MF8, VSSEG2E8_V }, // 7362
  { PseudoVSSEG2E8_V_MF8_MASK, VSSEG2E8_V }, // 7363
  { PseudoVSSEG3E16_V_M1, VSSEG3E16_V }, // 7364
  { PseudoVSSEG3E16_V_M1_MASK, VSSEG3E16_V }, // 7365
  { PseudoVSSEG3E16_V_M2, VSSEG3E16_V }, // 7366
  { PseudoVSSEG3E16_V_M2_MASK, VSSEG3E16_V }, // 7367
  { PseudoVSSEG3E16_V_MF2, VSSEG3E16_V }, // 7368
  { PseudoVSSEG3E16_V_MF2_MASK, VSSEG3E16_V }, // 7369
  { PseudoVSSEG3E16_V_MF4, VSSEG3E16_V }, // 7370
  { PseudoVSSEG3E16_V_MF4_MASK, VSSEG3E16_V }, // 7371
  { PseudoVSSEG3E32_V_M1, VSSEG3E32_V }, // 7372
  { PseudoVSSEG3E32_V_M1_MASK, VSSEG3E32_V }, // 7373
  { PseudoVSSEG3E32_V_M2, VSSEG3E32_V }, // 7374
  { PseudoVSSEG3E32_V_M2_MASK, VSSEG3E32_V }, // 7375
  { PseudoVSSEG3E32_V_MF2, VSSEG3E32_V }, // 7376
  { PseudoVSSEG3E32_V_MF2_MASK, VSSEG3E32_V }, // 7377
  { PseudoVSSEG3E64_V_M1, VSSEG3E64_V }, // 7378
  { PseudoVSSEG3E64_V_M1_MASK, VSSEG3E64_V }, // 7379
  { PseudoVSSEG3E64_V_M2, VSSEG3E64_V }, // 7380
  { PseudoVSSEG3E64_V_M2_MASK, VSSEG3E64_V }, // 7381
  { PseudoVSSEG3E8_V_M1, VSSEG3E8_V }, // 7382
  { PseudoVSSEG3E8_V_M1_MASK, VSSEG3E8_V }, // 7383
  { PseudoVSSEG3E8_V_M2, VSSEG3E8_V }, // 7384
  { PseudoVSSEG3E8_V_M2_MASK, VSSEG3E8_V }, // 7385
  { PseudoVSSEG3E8_V_MF2, VSSEG3E8_V }, // 7386
  { PseudoVSSEG3E8_V_MF2_MASK, VSSEG3E8_V }, // 7387
  { PseudoVSSEG3E8_V_MF4, VSSEG3E8_V }, // 7388
  { PseudoVSSEG3E8_V_MF4_MASK, VSSEG3E8_V }, // 7389
  { PseudoVSSEG3E8_V_MF8, VSSEG3E8_V }, // 7390
  { PseudoVSSEG3E8_V_MF8_MASK, VSSEG3E8_V }, // 7391
  { PseudoVSSEG4E16_V_M1, VSSEG4E16_V }, // 7392
  { PseudoVSSEG4E16_V_M1_MASK, VSSEG4E16_V }, // 7393
  { PseudoVSSEG4E16_V_M2, VSSEG4E16_V }, // 7394
  { PseudoVSSEG4E16_V_M2_MASK, VSSEG4E16_V }, // 7395
  { PseudoVSSEG4E16_V_MF2, VSSEG4E16_V }, // 7396
  { PseudoVSSEG4E16_V_MF2_MASK, VSSEG4E16_V }, // 7397
  { PseudoVSSEG4E16_V_MF4, VSSEG4E16_V }, // 7398
  { PseudoVSSEG4E16_V_MF4_MASK, VSSEG4E16_V }, // 7399
  { PseudoVSSEG4E32_V_M1, VSSEG4E32_V }, // 7400
  { PseudoVSSEG4E32_V_M1_MASK, VSSEG4E32_V }, // 7401
  { PseudoVSSEG4E32_V_M2, VSSEG4E32_V }, // 7402
  { PseudoVSSEG4E32_V_M2_MASK, VSSEG4E32_V }, // 7403
  { PseudoVSSEG4E32_V_MF2, VSSEG4E32_V }, // 7404
  { PseudoVSSEG4E32_V_MF2_MASK, VSSEG4E32_V }, // 7405
  { PseudoVSSEG4E64_V_M1, VSSEG4E64_V }, // 7406
  { PseudoVSSEG4E64_V_M1_MASK, VSSEG4E64_V }, // 7407
  { PseudoVSSEG4E64_V_M2, VSSEG4E64_V }, // 7408
  { PseudoVSSEG4E64_V_M2_MASK, VSSEG4E64_V }, // 7409
  { PseudoVSSEG4E8_V_M1, VSSEG4E8_V }, // 7410
  { PseudoVSSEG4E8_V_M1_MASK, VSSEG4E8_V }, // 7411
  { PseudoVSSEG4E8_V_M2, VSSEG4E8_V }, // 7412
  { PseudoVSSEG4E8_V_M2_MASK, VSSEG4E8_V }, // 7413
  { PseudoVSSEG4E8_V_MF2, VSSEG4E8_V }, // 7414
  { PseudoVSSEG4E8_V_MF2_MASK, VSSEG4E8_V }, // 7415
  { PseudoVSSEG4E8_V_MF4, VSSEG4E8_V }, // 7416
  { PseudoVSSEG4E8_V_MF4_MASK, VSSEG4E8_V }, // 7417
  { PseudoVSSEG4E8_V_MF8, VSSEG4E8_V }, // 7418
  { PseudoVSSEG4E8_V_MF8_MASK, VSSEG4E8_V }, // 7419
  { PseudoVSSEG5E16_V_M1, VSSEG5E16_V }, // 7420
  { PseudoVSSEG5E16_V_M1_MASK, VSSEG5E16_V }, // 7421
  { PseudoVSSEG5E16_V_MF2, VSSEG5E16_V }, // 7422
  { PseudoVSSEG5E16_V_MF2_MASK, VSSEG5E16_V }, // 7423
  { PseudoVSSEG5E16_V_MF4, VSSEG5E16_V }, // 7424
  { PseudoVSSEG5E16_V_MF4_MASK, VSSEG5E16_V }, // 7425
  { PseudoVSSEG5E32_V_M1, VSSEG5E32_V }, // 7426
  { PseudoVSSEG5E32_V_M1_MASK, VSSEG5E32_V }, // 7427
  { PseudoVSSEG5E32_V_MF2, VSSEG5E32_V }, // 7428
  { PseudoVSSEG5E32_V_MF2_MASK, VSSEG5E32_V }, // 7429
  { PseudoVSSEG5E64_V_M1, VSSEG5E64_V }, // 7430
  { PseudoVSSEG5E64_V_M1_MASK, VSSEG5E64_V }, // 7431
  { PseudoVSSEG5E8_V_M1, VSSEG5E8_V }, // 7432
  { PseudoVSSEG5E8_V_M1_MASK, VSSEG5E8_V }, // 7433
  { PseudoVSSEG5E8_V_MF2, VSSEG5E8_V }, // 7434
  { PseudoVSSEG5E8_V_MF2_MASK, VSSEG5E8_V }, // 7435
  { PseudoVSSEG5E8_V_MF4, VSSEG5E8_V }, // 7436
  { PseudoVSSEG5E8_V_MF4_MASK, VSSEG5E8_V }, // 7437
  { PseudoVSSEG5E8_V_MF8, VSSEG5E8_V }, // 7438
  { PseudoVSSEG5E8_V_MF8_MASK, VSSEG5E8_V }, // 7439
  { PseudoVSSEG6E16_V_M1, VSSEG6E16_V }, // 7440
  { PseudoVSSEG6E16_V_M1_MASK, VSSEG6E16_V }, // 7441
  { PseudoVSSEG6E16_V_MF2, VSSEG6E16_V }, // 7442
  { PseudoVSSEG6E16_V_MF2_MASK, VSSEG6E16_V }, // 7443
  { PseudoVSSEG6E16_V_MF4, VSSEG6E16_V }, // 7444
  { PseudoVSSEG6E16_V_MF4_MASK, VSSEG6E16_V }, // 7445
  { PseudoVSSEG6E32_V_M1, VSSEG6E32_V }, // 7446
  { PseudoVSSEG6E32_V_M1_MASK, VSSEG6E32_V }, // 7447
  { PseudoVSSEG6E32_V_MF2, VSSEG6E32_V }, // 7448
  { PseudoVSSEG6E32_V_MF2_MASK, VSSEG6E32_V }, // 7449
  { PseudoVSSEG6E64_V_M1, VSSEG6E64_V }, // 7450
  { PseudoVSSEG6E64_V_M1_MASK, VSSEG6E64_V }, // 7451
  { PseudoVSSEG6E8_V_M1, VSSEG6E8_V }, // 7452
  { PseudoVSSEG6E8_V_M1_MASK, VSSEG6E8_V }, // 7453
  { PseudoVSSEG6E8_V_MF2, VSSEG6E8_V }, // 7454
  { PseudoVSSEG6E8_V_MF2_MASK, VSSEG6E8_V }, // 7455
  { PseudoVSSEG6E8_V_MF4, VSSEG6E8_V }, // 7456
  { PseudoVSSEG6E8_V_MF4_MASK, VSSEG6E8_V }, // 7457
  { PseudoVSSEG6E8_V_MF8, VSSEG6E8_V }, // 7458
  { PseudoVSSEG6E8_V_MF8_MASK, VSSEG6E8_V }, // 7459
  { PseudoVSSEG7E16_V_M1, VSSEG7E16_V }, // 7460
  { PseudoVSSEG7E16_V_M1_MASK, VSSEG7E16_V }, // 7461
  { PseudoVSSEG7E16_V_MF2, VSSEG7E16_V }, // 7462
  { PseudoVSSEG7E16_V_MF2_MASK, VSSEG7E16_V }, // 7463
  { PseudoVSSEG7E16_V_MF4, VSSEG7E16_V }, // 7464
  { PseudoVSSEG7E16_V_MF4_MASK, VSSEG7E16_V }, // 7465
  { PseudoVSSEG7E32_V_M1, VSSEG7E32_V }, // 7466
  { PseudoVSSEG7E32_V_M1_MASK, VSSEG7E32_V }, // 7467
  { PseudoVSSEG7E32_V_MF2, VSSEG7E32_V }, // 7468
  { PseudoVSSEG7E32_V_MF2_MASK, VSSEG7E32_V }, // 7469
  { PseudoVSSEG7E64_V_M1, VSSEG7E64_V }, // 7470
  { PseudoVSSEG7E64_V_M1_MASK, VSSEG7E64_V }, // 7471
  { PseudoVSSEG7E8_V_M1, VSSEG7E8_V }, // 7472
  { PseudoVSSEG7E8_V_M1_MASK, VSSEG7E8_V }, // 7473
  { PseudoVSSEG7E8_V_MF2, VSSEG7E8_V }, // 7474
  { PseudoVSSEG7E8_V_MF2_MASK, VSSEG7E8_V }, // 7475
  { PseudoVSSEG7E8_V_MF4, VSSEG7E8_V }, // 7476
  { PseudoVSSEG7E8_V_MF4_MASK, VSSEG7E8_V }, // 7477
  { PseudoVSSEG7E8_V_MF8, VSSEG7E8_V }, // 7478
  { PseudoVSSEG7E8_V_MF8_MASK, VSSEG7E8_V }, // 7479
  { PseudoVSSEG8E16_V_M1, VSSEG8E16_V }, // 7480
  { PseudoVSSEG8E16_V_M1_MASK, VSSEG8E16_V }, // 7481
  { PseudoVSSEG8E16_V_MF2, VSSEG8E16_V }, // 7482
  { PseudoVSSEG8E16_V_MF2_MASK, VSSEG8E16_V }, // 7483
  { PseudoVSSEG8E16_V_MF4, VSSEG8E16_V }, // 7484
  { PseudoVSSEG8E16_V_MF4_MASK, VSSEG8E16_V }, // 7485
  { PseudoVSSEG8E32_V_M1, VSSEG8E32_V }, // 7486
  { PseudoVSSEG8E32_V_M1_MASK, VSSEG8E32_V }, // 7487
  { PseudoVSSEG8E32_V_MF2, VSSEG8E32_V }, // 7488
  { PseudoVSSEG8E32_V_MF2_MASK, VSSEG8E32_V }, // 7489
  { PseudoVSSEG8E64_V_M1, VSSEG8E64_V }, // 7490
  { PseudoVSSEG8E64_V_M1_MASK, VSSEG8E64_V }, // 7491
  { PseudoVSSEG8E8_V_M1, VSSEG8E8_V }, // 7492
  { PseudoVSSEG8E8_V_M1_MASK, VSSEG8E8_V }, // 7493
  { PseudoVSSEG8E8_V_MF2, VSSEG8E8_V }, // 7494
  { PseudoVSSEG8E8_V_MF2_MASK, VSSEG8E8_V }, // 7495
  { PseudoVSSEG8E8_V_MF4, VSSEG8E8_V }, // 7496
  { PseudoVSSEG8E8_V_MF4_MASK, VSSEG8E8_V }, // 7497
  { PseudoVSSEG8E8_V_MF8, VSSEG8E8_V }, // 7498
  { PseudoVSSEG8E8_V_MF8_MASK, VSSEG8E8_V }, // 7499
  { PseudoVSSRA_VI_M1, VSSRA_VI }, // 7500
  { PseudoVSSRA_VI_M1_MASK, VSSRA_VI }, // 7501
  { PseudoVSSRA_VI_M2, VSSRA_VI }, // 7502
  { PseudoVSSRA_VI_M2_MASK, VSSRA_VI }, // 7503
  { PseudoVSSRA_VI_M4, VSSRA_VI }, // 7504
  { PseudoVSSRA_VI_M4_MASK, VSSRA_VI }, // 7505
  { PseudoVSSRA_VI_M8, VSSRA_VI }, // 7506
  { PseudoVSSRA_VI_M8_MASK, VSSRA_VI }, // 7507
  { PseudoVSSRA_VI_MF2, VSSRA_VI }, // 7508
  { PseudoVSSRA_VI_MF2_MASK, VSSRA_VI }, // 7509
  { PseudoVSSRA_VI_MF4, VSSRA_VI }, // 7510
  { PseudoVSSRA_VI_MF4_MASK, VSSRA_VI }, // 7511
  { PseudoVSSRA_VI_MF8, VSSRA_VI }, // 7512
  { PseudoVSSRA_VI_MF8_MASK, VSSRA_VI }, // 7513
  { PseudoVSSRA_VV_M1, VSSRA_VV }, // 7514
  { PseudoVSSRA_VV_M1_MASK, VSSRA_VV }, // 7515
  { PseudoVSSRA_VV_M2, VSSRA_VV }, // 7516
  { PseudoVSSRA_VV_M2_MASK, VSSRA_VV }, // 7517
  { PseudoVSSRA_VV_M4, VSSRA_VV }, // 7518
  { PseudoVSSRA_VV_M4_MASK, VSSRA_VV }, // 7519
  { PseudoVSSRA_VV_M8, VSSRA_VV }, // 7520
  { PseudoVSSRA_VV_M8_MASK, VSSRA_VV }, // 7521
  { PseudoVSSRA_VV_MF2, VSSRA_VV }, // 7522
  { PseudoVSSRA_VV_MF2_MASK, VSSRA_VV }, // 7523
  { PseudoVSSRA_VV_MF4, VSSRA_VV }, // 7524
  { PseudoVSSRA_VV_MF4_MASK, VSSRA_VV }, // 7525
  { PseudoVSSRA_VV_MF8, VSSRA_VV }, // 7526
  { PseudoVSSRA_VV_MF8_MASK, VSSRA_VV }, // 7527
  { PseudoVSSRA_VX_M1, VSSRA_VX }, // 7528
  { PseudoVSSRA_VX_M1_MASK, VSSRA_VX }, // 7529
  { PseudoVSSRA_VX_M2, VSSRA_VX }, // 7530
  { PseudoVSSRA_VX_M2_MASK, VSSRA_VX }, // 7531
  { PseudoVSSRA_VX_M4, VSSRA_VX }, // 7532
  { PseudoVSSRA_VX_M4_MASK, VSSRA_VX }, // 7533
  { PseudoVSSRA_VX_M8, VSSRA_VX }, // 7534
  { PseudoVSSRA_VX_M8_MASK, VSSRA_VX }, // 7535
  { PseudoVSSRA_VX_MF2, VSSRA_VX }, // 7536
  { PseudoVSSRA_VX_MF2_MASK, VSSRA_VX }, // 7537
  { PseudoVSSRA_VX_MF4, VSSRA_VX }, // 7538
  { PseudoVSSRA_VX_MF4_MASK, VSSRA_VX }, // 7539
  { PseudoVSSRA_VX_MF8, VSSRA_VX }, // 7540
  { PseudoVSSRA_VX_MF8_MASK, VSSRA_VX }, // 7541
  { PseudoVSSRL_VI_M1, VSSRL_VI }, // 7542
  { PseudoVSSRL_VI_M1_MASK, VSSRL_VI }, // 7543
  { PseudoVSSRL_VI_M2, VSSRL_VI }, // 7544
  { PseudoVSSRL_VI_M2_MASK, VSSRL_VI }, // 7545
  { PseudoVSSRL_VI_M4, VSSRL_VI }, // 7546
  { PseudoVSSRL_VI_M4_MASK, VSSRL_VI }, // 7547
  { PseudoVSSRL_VI_M8, VSSRL_VI }, // 7548
  { PseudoVSSRL_VI_M8_MASK, VSSRL_VI }, // 7549
  { PseudoVSSRL_VI_MF2, VSSRL_VI }, // 7550
  { PseudoVSSRL_VI_MF2_MASK, VSSRL_VI }, // 7551
  { PseudoVSSRL_VI_MF4, VSSRL_VI }, // 7552
  { PseudoVSSRL_VI_MF4_MASK, VSSRL_VI }, // 7553
  { PseudoVSSRL_VI_MF8, VSSRL_VI }, // 7554
  { PseudoVSSRL_VI_MF8_MASK, VSSRL_VI }, // 7555
  { PseudoVSSRL_VV_M1, VSSRL_VV }, // 7556
  { PseudoVSSRL_VV_M1_MASK, VSSRL_VV }, // 7557
  { PseudoVSSRL_VV_M2, VSSRL_VV }, // 7558
  { PseudoVSSRL_VV_M2_MASK, VSSRL_VV }, // 7559
  { PseudoVSSRL_VV_M4, VSSRL_VV }, // 7560
  { PseudoVSSRL_VV_M4_MASK, VSSRL_VV }, // 7561
  { PseudoVSSRL_VV_M8, VSSRL_VV }, // 7562
  { PseudoVSSRL_VV_M8_MASK, VSSRL_VV }, // 7563
  { PseudoVSSRL_VV_MF2, VSSRL_VV }, // 7564
  { PseudoVSSRL_VV_MF2_MASK, VSSRL_VV }, // 7565
  { PseudoVSSRL_VV_MF4, VSSRL_VV }, // 7566
  { PseudoVSSRL_VV_MF4_MASK, VSSRL_VV }, // 7567
  { PseudoVSSRL_VV_MF8, VSSRL_VV }, // 7568
  { PseudoVSSRL_VV_MF8_MASK, VSSRL_VV }, // 7569
  { PseudoVSSRL_VX_M1, VSSRL_VX }, // 7570
  { PseudoVSSRL_VX_M1_MASK, VSSRL_VX }, // 7571
  { PseudoVSSRL_VX_M2, VSSRL_VX }, // 7572
  { PseudoVSSRL_VX_M2_MASK, VSSRL_VX }, // 7573
  { PseudoVSSRL_VX_M4, VSSRL_VX }, // 7574
  { PseudoVSSRL_VX_M4_MASK, VSSRL_VX }, // 7575
  { PseudoVSSRL_VX_M8, VSSRL_VX }, // 7576
  { PseudoVSSRL_VX_M8_MASK, VSSRL_VX }, // 7577
  { PseudoVSSRL_VX_MF2, VSSRL_VX }, // 7578
  { PseudoVSSRL_VX_MF2_MASK, VSSRL_VX }, // 7579
  { PseudoVSSRL_VX_MF4, VSSRL_VX }, // 7580
  { PseudoVSSRL_VX_MF4_MASK, VSSRL_VX }, // 7581
  { PseudoVSSRL_VX_MF8, VSSRL_VX }, // 7582
  { PseudoVSSRL_VX_MF8_MASK, VSSRL_VX }, // 7583
  { PseudoVSSSEG2E16_V_M1, VSSSEG2E16_V }, // 7584
  { PseudoVSSSEG2E16_V_M1_MASK, VSSSEG2E16_V }, // 7585
  { PseudoVSSSEG2E16_V_M2, VSSSEG2E16_V }, // 7586
  { PseudoVSSSEG2E16_V_M2_MASK, VSSSEG2E16_V }, // 7587
  { PseudoVSSSEG2E16_V_M4, VSSSEG2E16_V }, // 7588
  { PseudoVSSSEG2E16_V_M4_MASK, VSSSEG2E16_V }, // 7589
  { PseudoVSSSEG2E16_V_MF2, VSSSEG2E16_V }, // 7590
  { PseudoVSSSEG2E16_V_MF2_MASK, VSSSEG2E16_V }, // 7591
  { PseudoVSSSEG2E16_V_MF4, VSSSEG2E16_V }, // 7592
  { PseudoVSSSEG2E16_V_MF4_MASK, VSSSEG2E16_V }, // 7593
  { PseudoVSSSEG2E32_V_M1, VSSSEG2E32_V }, // 7594
  { PseudoVSSSEG2E32_V_M1_MASK, VSSSEG2E32_V }, // 7595
  { PseudoVSSSEG2E32_V_M2, VSSSEG2E32_V }, // 7596
  { PseudoVSSSEG2E32_V_M2_MASK, VSSSEG2E32_V }, // 7597
  { PseudoVSSSEG2E32_V_M4, VSSSEG2E32_V }, // 7598
  { PseudoVSSSEG2E32_V_M4_MASK, VSSSEG2E32_V }, // 7599
  { PseudoVSSSEG2E32_V_MF2, VSSSEG2E32_V }, // 7600
  { PseudoVSSSEG2E32_V_MF2_MASK, VSSSEG2E32_V }, // 7601
  { PseudoVSSSEG2E64_V_M1, VSSSEG2E64_V }, // 7602
  { PseudoVSSSEG2E64_V_M1_MASK, VSSSEG2E64_V }, // 7603
  { PseudoVSSSEG2E64_V_M2, VSSSEG2E64_V }, // 7604
  { PseudoVSSSEG2E64_V_M2_MASK, VSSSEG2E64_V }, // 7605
  { PseudoVSSSEG2E64_V_M4, VSSSEG2E64_V }, // 7606
  { PseudoVSSSEG2E64_V_M4_MASK, VSSSEG2E64_V }, // 7607
  { PseudoVSSSEG2E8_V_M1, VSSSEG2E8_V }, // 7608
  { PseudoVSSSEG2E8_V_M1_MASK, VSSSEG2E8_V }, // 7609
  { PseudoVSSSEG2E8_V_M2, VSSSEG2E8_V }, // 7610
  { PseudoVSSSEG2E8_V_M2_MASK, VSSSEG2E8_V }, // 7611
  { PseudoVSSSEG2E8_V_M4, VSSSEG2E8_V }, // 7612
  { PseudoVSSSEG2E8_V_M4_MASK, VSSSEG2E8_V }, // 7613
  { PseudoVSSSEG2E8_V_MF2, VSSSEG2E8_V }, // 7614
  { PseudoVSSSEG2E8_V_MF2_MASK, VSSSEG2E8_V }, // 7615
  { PseudoVSSSEG2E8_V_MF4, VSSSEG2E8_V }, // 7616
  { PseudoVSSSEG2E8_V_MF4_MASK, VSSSEG2E8_V }, // 7617
  { PseudoVSSSEG2E8_V_MF8, VSSSEG2E8_V }, // 7618
  { PseudoVSSSEG2E8_V_MF8_MASK, VSSSEG2E8_V }, // 7619
  { PseudoVSSSEG3E16_V_M1, VSSSEG3E16_V }, // 7620
  { PseudoVSSSEG3E16_V_M1_MASK, VSSSEG3E16_V }, // 7621
  { PseudoVSSSEG3E16_V_M2, VSSSEG3E16_V }, // 7622
  { PseudoVSSSEG3E16_V_M2_MASK, VSSSEG3E16_V }, // 7623
  { PseudoVSSSEG3E16_V_MF2, VSSSEG3E16_V }, // 7624
  { PseudoVSSSEG3E16_V_MF2_MASK, VSSSEG3E16_V }, // 7625
  { PseudoVSSSEG3E16_V_MF4, VSSSEG3E16_V }, // 7626
  { PseudoVSSSEG3E16_V_MF4_MASK, VSSSEG3E16_V }, // 7627
  { PseudoVSSSEG3E32_V_M1, VSSSEG3E32_V }, // 7628
  { PseudoVSSSEG3E32_V_M1_MASK, VSSSEG3E32_V }, // 7629
  { PseudoVSSSEG3E32_V_M2, VSSSEG3E32_V }, // 7630
  { PseudoVSSSEG3E32_V_M2_MASK, VSSSEG3E32_V }, // 7631
  { PseudoVSSSEG3E32_V_MF2, VSSSEG3E32_V }, // 7632
  { PseudoVSSSEG3E32_V_MF2_MASK, VSSSEG3E32_V }, // 7633
  { PseudoVSSSEG3E64_V_M1, VSSSEG3E64_V }, // 7634
  { PseudoVSSSEG3E64_V_M1_MASK, VSSSEG3E64_V }, // 7635
  { PseudoVSSSEG3E64_V_M2, VSSSEG3E64_V }, // 7636
  { PseudoVSSSEG3E64_V_M2_MASK, VSSSEG3E64_V }, // 7637
  { PseudoVSSSEG3E8_V_M1, VSSSEG3E8_V }, // 7638
  { PseudoVSSSEG3E8_V_M1_MASK, VSSSEG3E8_V }, // 7639
  { PseudoVSSSEG3E8_V_M2, VSSSEG3E8_V }, // 7640
  { PseudoVSSSEG3E8_V_M2_MASK, VSSSEG3E8_V }, // 7641
  { PseudoVSSSEG3E8_V_MF2, VSSSEG3E8_V }, // 7642
  { PseudoVSSSEG3E8_V_MF2_MASK, VSSSEG3E8_V }, // 7643
  { PseudoVSSSEG3E8_V_MF4, VSSSEG3E8_V }, // 7644
  { PseudoVSSSEG3E8_V_MF4_MASK, VSSSEG3E8_V }, // 7645
  { PseudoVSSSEG3E8_V_MF8, VSSSEG3E8_V }, // 7646
  { PseudoVSSSEG3E8_V_MF8_MASK, VSSSEG3E8_V }, // 7647
  { PseudoVSSSEG4E16_V_M1, VSSSEG4E16_V }, // 7648
  { PseudoVSSSEG4E16_V_M1_MASK, VSSSEG4E16_V }, // 7649
  { PseudoVSSSEG4E16_V_M2, VSSSEG4E16_V }, // 7650
  { PseudoVSSSEG4E16_V_M2_MASK, VSSSEG4E16_V }, // 7651
  { PseudoVSSSEG4E16_V_MF2, VSSSEG4E16_V }, // 7652
  { PseudoVSSSEG4E16_V_MF2_MASK, VSSSEG4E16_V }, // 7653
  { PseudoVSSSEG4E16_V_MF4, VSSSEG4E16_V }, // 7654
  { PseudoVSSSEG4E16_V_MF4_MASK, VSSSEG4E16_V }, // 7655
  { PseudoVSSSEG4E32_V_M1, VSSSEG4E32_V }, // 7656
  { PseudoVSSSEG4E32_V_M1_MASK, VSSSEG4E32_V }, // 7657
  { PseudoVSSSEG4E32_V_M2, VSSSEG4E32_V }, // 7658
  { PseudoVSSSEG4E32_V_M2_MASK, VSSSEG4E32_V }, // 7659
  { PseudoVSSSEG4E32_V_MF2, VSSSEG4E32_V }, // 7660
  { PseudoVSSSEG4E32_V_MF2_MASK, VSSSEG4E32_V }, // 7661
  { PseudoVSSSEG4E64_V_M1, VSSSEG4E64_V }, // 7662
  { PseudoVSSSEG4E64_V_M1_MASK, VSSSEG4E64_V }, // 7663
  { PseudoVSSSEG4E64_V_M2, VSSSEG4E64_V }, // 7664
  { PseudoVSSSEG4E64_V_M2_MASK, VSSSEG4E64_V }, // 7665
  { PseudoVSSSEG4E8_V_M1, VSSSEG4E8_V }, // 7666
  { PseudoVSSSEG4E8_V_M1_MASK, VSSSEG4E8_V }, // 7667
  { PseudoVSSSEG4E8_V_M2, VSSSEG4E8_V }, // 7668
  { PseudoVSSSEG4E8_V_M2_MASK, VSSSEG4E8_V }, // 7669
  { PseudoVSSSEG4E8_V_MF2, VSSSEG4E8_V }, // 7670
  { PseudoVSSSEG4E8_V_MF2_MASK, VSSSEG4E8_V }, // 7671
  { PseudoVSSSEG4E8_V_MF4, VSSSEG4E8_V }, // 7672
  { PseudoVSSSEG4E8_V_MF4_MASK, VSSSEG4E8_V }, // 7673
  { PseudoVSSSEG4E8_V_MF8, VSSSEG4E8_V }, // 7674
  { PseudoVSSSEG4E8_V_MF8_MASK, VSSSEG4E8_V }, // 7675
  { PseudoVSSSEG5E16_V_M1, VSSSEG5E16_V }, // 7676
  { PseudoVSSSEG5E16_V_M1_MASK, VSSSEG5E16_V }, // 7677
  { PseudoVSSSEG5E16_V_MF2, VSSSEG5E16_V }, // 7678
  { PseudoVSSSEG5E16_V_MF2_MASK, VSSSEG5E16_V }, // 7679
  { PseudoVSSSEG5E16_V_MF4, VSSSEG5E16_V }, // 7680
  { PseudoVSSSEG5E16_V_MF4_MASK, VSSSEG5E16_V }, // 7681
  { PseudoVSSSEG5E32_V_M1, VSSSEG5E32_V }, // 7682
  { PseudoVSSSEG5E32_V_M1_MASK, VSSSEG5E32_V }, // 7683
  { PseudoVSSSEG5E32_V_MF2, VSSSEG5E32_V }, // 7684
  { PseudoVSSSEG5E32_V_MF2_MASK, VSSSEG5E32_V }, // 7685
  { PseudoVSSSEG5E64_V_M1, VSSSEG5E64_V }, // 7686
  { PseudoVSSSEG5E64_V_M1_MASK, VSSSEG5E64_V }, // 7687
  { PseudoVSSSEG5E8_V_M1, VSSSEG5E8_V }, // 7688
  { PseudoVSSSEG5E8_V_M1_MASK, VSSSEG5E8_V }, // 7689
  { PseudoVSSSEG5E8_V_MF2, VSSSEG5E8_V }, // 7690
  { PseudoVSSSEG5E8_V_MF2_MASK, VSSSEG5E8_V }, // 7691
  { PseudoVSSSEG5E8_V_MF4, VSSSEG5E8_V }, // 7692
  { PseudoVSSSEG5E8_V_MF4_MASK, VSSSEG5E8_V }, // 7693
  { PseudoVSSSEG5E8_V_MF8, VSSSEG5E8_V }, // 7694
  { PseudoVSSSEG5E8_V_MF8_MASK, VSSSEG5E8_V }, // 7695
  { PseudoVSSSEG6E16_V_M1, VSSSEG6E16_V }, // 7696
  { PseudoVSSSEG6E16_V_M1_MASK, VSSSEG6E16_V }, // 7697
  { PseudoVSSSEG6E16_V_MF2, VSSSEG6E16_V }, // 7698
  { PseudoVSSSEG6E16_V_MF2_MASK, VSSSEG6E16_V }, // 7699
  { PseudoVSSSEG6E16_V_MF4, VSSSEG6E16_V }, // 7700
  { PseudoVSSSEG6E16_V_MF4_MASK, VSSSEG6E16_V }, // 7701
  { PseudoVSSSEG6E32_V_M1, VSSSEG6E32_V }, // 7702
  { PseudoVSSSEG6E32_V_M1_MASK, VSSSEG6E32_V }, // 7703
  { PseudoVSSSEG6E32_V_MF2, VSSSEG6E32_V }, // 7704
  { PseudoVSSSEG6E32_V_MF2_MASK, VSSSEG6E32_V }, // 7705
  { PseudoVSSSEG6E64_V_M1, VSSSEG6E64_V }, // 7706
  { PseudoVSSSEG6E64_V_M1_MASK, VSSSEG6E64_V }, // 7707
  { PseudoVSSSEG6E8_V_M1, VSSSEG6E8_V }, // 7708
  { PseudoVSSSEG6E8_V_M1_MASK, VSSSEG6E8_V }, // 7709
  { PseudoVSSSEG6E8_V_MF2, VSSSEG6E8_V }, // 7710
  { PseudoVSSSEG6E8_V_MF2_MASK, VSSSEG6E8_V }, // 7711
  { PseudoVSSSEG6E8_V_MF4, VSSSEG6E8_V }, // 7712
  { PseudoVSSSEG6E8_V_MF4_MASK, VSSSEG6E8_V }, // 7713
  { PseudoVSSSEG6E8_V_MF8, VSSSEG6E8_V }, // 7714
  { PseudoVSSSEG6E8_V_MF8_MASK, VSSSEG6E8_V }, // 7715
  { PseudoVSSSEG7E16_V_M1, VSSSEG7E16_V }, // 7716
  { PseudoVSSSEG7E16_V_M1_MASK, VSSSEG7E16_V }, // 7717
  { PseudoVSSSEG7E16_V_MF2, VSSSEG7E16_V }, // 7718
  { PseudoVSSSEG7E16_V_MF2_MASK, VSSSEG7E16_V }, // 7719
  { PseudoVSSSEG7E16_V_MF4, VSSSEG7E16_V }, // 7720
  { PseudoVSSSEG7E16_V_MF4_MASK, VSSSEG7E16_V }, // 7721
  { PseudoVSSSEG7E32_V_M1, VSSSEG7E32_V }, // 7722
  { PseudoVSSSEG7E32_V_M1_MASK, VSSSEG7E32_V }, // 7723
  { PseudoVSSSEG7E32_V_MF2, VSSSEG7E32_V }, // 7724
  { PseudoVSSSEG7E32_V_MF2_MASK, VSSSEG7E32_V }, // 7725
  { PseudoVSSSEG7E64_V_M1, VSSSEG7E64_V }, // 7726
  { PseudoVSSSEG7E64_V_M1_MASK, VSSSEG7E64_V }, // 7727
  { PseudoVSSSEG7E8_V_M1, VSSSEG7E8_V }, // 7728
  { PseudoVSSSEG7E8_V_M1_MASK, VSSSEG7E8_V }, // 7729
  { PseudoVSSSEG7E8_V_MF2, VSSSEG7E8_V }, // 7730
  { PseudoVSSSEG7E8_V_MF2_MASK, VSSSEG7E8_V }, // 7731
  { PseudoVSSSEG7E8_V_MF4, VSSSEG7E8_V }, // 7732
  { PseudoVSSSEG7E8_V_MF4_MASK, VSSSEG7E8_V }, // 7733
  { PseudoVSSSEG7E8_V_MF8, VSSSEG7E8_V }, // 7734
  { PseudoVSSSEG7E8_V_MF8_MASK, VSSSEG7E8_V }, // 7735
  { PseudoVSSSEG8E16_V_M1, VSSSEG8E16_V }, // 7736
  { PseudoVSSSEG8E16_V_M1_MASK, VSSSEG8E16_V }, // 7737
  { PseudoVSSSEG8E16_V_MF2, VSSSEG8E16_V }, // 7738
  { PseudoVSSSEG8E16_V_MF2_MASK, VSSSEG8E16_V }, // 7739
  { PseudoVSSSEG8E16_V_MF4, VSSSEG8E16_V }, // 7740
  { PseudoVSSSEG8E16_V_MF4_MASK, VSSSEG8E16_V }, // 7741
  { PseudoVSSSEG8E32_V_M1, VSSSEG8E32_V }, // 7742
  { PseudoVSSSEG8E32_V_M1_MASK, VSSSEG8E32_V }, // 7743
  { PseudoVSSSEG8E32_V_MF2, VSSSEG8E32_V }, // 7744
  { PseudoVSSSEG8E32_V_MF2_MASK, VSSSEG8E32_V }, // 7745
  { PseudoVSSSEG8E64_V_M1, VSSSEG8E64_V }, // 7746
  { PseudoVSSSEG8E64_V_M1_MASK, VSSSEG8E64_V }, // 7747
  { PseudoVSSSEG8E8_V_M1, VSSSEG8E8_V }, // 7748
  { PseudoVSSSEG8E8_V_M1_MASK, VSSSEG8E8_V }, // 7749
  { PseudoVSSSEG8E8_V_MF2, VSSSEG8E8_V }, // 7750
  { PseudoVSSSEG8E8_V_MF2_MASK, VSSSEG8E8_V }, // 7751
  { PseudoVSSSEG8E8_V_MF4, VSSSEG8E8_V }, // 7752
  { PseudoVSSSEG8E8_V_MF4_MASK, VSSSEG8E8_V }, // 7753
  { PseudoVSSSEG8E8_V_MF8, VSSSEG8E8_V }, // 7754
  { PseudoVSSSEG8E8_V_MF8_MASK, VSSSEG8E8_V }, // 7755
  { PseudoVSSUBU_VV_M1, VSSUBU_VV }, // 7756
  { PseudoVSSUBU_VV_M1_MASK, VSSUBU_VV }, // 7757
  { PseudoVSSUBU_VV_M2, VSSUBU_VV }, // 7758
  { PseudoVSSUBU_VV_M2_MASK, VSSUBU_VV }, // 7759
  { PseudoVSSUBU_VV_M4, VSSUBU_VV }, // 7760
  { PseudoVSSUBU_VV_M4_MASK, VSSUBU_VV }, // 7761
  { PseudoVSSUBU_VV_M8, VSSUBU_VV }, // 7762
  { PseudoVSSUBU_VV_M8_MASK, VSSUBU_VV }, // 7763
  { PseudoVSSUBU_VV_MF2, VSSUBU_VV }, // 7764
  { PseudoVSSUBU_VV_MF2_MASK, VSSUBU_VV }, // 7765
  { PseudoVSSUBU_VV_MF4, VSSUBU_VV }, // 7766
  { PseudoVSSUBU_VV_MF4_MASK, VSSUBU_VV }, // 7767
  { PseudoVSSUBU_VV_MF8, VSSUBU_VV }, // 7768
  { PseudoVSSUBU_VV_MF8_MASK, VSSUBU_VV }, // 7769
  { PseudoVSSUBU_VX_M1, VSSUBU_VX }, // 7770
  { PseudoVSSUBU_VX_M1_MASK, VSSUBU_VX }, // 7771
  { PseudoVSSUBU_VX_M2, VSSUBU_VX }, // 7772
  { PseudoVSSUBU_VX_M2_MASK, VSSUBU_VX }, // 7773
  { PseudoVSSUBU_VX_M4, VSSUBU_VX }, // 7774
  { PseudoVSSUBU_VX_M4_MASK, VSSUBU_VX }, // 7775
  { PseudoVSSUBU_VX_M8, VSSUBU_VX }, // 7776
  { PseudoVSSUBU_VX_M8_MASK, VSSUBU_VX }, // 7777
  { PseudoVSSUBU_VX_MF2, VSSUBU_VX }, // 7778
  { PseudoVSSUBU_VX_MF2_MASK, VSSUBU_VX }, // 7779
  { PseudoVSSUBU_VX_MF4, VSSUBU_VX }, // 7780
  { PseudoVSSUBU_VX_MF4_MASK, VSSUBU_VX }, // 7781
  { PseudoVSSUBU_VX_MF8, VSSUBU_VX }, // 7782
  { PseudoVSSUBU_VX_MF8_MASK, VSSUBU_VX }, // 7783
  { PseudoVSSUB_VV_M1, VSSUB_VV }, // 7784
  { PseudoVSSUB_VV_M1_MASK, VSSUB_VV }, // 7785
  { PseudoVSSUB_VV_M2, VSSUB_VV }, // 7786
  { PseudoVSSUB_VV_M2_MASK, VSSUB_VV }, // 7787
  { PseudoVSSUB_VV_M4, VSSUB_VV }, // 7788
  { PseudoVSSUB_VV_M4_MASK, VSSUB_VV }, // 7789
  { PseudoVSSUB_VV_M8, VSSUB_VV }, // 7790
  { PseudoVSSUB_VV_M8_MASK, VSSUB_VV }, // 7791
  { PseudoVSSUB_VV_MF2, VSSUB_VV }, // 7792
  { PseudoVSSUB_VV_MF2_MASK, VSSUB_VV }, // 7793
  { PseudoVSSUB_VV_MF4, VSSUB_VV }, // 7794
  { PseudoVSSUB_VV_MF4_MASK, VSSUB_VV }, // 7795
  { PseudoVSSUB_VV_MF8, VSSUB_VV }, // 7796
  { PseudoVSSUB_VV_MF8_MASK, VSSUB_VV }, // 7797
  { PseudoVSSUB_VX_M1, VSSUB_VX }, // 7798
  { PseudoVSSUB_VX_M1_MASK, VSSUB_VX }, // 7799
  { PseudoVSSUB_VX_M2, VSSUB_VX }, // 7800
  { PseudoVSSUB_VX_M2_MASK, VSSUB_VX }, // 7801
  { PseudoVSSUB_VX_M4, VSSUB_VX }, // 7802
  { PseudoVSSUB_VX_M4_MASK, VSSUB_VX }, // 7803
  { PseudoVSSUB_VX_M8, VSSUB_VX }, // 7804
  { PseudoVSSUB_VX_M8_MASK, VSSUB_VX }, // 7805
  { PseudoVSSUB_VX_MF2, VSSUB_VX }, // 7806
  { PseudoVSSUB_VX_MF2_MASK, VSSUB_VX }, // 7807
  { PseudoVSSUB_VX_MF4, VSSUB_VX }, // 7808
  { PseudoVSSUB_VX_MF4_MASK, VSSUB_VX }, // 7809
  { PseudoVSSUB_VX_MF8, VSSUB_VX }, // 7810
  { PseudoVSSUB_VX_MF8_MASK, VSSUB_VX }, // 7811
  { PseudoVSUB_VV_M1, VSUB_VV }, // 7812
  { PseudoVSUB_VV_M1_MASK, VSUB_VV }, // 7813
  { PseudoVSUB_VV_M2, VSUB_VV }, // 7814
  { PseudoVSUB_VV_M2_MASK, VSUB_VV }, // 7815
  { PseudoVSUB_VV_M4, VSUB_VV }, // 7816
  { PseudoVSUB_VV_M4_MASK, VSUB_VV }, // 7817
  { PseudoVSUB_VV_M8, VSUB_VV }, // 7818
  { PseudoVSUB_VV_M8_MASK, VSUB_VV }, // 7819
  { PseudoVSUB_VV_MF2, VSUB_VV }, // 7820
  { PseudoVSUB_VV_MF2_MASK, VSUB_VV }, // 7821
  { PseudoVSUB_VV_MF4, VSUB_VV }, // 7822
  { PseudoVSUB_VV_MF4_MASK, VSUB_VV }, // 7823
  { PseudoVSUB_VV_MF8, VSUB_VV }, // 7824
  { PseudoVSUB_VV_MF8_MASK, VSUB_VV }, // 7825
  { PseudoVSUB_VX_M1, VSUB_VX }, // 7826
  { PseudoVSUB_VX_M1_MASK, VSUB_VX }, // 7827
  { PseudoVSUB_VX_M2, VSUB_VX }, // 7828
  { PseudoVSUB_VX_M2_MASK, VSUB_VX }, // 7829
  { PseudoVSUB_VX_M4, VSUB_VX }, // 7830
  { PseudoVSUB_VX_M4_MASK, VSUB_VX }, // 7831
  { PseudoVSUB_VX_M8, VSUB_VX }, // 7832
  { PseudoVSUB_VX_M8_MASK, VSUB_VX }, // 7833
  { PseudoVSUB_VX_MF2, VSUB_VX }, // 7834
  { PseudoVSUB_VX_MF2_MASK, VSUB_VX }, // 7835
  { PseudoVSUB_VX_MF4, VSUB_VX }, // 7836
  { PseudoVSUB_VX_MF4_MASK, VSUB_VX }, // 7837
  { PseudoVSUB_VX_MF8, VSUB_VX }, // 7838
  { PseudoVSUB_VX_MF8_MASK, VSUB_VX }, // 7839
  { PseudoVSUXEI16_V_M1_M1, VSUXEI16_V }, // 7840
  { PseudoVSUXEI16_V_M1_M1_MASK, VSUXEI16_V }, // 7841
  { PseudoVSUXEI16_V_M1_M2, VSUXEI16_V }, // 7842
  { PseudoVSUXEI16_V_M1_M2_MASK, VSUXEI16_V }, // 7843
  { PseudoVSUXEI16_V_M1_M4, VSUXEI16_V }, // 7844
  { PseudoVSUXEI16_V_M1_M4_MASK, VSUXEI16_V }, // 7845
  { PseudoVSUXEI16_V_M1_MF2, VSUXEI16_V }, // 7846
  { PseudoVSUXEI16_V_M1_MF2_MASK, VSUXEI16_V }, // 7847
  { PseudoVSUXEI16_V_M2_M1, VSUXEI16_V }, // 7848
  { PseudoVSUXEI16_V_M2_M1_MASK, VSUXEI16_V }, // 7849
  { PseudoVSUXEI16_V_M2_M2, VSUXEI16_V }, // 7850
  { PseudoVSUXEI16_V_M2_M2_MASK, VSUXEI16_V }, // 7851
  { PseudoVSUXEI16_V_M2_M4, VSUXEI16_V }, // 7852
  { PseudoVSUXEI16_V_M2_M4_MASK, VSUXEI16_V }, // 7853
  { PseudoVSUXEI16_V_M2_M8, VSUXEI16_V }, // 7854
  { PseudoVSUXEI16_V_M2_M8_MASK, VSUXEI16_V }, // 7855
  { PseudoVSUXEI16_V_M4_M2, VSUXEI16_V }, // 7856
  { PseudoVSUXEI16_V_M4_M2_MASK, VSUXEI16_V }, // 7857
  { PseudoVSUXEI16_V_M4_M4, VSUXEI16_V }, // 7858
  { PseudoVSUXEI16_V_M4_M4_MASK, VSUXEI16_V }, // 7859
  { PseudoVSUXEI16_V_M4_M8, VSUXEI16_V }, // 7860
  { PseudoVSUXEI16_V_M4_M8_MASK, VSUXEI16_V }, // 7861
  { PseudoVSUXEI16_V_M8_M4, VSUXEI16_V }, // 7862
  { PseudoVSUXEI16_V_M8_M4_MASK, VSUXEI16_V }, // 7863
  { PseudoVSUXEI16_V_M8_M8, VSUXEI16_V }, // 7864
  { PseudoVSUXEI16_V_M8_M8_MASK, VSUXEI16_V }, // 7865
  { PseudoVSUXEI16_V_MF2_M1, VSUXEI16_V }, // 7866
  { PseudoVSUXEI16_V_MF2_M1_MASK, VSUXEI16_V }, // 7867
  { PseudoVSUXEI16_V_MF2_M2, VSUXEI16_V }, // 7868
  { PseudoVSUXEI16_V_MF2_M2_MASK, VSUXEI16_V }, // 7869
  { PseudoVSUXEI16_V_MF2_MF2, VSUXEI16_V }, // 7870
  { PseudoVSUXEI16_V_MF2_MF2_MASK, VSUXEI16_V }, // 7871
  { PseudoVSUXEI16_V_MF2_MF4, VSUXEI16_V }, // 7872
  { PseudoVSUXEI16_V_MF2_MF4_MASK, VSUXEI16_V }, // 7873
  { PseudoVSUXEI16_V_MF4_M1, VSUXEI16_V }, // 7874
  { PseudoVSUXEI16_V_MF4_M1_MASK, VSUXEI16_V }, // 7875
  { PseudoVSUXEI16_V_MF4_MF2, VSUXEI16_V }, // 7876
  { PseudoVSUXEI16_V_MF4_MF2_MASK, VSUXEI16_V }, // 7877
  { PseudoVSUXEI16_V_MF4_MF4, VSUXEI16_V }, // 7878
  { PseudoVSUXEI16_V_MF4_MF4_MASK, VSUXEI16_V }, // 7879
  { PseudoVSUXEI16_V_MF4_MF8, VSUXEI16_V }, // 7880
  { PseudoVSUXEI16_V_MF4_MF8_MASK, VSUXEI16_V }, // 7881
  { PseudoVSUXEI32_V_M1_M1, VSUXEI32_V }, // 7882
  { PseudoVSUXEI32_V_M1_M1_MASK, VSUXEI32_V }, // 7883
  { PseudoVSUXEI32_V_M1_M2, VSUXEI32_V }, // 7884
  { PseudoVSUXEI32_V_M1_M2_MASK, VSUXEI32_V }, // 7885
  { PseudoVSUXEI32_V_M1_MF2, VSUXEI32_V }, // 7886
  { PseudoVSUXEI32_V_M1_MF2_MASK, VSUXEI32_V }, // 7887
  { PseudoVSUXEI32_V_M1_MF4, VSUXEI32_V }, // 7888
  { PseudoVSUXEI32_V_M1_MF4_MASK, VSUXEI32_V }, // 7889
  { PseudoVSUXEI32_V_M2_M1, VSUXEI32_V }, // 7890
  { PseudoVSUXEI32_V_M2_M1_MASK, VSUXEI32_V }, // 7891
  { PseudoVSUXEI32_V_M2_M2, VSUXEI32_V }, // 7892
  { PseudoVSUXEI32_V_M2_M2_MASK, VSUXEI32_V }, // 7893
  { PseudoVSUXEI32_V_M2_M4, VSUXEI32_V }, // 7894
  { PseudoVSUXEI32_V_M2_M4_MASK, VSUXEI32_V }, // 7895
  { PseudoVSUXEI32_V_M2_MF2, VSUXEI32_V }, // 7896
  { PseudoVSUXEI32_V_M2_MF2_MASK, VSUXEI32_V }, // 7897
  { PseudoVSUXEI32_V_M4_M1, VSUXEI32_V }, // 7898
  { PseudoVSUXEI32_V_M4_M1_MASK, VSUXEI32_V }, // 7899
  { PseudoVSUXEI32_V_M4_M2, VSUXEI32_V }, // 7900
  { PseudoVSUXEI32_V_M4_M2_MASK, VSUXEI32_V }, // 7901
  { PseudoVSUXEI32_V_M4_M4, VSUXEI32_V }, // 7902
  { PseudoVSUXEI32_V_M4_M4_MASK, VSUXEI32_V }, // 7903
  { PseudoVSUXEI32_V_M4_M8, VSUXEI32_V }, // 7904
  { PseudoVSUXEI32_V_M4_M8_MASK, VSUXEI32_V }, // 7905
  { PseudoVSUXEI32_V_M8_M2, VSUXEI32_V }, // 7906
  { PseudoVSUXEI32_V_M8_M2_MASK, VSUXEI32_V }, // 7907
  { PseudoVSUXEI32_V_M8_M4, VSUXEI32_V }, // 7908
  { PseudoVSUXEI32_V_M8_M4_MASK, VSUXEI32_V }, // 7909
  { PseudoVSUXEI32_V_M8_M8, VSUXEI32_V }, // 7910
  { PseudoVSUXEI32_V_M8_M8_MASK, VSUXEI32_V }, // 7911
  { PseudoVSUXEI32_V_MF2_M1, VSUXEI32_V }, // 7912
  { PseudoVSUXEI32_V_MF2_M1_MASK, VSUXEI32_V }, // 7913
  { PseudoVSUXEI32_V_MF2_MF2, VSUXEI32_V }, // 7914
  { PseudoVSUXEI32_V_MF2_MF2_MASK, VSUXEI32_V }, // 7915
  { PseudoVSUXEI32_V_MF2_MF4, VSUXEI32_V }, // 7916
  { PseudoVSUXEI32_V_MF2_MF4_MASK, VSUXEI32_V }, // 7917
  { PseudoVSUXEI32_V_MF2_MF8, VSUXEI32_V }, // 7918
  { PseudoVSUXEI32_V_MF2_MF8_MASK, VSUXEI32_V }, // 7919
  { PseudoVSUXEI64_V_M1_M1, VSUXEI64_V }, // 7920
  { PseudoVSUXEI64_V_M1_M1_MASK, VSUXEI64_V }, // 7921
  { PseudoVSUXEI64_V_M1_MF2, VSUXEI64_V }, // 7922
  { PseudoVSUXEI64_V_M1_MF2_MASK, VSUXEI64_V }, // 7923
  { PseudoVSUXEI64_V_M1_MF4, VSUXEI64_V }, // 7924
  { PseudoVSUXEI64_V_M1_MF4_MASK, VSUXEI64_V }, // 7925
  { PseudoVSUXEI64_V_M1_MF8, VSUXEI64_V }, // 7926
  { PseudoVSUXEI64_V_M1_MF8_MASK, VSUXEI64_V }, // 7927
  { PseudoVSUXEI64_V_M2_M1, VSUXEI64_V }, // 7928
  { PseudoVSUXEI64_V_M2_M1_MASK, VSUXEI64_V }, // 7929
  { PseudoVSUXEI64_V_M2_M2, VSUXEI64_V }, // 7930
  { PseudoVSUXEI64_V_M2_M2_MASK, VSUXEI64_V }, // 7931
  { PseudoVSUXEI64_V_M2_MF2, VSUXEI64_V }, // 7932
  { PseudoVSUXEI64_V_M2_MF2_MASK, VSUXEI64_V }, // 7933
  { PseudoVSUXEI64_V_M2_MF4, VSUXEI64_V }, // 7934
  { PseudoVSUXEI64_V_M2_MF4_MASK, VSUXEI64_V }, // 7935
  { PseudoVSUXEI64_V_M4_M1, VSUXEI64_V }, // 7936
  { PseudoVSUXEI64_V_M4_M1_MASK, VSUXEI64_V }, // 7937
  { PseudoVSUXEI64_V_M4_M2, VSUXEI64_V }, // 7938
  { PseudoVSUXEI64_V_M4_M2_MASK, VSUXEI64_V }, // 7939
  { PseudoVSUXEI64_V_M4_M4, VSUXEI64_V }, // 7940
  { PseudoVSUXEI64_V_M4_M4_MASK, VSUXEI64_V }, // 7941
  { PseudoVSUXEI64_V_M4_MF2, VSUXEI64_V }, // 7942
  { PseudoVSUXEI64_V_M4_MF2_MASK, VSUXEI64_V }, // 7943
  { PseudoVSUXEI64_V_M8_M1, VSUXEI64_V }, // 7944
  { PseudoVSUXEI64_V_M8_M1_MASK, VSUXEI64_V }, // 7945
  { PseudoVSUXEI64_V_M8_M2, VSUXEI64_V }, // 7946
  { PseudoVSUXEI64_V_M8_M2_MASK, VSUXEI64_V }, // 7947
  { PseudoVSUXEI64_V_M8_M4, VSUXEI64_V }, // 7948
  { PseudoVSUXEI64_V_M8_M4_MASK, VSUXEI64_V }, // 7949
  { PseudoVSUXEI64_V_M8_M8, VSUXEI64_V }, // 7950
  { PseudoVSUXEI64_V_M8_M8_MASK, VSUXEI64_V }, // 7951
  { PseudoVSUXEI8_V_M1_M1, VSUXEI8_V }, // 7952
  { PseudoVSUXEI8_V_M1_M1_MASK, VSUXEI8_V }, // 7953
  { PseudoVSUXEI8_V_M1_M2, VSUXEI8_V }, // 7954
  { PseudoVSUXEI8_V_M1_M2_MASK, VSUXEI8_V }, // 7955
  { PseudoVSUXEI8_V_M1_M4, VSUXEI8_V }, // 7956
  { PseudoVSUXEI8_V_M1_M4_MASK, VSUXEI8_V }, // 7957
  { PseudoVSUXEI8_V_M1_M8, VSUXEI8_V }, // 7958
  { PseudoVSUXEI8_V_M1_M8_MASK, VSUXEI8_V }, // 7959
  { PseudoVSUXEI8_V_M2_M2, VSUXEI8_V }, // 7960
  { PseudoVSUXEI8_V_M2_M2_MASK, VSUXEI8_V }, // 7961
  { PseudoVSUXEI8_V_M2_M4, VSUXEI8_V }, // 7962
  { PseudoVSUXEI8_V_M2_M4_MASK, VSUXEI8_V }, // 7963
  { PseudoVSUXEI8_V_M2_M8, VSUXEI8_V }, // 7964
  { PseudoVSUXEI8_V_M2_M8_MASK, VSUXEI8_V }, // 7965
  { PseudoVSUXEI8_V_M4_M4, VSUXEI8_V }, // 7966
  { PseudoVSUXEI8_V_M4_M4_MASK, VSUXEI8_V }, // 7967
  { PseudoVSUXEI8_V_M4_M8, VSUXEI8_V }, // 7968
  { PseudoVSUXEI8_V_M4_M8_MASK, VSUXEI8_V }, // 7969
  { PseudoVSUXEI8_V_M8_M8, VSUXEI8_V }, // 7970
  { PseudoVSUXEI8_V_M8_M8_MASK, VSUXEI8_V }, // 7971
  { PseudoVSUXEI8_V_MF2_M1, VSUXEI8_V }, // 7972
  { PseudoVSUXEI8_V_MF2_M1_MASK, VSUXEI8_V }, // 7973
  { PseudoVSUXEI8_V_MF2_M2, VSUXEI8_V }, // 7974
  { PseudoVSUXEI8_V_MF2_M2_MASK, VSUXEI8_V }, // 7975
  { PseudoVSUXEI8_V_MF2_M4, VSUXEI8_V }, // 7976
  { PseudoVSUXEI8_V_MF2_M4_MASK, VSUXEI8_V }, // 7977
  { PseudoVSUXEI8_V_MF2_MF2, VSUXEI8_V }, // 7978
  { PseudoVSUXEI8_V_MF2_MF2_MASK, VSUXEI8_V }, // 7979
  { PseudoVSUXEI8_V_MF4_M1, VSUXEI8_V }, // 7980
  { PseudoVSUXEI8_V_MF4_M1_MASK, VSUXEI8_V }, // 7981
  { PseudoVSUXEI8_V_MF4_M2, VSUXEI8_V }, // 7982
  { PseudoVSUXEI8_V_MF4_M2_MASK, VSUXEI8_V }, // 7983
  { PseudoVSUXEI8_V_MF4_MF2, VSUXEI8_V }, // 7984
  { PseudoVSUXEI8_V_MF4_MF2_MASK, VSUXEI8_V }, // 7985
  { PseudoVSUXEI8_V_MF4_MF4, VSUXEI8_V }, // 7986
  { PseudoVSUXEI8_V_MF4_MF4_MASK, VSUXEI8_V }, // 7987
  { PseudoVSUXEI8_V_MF8_M1, VSUXEI8_V }, // 7988
  { PseudoVSUXEI8_V_MF8_M1_MASK, VSUXEI8_V }, // 7989
  { PseudoVSUXEI8_V_MF8_MF2, VSUXEI8_V }, // 7990
  { PseudoVSUXEI8_V_MF8_MF2_MASK, VSUXEI8_V }, // 7991
  { PseudoVSUXEI8_V_MF8_MF4, VSUXEI8_V }, // 7992
  { PseudoVSUXEI8_V_MF8_MF4_MASK, VSUXEI8_V }, // 7993
  { PseudoVSUXEI8_V_MF8_MF8, VSUXEI8_V }, // 7994
  { PseudoVSUXEI8_V_MF8_MF8_MASK, VSUXEI8_V }, // 7995
  { PseudoVSUXSEG2EI16_V_M1_M1, VSUXSEG2EI16_V }, // 7996
  { PseudoVSUXSEG2EI16_V_M1_M1_MASK, VSUXSEG2EI16_V }, // 7997
  { PseudoVSUXSEG2EI16_V_M1_M2, VSUXSEG2EI16_V }, // 7998
  { PseudoVSUXSEG2EI16_V_M1_M2_MASK, VSUXSEG2EI16_V }, // 7999
  { PseudoVSUXSEG2EI16_V_M1_M4, VSUXSEG2EI16_V }, // 8000
  { PseudoVSUXSEG2EI16_V_M1_M4_MASK, VSUXSEG2EI16_V }, // 8001
  { PseudoVSUXSEG2EI16_V_M1_MF2, VSUXSEG2EI16_V }, // 8002
  { PseudoVSUXSEG2EI16_V_M1_MF2_MASK, VSUXSEG2EI16_V }, // 8003
  { PseudoVSUXSEG2EI16_V_M2_M1, VSUXSEG2EI16_V }, // 8004
  { PseudoVSUXSEG2EI16_V_M2_M1_MASK, VSUXSEG2EI16_V }, // 8005
  { PseudoVSUXSEG2EI16_V_M2_M2, VSUXSEG2EI16_V }, // 8006
  { PseudoVSUXSEG2EI16_V_M2_M2_MASK, VSUXSEG2EI16_V }, // 8007
  { PseudoVSUXSEG2EI16_V_M2_M4, VSUXSEG2EI16_V }, // 8008
  { PseudoVSUXSEG2EI16_V_M2_M4_MASK, VSUXSEG2EI16_V }, // 8009
  { PseudoVSUXSEG2EI16_V_M4_M2, VSUXSEG2EI16_V }, // 8010
  { PseudoVSUXSEG2EI16_V_M4_M2_MASK, VSUXSEG2EI16_V }, // 8011
  { PseudoVSUXSEG2EI16_V_M4_M4, VSUXSEG2EI16_V }, // 8012
  { PseudoVSUXSEG2EI16_V_M4_M4_MASK, VSUXSEG2EI16_V }, // 8013
  { PseudoVSUXSEG2EI16_V_M8_M4, VSUXSEG2EI16_V }, // 8014
  { PseudoVSUXSEG2EI16_V_M8_M4_MASK, VSUXSEG2EI16_V }, // 8015
  { PseudoVSUXSEG2EI16_V_MF2_M1, VSUXSEG2EI16_V }, // 8016
  { PseudoVSUXSEG2EI16_V_MF2_M1_MASK, VSUXSEG2EI16_V }, // 8017
  { PseudoVSUXSEG2EI16_V_MF2_M2, VSUXSEG2EI16_V }, // 8018
  { PseudoVSUXSEG2EI16_V_MF2_M2_MASK, VSUXSEG2EI16_V }, // 8019
  { PseudoVSUXSEG2EI16_V_MF2_MF2, VSUXSEG2EI16_V }, // 8020
  { PseudoVSUXSEG2EI16_V_MF2_MF2_MASK, VSUXSEG2EI16_V }, // 8021
  { PseudoVSUXSEG2EI16_V_MF2_MF4, VSUXSEG2EI16_V }, // 8022
  { PseudoVSUXSEG2EI16_V_MF2_MF4_MASK, VSUXSEG2EI16_V }, // 8023
  { PseudoVSUXSEG2EI16_V_MF4_M1, VSUXSEG2EI16_V }, // 8024
  { PseudoVSUXSEG2EI16_V_MF4_M1_MASK, VSUXSEG2EI16_V }, // 8025
  { PseudoVSUXSEG2EI16_V_MF4_MF2, VSUXSEG2EI16_V }, // 8026
  { PseudoVSUXSEG2EI16_V_MF4_MF2_MASK, VSUXSEG2EI16_V }, // 8027
  { PseudoVSUXSEG2EI16_V_MF4_MF4, VSUXSEG2EI16_V }, // 8028
  { PseudoVSUXSEG2EI16_V_MF4_MF4_MASK, VSUXSEG2EI16_V }, // 8029
  { PseudoVSUXSEG2EI16_V_MF4_MF8, VSUXSEG2EI16_V }, // 8030
  { PseudoVSUXSEG2EI16_V_MF4_MF8_MASK, VSUXSEG2EI16_V }, // 8031
  { PseudoVSUXSEG2EI32_V_M1_M1, VSUXSEG2EI32_V }, // 8032
  { PseudoVSUXSEG2EI32_V_M1_M1_MASK, VSUXSEG2EI32_V }, // 8033
  { PseudoVSUXSEG2EI32_V_M1_M2, VSUXSEG2EI32_V }, // 8034
  { PseudoVSUXSEG2EI32_V_M1_M2_MASK, VSUXSEG2EI32_V }, // 8035
  { PseudoVSUXSEG2EI32_V_M1_MF2, VSUXSEG2EI32_V }, // 8036
  { PseudoVSUXSEG2EI32_V_M1_MF2_MASK, VSUXSEG2EI32_V }, // 8037
  { PseudoVSUXSEG2EI32_V_M1_MF4, VSUXSEG2EI32_V }, // 8038
  { PseudoVSUXSEG2EI32_V_M1_MF4_MASK, VSUXSEG2EI32_V }, // 8039
  { PseudoVSUXSEG2EI32_V_M2_M1, VSUXSEG2EI32_V }, // 8040
  { PseudoVSUXSEG2EI32_V_M2_M1_MASK, VSUXSEG2EI32_V }, // 8041
  { PseudoVSUXSEG2EI32_V_M2_M2, VSUXSEG2EI32_V }, // 8042
  { PseudoVSUXSEG2EI32_V_M2_M2_MASK, VSUXSEG2EI32_V }, // 8043
  { PseudoVSUXSEG2EI32_V_M2_M4, VSUXSEG2EI32_V }, // 8044
  { PseudoVSUXSEG2EI32_V_M2_M4_MASK, VSUXSEG2EI32_V }, // 8045
  { PseudoVSUXSEG2EI32_V_M2_MF2, VSUXSEG2EI32_V }, // 8046
  { PseudoVSUXSEG2EI32_V_M2_MF2_MASK, VSUXSEG2EI32_V }, // 8047
  { PseudoVSUXSEG2EI32_V_M4_M1, VSUXSEG2EI32_V }, // 8048
  { PseudoVSUXSEG2EI32_V_M4_M1_MASK, VSUXSEG2EI32_V }, // 8049
  { PseudoVSUXSEG2EI32_V_M4_M2, VSUXSEG2EI32_V }, // 8050
  { PseudoVSUXSEG2EI32_V_M4_M2_MASK, VSUXSEG2EI32_V }, // 8051
  { PseudoVSUXSEG2EI32_V_M4_M4, VSUXSEG2EI32_V }, // 8052
  { PseudoVSUXSEG2EI32_V_M4_M4_MASK, VSUXSEG2EI32_V }, // 8053
  { PseudoVSUXSEG2EI32_V_M8_M2, VSUXSEG2EI32_V }, // 8054
  { PseudoVSUXSEG2EI32_V_M8_M2_MASK, VSUXSEG2EI32_V }, // 8055
  { PseudoVSUXSEG2EI32_V_M8_M4, VSUXSEG2EI32_V }, // 8056
  { PseudoVSUXSEG2EI32_V_M8_M4_MASK, VSUXSEG2EI32_V }, // 8057
  { PseudoVSUXSEG2EI32_V_MF2_M1, VSUXSEG2EI32_V }, // 8058
  { PseudoVSUXSEG2EI32_V_MF2_M1_MASK, VSUXSEG2EI32_V }, // 8059
  { PseudoVSUXSEG2EI32_V_MF2_MF2, VSUXSEG2EI32_V }, // 8060
  { PseudoVSUXSEG2EI32_V_MF2_MF2_MASK, VSUXSEG2EI32_V }, // 8061
  { PseudoVSUXSEG2EI32_V_MF2_MF4, VSUXSEG2EI32_V }, // 8062
  { PseudoVSUXSEG2EI32_V_MF2_MF4_MASK, VSUXSEG2EI32_V }, // 8063
  { PseudoVSUXSEG2EI32_V_MF2_MF8, VSUXSEG2EI32_V }, // 8064
  { PseudoVSUXSEG2EI32_V_MF2_MF8_MASK, VSUXSEG2EI32_V }, // 8065
  { PseudoVSUXSEG2EI64_V_M1_M1, VSUXSEG2EI64_V }, // 8066
  { PseudoVSUXSEG2EI64_V_M1_M1_MASK, VSUXSEG2EI64_V }, // 8067
  { PseudoVSUXSEG2EI64_V_M1_MF2, VSUXSEG2EI64_V }, // 8068
  { PseudoVSUXSEG2EI64_V_M1_MF2_MASK, VSUXSEG2EI64_V }, // 8069
  { PseudoVSUXSEG2EI64_V_M1_MF4, VSUXSEG2EI64_V }, // 8070
  { PseudoVSUXSEG2EI64_V_M1_MF4_MASK, VSUXSEG2EI64_V }, // 8071
  { PseudoVSUXSEG2EI64_V_M1_MF8, VSUXSEG2EI64_V }, // 8072
  { PseudoVSUXSEG2EI64_V_M1_MF8_MASK, VSUXSEG2EI64_V }, // 8073
  { PseudoVSUXSEG2EI64_V_M2_M1, VSUXSEG2EI64_V }, // 8074
  { PseudoVSUXSEG2EI64_V_M2_M1_MASK, VSUXSEG2EI64_V }, // 8075
  { PseudoVSUXSEG2EI64_V_M2_M2, VSUXSEG2EI64_V }, // 8076
  { PseudoVSUXSEG2EI64_V_M2_M2_MASK, VSUXSEG2EI64_V }, // 8077
  { PseudoVSUXSEG2EI64_V_M2_MF2, VSUXSEG2EI64_V }, // 8078
  { PseudoVSUXSEG2EI64_V_M2_MF2_MASK, VSUXSEG2EI64_V }, // 8079
  { PseudoVSUXSEG2EI64_V_M2_MF4, VSUXSEG2EI64_V }, // 8080
  { PseudoVSUXSEG2EI64_V_M2_MF4_MASK, VSUXSEG2EI64_V }, // 8081
  { PseudoVSUXSEG2EI64_V_M4_M1, VSUXSEG2EI64_V }, // 8082
  { PseudoVSUXSEG2EI64_V_M4_M1_MASK, VSUXSEG2EI64_V }, // 8083
  { PseudoVSUXSEG2EI64_V_M4_M2, VSUXSEG2EI64_V }, // 8084
  { PseudoVSUXSEG2EI64_V_M4_M2_MASK, VSUXSEG2EI64_V }, // 8085
  { PseudoVSUXSEG2EI64_V_M4_M4, VSUXSEG2EI64_V }, // 8086
  { PseudoVSUXSEG2EI64_V_M4_M4_MASK, VSUXSEG2EI64_V }, // 8087
  { PseudoVSUXSEG2EI64_V_M4_MF2, VSUXSEG2EI64_V }, // 8088
  { PseudoVSUXSEG2EI64_V_M4_MF2_MASK, VSUXSEG2EI64_V }, // 8089
  { PseudoVSUXSEG2EI64_V_M8_M1, VSUXSEG2EI64_V }, // 8090
  { PseudoVSUXSEG2EI64_V_M8_M1_MASK, VSUXSEG2EI64_V }, // 8091
  { PseudoVSUXSEG2EI64_V_M8_M2, VSUXSEG2EI64_V }, // 8092
  { PseudoVSUXSEG2EI64_V_M8_M2_MASK, VSUXSEG2EI64_V }, // 8093
  { PseudoVSUXSEG2EI64_V_M8_M4, VSUXSEG2EI64_V }, // 8094
  { PseudoVSUXSEG2EI64_V_M8_M4_MASK, VSUXSEG2EI64_V }, // 8095
  { PseudoVSUXSEG2EI8_V_M1_M1, VSUXSEG2EI8_V }, // 8096
  { PseudoVSUXSEG2EI8_V_M1_M1_MASK, VSUXSEG2EI8_V }, // 8097
  { PseudoVSUXSEG2EI8_V_M1_M2, VSUXSEG2EI8_V }, // 8098
  { PseudoVSUXSEG2EI8_V_M1_M2_MASK, VSUXSEG2EI8_V }, // 8099
  { PseudoVSUXSEG2EI8_V_M1_M4, VSUXSEG2EI8_V }, // 8100
  { PseudoVSUXSEG2EI8_V_M1_M4_MASK, VSUXSEG2EI8_V }, // 8101
  { PseudoVSUXSEG2EI8_V_M2_M2, VSUXSEG2EI8_V }, // 8102
  { PseudoVSUXSEG2EI8_V_M2_M2_MASK, VSUXSEG2EI8_V }, // 8103
  { PseudoVSUXSEG2EI8_V_M2_M4, VSUXSEG2EI8_V }, // 8104
  { PseudoVSUXSEG2EI8_V_M2_M4_MASK, VSUXSEG2EI8_V }, // 8105
  { PseudoVSUXSEG2EI8_V_M4_M4, VSUXSEG2EI8_V }, // 8106
  { PseudoVSUXSEG2EI8_V_M4_M4_MASK, VSUXSEG2EI8_V }, // 8107
  { PseudoVSUXSEG2EI8_V_MF2_M1, VSUXSEG2EI8_V }, // 8108
  { PseudoVSUXSEG2EI8_V_MF2_M1_MASK, VSUXSEG2EI8_V }, // 8109
  { PseudoVSUXSEG2EI8_V_MF2_M2, VSUXSEG2EI8_V }, // 8110
  { PseudoVSUXSEG2EI8_V_MF2_M2_MASK, VSUXSEG2EI8_V }, // 8111
  { PseudoVSUXSEG2EI8_V_MF2_M4, VSUXSEG2EI8_V }, // 8112
  { PseudoVSUXSEG2EI8_V_MF2_M4_MASK, VSUXSEG2EI8_V }, // 8113
  { PseudoVSUXSEG2EI8_V_MF2_MF2, VSUXSEG2EI8_V }, // 8114
  { PseudoVSUXSEG2EI8_V_MF2_MF2_MASK, VSUXSEG2EI8_V }, // 8115
  { PseudoVSUXSEG2EI8_V_MF4_M1, VSUXSEG2EI8_V }, // 8116
  { PseudoVSUXSEG2EI8_V_MF4_M1_MASK, VSUXSEG2EI8_V }, // 8117
  { PseudoVSUXSEG2EI8_V_MF4_M2, VSUXSEG2EI8_V }, // 8118
  { PseudoVSUXSEG2EI8_V_MF4_M2_MASK, VSUXSEG2EI8_V }, // 8119
  { PseudoVSUXSEG2EI8_V_MF4_MF2, VSUXSEG2EI8_V }, // 8120
  { PseudoVSUXSEG2EI8_V_MF4_MF2_MASK, VSUXSEG2EI8_V }, // 8121
  { PseudoVSUXSEG2EI8_V_MF4_MF4, VSUXSEG2EI8_V }, // 8122
  { PseudoVSUXSEG2EI8_V_MF4_MF4_MASK, VSUXSEG2EI8_V }, // 8123
  { PseudoVSUXSEG2EI8_V_MF8_M1, VSUXSEG2EI8_V }, // 8124
  { PseudoVSUXSEG2EI8_V_MF8_M1_MASK, VSUXSEG2EI8_V }, // 8125
  { PseudoVSUXSEG2EI8_V_MF8_MF2, VSUXSEG2EI8_V }, // 8126
  { PseudoVSUXSEG2EI8_V_MF8_MF2_MASK, VSUXSEG2EI8_V }, // 8127
  { PseudoVSUXSEG2EI8_V_MF8_MF4, VSUXSEG2EI8_V }, // 8128
  { PseudoVSUXSEG2EI8_V_MF8_MF4_MASK, VSUXSEG2EI8_V }, // 8129
  { PseudoVSUXSEG2EI8_V_MF8_MF8, VSUXSEG2EI8_V }, // 8130
  { PseudoVSUXSEG2EI8_V_MF8_MF8_MASK, VSUXSEG2EI8_V }, // 8131
  { PseudoVSUXSEG3EI16_V_M1_M1, VSUXSEG3EI16_V }, // 8132
  { PseudoVSUXSEG3EI16_V_M1_M1_MASK, VSUXSEG3EI16_V }, // 8133
  { PseudoVSUXSEG3EI16_V_M1_M2, VSUXSEG3EI16_V }, // 8134
  { PseudoVSUXSEG3EI16_V_M1_M2_MASK, VSUXSEG3EI16_V }, // 8135
  { PseudoVSUXSEG3EI16_V_M1_MF2, VSUXSEG3EI16_V }, // 8136
  { PseudoVSUXSEG3EI16_V_M1_MF2_MASK, VSUXSEG3EI16_V }, // 8137
  { PseudoVSUXSEG3EI16_V_M2_M1, VSUXSEG3EI16_V }, // 8138
  { PseudoVSUXSEG3EI16_V_M2_M1_MASK, VSUXSEG3EI16_V }, // 8139
  { PseudoVSUXSEG3EI16_V_M2_M2, VSUXSEG3EI16_V }, // 8140
  { PseudoVSUXSEG3EI16_V_M2_M2_MASK, VSUXSEG3EI16_V }, // 8141
  { PseudoVSUXSEG3EI16_V_M4_M2, VSUXSEG3EI16_V }, // 8142
  { PseudoVSUXSEG3EI16_V_M4_M2_MASK, VSUXSEG3EI16_V }, // 8143
  { PseudoVSUXSEG3EI16_V_MF2_M1, VSUXSEG3EI16_V }, // 8144
  { PseudoVSUXSEG3EI16_V_MF2_M1_MASK, VSUXSEG3EI16_V }, // 8145
  { PseudoVSUXSEG3EI16_V_MF2_M2, VSUXSEG3EI16_V }, // 8146
  { PseudoVSUXSEG3EI16_V_MF2_M2_MASK, VSUXSEG3EI16_V }, // 8147
  { PseudoVSUXSEG3EI16_V_MF2_MF2, VSUXSEG3EI16_V }, // 8148
  { PseudoVSUXSEG3EI16_V_MF2_MF2_MASK, VSUXSEG3EI16_V }, // 8149
  { PseudoVSUXSEG3EI16_V_MF2_MF4, VSUXSEG3EI16_V }, // 8150
  { PseudoVSUXSEG3EI16_V_MF2_MF4_MASK, VSUXSEG3EI16_V }, // 8151
  { PseudoVSUXSEG3EI16_V_MF4_M1, VSUXSEG3EI16_V }, // 8152
  { PseudoVSUXSEG3EI16_V_MF4_M1_MASK, VSUXSEG3EI16_V }, // 8153
  { PseudoVSUXSEG3EI16_V_MF4_MF2, VSUXSEG3EI16_V }, // 8154
  { PseudoVSUXSEG3EI16_V_MF4_MF2_MASK, VSUXSEG3EI16_V }, // 8155
  { PseudoVSUXSEG3EI16_V_MF4_MF4, VSUXSEG3EI16_V }, // 8156
  { PseudoVSUXSEG3EI16_V_MF4_MF4_MASK, VSUXSEG3EI16_V }, // 8157
  { PseudoVSUXSEG3EI16_V_MF4_MF8, VSUXSEG3EI16_V }, // 8158
  { PseudoVSUXSEG3EI16_V_MF4_MF8_MASK, VSUXSEG3EI16_V }, // 8159
  { PseudoVSUXSEG3EI32_V_M1_M1, VSUXSEG3EI32_V }, // 8160
  { PseudoVSUXSEG3EI32_V_M1_M1_MASK, VSUXSEG3EI32_V }, // 8161
  { PseudoVSUXSEG3EI32_V_M1_M2, VSUXSEG3EI32_V }, // 8162
  { PseudoVSUXSEG3EI32_V_M1_M2_MASK, VSUXSEG3EI32_V }, // 8163
  { PseudoVSUXSEG3EI32_V_M1_MF2, VSUXSEG3EI32_V }, // 8164
  { PseudoVSUXSEG3EI32_V_M1_MF2_MASK, VSUXSEG3EI32_V }, // 8165
  { PseudoVSUXSEG3EI32_V_M1_MF4, VSUXSEG3EI32_V }, // 8166
  { PseudoVSUXSEG3EI32_V_M1_MF4_MASK, VSUXSEG3EI32_V }, // 8167
  { PseudoVSUXSEG3EI32_V_M2_M1, VSUXSEG3EI32_V }, // 8168
  { PseudoVSUXSEG3EI32_V_M2_M1_MASK, VSUXSEG3EI32_V }, // 8169
  { PseudoVSUXSEG3EI32_V_M2_M2, VSUXSEG3EI32_V }, // 8170
  { PseudoVSUXSEG3EI32_V_M2_M2_MASK, VSUXSEG3EI32_V }, // 8171
  { PseudoVSUXSEG3EI32_V_M2_MF2, VSUXSEG3EI32_V }, // 8172
  { PseudoVSUXSEG3EI32_V_M2_MF2_MASK, VSUXSEG3EI32_V }, // 8173
  { PseudoVSUXSEG3EI32_V_M4_M1, VSUXSEG3EI32_V }, // 8174
  { PseudoVSUXSEG3EI32_V_M4_M1_MASK, VSUXSEG3EI32_V }, // 8175
  { PseudoVSUXSEG3EI32_V_M4_M2, VSUXSEG3EI32_V }, // 8176
  { PseudoVSUXSEG3EI32_V_M4_M2_MASK, VSUXSEG3EI32_V }, // 8177
  { PseudoVSUXSEG3EI32_V_M8_M2, VSUXSEG3EI32_V }, // 8178
  { PseudoVSUXSEG3EI32_V_M8_M2_MASK, VSUXSEG3EI32_V }, // 8179
  { PseudoVSUXSEG3EI32_V_MF2_M1, VSUXSEG3EI32_V }, // 8180
  { PseudoVSUXSEG3EI32_V_MF2_M1_MASK, VSUXSEG3EI32_V }, // 8181
  { PseudoVSUXSEG3EI32_V_MF2_MF2, VSUXSEG3EI32_V }, // 8182
  { PseudoVSUXSEG3EI32_V_MF2_MF2_MASK, VSUXSEG3EI32_V }, // 8183
  { PseudoVSUXSEG3EI32_V_MF2_MF4, VSUXSEG3EI32_V }, // 8184
  { PseudoVSUXSEG3EI32_V_MF2_MF4_MASK, VSUXSEG3EI32_V }, // 8185
  { PseudoVSUXSEG3EI32_V_MF2_MF8, VSUXSEG3EI32_V }, // 8186
  { PseudoVSUXSEG3EI32_V_MF2_MF8_MASK, VSUXSEG3EI32_V }, // 8187
  { PseudoVSUXSEG3EI64_V_M1_M1, VSUXSEG3EI64_V }, // 8188
  { PseudoVSUXSEG3EI64_V_M1_M1_MASK, VSUXSEG3EI64_V }, // 8189
  { PseudoVSUXSEG3EI64_V_M1_MF2, VSUXSEG3EI64_V }, // 8190
  { PseudoVSUXSEG3EI64_V_M1_MF2_MASK, VSUXSEG3EI64_V }, // 8191
  { PseudoVSUXSEG3EI64_V_M1_MF4, VSUXSEG3EI64_V }, // 8192
  { PseudoVSUXSEG3EI64_V_M1_MF4_MASK, VSUXSEG3EI64_V }, // 8193
  { PseudoVSUXSEG3EI64_V_M1_MF8, VSUXSEG3EI64_V }, // 8194
  { PseudoVSUXSEG3EI64_V_M1_MF8_MASK, VSUXSEG3EI64_V }, // 8195
  { PseudoVSUXSEG3EI64_V_M2_M1, VSUXSEG3EI64_V }, // 8196
  { PseudoVSUXSEG3EI64_V_M2_M1_MASK, VSUXSEG3EI64_V }, // 8197
  { PseudoVSUXSEG3EI64_V_M2_M2, VSUXSEG3EI64_V }, // 8198
  { PseudoVSUXSEG3EI64_V_M2_M2_MASK, VSUXSEG3EI64_V }, // 8199
  { PseudoVSUXSEG3EI64_V_M2_MF2, VSUXSEG3EI64_V }, // 8200
  { PseudoVSUXSEG3EI64_V_M2_MF2_MASK, VSUXSEG3EI64_V }, // 8201
  { PseudoVSUXSEG3EI64_V_M2_MF4, VSUXSEG3EI64_V }, // 8202
  { PseudoVSUXSEG3EI64_V_M2_MF4_MASK, VSUXSEG3EI64_V }, // 8203
  { PseudoVSUXSEG3EI64_V_M4_M1, VSUXSEG3EI64_V }, // 8204
  { PseudoVSUXSEG3EI64_V_M4_M1_MASK, VSUXSEG3EI64_V }, // 8205
  { PseudoVSUXSEG3EI64_V_M4_M2, VSUXSEG3EI64_V }, // 8206
  { PseudoVSUXSEG3EI64_V_M4_M2_MASK, VSUXSEG3EI64_V }, // 8207
  { PseudoVSUXSEG3EI64_V_M4_MF2, VSUXSEG3EI64_V }, // 8208
  { PseudoVSUXSEG3EI64_V_M4_MF2_MASK, VSUXSEG3EI64_V }, // 8209
  { PseudoVSUXSEG3EI64_V_M8_M1, VSUXSEG3EI64_V }, // 8210
  { PseudoVSUXSEG3EI64_V_M8_M1_MASK, VSUXSEG3EI64_V }, // 8211
  { PseudoVSUXSEG3EI64_V_M8_M2, VSUXSEG3EI64_V }, // 8212
  { PseudoVSUXSEG3EI64_V_M8_M2_MASK, VSUXSEG3EI64_V }, // 8213
  { PseudoVSUXSEG3EI8_V_M1_M1, VSUXSEG3EI8_V }, // 8214
  { PseudoVSUXSEG3EI8_V_M1_M1_MASK, VSUXSEG3EI8_V }, // 8215
  { PseudoVSUXSEG3EI8_V_M1_M2, VSUXSEG3EI8_V }, // 8216
  { PseudoVSUXSEG3EI8_V_M1_M2_MASK, VSUXSEG3EI8_V }, // 8217
  { PseudoVSUXSEG3EI8_V_M2_M2, VSUXSEG3EI8_V }, // 8218
  { PseudoVSUXSEG3EI8_V_M2_M2_MASK, VSUXSEG3EI8_V }, // 8219
  { PseudoVSUXSEG3EI8_V_MF2_M1, VSUXSEG3EI8_V }, // 8220
  { PseudoVSUXSEG3EI8_V_MF2_M1_MASK, VSUXSEG3EI8_V }, // 8221
  { PseudoVSUXSEG3EI8_V_MF2_M2, VSUXSEG3EI8_V }, // 8222
  { PseudoVSUXSEG3EI8_V_MF2_M2_MASK, VSUXSEG3EI8_V }, // 8223
  { PseudoVSUXSEG3EI8_V_MF2_MF2, VSUXSEG3EI8_V }, // 8224
  { PseudoVSUXSEG3EI8_V_MF2_MF2_MASK, VSUXSEG3EI8_V }, // 8225
  { PseudoVSUXSEG3EI8_V_MF4_M1, VSUXSEG3EI8_V }, // 8226
  { PseudoVSUXSEG3EI8_V_MF4_M1_MASK, VSUXSEG3EI8_V }, // 8227
  { PseudoVSUXSEG3EI8_V_MF4_M2, VSUXSEG3EI8_V }, // 8228
  { PseudoVSUXSEG3EI8_V_MF4_M2_MASK, VSUXSEG3EI8_V }, // 8229
  { PseudoVSUXSEG3EI8_V_MF4_MF2, VSUXSEG3EI8_V }, // 8230
  { PseudoVSUXSEG3EI8_V_MF4_MF2_MASK, VSUXSEG3EI8_V }, // 8231
  { PseudoVSUXSEG3EI8_V_MF4_MF4, VSUXSEG3EI8_V }, // 8232
  { PseudoVSUXSEG3EI8_V_MF4_MF4_MASK, VSUXSEG3EI8_V }, // 8233
  { PseudoVSUXSEG3EI8_V_MF8_M1, VSUXSEG3EI8_V }, // 8234
  { PseudoVSUXSEG3EI8_V_MF8_M1_MASK, VSUXSEG3EI8_V }, // 8235
  { PseudoVSUXSEG3EI8_V_MF8_MF2, VSUXSEG3EI8_V }, // 8236
  { PseudoVSUXSEG3EI8_V_MF8_MF2_MASK, VSUXSEG3EI8_V }, // 8237
  { PseudoVSUXSEG3EI8_V_MF8_MF4, VSUXSEG3EI8_V }, // 8238
  { PseudoVSUXSEG3EI8_V_MF8_MF4_MASK, VSUXSEG3EI8_V }, // 8239
  { PseudoVSUXSEG3EI8_V_MF8_MF8, VSUXSEG3EI8_V }, // 8240
  { PseudoVSUXSEG3EI8_V_MF8_MF8_MASK, VSUXSEG3EI8_V }, // 8241
  { PseudoVSUXSEG4EI16_V_M1_M1, VSUXSEG4EI16_V }, // 8242
  { PseudoVSUXSEG4EI16_V_M1_M1_MASK, VSUXSEG4EI16_V }, // 8243
  { PseudoVSUXSEG4EI16_V_M1_M2, VSUXSEG4EI16_V }, // 8244
  { PseudoVSUXSEG4EI16_V_M1_M2_MASK, VSUXSEG4EI16_V }, // 8245
  { PseudoVSUXSEG4EI16_V_M1_MF2, VSUXSEG4EI16_V }, // 8246
  { PseudoVSUXSEG4EI16_V_M1_MF2_MASK, VSUXSEG4EI16_V }, // 8247
  { PseudoVSUXSEG4EI16_V_M2_M1, VSUXSEG4EI16_V }, // 8248
  { PseudoVSUXSEG4EI16_V_M2_M1_MASK, VSUXSEG4EI16_V }, // 8249
  { PseudoVSUXSEG4EI16_V_M2_M2, VSUXSEG4EI16_V }, // 8250
  { PseudoVSUXSEG4EI16_V_M2_M2_MASK, VSUXSEG4EI16_V }, // 8251
  { PseudoVSUXSEG4EI16_V_M4_M2, VSUXSEG4EI16_V }, // 8252
  { PseudoVSUXSEG4EI16_V_M4_M2_MASK, VSUXSEG4EI16_V }, // 8253
  { PseudoVSUXSEG4EI16_V_MF2_M1, VSUXSEG4EI16_V }, // 8254
  { PseudoVSUXSEG4EI16_V_MF2_M1_MASK, VSUXSEG4EI16_V }, // 8255
  { PseudoVSUXSEG4EI16_V_MF2_M2, VSUXSEG4EI16_V }, // 8256
  { PseudoVSUXSEG4EI16_V_MF2_M2_MASK, VSUXSEG4EI16_V }, // 8257
  { PseudoVSUXSEG4EI16_V_MF2_MF2, VSUXSEG4EI16_V }, // 8258
  { PseudoVSUXSEG4EI16_V_MF2_MF2_MASK, VSUXSEG4EI16_V }, // 8259
  { PseudoVSUXSEG4EI16_V_MF2_MF4, VSUXSEG4EI16_V }, // 8260
  { PseudoVSUXSEG4EI16_V_MF2_MF4_MASK, VSUXSEG4EI16_V }, // 8261
  { PseudoVSUXSEG4EI16_V_MF4_M1, VSUXSEG4EI16_V }, // 8262
  { PseudoVSUXSEG4EI16_V_MF4_M1_MASK, VSUXSEG4EI16_V }, // 8263
  { PseudoVSUXSEG4EI16_V_MF4_MF2, VSUXSEG4EI16_V }, // 8264
  { PseudoVSUXSEG4EI16_V_MF4_MF2_MASK, VSUXSEG4EI16_V }, // 8265
  { PseudoVSUXSEG4EI16_V_MF4_MF4, VSUXSEG4EI16_V }, // 8266
  { PseudoVSUXSEG4EI16_V_MF4_MF4_MASK, VSUXSEG4EI16_V }, // 8267
  { PseudoVSUXSEG4EI16_V_MF4_MF8, VSUXSEG4EI16_V }, // 8268
  { PseudoVSUXSEG4EI16_V_MF4_MF8_MASK, VSUXSEG4EI16_V }, // 8269
  { PseudoVSUXSEG4EI32_V_M1_M1, VSUXSEG4EI32_V }, // 8270
  { PseudoVSUXSEG4EI32_V_M1_M1_MASK, VSUXSEG4EI32_V }, // 8271
  { PseudoVSUXSEG4EI32_V_M1_M2, VSUXSEG4EI32_V }, // 8272
  { PseudoVSUXSEG4EI32_V_M1_M2_MASK, VSUXSEG4EI32_V }, // 8273
  { PseudoVSUXSEG4EI32_V_M1_MF2, VSUXSEG4EI32_V }, // 8274
  { PseudoVSUXSEG4EI32_V_M1_MF2_MASK, VSUXSEG4EI32_V }, // 8275
  { PseudoVSUXSEG4EI32_V_M1_MF4, VSUXSEG4EI32_V }, // 8276
  { PseudoVSUXSEG4EI32_V_M1_MF4_MASK, VSUXSEG4EI32_V }, // 8277
  { PseudoVSUXSEG4EI32_V_M2_M1, VSUXSEG4EI32_V }, // 8278
  { PseudoVSUXSEG4EI32_V_M2_M1_MASK, VSUXSEG4EI32_V }, // 8279
  { PseudoVSUXSEG4EI32_V_M2_M2, VSUXSEG4EI32_V }, // 8280
  { PseudoVSUXSEG4EI32_V_M2_M2_MASK, VSUXSEG4EI32_V }, // 8281
  { PseudoVSUXSEG4EI32_V_M2_MF2, VSUXSEG4EI32_V }, // 8282
  { PseudoVSUXSEG4EI32_V_M2_MF2_MASK, VSUXSEG4EI32_V }, // 8283
  { PseudoVSUXSEG4EI32_V_M4_M1, VSUXSEG4EI32_V }, // 8284
  { PseudoVSUXSEG4EI32_V_M4_M1_MASK, VSUXSEG4EI32_V }, // 8285
  { PseudoVSUXSEG4EI32_V_M4_M2, VSUXSEG4EI32_V }, // 8286
  { PseudoVSUXSEG4EI32_V_M4_M2_MASK, VSUXSEG4EI32_V }, // 8287
  { PseudoVSUXSEG4EI32_V_M8_M2, VSUXSEG4EI32_V }, // 8288
  { PseudoVSUXSEG4EI32_V_M8_M2_MASK, VSUXSEG4EI32_V }, // 8289
  { PseudoVSUXSEG4EI32_V_MF2_M1, VSUXSEG4EI32_V }, // 8290
  { PseudoVSUXSEG4EI32_V_MF2_M1_MASK, VSUXSEG4EI32_V }, // 8291
  { PseudoVSUXSEG4EI32_V_MF2_MF2, VSUXSEG4EI32_V }, // 8292
  { PseudoVSUXSEG4EI32_V_MF2_MF2_MASK, VSUXSEG4EI32_V }, // 8293
  { PseudoVSUXSEG4EI32_V_MF2_MF4, VSUXSEG4EI32_V }, // 8294
  { PseudoVSUXSEG4EI32_V_MF2_MF4_MASK, VSUXSEG4EI32_V }, // 8295
  { PseudoVSUXSEG4EI32_V_MF2_MF8, VSUXSEG4EI32_V }, // 8296
  { PseudoVSUXSEG4EI32_V_MF2_MF8_MASK, VSUXSEG4EI32_V }, // 8297
  { PseudoVSUXSEG4EI64_V_M1_M1, VSUXSEG4EI64_V }, // 8298
  { PseudoVSUXSEG4EI64_V_M1_M1_MASK, VSUXSEG4EI64_V }, // 8299
  { PseudoVSUXSEG4EI64_V_M1_MF2, VSUXSEG4EI64_V }, // 8300
  { PseudoVSUXSEG4EI64_V_M1_MF2_MASK, VSUXSEG4EI64_V }, // 8301
  { PseudoVSUXSEG4EI64_V_M1_MF4, VSUXSEG4EI64_V }, // 8302
  { PseudoVSUXSEG4EI64_V_M1_MF4_MASK, VSUXSEG4EI64_V }, // 8303
  { PseudoVSUXSEG4EI64_V_M1_MF8, VSUXSEG4EI64_V }, // 8304
  { PseudoVSUXSEG4EI64_V_M1_MF8_MASK, VSUXSEG4EI64_V }, // 8305
  { PseudoVSUXSEG4EI64_V_M2_M1, VSUXSEG4EI64_V }, // 8306
  { PseudoVSUXSEG4EI64_V_M2_M1_MASK, VSUXSEG4EI64_V }, // 8307
  { PseudoVSUXSEG4EI64_V_M2_M2, VSUXSEG4EI64_V }, // 8308
  { PseudoVSUXSEG4EI64_V_M2_M2_MASK, VSUXSEG4EI64_V }, // 8309
  { PseudoVSUXSEG4EI64_V_M2_MF2, VSUXSEG4EI64_V }, // 8310
  { PseudoVSUXSEG4EI64_V_M2_MF2_MASK, VSUXSEG4EI64_V }, // 8311
  { PseudoVSUXSEG4EI64_V_M2_MF4, VSUXSEG4EI64_V }, // 8312
  { PseudoVSUXSEG4EI64_V_M2_MF4_MASK, VSUXSEG4EI64_V }, // 8313
  { PseudoVSUXSEG4EI64_V_M4_M1, VSUXSEG4EI64_V }, // 8314
  { PseudoVSUXSEG4EI64_V_M4_M1_MASK, VSUXSEG4EI64_V }, // 8315
  { PseudoVSUXSEG4EI64_V_M4_M2, VSUXSEG4EI64_V }, // 8316
  { PseudoVSUXSEG4EI64_V_M4_M2_MASK, VSUXSEG4EI64_V }, // 8317
  { PseudoVSUXSEG4EI64_V_M4_MF2, VSUXSEG4EI64_V }, // 8318
  { PseudoVSUXSEG4EI64_V_M4_MF2_MASK, VSUXSEG4EI64_V }, // 8319
  { PseudoVSUXSEG4EI64_V_M8_M1, VSUXSEG4EI64_V }, // 8320
  { PseudoVSUXSEG4EI64_V_M8_M1_MASK, VSUXSEG4EI64_V }, // 8321
  { PseudoVSUXSEG4EI64_V_M8_M2, VSUXSEG4EI64_V }, // 8322
  { PseudoVSUXSEG4EI64_V_M8_M2_MASK, VSUXSEG4EI64_V }, // 8323
  { PseudoVSUXSEG4EI8_V_M1_M1, VSUXSEG4EI8_V }, // 8324
  { PseudoVSUXSEG4EI8_V_M1_M1_MASK, VSUXSEG4EI8_V }, // 8325
  { PseudoVSUXSEG4EI8_V_M1_M2, VSUXSEG4EI8_V }, // 8326
  { PseudoVSUXSEG4EI8_V_M1_M2_MASK, VSUXSEG4EI8_V }, // 8327
  { PseudoVSUXSEG4EI8_V_M2_M2, VSUXSEG4EI8_V }, // 8328
  { PseudoVSUXSEG4EI8_V_M2_M2_MASK, VSUXSEG4EI8_V }, // 8329
  { PseudoVSUXSEG4EI8_V_MF2_M1, VSUXSEG4EI8_V }, // 8330
  { PseudoVSUXSEG4EI8_V_MF2_M1_MASK, VSUXSEG4EI8_V }, // 8331
  { PseudoVSUXSEG4EI8_V_MF2_M2, VSUXSEG4EI8_V }, // 8332
  { PseudoVSUXSEG4EI8_V_MF2_M2_MASK, VSUXSEG4EI8_V }, // 8333
  { PseudoVSUXSEG4EI8_V_MF2_MF2, VSUXSEG4EI8_V }, // 8334
  { PseudoVSUXSEG4EI8_V_MF2_MF2_MASK, VSUXSEG4EI8_V }, // 8335
  { PseudoVSUXSEG4EI8_V_MF4_M1, VSUXSEG4EI8_V }, // 8336
  { PseudoVSUXSEG4EI8_V_MF4_M1_MASK, VSUXSEG4EI8_V }, // 8337
  { PseudoVSUXSEG4EI8_V_MF4_M2, VSUXSEG4EI8_V }, // 8338
  { PseudoVSUXSEG4EI8_V_MF4_M2_MASK, VSUXSEG4EI8_V }, // 8339
  { PseudoVSUXSEG4EI8_V_MF4_MF2, VSUXSEG4EI8_V }, // 8340
  { PseudoVSUXSEG4EI8_V_MF4_MF2_MASK, VSUXSEG4EI8_V }, // 8341
  { PseudoVSUXSEG4EI8_V_MF4_MF4, VSUXSEG4EI8_V }, // 8342
  { PseudoVSUXSEG4EI8_V_MF4_MF4_MASK, VSUXSEG4EI8_V }, // 8343
  { PseudoVSUXSEG4EI8_V_MF8_M1, VSUXSEG4EI8_V }, // 8344
  { PseudoVSUXSEG4EI8_V_MF8_M1_MASK, VSUXSEG4EI8_V }, // 8345
  { PseudoVSUXSEG4EI8_V_MF8_MF2, VSUXSEG4EI8_V }, // 8346
  { PseudoVSUXSEG4EI8_V_MF8_MF2_MASK, VSUXSEG4EI8_V }, // 8347
  { PseudoVSUXSEG4EI8_V_MF8_MF4, VSUXSEG4EI8_V }, // 8348
  { PseudoVSUXSEG4EI8_V_MF8_MF4_MASK, VSUXSEG4EI8_V }, // 8349
  { PseudoVSUXSEG4EI8_V_MF8_MF8, VSUXSEG4EI8_V }, // 8350
  { PseudoVSUXSEG4EI8_V_MF8_MF8_MASK, VSUXSEG4EI8_V }, // 8351
  { PseudoVSUXSEG5EI16_V_M1_M1, VSUXSEG5EI16_V }, // 8352
  { PseudoVSUXSEG5EI16_V_M1_M1_MASK, VSUXSEG5EI16_V }, // 8353
  { PseudoVSUXSEG5EI16_V_M1_MF2, VSUXSEG5EI16_V }, // 8354
  { PseudoVSUXSEG5EI16_V_M1_MF2_MASK, VSUXSEG5EI16_V }, // 8355
  { PseudoVSUXSEG5EI16_V_M2_M1, VSUXSEG5EI16_V }, // 8356
  { PseudoVSUXSEG5EI16_V_M2_M1_MASK, VSUXSEG5EI16_V }, // 8357
  { PseudoVSUXSEG5EI16_V_MF2_M1, VSUXSEG5EI16_V }, // 8358
  { PseudoVSUXSEG5EI16_V_MF2_M1_MASK, VSUXSEG5EI16_V }, // 8359
  { PseudoVSUXSEG5EI16_V_MF2_MF2, VSUXSEG5EI16_V }, // 8360
  { PseudoVSUXSEG5EI16_V_MF2_MF2_MASK, VSUXSEG5EI16_V }, // 8361
  { PseudoVSUXSEG5EI16_V_MF2_MF4, VSUXSEG5EI16_V }, // 8362
  { PseudoVSUXSEG5EI16_V_MF2_MF4_MASK, VSUXSEG5EI16_V }, // 8363
  { PseudoVSUXSEG5EI16_V_MF4_M1, VSUXSEG5EI16_V }, // 8364
  { PseudoVSUXSEG5EI16_V_MF4_M1_MASK, VSUXSEG5EI16_V }, // 8365
  { PseudoVSUXSEG5EI16_V_MF4_MF2, VSUXSEG5EI16_V }, // 8366
  { PseudoVSUXSEG5EI16_V_MF4_MF2_MASK, VSUXSEG5EI16_V }, // 8367
  { PseudoVSUXSEG5EI16_V_MF4_MF4, VSUXSEG5EI16_V }, // 8368
  { PseudoVSUXSEG5EI16_V_MF4_MF4_MASK, VSUXSEG5EI16_V }, // 8369
  { PseudoVSUXSEG5EI16_V_MF4_MF8, VSUXSEG5EI16_V }, // 8370
  { PseudoVSUXSEG5EI16_V_MF4_MF8_MASK, VSUXSEG5EI16_V }, // 8371
  { PseudoVSUXSEG5EI32_V_M1_M1, VSUXSEG5EI32_V }, // 8372
  { PseudoVSUXSEG5EI32_V_M1_M1_MASK, VSUXSEG5EI32_V }, // 8373
  { PseudoVSUXSEG5EI32_V_M1_MF2, VSUXSEG5EI32_V }, // 8374
  { PseudoVSUXSEG5EI32_V_M1_MF2_MASK, VSUXSEG5EI32_V }, // 8375
  { PseudoVSUXSEG5EI32_V_M1_MF4, VSUXSEG5EI32_V }, // 8376
  { PseudoVSUXSEG5EI32_V_M1_MF4_MASK, VSUXSEG5EI32_V }, // 8377
  { PseudoVSUXSEG5EI32_V_M2_M1, VSUXSEG5EI32_V }, // 8378
  { PseudoVSUXSEG5EI32_V_M2_M1_MASK, VSUXSEG5EI32_V }, // 8379
  { PseudoVSUXSEG5EI32_V_M2_MF2, VSUXSEG5EI32_V }, // 8380
  { PseudoVSUXSEG5EI32_V_M2_MF2_MASK, VSUXSEG5EI32_V }, // 8381
  { PseudoVSUXSEG5EI32_V_M4_M1, VSUXSEG5EI32_V }, // 8382
  { PseudoVSUXSEG5EI32_V_M4_M1_MASK, VSUXSEG5EI32_V }, // 8383
  { PseudoVSUXSEG5EI32_V_MF2_M1, VSUXSEG5EI32_V }, // 8384
  { PseudoVSUXSEG5EI32_V_MF2_M1_MASK, VSUXSEG5EI32_V }, // 8385
  { PseudoVSUXSEG5EI32_V_MF2_MF2, VSUXSEG5EI32_V }, // 8386
  { PseudoVSUXSEG5EI32_V_MF2_MF2_MASK, VSUXSEG5EI32_V }, // 8387
  { PseudoVSUXSEG5EI32_V_MF2_MF4, VSUXSEG5EI32_V }, // 8388
  { PseudoVSUXSEG5EI32_V_MF2_MF4_MASK, VSUXSEG5EI32_V }, // 8389
  { PseudoVSUXSEG5EI32_V_MF2_MF8, VSUXSEG5EI32_V }, // 8390
  { PseudoVSUXSEG5EI32_V_MF2_MF8_MASK, VSUXSEG5EI32_V }, // 8391
  { PseudoVSUXSEG5EI64_V_M1_M1, VSUXSEG5EI64_V }, // 8392
  { PseudoVSUXSEG5EI64_V_M1_M1_MASK, VSUXSEG5EI64_V }, // 8393
  { PseudoVSUXSEG5EI64_V_M1_MF2, VSUXSEG5EI64_V }, // 8394
  { PseudoVSUXSEG5EI64_V_M1_MF2_MASK, VSUXSEG5EI64_V }, // 8395
  { PseudoVSUXSEG5EI64_V_M1_MF4, VSUXSEG5EI64_V }, // 8396
  { PseudoVSUXSEG5EI64_V_M1_MF4_MASK, VSUXSEG5EI64_V }, // 8397
  { PseudoVSUXSEG5EI64_V_M1_MF8, VSUXSEG5EI64_V }, // 8398
  { PseudoVSUXSEG5EI64_V_M1_MF8_MASK, VSUXSEG5EI64_V }, // 8399
  { PseudoVSUXSEG5EI64_V_M2_M1, VSUXSEG5EI64_V }, // 8400
  { PseudoVSUXSEG5EI64_V_M2_M1_MASK, VSUXSEG5EI64_V }, // 8401
  { PseudoVSUXSEG5EI64_V_M2_MF2, VSUXSEG5EI64_V }, // 8402
  { PseudoVSUXSEG5EI64_V_M2_MF2_MASK, VSUXSEG5EI64_V }, // 8403
  { PseudoVSUXSEG5EI64_V_M2_MF4, VSUXSEG5EI64_V }, // 8404
  { PseudoVSUXSEG5EI64_V_M2_MF4_MASK, VSUXSEG5EI64_V }, // 8405
  { PseudoVSUXSEG5EI64_V_M4_M1, VSUXSEG5EI64_V }, // 8406
  { PseudoVSUXSEG5EI64_V_M4_M1_MASK, VSUXSEG5EI64_V }, // 8407
  { PseudoVSUXSEG5EI64_V_M4_MF2, VSUXSEG5EI64_V }, // 8408
  { PseudoVSUXSEG5EI64_V_M4_MF2_MASK, VSUXSEG5EI64_V }, // 8409
  { PseudoVSUXSEG5EI64_V_M8_M1, VSUXSEG5EI64_V }, // 8410
  { PseudoVSUXSEG5EI64_V_M8_M1_MASK, VSUXSEG5EI64_V }, // 8411
  { PseudoVSUXSEG5EI8_V_M1_M1, VSUXSEG5EI8_V }, // 8412
  { PseudoVSUXSEG5EI8_V_M1_M1_MASK, VSUXSEG5EI8_V }, // 8413
  { PseudoVSUXSEG5EI8_V_MF2_M1, VSUXSEG5EI8_V }, // 8414
  { PseudoVSUXSEG5EI8_V_MF2_M1_MASK, VSUXSEG5EI8_V }, // 8415
  { PseudoVSUXSEG5EI8_V_MF2_MF2, VSUXSEG5EI8_V }, // 8416
  { PseudoVSUXSEG5EI8_V_MF2_MF2_MASK, VSUXSEG5EI8_V }, // 8417
  { PseudoVSUXSEG5EI8_V_MF4_M1, VSUXSEG5EI8_V }, // 8418
  { PseudoVSUXSEG5EI8_V_MF4_M1_MASK, VSUXSEG5EI8_V }, // 8419
  { PseudoVSUXSEG5EI8_V_MF4_MF2, VSUXSEG5EI8_V }, // 8420
  { PseudoVSUXSEG5EI8_V_MF4_MF2_MASK, VSUXSEG5EI8_V }, // 8421
  { PseudoVSUXSEG5EI8_V_MF4_MF4, VSUXSEG5EI8_V }, // 8422
  { PseudoVSUXSEG5EI8_V_MF4_MF4_MASK, VSUXSEG5EI8_V }, // 8423
  { PseudoVSUXSEG5EI8_V_MF8_M1, VSUXSEG5EI8_V }, // 8424
  { PseudoVSUXSEG5EI8_V_MF8_M1_MASK, VSUXSEG5EI8_V }, // 8425
  { PseudoVSUXSEG5EI8_V_MF8_MF2, VSUXSEG5EI8_V }, // 8426
  { PseudoVSUXSEG5EI8_V_MF8_MF2_MASK, VSUXSEG5EI8_V }, // 8427
  { PseudoVSUXSEG5EI8_V_MF8_MF4, VSUXSEG5EI8_V }, // 8428
  { PseudoVSUXSEG5EI8_V_MF8_MF4_MASK, VSUXSEG5EI8_V }, // 8429
  { PseudoVSUXSEG5EI8_V_MF8_MF8, VSUXSEG5EI8_V }, // 8430
  { PseudoVSUXSEG5EI8_V_MF8_MF8_MASK, VSUXSEG5EI8_V }, // 8431
  { PseudoVSUXSEG6EI16_V_M1_M1, VSUXSEG6EI16_V }, // 8432
  { PseudoVSUXSEG6EI16_V_M1_M1_MASK, VSUXSEG6EI16_V }, // 8433
  { PseudoVSUXSEG6EI16_V_M1_MF2, VSUXSEG6EI16_V }, // 8434
  { PseudoVSUXSEG6EI16_V_M1_MF2_MASK, VSUXSEG6EI16_V }, // 8435
  { PseudoVSUXSEG6EI16_V_M2_M1, VSUXSEG6EI16_V }, // 8436
  { PseudoVSUXSEG6EI16_V_M2_M1_MASK, VSUXSEG6EI16_V }, // 8437
  { PseudoVSUXSEG6EI16_V_MF2_M1, VSUXSEG6EI16_V }, // 8438
  { PseudoVSUXSEG6EI16_V_MF2_M1_MASK, VSUXSEG6EI16_V }, // 8439
  { PseudoVSUXSEG6EI16_V_MF2_MF2, VSUXSEG6EI16_V }, // 8440
  { PseudoVSUXSEG6EI16_V_MF2_MF2_MASK, VSUXSEG6EI16_V }, // 8441
  { PseudoVSUXSEG6EI16_V_MF2_MF4, VSUXSEG6EI16_V }, // 8442
  { PseudoVSUXSEG6EI16_V_MF2_MF4_MASK, VSUXSEG6EI16_V }, // 8443
  { PseudoVSUXSEG6EI16_V_MF4_M1, VSUXSEG6EI16_V }, // 8444
  { PseudoVSUXSEG6EI16_V_MF4_M1_MASK, VSUXSEG6EI16_V }, // 8445
  { PseudoVSUXSEG6EI16_V_MF4_MF2, VSUXSEG6EI16_V }, // 8446
  { PseudoVSUXSEG6EI16_V_MF4_MF2_MASK, VSUXSEG6EI16_V }, // 8447
  { PseudoVSUXSEG6EI16_V_MF4_MF4, VSUXSEG6EI16_V }, // 8448
  { PseudoVSUXSEG6EI16_V_MF4_MF4_MASK, VSUXSEG6EI16_V }, // 8449
  { PseudoVSUXSEG6EI16_V_MF4_MF8, VSUXSEG6EI16_V }, // 8450
  { PseudoVSUXSEG6EI16_V_MF4_MF8_MASK, VSUXSEG6EI16_V }, // 8451
  { PseudoVSUXSEG6EI32_V_M1_M1, VSUXSEG6EI32_V }, // 8452
  { PseudoVSUXSEG6EI32_V_M1_M1_MASK, VSUXSEG6EI32_V }, // 8453
  { PseudoVSUXSEG6EI32_V_M1_MF2, VSUXSEG6EI32_V }, // 8454
  { PseudoVSUXSEG6EI32_V_M1_MF2_MASK, VSUXSEG6EI32_V }, // 8455
  { PseudoVSUXSEG6EI32_V_M1_MF4, VSUXSEG6EI32_V }, // 8456
  { PseudoVSUXSEG6EI32_V_M1_MF4_MASK, VSUXSEG6EI32_V }, // 8457
  { PseudoVSUXSEG6EI32_V_M2_M1, VSUXSEG6EI32_V }, // 8458
  { PseudoVSUXSEG6EI32_V_M2_M1_MASK, VSUXSEG6EI32_V }, // 8459
  { PseudoVSUXSEG6EI32_V_M2_MF2, VSUXSEG6EI32_V }, // 8460
  { PseudoVSUXSEG6EI32_V_M2_MF2_MASK, VSUXSEG6EI32_V }, // 8461
  { PseudoVSUXSEG6EI32_V_M4_M1, VSUXSEG6EI32_V }, // 8462
  { PseudoVSUXSEG6EI32_V_M4_M1_MASK, VSUXSEG6EI32_V }, // 8463
  { PseudoVSUXSEG6EI32_V_MF2_M1, VSUXSEG6EI32_V }, // 8464
  { PseudoVSUXSEG6EI32_V_MF2_M1_MASK, VSUXSEG6EI32_V }, // 8465
  { PseudoVSUXSEG6EI32_V_MF2_MF2, VSUXSEG6EI32_V }, // 8466
  { PseudoVSUXSEG6EI32_V_MF2_MF2_MASK, VSUXSEG6EI32_V }, // 8467
  { PseudoVSUXSEG6EI32_V_MF2_MF4, VSUXSEG6EI32_V }, // 8468
  { PseudoVSUXSEG6EI32_V_MF2_MF4_MASK, VSUXSEG6EI32_V }, // 8469
  { PseudoVSUXSEG6EI32_V_MF2_MF8, VSUXSEG6EI32_V }, // 8470
  { PseudoVSUXSEG6EI32_V_MF2_MF8_MASK, VSUXSEG6EI32_V }, // 8471
  { PseudoVSUXSEG6EI64_V_M1_M1, VSUXSEG6EI64_V }, // 8472
  { PseudoVSUXSEG6EI64_V_M1_M1_MASK, VSUXSEG6EI64_V }, // 8473
  { PseudoVSUXSEG6EI64_V_M1_MF2, VSUXSEG6EI64_V }, // 8474
  { PseudoVSUXSEG6EI64_V_M1_MF2_MASK, VSUXSEG6EI64_V }, // 8475
  { PseudoVSUXSEG6EI64_V_M1_MF4, VSUXSEG6EI64_V }, // 8476
  { PseudoVSUXSEG6EI64_V_M1_MF4_MASK, VSUXSEG6EI64_V }, // 8477
  { PseudoVSUXSEG6EI64_V_M1_MF8, VSUXSEG6EI64_V }, // 8478
  { PseudoVSUXSEG6EI64_V_M1_MF8_MASK, VSUXSEG6EI64_V }, // 8479
  { PseudoVSUXSEG6EI64_V_M2_M1, VSUXSEG6EI64_V }, // 8480
  { PseudoVSUXSEG6EI64_V_M2_M1_MASK, VSUXSEG6EI64_V }, // 8481
  { PseudoVSUXSEG6EI64_V_M2_MF2, VSUXSEG6EI64_V }, // 8482
  { PseudoVSUXSEG6EI64_V_M2_MF2_MASK, VSUXSEG6EI64_V }, // 8483
  { PseudoVSUXSEG6EI64_V_M2_MF4, VSUXSEG6EI64_V }, // 8484
  { PseudoVSUXSEG6EI64_V_M2_MF4_MASK, VSUXSEG6EI64_V }, // 8485
  { PseudoVSUXSEG6EI64_V_M4_M1, VSUXSEG6EI64_V }, // 8486
  { PseudoVSUXSEG6EI64_V_M4_M1_MASK, VSUXSEG6EI64_V }, // 8487
  { PseudoVSUXSEG6EI64_V_M4_MF2, VSUXSEG6EI64_V }, // 8488
  { PseudoVSUXSEG6EI64_V_M4_MF2_MASK, VSUXSEG6EI64_V }, // 8489
  { PseudoVSUXSEG6EI64_V_M8_M1, VSUXSEG6EI64_V }, // 8490
  { PseudoVSUXSEG6EI64_V_M8_M1_MASK, VSUXSEG6EI64_V }, // 8491
  { PseudoVSUXSEG6EI8_V_M1_M1, VSUXSEG6EI8_V }, // 8492
  { PseudoVSUXSEG6EI8_V_M1_M1_MASK, VSUXSEG6EI8_V }, // 8493
  { PseudoVSUXSEG6EI8_V_MF2_M1, VSUXSEG6EI8_V }, // 8494
  { PseudoVSUXSEG6EI8_V_MF2_M1_MASK, VSUXSEG6EI8_V }, // 8495
  { PseudoVSUXSEG6EI8_V_MF2_MF2, VSUXSEG6EI8_V }, // 8496
  { PseudoVSUXSEG6EI8_V_MF2_MF2_MASK, VSUXSEG6EI8_V }, // 8497
  { PseudoVSUXSEG6EI8_V_MF4_M1, VSUXSEG6EI8_V }, // 8498
  { PseudoVSUXSEG6EI8_V_MF4_M1_MASK, VSUXSEG6EI8_V }, // 8499
  { PseudoVSUXSEG6EI8_V_MF4_MF2, VSUXSEG6EI8_V }, // 8500
  { PseudoVSUXSEG6EI8_V_MF4_MF2_MASK, VSUXSEG6EI8_V }, // 8501
  { PseudoVSUXSEG6EI8_V_MF4_MF4, VSUXSEG6EI8_V }, // 8502
  { PseudoVSUXSEG6EI8_V_MF4_MF4_MASK, VSUXSEG6EI8_V }, // 8503
  { PseudoVSUXSEG6EI8_V_MF8_M1, VSUXSEG6EI8_V }, // 8504
  { PseudoVSUXSEG6EI8_V_MF8_M1_MASK, VSUXSEG6EI8_V }, // 8505
  { PseudoVSUXSEG6EI8_V_MF8_MF2, VSUXSEG6EI8_V }, // 8506
  { PseudoVSUXSEG6EI8_V_MF8_MF2_MASK, VSUXSEG6EI8_V }, // 8507
  { PseudoVSUXSEG6EI8_V_MF8_MF4, VSUXSEG6EI8_V }, // 8508
  { PseudoVSUXSEG6EI8_V_MF8_MF4_MASK, VSUXSEG6EI8_V }, // 8509
  { PseudoVSUXSEG6EI8_V_MF8_MF8, VSUXSEG6EI8_V }, // 8510
  { PseudoVSUXSEG6EI8_V_MF8_MF8_MASK, VSUXSEG6EI8_V }, // 8511
  { PseudoVSUXSEG7EI16_V_M1_M1, VSUXSEG7EI16_V }, // 8512
  { PseudoVSUXSEG7EI16_V_M1_M1_MASK, VSUXSEG7EI16_V }, // 8513
  { PseudoVSUXSEG7EI16_V_M1_MF2, VSUXSEG7EI16_V }, // 8514
  { PseudoVSUXSEG7EI16_V_M1_MF2_MASK, VSUXSEG7EI16_V }, // 8515
  { PseudoVSUXSEG7EI16_V_M2_M1, VSUXSEG7EI16_V }, // 8516
  { PseudoVSUXSEG7EI16_V_M2_M1_MASK, VSUXSEG7EI16_V }, // 8517
  { PseudoVSUXSEG7EI16_V_MF2_M1, VSUXSEG7EI16_V }, // 8518
  { PseudoVSUXSEG7EI16_V_MF2_M1_MASK, VSUXSEG7EI16_V }, // 8519
  { PseudoVSUXSEG7EI16_V_MF2_MF2, VSUXSEG7EI16_V }, // 8520
  { PseudoVSUXSEG7EI16_V_MF2_MF2_MASK, VSUXSEG7EI16_V }, // 8521
  { PseudoVSUXSEG7EI16_V_MF2_MF4, VSUXSEG7EI16_V }, // 8522
  { PseudoVSUXSEG7EI16_V_MF2_MF4_MASK, VSUXSEG7EI16_V }, // 8523
  { PseudoVSUXSEG7EI16_V_MF4_M1, VSUXSEG7EI16_V }, // 8524
  { PseudoVSUXSEG7EI16_V_MF4_M1_MASK, VSUXSEG7EI16_V }, // 8525
  { PseudoVSUXSEG7EI16_V_MF4_MF2, VSUXSEG7EI16_V }, // 8526
  { PseudoVSUXSEG7EI16_V_MF4_MF2_MASK, VSUXSEG7EI16_V }, // 8527
  { PseudoVSUXSEG7EI16_V_MF4_MF4, VSUXSEG7EI16_V }, // 8528
  { PseudoVSUXSEG7EI16_V_MF4_MF4_MASK, VSUXSEG7EI16_V }, // 8529
  { PseudoVSUXSEG7EI16_V_MF4_MF8, VSUXSEG7EI16_V }, // 8530
  { PseudoVSUXSEG7EI16_V_MF4_MF8_MASK, VSUXSEG7EI16_V }, // 8531
  { PseudoVSUXSEG7EI32_V_M1_M1, VSUXSEG7EI32_V }, // 8532
  { PseudoVSUXSEG7EI32_V_M1_M1_MASK, VSUXSEG7EI32_V }, // 8533
  { PseudoVSUXSEG7EI32_V_M1_MF2, VSUXSEG7EI32_V }, // 8534
  { PseudoVSUXSEG7EI32_V_M1_MF2_MASK, VSUXSEG7EI32_V }, // 8535
  { PseudoVSUXSEG7EI32_V_M1_MF4, VSUXSEG7EI32_V }, // 8536
  { PseudoVSUXSEG7EI32_V_M1_MF4_MASK, VSUXSEG7EI32_V }, // 8537
  { PseudoVSUXSEG7EI32_V_M2_M1, VSUXSEG7EI32_V }, // 8538
  { PseudoVSUXSEG7EI32_V_M2_M1_MASK, VSUXSEG7EI32_V }, // 8539
  { PseudoVSUXSEG7EI32_V_M2_MF2, VSUXSEG7EI32_V }, // 8540
  { PseudoVSUXSEG7EI32_V_M2_MF2_MASK, VSUXSEG7EI32_V }, // 8541
  { PseudoVSUXSEG7EI32_V_M4_M1, VSUXSEG7EI32_V }, // 8542
  { PseudoVSUXSEG7EI32_V_M4_M1_MASK, VSUXSEG7EI32_V }, // 8543
  { PseudoVSUXSEG7EI32_V_MF2_M1, VSUXSEG7EI32_V }, // 8544
  { PseudoVSUXSEG7EI32_V_MF2_M1_MASK, VSUXSEG7EI32_V }, // 8545
  { PseudoVSUXSEG7EI32_V_MF2_MF2, VSUXSEG7EI32_V }, // 8546
  { PseudoVSUXSEG7EI32_V_MF2_MF2_MASK, VSUXSEG7EI32_V }, // 8547
  { PseudoVSUXSEG7EI32_V_MF2_MF4, VSUXSEG7EI32_V }, // 8548
  { PseudoVSUXSEG7EI32_V_MF2_MF4_MASK, VSUXSEG7EI32_V }, // 8549
  { PseudoVSUXSEG7EI32_V_MF2_MF8, VSUXSEG7EI32_V }, // 8550
  { PseudoVSUXSEG7EI32_V_MF2_MF8_MASK, VSUXSEG7EI32_V }, // 8551
  { PseudoVSUXSEG7EI64_V_M1_M1, VSUXSEG7EI64_V }, // 8552
  { PseudoVSUXSEG7EI64_V_M1_M1_MASK, VSUXSEG7EI64_V }, // 8553
  { PseudoVSUXSEG7EI64_V_M1_MF2, VSUXSEG7EI64_V }, // 8554
  { PseudoVSUXSEG7EI64_V_M1_MF2_MASK, VSUXSEG7EI64_V }, // 8555
  { PseudoVSUXSEG7EI64_V_M1_MF4, VSUXSEG7EI64_V }, // 8556
  { PseudoVSUXSEG7EI64_V_M1_MF4_MASK, VSUXSEG7EI64_V }, // 8557
  { PseudoVSUXSEG7EI64_V_M1_MF8, VSUXSEG7EI64_V }, // 8558
  { PseudoVSUXSEG7EI64_V_M1_MF8_MASK, VSUXSEG7EI64_V }, // 8559
  { PseudoVSUXSEG7EI64_V_M2_M1, VSUXSEG7EI64_V }, // 8560
  { PseudoVSUXSEG7EI64_V_M2_M1_MASK, VSUXSEG7EI64_V }, // 8561
  { PseudoVSUXSEG7EI64_V_M2_MF2, VSUXSEG7EI64_V }, // 8562
  { PseudoVSUXSEG7EI64_V_M2_MF2_MASK, VSUXSEG7EI64_V }, // 8563
  { PseudoVSUXSEG7EI64_V_M2_MF4, VSUXSEG7EI64_V }, // 8564
  { PseudoVSUXSEG7EI64_V_M2_MF4_MASK, VSUXSEG7EI64_V }, // 8565
  { PseudoVSUXSEG7EI64_V_M4_M1, VSUXSEG7EI64_V }, // 8566
  { PseudoVSUXSEG7EI64_V_M4_M1_MASK, VSUXSEG7EI64_V }, // 8567
  { PseudoVSUXSEG7EI64_V_M4_MF2, VSUXSEG7EI64_V }, // 8568
  { PseudoVSUXSEG7EI64_V_M4_MF2_MASK, VSUXSEG7EI64_V }, // 8569
  { PseudoVSUXSEG7EI64_V_M8_M1, VSUXSEG7EI64_V }, // 8570
  { PseudoVSUXSEG7EI64_V_M8_M1_MASK, VSUXSEG7EI64_V }, // 8571
  { PseudoVSUXSEG7EI8_V_M1_M1, VSUXSEG7EI8_V }, // 8572
  { PseudoVSUXSEG7EI8_V_M1_M1_MASK, VSUXSEG7EI8_V }, // 8573
  { PseudoVSUXSEG7EI8_V_MF2_M1, VSUXSEG7EI8_V }, // 8574
  { PseudoVSUXSEG7EI8_V_MF2_M1_MASK, VSUXSEG7EI8_V }, // 8575
  { PseudoVSUXSEG7EI8_V_MF2_MF2, VSUXSEG7EI8_V }, // 8576
  { PseudoVSUXSEG7EI8_V_MF2_MF2_MASK, VSUXSEG7EI8_V }, // 8577
  { PseudoVSUXSEG7EI8_V_MF4_M1, VSUXSEG7EI8_V }, // 8578
  { PseudoVSUXSEG7EI8_V_MF4_M1_MASK, VSUXSEG7EI8_V }, // 8579
  { PseudoVSUXSEG7EI8_V_MF4_MF2, VSUXSEG7EI8_V }, // 8580
  { PseudoVSUXSEG7EI8_V_MF4_MF2_MASK, VSUXSEG7EI8_V }, // 8581
  { PseudoVSUXSEG7EI8_V_MF4_MF4, VSUXSEG7EI8_V }, // 8582
  { PseudoVSUXSEG7EI8_V_MF4_MF4_MASK, VSUXSEG7EI8_V }, // 8583
  { PseudoVSUXSEG7EI8_V_MF8_M1, VSUXSEG7EI8_V }, // 8584
  { PseudoVSUXSEG7EI8_V_MF8_M1_MASK, VSUXSEG7EI8_V }, // 8585
  { PseudoVSUXSEG7EI8_V_MF8_MF2, VSUXSEG7EI8_V }, // 8586
  { PseudoVSUXSEG7EI8_V_MF8_MF2_MASK, VSUXSEG7EI8_V }, // 8587
  { PseudoVSUXSEG7EI8_V_MF8_MF4, VSUXSEG7EI8_V }, // 8588
  { PseudoVSUXSEG7EI8_V_MF8_MF4_MASK, VSUXSEG7EI8_V }, // 8589
  { PseudoVSUXSEG7EI8_V_MF8_MF8, VSUXSEG7EI8_V }, // 8590
  { PseudoVSUXSEG7EI8_V_MF8_MF8_MASK, VSUXSEG7EI8_V }, // 8591
  { PseudoVSUXSEG8EI16_V_M1_M1, VSUXSEG8EI16_V }, // 8592
  { PseudoVSUXSEG8EI16_V_M1_M1_MASK, VSUXSEG8EI16_V }, // 8593
  { PseudoVSUXSEG8EI16_V_M1_MF2, VSUXSEG8EI16_V }, // 8594
  { PseudoVSUXSEG8EI16_V_M1_MF2_MASK, VSUXSEG8EI16_V }, // 8595
  { PseudoVSUXSEG8EI16_V_M2_M1, VSUXSEG8EI16_V }, // 8596
  { PseudoVSUXSEG8EI16_V_M2_M1_MASK, VSUXSEG8EI16_V }, // 8597
  { PseudoVSUXSEG8EI16_V_MF2_M1, VSUXSEG8EI16_V }, // 8598
  { PseudoVSUXSEG8EI16_V_MF2_M1_MASK, VSUXSEG8EI16_V }, // 8599
  { PseudoVSUXSEG8EI16_V_MF2_MF2, VSUXSEG8EI16_V }, // 8600
  { PseudoVSUXSEG8EI16_V_MF2_MF2_MASK, VSUXSEG8EI16_V }, // 8601
  { PseudoVSUXSEG8EI16_V_MF2_MF4, VSUXSEG8EI16_V }, // 8602
  { PseudoVSUXSEG8EI16_V_MF2_MF4_MASK, VSUXSEG8EI16_V }, // 8603
  { PseudoVSUXSEG8EI16_V_MF4_M1, VSUXSEG8EI16_V }, // 8604
  { PseudoVSUXSEG8EI16_V_MF4_M1_MASK, VSUXSEG8EI16_V }, // 8605
  { PseudoVSUXSEG8EI16_V_MF4_MF2, VSUXSEG8EI16_V }, // 8606
  { PseudoVSUXSEG8EI16_V_MF4_MF2_MASK, VSUXSEG8EI16_V }, // 8607
  { PseudoVSUXSEG8EI16_V_MF4_MF4, VSUXSEG8EI16_V }, // 8608
  { PseudoVSUXSEG8EI16_V_MF4_MF4_MASK, VSUXSEG8EI16_V }, // 8609
  { PseudoVSUXSEG8EI16_V_MF4_MF8, VSUXSEG8EI16_V }, // 8610
  { PseudoVSUXSEG8EI16_V_MF4_MF8_MASK, VSUXSEG8EI16_V }, // 8611
  { PseudoVSUXSEG8EI32_V_M1_M1, VSUXSEG8EI32_V }, // 8612
  { PseudoVSUXSEG8EI32_V_M1_M1_MASK, VSUXSEG8EI32_V }, // 8613
  { PseudoVSUXSEG8EI32_V_M1_MF2, VSUXSEG8EI32_V }, // 8614
  { PseudoVSUXSEG8EI32_V_M1_MF2_MASK, VSUXSEG8EI32_V }, // 8615
  { PseudoVSUXSEG8EI32_V_M1_MF4, VSUXSEG8EI32_V }, // 8616
  { PseudoVSUXSEG8EI32_V_M1_MF4_MASK, VSUXSEG8EI32_V }, // 8617
  { PseudoVSUXSEG8EI32_V_M2_M1, VSUXSEG8EI32_V }, // 8618
  { PseudoVSUXSEG8EI32_V_M2_M1_MASK, VSUXSEG8EI32_V }, // 8619
  { PseudoVSUXSEG8EI32_V_M2_MF2, VSUXSEG8EI32_V }, // 8620
  { PseudoVSUXSEG8EI32_V_M2_MF2_MASK, VSUXSEG8EI32_V }, // 8621
  { PseudoVSUXSEG8EI32_V_M4_M1, VSUXSEG8EI32_V }, // 8622
  { PseudoVSUXSEG8EI32_V_M4_M1_MASK, VSUXSEG8EI32_V }, // 8623
  { PseudoVSUXSEG8EI32_V_MF2_M1, VSUXSEG8EI32_V }, // 8624
  { PseudoVSUXSEG8EI32_V_MF2_M1_MASK, VSUXSEG8EI32_V }, // 8625
  { PseudoVSUXSEG8EI32_V_MF2_MF2, VSUXSEG8EI32_V }, // 8626
  { PseudoVSUXSEG8EI32_V_MF2_MF2_MASK, VSUXSEG8EI32_V }, // 8627
  { PseudoVSUXSEG8EI32_V_MF2_MF4, VSUXSEG8EI32_V }, // 8628
  { PseudoVSUXSEG8EI32_V_MF2_MF4_MASK, VSUXSEG8EI32_V }, // 8629
  { PseudoVSUXSEG8EI32_V_MF2_MF8, VSUXSEG8EI32_V }, // 8630
  { PseudoVSUXSEG8EI32_V_MF2_MF8_MASK, VSUXSEG8EI32_V }, // 8631
  { PseudoVSUXSEG8EI64_V_M1_M1, VSUXSEG8EI64_V }, // 8632
  { PseudoVSUXSEG8EI64_V_M1_M1_MASK, VSUXSEG8EI64_V }, // 8633
  { PseudoVSUXSEG8EI64_V_M1_MF2, VSUXSEG8EI64_V }, // 8634
  { PseudoVSUXSEG8EI64_V_M1_MF2_MASK, VSUXSEG8EI64_V }, // 8635
  { PseudoVSUXSEG8EI64_V_M1_MF4, VSUXSEG8EI64_V }, // 8636
  { PseudoVSUXSEG8EI64_V_M1_MF4_MASK, VSUXSEG8EI64_V }, // 8637
  { PseudoVSUXSEG8EI64_V_M1_MF8, VSUXSEG8EI64_V }, // 8638
  { PseudoVSUXSEG8EI64_V_M1_MF8_MASK, VSUXSEG8EI64_V }, // 8639
  { PseudoVSUXSEG8EI64_V_M2_M1, VSUXSEG8EI64_V }, // 8640
  { PseudoVSUXSEG8EI64_V_M2_M1_MASK, VSUXSEG8EI64_V }, // 8641
  { PseudoVSUXSEG8EI64_V_M2_MF2, VSUXSEG8EI64_V }, // 8642
  { PseudoVSUXSEG8EI64_V_M2_MF2_MASK, VSUXSEG8EI64_V }, // 8643
  { PseudoVSUXSEG8EI64_V_M2_MF4, VSUXSEG8EI64_V }, // 8644
  { PseudoVSUXSEG8EI64_V_M2_MF4_MASK, VSUXSEG8EI64_V }, // 8645
  { PseudoVSUXSEG8EI64_V_M4_M1, VSUXSEG8EI64_V }, // 8646
  { PseudoVSUXSEG8EI64_V_M4_M1_MASK, VSUXSEG8EI64_V }, // 8647
  { PseudoVSUXSEG8EI64_V_M4_MF2, VSUXSEG8EI64_V }, // 8648
  { PseudoVSUXSEG8EI64_V_M4_MF2_MASK, VSUXSEG8EI64_V }, // 8649
  { PseudoVSUXSEG8EI64_V_M8_M1, VSUXSEG8EI64_V }, // 8650
  { PseudoVSUXSEG8EI64_V_M8_M1_MASK, VSUXSEG8EI64_V }, // 8651
  { PseudoVSUXSEG8EI8_V_M1_M1, VSUXSEG8EI8_V }, // 8652
  { PseudoVSUXSEG8EI8_V_M1_M1_MASK, VSUXSEG8EI8_V }, // 8653
  { PseudoVSUXSEG8EI8_V_MF2_M1, VSUXSEG8EI8_V }, // 8654
  { PseudoVSUXSEG8EI8_V_MF2_M1_MASK, VSUXSEG8EI8_V }, // 8655
  { PseudoVSUXSEG8EI8_V_MF2_MF2, VSUXSEG8EI8_V }, // 8656
  { PseudoVSUXSEG8EI8_V_MF2_MF2_MASK, VSUXSEG8EI8_V }, // 8657
  { PseudoVSUXSEG8EI8_V_MF4_M1, VSUXSEG8EI8_V }, // 8658
  { PseudoVSUXSEG8EI8_V_MF4_M1_MASK, VSUXSEG8EI8_V }, // 8659
  { PseudoVSUXSEG8EI8_V_MF4_MF2, VSUXSEG8EI8_V }, // 8660
  { PseudoVSUXSEG8EI8_V_MF4_MF2_MASK, VSUXSEG8EI8_V }, // 8661
  { PseudoVSUXSEG8EI8_V_MF4_MF4, VSUXSEG8EI8_V }, // 8662
  { PseudoVSUXSEG8EI8_V_MF4_MF4_MASK, VSUXSEG8EI8_V }, // 8663
  { PseudoVSUXSEG8EI8_V_MF8_M1, VSUXSEG8EI8_V }, // 8664
  { PseudoVSUXSEG8EI8_V_MF8_M1_MASK, VSUXSEG8EI8_V }, // 8665
  { PseudoVSUXSEG8EI8_V_MF8_MF2, VSUXSEG8EI8_V }, // 8666
  { PseudoVSUXSEG8EI8_V_MF8_MF2_MASK, VSUXSEG8EI8_V }, // 8667
  { PseudoVSUXSEG8EI8_V_MF8_MF4, VSUXSEG8EI8_V }, // 8668
  { PseudoVSUXSEG8EI8_V_MF8_MF4_MASK, VSUXSEG8EI8_V }, // 8669
  { PseudoVSUXSEG8EI8_V_MF8_MF8, VSUXSEG8EI8_V }, // 8670
  { PseudoVSUXSEG8EI8_V_MF8_MF8_MASK, VSUXSEG8EI8_V }, // 8671
  { PseudoVWADDU_VV_M1, VWADDU_VV }, // 8672
  { PseudoVWADDU_VV_M1_MASK, VWADDU_VV }, // 8673
  { PseudoVWADDU_VV_M2, VWADDU_VV }, // 8674
  { PseudoVWADDU_VV_M2_MASK, VWADDU_VV }, // 8675
  { PseudoVWADDU_VV_M4, VWADDU_VV }, // 8676
  { PseudoVWADDU_VV_M4_MASK, VWADDU_VV }, // 8677
  { PseudoVWADDU_VV_MF2, VWADDU_VV }, // 8678
  { PseudoVWADDU_VV_MF2_MASK, VWADDU_VV }, // 8679
  { PseudoVWADDU_VV_MF4, VWADDU_VV }, // 8680
  { PseudoVWADDU_VV_MF4_MASK, VWADDU_VV }, // 8681
  { PseudoVWADDU_VV_MF8, VWADDU_VV }, // 8682
  { PseudoVWADDU_VV_MF8_MASK, VWADDU_VV }, // 8683
  { PseudoVWADDU_VX_M1, VWADDU_VX }, // 8684
  { PseudoVWADDU_VX_M1_MASK, VWADDU_VX }, // 8685
  { PseudoVWADDU_VX_M2, VWADDU_VX }, // 8686
  { PseudoVWADDU_VX_M2_MASK, VWADDU_VX }, // 8687
  { PseudoVWADDU_VX_M4, VWADDU_VX }, // 8688
  { PseudoVWADDU_VX_M4_MASK, VWADDU_VX }, // 8689
  { PseudoVWADDU_VX_MF2, VWADDU_VX }, // 8690
  { PseudoVWADDU_VX_MF2_MASK, VWADDU_VX }, // 8691
  { PseudoVWADDU_VX_MF4, VWADDU_VX }, // 8692
  { PseudoVWADDU_VX_MF4_MASK, VWADDU_VX }, // 8693
  { PseudoVWADDU_VX_MF8, VWADDU_VX }, // 8694
  { PseudoVWADDU_VX_MF8_MASK, VWADDU_VX }, // 8695
  { PseudoVWADDU_WV_M1, VWADDU_WV }, // 8696
  { PseudoVWADDU_WV_M1_MASK, VWADDU_WV }, // 8697
  { PseudoVWADDU_WV_M1_MASK_TIED, VWADDU_WV }, // 8698
  { PseudoVWADDU_WV_M1_TIED, VWADDU_WV }, // 8699
  { PseudoVWADDU_WV_M2, VWADDU_WV }, // 8700
  { PseudoVWADDU_WV_M2_MASK, VWADDU_WV }, // 8701
  { PseudoVWADDU_WV_M2_MASK_TIED, VWADDU_WV }, // 8702
  { PseudoVWADDU_WV_M2_TIED, VWADDU_WV }, // 8703
  { PseudoVWADDU_WV_M4, VWADDU_WV }, // 8704
  { PseudoVWADDU_WV_M4_MASK, VWADDU_WV }, // 8705
  { PseudoVWADDU_WV_M4_MASK_TIED, VWADDU_WV }, // 8706
  { PseudoVWADDU_WV_M4_TIED, VWADDU_WV }, // 8707
  { PseudoVWADDU_WV_MF2, VWADDU_WV }, // 8708
  { PseudoVWADDU_WV_MF2_MASK, VWADDU_WV }, // 8709
  { PseudoVWADDU_WV_MF2_MASK_TIED, VWADDU_WV }, // 8710
  { PseudoVWADDU_WV_MF2_TIED, VWADDU_WV }, // 8711
  { PseudoVWADDU_WV_MF4, VWADDU_WV }, // 8712
  { PseudoVWADDU_WV_MF4_MASK, VWADDU_WV }, // 8713
  { PseudoVWADDU_WV_MF4_MASK_TIED, VWADDU_WV }, // 8714
  { PseudoVWADDU_WV_MF4_TIED, VWADDU_WV }, // 8715
  { PseudoVWADDU_WV_MF8, VWADDU_WV }, // 8716
  { PseudoVWADDU_WV_MF8_MASK, VWADDU_WV }, // 8717
  { PseudoVWADDU_WV_MF8_MASK_TIED, VWADDU_WV }, // 8718
  { PseudoVWADDU_WV_MF8_TIED, VWADDU_WV }, // 8719
  { PseudoVWADDU_WX_M1, VWADDU_WX }, // 8720
  { PseudoVWADDU_WX_M1_MASK, VWADDU_WX }, // 8721
  { PseudoVWADDU_WX_M2, VWADDU_WX }, // 8722
  { PseudoVWADDU_WX_M2_MASK, VWADDU_WX }, // 8723
  { PseudoVWADDU_WX_M4, VWADDU_WX }, // 8724
  { PseudoVWADDU_WX_M4_MASK, VWADDU_WX }, // 8725
  { PseudoVWADDU_WX_MF2, VWADDU_WX }, // 8726
  { PseudoVWADDU_WX_MF2_MASK, VWADDU_WX }, // 8727
  { PseudoVWADDU_WX_MF4, VWADDU_WX }, // 8728
  { PseudoVWADDU_WX_MF4_MASK, VWADDU_WX }, // 8729
  { PseudoVWADDU_WX_MF8, VWADDU_WX }, // 8730
  { PseudoVWADDU_WX_MF8_MASK, VWADDU_WX }, // 8731
  { PseudoVWADD_VV_M1, VWADD_VV }, // 8732
  { PseudoVWADD_VV_M1_MASK, VWADD_VV }, // 8733
  { PseudoVWADD_VV_M2, VWADD_VV }, // 8734
  { PseudoVWADD_VV_M2_MASK, VWADD_VV }, // 8735
  { PseudoVWADD_VV_M4, VWADD_VV }, // 8736
  { PseudoVWADD_VV_M4_MASK, VWADD_VV }, // 8737
  { PseudoVWADD_VV_MF2, VWADD_VV }, // 8738
  { PseudoVWADD_VV_MF2_MASK, VWADD_VV }, // 8739
  { PseudoVWADD_VV_MF4, VWADD_VV }, // 8740
  { PseudoVWADD_VV_MF4_MASK, VWADD_VV }, // 8741
  { PseudoVWADD_VV_MF8, VWADD_VV }, // 8742
  { PseudoVWADD_VV_MF8_MASK, VWADD_VV }, // 8743
  { PseudoVWADD_VX_M1, VWADD_VX }, // 8744
  { PseudoVWADD_VX_M1_MASK, VWADD_VX }, // 8745
  { PseudoVWADD_VX_M2, VWADD_VX }, // 8746
  { PseudoVWADD_VX_M2_MASK, VWADD_VX }, // 8747
  { PseudoVWADD_VX_M4, VWADD_VX }, // 8748
  { PseudoVWADD_VX_M4_MASK, VWADD_VX }, // 8749
  { PseudoVWADD_VX_MF2, VWADD_VX }, // 8750
  { PseudoVWADD_VX_MF2_MASK, VWADD_VX }, // 8751
  { PseudoVWADD_VX_MF4, VWADD_VX }, // 8752
  { PseudoVWADD_VX_MF4_MASK, VWADD_VX }, // 8753
  { PseudoVWADD_VX_MF8, VWADD_VX }, // 8754
  { PseudoVWADD_VX_MF8_MASK, VWADD_VX }, // 8755
  { PseudoVWADD_WV_M1, VWADD_WV }, // 8756
  { PseudoVWADD_WV_M1_MASK, VWADD_WV }, // 8757
  { PseudoVWADD_WV_M1_MASK_TIED, VWADD_WV }, // 8758
  { PseudoVWADD_WV_M1_TIED, VWADD_WV }, // 8759
  { PseudoVWADD_WV_M2, VWADD_WV }, // 8760
  { PseudoVWADD_WV_M2_MASK, VWADD_WV }, // 8761
  { PseudoVWADD_WV_M2_MASK_TIED, VWADD_WV }, // 8762
  { PseudoVWADD_WV_M2_TIED, VWADD_WV }, // 8763
  { PseudoVWADD_WV_M4, VWADD_WV }, // 8764
  { PseudoVWADD_WV_M4_MASK, VWADD_WV }, // 8765
  { PseudoVWADD_WV_M4_MASK_TIED, VWADD_WV }, // 8766
  { PseudoVWADD_WV_M4_TIED, VWADD_WV }, // 8767
  { PseudoVWADD_WV_MF2, VWADD_WV }, // 8768
  { PseudoVWADD_WV_MF2_MASK, VWADD_WV }, // 8769
  { PseudoVWADD_WV_MF2_MASK_TIED, VWADD_WV }, // 8770
  { PseudoVWADD_WV_MF2_TIED, VWADD_WV }, // 8771
  { PseudoVWADD_WV_MF4, VWADD_WV }, // 8772
  { PseudoVWADD_WV_MF4_MASK, VWADD_WV }, // 8773
  { PseudoVWADD_WV_MF4_MASK_TIED, VWADD_WV }, // 8774
  { PseudoVWADD_WV_MF4_TIED, VWADD_WV }, // 8775
  { PseudoVWADD_WV_MF8, VWADD_WV }, // 8776
  { PseudoVWADD_WV_MF8_MASK, VWADD_WV }, // 8777
  { PseudoVWADD_WV_MF8_MASK_TIED, VWADD_WV }, // 8778
  { PseudoVWADD_WV_MF8_TIED, VWADD_WV }, // 8779
  { PseudoVWADD_WX_M1, VWADD_WX }, // 8780
  { PseudoVWADD_WX_M1_MASK, VWADD_WX }, // 8781
  { PseudoVWADD_WX_M2, VWADD_WX }, // 8782
  { PseudoVWADD_WX_M2_MASK, VWADD_WX }, // 8783
  { PseudoVWADD_WX_M4, VWADD_WX }, // 8784
  { PseudoVWADD_WX_M4_MASK, VWADD_WX }, // 8785
  { PseudoVWADD_WX_MF2, VWADD_WX }, // 8786
  { PseudoVWADD_WX_MF2_MASK, VWADD_WX }, // 8787
  { PseudoVWADD_WX_MF4, VWADD_WX }, // 8788
  { PseudoVWADD_WX_MF4_MASK, VWADD_WX }, // 8789
  { PseudoVWADD_WX_MF8, VWADD_WX }, // 8790
  { PseudoVWADD_WX_MF8_MASK, VWADD_WX }, // 8791
  { PseudoVWMACCSU_VV_M1, VWMACCSU_VV }, // 8792
  { PseudoVWMACCSU_VV_M1_MASK, VWMACCSU_VV }, // 8793
  { PseudoVWMACCSU_VV_M2, VWMACCSU_VV }, // 8794
  { PseudoVWMACCSU_VV_M2_MASK, VWMACCSU_VV }, // 8795
  { PseudoVWMACCSU_VV_M4, VWMACCSU_VV }, // 8796
  { PseudoVWMACCSU_VV_M4_MASK, VWMACCSU_VV }, // 8797
  { PseudoVWMACCSU_VV_MF2, VWMACCSU_VV }, // 8798
  { PseudoVWMACCSU_VV_MF2_MASK, VWMACCSU_VV }, // 8799
  { PseudoVWMACCSU_VV_MF4, VWMACCSU_VV }, // 8800
  { PseudoVWMACCSU_VV_MF4_MASK, VWMACCSU_VV }, // 8801
  { PseudoVWMACCSU_VV_MF8, VWMACCSU_VV }, // 8802
  { PseudoVWMACCSU_VV_MF8_MASK, VWMACCSU_VV }, // 8803
  { PseudoVWMACCSU_VX_M1, VWMACCSU_VX }, // 8804
  { PseudoVWMACCSU_VX_M1_MASK, VWMACCSU_VX }, // 8805
  { PseudoVWMACCSU_VX_M2, VWMACCSU_VX }, // 8806
  { PseudoVWMACCSU_VX_M2_MASK, VWMACCSU_VX }, // 8807
  { PseudoVWMACCSU_VX_M4, VWMACCSU_VX }, // 8808
  { PseudoVWMACCSU_VX_M4_MASK, VWMACCSU_VX }, // 8809
  { PseudoVWMACCSU_VX_MF2, VWMACCSU_VX }, // 8810
  { PseudoVWMACCSU_VX_MF2_MASK, VWMACCSU_VX }, // 8811
  { PseudoVWMACCSU_VX_MF4, VWMACCSU_VX }, // 8812
  { PseudoVWMACCSU_VX_MF4_MASK, VWMACCSU_VX }, // 8813
  { PseudoVWMACCSU_VX_MF8, VWMACCSU_VX }, // 8814
  { PseudoVWMACCSU_VX_MF8_MASK, VWMACCSU_VX }, // 8815
  { PseudoVWMACCUS_VX_M1, VWMACCUS_VX }, // 8816
  { PseudoVWMACCUS_VX_M1_MASK, VWMACCUS_VX }, // 8817
  { PseudoVWMACCUS_VX_M2, VWMACCUS_VX }, // 8818
  { PseudoVWMACCUS_VX_M2_MASK, VWMACCUS_VX }, // 8819
  { PseudoVWMACCUS_VX_M4, VWMACCUS_VX }, // 8820
  { PseudoVWMACCUS_VX_M4_MASK, VWMACCUS_VX }, // 8821
  { PseudoVWMACCUS_VX_MF2, VWMACCUS_VX }, // 8822
  { PseudoVWMACCUS_VX_MF2_MASK, VWMACCUS_VX }, // 8823
  { PseudoVWMACCUS_VX_MF4, VWMACCUS_VX }, // 8824
  { PseudoVWMACCUS_VX_MF4_MASK, VWMACCUS_VX }, // 8825
  { PseudoVWMACCUS_VX_MF8, VWMACCUS_VX }, // 8826
  { PseudoVWMACCUS_VX_MF8_MASK, VWMACCUS_VX }, // 8827
  { PseudoVWMACCU_VV_M1, VWMACCU_VV }, // 8828
  { PseudoVWMACCU_VV_M1_MASK, VWMACCU_VV }, // 8829
  { PseudoVWMACCU_VV_M2, VWMACCU_VV }, // 8830
  { PseudoVWMACCU_VV_M2_MASK, VWMACCU_VV }, // 8831
  { PseudoVWMACCU_VV_M4, VWMACCU_VV }, // 8832
  { PseudoVWMACCU_VV_M4_MASK, VWMACCU_VV }, // 8833
  { PseudoVWMACCU_VV_MF2, VWMACCU_VV }, // 8834
  { PseudoVWMACCU_VV_MF2_MASK, VWMACCU_VV }, // 8835
  { PseudoVWMACCU_VV_MF4, VWMACCU_VV }, // 8836
  { PseudoVWMACCU_VV_MF4_MASK, VWMACCU_VV }, // 8837
  { PseudoVWMACCU_VV_MF8, VWMACCU_VV }, // 8838
  { PseudoVWMACCU_VV_MF8_MASK, VWMACCU_VV }, // 8839
  { PseudoVWMACCU_VX_M1, VWMACCU_VX }, // 8840
  { PseudoVWMACCU_VX_M1_MASK, VWMACCU_VX }, // 8841
  { PseudoVWMACCU_VX_M2, VWMACCU_VX }, // 8842
  { PseudoVWMACCU_VX_M2_MASK, VWMACCU_VX }, // 8843
  { PseudoVWMACCU_VX_M4, VWMACCU_VX }, // 8844
  { PseudoVWMACCU_VX_M4_MASK, VWMACCU_VX }, // 8845
  { PseudoVWMACCU_VX_MF2, VWMACCU_VX }, // 8846
  { PseudoVWMACCU_VX_MF2_MASK, VWMACCU_VX }, // 8847
  { PseudoVWMACCU_VX_MF4, VWMACCU_VX }, // 8848
  { PseudoVWMACCU_VX_MF4_MASK, VWMACCU_VX }, // 8849
  { PseudoVWMACCU_VX_MF8, VWMACCU_VX }, // 8850
  { PseudoVWMACCU_VX_MF8_MASK, VWMACCU_VX }, // 8851
  { PseudoVWMACC_VV_M1, VWMACC_VV }, // 8852
  { PseudoVWMACC_VV_M1_MASK, VWMACC_VV }, // 8853
  { PseudoVWMACC_VV_M2, VWMACC_VV }, // 8854
  { PseudoVWMACC_VV_M2_MASK, VWMACC_VV }, // 8855
  { PseudoVWMACC_VV_M4, VWMACC_VV }, // 8856
  { PseudoVWMACC_VV_M4_MASK, VWMACC_VV }, // 8857
  { PseudoVWMACC_VV_MF2, VWMACC_VV }, // 8858
  { PseudoVWMACC_VV_MF2_MASK, VWMACC_VV }, // 8859
  { PseudoVWMACC_VV_MF4, VWMACC_VV }, // 8860
  { PseudoVWMACC_VV_MF4_MASK, VWMACC_VV }, // 8861
  { PseudoVWMACC_VV_MF8, VWMACC_VV }, // 8862
  { PseudoVWMACC_VV_MF8_MASK, VWMACC_VV }, // 8863
  { PseudoVWMACC_VX_M1, VWMACC_VX }, // 8864
  { PseudoVWMACC_VX_M1_MASK, VWMACC_VX }, // 8865
  { PseudoVWMACC_VX_M2, VWMACC_VX }, // 8866
  { PseudoVWMACC_VX_M2_MASK, VWMACC_VX }, // 8867
  { PseudoVWMACC_VX_M4, VWMACC_VX }, // 8868
  { PseudoVWMACC_VX_M4_MASK, VWMACC_VX }, // 8869
  { PseudoVWMACC_VX_MF2, VWMACC_VX }, // 8870
  { PseudoVWMACC_VX_MF2_MASK, VWMACC_VX }, // 8871
  { PseudoVWMACC_VX_MF4, VWMACC_VX }, // 8872
  { PseudoVWMACC_VX_MF4_MASK, VWMACC_VX }, // 8873
  { PseudoVWMACC_VX_MF8, VWMACC_VX }, // 8874
  { PseudoVWMACC_VX_MF8_MASK, VWMACC_VX }, // 8875
  { PseudoVWMULSU_VV_M1, VWMULSU_VV }, // 8876
  { PseudoVWMULSU_VV_M1_MASK, VWMULSU_VV }, // 8877
  { PseudoVWMULSU_VV_M2, VWMULSU_VV }, // 8878
  { PseudoVWMULSU_VV_M2_MASK, VWMULSU_VV }, // 8879
  { PseudoVWMULSU_VV_M4, VWMULSU_VV }, // 8880
  { PseudoVWMULSU_VV_M4_MASK, VWMULSU_VV }, // 8881
  { PseudoVWMULSU_VV_MF2, VWMULSU_VV }, // 8882
  { PseudoVWMULSU_VV_MF2_MASK, VWMULSU_VV }, // 8883
  { PseudoVWMULSU_VV_MF4, VWMULSU_VV }, // 8884
  { PseudoVWMULSU_VV_MF4_MASK, VWMULSU_VV }, // 8885
  { PseudoVWMULSU_VV_MF8, VWMULSU_VV }, // 8886
  { PseudoVWMULSU_VV_MF8_MASK, VWMULSU_VV }, // 8887
  { PseudoVWMULSU_VX_M1, VWMULSU_VX }, // 8888
  { PseudoVWMULSU_VX_M1_MASK, VWMULSU_VX }, // 8889
  { PseudoVWMULSU_VX_M2, VWMULSU_VX }, // 8890
  { PseudoVWMULSU_VX_M2_MASK, VWMULSU_VX }, // 8891
  { PseudoVWMULSU_VX_M4, VWMULSU_VX }, // 8892
  { PseudoVWMULSU_VX_M4_MASK, VWMULSU_VX }, // 8893
  { PseudoVWMULSU_VX_MF2, VWMULSU_VX }, // 8894
  { PseudoVWMULSU_VX_MF2_MASK, VWMULSU_VX }, // 8895
  { PseudoVWMULSU_VX_MF4, VWMULSU_VX }, // 8896
  { PseudoVWMULSU_VX_MF4_MASK, VWMULSU_VX }, // 8897
  { PseudoVWMULSU_VX_MF8, VWMULSU_VX }, // 8898
  { PseudoVWMULSU_VX_MF8_MASK, VWMULSU_VX }, // 8899
  { PseudoVWMULU_VV_M1, VWMULU_VV }, // 8900
  { PseudoVWMULU_VV_M1_MASK, VWMULU_VV }, // 8901
  { PseudoVWMULU_VV_M2, VWMULU_VV }, // 8902
  { PseudoVWMULU_VV_M2_MASK, VWMULU_VV }, // 8903
  { PseudoVWMULU_VV_M4, VWMULU_VV }, // 8904
  { PseudoVWMULU_VV_M4_MASK, VWMULU_VV }, // 8905
  { PseudoVWMULU_VV_MF2, VWMULU_VV }, // 8906
  { PseudoVWMULU_VV_MF2_MASK, VWMULU_VV }, // 8907
  { PseudoVWMULU_VV_MF4, VWMULU_VV }, // 8908
  { PseudoVWMULU_VV_MF4_MASK, VWMULU_VV }, // 8909
  { PseudoVWMULU_VV_MF8, VWMULU_VV }, // 8910
  { PseudoVWMULU_VV_MF8_MASK, VWMULU_VV }, // 8911
  { PseudoVWMULU_VX_M1, VWMULU_VX }, // 8912
  { PseudoVWMULU_VX_M1_MASK, VWMULU_VX }, // 8913
  { PseudoVWMULU_VX_M2, VWMULU_VX }, // 8914
  { PseudoVWMULU_VX_M2_MASK, VWMULU_VX }, // 8915
  { PseudoVWMULU_VX_M4, VWMULU_VX }, // 8916
  { PseudoVWMULU_VX_M4_MASK, VWMULU_VX }, // 8917
  { PseudoVWMULU_VX_MF2, VWMULU_VX }, // 8918
  { PseudoVWMULU_VX_MF2_MASK, VWMULU_VX }, // 8919
  { PseudoVWMULU_VX_MF4, VWMULU_VX }, // 8920
  { PseudoVWMULU_VX_MF4_MASK, VWMULU_VX }, // 8921
  { PseudoVWMULU_VX_MF8, VWMULU_VX }, // 8922
  { PseudoVWMULU_VX_MF8_MASK, VWMULU_VX }, // 8923
  { PseudoVWMUL_VV_M1, VWMUL_VV }, // 8924
  { PseudoVWMUL_VV_M1_MASK, VWMUL_VV }, // 8925
  { PseudoVWMUL_VV_M2, VWMUL_VV }, // 8926
  { PseudoVWMUL_VV_M2_MASK, VWMUL_VV }, // 8927
  { PseudoVWMUL_VV_M4, VWMUL_VV }, // 8928
  { PseudoVWMUL_VV_M4_MASK, VWMUL_VV }, // 8929
  { PseudoVWMUL_VV_MF2, VWMUL_VV }, // 8930
  { PseudoVWMUL_VV_MF2_MASK, VWMUL_VV }, // 8931
  { PseudoVWMUL_VV_MF4, VWMUL_VV }, // 8932
  { PseudoVWMUL_VV_MF4_MASK, VWMUL_VV }, // 8933
  { PseudoVWMUL_VV_MF8, VWMUL_VV }, // 8934
  { PseudoVWMUL_VV_MF8_MASK, VWMUL_VV }, // 8935
  { PseudoVWMUL_VX_M1, VWMUL_VX }, // 8936
  { PseudoVWMUL_VX_M1_MASK, VWMUL_VX }, // 8937
  { PseudoVWMUL_VX_M2, VWMUL_VX }, // 8938
  { PseudoVWMUL_VX_M2_MASK, VWMUL_VX }, // 8939
  { PseudoVWMUL_VX_M4, VWMUL_VX }, // 8940
  { PseudoVWMUL_VX_M4_MASK, VWMUL_VX }, // 8941
  { PseudoVWMUL_VX_MF2, VWMUL_VX }, // 8942
  { PseudoVWMUL_VX_MF2_MASK, VWMUL_VX }, // 8943
  { PseudoVWMUL_VX_MF4, VWMUL_VX }, // 8944
  { PseudoVWMUL_VX_MF4_MASK, VWMUL_VX }, // 8945
  { PseudoVWMUL_VX_MF8, VWMUL_VX }, // 8946
  { PseudoVWMUL_VX_MF8_MASK, VWMUL_VX }, // 8947
  { PseudoVWREDSUMU_VS_M1, VWREDSUMU_VS }, // 8948
  { PseudoVWREDSUMU_VS_M1_MASK, VWREDSUMU_VS }, // 8949
  { PseudoVWREDSUMU_VS_M2, VWREDSUMU_VS }, // 8950
  { PseudoVWREDSUMU_VS_M2_MASK, VWREDSUMU_VS }, // 8951
  { PseudoVWREDSUMU_VS_M4, VWREDSUMU_VS }, // 8952
  { PseudoVWREDSUMU_VS_M4_MASK, VWREDSUMU_VS }, // 8953
  { PseudoVWREDSUMU_VS_M8, VWREDSUMU_VS }, // 8954
  { PseudoVWREDSUMU_VS_M8_MASK, VWREDSUMU_VS }, // 8955
  { PseudoVWREDSUMU_VS_MF2, VWREDSUMU_VS }, // 8956
  { PseudoVWREDSUMU_VS_MF2_MASK, VWREDSUMU_VS }, // 8957
  { PseudoVWREDSUMU_VS_MF4, VWREDSUMU_VS }, // 8958
  { PseudoVWREDSUMU_VS_MF4_MASK, VWREDSUMU_VS }, // 8959
  { PseudoVWREDSUMU_VS_MF8, VWREDSUMU_VS }, // 8960
  { PseudoVWREDSUMU_VS_MF8_MASK, VWREDSUMU_VS }, // 8961
  { PseudoVWREDSUM_VS_M1, VWREDSUM_VS }, // 8962
  { PseudoVWREDSUM_VS_M1_MASK, VWREDSUM_VS }, // 8963
  { PseudoVWREDSUM_VS_M2, VWREDSUM_VS }, // 8964
  { PseudoVWREDSUM_VS_M2_MASK, VWREDSUM_VS }, // 8965
  { PseudoVWREDSUM_VS_M4, VWREDSUM_VS }, // 8966
  { PseudoVWREDSUM_VS_M4_MASK, VWREDSUM_VS }, // 8967
  { PseudoVWREDSUM_VS_M8, VWREDSUM_VS }, // 8968
  { PseudoVWREDSUM_VS_M8_MASK, VWREDSUM_VS }, // 8969
  { PseudoVWREDSUM_VS_MF2, VWREDSUM_VS }, // 8970
  { PseudoVWREDSUM_VS_MF2_MASK, VWREDSUM_VS }, // 8971
  { PseudoVWREDSUM_VS_MF4, VWREDSUM_VS }, // 8972
  { PseudoVWREDSUM_VS_MF4_MASK, VWREDSUM_VS }, // 8973
  { PseudoVWREDSUM_VS_MF8, VWREDSUM_VS }, // 8974
  { PseudoVWREDSUM_VS_MF8_MASK, VWREDSUM_VS }, // 8975
  { PseudoVWSUBU_VV_M1, VWSUBU_VV }, // 8976
  { PseudoVWSUBU_VV_M1_MASK, VWSUBU_VV }, // 8977
  { PseudoVWSUBU_VV_M2, VWSUBU_VV }, // 8978
  { PseudoVWSUBU_VV_M2_MASK, VWSUBU_VV }, // 8979
  { PseudoVWSUBU_VV_M4, VWSUBU_VV }, // 8980
  { PseudoVWSUBU_VV_M4_MASK, VWSUBU_VV }, // 8981
  { PseudoVWSUBU_VV_MF2, VWSUBU_VV }, // 8982
  { PseudoVWSUBU_VV_MF2_MASK, VWSUBU_VV }, // 8983
  { PseudoVWSUBU_VV_MF4, VWSUBU_VV }, // 8984
  { PseudoVWSUBU_VV_MF4_MASK, VWSUBU_VV }, // 8985
  { PseudoVWSUBU_VV_MF8, VWSUBU_VV }, // 8986
  { PseudoVWSUBU_VV_MF8_MASK, VWSUBU_VV }, // 8987
  { PseudoVWSUBU_VX_M1, VWSUBU_VX }, // 8988
  { PseudoVWSUBU_VX_M1_MASK, VWSUBU_VX }, // 8989
  { PseudoVWSUBU_VX_M2, VWSUBU_VX }, // 8990
  { PseudoVWSUBU_VX_M2_MASK, VWSUBU_VX }, // 8991
  { PseudoVWSUBU_VX_M4, VWSUBU_VX }, // 8992
  { PseudoVWSUBU_VX_M4_MASK, VWSUBU_VX }, // 8993
  { PseudoVWSUBU_VX_MF2, VWSUBU_VX }, // 8994
  { PseudoVWSUBU_VX_MF2_MASK, VWSUBU_VX }, // 8995
  { PseudoVWSUBU_VX_MF4, VWSUBU_VX }, // 8996
  { PseudoVWSUBU_VX_MF4_MASK, VWSUBU_VX }, // 8997
  { PseudoVWSUBU_VX_MF8, VWSUBU_VX }, // 8998
  { PseudoVWSUBU_VX_MF8_MASK, VWSUBU_VX }, // 8999
  { PseudoVWSUBU_WV_M1, VWSUBU_WV }, // 9000
  { PseudoVWSUBU_WV_M1_MASK, VWSUBU_WV }, // 9001
  { PseudoVWSUBU_WV_M1_MASK_TIED, VWSUBU_WV }, // 9002
  { PseudoVWSUBU_WV_M1_TIED, VWSUBU_WV }, // 9003
  { PseudoVWSUBU_WV_M2, VWSUBU_WV }, // 9004
  { PseudoVWSUBU_WV_M2_MASK, VWSUBU_WV }, // 9005
  { PseudoVWSUBU_WV_M2_MASK_TIED, VWSUBU_WV }, // 9006
  { PseudoVWSUBU_WV_M2_TIED, VWSUBU_WV }, // 9007
  { PseudoVWSUBU_WV_M4, VWSUBU_WV }, // 9008
  { PseudoVWSUBU_WV_M4_MASK, VWSUBU_WV }, // 9009
  { PseudoVWSUBU_WV_M4_MASK_TIED, VWSUBU_WV }, // 9010
  { PseudoVWSUBU_WV_M4_TIED, VWSUBU_WV }, // 9011
  { PseudoVWSUBU_WV_MF2, VWSUBU_WV }, // 9012
  { PseudoVWSUBU_WV_MF2_MASK, VWSUBU_WV }, // 9013
  { PseudoVWSUBU_WV_MF2_MASK_TIED, VWSUBU_WV }, // 9014
  { PseudoVWSUBU_WV_MF2_TIED, VWSUBU_WV }, // 9015
  { PseudoVWSUBU_WV_MF4, VWSUBU_WV }, // 9016
  { PseudoVWSUBU_WV_MF4_MASK, VWSUBU_WV }, // 9017
  { PseudoVWSUBU_WV_MF4_MASK_TIED, VWSUBU_WV }, // 9018
  { PseudoVWSUBU_WV_MF4_TIED, VWSUBU_WV }, // 9019
  { PseudoVWSUBU_WV_MF8, VWSUBU_WV }, // 9020
  { PseudoVWSUBU_WV_MF8_MASK, VWSUBU_WV }, // 9021
  { PseudoVWSUBU_WV_MF8_MASK_TIED, VWSUBU_WV }, // 9022
  { PseudoVWSUBU_WV_MF8_TIED, VWSUBU_WV }, // 9023
  { PseudoVWSUBU_WX_M1, VWSUBU_WX }, // 9024
  { PseudoVWSUBU_WX_M1_MASK, VWSUBU_WX }, // 9025
  { PseudoVWSUBU_WX_M2, VWSUBU_WX }, // 9026
  { PseudoVWSUBU_WX_M2_MASK, VWSUBU_WX }, // 9027
  { PseudoVWSUBU_WX_M4, VWSUBU_WX }, // 9028
  { PseudoVWSUBU_WX_M4_MASK, VWSUBU_WX }, // 9029
  { PseudoVWSUBU_WX_MF2, VWSUBU_WX }, // 9030
  { PseudoVWSUBU_WX_MF2_MASK, VWSUBU_WX }, // 9031
  { PseudoVWSUBU_WX_MF4, VWSUBU_WX }, // 9032
  { PseudoVWSUBU_WX_MF4_MASK, VWSUBU_WX }, // 9033
  { PseudoVWSUBU_WX_MF8, VWSUBU_WX }, // 9034
  { PseudoVWSUBU_WX_MF8_MASK, VWSUBU_WX }, // 9035
  { PseudoVWSUB_VV_M1, VWSUB_VV }, // 9036
  { PseudoVWSUB_VV_M1_MASK, VWSUB_VV }, // 9037
  { PseudoVWSUB_VV_M2, VWSUB_VV }, // 9038
  { PseudoVWSUB_VV_M2_MASK, VWSUB_VV }, // 9039
  { PseudoVWSUB_VV_M4, VWSUB_VV }, // 9040
  { PseudoVWSUB_VV_M4_MASK, VWSUB_VV }, // 9041
  { PseudoVWSUB_VV_MF2, VWSUB_VV }, // 9042
  { PseudoVWSUB_VV_MF2_MASK, VWSUB_VV }, // 9043
  { PseudoVWSUB_VV_MF4, VWSUB_VV }, // 9044
  { PseudoVWSUB_VV_MF4_MASK, VWSUB_VV }, // 9045
  { PseudoVWSUB_VV_MF8, VWSUB_VV }, // 9046
  { PseudoVWSUB_VV_MF8_MASK, VWSUB_VV }, // 9047
  { PseudoVWSUB_VX_M1, VWSUB_VX }, // 9048
  { PseudoVWSUB_VX_M1_MASK, VWSUB_VX }, // 9049
  { PseudoVWSUB_VX_M2, VWSUB_VX }, // 9050
  { PseudoVWSUB_VX_M2_MASK, VWSUB_VX }, // 9051
  { PseudoVWSUB_VX_M4, VWSUB_VX }, // 9052
  { PseudoVWSUB_VX_M4_MASK, VWSUB_VX }, // 9053
  { PseudoVWSUB_VX_MF2, VWSUB_VX }, // 9054
  { PseudoVWSUB_VX_MF2_MASK, VWSUB_VX }, // 9055
  { PseudoVWSUB_VX_MF4, VWSUB_VX }, // 9056
  { PseudoVWSUB_VX_MF4_MASK, VWSUB_VX }, // 9057
  { PseudoVWSUB_VX_MF8, VWSUB_VX }, // 9058
  { PseudoVWSUB_VX_MF8_MASK, VWSUB_VX }, // 9059
  { PseudoVWSUB_WV_M1, VWSUB_WV }, // 9060
  { PseudoVWSUB_WV_M1_MASK, VWSUB_WV }, // 9061
  { PseudoVWSUB_WV_M1_MASK_TIED, VWSUB_WV }, // 9062
  { PseudoVWSUB_WV_M1_TIED, VWSUB_WV }, // 9063
  { PseudoVWSUB_WV_M2, VWSUB_WV }, // 9064
  { PseudoVWSUB_WV_M2_MASK, VWSUB_WV }, // 9065
  { PseudoVWSUB_WV_M2_MASK_TIED, VWSUB_WV }, // 9066
  { PseudoVWSUB_WV_M2_TIED, VWSUB_WV }, // 9067
  { PseudoVWSUB_WV_M4, VWSUB_WV }, // 9068
  { PseudoVWSUB_WV_M4_MASK, VWSUB_WV }, // 9069
  { PseudoVWSUB_WV_M4_MASK_TIED, VWSUB_WV }, // 9070
  { PseudoVWSUB_WV_M4_TIED, VWSUB_WV }, // 9071
  { PseudoVWSUB_WV_MF2, VWSUB_WV }, // 9072
  { PseudoVWSUB_WV_MF2_MASK, VWSUB_WV }, // 9073
  { PseudoVWSUB_WV_MF2_MASK_TIED, VWSUB_WV }, // 9074
  { PseudoVWSUB_WV_MF2_TIED, VWSUB_WV }, // 9075
  { PseudoVWSUB_WV_MF4, VWSUB_WV }, // 9076
  { PseudoVWSUB_WV_MF4_MASK, VWSUB_WV }, // 9077
  { PseudoVWSUB_WV_MF4_MASK_TIED, VWSUB_WV }, // 9078
  { PseudoVWSUB_WV_MF4_TIED, VWSUB_WV }, // 9079
  { PseudoVWSUB_WV_MF8, VWSUB_WV }, // 9080
  { PseudoVWSUB_WV_MF8_MASK, VWSUB_WV }, // 9081
  { PseudoVWSUB_WV_MF8_MASK_TIED, VWSUB_WV }, // 9082
  { PseudoVWSUB_WV_MF8_TIED, VWSUB_WV }, // 9083
  { PseudoVWSUB_WX_M1, VWSUB_WX }, // 9084
  { PseudoVWSUB_WX_M1_MASK, VWSUB_WX }, // 9085
  { PseudoVWSUB_WX_M2, VWSUB_WX }, // 9086
  { PseudoVWSUB_WX_M2_MASK, VWSUB_WX }, // 9087
  { PseudoVWSUB_WX_M4, VWSUB_WX }, // 9088
  { PseudoVWSUB_WX_M4_MASK, VWSUB_WX }, // 9089
  { PseudoVWSUB_WX_MF2, VWSUB_WX }, // 9090
  { PseudoVWSUB_WX_MF2_MASK, VWSUB_WX }, // 9091
  { PseudoVWSUB_WX_MF4, VWSUB_WX }, // 9092
  { PseudoVWSUB_WX_MF4_MASK, VWSUB_WX }, // 9093
  { PseudoVWSUB_WX_MF8, VWSUB_WX }, // 9094
  { PseudoVWSUB_WX_MF8_MASK, VWSUB_WX }, // 9095
  { PseudoVXOR_VI_M1, VXOR_VI }, // 9096
  { PseudoVXOR_VI_M1_MASK, VXOR_VI }, // 9097
  { PseudoVXOR_VI_M2, VXOR_VI }, // 9098
  { PseudoVXOR_VI_M2_MASK, VXOR_VI }, // 9099
  { PseudoVXOR_VI_M4, VXOR_VI }, // 9100
  { PseudoVXOR_VI_M4_MASK, VXOR_VI }, // 9101
  { PseudoVXOR_VI_M8, VXOR_VI }, // 9102
  { PseudoVXOR_VI_M8_MASK, VXOR_VI }, // 9103
  { PseudoVXOR_VI_MF2, VXOR_VI }, // 9104
  { PseudoVXOR_VI_MF2_MASK, VXOR_VI }, // 9105
  { PseudoVXOR_VI_MF4, VXOR_VI }, // 9106
  { PseudoVXOR_VI_MF4_MASK, VXOR_VI }, // 9107
  { PseudoVXOR_VI_MF8, VXOR_VI }, // 9108
  { PseudoVXOR_VI_MF8_MASK, VXOR_VI }, // 9109
  { PseudoVXOR_VV_M1, VXOR_VV }, // 9110
  { PseudoVXOR_VV_M1_MASK, VXOR_VV }, // 9111
  { PseudoVXOR_VV_M2, VXOR_VV }, // 9112
  { PseudoVXOR_VV_M2_MASK, VXOR_VV }, // 9113
  { PseudoVXOR_VV_M4, VXOR_VV }, // 9114
  { PseudoVXOR_VV_M4_MASK, VXOR_VV }, // 9115
  { PseudoVXOR_VV_M8, VXOR_VV }, // 9116
  { PseudoVXOR_VV_M8_MASK, VXOR_VV }, // 9117
  { PseudoVXOR_VV_MF2, VXOR_VV }, // 9118
  { PseudoVXOR_VV_MF2_MASK, VXOR_VV }, // 9119
  { PseudoVXOR_VV_MF4, VXOR_VV }, // 9120
  { PseudoVXOR_VV_MF4_MASK, VXOR_VV }, // 9121
  { PseudoVXOR_VV_MF8, VXOR_VV }, // 9122
  { PseudoVXOR_VV_MF8_MASK, VXOR_VV }, // 9123
  { PseudoVXOR_VX_M1, VXOR_VX }, // 9124
  { PseudoVXOR_VX_M1_MASK, VXOR_VX }, // 9125
  { PseudoVXOR_VX_M2, VXOR_VX }, // 9126
  { PseudoVXOR_VX_M2_MASK, VXOR_VX }, // 9127
  { PseudoVXOR_VX_M4, VXOR_VX }, // 9128
  { PseudoVXOR_VX_M4_MASK, VXOR_VX }, // 9129
  { PseudoVXOR_VX_M8, VXOR_VX }, // 9130
  { PseudoVXOR_VX_M8_MASK, VXOR_VX }, // 9131
  { PseudoVXOR_VX_MF2, VXOR_VX }, // 9132
  { PseudoVXOR_VX_MF2_MASK, VXOR_VX }, // 9133
  { PseudoVXOR_VX_MF4, VXOR_VX }, // 9134
  { PseudoVXOR_VX_MF4_MASK, VXOR_VX }, // 9135
  { PseudoVXOR_VX_MF8, VXOR_VX }, // 9136
  { PseudoVXOR_VX_MF8_MASK, VXOR_VX }, // 9137
  { PseudoVZEXT_VF2_M1, VZEXT_VF2 }, // 9138
  { PseudoVZEXT_VF2_M1_MASK, VZEXT_VF2 }, // 9139
  { PseudoVZEXT_VF2_M2, VZEXT_VF2 }, // 9140
  { PseudoVZEXT_VF2_M2_MASK, VZEXT_VF2 }, // 9141
  { PseudoVZEXT_VF2_M4, VZEXT_VF2 }, // 9142
  { PseudoVZEXT_VF2_M4_MASK, VZEXT_VF2 }, // 9143
  { PseudoVZEXT_VF2_M8, VZEXT_VF2 }, // 9144
  { PseudoVZEXT_VF2_M8_MASK, VZEXT_VF2 }, // 9145
  { PseudoVZEXT_VF2_MF2, VZEXT_VF2 }, // 9146
  { PseudoVZEXT_VF2_MF2_MASK, VZEXT_VF2 }, // 9147
  { PseudoVZEXT_VF2_MF4, VZEXT_VF2 }, // 9148
  { PseudoVZEXT_VF2_MF4_MASK, VZEXT_VF2 }, // 9149
  { PseudoVZEXT_VF4_M1, VZEXT_VF4 }, // 9150
  { PseudoVZEXT_VF4_M1_MASK, VZEXT_VF4 }, // 9151
  { PseudoVZEXT_VF4_M2, VZEXT_VF4 }, // 9152
  { PseudoVZEXT_VF4_M2_MASK, VZEXT_VF4 }, // 9153
  { PseudoVZEXT_VF4_M4, VZEXT_VF4 }, // 9154
  { PseudoVZEXT_VF4_M4_MASK, VZEXT_VF4 }, // 9155
  { PseudoVZEXT_VF4_M8, VZEXT_VF4 }, // 9156
  { PseudoVZEXT_VF4_M8_MASK, VZEXT_VF4 }, // 9157
  { PseudoVZEXT_VF4_MF2, VZEXT_VF4 }, // 9158
  { PseudoVZEXT_VF4_MF2_MASK, VZEXT_VF4 }, // 9159
  { PseudoVZEXT_VF8_M1, VZEXT_VF8 }, // 9160
  { PseudoVZEXT_VF8_M1_MASK, VZEXT_VF8 }, // 9161
  { PseudoVZEXT_VF8_M2, VZEXT_VF8 }, // 9162
  { PseudoVZEXT_VF8_M2_MASK, VZEXT_VF8 }, // 9163
  { PseudoVZEXT_VF8_M4, VZEXT_VF8 }, // 9164
  { PseudoVZEXT_VF8_M4_MASK, VZEXT_VF8 }, // 9165
  { PseudoVZEXT_VF8_M8, VZEXT_VF8 }, // 9166
  { PseudoVZEXT_VF8_M8_MASK, VZEXT_VF8 }, // 9167
 };

const PseudoInfo *getPseudoInfo(unsigned Pseudo) {
  if ((Pseudo < PseudoVAADDU_VV_M1) ||
      (Pseudo > PseudoVZEXT_VF8_M8_MASK))
    return nullptr;

  struct KeyType {
    unsigned Pseudo;
  };
  KeyType Key = {Pseudo};
  auto Table = makeArrayRef(RISCVVPseudosTable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const PseudoInfo &LHS, const KeyType &RHS) {
      if (LHS.Pseudo < RHS.Pseudo)
        return true;
      if (LHS.Pseudo > RHS.Pseudo)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.Pseudo != Idx->Pseudo)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_RISCVVSETable_DECL
const VSEPseudo *getVSEPseudo(uint8_t Masked, uint8_t Strided, uint8_t Log2SEW, uint8_t LMUL);
#endif

#ifdef GET_RISCVVSETable_IMPL
constexpr VSEPseudo RISCVVSETable[] = {
  { 0x0, 0x0, 0x0, 0x0, PseudoVSM_V_B8 }, // 0
  { 0x0, 0x0, 0x0, 0x1, PseudoVSM_V_B16 }, // 1
  { 0x0, 0x0, 0x0, 0x2, PseudoVSM_V_B32 }, // 2
  { 0x0, 0x0, 0x0, 0x3, PseudoVSM_V_B64 }, // 3
  { 0x0, 0x0, 0x0, 0x5, PseudoVSM_V_B1 }, // 4
  { 0x0, 0x0, 0x0, 0x6, PseudoVSM_V_B2 }, // 5
  { 0x0, 0x0, 0x0, 0x7, PseudoVSM_V_B4 }, // 6
  { 0x0, 0x0, 0x3, 0x0, PseudoVSE8_V_M1 }, // 7
  { 0x0, 0x0, 0x3, 0x1, PseudoVSE8_V_M2 }, // 8
  { 0x0, 0x0, 0x3, 0x2, PseudoVSE8_V_M4 }, // 9
  { 0x0, 0x0, 0x3, 0x3, PseudoVSE8_V_M8 }, // 10
  { 0x0, 0x0, 0x3, 0x5, PseudoVSE8_V_MF8 }, // 11
  { 0x0, 0x0, 0x3, 0x6, PseudoVSE8_V_MF4 }, // 12
  { 0x0, 0x0, 0x3, 0x7, PseudoVSE8_V_MF2 }, // 13
  { 0x0, 0x0, 0x4, 0x0, PseudoVSE16_V_M1 }, // 14
  { 0x0, 0x0, 0x4, 0x1, PseudoVSE16_V_M2 }, // 15
  { 0x0, 0x0, 0x4, 0x2, PseudoVSE16_V_M4 }, // 16
  { 0x0, 0x0, 0x4, 0x3, PseudoVSE16_V_M8 }, // 17
  { 0x0, 0x0, 0x4, 0x6, PseudoVSE16_V_MF4 }, // 18
  { 0x0, 0x0, 0x4, 0x7, PseudoVSE16_V_MF2 }, // 19
  { 0x0, 0x0, 0x5, 0x0, PseudoVSE32_V_M1 }, // 20
  { 0x0, 0x0, 0x5, 0x1, PseudoVSE32_V_M2 }, // 21
  { 0x0, 0x0, 0x5, 0x2, PseudoVSE32_V_M4 }, // 22
  { 0x0, 0x0, 0x5, 0x3, PseudoVSE32_V_M8 }, // 23
  { 0x0, 0x0, 0x5, 0x7, PseudoVSE32_V_MF2 }, // 24
  { 0x0, 0x0, 0x6, 0x0, PseudoVSE64_V_M1 }, // 25
  { 0x0, 0x0, 0x6, 0x1, PseudoVSE64_V_M2 }, // 26
  { 0x0, 0x0, 0x6, 0x2, PseudoVSE64_V_M4 }, // 27
  { 0x0, 0x0, 0x6, 0x3, PseudoVSE64_V_M8 }, // 28
  { 0x0, 0x1, 0x3, 0x0, PseudoVSSE8_V_M1 }, // 29
  { 0x0, 0x1, 0x3, 0x1, PseudoVSSE8_V_M2 }, // 30
  { 0x0, 0x1, 0x3, 0x2, PseudoVSSE8_V_M4 }, // 31
  { 0x0, 0x1, 0x3, 0x3, PseudoVSSE8_V_M8 }, // 32
  { 0x0, 0x1, 0x3, 0x5, PseudoVSSE8_V_MF8 }, // 33
  { 0x0, 0x1, 0x3, 0x6, PseudoVSSE8_V_MF4 }, // 34
  { 0x0, 0x1, 0x3, 0x7, PseudoVSSE8_V_MF2 }, // 35
  { 0x0, 0x1, 0x4, 0x0, PseudoVSSE16_V_M1 }, // 36
  { 0x0, 0x1, 0x4, 0x1, PseudoVSSE16_V_M2 }, // 37
  { 0x0, 0x1, 0x4, 0x2, PseudoVSSE16_V_M4 }, // 38
  { 0x0, 0x1, 0x4, 0x3, PseudoVSSE16_V_M8 }, // 39
  { 0x0, 0x1, 0x4, 0x6, PseudoVSSE16_V_MF4 }, // 40
  { 0x0, 0x1, 0x4, 0x7, PseudoVSSE16_V_MF2 }, // 41
  { 0x0, 0x1, 0x5, 0x0, PseudoVSSE32_V_M1 }, // 42
  { 0x0, 0x1, 0x5, 0x1, PseudoVSSE32_V_M2 }, // 43
  { 0x0, 0x1, 0x5, 0x2, PseudoVSSE32_V_M4 }, // 44
  { 0x0, 0x1, 0x5, 0x3, PseudoVSSE32_V_M8 }, // 45
  { 0x0, 0x1, 0x5, 0x7, PseudoVSSE32_V_MF2 }, // 46
  { 0x0, 0x1, 0x6, 0x0, PseudoVSSE64_V_M1 }, // 47
  { 0x0, 0x1, 0x6, 0x1, PseudoVSSE64_V_M2 }, // 48
  { 0x0, 0x1, 0x6, 0x2, PseudoVSSE64_V_M4 }, // 49
  { 0x0, 0x1, 0x6, 0x3, PseudoVSSE64_V_M8 }, // 50
  { 0x1, 0x0, 0x3, 0x0, PseudoVSE8_V_M1_MASK }, // 51
  { 0x1, 0x0, 0x3, 0x1, PseudoVSE8_V_M2_MASK }, // 52
  { 0x1, 0x0, 0x3, 0x2, PseudoVSE8_V_M4_MASK }, // 53
  { 0x1, 0x0, 0x3, 0x3, PseudoVSE8_V_M8_MASK }, // 54
  { 0x1, 0x0, 0x3, 0x5, PseudoVSE8_V_MF8_MASK }, // 55
  { 0x1, 0x0, 0x3, 0x6, PseudoVSE8_V_MF4_MASK }, // 56
  { 0x1, 0x0, 0x3, 0x7, PseudoVSE8_V_MF2_MASK }, // 57
  { 0x1, 0x0, 0x4, 0x0, PseudoVSE16_V_M1_MASK }, // 58
  { 0x1, 0x0, 0x4, 0x1, PseudoVSE16_V_M2_MASK }, // 59
  { 0x1, 0x0, 0x4, 0x2, PseudoVSE16_V_M4_MASK }, // 60
  { 0x1, 0x0, 0x4, 0x3, PseudoVSE16_V_M8_MASK }, // 61
  { 0x1, 0x0, 0x4, 0x6, PseudoVSE16_V_MF4_MASK }, // 62
  { 0x1, 0x0, 0x4, 0x7, PseudoVSE16_V_MF2_MASK }, // 63
  { 0x1, 0x0, 0x5, 0x0, PseudoVSE32_V_M1_MASK }, // 64
  { 0x1, 0x0, 0x5, 0x1, PseudoVSE32_V_M2_MASK }, // 65
  { 0x1, 0x0, 0x5, 0x2, PseudoVSE32_V_M4_MASK }, // 66
  { 0x1, 0x0, 0x5, 0x3, PseudoVSE32_V_M8_MASK }, // 67
  { 0x1, 0x0, 0x5, 0x7, PseudoVSE32_V_MF2_MASK }, // 68
  { 0x1, 0x0, 0x6, 0x0, PseudoVSE64_V_M1_MASK }, // 69
  { 0x1, 0x0, 0x6, 0x1, PseudoVSE64_V_M2_MASK }, // 70
  { 0x1, 0x0, 0x6, 0x2, PseudoVSE64_V_M4_MASK }, // 71
  { 0x1, 0x0, 0x6, 0x3, PseudoVSE64_V_M8_MASK }, // 72
  { 0x1, 0x1, 0x3, 0x0, PseudoVSSE8_V_M1_MASK }, // 73
  { 0x1, 0x1, 0x3, 0x1, PseudoVSSE8_V_M2_MASK }, // 74
  { 0x1, 0x1, 0x3, 0x2, PseudoVSSE8_V_M4_MASK }, // 75
  { 0x1, 0x1, 0x3, 0x3, PseudoVSSE8_V_M8_MASK }, // 76
  { 0x1, 0x1, 0x3, 0x5, PseudoVSSE8_V_MF8_MASK }, // 77
  { 0x1, 0x1, 0x3, 0x6, PseudoVSSE8_V_MF4_MASK }, // 78
  { 0x1, 0x1, 0x3, 0x7, PseudoVSSE8_V_MF2_MASK }, // 79
  { 0x1, 0x1, 0x4, 0x0, PseudoVSSE16_V_M1_MASK }, // 80
  { 0x1, 0x1, 0x4, 0x1, PseudoVSSE16_V_M2_MASK }, // 81
  { 0x1, 0x1, 0x4, 0x2, PseudoVSSE16_V_M4_MASK }, // 82
  { 0x1, 0x1, 0x4, 0x3, PseudoVSSE16_V_M8_MASK }, // 83
  { 0x1, 0x1, 0x4, 0x6, PseudoVSSE16_V_MF4_MASK }, // 84
  { 0x1, 0x1, 0x4, 0x7, PseudoVSSE16_V_MF2_MASK }, // 85
  { 0x1, 0x1, 0x5, 0x0, PseudoVSSE32_V_M1_MASK }, // 86
  { 0x1, 0x1, 0x5, 0x1, PseudoVSSE32_V_M2_MASK }, // 87
  { 0x1, 0x1, 0x5, 0x2, PseudoVSSE32_V_M4_MASK }, // 88
  { 0x1, 0x1, 0x5, 0x3, PseudoVSSE32_V_M8_MASK }, // 89
  { 0x1, 0x1, 0x5, 0x7, PseudoVSSE32_V_MF2_MASK }, // 90
  { 0x1, 0x1, 0x6, 0x0, PseudoVSSE64_V_M1_MASK }, // 91
  { 0x1, 0x1, 0x6, 0x1, PseudoVSSE64_V_M2_MASK }, // 92
  { 0x1, 0x1, 0x6, 0x2, PseudoVSSE64_V_M4_MASK }, // 93
  { 0x1, 0x1, 0x6, 0x3, PseudoVSSE64_V_M8_MASK }, // 94
 };

const VSEPseudo *getVSEPseudo(uint8_t Masked, uint8_t Strided, uint8_t Log2SEW, uint8_t LMUL) {
  struct KeyType {
    uint8_t Masked;
    uint8_t Strided;
    uint8_t Log2SEW;
    uint8_t LMUL;
  };
  KeyType Key = {Masked, Strided, Log2SEW, LMUL};
  auto Table = makeArrayRef(RISCVVSETable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const VSEPseudo &LHS, const KeyType &RHS) {
      if (LHS.Masked < RHS.Masked)
        return true;
      if (LHS.Masked > RHS.Masked)
        return false;
      if (LHS.Strided < RHS.Strided)
        return true;
      if (LHS.Strided > RHS.Strided)
        return false;
      if (LHS.Log2SEW < RHS.Log2SEW)
        return true;
      if (LHS.Log2SEW > RHS.Log2SEW)
        return false;
      if (LHS.LMUL < RHS.LMUL)
        return true;
      if (LHS.LMUL > RHS.LMUL)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.Masked != Idx->Masked ||
      Key.Strided != Idx->Strided ||
      Key.Log2SEW != Idx->Log2SEW ||
      Key.LMUL != Idx->LMUL)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_RISCVVSSEGTable_DECL
const VSSEGPseudo *getVSSEGPseudo(uint8_t NF, uint8_t Masked, uint8_t Strided, uint8_t Log2SEW, uint8_t LMUL);
#endif

#ifdef GET_RISCVVSSEGTable_IMPL
constexpr VSSEGPseudo RISCVVSSEGTable[] = {
  { 0x2, 0x0, 0x0, 0x3, 0x0, PseudoVSSEG2E8_V_M1 }, // 0
  { 0x2, 0x0, 0x0, 0x3, 0x1, PseudoVSSEG2E8_V_M2 }, // 1
  { 0x2, 0x0, 0x0, 0x3, 0x2, PseudoVSSEG2E8_V_M4 }, // 2
  { 0x2, 0x0, 0x0, 0x3, 0x5, PseudoVSSEG2E8_V_MF8 }, // 3
  { 0x2, 0x0, 0x0, 0x3, 0x6, PseudoVSSEG2E8_V_MF4 }, // 4
  { 0x2, 0x0, 0x0, 0x3, 0x7, PseudoVSSEG2E8_V_MF2 }, // 5
  { 0x2, 0x0, 0x0, 0x4, 0x0, PseudoVSSEG2E16_V_M1 }, // 6
  { 0x2, 0x0, 0x0, 0x4, 0x1, PseudoVSSEG2E16_V_M2 }, // 7
  { 0x2, 0x0, 0x0, 0x4, 0x2, PseudoVSSEG2E16_V_M4 }, // 8
  { 0x2, 0x0, 0x0, 0x4, 0x6, PseudoVSSEG2E16_V_MF4 }, // 9
  { 0x2, 0x0, 0x0, 0x4, 0x7, PseudoVSSEG2E16_V_MF2 }, // 10
  { 0x2, 0x0, 0x0, 0x5, 0x0, PseudoVSSEG2E32_V_M1 }, // 11
  { 0x2, 0x0, 0x0, 0x5, 0x1, PseudoVSSEG2E32_V_M2 }, // 12
  { 0x2, 0x0, 0x0, 0x5, 0x2, PseudoVSSEG2E32_V_M4 }, // 13
  { 0x2, 0x0, 0x0, 0x5, 0x7, PseudoVSSEG2E32_V_MF2 }, // 14
  { 0x2, 0x0, 0x0, 0x6, 0x0, PseudoVSSEG2E64_V_M1 }, // 15
  { 0x2, 0x0, 0x0, 0x6, 0x1, PseudoVSSEG2E64_V_M2 }, // 16
  { 0x2, 0x0, 0x0, 0x6, 0x2, PseudoVSSEG2E64_V_M4 }, // 17
  { 0x2, 0x0, 0x1, 0x3, 0x0, PseudoVSSSEG2E8_V_M1 }, // 18
  { 0x2, 0x0, 0x1, 0x3, 0x1, PseudoVSSSEG2E8_V_M2 }, // 19
  { 0x2, 0x0, 0x1, 0x3, 0x2, PseudoVSSSEG2E8_V_M4 }, // 20
  { 0x2, 0x0, 0x1, 0x3, 0x5, PseudoVSSSEG2E8_V_MF8 }, // 21
  { 0x2, 0x0, 0x1, 0x3, 0x6, PseudoVSSSEG2E8_V_MF4 }, // 22
  { 0x2, 0x0, 0x1, 0x3, 0x7, PseudoVSSSEG2E8_V_MF2 }, // 23
  { 0x2, 0x0, 0x1, 0x4, 0x0, PseudoVSSSEG2E16_V_M1 }, // 24
  { 0x2, 0x0, 0x1, 0x4, 0x1, PseudoVSSSEG2E16_V_M2 }, // 25
  { 0x2, 0x0, 0x1, 0x4, 0x2, PseudoVSSSEG2E16_V_M4 }, // 26
  { 0x2, 0x0, 0x1, 0x4, 0x6, PseudoVSSSEG2E16_V_MF4 }, // 27
  { 0x2, 0x0, 0x1, 0x4, 0x7, PseudoVSSSEG2E16_V_MF2 }, // 28
  { 0x2, 0x0, 0x1, 0x5, 0x0, PseudoVSSSEG2E32_V_M1 }, // 29
  { 0x2, 0x0, 0x1, 0x5, 0x1, PseudoVSSSEG2E32_V_M2 }, // 30
  { 0x2, 0x0, 0x1, 0x5, 0x2, PseudoVSSSEG2E32_V_M4 }, // 31
  { 0x2, 0x0, 0x1, 0x5, 0x7, PseudoVSSSEG2E32_V_MF2 }, // 32
  { 0x2, 0x0, 0x1, 0x6, 0x0, PseudoVSSSEG2E64_V_M1 }, // 33
  { 0x2, 0x0, 0x1, 0x6, 0x1, PseudoVSSSEG2E64_V_M2 }, // 34
  { 0x2, 0x0, 0x1, 0x6, 0x2, PseudoVSSSEG2E64_V_M4 }, // 35
  { 0x2, 0x1, 0x0, 0x3, 0x0, PseudoVSSEG2E8_V_M1_MASK }, // 36
  { 0x2, 0x1, 0x0, 0x3, 0x1, PseudoVSSEG2E8_V_M2_MASK }, // 37
  { 0x2, 0x1, 0x0, 0x3, 0x2, PseudoVSSEG2E8_V_M4_MASK }, // 38
  { 0x2, 0x1, 0x0, 0x3, 0x5, PseudoVSSEG2E8_V_MF8_MASK }, // 39
  { 0x2, 0x1, 0x0, 0x3, 0x6, PseudoVSSEG2E8_V_MF4_MASK }, // 40
  { 0x2, 0x1, 0x0, 0x3, 0x7, PseudoVSSEG2E8_V_MF2_MASK }, // 41
  { 0x2, 0x1, 0x0, 0x4, 0x0, PseudoVSSEG2E16_V_M1_MASK }, // 42
  { 0x2, 0x1, 0x0, 0x4, 0x1, PseudoVSSEG2E16_V_M2_MASK }, // 43
  { 0x2, 0x1, 0x0, 0x4, 0x2, PseudoVSSEG2E16_V_M4_MASK }, // 44
  { 0x2, 0x1, 0x0, 0x4, 0x6, PseudoVSSEG2E16_V_MF4_MASK }, // 45
  { 0x2, 0x1, 0x0, 0x4, 0x7, PseudoVSSEG2E16_V_MF2_MASK }, // 46
  { 0x2, 0x1, 0x0, 0x5, 0x0, PseudoVSSEG2E32_V_M1_MASK }, // 47
  { 0x2, 0x1, 0x0, 0x5, 0x1, PseudoVSSEG2E32_V_M2_MASK }, // 48
  { 0x2, 0x1, 0x0, 0x5, 0x2, PseudoVSSEG2E32_V_M4_MASK }, // 49
  { 0x2, 0x1, 0x0, 0x5, 0x7, PseudoVSSEG2E32_V_MF2_MASK }, // 50
  { 0x2, 0x1, 0x0, 0x6, 0x0, PseudoVSSEG2E64_V_M1_MASK }, // 51
  { 0x2, 0x1, 0x0, 0x6, 0x1, PseudoVSSEG2E64_V_M2_MASK }, // 52
  { 0x2, 0x1, 0x0, 0x6, 0x2, PseudoVSSEG2E64_V_M4_MASK }, // 53
  { 0x2, 0x1, 0x1, 0x3, 0x0, PseudoVSSSEG2E8_V_M1_MASK }, // 54
  { 0x2, 0x1, 0x1, 0x3, 0x1, PseudoVSSSEG2E8_V_M2_MASK }, // 55
  { 0x2, 0x1, 0x1, 0x3, 0x2, PseudoVSSSEG2E8_V_M4_MASK }, // 56
  { 0x2, 0x1, 0x1, 0x3, 0x5, PseudoVSSSEG2E8_V_MF8_MASK }, // 57
  { 0x2, 0x1, 0x1, 0x3, 0x6, PseudoVSSSEG2E8_V_MF4_MASK }, // 58
  { 0x2, 0x1, 0x1, 0x3, 0x7, PseudoVSSSEG2E8_V_MF2_MASK }, // 59
  { 0x2, 0x1, 0x1, 0x4, 0x0, PseudoVSSSEG2E16_V_M1_MASK }, // 60
  { 0x2, 0x1, 0x1, 0x4, 0x1, PseudoVSSSEG2E16_V_M2_MASK }, // 61
  { 0x2, 0x1, 0x1, 0x4, 0x2, PseudoVSSSEG2E16_V_M4_MASK }, // 62
  { 0x2, 0x1, 0x1, 0x4, 0x6, PseudoVSSSEG2E16_V_MF4_MASK }, // 63
  { 0x2, 0x1, 0x1, 0x4, 0x7, PseudoVSSSEG2E16_V_MF2_MASK }, // 64
  { 0x2, 0x1, 0x1, 0x5, 0x0, PseudoVSSSEG2E32_V_M1_MASK }, // 65
  { 0x2, 0x1, 0x1, 0x5, 0x1, PseudoVSSSEG2E32_V_M2_MASK }, // 66
  { 0x2, 0x1, 0x1, 0x5, 0x2, PseudoVSSSEG2E32_V_M4_MASK }, // 67
  { 0x2, 0x1, 0x1, 0x5, 0x7, PseudoVSSSEG2E32_V_MF2_MASK }, // 68
  { 0x2, 0x1, 0x1, 0x6, 0x0, PseudoVSSSEG2E64_V_M1_MASK }, // 69
  { 0x2, 0x1, 0x1, 0x6, 0x1, PseudoVSSSEG2E64_V_M2_MASK }, // 70
  { 0x2, 0x1, 0x1, 0x6, 0x2, PseudoVSSSEG2E64_V_M4_MASK }, // 71
  { 0x3, 0x0, 0x0, 0x3, 0x0, PseudoVSSEG3E8_V_M1 }, // 72
  { 0x3, 0x0, 0x0, 0x3, 0x1, PseudoVSSEG3E8_V_M2 }, // 73
  { 0x3, 0x0, 0x0, 0x3, 0x5, PseudoVSSEG3E8_V_MF8 }, // 74
  { 0x3, 0x0, 0x0, 0x3, 0x6, PseudoVSSEG3E8_V_MF4 }, // 75
  { 0x3, 0x0, 0x0, 0x3, 0x7, PseudoVSSEG3E8_V_MF2 }, // 76
  { 0x3, 0x0, 0x0, 0x4, 0x0, PseudoVSSEG3E16_V_M1 }, // 77
  { 0x3, 0x0, 0x0, 0x4, 0x1, PseudoVSSEG3E16_V_M2 }, // 78
  { 0x3, 0x0, 0x0, 0x4, 0x6, PseudoVSSEG3E16_V_MF4 }, // 79
  { 0x3, 0x0, 0x0, 0x4, 0x7, PseudoVSSEG3E16_V_MF2 }, // 80
  { 0x3, 0x0, 0x0, 0x5, 0x0, PseudoVSSEG3E32_V_M1 }, // 81
  { 0x3, 0x0, 0x0, 0x5, 0x1, PseudoVSSEG3E32_V_M2 }, // 82
  { 0x3, 0x0, 0x0, 0x5, 0x7, PseudoVSSEG3E32_V_MF2 }, // 83
  { 0x3, 0x0, 0x0, 0x6, 0x0, PseudoVSSEG3E64_V_M1 }, // 84
  { 0x3, 0x0, 0x0, 0x6, 0x1, PseudoVSSEG3E64_V_M2 }, // 85
  { 0x3, 0x0, 0x1, 0x3, 0x0, PseudoVSSSEG3E8_V_M1 }, // 86
  { 0x3, 0x0, 0x1, 0x3, 0x1, PseudoVSSSEG3E8_V_M2 }, // 87
  { 0x3, 0x0, 0x1, 0x3, 0x5, PseudoVSSSEG3E8_V_MF8 }, // 88
  { 0x3, 0x0, 0x1, 0x3, 0x6, PseudoVSSSEG3E8_V_MF4 }, // 89
  { 0x3, 0x0, 0x1, 0x3, 0x7, PseudoVSSSEG3E8_V_MF2 }, // 90
  { 0x3, 0x0, 0x1, 0x4, 0x0, PseudoVSSSEG3E16_V_M1 }, // 91
  { 0x3, 0x0, 0x1, 0x4, 0x1, PseudoVSSSEG3E16_V_M2 }, // 92
  { 0x3, 0x0, 0x1, 0x4, 0x6, PseudoVSSSEG3E16_V_MF4 }, // 93
  { 0x3, 0x0, 0x1, 0x4, 0x7, PseudoVSSSEG3E16_V_MF2 }, // 94
  { 0x3, 0x0, 0x1, 0x5, 0x0, PseudoVSSSEG3E32_V_M1 }, // 95
  { 0x3, 0x0, 0x1, 0x5, 0x1, PseudoVSSSEG3E32_V_M2 }, // 96
  { 0x3, 0x0, 0x1, 0x5, 0x7, PseudoVSSSEG3E32_V_MF2 }, // 97
  { 0x3, 0x0, 0x1, 0x6, 0x0, PseudoVSSSEG3E64_V_M1 }, // 98
  { 0x3, 0x0, 0x1, 0x6, 0x1, PseudoVSSSEG3E64_V_M2 }, // 99
  { 0x3, 0x1, 0x0, 0x3, 0x0, PseudoVSSEG3E8_V_M1_MASK }, // 100
  { 0x3, 0x1, 0x0, 0x3, 0x1, PseudoVSSEG3E8_V_M2_MASK }, // 101
  { 0x3, 0x1, 0x0, 0x3, 0x5, PseudoVSSEG3E8_V_MF8_MASK }, // 102
  { 0x3, 0x1, 0x0, 0x3, 0x6, PseudoVSSEG3E8_V_MF4_MASK }, // 103
  { 0x3, 0x1, 0x0, 0x3, 0x7, PseudoVSSEG3E8_V_MF2_MASK }, // 104
  { 0x3, 0x1, 0x0, 0x4, 0x0, PseudoVSSEG3E16_V_M1_MASK }, // 105
  { 0x3, 0x1, 0x0, 0x4, 0x1, PseudoVSSEG3E16_V_M2_MASK }, // 106
  { 0x3, 0x1, 0x0, 0x4, 0x6, PseudoVSSEG3E16_V_MF4_MASK }, // 107
  { 0x3, 0x1, 0x0, 0x4, 0x7, PseudoVSSEG3E16_V_MF2_MASK }, // 108
  { 0x3, 0x1, 0x0, 0x5, 0x0, PseudoVSSEG3E32_V_M1_MASK }, // 109
  { 0x3, 0x1, 0x0, 0x5, 0x1, PseudoVSSEG3E32_V_M2_MASK }, // 110
  { 0x3, 0x1, 0x0, 0x5, 0x7, PseudoVSSEG3E32_V_MF2_MASK }, // 111
  { 0x3, 0x1, 0x0, 0x6, 0x0, PseudoVSSEG3E64_V_M1_MASK }, // 112
  { 0x3, 0x1, 0x0, 0x6, 0x1, PseudoVSSEG3E64_V_M2_MASK }, // 113
  { 0x3, 0x1, 0x1, 0x3, 0x0, PseudoVSSSEG3E8_V_M1_MASK }, // 114
  { 0x3, 0x1, 0x1, 0x3, 0x1, PseudoVSSSEG3E8_V_M2_MASK }, // 115
  { 0x3, 0x1, 0x1, 0x3, 0x5, PseudoVSSSEG3E8_V_MF8_MASK }, // 116
  { 0x3, 0x1, 0x1, 0x3, 0x6, PseudoVSSSEG3E8_V_MF4_MASK }, // 117
  { 0x3, 0x1, 0x1, 0x3, 0x7, PseudoVSSSEG3E8_V_MF2_MASK }, // 118
  { 0x3, 0x1, 0x1, 0x4, 0x0, PseudoVSSSEG3E16_V_M1_MASK }, // 119
  { 0x3, 0x1, 0x1, 0x4, 0x1, PseudoVSSSEG3E16_V_M2_MASK }, // 120
  { 0x3, 0x1, 0x1, 0x4, 0x6, PseudoVSSSEG3E16_V_MF4_MASK }, // 121
  { 0x3, 0x1, 0x1, 0x4, 0x7, PseudoVSSSEG3E16_V_MF2_MASK }, // 122
  { 0x3, 0x1, 0x1, 0x5, 0x0, PseudoVSSSEG3E32_V_M1_MASK }, // 123
  { 0x3, 0x1, 0x1, 0x5, 0x1, PseudoVSSSEG3E32_V_M2_MASK }, // 124
  { 0x3, 0x1, 0x1, 0x5, 0x7, PseudoVSSSEG3E32_V_MF2_MASK }, // 125
  { 0x3, 0x1, 0x1, 0x6, 0x0, PseudoVSSSEG3E64_V_M1_MASK }, // 126
  { 0x3, 0x1, 0x1, 0x6, 0x1, PseudoVSSSEG3E64_V_M2_MASK }, // 127
  { 0x4, 0x0, 0x0, 0x3, 0x0, PseudoVSSEG4E8_V_M1 }, // 128
  { 0x4, 0x0, 0x0, 0x3, 0x1, PseudoVSSEG4E8_V_M2 }, // 129
  { 0x4, 0x0, 0x0, 0x3, 0x5, PseudoVSSEG4E8_V_MF8 }, // 130
  { 0x4, 0x0, 0x0, 0x3, 0x6, PseudoVSSEG4E8_V_MF4 }, // 131
  { 0x4, 0x0, 0x0, 0x3, 0x7, PseudoVSSEG4E8_V_MF2 }, // 132
  { 0x4, 0x0, 0x0, 0x4, 0x0, PseudoVSSEG4E16_V_M1 }, // 133
  { 0x4, 0x0, 0x0, 0x4, 0x1, PseudoVSSEG4E16_V_M2 }, // 134
  { 0x4, 0x0, 0x0, 0x4, 0x6, PseudoVSSEG4E16_V_MF4 }, // 135
  { 0x4, 0x0, 0x0, 0x4, 0x7, PseudoVSSEG4E16_V_MF2 }, // 136
  { 0x4, 0x0, 0x0, 0x5, 0x0, PseudoVSSEG4E32_V_M1 }, // 137
  { 0x4, 0x0, 0x0, 0x5, 0x1, PseudoVSSEG4E32_V_M2 }, // 138
  { 0x4, 0x0, 0x0, 0x5, 0x7, PseudoVSSEG4E32_V_MF2 }, // 139
  { 0x4, 0x0, 0x0, 0x6, 0x0, PseudoVSSEG4E64_V_M1 }, // 140
  { 0x4, 0x0, 0x0, 0x6, 0x1, PseudoVSSEG4E64_V_M2 }, // 141
  { 0x4, 0x0, 0x1, 0x3, 0x0, PseudoVSSSEG4E8_V_M1 }, // 142
  { 0x4, 0x0, 0x1, 0x3, 0x1, PseudoVSSSEG4E8_V_M2 }, // 143
  { 0x4, 0x0, 0x1, 0x3, 0x5, PseudoVSSSEG4E8_V_MF8 }, // 144
  { 0x4, 0x0, 0x1, 0x3, 0x6, PseudoVSSSEG4E8_V_MF4 }, // 145
  { 0x4, 0x0, 0x1, 0x3, 0x7, PseudoVSSSEG4E8_V_MF2 }, // 146
  { 0x4, 0x0, 0x1, 0x4, 0x0, PseudoVSSSEG4E16_V_M1 }, // 147
  { 0x4, 0x0, 0x1, 0x4, 0x1, PseudoVSSSEG4E16_V_M2 }, // 148
  { 0x4, 0x0, 0x1, 0x4, 0x6, PseudoVSSSEG4E16_V_MF4 }, // 149
  { 0x4, 0x0, 0x1, 0x4, 0x7, PseudoVSSSEG4E16_V_MF2 }, // 150
  { 0x4, 0x0, 0x1, 0x5, 0x0, PseudoVSSSEG4E32_V_M1 }, // 151
  { 0x4, 0x0, 0x1, 0x5, 0x1, PseudoVSSSEG4E32_V_M2 }, // 152
  { 0x4, 0x0, 0x1, 0x5, 0x7, PseudoVSSSEG4E32_V_MF2 }, // 153
  { 0x4, 0x0, 0x1, 0x6, 0x0, PseudoVSSSEG4E64_V_M1 }, // 154
  { 0x4, 0x0, 0x1, 0x6, 0x1, PseudoVSSSEG4E64_V_M2 }, // 155
  { 0x4, 0x1, 0x0, 0x3, 0x0, PseudoVSSEG4E8_V_M1_MASK }, // 156
  { 0x4, 0x1, 0x0, 0x3, 0x1, PseudoVSSEG4E8_V_M2_MASK }, // 157
  { 0x4, 0x1, 0x0, 0x3, 0x5, PseudoVSSEG4E8_V_MF8_MASK }, // 158
  { 0x4, 0x1, 0x0, 0x3, 0x6, PseudoVSSEG4E8_V_MF4_MASK }, // 159
  { 0x4, 0x1, 0x0, 0x3, 0x7, PseudoVSSEG4E8_V_MF2_MASK }, // 160
  { 0x4, 0x1, 0x0, 0x4, 0x0, PseudoVSSEG4E16_V_M1_MASK }, // 161
  { 0x4, 0x1, 0x0, 0x4, 0x1, PseudoVSSEG4E16_V_M2_MASK }, // 162
  { 0x4, 0x1, 0x0, 0x4, 0x6, PseudoVSSEG4E16_V_MF4_MASK }, // 163
  { 0x4, 0x1, 0x0, 0x4, 0x7, PseudoVSSEG4E16_V_MF2_MASK }, // 164
  { 0x4, 0x1, 0x0, 0x5, 0x0, PseudoVSSEG4E32_V_M1_MASK }, // 165
  { 0x4, 0x1, 0x0, 0x5, 0x1, PseudoVSSEG4E32_V_M2_MASK }, // 166
  { 0x4, 0x1, 0x0, 0x5, 0x7, PseudoVSSEG4E32_V_MF2_MASK }, // 167
  { 0x4, 0x1, 0x0, 0x6, 0x0, PseudoVSSEG4E64_V_M1_MASK }, // 168
  { 0x4, 0x1, 0x0, 0x6, 0x1, PseudoVSSEG4E64_V_M2_MASK }, // 169
  { 0x4, 0x1, 0x1, 0x3, 0x0, PseudoVSSSEG4E8_V_M1_MASK }, // 170
  { 0x4, 0x1, 0x1, 0x3, 0x1, PseudoVSSSEG4E8_V_M2_MASK }, // 171
  { 0x4, 0x1, 0x1, 0x3, 0x5, PseudoVSSSEG4E8_V_MF8_MASK }, // 172
  { 0x4, 0x1, 0x1, 0x3, 0x6, PseudoVSSSEG4E8_V_MF4_MASK }, // 173
  { 0x4, 0x1, 0x1, 0x3, 0x7, PseudoVSSSEG4E8_V_MF2_MASK }, // 174
  { 0x4, 0x1, 0x1, 0x4, 0x0, PseudoVSSSEG4E16_V_M1_MASK }, // 175
  { 0x4, 0x1, 0x1, 0x4, 0x1, PseudoVSSSEG4E16_V_M2_MASK }, // 176
  { 0x4, 0x1, 0x1, 0x4, 0x6, PseudoVSSSEG4E16_V_MF4_MASK }, // 177
  { 0x4, 0x1, 0x1, 0x4, 0x7, PseudoVSSSEG4E16_V_MF2_MASK }, // 178
  { 0x4, 0x1, 0x1, 0x5, 0x0, PseudoVSSSEG4E32_V_M1_MASK }, // 179
  { 0x4, 0x1, 0x1, 0x5, 0x1, PseudoVSSSEG4E32_V_M2_MASK }, // 180
  { 0x4, 0x1, 0x1, 0x5, 0x7, PseudoVSSSEG4E32_V_MF2_MASK }, // 181
  { 0x4, 0x1, 0x1, 0x6, 0x0, PseudoVSSSEG4E64_V_M1_MASK }, // 182
  { 0x4, 0x1, 0x1, 0x6, 0x1, PseudoVSSSEG4E64_V_M2_MASK }, // 183
  { 0x5, 0x0, 0x0, 0x3, 0x0, PseudoVSSEG5E8_V_M1 }, // 184
  { 0x5, 0x0, 0x0, 0x3, 0x5, PseudoVSSEG5E8_V_MF8 }, // 185
  { 0x5, 0x0, 0x0, 0x3, 0x6, PseudoVSSEG5E8_V_MF4 }, // 186
  { 0x5, 0x0, 0x0, 0x3, 0x7, PseudoVSSEG5E8_V_MF2 }, // 187
  { 0x5, 0x0, 0x0, 0x4, 0x0, PseudoVSSEG5E16_V_M1 }, // 188
  { 0x5, 0x0, 0x0, 0x4, 0x6, PseudoVSSEG5E16_V_MF4 }, // 189
  { 0x5, 0x0, 0x0, 0x4, 0x7, PseudoVSSEG5E16_V_MF2 }, // 190
  { 0x5, 0x0, 0x0, 0x5, 0x0, PseudoVSSEG5E32_V_M1 }, // 191
  { 0x5, 0x0, 0x0, 0x5, 0x7, PseudoVSSEG5E32_V_MF2 }, // 192
  { 0x5, 0x0, 0x0, 0x6, 0x0, PseudoVSSEG5E64_V_M1 }, // 193
  { 0x5, 0x0, 0x1, 0x3, 0x0, PseudoVSSSEG5E8_V_M1 }, // 194
  { 0x5, 0x0, 0x1, 0x3, 0x5, PseudoVSSSEG5E8_V_MF8 }, // 195
  { 0x5, 0x0, 0x1, 0x3, 0x6, PseudoVSSSEG5E8_V_MF4 }, // 196
  { 0x5, 0x0, 0x1, 0x3, 0x7, PseudoVSSSEG5E8_V_MF2 }, // 197
  { 0x5, 0x0, 0x1, 0x4, 0x0, PseudoVSSSEG5E16_V_M1 }, // 198
  { 0x5, 0x0, 0x1, 0x4, 0x6, PseudoVSSSEG5E16_V_MF4 }, // 199
  { 0x5, 0x0, 0x1, 0x4, 0x7, PseudoVSSSEG5E16_V_MF2 }, // 200
  { 0x5, 0x0, 0x1, 0x5, 0x0, PseudoVSSSEG5E32_V_M1 }, // 201
  { 0x5, 0x0, 0x1, 0x5, 0x7, PseudoVSSSEG5E32_V_MF2 }, // 202
  { 0x5, 0x0, 0x1, 0x6, 0x0, PseudoVSSSEG5E64_V_M1 }, // 203
  { 0x5, 0x1, 0x0, 0x3, 0x0, PseudoVSSEG5E8_V_M1_MASK }, // 204
  { 0x5, 0x1, 0x0, 0x3, 0x5, PseudoVSSEG5E8_V_MF8_MASK }, // 205
  { 0x5, 0x1, 0x0, 0x3, 0x6, PseudoVSSEG5E8_V_MF4_MASK }, // 206
  { 0x5, 0x1, 0x0, 0x3, 0x7, PseudoVSSEG5E8_V_MF2_MASK }, // 207
  { 0x5, 0x1, 0x0, 0x4, 0x0, PseudoVSSEG5E16_V_M1_MASK }, // 208
  { 0x5, 0x1, 0x0, 0x4, 0x6, PseudoVSSEG5E16_V_MF4_MASK }, // 209
  { 0x5, 0x1, 0x0, 0x4, 0x7, PseudoVSSEG5E16_V_MF2_MASK }, // 210
  { 0x5, 0x1, 0x0, 0x5, 0x0, PseudoVSSEG5E32_V_M1_MASK }, // 211
  { 0x5, 0x1, 0x0, 0x5, 0x7, PseudoVSSEG5E32_V_MF2_MASK }, // 212
  { 0x5, 0x1, 0x0, 0x6, 0x0, PseudoVSSEG5E64_V_M1_MASK }, // 213
  { 0x5, 0x1, 0x1, 0x3, 0x0, PseudoVSSSEG5E8_V_M1_MASK }, // 214
  { 0x5, 0x1, 0x1, 0x3, 0x5, PseudoVSSSEG5E8_V_MF8_MASK }, // 215
  { 0x5, 0x1, 0x1, 0x3, 0x6, PseudoVSSSEG5E8_V_MF4_MASK }, // 216
  { 0x5, 0x1, 0x1, 0x3, 0x7, PseudoVSSSEG5E8_V_MF2_MASK }, // 217
  { 0x5, 0x1, 0x1, 0x4, 0x0, PseudoVSSSEG5E16_V_M1_MASK }, // 218
  { 0x5, 0x1, 0x1, 0x4, 0x6, PseudoVSSSEG5E16_V_MF4_MASK }, // 219
  { 0x5, 0x1, 0x1, 0x4, 0x7, PseudoVSSSEG5E16_V_MF2_MASK }, // 220
  { 0x5, 0x1, 0x1, 0x5, 0x0, PseudoVSSSEG5E32_V_M1_MASK }, // 221
  { 0x5, 0x1, 0x1, 0x5, 0x7, PseudoVSSSEG5E32_V_MF2_MASK }, // 222
  { 0x5, 0x1, 0x1, 0x6, 0x0, PseudoVSSSEG5E64_V_M1_MASK }, // 223
  { 0x6, 0x0, 0x0, 0x3, 0x0, PseudoVSSEG6E8_V_M1 }, // 224
  { 0x6, 0x0, 0x0, 0x3, 0x5, PseudoVSSEG6E8_V_MF8 }, // 225
  { 0x6, 0x0, 0x0, 0x3, 0x6, PseudoVSSEG6E8_V_MF4 }, // 226
  { 0x6, 0x0, 0x0, 0x3, 0x7, PseudoVSSEG6E8_V_MF2 }, // 227
  { 0x6, 0x0, 0x0, 0x4, 0x0, PseudoVSSEG6E16_V_M1 }, // 228
  { 0x6, 0x0, 0x0, 0x4, 0x6, PseudoVSSEG6E16_V_MF4 }, // 229
  { 0x6, 0x0, 0x0, 0x4, 0x7, PseudoVSSEG6E16_V_MF2 }, // 230
  { 0x6, 0x0, 0x0, 0x5, 0x0, PseudoVSSEG6E32_V_M1 }, // 231
  { 0x6, 0x0, 0x0, 0x5, 0x7, PseudoVSSEG6E32_V_MF2 }, // 232
  { 0x6, 0x0, 0x0, 0x6, 0x0, PseudoVSSEG6E64_V_M1 }, // 233
  { 0x6, 0x0, 0x1, 0x3, 0x0, PseudoVSSSEG6E8_V_M1 }, // 234
  { 0x6, 0x0, 0x1, 0x3, 0x5, PseudoVSSSEG6E8_V_MF8 }, // 235
  { 0x6, 0x0, 0x1, 0x3, 0x6, PseudoVSSSEG6E8_V_MF4 }, // 236
  { 0x6, 0x0, 0x1, 0x3, 0x7, PseudoVSSSEG6E8_V_MF2 }, // 237
  { 0x6, 0x0, 0x1, 0x4, 0x0, PseudoVSSSEG6E16_V_M1 }, // 238
  { 0x6, 0x0, 0x1, 0x4, 0x6, PseudoVSSSEG6E16_V_MF4 }, // 239
  { 0x6, 0x0, 0x1, 0x4, 0x7, PseudoVSSSEG6E16_V_MF2 }, // 240
  { 0x6, 0x0, 0x1, 0x5, 0x0, PseudoVSSSEG6E32_V_M1 }, // 241
  { 0x6, 0x0, 0x1, 0x5, 0x7, PseudoVSSSEG6E32_V_MF2 }, // 242
  { 0x6, 0x0, 0x1, 0x6, 0x0, PseudoVSSSEG6E64_V_M1 }, // 243
  { 0x6, 0x1, 0x0, 0x3, 0x0, PseudoVSSEG6E8_V_M1_MASK }, // 244
  { 0x6, 0x1, 0x0, 0x3, 0x5, PseudoVSSEG6E8_V_MF8_MASK }, // 245
  { 0x6, 0x1, 0x0, 0x3, 0x6, PseudoVSSEG6E8_V_MF4_MASK }, // 246
  { 0x6, 0x1, 0x0, 0x3, 0x7, PseudoVSSEG6E8_V_MF2_MASK }, // 247
  { 0x6, 0x1, 0x0, 0x4, 0x0, PseudoVSSEG6E16_V_M1_MASK }, // 248
  { 0x6, 0x1, 0x0, 0x4, 0x6, PseudoVSSEG6E16_V_MF4_MASK }, // 249
  { 0x6, 0x1, 0x0, 0x4, 0x7, PseudoVSSEG6E16_V_MF2_MASK }, // 250
  { 0x6, 0x1, 0x0, 0x5, 0x0, PseudoVSSEG6E32_V_M1_MASK }, // 251
  { 0x6, 0x1, 0x0, 0x5, 0x7, PseudoVSSEG6E32_V_MF2_MASK }, // 252
  { 0x6, 0x1, 0x0, 0x6, 0x0, PseudoVSSEG6E64_V_M1_MASK }, // 253
  { 0x6, 0x1, 0x1, 0x3, 0x0, PseudoVSSSEG6E8_V_M1_MASK }, // 254
  { 0x6, 0x1, 0x1, 0x3, 0x5, PseudoVSSSEG6E8_V_MF8_MASK }, // 255
  { 0x6, 0x1, 0x1, 0x3, 0x6, PseudoVSSSEG6E8_V_MF4_MASK }, // 256
  { 0x6, 0x1, 0x1, 0x3, 0x7, PseudoVSSSEG6E8_V_MF2_MASK }, // 257
  { 0x6, 0x1, 0x1, 0x4, 0x0, PseudoVSSSEG6E16_V_M1_MASK }, // 258
  { 0x6, 0x1, 0x1, 0x4, 0x6, PseudoVSSSEG6E16_V_MF4_MASK }, // 259
  { 0x6, 0x1, 0x1, 0x4, 0x7, PseudoVSSSEG6E16_V_MF2_MASK }, // 260
  { 0x6, 0x1, 0x1, 0x5, 0x0, PseudoVSSSEG6E32_V_M1_MASK }, // 261
  { 0x6, 0x1, 0x1, 0x5, 0x7, PseudoVSSSEG6E32_V_MF2_MASK }, // 262
  { 0x6, 0x1, 0x1, 0x6, 0x0, PseudoVSSSEG6E64_V_M1_MASK }, // 263
  { 0x7, 0x0, 0x0, 0x3, 0x0, PseudoVSSEG7E8_V_M1 }, // 264
  { 0x7, 0x0, 0x0, 0x3, 0x5, PseudoVSSEG7E8_V_MF8 }, // 265
  { 0x7, 0x0, 0x0, 0x3, 0x6, PseudoVSSEG7E8_V_MF4 }, // 266
  { 0x7, 0x0, 0x0, 0x3, 0x7, PseudoVSSEG7E8_V_MF2 }, // 267
  { 0x7, 0x0, 0x0, 0x4, 0x0, PseudoVSSEG7E16_V_M1 }, // 268
  { 0x7, 0x0, 0x0, 0x4, 0x6, PseudoVSSEG7E16_V_MF4 }, // 269
  { 0x7, 0x0, 0x0, 0x4, 0x7, PseudoVSSEG7E16_V_MF2 }, // 270
  { 0x7, 0x0, 0x0, 0x5, 0x0, PseudoVSSEG7E32_V_M1 }, // 271
  { 0x7, 0x0, 0x0, 0x5, 0x7, PseudoVSSEG7E32_V_MF2 }, // 272
  { 0x7, 0x0, 0x0, 0x6, 0x0, PseudoVSSEG7E64_V_M1 }, // 273
  { 0x7, 0x0, 0x1, 0x3, 0x0, PseudoVSSSEG7E8_V_M1 }, // 274
  { 0x7, 0x0, 0x1, 0x3, 0x5, PseudoVSSSEG7E8_V_MF8 }, // 275
  { 0x7, 0x0, 0x1, 0x3, 0x6, PseudoVSSSEG7E8_V_MF4 }, // 276
  { 0x7, 0x0, 0x1, 0x3, 0x7, PseudoVSSSEG7E8_V_MF2 }, // 277
  { 0x7, 0x0, 0x1, 0x4, 0x0, PseudoVSSSEG7E16_V_M1 }, // 278
  { 0x7, 0x0, 0x1, 0x4, 0x6, PseudoVSSSEG7E16_V_MF4 }, // 279
  { 0x7, 0x0, 0x1, 0x4, 0x7, PseudoVSSSEG7E16_V_MF2 }, // 280
  { 0x7, 0x0, 0x1, 0x5, 0x0, PseudoVSSSEG7E32_V_M1 }, // 281
  { 0x7, 0x0, 0x1, 0x5, 0x7, PseudoVSSSEG7E32_V_MF2 }, // 282
  { 0x7, 0x0, 0x1, 0x6, 0x0, PseudoVSSSEG7E64_V_M1 }, // 283
  { 0x7, 0x1, 0x0, 0x3, 0x0, PseudoVSSEG7E8_V_M1_MASK }, // 284
  { 0x7, 0x1, 0x0, 0x3, 0x5, PseudoVSSEG7E8_V_MF8_MASK }, // 285
  { 0x7, 0x1, 0x0, 0x3, 0x6, PseudoVSSEG7E8_V_MF4_MASK }, // 286
  { 0x7, 0x1, 0x0, 0x3, 0x7, PseudoVSSEG7E8_V_MF2_MASK }, // 287
  { 0x7, 0x1, 0x0, 0x4, 0x0, PseudoVSSEG7E16_V_M1_MASK }, // 288
  { 0x7, 0x1, 0x0, 0x4, 0x6, PseudoVSSEG7E16_V_MF4_MASK }, // 289
  { 0x7, 0x1, 0x0, 0x4, 0x7, PseudoVSSEG7E16_V_MF2_MASK }, // 290
  { 0x7, 0x1, 0x0, 0x5, 0x0, PseudoVSSEG7E32_V_M1_MASK }, // 291
  { 0x7, 0x1, 0x0, 0x5, 0x7, PseudoVSSEG7E32_V_MF2_MASK }, // 292
  { 0x7, 0x1, 0x0, 0x6, 0x0, PseudoVSSEG7E64_V_M1_MASK }, // 293
  { 0x7, 0x1, 0x1, 0x3, 0x0, PseudoVSSSEG7E8_V_M1_MASK }, // 294
  { 0x7, 0x1, 0x1, 0x3, 0x5, PseudoVSSSEG7E8_V_MF8_MASK }, // 295
  { 0x7, 0x1, 0x1, 0x3, 0x6, PseudoVSSSEG7E8_V_MF4_MASK }, // 296
  { 0x7, 0x1, 0x1, 0x3, 0x7, PseudoVSSSEG7E8_V_MF2_MASK }, // 297
  { 0x7, 0x1, 0x1, 0x4, 0x0, PseudoVSSSEG7E16_V_M1_MASK }, // 298
  { 0x7, 0x1, 0x1, 0x4, 0x6, PseudoVSSSEG7E16_V_MF4_MASK }, // 299
  { 0x7, 0x1, 0x1, 0x4, 0x7, PseudoVSSSEG7E16_V_MF2_MASK }, // 300
  { 0x7, 0x1, 0x1, 0x5, 0x0, PseudoVSSSEG7E32_V_M1_MASK }, // 301
  { 0x7, 0x1, 0x1, 0x5, 0x7, PseudoVSSSEG7E32_V_MF2_MASK }, // 302
  { 0x7, 0x1, 0x1, 0x6, 0x0, PseudoVSSSEG7E64_V_M1_MASK }, // 303
  { 0x8, 0x0, 0x0, 0x3, 0x0, PseudoVSSEG8E8_V_M1 }, // 304
  { 0x8, 0x0, 0x0, 0x3, 0x5, PseudoVSSEG8E8_V_MF8 }, // 305
  { 0x8, 0x0, 0x0, 0x3, 0x6, PseudoVSSEG8E8_V_MF4 }, // 306
  { 0x8, 0x0, 0x0, 0x3, 0x7, PseudoVSSEG8E8_V_MF2 }, // 307
  { 0x8, 0x0, 0x0, 0x4, 0x0, PseudoVSSEG8E16_V_M1 }, // 308
  { 0x8, 0x0, 0x0, 0x4, 0x6, PseudoVSSEG8E16_V_MF4 }, // 309
  { 0x8, 0x0, 0x0, 0x4, 0x7, PseudoVSSEG8E16_V_MF2 }, // 310
  { 0x8, 0x0, 0x0, 0x5, 0x0, PseudoVSSEG8E32_V_M1 }, // 311
  { 0x8, 0x0, 0x0, 0x5, 0x7, PseudoVSSEG8E32_V_MF2 }, // 312
  { 0x8, 0x0, 0x0, 0x6, 0x0, PseudoVSSEG8E64_V_M1 }, // 313
  { 0x8, 0x0, 0x1, 0x3, 0x0, PseudoVSSSEG8E8_V_M1 }, // 314
  { 0x8, 0x0, 0x1, 0x3, 0x5, PseudoVSSSEG8E8_V_MF8 }, // 315
  { 0x8, 0x0, 0x1, 0x3, 0x6, PseudoVSSSEG8E8_V_MF4 }, // 316
  { 0x8, 0x0, 0x1, 0x3, 0x7, PseudoVSSSEG8E8_V_MF2 }, // 317
  { 0x8, 0x0, 0x1, 0x4, 0x0, PseudoVSSSEG8E16_V_M1 }, // 318
  { 0x8, 0x0, 0x1, 0x4, 0x6, PseudoVSSSEG8E16_V_MF4 }, // 319
  { 0x8, 0x0, 0x1, 0x4, 0x7, PseudoVSSSEG8E16_V_MF2 }, // 320
  { 0x8, 0x0, 0x1, 0x5, 0x0, PseudoVSSSEG8E32_V_M1 }, // 321
  { 0x8, 0x0, 0x1, 0x5, 0x7, PseudoVSSSEG8E32_V_MF2 }, // 322
  { 0x8, 0x0, 0x1, 0x6, 0x0, PseudoVSSSEG8E64_V_M1 }, // 323
  { 0x8, 0x1, 0x0, 0x3, 0x0, PseudoVSSEG8E8_V_M1_MASK }, // 324
  { 0x8, 0x1, 0x0, 0x3, 0x5, PseudoVSSEG8E8_V_MF8_MASK }, // 325
  { 0x8, 0x1, 0x0, 0x3, 0x6, PseudoVSSEG8E8_V_MF4_MASK }, // 326
  { 0x8, 0x1, 0x0, 0x3, 0x7, PseudoVSSEG8E8_V_MF2_MASK }, // 327
  { 0x8, 0x1, 0x0, 0x4, 0x0, PseudoVSSEG8E16_V_M1_MASK }, // 328
  { 0x8, 0x1, 0x0, 0x4, 0x6, PseudoVSSEG8E16_V_MF4_MASK }, // 329
  { 0x8, 0x1, 0x0, 0x4, 0x7, PseudoVSSEG8E16_V_MF2_MASK }, // 330
  { 0x8, 0x1, 0x0, 0x5, 0x0, PseudoVSSEG8E32_V_M1_MASK }, // 331
  { 0x8, 0x1, 0x0, 0x5, 0x7, PseudoVSSEG8E32_V_MF2_MASK }, // 332
  { 0x8, 0x1, 0x0, 0x6, 0x0, PseudoVSSEG8E64_V_M1_MASK }, // 333
  { 0x8, 0x1, 0x1, 0x3, 0x0, PseudoVSSSEG8E8_V_M1_MASK }, // 334
  { 0x8, 0x1, 0x1, 0x3, 0x5, PseudoVSSSEG8E8_V_MF8_MASK }, // 335
  { 0x8, 0x1, 0x1, 0x3, 0x6, PseudoVSSSEG8E8_V_MF4_MASK }, // 336
  { 0x8, 0x1, 0x1, 0x3, 0x7, PseudoVSSSEG8E8_V_MF2_MASK }, // 337
  { 0x8, 0x1, 0x1, 0x4, 0x0, PseudoVSSSEG8E16_V_M1_MASK }, // 338
  { 0x8, 0x1, 0x1, 0x4, 0x6, PseudoVSSSEG8E16_V_MF4_MASK }, // 339
  { 0x8, 0x1, 0x1, 0x4, 0x7, PseudoVSSSEG8E16_V_MF2_MASK }, // 340
  { 0x8, 0x1, 0x1, 0x5, 0x0, PseudoVSSSEG8E32_V_M1_MASK }, // 341
  { 0x8, 0x1, 0x1, 0x5, 0x7, PseudoVSSSEG8E32_V_MF2_MASK }, // 342
  { 0x8, 0x1, 0x1, 0x6, 0x0, PseudoVSSSEG8E64_V_M1_MASK }, // 343
 };

const VSSEGPseudo *getVSSEGPseudo(uint8_t NF, uint8_t Masked, uint8_t Strided, uint8_t Log2SEW, uint8_t LMUL) {
  struct KeyType {
    uint8_t NF;
    uint8_t Masked;
    uint8_t Strided;
    uint8_t Log2SEW;
    uint8_t LMUL;
  };
  KeyType Key = {NF, Masked, Strided, Log2SEW, LMUL};
  auto Table = makeArrayRef(RISCVVSSEGTable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const VSSEGPseudo &LHS, const KeyType &RHS) {
      if (LHS.NF < RHS.NF)
        return true;
      if (LHS.NF > RHS.NF)
        return false;
      if (LHS.Masked < RHS.Masked)
        return true;
      if (LHS.Masked > RHS.Masked)
        return false;
      if (LHS.Strided < RHS.Strided)
        return true;
      if (LHS.Strided > RHS.Strided)
        return false;
      if (LHS.Log2SEW < RHS.Log2SEW)
        return true;
      if (LHS.Log2SEW > RHS.Log2SEW)
        return false;
      if (LHS.LMUL < RHS.LMUL)
        return true;
      if (LHS.LMUL > RHS.LMUL)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.NF != Idx->NF ||
      Key.Masked != Idx->Masked ||
      Key.Strided != Idx->Strided ||
      Key.Log2SEW != Idx->Log2SEW ||
      Key.LMUL != Idx->LMUL)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_RISCVVSXSEGTable_DECL
const VSXSEGPseudo *getVSXSEGPseudo(uint8_t NF, uint8_t Masked, uint8_t Ordered, uint8_t Log2SEW, uint8_t LMUL, uint8_t IndexLMUL);
#endif

#ifdef GET_RISCVVSXSEGTable_IMPL
constexpr VSXSEGPseudo RISCVVSXSEGTable[] = {
  { 0x2, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG2EI8_V_M1_M1 }, // 0
  { 0x2, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG2EI8_V_MF8_M1 }, // 1
  { 0x2, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG2EI8_V_MF4_M1 }, // 2
  { 0x2, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG2EI8_V_MF2_M1 }, // 3
  { 0x2, 0x0, 0x0, 0x3, 0x1, 0x0, PseudoVSUXSEG2EI8_V_M1_M2 }, // 4
  { 0x2, 0x0, 0x0, 0x3, 0x1, 0x1, PseudoVSUXSEG2EI8_V_M2_M2 }, // 5
  { 0x2, 0x0, 0x0, 0x3, 0x1, 0x6, PseudoVSUXSEG2EI8_V_MF4_M2 }, // 6
  { 0x2, 0x0, 0x0, 0x3, 0x1, 0x7, PseudoVSUXSEG2EI8_V_MF2_M2 }, // 7
  { 0x2, 0x0, 0x0, 0x3, 0x2, 0x0, PseudoVSUXSEG2EI8_V_M1_M4 }, // 8
  { 0x2, 0x0, 0x0, 0x3, 0x2, 0x1, PseudoVSUXSEG2EI8_V_M2_M4 }, // 9
  { 0x2, 0x0, 0x0, 0x3, 0x2, 0x2, PseudoVSUXSEG2EI8_V_M4_M4 }, // 10
  { 0x2, 0x0, 0x0, 0x3, 0x2, 0x7, PseudoVSUXSEG2EI8_V_MF2_M4 }, // 11
  { 0x2, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG2EI8_V_MF8_MF8 }, // 12
  { 0x2, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG2EI8_V_MF8_MF4 }, // 13
  { 0x2, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG2EI8_V_MF4_MF4 }, // 14
  { 0x2, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG2EI8_V_MF8_MF2 }, // 15
  { 0x2, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG2EI8_V_MF4_MF2 }, // 16
  { 0x2, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG2EI8_V_MF2_MF2 }, // 17
  { 0x2, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG2EI16_V_M1_M1 }, // 18
  { 0x2, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG2EI16_V_M2_M1 }, // 19
  { 0x2, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG2EI16_V_MF4_M1 }, // 20
  { 0x2, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG2EI16_V_MF2_M1 }, // 21
  { 0x2, 0x0, 0x0, 0x4, 0x1, 0x0, PseudoVSUXSEG2EI16_V_M1_M2 }, // 22
  { 0x2, 0x0, 0x0, 0x4, 0x1, 0x1, PseudoVSUXSEG2EI16_V_M2_M2 }, // 23
  { 0x2, 0x0, 0x0, 0x4, 0x1, 0x2, PseudoVSUXSEG2EI16_V_M4_M2 }, // 24
  { 0x2, 0x0, 0x0, 0x4, 0x1, 0x7, PseudoVSUXSEG2EI16_V_MF2_M2 }, // 25
  { 0x2, 0x0, 0x0, 0x4, 0x2, 0x0, PseudoVSUXSEG2EI16_V_M1_M4 }, // 26
  { 0x2, 0x0, 0x0, 0x4, 0x2, 0x1, PseudoVSUXSEG2EI16_V_M2_M4 }, // 27
  { 0x2, 0x0, 0x0, 0x4, 0x2, 0x2, PseudoVSUXSEG2EI16_V_M4_M4 }, // 28
  { 0x2, 0x0, 0x0, 0x4, 0x2, 0x3, PseudoVSUXSEG2EI16_V_M8_M4 }, // 29
  { 0x2, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG2EI16_V_MF4_MF8 }, // 30
  { 0x2, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG2EI16_V_MF4_MF4 }, // 31
  { 0x2, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG2EI16_V_MF2_MF4 }, // 32
  { 0x2, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG2EI16_V_M1_MF2 }, // 33
  { 0x2, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG2EI16_V_MF4_MF2 }, // 34
  { 0x2, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG2EI16_V_MF2_MF2 }, // 35
  { 0x2, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG2EI32_V_M1_M1 }, // 36
  { 0x2, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG2EI32_V_M2_M1 }, // 37
  { 0x2, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG2EI32_V_M4_M1 }, // 38
  { 0x2, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG2EI32_V_MF2_M1 }, // 39
  { 0x2, 0x0, 0x0, 0x5, 0x1, 0x0, PseudoVSUXSEG2EI32_V_M1_M2 }, // 40
  { 0x2, 0x0, 0x0, 0x5, 0x1, 0x1, PseudoVSUXSEG2EI32_V_M2_M2 }, // 41
  { 0x2, 0x0, 0x0, 0x5, 0x1, 0x2, PseudoVSUXSEG2EI32_V_M4_M2 }, // 42
  { 0x2, 0x0, 0x0, 0x5, 0x1, 0x3, PseudoVSUXSEG2EI32_V_M8_M2 }, // 43
  { 0x2, 0x0, 0x0, 0x5, 0x2, 0x1, PseudoVSUXSEG2EI32_V_M2_M4 }, // 44
  { 0x2, 0x0, 0x0, 0x5, 0x2, 0x2, PseudoVSUXSEG2EI32_V_M4_M4 }, // 45
  { 0x2, 0x0, 0x0, 0x5, 0x2, 0x3, PseudoVSUXSEG2EI32_V_M8_M4 }, // 46
  { 0x2, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG2EI32_V_MF2_MF8 }, // 47
  { 0x2, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG2EI32_V_M1_MF4 }, // 48
  { 0x2, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG2EI32_V_MF2_MF4 }, // 49
  { 0x2, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG2EI32_V_M1_MF2 }, // 50
  { 0x2, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG2EI32_V_M2_MF2 }, // 51
  { 0x2, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG2EI32_V_MF2_MF2 }, // 52
  { 0x2, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG2EI64_V_M1_M1 }, // 53
  { 0x2, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG2EI64_V_M2_M1 }, // 54
  { 0x2, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG2EI64_V_M4_M1 }, // 55
  { 0x2, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG2EI64_V_M8_M1 }, // 56
  { 0x2, 0x0, 0x0, 0x6, 0x1, 0x1, PseudoVSUXSEG2EI64_V_M2_M2 }, // 57
  { 0x2, 0x0, 0x0, 0x6, 0x1, 0x2, PseudoVSUXSEG2EI64_V_M4_M2 }, // 58
  { 0x2, 0x0, 0x0, 0x6, 0x1, 0x3, PseudoVSUXSEG2EI64_V_M8_M2 }, // 59
  { 0x2, 0x0, 0x0, 0x6, 0x2, 0x2, PseudoVSUXSEG2EI64_V_M4_M4 }, // 60
  { 0x2, 0x0, 0x0, 0x6, 0x2, 0x3, PseudoVSUXSEG2EI64_V_M8_M4 }, // 61
  { 0x2, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG2EI64_V_M1_MF8 }, // 62
  { 0x2, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG2EI64_V_M1_MF4 }, // 63
  { 0x2, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG2EI64_V_M2_MF4 }, // 64
  { 0x2, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG2EI64_V_M1_MF2 }, // 65
  { 0x2, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG2EI64_V_M2_MF2 }, // 66
  { 0x2, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG2EI64_V_M4_MF2 }, // 67
  { 0x2, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG2EI8_V_M1_M1 }, // 68
  { 0x2, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG2EI8_V_MF8_M1 }, // 69
  { 0x2, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG2EI8_V_MF4_M1 }, // 70
  { 0x2, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG2EI8_V_MF2_M1 }, // 71
  { 0x2, 0x0, 0x1, 0x3, 0x1, 0x0, PseudoVSOXSEG2EI8_V_M1_M2 }, // 72
  { 0x2, 0x0, 0x1, 0x3, 0x1, 0x1, PseudoVSOXSEG2EI8_V_M2_M2 }, // 73
  { 0x2, 0x0, 0x1, 0x3, 0x1, 0x6, PseudoVSOXSEG2EI8_V_MF4_M2 }, // 74
  { 0x2, 0x0, 0x1, 0x3, 0x1, 0x7, PseudoVSOXSEG2EI8_V_MF2_M2 }, // 75
  { 0x2, 0x0, 0x1, 0x3, 0x2, 0x0, PseudoVSOXSEG2EI8_V_M1_M4 }, // 76
  { 0x2, 0x0, 0x1, 0x3, 0x2, 0x1, PseudoVSOXSEG2EI8_V_M2_M4 }, // 77
  { 0x2, 0x0, 0x1, 0x3, 0x2, 0x2, PseudoVSOXSEG2EI8_V_M4_M4 }, // 78
  { 0x2, 0x0, 0x1, 0x3, 0x2, 0x7, PseudoVSOXSEG2EI8_V_MF2_M4 }, // 79
  { 0x2, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG2EI8_V_MF8_MF8 }, // 80
  { 0x2, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG2EI8_V_MF8_MF4 }, // 81
  { 0x2, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG2EI8_V_MF4_MF4 }, // 82
  { 0x2, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG2EI8_V_MF8_MF2 }, // 83
  { 0x2, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG2EI8_V_MF4_MF2 }, // 84
  { 0x2, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG2EI8_V_MF2_MF2 }, // 85
  { 0x2, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG2EI16_V_M1_M1 }, // 86
  { 0x2, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG2EI16_V_M2_M1 }, // 87
  { 0x2, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG2EI16_V_MF4_M1 }, // 88
  { 0x2, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG2EI16_V_MF2_M1 }, // 89
  { 0x2, 0x0, 0x1, 0x4, 0x1, 0x0, PseudoVSOXSEG2EI16_V_M1_M2 }, // 90
  { 0x2, 0x0, 0x1, 0x4, 0x1, 0x1, PseudoVSOXSEG2EI16_V_M2_M2 }, // 91
  { 0x2, 0x0, 0x1, 0x4, 0x1, 0x2, PseudoVSOXSEG2EI16_V_M4_M2 }, // 92
  { 0x2, 0x0, 0x1, 0x4, 0x1, 0x7, PseudoVSOXSEG2EI16_V_MF2_M2 }, // 93
  { 0x2, 0x0, 0x1, 0x4, 0x2, 0x0, PseudoVSOXSEG2EI16_V_M1_M4 }, // 94
  { 0x2, 0x0, 0x1, 0x4, 0x2, 0x1, PseudoVSOXSEG2EI16_V_M2_M4 }, // 95
  { 0x2, 0x0, 0x1, 0x4, 0x2, 0x2, PseudoVSOXSEG2EI16_V_M4_M4 }, // 96
  { 0x2, 0x0, 0x1, 0x4, 0x2, 0x3, PseudoVSOXSEG2EI16_V_M8_M4 }, // 97
  { 0x2, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG2EI16_V_MF4_MF8 }, // 98
  { 0x2, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG2EI16_V_MF4_MF4 }, // 99
  { 0x2, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG2EI16_V_MF2_MF4 }, // 100
  { 0x2, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG2EI16_V_M1_MF2 }, // 101
  { 0x2, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG2EI16_V_MF4_MF2 }, // 102
  { 0x2, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG2EI16_V_MF2_MF2 }, // 103
  { 0x2, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG2EI32_V_M1_M1 }, // 104
  { 0x2, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG2EI32_V_M2_M1 }, // 105
  { 0x2, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG2EI32_V_M4_M1 }, // 106
  { 0x2, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG2EI32_V_MF2_M1 }, // 107
  { 0x2, 0x0, 0x1, 0x5, 0x1, 0x0, PseudoVSOXSEG2EI32_V_M1_M2 }, // 108
  { 0x2, 0x0, 0x1, 0x5, 0x1, 0x1, PseudoVSOXSEG2EI32_V_M2_M2 }, // 109
  { 0x2, 0x0, 0x1, 0x5, 0x1, 0x2, PseudoVSOXSEG2EI32_V_M4_M2 }, // 110
  { 0x2, 0x0, 0x1, 0x5, 0x1, 0x3, PseudoVSOXSEG2EI32_V_M8_M2 }, // 111
  { 0x2, 0x0, 0x1, 0x5, 0x2, 0x1, PseudoVSOXSEG2EI32_V_M2_M4 }, // 112
  { 0x2, 0x0, 0x1, 0x5, 0x2, 0x2, PseudoVSOXSEG2EI32_V_M4_M4 }, // 113
  { 0x2, 0x0, 0x1, 0x5, 0x2, 0x3, PseudoVSOXSEG2EI32_V_M8_M4 }, // 114
  { 0x2, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG2EI32_V_MF2_MF8 }, // 115
  { 0x2, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG2EI32_V_M1_MF4 }, // 116
  { 0x2, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG2EI32_V_MF2_MF4 }, // 117
  { 0x2, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG2EI32_V_M1_MF2 }, // 118
  { 0x2, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG2EI32_V_M2_MF2 }, // 119
  { 0x2, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG2EI32_V_MF2_MF2 }, // 120
  { 0x2, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG2EI64_V_M1_M1 }, // 121
  { 0x2, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG2EI64_V_M2_M1 }, // 122
  { 0x2, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG2EI64_V_M4_M1 }, // 123
  { 0x2, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG2EI64_V_M8_M1 }, // 124
  { 0x2, 0x0, 0x1, 0x6, 0x1, 0x1, PseudoVSOXSEG2EI64_V_M2_M2 }, // 125
  { 0x2, 0x0, 0x1, 0x6, 0x1, 0x2, PseudoVSOXSEG2EI64_V_M4_M2 }, // 126
  { 0x2, 0x0, 0x1, 0x6, 0x1, 0x3, PseudoVSOXSEG2EI64_V_M8_M2 }, // 127
  { 0x2, 0x0, 0x1, 0x6, 0x2, 0x2, PseudoVSOXSEG2EI64_V_M4_M4 }, // 128
  { 0x2, 0x0, 0x1, 0x6, 0x2, 0x3, PseudoVSOXSEG2EI64_V_M8_M4 }, // 129
  { 0x2, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG2EI64_V_M1_MF8 }, // 130
  { 0x2, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG2EI64_V_M1_MF4 }, // 131
  { 0x2, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG2EI64_V_M2_MF4 }, // 132
  { 0x2, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG2EI64_V_M1_MF2 }, // 133
  { 0x2, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG2EI64_V_M2_MF2 }, // 134
  { 0x2, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG2EI64_V_M4_MF2 }, // 135
  { 0x2, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG2EI8_V_M1_M1_MASK }, // 136
  { 0x2, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG2EI8_V_MF8_M1_MASK }, // 137
  { 0x2, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG2EI8_V_MF4_M1_MASK }, // 138
  { 0x2, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG2EI8_V_MF2_M1_MASK }, // 139
  { 0x2, 0x1, 0x0, 0x3, 0x1, 0x0, PseudoVSUXSEG2EI8_V_M1_M2_MASK }, // 140
  { 0x2, 0x1, 0x0, 0x3, 0x1, 0x1, PseudoVSUXSEG2EI8_V_M2_M2_MASK }, // 141
  { 0x2, 0x1, 0x0, 0x3, 0x1, 0x6, PseudoVSUXSEG2EI8_V_MF4_M2_MASK }, // 142
  { 0x2, 0x1, 0x0, 0x3, 0x1, 0x7, PseudoVSUXSEG2EI8_V_MF2_M2_MASK }, // 143
  { 0x2, 0x1, 0x0, 0x3, 0x2, 0x0, PseudoVSUXSEG2EI8_V_M1_M4_MASK }, // 144
  { 0x2, 0x1, 0x0, 0x3, 0x2, 0x1, PseudoVSUXSEG2EI8_V_M2_M4_MASK }, // 145
  { 0x2, 0x1, 0x0, 0x3, 0x2, 0x2, PseudoVSUXSEG2EI8_V_M4_M4_MASK }, // 146
  { 0x2, 0x1, 0x0, 0x3, 0x2, 0x7, PseudoVSUXSEG2EI8_V_MF2_M4_MASK }, // 147
  { 0x2, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG2EI8_V_MF8_MF8_MASK }, // 148
  { 0x2, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG2EI8_V_MF8_MF4_MASK }, // 149
  { 0x2, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG2EI8_V_MF4_MF4_MASK }, // 150
  { 0x2, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG2EI8_V_MF8_MF2_MASK }, // 151
  { 0x2, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG2EI8_V_MF4_MF2_MASK }, // 152
  { 0x2, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG2EI8_V_MF2_MF2_MASK }, // 153
  { 0x2, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG2EI16_V_M1_M1_MASK }, // 154
  { 0x2, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG2EI16_V_M2_M1_MASK }, // 155
  { 0x2, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG2EI16_V_MF4_M1_MASK }, // 156
  { 0x2, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG2EI16_V_MF2_M1_MASK }, // 157
  { 0x2, 0x1, 0x0, 0x4, 0x1, 0x0, PseudoVSUXSEG2EI16_V_M1_M2_MASK }, // 158
  { 0x2, 0x1, 0x0, 0x4, 0x1, 0x1, PseudoVSUXSEG2EI16_V_M2_M2_MASK }, // 159
  { 0x2, 0x1, 0x0, 0x4, 0x1, 0x2, PseudoVSUXSEG2EI16_V_M4_M2_MASK }, // 160
  { 0x2, 0x1, 0x0, 0x4, 0x1, 0x7, PseudoVSUXSEG2EI16_V_MF2_M2_MASK }, // 161
  { 0x2, 0x1, 0x0, 0x4, 0x2, 0x0, PseudoVSUXSEG2EI16_V_M1_M4_MASK }, // 162
  { 0x2, 0x1, 0x0, 0x4, 0x2, 0x1, PseudoVSUXSEG2EI16_V_M2_M4_MASK }, // 163
  { 0x2, 0x1, 0x0, 0x4, 0x2, 0x2, PseudoVSUXSEG2EI16_V_M4_M4_MASK }, // 164
  { 0x2, 0x1, 0x0, 0x4, 0x2, 0x3, PseudoVSUXSEG2EI16_V_M8_M4_MASK }, // 165
  { 0x2, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG2EI16_V_MF4_MF8_MASK }, // 166
  { 0x2, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG2EI16_V_MF4_MF4_MASK }, // 167
  { 0x2, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG2EI16_V_MF2_MF4_MASK }, // 168
  { 0x2, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG2EI16_V_M1_MF2_MASK }, // 169
  { 0x2, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG2EI16_V_MF4_MF2_MASK }, // 170
  { 0x2, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG2EI16_V_MF2_MF2_MASK }, // 171
  { 0x2, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG2EI32_V_M1_M1_MASK }, // 172
  { 0x2, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG2EI32_V_M2_M1_MASK }, // 173
  { 0x2, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG2EI32_V_M4_M1_MASK }, // 174
  { 0x2, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG2EI32_V_MF2_M1_MASK }, // 175
  { 0x2, 0x1, 0x0, 0x5, 0x1, 0x0, PseudoVSUXSEG2EI32_V_M1_M2_MASK }, // 176
  { 0x2, 0x1, 0x0, 0x5, 0x1, 0x1, PseudoVSUXSEG2EI32_V_M2_M2_MASK }, // 177
  { 0x2, 0x1, 0x0, 0x5, 0x1, 0x2, PseudoVSUXSEG2EI32_V_M4_M2_MASK }, // 178
  { 0x2, 0x1, 0x0, 0x5, 0x1, 0x3, PseudoVSUXSEG2EI32_V_M8_M2_MASK }, // 179
  { 0x2, 0x1, 0x0, 0x5, 0x2, 0x1, PseudoVSUXSEG2EI32_V_M2_M4_MASK }, // 180
  { 0x2, 0x1, 0x0, 0x5, 0x2, 0x2, PseudoVSUXSEG2EI32_V_M4_M4_MASK }, // 181
  { 0x2, 0x1, 0x0, 0x5, 0x2, 0x3, PseudoVSUXSEG2EI32_V_M8_M4_MASK }, // 182
  { 0x2, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG2EI32_V_MF2_MF8_MASK }, // 183
  { 0x2, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG2EI32_V_M1_MF4_MASK }, // 184
  { 0x2, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG2EI32_V_MF2_MF4_MASK }, // 185
  { 0x2, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG2EI32_V_M1_MF2_MASK }, // 186
  { 0x2, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG2EI32_V_M2_MF2_MASK }, // 187
  { 0x2, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG2EI32_V_MF2_MF2_MASK }, // 188
  { 0x2, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG2EI64_V_M1_M1_MASK }, // 189
  { 0x2, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG2EI64_V_M2_M1_MASK }, // 190
  { 0x2, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG2EI64_V_M4_M1_MASK }, // 191
  { 0x2, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG2EI64_V_M8_M1_MASK }, // 192
  { 0x2, 0x1, 0x0, 0x6, 0x1, 0x1, PseudoVSUXSEG2EI64_V_M2_M2_MASK }, // 193
  { 0x2, 0x1, 0x0, 0x6, 0x1, 0x2, PseudoVSUXSEG2EI64_V_M4_M2_MASK }, // 194
  { 0x2, 0x1, 0x0, 0x6, 0x1, 0x3, PseudoVSUXSEG2EI64_V_M8_M2_MASK }, // 195
  { 0x2, 0x1, 0x0, 0x6, 0x2, 0x2, PseudoVSUXSEG2EI64_V_M4_M4_MASK }, // 196
  { 0x2, 0x1, 0x0, 0x6, 0x2, 0x3, PseudoVSUXSEG2EI64_V_M8_M4_MASK }, // 197
  { 0x2, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG2EI64_V_M1_MF8_MASK }, // 198
  { 0x2, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG2EI64_V_M1_MF4_MASK }, // 199
  { 0x2, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG2EI64_V_M2_MF4_MASK }, // 200
  { 0x2, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG2EI64_V_M1_MF2_MASK }, // 201
  { 0x2, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG2EI64_V_M2_MF2_MASK }, // 202
  { 0x2, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG2EI64_V_M4_MF2_MASK }, // 203
  { 0x2, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG2EI8_V_M1_M1_MASK }, // 204
  { 0x2, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG2EI8_V_MF8_M1_MASK }, // 205
  { 0x2, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG2EI8_V_MF4_M1_MASK }, // 206
  { 0x2, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG2EI8_V_MF2_M1_MASK }, // 207
  { 0x2, 0x1, 0x1, 0x3, 0x1, 0x0, PseudoVSOXSEG2EI8_V_M1_M2_MASK }, // 208
  { 0x2, 0x1, 0x1, 0x3, 0x1, 0x1, PseudoVSOXSEG2EI8_V_M2_M2_MASK }, // 209
  { 0x2, 0x1, 0x1, 0x3, 0x1, 0x6, PseudoVSOXSEG2EI8_V_MF4_M2_MASK }, // 210
  { 0x2, 0x1, 0x1, 0x3, 0x1, 0x7, PseudoVSOXSEG2EI8_V_MF2_M2_MASK }, // 211
  { 0x2, 0x1, 0x1, 0x3, 0x2, 0x0, PseudoVSOXSEG2EI8_V_M1_M4_MASK }, // 212
  { 0x2, 0x1, 0x1, 0x3, 0x2, 0x1, PseudoVSOXSEG2EI8_V_M2_M4_MASK }, // 213
  { 0x2, 0x1, 0x1, 0x3, 0x2, 0x2, PseudoVSOXSEG2EI8_V_M4_M4_MASK }, // 214
  { 0x2, 0x1, 0x1, 0x3, 0x2, 0x7, PseudoVSOXSEG2EI8_V_MF2_M4_MASK }, // 215
  { 0x2, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG2EI8_V_MF8_MF8_MASK }, // 216
  { 0x2, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG2EI8_V_MF8_MF4_MASK }, // 217
  { 0x2, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG2EI8_V_MF4_MF4_MASK }, // 218
  { 0x2, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG2EI8_V_MF8_MF2_MASK }, // 219
  { 0x2, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG2EI8_V_MF4_MF2_MASK }, // 220
  { 0x2, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG2EI8_V_MF2_MF2_MASK }, // 221
  { 0x2, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG2EI16_V_M1_M1_MASK }, // 222
  { 0x2, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG2EI16_V_M2_M1_MASK }, // 223
  { 0x2, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG2EI16_V_MF4_M1_MASK }, // 224
  { 0x2, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG2EI16_V_MF2_M1_MASK }, // 225
  { 0x2, 0x1, 0x1, 0x4, 0x1, 0x0, PseudoVSOXSEG2EI16_V_M1_M2_MASK }, // 226
  { 0x2, 0x1, 0x1, 0x4, 0x1, 0x1, PseudoVSOXSEG2EI16_V_M2_M2_MASK }, // 227
  { 0x2, 0x1, 0x1, 0x4, 0x1, 0x2, PseudoVSOXSEG2EI16_V_M4_M2_MASK }, // 228
  { 0x2, 0x1, 0x1, 0x4, 0x1, 0x7, PseudoVSOXSEG2EI16_V_MF2_M2_MASK }, // 229
  { 0x2, 0x1, 0x1, 0x4, 0x2, 0x0, PseudoVSOXSEG2EI16_V_M1_M4_MASK }, // 230
  { 0x2, 0x1, 0x1, 0x4, 0x2, 0x1, PseudoVSOXSEG2EI16_V_M2_M4_MASK }, // 231
  { 0x2, 0x1, 0x1, 0x4, 0x2, 0x2, PseudoVSOXSEG2EI16_V_M4_M4_MASK }, // 232
  { 0x2, 0x1, 0x1, 0x4, 0x2, 0x3, PseudoVSOXSEG2EI16_V_M8_M4_MASK }, // 233
  { 0x2, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG2EI16_V_MF4_MF8_MASK }, // 234
  { 0x2, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG2EI16_V_MF4_MF4_MASK }, // 235
  { 0x2, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG2EI16_V_MF2_MF4_MASK }, // 236
  { 0x2, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG2EI16_V_M1_MF2_MASK }, // 237
  { 0x2, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG2EI16_V_MF4_MF2_MASK }, // 238
  { 0x2, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG2EI16_V_MF2_MF2_MASK }, // 239
  { 0x2, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG2EI32_V_M1_M1_MASK }, // 240
  { 0x2, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG2EI32_V_M2_M1_MASK }, // 241
  { 0x2, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG2EI32_V_M4_M1_MASK }, // 242
  { 0x2, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG2EI32_V_MF2_M1_MASK }, // 243
  { 0x2, 0x1, 0x1, 0x5, 0x1, 0x0, PseudoVSOXSEG2EI32_V_M1_M2_MASK }, // 244
  { 0x2, 0x1, 0x1, 0x5, 0x1, 0x1, PseudoVSOXSEG2EI32_V_M2_M2_MASK }, // 245
  { 0x2, 0x1, 0x1, 0x5, 0x1, 0x2, PseudoVSOXSEG2EI32_V_M4_M2_MASK }, // 246
  { 0x2, 0x1, 0x1, 0x5, 0x1, 0x3, PseudoVSOXSEG2EI32_V_M8_M2_MASK }, // 247
  { 0x2, 0x1, 0x1, 0x5, 0x2, 0x1, PseudoVSOXSEG2EI32_V_M2_M4_MASK }, // 248
  { 0x2, 0x1, 0x1, 0x5, 0x2, 0x2, PseudoVSOXSEG2EI32_V_M4_M4_MASK }, // 249
  { 0x2, 0x1, 0x1, 0x5, 0x2, 0x3, PseudoVSOXSEG2EI32_V_M8_M4_MASK }, // 250
  { 0x2, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG2EI32_V_MF2_MF8_MASK }, // 251
  { 0x2, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG2EI32_V_M1_MF4_MASK }, // 252
  { 0x2, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG2EI32_V_MF2_MF4_MASK }, // 253
  { 0x2, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG2EI32_V_M1_MF2_MASK }, // 254
  { 0x2, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG2EI32_V_M2_MF2_MASK }, // 255
  { 0x2, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG2EI32_V_MF2_MF2_MASK }, // 256
  { 0x2, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG2EI64_V_M1_M1_MASK }, // 257
  { 0x2, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG2EI64_V_M2_M1_MASK }, // 258
  { 0x2, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG2EI64_V_M4_M1_MASK }, // 259
  { 0x2, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG2EI64_V_M8_M1_MASK }, // 260
  { 0x2, 0x1, 0x1, 0x6, 0x1, 0x1, PseudoVSOXSEG2EI64_V_M2_M2_MASK }, // 261
  { 0x2, 0x1, 0x1, 0x6, 0x1, 0x2, PseudoVSOXSEG2EI64_V_M4_M2_MASK }, // 262
  { 0x2, 0x1, 0x1, 0x6, 0x1, 0x3, PseudoVSOXSEG2EI64_V_M8_M2_MASK }, // 263
  { 0x2, 0x1, 0x1, 0x6, 0x2, 0x2, PseudoVSOXSEG2EI64_V_M4_M4_MASK }, // 264
  { 0x2, 0x1, 0x1, 0x6, 0x2, 0x3, PseudoVSOXSEG2EI64_V_M8_M4_MASK }, // 265
  { 0x2, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG2EI64_V_M1_MF8_MASK }, // 266
  { 0x2, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG2EI64_V_M1_MF4_MASK }, // 267
  { 0x2, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG2EI64_V_M2_MF4_MASK }, // 268
  { 0x2, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG2EI64_V_M1_MF2_MASK }, // 269
  { 0x2, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG2EI64_V_M2_MF2_MASK }, // 270
  { 0x2, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG2EI64_V_M4_MF2_MASK }, // 271
  { 0x3, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG3EI8_V_M1_M1 }, // 272
  { 0x3, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG3EI8_V_MF8_M1 }, // 273
  { 0x3, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG3EI8_V_MF4_M1 }, // 274
  { 0x3, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG3EI8_V_MF2_M1 }, // 275
  { 0x3, 0x0, 0x0, 0x3, 0x1, 0x0, PseudoVSUXSEG3EI8_V_M1_M2 }, // 276
  { 0x3, 0x0, 0x0, 0x3, 0x1, 0x1, PseudoVSUXSEG3EI8_V_M2_M2 }, // 277
  { 0x3, 0x0, 0x0, 0x3, 0x1, 0x6, PseudoVSUXSEG3EI8_V_MF4_M2 }, // 278
  { 0x3, 0x0, 0x0, 0x3, 0x1, 0x7, PseudoVSUXSEG3EI8_V_MF2_M2 }, // 279
  { 0x3, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG3EI8_V_MF8_MF8 }, // 280
  { 0x3, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG3EI8_V_MF8_MF4 }, // 281
  { 0x3, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG3EI8_V_MF4_MF4 }, // 282
  { 0x3, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG3EI8_V_MF8_MF2 }, // 283
  { 0x3, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG3EI8_V_MF4_MF2 }, // 284
  { 0x3, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG3EI8_V_MF2_MF2 }, // 285
  { 0x3, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG3EI16_V_M1_M1 }, // 286
  { 0x3, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG3EI16_V_M2_M1 }, // 287
  { 0x3, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG3EI16_V_MF4_M1 }, // 288
  { 0x3, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG3EI16_V_MF2_M1 }, // 289
  { 0x3, 0x0, 0x0, 0x4, 0x1, 0x0, PseudoVSUXSEG3EI16_V_M1_M2 }, // 290
  { 0x3, 0x0, 0x0, 0x4, 0x1, 0x1, PseudoVSUXSEG3EI16_V_M2_M2 }, // 291
  { 0x3, 0x0, 0x0, 0x4, 0x1, 0x2, PseudoVSUXSEG3EI16_V_M4_M2 }, // 292
  { 0x3, 0x0, 0x0, 0x4, 0x1, 0x7, PseudoVSUXSEG3EI16_V_MF2_M2 }, // 293
  { 0x3, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG3EI16_V_MF4_MF8 }, // 294
  { 0x3, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG3EI16_V_MF4_MF4 }, // 295
  { 0x3, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG3EI16_V_MF2_MF4 }, // 296
  { 0x3, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG3EI16_V_M1_MF2 }, // 297
  { 0x3, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG3EI16_V_MF4_MF2 }, // 298
  { 0x3, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG3EI16_V_MF2_MF2 }, // 299
  { 0x3, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG3EI32_V_M1_M1 }, // 300
  { 0x3, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG3EI32_V_M2_M1 }, // 301
  { 0x3, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG3EI32_V_M4_M1 }, // 302
  { 0x3, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG3EI32_V_MF2_M1 }, // 303
  { 0x3, 0x0, 0x0, 0x5, 0x1, 0x0, PseudoVSUXSEG3EI32_V_M1_M2 }, // 304
  { 0x3, 0x0, 0x0, 0x5, 0x1, 0x1, PseudoVSUXSEG3EI32_V_M2_M2 }, // 305
  { 0x3, 0x0, 0x0, 0x5, 0x1, 0x2, PseudoVSUXSEG3EI32_V_M4_M2 }, // 306
  { 0x3, 0x0, 0x0, 0x5, 0x1, 0x3, PseudoVSUXSEG3EI32_V_M8_M2 }, // 307
  { 0x3, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG3EI32_V_MF2_MF8 }, // 308
  { 0x3, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG3EI32_V_M1_MF4 }, // 309
  { 0x3, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG3EI32_V_MF2_MF4 }, // 310
  { 0x3, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG3EI32_V_M1_MF2 }, // 311
  { 0x3, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG3EI32_V_M2_MF2 }, // 312
  { 0x3, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG3EI32_V_MF2_MF2 }, // 313
  { 0x3, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG3EI64_V_M1_M1 }, // 314
  { 0x3, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG3EI64_V_M2_M1 }, // 315
  { 0x3, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG3EI64_V_M4_M1 }, // 316
  { 0x3, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG3EI64_V_M8_M1 }, // 317
  { 0x3, 0x0, 0x0, 0x6, 0x1, 0x1, PseudoVSUXSEG3EI64_V_M2_M2 }, // 318
  { 0x3, 0x0, 0x0, 0x6, 0x1, 0x2, PseudoVSUXSEG3EI64_V_M4_M2 }, // 319
  { 0x3, 0x0, 0x0, 0x6, 0x1, 0x3, PseudoVSUXSEG3EI64_V_M8_M2 }, // 320
  { 0x3, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG3EI64_V_M1_MF8 }, // 321
  { 0x3, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG3EI64_V_M1_MF4 }, // 322
  { 0x3, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG3EI64_V_M2_MF4 }, // 323
  { 0x3, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG3EI64_V_M1_MF2 }, // 324
  { 0x3, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG3EI64_V_M2_MF2 }, // 325
  { 0x3, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG3EI64_V_M4_MF2 }, // 326
  { 0x3, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG3EI8_V_M1_M1 }, // 327
  { 0x3, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG3EI8_V_MF8_M1 }, // 328
  { 0x3, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG3EI8_V_MF4_M1 }, // 329
  { 0x3, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG3EI8_V_MF2_M1 }, // 330
  { 0x3, 0x0, 0x1, 0x3, 0x1, 0x0, PseudoVSOXSEG3EI8_V_M1_M2 }, // 331
  { 0x3, 0x0, 0x1, 0x3, 0x1, 0x1, PseudoVSOXSEG3EI8_V_M2_M2 }, // 332
  { 0x3, 0x0, 0x1, 0x3, 0x1, 0x6, PseudoVSOXSEG3EI8_V_MF4_M2 }, // 333
  { 0x3, 0x0, 0x1, 0x3, 0x1, 0x7, PseudoVSOXSEG3EI8_V_MF2_M2 }, // 334
  { 0x3, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG3EI8_V_MF8_MF8 }, // 335
  { 0x3, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG3EI8_V_MF8_MF4 }, // 336
  { 0x3, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG3EI8_V_MF4_MF4 }, // 337
  { 0x3, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG3EI8_V_MF8_MF2 }, // 338
  { 0x3, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG3EI8_V_MF4_MF2 }, // 339
  { 0x3, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG3EI8_V_MF2_MF2 }, // 340
  { 0x3, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG3EI16_V_M1_M1 }, // 341
  { 0x3, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG3EI16_V_M2_M1 }, // 342
  { 0x3, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG3EI16_V_MF4_M1 }, // 343
  { 0x3, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG3EI16_V_MF2_M1 }, // 344
  { 0x3, 0x0, 0x1, 0x4, 0x1, 0x0, PseudoVSOXSEG3EI16_V_M1_M2 }, // 345
  { 0x3, 0x0, 0x1, 0x4, 0x1, 0x1, PseudoVSOXSEG3EI16_V_M2_M2 }, // 346
  { 0x3, 0x0, 0x1, 0x4, 0x1, 0x2, PseudoVSOXSEG3EI16_V_M4_M2 }, // 347
  { 0x3, 0x0, 0x1, 0x4, 0x1, 0x7, PseudoVSOXSEG3EI16_V_MF2_M2 }, // 348
  { 0x3, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG3EI16_V_MF4_MF8 }, // 349
  { 0x3, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG3EI16_V_MF4_MF4 }, // 350
  { 0x3, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG3EI16_V_MF2_MF4 }, // 351
  { 0x3, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG3EI16_V_M1_MF2 }, // 352
  { 0x3, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG3EI16_V_MF4_MF2 }, // 353
  { 0x3, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG3EI16_V_MF2_MF2 }, // 354
  { 0x3, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG3EI32_V_M1_M1 }, // 355
  { 0x3, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG3EI32_V_M2_M1 }, // 356
  { 0x3, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG3EI32_V_M4_M1 }, // 357
  { 0x3, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG3EI32_V_MF2_M1 }, // 358
  { 0x3, 0x0, 0x1, 0x5, 0x1, 0x0, PseudoVSOXSEG3EI32_V_M1_M2 }, // 359
  { 0x3, 0x0, 0x1, 0x5, 0x1, 0x1, PseudoVSOXSEG3EI32_V_M2_M2 }, // 360
  { 0x3, 0x0, 0x1, 0x5, 0x1, 0x2, PseudoVSOXSEG3EI32_V_M4_M2 }, // 361
  { 0x3, 0x0, 0x1, 0x5, 0x1, 0x3, PseudoVSOXSEG3EI32_V_M8_M2 }, // 362
  { 0x3, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG3EI32_V_MF2_MF8 }, // 363
  { 0x3, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG3EI32_V_M1_MF4 }, // 364
  { 0x3, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG3EI32_V_MF2_MF4 }, // 365
  { 0x3, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG3EI32_V_M1_MF2 }, // 366
  { 0x3, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG3EI32_V_M2_MF2 }, // 367
  { 0x3, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG3EI32_V_MF2_MF2 }, // 368
  { 0x3, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG3EI64_V_M1_M1 }, // 369
  { 0x3, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG3EI64_V_M2_M1 }, // 370
  { 0x3, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG3EI64_V_M4_M1 }, // 371
  { 0x3, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG3EI64_V_M8_M1 }, // 372
  { 0x3, 0x0, 0x1, 0x6, 0x1, 0x1, PseudoVSOXSEG3EI64_V_M2_M2 }, // 373
  { 0x3, 0x0, 0x1, 0x6, 0x1, 0x2, PseudoVSOXSEG3EI64_V_M4_M2 }, // 374
  { 0x3, 0x0, 0x1, 0x6, 0x1, 0x3, PseudoVSOXSEG3EI64_V_M8_M2 }, // 375
  { 0x3, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG3EI64_V_M1_MF8 }, // 376
  { 0x3, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG3EI64_V_M1_MF4 }, // 377
  { 0x3, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG3EI64_V_M2_MF4 }, // 378
  { 0x3, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG3EI64_V_M1_MF2 }, // 379
  { 0x3, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG3EI64_V_M2_MF2 }, // 380
  { 0x3, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG3EI64_V_M4_MF2 }, // 381
  { 0x3, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG3EI8_V_M1_M1_MASK }, // 382
  { 0x3, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG3EI8_V_MF8_M1_MASK }, // 383
  { 0x3, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG3EI8_V_MF4_M1_MASK }, // 384
  { 0x3, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG3EI8_V_MF2_M1_MASK }, // 385
  { 0x3, 0x1, 0x0, 0x3, 0x1, 0x0, PseudoVSUXSEG3EI8_V_M1_M2_MASK }, // 386
  { 0x3, 0x1, 0x0, 0x3, 0x1, 0x1, PseudoVSUXSEG3EI8_V_M2_M2_MASK }, // 387
  { 0x3, 0x1, 0x0, 0x3, 0x1, 0x6, PseudoVSUXSEG3EI8_V_MF4_M2_MASK }, // 388
  { 0x3, 0x1, 0x0, 0x3, 0x1, 0x7, PseudoVSUXSEG3EI8_V_MF2_M2_MASK }, // 389
  { 0x3, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG3EI8_V_MF8_MF8_MASK }, // 390
  { 0x3, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG3EI8_V_MF8_MF4_MASK }, // 391
  { 0x3, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG3EI8_V_MF4_MF4_MASK }, // 392
  { 0x3, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG3EI8_V_MF8_MF2_MASK }, // 393
  { 0x3, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG3EI8_V_MF4_MF2_MASK }, // 394
  { 0x3, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG3EI8_V_MF2_MF2_MASK }, // 395
  { 0x3, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG3EI16_V_M1_M1_MASK }, // 396
  { 0x3, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG3EI16_V_M2_M1_MASK }, // 397
  { 0x3, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG3EI16_V_MF4_M1_MASK }, // 398
  { 0x3, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG3EI16_V_MF2_M1_MASK }, // 399
  { 0x3, 0x1, 0x0, 0x4, 0x1, 0x0, PseudoVSUXSEG3EI16_V_M1_M2_MASK }, // 400
  { 0x3, 0x1, 0x0, 0x4, 0x1, 0x1, PseudoVSUXSEG3EI16_V_M2_M2_MASK }, // 401
  { 0x3, 0x1, 0x0, 0x4, 0x1, 0x2, PseudoVSUXSEG3EI16_V_M4_M2_MASK }, // 402
  { 0x3, 0x1, 0x0, 0x4, 0x1, 0x7, PseudoVSUXSEG3EI16_V_MF2_M2_MASK }, // 403
  { 0x3, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG3EI16_V_MF4_MF8_MASK }, // 404
  { 0x3, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG3EI16_V_MF4_MF4_MASK }, // 405
  { 0x3, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG3EI16_V_MF2_MF4_MASK }, // 406
  { 0x3, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG3EI16_V_M1_MF2_MASK }, // 407
  { 0x3, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG3EI16_V_MF4_MF2_MASK }, // 408
  { 0x3, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG3EI16_V_MF2_MF2_MASK }, // 409
  { 0x3, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG3EI32_V_M1_M1_MASK }, // 410
  { 0x3, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG3EI32_V_M2_M1_MASK }, // 411
  { 0x3, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG3EI32_V_M4_M1_MASK }, // 412
  { 0x3, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG3EI32_V_MF2_M1_MASK }, // 413
  { 0x3, 0x1, 0x0, 0x5, 0x1, 0x0, PseudoVSUXSEG3EI32_V_M1_M2_MASK }, // 414
  { 0x3, 0x1, 0x0, 0x5, 0x1, 0x1, PseudoVSUXSEG3EI32_V_M2_M2_MASK }, // 415
  { 0x3, 0x1, 0x0, 0x5, 0x1, 0x2, PseudoVSUXSEG3EI32_V_M4_M2_MASK }, // 416
  { 0x3, 0x1, 0x0, 0x5, 0x1, 0x3, PseudoVSUXSEG3EI32_V_M8_M2_MASK }, // 417
  { 0x3, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG3EI32_V_MF2_MF8_MASK }, // 418
  { 0x3, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG3EI32_V_M1_MF4_MASK }, // 419
  { 0x3, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG3EI32_V_MF2_MF4_MASK }, // 420
  { 0x3, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG3EI32_V_M1_MF2_MASK }, // 421
  { 0x3, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG3EI32_V_M2_MF2_MASK }, // 422
  { 0x3, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG3EI32_V_MF2_MF2_MASK }, // 423
  { 0x3, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG3EI64_V_M1_M1_MASK }, // 424
  { 0x3, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG3EI64_V_M2_M1_MASK }, // 425
  { 0x3, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG3EI64_V_M4_M1_MASK }, // 426
  { 0x3, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG3EI64_V_M8_M1_MASK }, // 427
  { 0x3, 0x1, 0x0, 0x6, 0x1, 0x1, PseudoVSUXSEG3EI64_V_M2_M2_MASK }, // 428
  { 0x3, 0x1, 0x0, 0x6, 0x1, 0x2, PseudoVSUXSEG3EI64_V_M4_M2_MASK }, // 429
  { 0x3, 0x1, 0x0, 0x6, 0x1, 0x3, PseudoVSUXSEG3EI64_V_M8_M2_MASK }, // 430
  { 0x3, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG3EI64_V_M1_MF8_MASK }, // 431
  { 0x3, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG3EI64_V_M1_MF4_MASK }, // 432
  { 0x3, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG3EI64_V_M2_MF4_MASK }, // 433
  { 0x3, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG3EI64_V_M1_MF2_MASK }, // 434
  { 0x3, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG3EI64_V_M2_MF2_MASK }, // 435
  { 0x3, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG3EI64_V_M4_MF2_MASK }, // 436
  { 0x3, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG3EI8_V_M1_M1_MASK }, // 437
  { 0x3, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG3EI8_V_MF8_M1_MASK }, // 438
  { 0x3, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG3EI8_V_MF4_M1_MASK }, // 439
  { 0x3, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG3EI8_V_MF2_M1_MASK }, // 440
  { 0x3, 0x1, 0x1, 0x3, 0x1, 0x0, PseudoVSOXSEG3EI8_V_M1_M2_MASK }, // 441
  { 0x3, 0x1, 0x1, 0x3, 0x1, 0x1, PseudoVSOXSEG3EI8_V_M2_M2_MASK }, // 442
  { 0x3, 0x1, 0x1, 0x3, 0x1, 0x6, PseudoVSOXSEG3EI8_V_MF4_M2_MASK }, // 443
  { 0x3, 0x1, 0x1, 0x3, 0x1, 0x7, PseudoVSOXSEG3EI8_V_MF2_M2_MASK }, // 444
  { 0x3, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG3EI8_V_MF8_MF8_MASK }, // 445
  { 0x3, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG3EI8_V_MF8_MF4_MASK }, // 446
  { 0x3, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG3EI8_V_MF4_MF4_MASK }, // 447
  { 0x3, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG3EI8_V_MF8_MF2_MASK }, // 448
  { 0x3, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG3EI8_V_MF4_MF2_MASK }, // 449
  { 0x3, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG3EI8_V_MF2_MF2_MASK }, // 450
  { 0x3, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG3EI16_V_M1_M1_MASK }, // 451
  { 0x3, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG3EI16_V_M2_M1_MASK }, // 452
  { 0x3, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG3EI16_V_MF4_M1_MASK }, // 453
  { 0x3, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG3EI16_V_MF2_M1_MASK }, // 454
  { 0x3, 0x1, 0x1, 0x4, 0x1, 0x0, PseudoVSOXSEG3EI16_V_M1_M2_MASK }, // 455
  { 0x3, 0x1, 0x1, 0x4, 0x1, 0x1, PseudoVSOXSEG3EI16_V_M2_M2_MASK }, // 456
  { 0x3, 0x1, 0x1, 0x4, 0x1, 0x2, PseudoVSOXSEG3EI16_V_M4_M2_MASK }, // 457
  { 0x3, 0x1, 0x1, 0x4, 0x1, 0x7, PseudoVSOXSEG3EI16_V_MF2_M2_MASK }, // 458
  { 0x3, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG3EI16_V_MF4_MF8_MASK }, // 459
  { 0x3, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG3EI16_V_MF4_MF4_MASK }, // 460
  { 0x3, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG3EI16_V_MF2_MF4_MASK }, // 461
  { 0x3, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG3EI16_V_M1_MF2_MASK }, // 462
  { 0x3, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG3EI16_V_MF4_MF2_MASK }, // 463
  { 0x3, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG3EI16_V_MF2_MF2_MASK }, // 464
  { 0x3, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG3EI32_V_M1_M1_MASK }, // 465
  { 0x3, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG3EI32_V_M2_M1_MASK }, // 466
  { 0x3, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG3EI32_V_M4_M1_MASK }, // 467
  { 0x3, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG3EI32_V_MF2_M1_MASK }, // 468
  { 0x3, 0x1, 0x1, 0x5, 0x1, 0x0, PseudoVSOXSEG3EI32_V_M1_M2_MASK }, // 469
  { 0x3, 0x1, 0x1, 0x5, 0x1, 0x1, PseudoVSOXSEG3EI32_V_M2_M2_MASK }, // 470
  { 0x3, 0x1, 0x1, 0x5, 0x1, 0x2, PseudoVSOXSEG3EI32_V_M4_M2_MASK }, // 471
  { 0x3, 0x1, 0x1, 0x5, 0x1, 0x3, PseudoVSOXSEG3EI32_V_M8_M2_MASK }, // 472
  { 0x3, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG3EI32_V_MF2_MF8_MASK }, // 473
  { 0x3, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG3EI32_V_M1_MF4_MASK }, // 474
  { 0x3, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG3EI32_V_MF2_MF4_MASK }, // 475
  { 0x3, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG3EI32_V_M1_MF2_MASK }, // 476
  { 0x3, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG3EI32_V_M2_MF2_MASK }, // 477
  { 0x3, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG3EI32_V_MF2_MF2_MASK }, // 478
  { 0x3, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG3EI64_V_M1_M1_MASK }, // 479
  { 0x3, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG3EI64_V_M2_M1_MASK }, // 480
  { 0x3, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG3EI64_V_M4_M1_MASK }, // 481
  { 0x3, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG3EI64_V_M8_M1_MASK }, // 482
  { 0x3, 0x1, 0x1, 0x6, 0x1, 0x1, PseudoVSOXSEG3EI64_V_M2_M2_MASK }, // 483
  { 0x3, 0x1, 0x1, 0x6, 0x1, 0x2, PseudoVSOXSEG3EI64_V_M4_M2_MASK }, // 484
  { 0x3, 0x1, 0x1, 0x6, 0x1, 0x3, PseudoVSOXSEG3EI64_V_M8_M2_MASK }, // 485
  { 0x3, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG3EI64_V_M1_MF8_MASK }, // 486
  { 0x3, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG3EI64_V_M1_MF4_MASK }, // 487
  { 0x3, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG3EI64_V_M2_MF4_MASK }, // 488
  { 0x3, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG3EI64_V_M1_MF2_MASK }, // 489
  { 0x3, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG3EI64_V_M2_MF2_MASK }, // 490
  { 0x3, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG3EI64_V_M4_MF2_MASK }, // 491
  { 0x4, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG4EI8_V_M1_M1 }, // 492
  { 0x4, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG4EI8_V_MF8_M1 }, // 493
  { 0x4, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG4EI8_V_MF4_M1 }, // 494
  { 0x4, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG4EI8_V_MF2_M1 }, // 495
  { 0x4, 0x0, 0x0, 0x3, 0x1, 0x0, PseudoVSUXSEG4EI8_V_M1_M2 }, // 496
  { 0x4, 0x0, 0x0, 0x3, 0x1, 0x1, PseudoVSUXSEG4EI8_V_M2_M2 }, // 497
  { 0x4, 0x0, 0x0, 0x3, 0x1, 0x6, PseudoVSUXSEG4EI8_V_MF4_M2 }, // 498
  { 0x4, 0x0, 0x0, 0x3, 0x1, 0x7, PseudoVSUXSEG4EI8_V_MF2_M2 }, // 499
  { 0x4, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG4EI8_V_MF8_MF8 }, // 500
  { 0x4, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG4EI8_V_MF8_MF4 }, // 501
  { 0x4, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG4EI8_V_MF4_MF4 }, // 502
  { 0x4, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG4EI8_V_MF8_MF2 }, // 503
  { 0x4, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG4EI8_V_MF4_MF2 }, // 504
  { 0x4, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG4EI8_V_MF2_MF2 }, // 505
  { 0x4, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG4EI16_V_M1_M1 }, // 506
  { 0x4, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG4EI16_V_M2_M1 }, // 507
  { 0x4, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG4EI16_V_MF4_M1 }, // 508
  { 0x4, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG4EI16_V_MF2_M1 }, // 509
  { 0x4, 0x0, 0x0, 0x4, 0x1, 0x0, PseudoVSUXSEG4EI16_V_M1_M2 }, // 510
  { 0x4, 0x0, 0x0, 0x4, 0x1, 0x1, PseudoVSUXSEG4EI16_V_M2_M2 }, // 511
  { 0x4, 0x0, 0x0, 0x4, 0x1, 0x2, PseudoVSUXSEG4EI16_V_M4_M2 }, // 512
  { 0x4, 0x0, 0x0, 0x4, 0x1, 0x7, PseudoVSUXSEG4EI16_V_MF2_M2 }, // 513
  { 0x4, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG4EI16_V_MF4_MF8 }, // 514
  { 0x4, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG4EI16_V_MF4_MF4 }, // 515
  { 0x4, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG4EI16_V_MF2_MF4 }, // 516
  { 0x4, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG4EI16_V_M1_MF2 }, // 517
  { 0x4, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG4EI16_V_MF4_MF2 }, // 518
  { 0x4, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG4EI16_V_MF2_MF2 }, // 519
  { 0x4, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG4EI32_V_M1_M1 }, // 520
  { 0x4, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG4EI32_V_M2_M1 }, // 521
  { 0x4, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG4EI32_V_M4_M1 }, // 522
  { 0x4, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG4EI32_V_MF2_M1 }, // 523
  { 0x4, 0x0, 0x0, 0x5, 0x1, 0x0, PseudoVSUXSEG4EI32_V_M1_M2 }, // 524
  { 0x4, 0x0, 0x0, 0x5, 0x1, 0x1, PseudoVSUXSEG4EI32_V_M2_M2 }, // 525
  { 0x4, 0x0, 0x0, 0x5, 0x1, 0x2, PseudoVSUXSEG4EI32_V_M4_M2 }, // 526
  { 0x4, 0x0, 0x0, 0x5, 0x1, 0x3, PseudoVSUXSEG4EI32_V_M8_M2 }, // 527
  { 0x4, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG4EI32_V_MF2_MF8 }, // 528
  { 0x4, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG4EI32_V_M1_MF4 }, // 529
  { 0x4, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG4EI32_V_MF2_MF4 }, // 530
  { 0x4, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG4EI32_V_M1_MF2 }, // 531
  { 0x4, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG4EI32_V_M2_MF2 }, // 532
  { 0x4, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG4EI32_V_MF2_MF2 }, // 533
  { 0x4, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG4EI64_V_M1_M1 }, // 534
  { 0x4, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG4EI64_V_M2_M1 }, // 535
  { 0x4, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG4EI64_V_M4_M1 }, // 536
  { 0x4, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG4EI64_V_M8_M1 }, // 537
  { 0x4, 0x0, 0x0, 0x6, 0x1, 0x1, PseudoVSUXSEG4EI64_V_M2_M2 }, // 538
  { 0x4, 0x0, 0x0, 0x6, 0x1, 0x2, PseudoVSUXSEG4EI64_V_M4_M2 }, // 539
  { 0x4, 0x0, 0x0, 0x6, 0x1, 0x3, PseudoVSUXSEG4EI64_V_M8_M2 }, // 540
  { 0x4, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG4EI64_V_M1_MF8 }, // 541
  { 0x4, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG4EI64_V_M1_MF4 }, // 542
  { 0x4, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG4EI64_V_M2_MF4 }, // 543
  { 0x4, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG4EI64_V_M1_MF2 }, // 544
  { 0x4, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG4EI64_V_M2_MF2 }, // 545
  { 0x4, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG4EI64_V_M4_MF2 }, // 546
  { 0x4, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG4EI8_V_M1_M1 }, // 547
  { 0x4, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG4EI8_V_MF8_M1 }, // 548
  { 0x4, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG4EI8_V_MF4_M1 }, // 549
  { 0x4, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG4EI8_V_MF2_M1 }, // 550
  { 0x4, 0x0, 0x1, 0x3, 0x1, 0x0, PseudoVSOXSEG4EI8_V_M1_M2 }, // 551
  { 0x4, 0x0, 0x1, 0x3, 0x1, 0x1, PseudoVSOXSEG4EI8_V_M2_M2 }, // 552
  { 0x4, 0x0, 0x1, 0x3, 0x1, 0x6, PseudoVSOXSEG4EI8_V_MF4_M2 }, // 553
  { 0x4, 0x0, 0x1, 0x3, 0x1, 0x7, PseudoVSOXSEG4EI8_V_MF2_M2 }, // 554
  { 0x4, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG4EI8_V_MF8_MF8 }, // 555
  { 0x4, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG4EI8_V_MF8_MF4 }, // 556
  { 0x4, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG4EI8_V_MF4_MF4 }, // 557
  { 0x4, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG4EI8_V_MF8_MF2 }, // 558
  { 0x4, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG4EI8_V_MF4_MF2 }, // 559
  { 0x4, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG4EI8_V_MF2_MF2 }, // 560
  { 0x4, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG4EI16_V_M1_M1 }, // 561
  { 0x4, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG4EI16_V_M2_M1 }, // 562
  { 0x4, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG4EI16_V_MF4_M1 }, // 563
  { 0x4, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG4EI16_V_MF2_M1 }, // 564
  { 0x4, 0x0, 0x1, 0x4, 0x1, 0x0, PseudoVSOXSEG4EI16_V_M1_M2 }, // 565
  { 0x4, 0x0, 0x1, 0x4, 0x1, 0x1, PseudoVSOXSEG4EI16_V_M2_M2 }, // 566
  { 0x4, 0x0, 0x1, 0x4, 0x1, 0x2, PseudoVSOXSEG4EI16_V_M4_M2 }, // 567
  { 0x4, 0x0, 0x1, 0x4, 0x1, 0x7, PseudoVSOXSEG4EI16_V_MF2_M2 }, // 568
  { 0x4, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG4EI16_V_MF4_MF8 }, // 569
  { 0x4, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG4EI16_V_MF4_MF4 }, // 570
  { 0x4, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG4EI16_V_MF2_MF4 }, // 571
  { 0x4, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG4EI16_V_M1_MF2 }, // 572
  { 0x4, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG4EI16_V_MF4_MF2 }, // 573
  { 0x4, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG4EI16_V_MF2_MF2 }, // 574
  { 0x4, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG4EI32_V_M1_M1 }, // 575
  { 0x4, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG4EI32_V_M2_M1 }, // 576
  { 0x4, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG4EI32_V_M4_M1 }, // 577
  { 0x4, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG4EI32_V_MF2_M1 }, // 578
  { 0x4, 0x0, 0x1, 0x5, 0x1, 0x0, PseudoVSOXSEG4EI32_V_M1_M2 }, // 579
  { 0x4, 0x0, 0x1, 0x5, 0x1, 0x1, PseudoVSOXSEG4EI32_V_M2_M2 }, // 580
  { 0x4, 0x0, 0x1, 0x5, 0x1, 0x2, PseudoVSOXSEG4EI32_V_M4_M2 }, // 581
  { 0x4, 0x0, 0x1, 0x5, 0x1, 0x3, PseudoVSOXSEG4EI32_V_M8_M2 }, // 582
  { 0x4, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG4EI32_V_MF2_MF8 }, // 583
  { 0x4, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG4EI32_V_M1_MF4 }, // 584
  { 0x4, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG4EI32_V_MF2_MF4 }, // 585
  { 0x4, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG4EI32_V_M1_MF2 }, // 586
  { 0x4, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG4EI32_V_M2_MF2 }, // 587
  { 0x4, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG4EI32_V_MF2_MF2 }, // 588
  { 0x4, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG4EI64_V_M1_M1 }, // 589
  { 0x4, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG4EI64_V_M2_M1 }, // 590
  { 0x4, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG4EI64_V_M4_M1 }, // 591
  { 0x4, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG4EI64_V_M8_M1 }, // 592
  { 0x4, 0x0, 0x1, 0x6, 0x1, 0x1, PseudoVSOXSEG4EI64_V_M2_M2 }, // 593
  { 0x4, 0x0, 0x1, 0x6, 0x1, 0x2, PseudoVSOXSEG4EI64_V_M4_M2 }, // 594
  { 0x4, 0x0, 0x1, 0x6, 0x1, 0x3, PseudoVSOXSEG4EI64_V_M8_M2 }, // 595
  { 0x4, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG4EI64_V_M1_MF8 }, // 596
  { 0x4, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG4EI64_V_M1_MF4 }, // 597
  { 0x4, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG4EI64_V_M2_MF4 }, // 598
  { 0x4, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG4EI64_V_M1_MF2 }, // 599
  { 0x4, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG4EI64_V_M2_MF2 }, // 600
  { 0x4, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG4EI64_V_M4_MF2 }, // 601
  { 0x4, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG4EI8_V_M1_M1_MASK }, // 602
  { 0x4, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG4EI8_V_MF8_M1_MASK }, // 603
  { 0x4, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG4EI8_V_MF4_M1_MASK }, // 604
  { 0x4, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG4EI8_V_MF2_M1_MASK }, // 605
  { 0x4, 0x1, 0x0, 0x3, 0x1, 0x0, PseudoVSUXSEG4EI8_V_M1_M2_MASK }, // 606
  { 0x4, 0x1, 0x0, 0x3, 0x1, 0x1, PseudoVSUXSEG4EI8_V_M2_M2_MASK }, // 607
  { 0x4, 0x1, 0x0, 0x3, 0x1, 0x6, PseudoVSUXSEG4EI8_V_MF4_M2_MASK }, // 608
  { 0x4, 0x1, 0x0, 0x3, 0x1, 0x7, PseudoVSUXSEG4EI8_V_MF2_M2_MASK }, // 609
  { 0x4, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG4EI8_V_MF8_MF8_MASK }, // 610
  { 0x4, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG4EI8_V_MF8_MF4_MASK }, // 611
  { 0x4, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG4EI8_V_MF4_MF4_MASK }, // 612
  { 0x4, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG4EI8_V_MF8_MF2_MASK }, // 613
  { 0x4, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG4EI8_V_MF4_MF2_MASK }, // 614
  { 0x4, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG4EI8_V_MF2_MF2_MASK }, // 615
  { 0x4, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG4EI16_V_M1_M1_MASK }, // 616
  { 0x4, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG4EI16_V_M2_M1_MASK }, // 617
  { 0x4, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG4EI16_V_MF4_M1_MASK }, // 618
  { 0x4, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG4EI16_V_MF2_M1_MASK }, // 619
  { 0x4, 0x1, 0x0, 0x4, 0x1, 0x0, PseudoVSUXSEG4EI16_V_M1_M2_MASK }, // 620
  { 0x4, 0x1, 0x0, 0x4, 0x1, 0x1, PseudoVSUXSEG4EI16_V_M2_M2_MASK }, // 621
  { 0x4, 0x1, 0x0, 0x4, 0x1, 0x2, PseudoVSUXSEG4EI16_V_M4_M2_MASK }, // 622
  { 0x4, 0x1, 0x0, 0x4, 0x1, 0x7, PseudoVSUXSEG4EI16_V_MF2_M2_MASK }, // 623
  { 0x4, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG4EI16_V_MF4_MF8_MASK }, // 624
  { 0x4, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG4EI16_V_MF4_MF4_MASK }, // 625
  { 0x4, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG4EI16_V_MF2_MF4_MASK }, // 626
  { 0x4, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG4EI16_V_M1_MF2_MASK }, // 627
  { 0x4, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG4EI16_V_MF4_MF2_MASK }, // 628
  { 0x4, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG4EI16_V_MF2_MF2_MASK }, // 629
  { 0x4, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG4EI32_V_M1_M1_MASK }, // 630
  { 0x4, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG4EI32_V_M2_M1_MASK }, // 631
  { 0x4, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG4EI32_V_M4_M1_MASK }, // 632
  { 0x4, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG4EI32_V_MF2_M1_MASK }, // 633
  { 0x4, 0x1, 0x0, 0x5, 0x1, 0x0, PseudoVSUXSEG4EI32_V_M1_M2_MASK }, // 634
  { 0x4, 0x1, 0x0, 0x5, 0x1, 0x1, PseudoVSUXSEG4EI32_V_M2_M2_MASK }, // 635
  { 0x4, 0x1, 0x0, 0x5, 0x1, 0x2, PseudoVSUXSEG4EI32_V_M4_M2_MASK }, // 636
  { 0x4, 0x1, 0x0, 0x5, 0x1, 0x3, PseudoVSUXSEG4EI32_V_M8_M2_MASK }, // 637
  { 0x4, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG4EI32_V_MF2_MF8_MASK }, // 638
  { 0x4, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG4EI32_V_M1_MF4_MASK }, // 639
  { 0x4, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG4EI32_V_MF2_MF4_MASK }, // 640
  { 0x4, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG4EI32_V_M1_MF2_MASK }, // 641
  { 0x4, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG4EI32_V_M2_MF2_MASK }, // 642
  { 0x4, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG4EI32_V_MF2_MF2_MASK }, // 643
  { 0x4, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG4EI64_V_M1_M1_MASK }, // 644
  { 0x4, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG4EI64_V_M2_M1_MASK }, // 645
  { 0x4, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG4EI64_V_M4_M1_MASK }, // 646
  { 0x4, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG4EI64_V_M8_M1_MASK }, // 647
  { 0x4, 0x1, 0x0, 0x6, 0x1, 0x1, PseudoVSUXSEG4EI64_V_M2_M2_MASK }, // 648
  { 0x4, 0x1, 0x0, 0x6, 0x1, 0x2, PseudoVSUXSEG4EI64_V_M4_M2_MASK }, // 649
  { 0x4, 0x1, 0x0, 0x6, 0x1, 0x3, PseudoVSUXSEG4EI64_V_M8_M2_MASK }, // 650
  { 0x4, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG4EI64_V_M1_MF8_MASK }, // 651
  { 0x4, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG4EI64_V_M1_MF4_MASK }, // 652
  { 0x4, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG4EI64_V_M2_MF4_MASK }, // 653
  { 0x4, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG4EI64_V_M1_MF2_MASK }, // 654
  { 0x4, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG4EI64_V_M2_MF2_MASK }, // 655
  { 0x4, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG4EI64_V_M4_MF2_MASK }, // 656
  { 0x4, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG4EI8_V_M1_M1_MASK }, // 657
  { 0x4, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG4EI8_V_MF8_M1_MASK }, // 658
  { 0x4, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG4EI8_V_MF4_M1_MASK }, // 659
  { 0x4, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG4EI8_V_MF2_M1_MASK }, // 660
  { 0x4, 0x1, 0x1, 0x3, 0x1, 0x0, PseudoVSOXSEG4EI8_V_M1_M2_MASK }, // 661
  { 0x4, 0x1, 0x1, 0x3, 0x1, 0x1, PseudoVSOXSEG4EI8_V_M2_M2_MASK }, // 662
  { 0x4, 0x1, 0x1, 0x3, 0x1, 0x6, PseudoVSOXSEG4EI8_V_MF4_M2_MASK }, // 663
  { 0x4, 0x1, 0x1, 0x3, 0x1, 0x7, PseudoVSOXSEG4EI8_V_MF2_M2_MASK }, // 664
  { 0x4, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG4EI8_V_MF8_MF8_MASK }, // 665
  { 0x4, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG4EI8_V_MF8_MF4_MASK }, // 666
  { 0x4, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG4EI8_V_MF4_MF4_MASK }, // 667
  { 0x4, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG4EI8_V_MF8_MF2_MASK }, // 668
  { 0x4, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG4EI8_V_MF4_MF2_MASK }, // 669
  { 0x4, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG4EI8_V_MF2_MF2_MASK }, // 670
  { 0x4, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG4EI16_V_M1_M1_MASK }, // 671
  { 0x4, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG4EI16_V_M2_M1_MASK }, // 672
  { 0x4, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG4EI16_V_MF4_M1_MASK }, // 673
  { 0x4, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG4EI16_V_MF2_M1_MASK }, // 674
  { 0x4, 0x1, 0x1, 0x4, 0x1, 0x0, PseudoVSOXSEG4EI16_V_M1_M2_MASK }, // 675
  { 0x4, 0x1, 0x1, 0x4, 0x1, 0x1, PseudoVSOXSEG4EI16_V_M2_M2_MASK }, // 676
  { 0x4, 0x1, 0x1, 0x4, 0x1, 0x2, PseudoVSOXSEG4EI16_V_M4_M2_MASK }, // 677
  { 0x4, 0x1, 0x1, 0x4, 0x1, 0x7, PseudoVSOXSEG4EI16_V_MF2_M2_MASK }, // 678
  { 0x4, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG4EI16_V_MF4_MF8_MASK }, // 679
  { 0x4, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG4EI16_V_MF4_MF4_MASK }, // 680
  { 0x4, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG4EI16_V_MF2_MF4_MASK }, // 681
  { 0x4, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG4EI16_V_M1_MF2_MASK }, // 682
  { 0x4, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG4EI16_V_MF4_MF2_MASK }, // 683
  { 0x4, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG4EI16_V_MF2_MF2_MASK }, // 684
  { 0x4, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG4EI32_V_M1_M1_MASK }, // 685
  { 0x4, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG4EI32_V_M2_M1_MASK }, // 686
  { 0x4, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG4EI32_V_M4_M1_MASK }, // 687
  { 0x4, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG4EI32_V_MF2_M1_MASK }, // 688
  { 0x4, 0x1, 0x1, 0x5, 0x1, 0x0, PseudoVSOXSEG4EI32_V_M1_M2_MASK }, // 689
  { 0x4, 0x1, 0x1, 0x5, 0x1, 0x1, PseudoVSOXSEG4EI32_V_M2_M2_MASK }, // 690
  { 0x4, 0x1, 0x1, 0x5, 0x1, 0x2, PseudoVSOXSEG4EI32_V_M4_M2_MASK }, // 691
  { 0x4, 0x1, 0x1, 0x5, 0x1, 0x3, PseudoVSOXSEG4EI32_V_M8_M2_MASK }, // 692
  { 0x4, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG4EI32_V_MF2_MF8_MASK }, // 693
  { 0x4, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG4EI32_V_M1_MF4_MASK }, // 694
  { 0x4, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG4EI32_V_MF2_MF4_MASK }, // 695
  { 0x4, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG4EI32_V_M1_MF2_MASK }, // 696
  { 0x4, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG4EI32_V_M2_MF2_MASK }, // 697
  { 0x4, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG4EI32_V_MF2_MF2_MASK }, // 698
  { 0x4, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG4EI64_V_M1_M1_MASK }, // 699
  { 0x4, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG4EI64_V_M2_M1_MASK }, // 700
  { 0x4, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG4EI64_V_M4_M1_MASK }, // 701
  { 0x4, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG4EI64_V_M8_M1_MASK }, // 702
  { 0x4, 0x1, 0x1, 0x6, 0x1, 0x1, PseudoVSOXSEG4EI64_V_M2_M2_MASK }, // 703
  { 0x4, 0x1, 0x1, 0x6, 0x1, 0x2, PseudoVSOXSEG4EI64_V_M4_M2_MASK }, // 704
  { 0x4, 0x1, 0x1, 0x6, 0x1, 0x3, PseudoVSOXSEG4EI64_V_M8_M2_MASK }, // 705
  { 0x4, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG4EI64_V_M1_MF8_MASK }, // 706
  { 0x4, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG4EI64_V_M1_MF4_MASK }, // 707
  { 0x4, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG4EI64_V_M2_MF4_MASK }, // 708
  { 0x4, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG4EI64_V_M1_MF2_MASK }, // 709
  { 0x4, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG4EI64_V_M2_MF2_MASK }, // 710
  { 0x4, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG4EI64_V_M4_MF2_MASK }, // 711
  { 0x5, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG5EI8_V_M1_M1 }, // 712
  { 0x5, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG5EI8_V_MF8_M1 }, // 713
  { 0x5, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG5EI8_V_MF4_M1 }, // 714
  { 0x5, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG5EI8_V_MF2_M1 }, // 715
  { 0x5, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG5EI8_V_MF8_MF8 }, // 716
  { 0x5, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG5EI8_V_MF8_MF4 }, // 717
  { 0x5, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG5EI8_V_MF4_MF4 }, // 718
  { 0x5, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG5EI8_V_MF8_MF2 }, // 719
  { 0x5, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG5EI8_V_MF4_MF2 }, // 720
  { 0x5, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG5EI8_V_MF2_MF2 }, // 721
  { 0x5, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG5EI16_V_M1_M1 }, // 722
  { 0x5, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG5EI16_V_M2_M1 }, // 723
  { 0x5, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG5EI16_V_MF4_M1 }, // 724
  { 0x5, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG5EI16_V_MF2_M1 }, // 725
  { 0x5, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG5EI16_V_MF4_MF8 }, // 726
  { 0x5, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG5EI16_V_MF4_MF4 }, // 727
  { 0x5, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG5EI16_V_MF2_MF4 }, // 728
  { 0x5, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG5EI16_V_M1_MF2 }, // 729
  { 0x5, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG5EI16_V_MF4_MF2 }, // 730
  { 0x5, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG5EI16_V_MF2_MF2 }, // 731
  { 0x5, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG5EI32_V_M1_M1 }, // 732
  { 0x5, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG5EI32_V_M2_M1 }, // 733
  { 0x5, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG5EI32_V_M4_M1 }, // 734
  { 0x5, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG5EI32_V_MF2_M1 }, // 735
  { 0x5, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG5EI32_V_MF2_MF8 }, // 736
  { 0x5, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG5EI32_V_M1_MF4 }, // 737
  { 0x5, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG5EI32_V_MF2_MF4 }, // 738
  { 0x5, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG5EI32_V_M1_MF2 }, // 739
  { 0x5, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG5EI32_V_M2_MF2 }, // 740
  { 0x5, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG5EI32_V_MF2_MF2 }, // 741
  { 0x5, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG5EI64_V_M1_M1 }, // 742
  { 0x5, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG5EI64_V_M2_M1 }, // 743
  { 0x5, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG5EI64_V_M4_M1 }, // 744
  { 0x5, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG5EI64_V_M8_M1 }, // 745
  { 0x5, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG5EI64_V_M1_MF8 }, // 746
  { 0x5, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG5EI64_V_M1_MF4 }, // 747
  { 0x5, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG5EI64_V_M2_MF4 }, // 748
  { 0x5, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG5EI64_V_M1_MF2 }, // 749
  { 0x5, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG5EI64_V_M2_MF2 }, // 750
  { 0x5, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG5EI64_V_M4_MF2 }, // 751
  { 0x5, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG5EI8_V_M1_M1 }, // 752
  { 0x5, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG5EI8_V_MF8_M1 }, // 753
  { 0x5, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG5EI8_V_MF4_M1 }, // 754
  { 0x5, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG5EI8_V_MF2_M1 }, // 755
  { 0x5, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG5EI8_V_MF8_MF8 }, // 756
  { 0x5, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG5EI8_V_MF8_MF4 }, // 757
  { 0x5, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG5EI8_V_MF4_MF4 }, // 758
  { 0x5, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG5EI8_V_MF8_MF2 }, // 759
  { 0x5, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG5EI8_V_MF4_MF2 }, // 760
  { 0x5, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG5EI8_V_MF2_MF2 }, // 761
  { 0x5, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG5EI16_V_M1_M1 }, // 762
  { 0x5, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG5EI16_V_M2_M1 }, // 763
  { 0x5, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG5EI16_V_MF4_M1 }, // 764
  { 0x5, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG5EI16_V_MF2_M1 }, // 765
  { 0x5, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG5EI16_V_MF4_MF8 }, // 766
  { 0x5, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG5EI16_V_MF4_MF4 }, // 767
  { 0x5, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG5EI16_V_MF2_MF4 }, // 768
  { 0x5, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG5EI16_V_M1_MF2 }, // 769
  { 0x5, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG5EI16_V_MF4_MF2 }, // 770
  { 0x5, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG5EI16_V_MF2_MF2 }, // 771
  { 0x5, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG5EI32_V_M1_M1 }, // 772
  { 0x5, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG5EI32_V_M2_M1 }, // 773
  { 0x5, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG5EI32_V_M4_M1 }, // 774
  { 0x5, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG5EI32_V_MF2_M1 }, // 775
  { 0x5, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG5EI32_V_MF2_MF8 }, // 776
  { 0x5, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG5EI32_V_M1_MF4 }, // 777
  { 0x5, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG5EI32_V_MF2_MF4 }, // 778
  { 0x5, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG5EI32_V_M1_MF2 }, // 779
  { 0x5, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG5EI32_V_M2_MF2 }, // 780
  { 0x5, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG5EI32_V_MF2_MF2 }, // 781
  { 0x5, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG5EI64_V_M1_M1 }, // 782
  { 0x5, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG5EI64_V_M2_M1 }, // 783
  { 0x5, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG5EI64_V_M4_M1 }, // 784
  { 0x5, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG5EI64_V_M8_M1 }, // 785
  { 0x5, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG5EI64_V_M1_MF8 }, // 786
  { 0x5, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG5EI64_V_M1_MF4 }, // 787
  { 0x5, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG5EI64_V_M2_MF4 }, // 788
  { 0x5, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG5EI64_V_M1_MF2 }, // 789
  { 0x5, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG5EI64_V_M2_MF2 }, // 790
  { 0x5, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG5EI64_V_M4_MF2 }, // 791
  { 0x5, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG5EI8_V_M1_M1_MASK }, // 792
  { 0x5, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG5EI8_V_MF8_M1_MASK }, // 793
  { 0x5, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG5EI8_V_MF4_M1_MASK }, // 794
  { 0x5, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG5EI8_V_MF2_M1_MASK }, // 795
  { 0x5, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG5EI8_V_MF8_MF8_MASK }, // 796
  { 0x5, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG5EI8_V_MF8_MF4_MASK }, // 797
  { 0x5, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG5EI8_V_MF4_MF4_MASK }, // 798
  { 0x5, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG5EI8_V_MF8_MF2_MASK }, // 799
  { 0x5, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG5EI8_V_MF4_MF2_MASK }, // 800
  { 0x5, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG5EI8_V_MF2_MF2_MASK }, // 801
  { 0x5, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG5EI16_V_M1_M1_MASK }, // 802
  { 0x5, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG5EI16_V_M2_M1_MASK }, // 803
  { 0x5, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG5EI16_V_MF4_M1_MASK }, // 804
  { 0x5, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG5EI16_V_MF2_M1_MASK }, // 805
  { 0x5, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG5EI16_V_MF4_MF8_MASK }, // 806
  { 0x5, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG5EI16_V_MF4_MF4_MASK }, // 807
  { 0x5, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG5EI16_V_MF2_MF4_MASK }, // 808
  { 0x5, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG5EI16_V_M1_MF2_MASK }, // 809
  { 0x5, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG5EI16_V_MF4_MF2_MASK }, // 810
  { 0x5, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG5EI16_V_MF2_MF2_MASK }, // 811
  { 0x5, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG5EI32_V_M1_M1_MASK }, // 812
  { 0x5, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG5EI32_V_M2_M1_MASK }, // 813
  { 0x5, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG5EI32_V_M4_M1_MASK }, // 814
  { 0x5, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG5EI32_V_MF2_M1_MASK }, // 815
  { 0x5, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG5EI32_V_MF2_MF8_MASK }, // 816
  { 0x5, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG5EI32_V_M1_MF4_MASK }, // 817
  { 0x5, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG5EI32_V_MF2_MF4_MASK }, // 818
  { 0x5, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG5EI32_V_M1_MF2_MASK }, // 819
  { 0x5, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG5EI32_V_M2_MF2_MASK }, // 820
  { 0x5, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG5EI32_V_MF2_MF2_MASK }, // 821
  { 0x5, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG5EI64_V_M1_M1_MASK }, // 822
  { 0x5, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG5EI64_V_M2_M1_MASK }, // 823
  { 0x5, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG5EI64_V_M4_M1_MASK }, // 824
  { 0x5, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG5EI64_V_M8_M1_MASK }, // 825
  { 0x5, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG5EI64_V_M1_MF8_MASK }, // 826
  { 0x5, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG5EI64_V_M1_MF4_MASK }, // 827
  { 0x5, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG5EI64_V_M2_MF4_MASK }, // 828
  { 0x5, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG5EI64_V_M1_MF2_MASK }, // 829
  { 0x5, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG5EI64_V_M2_MF2_MASK }, // 830
  { 0x5, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG5EI64_V_M4_MF2_MASK }, // 831
  { 0x5, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG5EI8_V_M1_M1_MASK }, // 832
  { 0x5, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG5EI8_V_MF8_M1_MASK }, // 833
  { 0x5, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG5EI8_V_MF4_M1_MASK }, // 834
  { 0x5, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG5EI8_V_MF2_M1_MASK }, // 835
  { 0x5, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG5EI8_V_MF8_MF8_MASK }, // 836
  { 0x5, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG5EI8_V_MF8_MF4_MASK }, // 837
  { 0x5, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG5EI8_V_MF4_MF4_MASK }, // 838
  { 0x5, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG5EI8_V_MF8_MF2_MASK }, // 839
  { 0x5, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG5EI8_V_MF4_MF2_MASK }, // 840
  { 0x5, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG5EI8_V_MF2_MF2_MASK }, // 841
  { 0x5, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG5EI16_V_M1_M1_MASK }, // 842
  { 0x5, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG5EI16_V_M2_M1_MASK }, // 843
  { 0x5, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG5EI16_V_MF4_M1_MASK }, // 844
  { 0x5, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG5EI16_V_MF2_M1_MASK }, // 845
  { 0x5, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG5EI16_V_MF4_MF8_MASK }, // 846
  { 0x5, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG5EI16_V_MF4_MF4_MASK }, // 847
  { 0x5, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG5EI16_V_MF2_MF4_MASK }, // 848
  { 0x5, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG5EI16_V_M1_MF2_MASK }, // 849
  { 0x5, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG5EI16_V_MF4_MF2_MASK }, // 850
  { 0x5, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG5EI16_V_MF2_MF2_MASK }, // 851
  { 0x5, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG5EI32_V_M1_M1_MASK }, // 852
  { 0x5, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG5EI32_V_M2_M1_MASK }, // 853
  { 0x5, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG5EI32_V_M4_M1_MASK }, // 854
  { 0x5, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG5EI32_V_MF2_M1_MASK }, // 855
  { 0x5, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG5EI32_V_MF2_MF8_MASK }, // 856
  { 0x5, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG5EI32_V_M1_MF4_MASK }, // 857
  { 0x5, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG5EI32_V_MF2_MF4_MASK }, // 858
  { 0x5, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG5EI32_V_M1_MF2_MASK }, // 859
  { 0x5, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG5EI32_V_M2_MF2_MASK }, // 860
  { 0x5, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG5EI32_V_MF2_MF2_MASK }, // 861
  { 0x5, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG5EI64_V_M1_M1_MASK }, // 862
  { 0x5, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG5EI64_V_M2_M1_MASK }, // 863
  { 0x5, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG5EI64_V_M4_M1_MASK }, // 864
  { 0x5, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG5EI64_V_M8_M1_MASK }, // 865
  { 0x5, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG5EI64_V_M1_MF8_MASK }, // 866
  { 0x5, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG5EI64_V_M1_MF4_MASK }, // 867
  { 0x5, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG5EI64_V_M2_MF4_MASK }, // 868
  { 0x5, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG5EI64_V_M1_MF2_MASK }, // 869
  { 0x5, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG5EI64_V_M2_MF2_MASK }, // 870
  { 0x5, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG5EI64_V_M4_MF2_MASK }, // 871
  { 0x6, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG6EI8_V_M1_M1 }, // 872
  { 0x6, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG6EI8_V_MF8_M1 }, // 873
  { 0x6, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG6EI8_V_MF4_M1 }, // 874
  { 0x6, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG6EI8_V_MF2_M1 }, // 875
  { 0x6, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG6EI8_V_MF8_MF8 }, // 876
  { 0x6, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG6EI8_V_MF8_MF4 }, // 877
  { 0x6, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG6EI8_V_MF4_MF4 }, // 878
  { 0x6, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG6EI8_V_MF8_MF2 }, // 879
  { 0x6, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG6EI8_V_MF4_MF2 }, // 880
  { 0x6, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG6EI8_V_MF2_MF2 }, // 881
  { 0x6, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG6EI16_V_M1_M1 }, // 882
  { 0x6, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG6EI16_V_M2_M1 }, // 883
  { 0x6, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG6EI16_V_MF4_M1 }, // 884
  { 0x6, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG6EI16_V_MF2_M1 }, // 885
  { 0x6, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG6EI16_V_MF4_MF8 }, // 886
  { 0x6, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG6EI16_V_MF4_MF4 }, // 887
  { 0x6, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG6EI16_V_MF2_MF4 }, // 888
  { 0x6, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG6EI16_V_M1_MF2 }, // 889
  { 0x6, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG6EI16_V_MF4_MF2 }, // 890
  { 0x6, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG6EI16_V_MF2_MF2 }, // 891
  { 0x6, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG6EI32_V_M1_M1 }, // 892
  { 0x6, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG6EI32_V_M2_M1 }, // 893
  { 0x6, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG6EI32_V_M4_M1 }, // 894
  { 0x6, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG6EI32_V_MF2_M1 }, // 895
  { 0x6, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG6EI32_V_MF2_MF8 }, // 896
  { 0x6, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG6EI32_V_M1_MF4 }, // 897
  { 0x6, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG6EI32_V_MF2_MF4 }, // 898
  { 0x6, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG6EI32_V_M1_MF2 }, // 899
  { 0x6, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG6EI32_V_M2_MF2 }, // 900
  { 0x6, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG6EI32_V_MF2_MF2 }, // 901
  { 0x6, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG6EI64_V_M1_M1 }, // 902
  { 0x6, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG6EI64_V_M2_M1 }, // 903
  { 0x6, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG6EI64_V_M4_M1 }, // 904
  { 0x6, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG6EI64_V_M8_M1 }, // 905
  { 0x6, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG6EI64_V_M1_MF8 }, // 906
  { 0x6, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG6EI64_V_M1_MF4 }, // 907
  { 0x6, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG6EI64_V_M2_MF4 }, // 908
  { 0x6, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG6EI64_V_M1_MF2 }, // 909
  { 0x6, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG6EI64_V_M2_MF2 }, // 910
  { 0x6, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG6EI64_V_M4_MF2 }, // 911
  { 0x6, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG6EI8_V_M1_M1 }, // 912
  { 0x6, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG6EI8_V_MF8_M1 }, // 913
  { 0x6, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG6EI8_V_MF4_M1 }, // 914
  { 0x6, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG6EI8_V_MF2_M1 }, // 915
  { 0x6, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG6EI8_V_MF8_MF8 }, // 916
  { 0x6, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG6EI8_V_MF8_MF4 }, // 917
  { 0x6, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG6EI8_V_MF4_MF4 }, // 918
  { 0x6, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG6EI8_V_MF8_MF2 }, // 919
  { 0x6, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG6EI8_V_MF4_MF2 }, // 920
  { 0x6, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG6EI8_V_MF2_MF2 }, // 921
  { 0x6, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG6EI16_V_M1_M1 }, // 922
  { 0x6, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG6EI16_V_M2_M1 }, // 923
  { 0x6, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG6EI16_V_MF4_M1 }, // 924
  { 0x6, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG6EI16_V_MF2_M1 }, // 925
  { 0x6, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG6EI16_V_MF4_MF8 }, // 926
  { 0x6, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG6EI16_V_MF4_MF4 }, // 927
  { 0x6, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG6EI16_V_MF2_MF4 }, // 928
  { 0x6, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG6EI16_V_M1_MF2 }, // 929
  { 0x6, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG6EI16_V_MF4_MF2 }, // 930
  { 0x6, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG6EI16_V_MF2_MF2 }, // 931
  { 0x6, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG6EI32_V_M1_M1 }, // 932
  { 0x6, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG6EI32_V_M2_M1 }, // 933
  { 0x6, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG6EI32_V_M4_M1 }, // 934
  { 0x6, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG6EI32_V_MF2_M1 }, // 935
  { 0x6, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG6EI32_V_MF2_MF8 }, // 936
  { 0x6, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG6EI32_V_M1_MF4 }, // 937
  { 0x6, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG6EI32_V_MF2_MF4 }, // 938
  { 0x6, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG6EI32_V_M1_MF2 }, // 939
  { 0x6, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG6EI32_V_M2_MF2 }, // 940
  { 0x6, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG6EI32_V_MF2_MF2 }, // 941
  { 0x6, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG6EI64_V_M1_M1 }, // 942
  { 0x6, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG6EI64_V_M2_M1 }, // 943
  { 0x6, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG6EI64_V_M4_M1 }, // 944
  { 0x6, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG6EI64_V_M8_M1 }, // 945
  { 0x6, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG6EI64_V_M1_MF8 }, // 946
  { 0x6, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG6EI64_V_M1_MF4 }, // 947
  { 0x6, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG6EI64_V_M2_MF4 }, // 948
  { 0x6, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG6EI64_V_M1_MF2 }, // 949
  { 0x6, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG6EI64_V_M2_MF2 }, // 950
  { 0x6, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG6EI64_V_M4_MF2 }, // 951
  { 0x6, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG6EI8_V_M1_M1_MASK }, // 952
  { 0x6, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG6EI8_V_MF8_M1_MASK }, // 953
  { 0x6, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG6EI8_V_MF4_M1_MASK }, // 954
  { 0x6, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG6EI8_V_MF2_M1_MASK }, // 955
  { 0x6, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG6EI8_V_MF8_MF8_MASK }, // 956
  { 0x6, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG6EI8_V_MF8_MF4_MASK }, // 957
  { 0x6, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG6EI8_V_MF4_MF4_MASK }, // 958
  { 0x6, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG6EI8_V_MF8_MF2_MASK }, // 959
  { 0x6, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG6EI8_V_MF4_MF2_MASK }, // 960
  { 0x6, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG6EI8_V_MF2_MF2_MASK }, // 961
  { 0x6, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG6EI16_V_M1_M1_MASK }, // 962
  { 0x6, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG6EI16_V_M2_M1_MASK }, // 963
  { 0x6, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG6EI16_V_MF4_M1_MASK }, // 964
  { 0x6, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG6EI16_V_MF2_M1_MASK }, // 965
  { 0x6, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG6EI16_V_MF4_MF8_MASK }, // 966
  { 0x6, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG6EI16_V_MF4_MF4_MASK }, // 967
  { 0x6, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG6EI16_V_MF2_MF4_MASK }, // 968
  { 0x6, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG6EI16_V_M1_MF2_MASK }, // 969
  { 0x6, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG6EI16_V_MF4_MF2_MASK }, // 970
  { 0x6, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG6EI16_V_MF2_MF2_MASK }, // 971
  { 0x6, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG6EI32_V_M1_M1_MASK }, // 972
  { 0x6, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG6EI32_V_M2_M1_MASK }, // 973
  { 0x6, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG6EI32_V_M4_M1_MASK }, // 974
  { 0x6, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG6EI32_V_MF2_M1_MASK }, // 975
  { 0x6, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG6EI32_V_MF2_MF8_MASK }, // 976
  { 0x6, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG6EI32_V_M1_MF4_MASK }, // 977
  { 0x6, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG6EI32_V_MF2_MF4_MASK }, // 978
  { 0x6, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG6EI32_V_M1_MF2_MASK }, // 979
  { 0x6, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG6EI32_V_M2_MF2_MASK }, // 980
  { 0x6, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG6EI32_V_MF2_MF2_MASK }, // 981
  { 0x6, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG6EI64_V_M1_M1_MASK }, // 982
  { 0x6, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG6EI64_V_M2_M1_MASK }, // 983
  { 0x6, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG6EI64_V_M4_M1_MASK }, // 984
  { 0x6, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG6EI64_V_M8_M1_MASK }, // 985
  { 0x6, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG6EI64_V_M1_MF8_MASK }, // 986
  { 0x6, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG6EI64_V_M1_MF4_MASK }, // 987
  { 0x6, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG6EI64_V_M2_MF4_MASK }, // 988
  { 0x6, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG6EI64_V_M1_MF2_MASK }, // 989
  { 0x6, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG6EI64_V_M2_MF2_MASK }, // 990
  { 0x6, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG6EI64_V_M4_MF2_MASK }, // 991
  { 0x6, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG6EI8_V_M1_M1_MASK }, // 992
  { 0x6, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG6EI8_V_MF8_M1_MASK }, // 993
  { 0x6, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG6EI8_V_MF4_M1_MASK }, // 994
  { 0x6, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG6EI8_V_MF2_M1_MASK }, // 995
  { 0x6, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG6EI8_V_MF8_MF8_MASK }, // 996
  { 0x6, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG6EI8_V_MF8_MF4_MASK }, // 997
  { 0x6, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG6EI8_V_MF4_MF4_MASK }, // 998
  { 0x6, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG6EI8_V_MF8_MF2_MASK }, // 999
  { 0x6, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG6EI8_V_MF4_MF2_MASK }, // 1000
  { 0x6, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG6EI8_V_MF2_MF2_MASK }, // 1001
  { 0x6, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG6EI16_V_M1_M1_MASK }, // 1002
  { 0x6, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG6EI16_V_M2_M1_MASK }, // 1003
  { 0x6, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG6EI16_V_MF4_M1_MASK }, // 1004
  { 0x6, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG6EI16_V_MF2_M1_MASK }, // 1005
  { 0x6, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG6EI16_V_MF4_MF8_MASK }, // 1006
  { 0x6, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG6EI16_V_MF4_MF4_MASK }, // 1007
  { 0x6, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG6EI16_V_MF2_MF4_MASK }, // 1008
  { 0x6, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG6EI16_V_M1_MF2_MASK }, // 1009
  { 0x6, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG6EI16_V_MF4_MF2_MASK }, // 1010
  { 0x6, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG6EI16_V_MF2_MF2_MASK }, // 1011
  { 0x6, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG6EI32_V_M1_M1_MASK }, // 1012
  { 0x6, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG6EI32_V_M2_M1_MASK }, // 1013
  { 0x6, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG6EI32_V_M4_M1_MASK }, // 1014
  { 0x6, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG6EI32_V_MF2_M1_MASK }, // 1015
  { 0x6, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG6EI32_V_MF2_MF8_MASK }, // 1016
  { 0x6, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG6EI32_V_M1_MF4_MASK }, // 1017
  { 0x6, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG6EI32_V_MF2_MF4_MASK }, // 1018
  { 0x6, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG6EI32_V_M1_MF2_MASK }, // 1019
  { 0x6, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG6EI32_V_M2_MF2_MASK }, // 1020
  { 0x6, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG6EI32_V_MF2_MF2_MASK }, // 1021
  { 0x6, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG6EI64_V_M1_M1_MASK }, // 1022
  { 0x6, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG6EI64_V_M2_M1_MASK }, // 1023
  { 0x6, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG6EI64_V_M4_M1_MASK }, // 1024
  { 0x6, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG6EI64_V_M8_M1_MASK }, // 1025
  { 0x6, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG6EI64_V_M1_MF8_MASK }, // 1026
  { 0x6, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG6EI64_V_M1_MF4_MASK }, // 1027
  { 0x6, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG6EI64_V_M2_MF4_MASK }, // 1028
  { 0x6, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG6EI64_V_M1_MF2_MASK }, // 1029
  { 0x6, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG6EI64_V_M2_MF2_MASK }, // 1030
  { 0x6, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG6EI64_V_M4_MF2_MASK }, // 1031
  { 0x7, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG7EI8_V_M1_M1 }, // 1032
  { 0x7, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG7EI8_V_MF8_M1 }, // 1033
  { 0x7, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG7EI8_V_MF4_M1 }, // 1034
  { 0x7, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG7EI8_V_MF2_M1 }, // 1035
  { 0x7, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG7EI8_V_MF8_MF8 }, // 1036
  { 0x7, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG7EI8_V_MF8_MF4 }, // 1037
  { 0x7, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG7EI8_V_MF4_MF4 }, // 1038
  { 0x7, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG7EI8_V_MF8_MF2 }, // 1039
  { 0x7, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG7EI8_V_MF4_MF2 }, // 1040
  { 0x7, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG7EI8_V_MF2_MF2 }, // 1041
  { 0x7, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG7EI16_V_M1_M1 }, // 1042
  { 0x7, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG7EI16_V_M2_M1 }, // 1043
  { 0x7, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG7EI16_V_MF4_M1 }, // 1044
  { 0x7, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG7EI16_V_MF2_M1 }, // 1045
  { 0x7, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG7EI16_V_MF4_MF8 }, // 1046
  { 0x7, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG7EI16_V_MF4_MF4 }, // 1047
  { 0x7, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG7EI16_V_MF2_MF4 }, // 1048
  { 0x7, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG7EI16_V_M1_MF2 }, // 1049
  { 0x7, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG7EI16_V_MF4_MF2 }, // 1050
  { 0x7, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG7EI16_V_MF2_MF2 }, // 1051
  { 0x7, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG7EI32_V_M1_M1 }, // 1052
  { 0x7, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG7EI32_V_M2_M1 }, // 1053
  { 0x7, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG7EI32_V_M4_M1 }, // 1054
  { 0x7, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG7EI32_V_MF2_M1 }, // 1055
  { 0x7, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG7EI32_V_MF2_MF8 }, // 1056
  { 0x7, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG7EI32_V_M1_MF4 }, // 1057
  { 0x7, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG7EI32_V_MF2_MF4 }, // 1058
  { 0x7, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG7EI32_V_M1_MF2 }, // 1059
  { 0x7, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG7EI32_V_M2_MF2 }, // 1060
  { 0x7, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG7EI32_V_MF2_MF2 }, // 1061
  { 0x7, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG7EI64_V_M1_M1 }, // 1062
  { 0x7, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG7EI64_V_M2_M1 }, // 1063
  { 0x7, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG7EI64_V_M4_M1 }, // 1064
  { 0x7, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG7EI64_V_M8_M1 }, // 1065
  { 0x7, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG7EI64_V_M1_MF8 }, // 1066
  { 0x7, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG7EI64_V_M1_MF4 }, // 1067
  { 0x7, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG7EI64_V_M2_MF4 }, // 1068
  { 0x7, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG7EI64_V_M1_MF2 }, // 1069
  { 0x7, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG7EI64_V_M2_MF2 }, // 1070
  { 0x7, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG7EI64_V_M4_MF2 }, // 1071
  { 0x7, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG7EI8_V_M1_M1 }, // 1072
  { 0x7, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG7EI8_V_MF8_M1 }, // 1073
  { 0x7, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG7EI8_V_MF4_M1 }, // 1074
  { 0x7, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG7EI8_V_MF2_M1 }, // 1075
  { 0x7, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG7EI8_V_MF8_MF8 }, // 1076
  { 0x7, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG7EI8_V_MF8_MF4 }, // 1077
  { 0x7, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG7EI8_V_MF4_MF4 }, // 1078
  { 0x7, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG7EI8_V_MF8_MF2 }, // 1079
  { 0x7, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG7EI8_V_MF4_MF2 }, // 1080
  { 0x7, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG7EI8_V_MF2_MF2 }, // 1081
  { 0x7, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG7EI16_V_M1_M1 }, // 1082
  { 0x7, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG7EI16_V_M2_M1 }, // 1083
  { 0x7, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG7EI16_V_MF4_M1 }, // 1084
  { 0x7, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG7EI16_V_MF2_M1 }, // 1085
  { 0x7, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG7EI16_V_MF4_MF8 }, // 1086
  { 0x7, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG7EI16_V_MF4_MF4 }, // 1087
  { 0x7, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG7EI16_V_MF2_MF4 }, // 1088
  { 0x7, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG7EI16_V_M1_MF2 }, // 1089
  { 0x7, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG7EI16_V_MF4_MF2 }, // 1090
  { 0x7, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG7EI16_V_MF2_MF2 }, // 1091
  { 0x7, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG7EI32_V_M1_M1 }, // 1092
  { 0x7, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG7EI32_V_M2_M1 }, // 1093
  { 0x7, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG7EI32_V_M4_M1 }, // 1094
  { 0x7, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG7EI32_V_MF2_M1 }, // 1095
  { 0x7, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG7EI32_V_MF2_MF8 }, // 1096
  { 0x7, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG7EI32_V_M1_MF4 }, // 1097
  { 0x7, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG7EI32_V_MF2_MF4 }, // 1098
  { 0x7, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG7EI32_V_M1_MF2 }, // 1099
  { 0x7, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG7EI32_V_M2_MF2 }, // 1100
  { 0x7, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG7EI32_V_MF2_MF2 }, // 1101
  { 0x7, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG7EI64_V_M1_M1 }, // 1102
  { 0x7, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG7EI64_V_M2_M1 }, // 1103
  { 0x7, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG7EI64_V_M4_M1 }, // 1104
  { 0x7, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG7EI64_V_M8_M1 }, // 1105
  { 0x7, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG7EI64_V_M1_MF8 }, // 1106
  { 0x7, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG7EI64_V_M1_MF4 }, // 1107
  { 0x7, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG7EI64_V_M2_MF4 }, // 1108
  { 0x7, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG7EI64_V_M1_MF2 }, // 1109
  { 0x7, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG7EI64_V_M2_MF2 }, // 1110
  { 0x7, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG7EI64_V_M4_MF2 }, // 1111
  { 0x7, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG7EI8_V_M1_M1_MASK }, // 1112
  { 0x7, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG7EI8_V_MF8_M1_MASK }, // 1113
  { 0x7, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG7EI8_V_MF4_M1_MASK }, // 1114
  { 0x7, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG7EI8_V_MF2_M1_MASK }, // 1115
  { 0x7, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG7EI8_V_MF8_MF8_MASK }, // 1116
  { 0x7, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG7EI8_V_MF8_MF4_MASK }, // 1117
  { 0x7, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG7EI8_V_MF4_MF4_MASK }, // 1118
  { 0x7, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG7EI8_V_MF8_MF2_MASK }, // 1119
  { 0x7, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG7EI8_V_MF4_MF2_MASK }, // 1120
  { 0x7, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG7EI8_V_MF2_MF2_MASK }, // 1121
  { 0x7, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG7EI16_V_M1_M1_MASK }, // 1122
  { 0x7, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG7EI16_V_M2_M1_MASK }, // 1123
  { 0x7, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG7EI16_V_MF4_M1_MASK }, // 1124
  { 0x7, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG7EI16_V_MF2_M1_MASK }, // 1125
  { 0x7, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG7EI16_V_MF4_MF8_MASK }, // 1126
  { 0x7, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG7EI16_V_MF4_MF4_MASK }, // 1127
  { 0x7, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG7EI16_V_MF2_MF4_MASK }, // 1128
  { 0x7, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG7EI16_V_M1_MF2_MASK }, // 1129
  { 0x7, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG7EI16_V_MF4_MF2_MASK }, // 1130
  { 0x7, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG7EI16_V_MF2_MF2_MASK }, // 1131
  { 0x7, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG7EI32_V_M1_M1_MASK }, // 1132
  { 0x7, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG7EI32_V_M2_M1_MASK }, // 1133
  { 0x7, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG7EI32_V_M4_M1_MASK }, // 1134
  { 0x7, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG7EI32_V_MF2_M1_MASK }, // 1135
  { 0x7, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG7EI32_V_MF2_MF8_MASK }, // 1136
  { 0x7, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG7EI32_V_M1_MF4_MASK }, // 1137
  { 0x7, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG7EI32_V_MF2_MF4_MASK }, // 1138
  { 0x7, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG7EI32_V_M1_MF2_MASK }, // 1139
  { 0x7, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG7EI32_V_M2_MF2_MASK }, // 1140
  { 0x7, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG7EI32_V_MF2_MF2_MASK }, // 1141
  { 0x7, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG7EI64_V_M1_M1_MASK }, // 1142
  { 0x7, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG7EI64_V_M2_M1_MASK }, // 1143
  { 0x7, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG7EI64_V_M4_M1_MASK }, // 1144
  { 0x7, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG7EI64_V_M8_M1_MASK }, // 1145
  { 0x7, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG7EI64_V_M1_MF8_MASK }, // 1146
  { 0x7, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG7EI64_V_M1_MF4_MASK }, // 1147
  { 0x7, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG7EI64_V_M2_MF4_MASK }, // 1148
  { 0x7, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG7EI64_V_M1_MF2_MASK }, // 1149
  { 0x7, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG7EI64_V_M2_MF2_MASK }, // 1150
  { 0x7, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG7EI64_V_M4_MF2_MASK }, // 1151
  { 0x7, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG7EI8_V_M1_M1_MASK }, // 1152
  { 0x7, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG7EI8_V_MF8_M1_MASK }, // 1153
  { 0x7, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG7EI8_V_MF4_M1_MASK }, // 1154
  { 0x7, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG7EI8_V_MF2_M1_MASK }, // 1155
  { 0x7, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG7EI8_V_MF8_MF8_MASK }, // 1156
  { 0x7, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG7EI8_V_MF8_MF4_MASK }, // 1157
  { 0x7, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG7EI8_V_MF4_MF4_MASK }, // 1158
  { 0x7, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG7EI8_V_MF8_MF2_MASK }, // 1159
  { 0x7, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG7EI8_V_MF4_MF2_MASK }, // 1160
  { 0x7, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG7EI8_V_MF2_MF2_MASK }, // 1161
  { 0x7, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG7EI16_V_M1_M1_MASK }, // 1162
  { 0x7, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG7EI16_V_M2_M1_MASK }, // 1163
  { 0x7, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG7EI16_V_MF4_M1_MASK }, // 1164
  { 0x7, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG7EI16_V_MF2_M1_MASK }, // 1165
  { 0x7, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG7EI16_V_MF4_MF8_MASK }, // 1166
  { 0x7, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG7EI16_V_MF4_MF4_MASK }, // 1167
  { 0x7, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG7EI16_V_MF2_MF4_MASK }, // 1168
  { 0x7, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG7EI16_V_M1_MF2_MASK }, // 1169
  { 0x7, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG7EI16_V_MF4_MF2_MASK }, // 1170
  { 0x7, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG7EI16_V_MF2_MF2_MASK }, // 1171
  { 0x7, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG7EI32_V_M1_M1_MASK }, // 1172
  { 0x7, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG7EI32_V_M2_M1_MASK }, // 1173
  { 0x7, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG7EI32_V_M4_M1_MASK }, // 1174
  { 0x7, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG7EI32_V_MF2_M1_MASK }, // 1175
  { 0x7, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG7EI32_V_MF2_MF8_MASK }, // 1176
  { 0x7, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG7EI32_V_M1_MF4_MASK }, // 1177
  { 0x7, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG7EI32_V_MF2_MF4_MASK }, // 1178
  { 0x7, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG7EI32_V_M1_MF2_MASK }, // 1179
  { 0x7, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG7EI32_V_M2_MF2_MASK }, // 1180
  { 0x7, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG7EI32_V_MF2_MF2_MASK }, // 1181
  { 0x7, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG7EI64_V_M1_M1_MASK }, // 1182
  { 0x7, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG7EI64_V_M2_M1_MASK }, // 1183
  { 0x7, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG7EI64_V_M4_M1_MASK }, // 1184
  { 0x7, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG7EI64_V_M8_M1_MASK }, // 1185
  { 0x7, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG7EI64_V_M1_MF8_MASK }, // 1186
  { 0x7, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG7EI64_V_M1_MF4_MASK }, // 1187
  { 0x7, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG7EI64_V_M2_MF4_MASK }, // 1188
  { 0x7, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG7EI64_V_M1_MF2_MASK }, // 1189
  { 0x7, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG7EI64_V_M2_MF2_MASK }, // 1190
  { 0x7, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG7EI64_V_M4_MF2_MASK }, // 1191
  { 0x8, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG8EI8_V_M1_M1 }, // 1192
  { 0x8, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG8EI8_V_MF8_M1 }, // 1193
  { 0x8, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG8EI8_V_MF4_M1 }, // 1194
  { 0x8, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG8EI8_V_MF2_M1 }, // 1195
  { 0x8, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG8EI8_V_MF8_MF8 }, // 1196
  { 0x8, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG8EI8_V_MF8_MF4 }, // 1197
  { 0x8, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG8EI8_V_MF4_MF4 }, // 1198
  { 0x8, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG8EI8_V_MF8_MF2 }, // 1199
  { 0x8, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG8EI8_V_MF4_MF2 }, // 1200
  { 0x8, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG8EI8_V_MF2_MF2 }, // 1201
  { 0x8, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG8EI16_V_M1_M1 }, // 1202
  { 0x8, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG8EI16_V_M2_M1 }, // 1203
  { 0x8, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG8EI16_V_MF4_M1 }, // 1204
  { 0x8, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG8EI16_V_MF2_M1 }, // 1205
  { 0x8, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG8EI16_V_MF4_MF8 }, // 1206
  { 0x8, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG8EI16_V_MF4_MF4 }, // 1207
  { 0x8, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG8EI16_V_MF2_MF4 }, // 1208
  { 0x8, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG8EI16_V_M1_MF2 }, // 1209
  { 0x8, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG8EI16_V_MF4_MF2 }, // 1210
  { 0x8, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG8EI16_V_MF2_MF2 }, // 1211
  { 0x8, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG8EI32_V_M1_M1 }, // 1212
  { 0x8, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG8EI32_V_M2_M1 }, // 1213
  { 0x8, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG8EI32_V_M4_M1 }, // 1214
  { 0x8, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG8EI32_V_MF2_M1 }, // 1215
  { 0x8, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG8EI32_V_MF2_MF8 }, // 1216
  { 0x8, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG8EI32_V_M1_MF4 }, // 1217
  { 0x8, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG8EI32_V_MF2_MF4 }, // 1218
  { 0x8, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG8EI32_V_M1_MF2 }, // 1219
  { 0x8, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG8EI32_V_M2_MF2 }, // 1220
  { 0x8, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG8EI32_V_MF2_MF2 }, // 1221
  { 0x8, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG8EI64_V_M1_M1 }, // 1222
  { 0x8, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG8EI64_V_M2_M1 }, // 1223
  { 0x8, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG8EI64_V_M4_M1 }, // 1224
  { 0x8, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG8EI64_V_M8_M1 }, // 1225
  { 0x8, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG8EI64_V_M1_MF8 }, // 1226
  { 0x8, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG8EI64_V_M1_MF4 }, // 1227
  { 0x8, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG8EI64_V_M2_MF4 }, // 1228
  { 0x8, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG8EI64_V_M1_MF2 }, // 1229
  { 0x8, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG8EI64_V_M2_MF2 }, // 1230
  { 0x8, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG8EI64_V_M4_MF2 }, // 1231
  { 0x8, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG8EI8_V_M1_M1 }, // 1232
  { 0x8, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG8EI8_V_MF8_M1 }, // 1233
  { 0x8, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG8EI8_V_MF4_M1 }, // 1234
  { 0x8, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG8EI8_V_MF2_M1 }, // 1235
  { 0x8, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG8EI8_V_MF8_MF8 }, // 1236
  { 0x8, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG8EI8_V_MF8_MF4 }, // 1237
  { 0x8, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG8EI8_V_MF4_MF4 }, // 1238
  { 0x8, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG8EI8_V_MF8_MF2 }, // 1239
  { 0x8, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG8EI8_V_MF4_MF2 }, // 1240
  { 0x8, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG8EI8_V_MF2_MF2 }, // 1241
  { 0x8, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG8EI16_V_M1_M1 }, // 1242
  { 0x8, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG8EI16_V_M2_M1 }, // 1243
  { 0x8, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG8EI16_V_MF4_M1 }, // 1244
  { 0x8, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG8EI16_V_MF2_M1 }, // 1245
  { 0x8, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG8EI16_V_MF4_MF8 }, // 1246
  { 0x8, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG8EI16_V_MF4_MF4 }, // 1247
  { 0x8, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG8EI16_V_MF2_MF4 }, // 1248
  { 0x8, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG8EI16_V_M1_MF2 }, // 1249
  { 0x8, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG8EI16_V_MF4_MF2 }, // 1250
  { 0x8, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG8EI16_V_MF2_MF2 }, // 1251
  { 0x8, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG8EI32_V_M1_M1 }, // 1252
  { 0x8, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG8EI32_V_M2_M1 }, // 1253
  { 0x8, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG8EI32_V_M4_M1 }, // 1254
  { 0x8, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG8EI32_V_MF2_M1 }, // 1255
  { 0x8, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG8EI32_V_MF2_MF8 }, // 1256
  { 0x8, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG8EI32_V_M1_MF4 }, // 1257
  { 0x8, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG8EI32_V_MF2_MF4 }, // 1258
  { 0x8, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG8EI32_V_M1_MF2 }, // 1259
  { 0x8, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG8EI32_V_M2_MF2 }, // 1260
  { 0x8, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG8EI32_V_MF2_MF2 }, // 1261
  { 0x8, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG8EI64_V_M1_M1 }, // 1262
  { 0x8, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG8EI64_V_M2_M1 }, // 1263
  { 0x8, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG8EI64_V_M4_M1 }, // 1264
  { 0x8, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG8EI64_V_M8_M1 }, // 1265
  { 0x8, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG8EI64_V_M1_MF8 }, // 1266
  { 0x8, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG8EI64_V_M1_MF4 }, // 1267
  { 0x8, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG8EI64_V_M2_MF4 }, // 1268
  { 0x8, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG8EI64_V_M1_MF2 }, // 1269
  { 0x8, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG8EI64_V_M2_MF2 }, // 1270
  { 0x8, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG8EI64_V_M4_MF2 }, // 1271
  { 0x8, 0x1, 0x0, 0x3, 0x0, 0x0, PseudoVSUXSEG8EI8_V_M1_M1_MASK }, // 1272
  { 0x8, 0x1, 0x0, 0x3, 0x0, 0x5, PseudoVSUXSEG8EI8_V_MF8_M1_MASK }, // 1273
  { 0x8, 0x1, 0x0, 0x3, 0x0, 0x6, PseudoVSUXSEG8EI8_V_MF4_M1_MASK }, // 1274
  { 0x8, 0x1, 0x0, 0x3, 0x0, 0x7, PseudoVSUXSEG8EI8_V_MF2_M1_MASK }, // 1275
  { 0x8, 0x1, 0x0, 0x3, 0x5, 0x5, PseudoVSUXSEG8EI8_V_MF8_MF8_MASK }, // 1276
  { 0x8, 0x1, 0x0, 0x3, 0x6, 0x5, PseudoVSUXSEG8EI8_V_MF8_MF4_MASK }, // 1277
  { 0x8, 0x1, 0x0, 0x3, 0x6, 0x6, PseudoVSUXSEG8EI8_V_MF4_MF4_MASK }, // 1278
  { 0x8, 0x1, 0x0, 0x3, 0x7, 0x5, PseudoVSUXSEG8EI8_V_MF8_MF2_MASK }, // 1279
  { 0x8, 0x1, 0x0, 0x3, 0x7, 0x6, PseudoVSUXSEG8EI8_V_MF4_MF2_MASK }, // 1280
  { 0x8, 0x1, 0x0, 0x3, 0x7, 0x7, PseudoVSUXSEG8EI8_V_MF2_MF2_MASK }, // 1281
  { 0x8, 0x1, 0x0, 0x4, 0x0, 0x0, PseudoVSUXSEG8EI16_V_M1_M1_MASK }, // 1282
  { 0x8, 0x1, 0x0, 0x4, 0x0, 0x1, PseudoVSUXSEG8EI16_V_M2_M1_MASK }, // 1283
  { 0x8, 0x1, 0x0, 0x4, 0x0, 0x6, PseudoVSUXSEG8EI16_V_MF4_M1_MASK }, // 1284
  { 0x8, 0x1, 0x0, 0x4, 0x0, 0x7, PseudoVSUXSEG8EI16_V_MF2_M1_MASK }, // 1285
  { 0x8, 0x1, 0x0, 0x4, 0x5, 0x6, PseudoVSUXSEG8EI16_V_MF4_MF8_MASK }, // 1286
  { 0x8, 0x1, 0x0, 0x4, 0x6, 0x6, PseudoVSUXSEG8EI16_V_MF4_MF4_MASK }, // 1287
  { 0x8, 0x1, 0x0, 0x4, 0x6, 0x7, PseudoVSUXSEG8EI16_V_MF2_MF4_MASK }, // 1288
  { 0x8, 0x1, 0x0, 0x4, 0x7, 0x0, PseudoVSUXSEG8EI16_V_M1_MF2_MASK }, // 1289
  { 0x8, 0x1, 0x0, 0x4, 0x7, 0x6, PseudoVSUXSEG8EI16_V_MF4_MF2_MASK }, // 1290
  { 0x8, 0x1, 0x0, 0x4, 0x7, 0x7, PseudoVSUXSEG8EI16_V_MF2_MF2_MASK }, // 1291
  { 0x8, 0x1, 0x0, 0x5, 0x0, 0x0, PseudoVSUXSEG8EI32_V_M1_M1_MASK }, // 1292
  { 0x8, 0x1, 0x0, 0x5, 0x0, 0x1, PseudoVSUXSEG8EI32_V_M2_M1_MASK }, // 1293
  { 0x8, 0x1, 0x0, 0x5, 0x0, 0x2, PseudoVSUXSEG8EI32_V_M4_M1_MASK }, // 1294
  { 0x8, 0x1, 0x0, 0x5, 0x0, 0x7, PseudoVSUXSEG8EI32_V_MF2_M1_MASK }, // 1295
  { 0x8, 0x1, 0x0, 0x5, 0x5, 0x7, PseudoVSUXSEG8EI32_V_MF2_MF8_MASK }, // 1296
  { 0x8, 0x1, 0x0, 0x5, 0x6, 0x0, PseudoVSUXSEG8EI32_V_M1_MF4_MASK }, // 1297
  { 0x8, 0x1, 0x0, 0x5, 0x6, 0x7, PseudoVSUXSEG8EI32_V_MF2_MF4_MASK }, // 1298
  { 0x8, 0x1, 0x0, 0x5, 0x7, 0x0, PseudoVSUXSEG8EI32_V_M1_MF2_MASK }, // 1299
  { 0x8, 0x1, 0x0, 0x5, 0x7, 0x1, PseudoVSUXSEG8EI32_V_M2_MF2_MASK }, // 1300
  { 0x8, 0x1, 0x0, 0x5, 0x7, 0x7, PseudoVSUXSEG8EI32_V_MF2_MF2_MASK }, // 1301
  { 0x8, 0x1, 0x0, 0x6, 0x0, 0x0, PseudoVSUXSEG8EI64_V_M1_M1_MASK }, // 1302
  { 0x8, 0x1, 0x0, 0x6, 0x0, 0x1, PseudoVSUXSEG8EI64_V_M2_M1_MASK }, // 1303
  { 0x8, 0x1, 0x0, 0x6, 0x0, 0x2, PseudoVSUXSEG8EI64_V_M4_M1_MASK }, // 1304
  { 0x8, 0x1, 0x0, 0x6, 0x0, 0x3, PseudoVSUXSEG8EI64_V_M8_M1_MASK }, // 1305
  { 0x8, 0x1, 0x0, 0x6, 0x5, 0x0, PseudoVSUXSEG8EI64_V_M1_MF8_MASK }, // 1306
  { 0x8, 0x1, 0x0, 0x6, 0x6, 0x0, PseudoVSUXSEG8EI64_V_M1_MF4_MASK }, // 1307
  { 0x8, 0x1, 0x0, 0x6, 0x6, 0x1, PseudoVSUXSEG8EI64_V_M2_MF4_MASK }, // 1308
  { 0x8, 0x1, 0x0, 0x6, 0x7, 0x0, PseudoVSUXSEG8EI64_V_M1_MF2_MASK }, // 1309
  { 0x8, 0x1, 0x0, 0x6, 0x7, 0x1, PseudoVSUXSEG8EI64_V_M2_MF2_MASK }, // 1310
  { 0x8, 0x1, 0x0, 0x6, 0x7, 0x2, PseudoVSUXSEG8EI64_V_M4_MF2_MASK }, // 1311
  { 0x8, 0x1, 0x1, 0x3, 0x0, 0x0, PseudoVSOXSEG8EI8_V_M1_M1_MASK }, // 1312
  { 0x8, 0x1, 0x1, 0x3, 0x0, 0x5, PseudoVSOXSEG8EI8_V_MF8_M1_MASK }, // 1313
  { 0x8, 0x1, 0x1, 0x3, 0x0, 0x6, PseudoVSOXSEG8EI8_V_MF4_M1_MASK }, // 1314
  { 0x8, 0x1, 0x1, 0x3, 0x0, 0x7, PseudoVSOXSEG8EI8_V_MF2_M1_MASK }, // 1315
  { 0x8, 0x1, 0x1, 0x3, 0x5, 0x5, PseudoVSOXSEG8EI8_V_MF8_MF8_MASK }, // 1316
  { 0x8, 0x1, 0x1, 0x3, 0x6, 0x5, PseudoVSOXSEG8EI8_V_MF8_MF4_MASK }, // 1317
  { 0x8, 0x1, 0x1, 0x3, 0x6, 0x6, PseudoVSOXSEG8EI8_V_MF4_MF4_MASK }, // 1318
  { 0x8, 0x1, 0x1, 0x3, 0x7, 0x5, PseudoVSOXSEG8EI8_V_MF8_MF2_MASK }, // 1319
  { 0x8, 0x1, 0x1, 0x3, 0x7, 0x6, PseudoVSOXSEG8EI8_V_MF4_MF2_MASK }, // 1320
  { 0x8, 0x1, 0x1, 0x3, 0x7, 0x7, PseudoVSOXSEG8EI8_V_MF2_MF2_MASK }, // 1321
  { 0x8, 0x1, 0x1, 0x4, 0x0, 0x0, PseudoVSOXSEG8EI16_V_M1_M1_MASK }, // 1322
  { 0x8, 0x1, 0x1, 0x4, 0x0, 0x1, PseudoVSOXSEG8EI16_V_M2_M1_MASK }, // 1323
  { 0x8, 0x1, 0x1, 0x4, 0x0, 0x6, PseudoVSOXSEG8EI16_V_MF4_M1_MASK }, // 1324
  { 0x8, 0x1, 0x1, 0x4, 0x0, 0x7, PseudoVSOXSEG8EI16_V_MF2_M1_MASK }, // 1325
  { 0x8, 0x1, 0x1, 0x4, 0x5, 0x6, PseudoVSOXSEG8EI16_V_MF4_MF8_MASK }, // 1326
  { 0x8, 0x1, 0x1, 0x4, 0x6, 0x6, PseudoVSOXSEG8EI16_V_MF4_MF4_MASK }, // 1327
  { 0x8, 0x1, 0x1, 0x4, 0x6, 0x7, PseudoVSOXSEG8EI16_V_MF2_MF4_MASK }, // 1328
  { 0x8, 0x1, 0x1, 0x4, 0x7, 0x0, PseudoVSOXSEG8EI16_V_M1_MF2_MASK }, // 1329
  { 0x8, 0x1, 0x1, 0x4, 0x7, 0x6, PseudoVSOXSEG8EI16_V_MF4_MF2_MASK }, // 1330
  { 0x8, 0x1, 0x1, 0x4, 0x7, 0x7, PseudoVSOXSEG8EI16_V_MF2_MF2_MASK }, // 1331
  { 0x8, 0x1, 0x1, 0x5, 0x0, 0x0, PseudoVSOXSEG8EI32_V_M1_M1_MASK }, // 1332
  { 0x8, 0x1, 0x1, 0x5, 0x0, 0x1, PseudoVSOXSEG8EI32_V_M2_M1_MASK }, // 1333
  { 0x8, 0x1, 0x1, 0x5, 0x0, 0x2, PseudoVSOXSEG8EI32_V_M4_M1_MASK }, // 1334
  { 0x8, 0x1, 0x1, 0x5, 0x0, 0x7, PseudoVSOXSEG8EI32_V_MF2_M1_MASK }, // 1335
  { 0x8, 0x1, 0x1, 0x5, 0x5, 0x7, PseudoVSOXSEG8EI32_V_MF2_MF8_MASK }, // 1336
  { 0x8, 0x1, 0x1, 0x5, 0x6, 0x0, PseudoVSOXSEG8EI32_V_M1_MF4_MASK }, // 1337
  { 0x8, 0x1, 0x1, 0x5, 0x6, 0x7, PseudoVSOXSEG8EI32_V_MF2_MF4_MASK }, // 1338
  { 0x8, 0x1, 0x1, 0x5, 0x7, 0x0, PseudoVSOXSEG8EI32_V_M1_MF2_MASK }, // 1339
  { 0x8, 0x1, 0x1, 0x5, 0x7, 0x1, PseudoVSOXSEG8EI32_V_M2_MF2_MASK }, // 1340
  { 0x8, 0x1, 0x1, 0x5, 0x7, 0x7, PseudoVSOXSEG8EI32_V_MF2_MF2_MASK }, // 1341
  { 0x8, 0x1, 0x1, 0x6, 0x0, 0x0, PseudoVSOXSEG8EI64_V_M1_M1_MASK }, // 1342
  { 0x8, 0x1, 0x1, 0x6, 0x0, 0x1, PseudoVSOXSEG8EI64_V_M2_M1_MASK }, // 1343
  { 0x8, 0x1, 0x1, 0x6, 0x0, 0x2, PseudoVSOXSEG8EI64_V_M4_M1_MASK }, // 1344
  { 0x8, 0x1, 0x1, 0x6, 0x0, 0x3, PseudoVSOXSEG8EI64_V_M8_M1_MASK }, // 1345
  { 0x8, 0x1, 0x1, 0x6, 0x5, 0x0, PseudoVSOXSEG8EI64_V_M1_MF8_MASK }, // 1346
  { 0x8, 0x1, 0x1, 0x6, 0x6, 0x0, PseudoVSOXSEG8EI64_V_M1_MF4_MASK }, // 1347
  { 0x8, 0x1, 0x1, 0x6, 0x6, 0x1, PseudoVSOXSEG8EI64_V_M2_MF4_MASK }, // 1348
  { 0x8, 0x1, 0x1, 0x6, 0x7, 0x0, PseudoVSOXSEG8EI64_V_M1_MF2_MASK }, // 1349
  { 0x8, 0x1, 0x1, 0x6, 0x7, 0x1, PseudoVSOXSEG8EI64_V_M2_MF2_MASK }, // 1350
  { 0x8, 0x1, 0x1, 0x6, 0x7, 0x2, PseudoVSOXSEG8EI64_V_M4_MF2_MASK }, // 1351
 };

const VSXSEGPseudo *getVSXSEGPseudo(uint8_t NF, uint8_t Masked, uint8_t Ordered, uint8_t Log2SEW, uint8_t LMUL, uint8_t IndexLMUL) {
  struct KeyType {
    uint8_t NF;
    uint8_t Masked;
    uint8_t Ordered;
    uint8_t Log2SEW;
    uint8_t LMUL;
    uint8_t IndexLMUL;
  };
  KeyType Key = {NF, Masked, Ordered, Log2SEW, LMUL, IndexLMUL};
  auto Table = makeArrayRef(RISCVVSXSEGTable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const VSXSEGPseudo &LHS, const KeyType &RHS) {
      if (LHS.NF < RHS.NF)
        return true;
      if (LHS.NF > RHS.NF)
        return false;
      if (LHS.Masked < RHS.Masked)
        return true;
      if (LHS.Masked > RHS.Masked)
        return false;
      if (LHS.Ordered < RHS.Ordered)
        return true;
      if (LHS.Ordered > RHS.Ordered)
        return false;
      if (LHS.Log2SEW < RHS.Log2SEW)
        return true;
      if (LHS.Log2SEW > RHS.Log2SEW)
        return false;
      if (LHS.LMUL < RHS.LMUL)
        return true;
      if (LHS.LMUL > RHS.LMUL)
        return false;
      if (LHS.IndexLMUL < RHS.IndexLMUL)
        return true;
      if (LHS.IndexLMUL > RHS.IndexLMUL)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.NF != Idx->NF ||
      Key.Masked != Idx->Masked ||
      Key.Ordered != Idx->Ordered ||
      Key.Log2SEW != Idx->Log2SEW ||
      Key.LMUL != Idx->LMUL ||
      Key.IndexLMUL != Idx->IndexLMUL)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_RISCVVSXTable_DECL
const VLX_VSXPseudo *getVSXPseudo(uint8_t Masked, uint8_t IsTU, uint8_t Ordered, uint8_t Log2SEW, uint8_t LMUL, uint8_t IndexLMUL);
#endif

#ifdef GET_RISCVVSXTable_IMPL
constexpr VLX_VSXPseudo RISCVVSXTable[] = {
  { 0x0, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVSUXEI8_V_M1_M1 }, // 0
  { 0x0, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVSUXEI8_V_MF8_M1 }, // 1
  { 0x0, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVSUXEI8_V_MF4_M1 }, // 2
  { 0x0, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVSUXEI8_V_MF2_M1 }, // 3
  { 0x0, 0x0, 0x0, 0x3, 0x1, 0x0, PseudoVSUXEI8_V_M1_M2 }, // 4
  { 0x0, 0x0, 0x0, 0x3, 0x1, 0x1, PseudoVSUXEI8_V_M2_M2 }, // 5
  { 0x0, 0x0, 0x0, 0x3, 0x1, 0x6, PseudoVSUXEI8_V_MF4_M2 }, // 6
  { 0x0, 0x0, 0x0, 0x3, 0x1, 0x7, PseudoVSUXEI8_V_MF2_M2 }, // 7
  { 0x0, 0x0, 0x0, 0x3, 0x2, 0x0, PseudoVSUXEI8_V_M1_M4 }, // 8
  { 0x0, 0x0, 0x0, 0x3, 0x2, 0x1, PseudoVSUXEI8_V_M2_M4 }, // 9
  { 0x0, 0x0, 0x0, 0x3, 0x2, 0x2, PseudoVSUXEI8_V_M4_M4 }, // 10
  { 0x0, 0x0, 0x0, 0x3, 0x2, 0x7, PseudoVSUXEI8_V_MF2_M4 }, // 11
  { 0x0, 0x0, 0x0, 0x3, 0x3, 0x0, PseudoVSUXEI8_V_M1_M8 }, // 12
  { 0x0, 0x0, 0x0, 0x3, 0x3, 0x1, PseudoVSUXEI8_V_M2_M8 }, // 13
  { 0x0, 0x0, 0x0, 0x3, 0x3, 0x2, PseudoVSUXEI8_V_M4_M8 }, // 14
  { 0x0, 0x0, 0x0, 0x3, 0x3, 0x3, PseudoVSUXEI8_V_M8_M8 }, // 15
  { 0x0, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVSUXEI8_V_MF8_MF8 }, // 16
  { 0x0, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVSUXEI8_V_MF8_MF4 }, // 17
  { 0x0, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVSUXEI8_V_MF4_MF4 }, // 18
  { 0x0, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVSUXEI8_V_MF8_MF2 }, // 19
  { 0x0, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVSUXEI8_V_MF4_MF2 }, // 20
  { 0x0, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVSUXEI8_V_MF2_MF2 }, // 21
  { 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVSUXEI16_V_M1_M1 }, // 22
  { 0x0, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVSUXEI16_V_M2_M1 }, // 23
  { 0x0, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVSUXEI16_V_MF4_M1 }, // 24
  { 0x0, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVSUXEI16_V_MF2_M1 }, // 25
  { 0x0, 0x0, 0x0, 0x4, 0x1, 0x0, PseudoVSUXEI16_V_M1_M2 }, // 26
  { 0x0, 0x0, 0x0, 0x4, 0x1, 0x1, PseudoVSUXEI16_V_M2_M2 }, // 27
  { 0x0, 0x0, 0x0, 0x4, 0x1, 0x2, PseudoVSUXEI16_V_M4_M2 }, // 28
  { 0x0, 0x0, 0x0, 0x4, 0x1, 0x7, PseudoVSUXEI16_V_MF2_M2 }, // 29
  { 0x0, 0x0, 0x0, 0x4, 0x2, 0x0, PseudoVSUXEI16_V_M1_M4 }, // 30
  { 0x0, 0x0, 0x0, 0x4, 0x2, 0x1, PseudoVSUXEI16_V_M2_M4 }, // 31
  { 0x0, 0x0, 0x0, 0x4, 0x2, 0x2, PseudoVSUXEI16_V_M4_M4 }, // 32
  { 0x0, 0x0, 0x0, 0x4, 0x2, 0x3, PseudoVSUXEI16_V_M8_M4 }, // 33
  { 0x0, 0x0, 0x0, 0x4, 0x3, 0x1, PseudoVSUXEI16_V_M2_M8 }, // 34
  { 0x0, 0x0, 0x0, 0x4, 0x3, 0x2, PseudoVSUXEI16_V_M4_M8 }, // 35
  { 0x0, 0x0, 0x0, 0x4, 0x3, 0x3, PseudoVSUXEI16_V_M8_M8 }, // 36
  { 0x0, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVSUXEI16_V_MF4_MF8 }, // 37
  { 0x0, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVSUXEI16_V_MF4_MF4 }, // 38
  { 0x0, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVSUXEI16_V_MF2_MF4 }, // 39
  { 0x0, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVSUXEI16_V_M1_MF2 }, // 40
  { 0x0, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVSUXEI16_V_MF4_MF2 }, // 41
  { 0x0, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVSUXEI16_V_MF2_MF2 }, // 42
  { 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVSUXEI32_V_M1_M1 }, // 43
  { 0x0, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVSUXEI32_V_M2_M1 }, // 44
  { 0x0, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVSUXEI32_V_M4_M1 }, // 45
  { 0x0, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVSUXEI32_V_MF2_M1 }, // 46
  { 0x0, 0x0, 0x0, 0x5, 0x1, 0x0, PseudoVSUXEI32_V_M1_M2 }, // 47
  { 0x0, 0x0, 0x0, 0x5, 0x1, 0x1, PseudoVSUXEI32_V_M2_M2 }, // 48
  { 0x0, 0x0, 0x0, 0x5, 0x1, 0x2, PseudoVSUXEI32_V_M4_M2 }, // 49
  { 0x0, 0x0, 0x0, 0x5, 0x1, 0x3, PseudoVSUXEI32_V_M8_M2 }, // 50
  { 0x0, 0x0, 0x0, 0x5, 0x2, 0x1, PseudoVSUXEI32_V_M2_M4 }, // 51
  { 0x0, 0x0, 0x0, 0x5, 0x2, 0x2, PseudoVSUXEI32_V_M4_M4 }, // 52
  { 0x0, 0x0, 0x0, 0x5, 0x2, 0x3, PseudoVSUXEI32_V_M8_M4 }, // 53
  { 0x0, 0x0, 0x0, 0x5, 0x3, 0x2, PseudoVSUXEI32_V_M4_M8 }, // 54
  { 0x0, 0x0, 0x0, 0x5, 0x3, 0x3, PseudoVSUXEI32_V_M8_M8 }, // 55
  { 0x0, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVSUXEI32_V_MF2_MF8 }, // 56
  { 0x0, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVSUXEI32_V_M1_MF4 }, // 57
  { 0x0, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVSUXEI32_V_MF2_MF4 }, // 58
  { 0x0, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVSUXEI32_V_M1_MF2 }, // 59
  { 0x0, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVSUXEI32_V_M2_MF2 }, // 60
  { 0x0, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVSUXEI32_V_MF2_MF2 }, // 61
  { 0x0, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVSUXEI64_V_M1_M1 }, // 62
  { 0x0, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVSUXEI64_V_M2_M1 }, // 63
  { 0x0, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVSUXEI64_V_M4_M1 }, // 64
  { 0x0, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVSUXEI64_V_M8_M1 }, // 65
  { 0x0, 0x0, 0x0, 0x6, 0x1, 0x1, PseudoVSUXEI64_V_M2_M2 }, // 66
  { 0x0, 0x0, 0x0, 0x6, 0x1, 0x2, PseudoVSUXEI64_V_M4_M2 }, // 67
  { 0x0, 0x0, 0x0, 0x6, 0x1, 0x3, PseudoVSUXEI64_V_M8_M2 }, // 68
  { 0x0, 0x0, 0x0, 0x6, 0x2, 0x2, PseudoVSUXEI64_V_M4_M4 }, // 69
  { 0x0, 0x0, 0x0, 0x6, 0x2, 0x3, PseudoVSUXEI64_V_M8_M4 }, // 70
  { 0x0, 0x0, 0x0, 0x6, 0x3, 0x3, PseudoVSUXEI64_V_M8_M8 }, // 71
  { 0x0, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVSUXEI64_V_M1_MF8 }, // 72
  { 0x0, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVSUXEI64_V_M1_MF4 }, // 73
  { 0x0, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVSUXEI64_V_M2_MF4 }, // 74
  { 0x0, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVSUXEI64_V_M1_MF2 }, // 75
  { 0x0, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVSUXEI64_V_M2_MF2 }, // 76
  { 0x0, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVSUXEI64_V_M4_MF2 }, // 77
  { 0x0, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVSOXEI8_V_M1_M1 }, // 78
  { 0x0, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVSOXEI8_V_MF8_M1 }, // 79
  { 0x0, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVSOXEI8_V_MF4_M1 }, // 80
  { 0x0, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVSOXEI8_V_MF2_M1 }, // 81
  { 0x0, 0x0, 0x1, 0x3, 0x1, 0x0, PseudoVSOXEI8_V_M1_M2 }, // 82
  { 0x0, 0x0, 0x1, 0x3, 0x1, 0x1, PseudoVSOXEI8_V_M2_M2 }, // 83
  { 0x0, 0x0, 0x1, 0x3, 0x1, 0x6, PseudoVSOXEI8_V_MF4_M2 }, // 84
  { 0x0, 0x0, 0x1, 0x3, 0x1, 0x7, PseudoVSOXEI8_V_MF2_M2 }, // 85
  { 0x0, 0x0, 0x1, 0x3, 0x2, 0x0, PseudoVSOXEI8_V_M1_M4 }, // 86
  { 0x0, 0x0, 0x1, 0x3, 0x2, 0x1, PseudoVSOXEI8_V_M2_M4 }, // 87
  { 0x0, 0x0, 0x1, 0x3, 0x2, 0x2, PseudoVSOXEI8_V_M4_M4 }, // 88
  { 0x0, 0x0, 0x1, 0x3, 0x2, 0x7, PseudoVSOXEI8_V_MF2_M4 }, // 89
  { 0x0, 0x0, 0x1, 0x3, 0x3, 0x0, PseudoVSOXEI8_V_M1_M8 }, // 90
  { 0x0, 0x0, 0x1, 0x3, 0x3, 0x1, PseudoVSOXEI8_V_M2_M8 }, // 91
  { 0x0, 0x0, 0x1, 0x3, 0x3, 0x2, PseudoVSOXEI8_V_M4_M8 }, // 92
  { 0x0, 0x0, 0x1, 0x3, 0x3, 0x3, PseudoVSOXEI8_V_M8_M8 }, // 93
  { 0x0, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVSOXEI8_V_MF8_MF8 }, // 94
  { 0x0, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVSOXEI8_V_MF8_MF4 }, // 95
  { 0x0, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVSOXEI8_V_MF4_MF4 }, // 96
  { 0x0, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVSOXEI8_V_MF8_MF2 }, // 97
  { 0x0, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVSOXEI8_V_MF4_MF2 }, // 98
  { 0x0, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVSOXEI8_V_MF2_MF2 }, // 99
  { 0x0, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVSOXEI16_V_M1_M1 }, // 100
  { 0x0, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVSOXEI16_V_M2_M1 }, // 101
  { 0x0, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVSOXEI16_V_MF4_M1 }, // 102
  { 0x0, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVSOXEI16_V_MF2_M1 }, // 103
  { 0x0, 0x0, 0x1, 0x4, 0x1, 0x0, PseudoVSOXEI16_V_M1_M2 }, // 104
  { 0x0, 0x0, 0x1, 0x4, 0x1, 0x1, PseudoVSOXEI16_V_M2_M2 }, // 105
  { 0x0, 0x0, 0x1, 0x4, 0x1, 0x2, PseudoVSOXEI16_V_M4_M2 }, // 106
  { 0x0, 0x0, 0x1, 0x4, 0x1, 0x7, PseudoVSOXEI16_V_MF2_M2 }, // 107
  { 0x0, 0x0, 0x1, 0x4, 0x2, 0x0, PseudoVSOXEI16_V_M1_M4 }, // 108
  { 0x0, 0x0, 0x1, 0x4, 0x2, 0x1, PseudoVSOXEI16_V_M2_M4 }, // 109
  { 0x0, 0x0, 0x1, 0x4, 0x2, 0x2, PseudoVSOXEI16_V_M4_M4 }, // 110
  { 0x0, 0x0, 0x1, 0x4, 0x2, 0x3, PseudoVSOXEI16_V_M8_M4 }, // 111
  { 0x0, 0x0, 0x1, 0x4, 0x3, 0x1, PseudoVSOXEI16_V_M2_M8 }, // 112
  { 0x0, 0x0, 0x1, 0x4, 0x3, 0x2, PseudoVSOXEI16_V_M4_M8 }, // 113
  { 0x0, 0x0, 0x1, 0x4, 0x3, 0x3, PseudoVSOXEI16_V_M8_M8 }, // 114
  { 0x0, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVSOXEI16_V_MF4_MF8 }, // 115
  { 0x0, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVSOXEI16_V_MF4_MF4 }, // 116
  { 0x0, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVSOXEI16_V_MF2_MF4 }, // 117
  { 0x0, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVSOXEI16_V_M1_MF2 }, // 118
  { 0x0, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVSOXEI16_V_MF4_MF2 }, // 119
  { 0x0, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVSOXEI16_V_MF2_MF2 }, // 120
  { 0x0, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVSOXEI32_V_M1_M1 }, // 121
  { 0x0, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVSOXEI32_V_M2_M1 }, // 122
  { 0x0, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVSOXEI32_V_M4_M1 }, // 123
  { 0x0, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVSOXEI32_V_MF2_M1 }, // 124
  { 0x0, 0x0, 0x1, 0x5, 0x1, 0x0, PseudoVSOXEI32_V_M1_M2 }, // 125
  { 0x0, 0x0, 0x1, 0x5, 0x1, 0x1, PseudoVSOXEI32_V_M2_M2 }, // 126
  { 0x0, 0x0, 0x1, 0x5, 0x1, 0x2, PseudoVSOXEI32_V_M4_M2 }, // 127
  { 0x0, 0x0, 0x1, 0x5, 0x1, 0x3, PseudoVSOXEI32_V_M8_M2 }, // 128
  { 0x0, 0x0, 0x1, 0x5, 0x2, 0x1, PseudoVSOXEI32_V_M2_M4 }, // 129
  { 0x0, 0x0, 0x1, 0x5, 0x2, 0x2, PseudoVSOXEI32_V_M4_M4 }, // 130
  { 0x0, 0x0, 0x1, 0x5, 0x2, 0x3, PseudoVSOXEI32_V_M8_M4 }, // 131
  { 0x0, 0x0, 0x1, 0x5, 0x3, 0x2, PseudoVSOXEI32_V_M4_M8 }, // 132
  { 0x0, 0x0, 0x1, 0x5, 0x3, 0x3, PseudoVSOXEI32_V_M8_M8 }, // 133
  { 0x0, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVSOXEI32_V_MF2_MF8 }, // 134
  { 0x0, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVSOXEI32_V_M1_MF4 }, // 135
  { 0x0, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVSOXEI32_V_MF2_MF4 }, // 136
  { 0x0, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVSOXEI32_V_M1_MF2 }, // 137
  { 0x0, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVSOXEI32_V_M2_MF2 }, // 138
  { 0x0, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVSOXEI32_V_MF2_MF2 }, // 139
  { 0x0, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVSOXEI64_V_M1_M1 }, // 140
  { 0x0, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVSOXEI64_V_M2_M1 }, // 141
  { 0x0, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVSOXEI64_V_M4_M1 }, // 142
  { 0x0, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVSOXEI64_V_M8_M1 }, // 143
  { 0x0, 0x0, 0x1, 0x6, 0x1, 0x1, PseudoVSOXEI64_V_M2_M2 }, // 144
  { 0x0, 0x0, 0x1, 0x6, 0x1, 0x2, PseudoVSOXEI64_V_M4_M2 }, // 145
  { 0x0, 0x0, 0x1, 0x6, 0x1, 0x3, PseudoVSOXEI64_V_M8_M2 }, // 146
  { 0x0, 0x0, 0x1, 0x6, 0x2, 0x2, PseudoVSOXEI64_V_M4_M4 }, // 147
  { 0x0, 0x0, 0x1, 0x6, 0x2, 0x3, PseudoVSOXEI64_V_M8_M4 }, // 148
  { 0x0, 0x0, 0x1, 0x6, 0x3, 0x3, PseudoVSOXEI64_V_M8_M8 }, // 149
  { 0x0, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVSOXEI64_V_M1_MF8 }, // 150
  { 0x0, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVSOXEI64_V_M1_MF4 }, // 151
  { 0x0, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVSOXEI64_V_M2_MF4 }, // 152
  { 0x0, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVSOXEI64_V_M1_MF2 }, // 153
  { 0x0, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVSOXEI64_V_M2_MF2 }, // 154
  { 0x0, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVSOXEI64_V_M4_MF2 }, // 155
  { 0x1, 0x0, 0x0, 0x3, 0x0, 0x0, PseudoVSUXEI8_V_M1_M1_MASK }, // 156
  { 0x1, 0x0, 0x0, 0x3, 0x0, 0x5, PseudoVSUXEI8_V_MF8_M1_MASK }, // 157
  { 0x1, 0x0, 0x0, 0x3, 0x0, 0x6, PseudoVSUXEI8_V_MF4_M1_MASK }, // 158
  { 0x1, 0x0, 0x0, 0x3, 0x0, 0x7, PseudoVSUXEI8_V_MF2_M1_MASK }, // 159
  { 0x1, 0x0, 0x0, 0x3, 0x1, 0x0, PseudoVSUXEI8_V_M1_M2_MASK }, // 160
  { 0x1, 0x0, 0x0, 0x3, 0x1, 0x1, PseudoVSUXEI8_V_M2_M2_MASK }, // 161
  { 0x1, 0x0, 0x0, 0x3, 0x1, 0x6, PseudoVSUXEI8_V_MF4_M2_MASK }, // 162
  { 0x1, 0x0, 0x0, 0x3, 0x1, 0x7, PseudoVSUXEI8_V_MF2_M2_MASK }, // 163
  { 0x1, 0x0, 0x0, 0x3, 0x2, 0x0, PseudoVSUXEI8_V_M1_M4_MASK }, // 164
  { 0x1, 0x0, 0x0, 0x3, 0x2, 0x1, PseudoVSUXEI8_V_M2_M4_MASK }, // 165
  { 0x1, 0x0, 0x0, 0x3, 0x2, 0x2, PseudoVSUXEI8_V_M4_M4_MASK }, // 166
  { 0x1, 0x0, 0x0, 0x3, 0x2, 0x7, PseudoVSUXEI8_V_MF2_M4_MASK }, // 167
  { 0x1, 0x0, 0x0, 0x3, 0x3, 0x0, PseudoVSUXEI8_V_M1_M8_MASK }, // 168
  { 0x1, 0x0, 0x0, 0x3, 0x3, 0x1, PseudoVSUXEI8_V_M2_M8_MASK }, // 169
  { 0x1, 0x0, 0x0, 0x3, 0x3, 0x2, PseudoVSUXEI8_V_M4_M8_MASK }, // 170
  { 0x1, 0x0, 0x0, 0x3, 0x3, 0x3, PseudoVSUXEI8_V_M8_M8_MASK }, // 171
  { 0x1, 0x0, 0x0, 0x3, 0x5, 0x5, PseudoVSUXEI8_V_MF8_MF8_MASK }, // 172
  { 0x1, 0x0, 0x0, 0x3, 0x6, 0x5, PseudoVSUXEI8_V_MF8_MF4_MASK }, // 173
  { 0x1, 0x0, 0x0, 0x3, 0x6, 0x6, PseudoVSUXEI8_V_MF4_MF4_MASK }, // 174
  { 0x1, 0x0, 0x0, 0x3, 0x7, 0x5, PseudoVSUXEI8_V_MF8_MF2_MASK }, // 175
  { 0x1, 0x0, 0x0, 0x3, 0x7, 0x6, PseudoVSUXEI8_V_MF4_MF2_MASK }, // 176
  { 0x1, 0x0, 0x0, 0x3, 0x7, 0x7, PseudoVSUXEI8_V_MF2_MF2_MASK }, // 177
  { 0x1, 0x0, 0x0, 0x4, 0x0, 0x0, PseudoVSUXEI16_V_M1_M1_MASK }, // 178
  { 0x1, 0x0, 0x0, 0x4, 0x0, 0x1, PseudoVSUXEI16_V_M2_M1_MASK }, // 179
  { 0x1, 0x0, 0x0, 0x4, 0x0, 0x6, PseudoVSUXEI16_V_MF4_M1_MASK }, // 180
  { 0x1, 0x0, 0x0, 0x4, 0x0, 0x7, PseudoVSUXEI16_V_MF2_M1_MASK }, // 181
  { 0x1, 0x0, 0x0, 0x4, 0x1, 0x0, PseudoVSUXEI16_V_M1_M2_MASK }, // 182
  { 0x1, 0x0, 0x0, 0x4, 0x1, 0x1, PseudoVSUXEI16_V_M2_M2_MASK }, // 183
  { 0x1, 0x0, 0x0, 0x4, 0x1, 0x2, PseudoVSUXEI16_V_M4_M2_MASK }, // 184
  { 0x1, 0x0, 0x0, 0x4, 0x1, 0x7, PseudoVSUXEI16_V_MF2_M2_MASK }, // 185
  { 0x1, 0x0, 0x0, 0x4, 0x2, 0x0, PseudoVSUXEI16_V_M1_M4_MASK }, // 186
  { 0x1, 0x0, 0x0, 0x4, 0x2, 0x1, PseudoVSUXEI16_V_M2_M4_MASK }, // 187
  { 0x1, 0x0, 0x0, 0x4, 0x2, 0x2, PseudoVSUXEI16_V_M4_M4_MASK }, // 188
  { 0x1, 0x0, 0x0, 0x4, 0x2, 0x3, PseudoVSUXEI16_V_M8_M4_MASK }, // 189
  { 0x1, 0x0, 0x0, 0x4, 0x3, 0x1, PseudoVSUXEI16_V_M2_M8_MASK }, // 190
  { 0x1, 0x0, 0x0, 0x4, 0x3, 0x2, PseudoVSUXEI16_V_M4_M8_MASK }, // 191
  { 0x1, 0x0, 0x0, 0x4, 0x3, 0x3, PseudoVSUXEI16_V_M8_M8_MASK }, // 192
  { 0x1, 0x0, 0x0, 0x4, 0x5, 0x6, PseudoVSUXEI16_V_MF4_MF8_MASK }, // 193
  { 0x1, 0x0, 0x0, 0x4, 0x6, 0x6, PseudoVSUXEI16_V_MF4_MF4_MASK }, // 194
  { 0x1, 0x0, 0x0, 0x4, 0x6, 0x7, PseudoVSUXEI16_V_MF2_MF4_MASK }, // 195
  { 0x1, 0x0, 0x0, 0x4, 0x7, 0x0, PseudoVSUXEI16_V_M1_MF2_MASK }, // 196
  { 0x1, 0x0, 0x0, 0x4, 0x7, 0x6, PseudoVSUXEI16_V_MF4_MF2_MASK }, // 197
  { 0x1, 0x0, 0x0, 0x4, 0x7, 0x7, PseudoVSUXEI16_V_MF2_MF2_MASK }, // 198
  { 0x1, 0x0, 0x0, 0x5, 0x0, 0x0, PseudoVSUXEI32_V_M1_M1_MASK }, // 199
  { 0x1, 0x0, 0x0, 0x5, 0x0, 0x1, PseudoVSUXEI32_V_M2_M1_MASK }, // 200
  { 0x1, 0x0, 0x0, 0x5, 0x0, 0x2, PseudoVSUXEI32_V_M4_M1_MASK }, // 201
  { 0x1, 0x0, 0x0, 0x5, 0x0, 0x7, PseudoVSUXEI32_V_MF2_M1_MASK }, // 202
  { 0x1, 0x0, 0x0, 0x5, 0x1, 0x0, PseudoVSUXEI32_V_M1_M2_MASK }, // 203
  { 0x1, 0x0, 0x0, 0x5, 0x1, 0x1, PseudoVSUXEI32_V_M2_M2_MASK }, // 204
  { 0x1, 0x0, 0x0, 0x5, 0x1, 0x2, PseudoVSUXEI32_V_M4_M2_MASK }, // 205
  { 0x1, 0x0, 0x0, 0x5, 0x1, 0x3, PseudoVSUXEI32_V_M8_M2_MASK }, // 206
  { 0x1, 0x0, 0x0, 0x5, 0x2, 0x1, PseudoVSUXEI32_V_M2_M4_MASK }, // 207
  { 0x1, 0x0, 0x0, 0x5, 0x2, 0x2, PseudoVSUXEI32_V_M4_M4_MASK }, // 208
  { 0x1, 0x0, 0x0, 0x5, 0x2, 0x3, PseudoVSUXEI32_V_M8_M4_MASK }, // 209
  { 0x1, 0x0, 0x0, 0x5, 0x3, 0x2, PseudoVSUXEI32_V_M4_M8_MASK }, // 210
  { 0x1, 0x0, 0x0, 0x5, 0x3, 0x3, PseudoVSUXEI32_V_M8_M8_MASK }, // 211
  { 0x1, 0x0, 0x0, 0x5, 0x5, 0x7, PseudoVSUXEI32_V_MF2_MF8_MASK }, // 212
  { 0x1, 0x0, 0x0, 0x5, 0x6, 0x0, PseudoVSUXEI32_V_M1_MF4_MASK }, // 213
  { 0x1, 0x0, 0x0, 0x5, 0x6, 0x7, PseudoVSUXEI32_V_MF2_MF4_MASK }, // 214
  { 0x1, 0x0, 0x0, 0x5, 0x7, 0x0, PseudoVSUXEI32_V_M1_MF2_MASK }, // 215
  { 0x1, 0x0, 0x0, 0x5, 0x7, 0x1, PseudoVSUXEI32_V_M2_MF2_MASK }, // 216
  { 0x1, 0x0, 0x0, 0x5, 0x7, 0x7, PseudoVSUXEI32_V_MF2_MF2_MASK }, // 217
  { 0x1, 0x0, 0x0, 0x6, 0x0, 0x0, PseudoVSUXEI64_V_M1_M1_MASK }, // 218
  { 0x1, 0x0, 0x0, 0x6, 0x0, 0x1, PseudoVSUXEI64_V_M2_M1_MASK }, // 219
  { 0x1, 0x0, 0x0, 0x6, 0x0, 0x2, PseudoVSUXEI64_V_M4_M1_MASK }, // 220
  { 0x1, 0x0, 0x0, 0x6, 0x0, 0x3, PseudoVSUXEI64_V_M8_M1_MASK }, // 221
  { 0x1, 0x0, 0x0, 0x6, 0x1, 0x1, PseudoVSUXEI64_V_M2_M2_MASK }, // 222
  { 0x1, 0x0, 0x0, 0x6, 0x1, 0x2, PseudoVSUXEI64_V_M4_M2_MASK }, // 223
  { 0x1, 0x0, 0x0, 0x6, 0x1, 0x3, PseudoVSUXEI64_V_M8_M2_MASK }, // 224
  { 0x1, 0x0, 0x0, 0x6, 0x2, 0x2, PseudoVSUXEI64_V_M4_M4_MASK }, // 225
  { 0x1, 0x0, 0x0, 0x6, 0x2, 0x3, PseudoVSUXEI64_V_M8_M4_MASK }, // 226
  { 0x1, 0x0, 0x0, 0x6, 0x3, 0x3, PseudoVSUXEI64_V_M8_M8_MASK }, // 227
  { 0x1, 0x0, 0x0, 0x6, 0x5, 0x0, PseudoVSUXEI64_V_M1_MF8_MASK }, // 228
  { 0x1, 0x0, 0x0, 0x6, 0x6, 0x0, PseudoVSUXEI64_V_M1_MF4_MASK }, // 229
  { 0x1, 0x0, 0x0, 0x6, 0x6, 0x1, PseudoVSUXEI64_V_M2_MF4_MASK }, // 230
  { 0x1, 0x0, 0x0, 0x6, 0x7, 0x0, PseudoVSUXEI64_V_M1_MF2_MASK }, // 231
  { 0x1, 0x0, 0x0, 0x6, 0x7, 0x1, PseudoVSUXEI64_V_M2_MF2_MASK }, // 232
  { 0x1, 0x0, 0x0, 0x6, 0x7, 0x2, PseudoVSUXEI64_V_M4_MF2_MASK }, // 233
  { 0x1, 0x0, 0x1, 0x3, 0x0, 0x0, PseudoVSOXEI8_V_M1_M1_MASK }, // 234
  { 0x1, 0x0, 0x1, 0x3, 0x0, 0x5, PseudoVSOXEI8_V_MF8_M1_MASK }, // 235
  { 0x1, 0x0, 0x1, 0x3, 0x0, 0x6, PseudoVSOXEI8_V_MF4_M1_MASK }, // 236
  { 0x1, 0x0, 0x1, 0x3, 0x0, 0x7, PseudoVSOXEI8_V_MF2_M1_MASK }, // 237
  { 0x1, 0x0, 0x1, 0x3, 0x1, 0x0, PseudoVSOXEI8_V_M1_M2_MASK }, // 238
  { 0x1, 0x0, 0x1, 0x3, 0x1, 0x1, PseudoVSOXEI8_V_M2_M2_MASK }, // 239
  { 0x1, 0x0, 0x1, 0x3, 0x1, 0x6, PseudoVSOXEI8_V_MF4_M2_MASK }, // 240
  { 0x1, 0x0, 0x1, 0x3, 0x1, 0x7, PseudoVSOXEI8_V_MF2_M2_MASK }, // 241
  { 0x1, 0x0, 0x1, 0x3, 0x2, 0x0, PseudoVSOXEI8_V_M1_M4_MASK }, // 242
  { 0x1, 0x0, 0x1, 0x3, 0x2, 0x1, PseudoVSOXEI8_V_M2_M4_MASK }, // 243
  { 0x1, 0x0, 0x1, 0x3, 0x2, 0x2, PseudoVSOXEI8_V_M4_M4_MASK }, // 244
  { 0x1, 0x0, 0x1, 0x3, 0x2, 0x7, PseudoVSOXEI8_V_MF2_M4_MASK }, // 245
  { 0x1, 0x0, 0x1, 0x3, 0x3, 0x0, PseudoVSOXEI8_V_M1_M8_MASK }, // 246
  { 0x1, 0x0, 0x1, 0x3, 0x3, 0x1, PseudoVSOXEI8_V_M2_M8_MASK }, // 247
  { 0x1, 0x0, 0x1, 0x3, 0x3, 0x2, PseudoVSOXEI8_V_M4_M8_MASK }, // 248
  { 0x1, 0x0, 0x1, 0x3, 0x3, 0x3, PseudoVSOXEI8_V_M8_M8_MASK }, // 249
  { 0x1, 0x0, 0x1, 0x3, 0x5, 0x5, PseudoVSOXEI8_V_MF8_MF8_MASK }, // 250
  { 0x1, 0x0, 0x1, 0x3, 0x6, 0x5, PseudoVSOXEI8_V_MF8_MF4_MASK }, // 251
  { 0x1, 0x0, 0x1, 0x3, 0x6, 0x6, PseudoVSOXEI8_V_MF4_MF4_MASK }, // 252
  { 0x1, 0x0, 0x1, 0x3, 0x7, 0x5, PseudoVSOXEI8_V_MF8_MF2_MASK }, // 253
  { 0x1, 0x0, 0x1, 0x3, 0x7, 0x6, PseudoVSOXEI8_V_MF4_MF2_MASK }, // 254
  { 0x1, 0x0, 0x1, 0x3, 0x7, 0x7, PseudoVSOXEI8_V_MF2_MF2_MASK }, // 255
  { 0x1, 0x0, 0x1, 0x4, 0x0, 0x0, PseudoVSOXEI16_V_M1_M1_MASK }, // 256
  { 0x1, 0x0, 0x1, 0x4, 0x0, 0x1, PseudoVSOXEI16_V_M2_M1_MASK }, // 257
  { 0x1, 0x0, 0x1, 0x4, 0x0, 0x6, PseudoVSOXEI16_V_MF4_M1_MASK }, // 258
  { 0x1, 0x0, 0x1, 0x4, 0x0, 0x7, PseudoVSOXEI16_V_MF2_M1_MASK }, // 259
  { 0x1, 0x0, 0x1, 0x4, 0x1, 0x0, PseudoVSOXEI16_V_M1_M2_MASK }, // 260
  { 0x1, 0x0, 0x1, 0x4, 0x1, 0x1, PseudoVSOXEI16_V_M2_M2_MASK }, // 261
  { 0x1, 0x0, 0x1, 0x4, 0x1, 0x2, PseudoVSOXEI16_V_M4_M2_MASK }, // 262
  { 0x1, 0x0, 0x1, 0x4, 0x1, 0x7, PseudoVSOXEI16_V_MF2_M2_MASK }, // 263
  { 0x1, 0x0, 0x1, 0x4, 0x2, 0x0, PseudoVSOXEI16_V_M1_M4_MASK }, // 264
  { 0x1, 0x0, 0x1, 0x4, 0x2, 0x1, PseudoVSOXEI16_V_M2_M4_MASK }, // 265
  { 0x1, 0x0, 0x1, 0x4, 0x2, 0x2, PseudoVSOXEI16_V_M4_M4_MASK }, // 266
  { 0x1, 0x0, 0x1, 0x4, 0x2, 0x3, PseudoVSOXEI16_V_M8_M4_MASK }, // 267
  { 0x1, 0x0, 0x1, 0x4, 0x3, 0x1, PseudoVSOXEI16_V_M2_M8_MASK }, // 268
  { 0x1, 0x0, 0x1, 0x4, 0x3, 0x2, PseudoVSOXEI16_V_M4_M8_MASK }, // 269
  { 0x1, 0x0, 0x1, 0x4, 0x3, 0x3, PseudoVSOXEI16_V_M8_M8_MASK }, // 270
  { 0x1, 0x0, 0x1, 0x4, 0x5, 0x6, PseudoVSOXEI16_V_MF4_MF8_MASK }, // 271
  { 0x1, 0x0, 0x1, 0x4, 0x6, 0x6, PseudoVSOXEI16_V_MF4_MF4_MASK }, // 272
  { 0x1, 0x0, 0x1, 0x4, 0x6, 0x7, PseudoVSOXEI16_V_MF2_MF4_MASK }, // 273
  { 0x1, 0x0, 0x1, 0x4, 0x7, 0x0, PseudoVSOXEI16_V_M1_MF2_MASK }, // 274
  { 0x1, 0x0, 0x1, 0x4, 0x7, 0x6, PseudoVSOXEI16_V_MF4_MF2_MASK }, // 275
  { 0x1, 0x0, 0x1, 0x4, 0x7, 0x7, PseudoVSOXEI16_V_MF2_MF2_MASK }, // 276
  { 0x1, 0x0, 0x1, 0x5, 0x0, 0x0, PseudoVSOXEI32_V_M1_M1_MASK }, // 277
  { 0x1, 0x0, 0x1, 0x5, 0x0, 0x1, PseudoVSOXEI32_V_M2_M1_MASK }, // 278
  { 0x1, 0x0, 0x1, 0x5, 0x0, 0x2, PseudoVSOXEI32_V_M4_M1_MASK }, // 279
  { 0x1, 0x0, 0x1, 0x5, 0x0, 0x7, PseudoVSOXEI32_V_MF2_M1_MASK }, // 280
  { 0x1, 0x0, 0x1, 0x5, 0x1, 0x0, PseudoVSOXEI32_V_M1_M2_MASK }, // 281
  { 0x1, 0x0, 0x1, 0x5, 0x1, 0x1, PseudoVSOXEI32_V_M2_M2_MASK }, // 282
  { 0x1, 0x0, 0x1, 0x5, 0x1, 0x2, PseudoVSOXEI32_V_M4_M2_MASK }, // 283
  { 0x1, 0x0, 0x1, 0x5, 0x1, 0x3, PseudoVSOXEI32_V_M8_M2_MASK }, // 284
  { 0x1, 0x0, 0x1, 0x5, 0x2, 0x1, PseudoVSOXEI32_V_M2_M4_MASK }, // 285
  { 0x1, 0x0, 0x1, 0x5, 0x2, 0x2, PseudoVSOXEI32_V_M4_M4_MASK }, // 286
  { 0x1, 0x0, 0x1, 0x5, 0x2, 0x3, PseudoVSOXEI32_V_M8_M4_MASK }, // 287
  { 0x1, 0x0, 0x1, 0x5, 0x3, 0x2, PseudoVSOXEI32_V_M4_M8_MASK }, // 288
  { 0x1, 0x0, 0x1, 0x5, 0x3, 0x3, PseudoVSOXEI32_V_M8_M8_MASK }, // 289
  { 0x1, 0x0, 0x1, 0x5, 0x5, 0x7, PseudoVSOXEI32_V_MF2_MF8_MASK }, // 290
  { 0x1, 0x0, 0x1, 0x5, 0x6, 0x0, PseudoVSOXEI32_V_M1_MF4_MASK }, // 291
  { 0x1, 0x0, 0x1, 0x5, 0x6, 0x7, PseudoVSOXEI32_V_MF2_MF4_MASK }, // 292
  { 0x1, 0x0, 0x1, 0x5, 0x7, 0x0, PseudoVSOXEI32_V_M1_MF2_MASK }, // 293
  { 0x1, 0x0, 0x1, 0x5, 0x7, 0x1, PseudoVSOXEI32_V_M2_MF2_MASK }, // 294
  { 0x1, 0x0, 0x1, 0x5, 0x7, 0x7, PseudoVSOXEI32_V_MF2_MF2_MASK }, // 295
  { 0x1, 0x0, 0x1, 0x6, 0x0, 0x0, PseudoVSOXEI64_V_M1_M1_MASK }, // 296
  { 0x1, 0x0, 0x1, 0x6, 0x0, 0x1, PseudoVSOXEI64_V_M2_M1_MASK }, // 297
  { 0x1, 0x0, 0x1, 0x6, 0x0, 0x2, PseudoVSOXEI64_V_M4_M1_MASK }, // 298
  { 0x1, 0x0, 0x1, 0x6, 0x0, 0x3, PseudoVSOXEI64_V_M8_M1_MASK }, // 299
  { 0x1, 0x0, 0x1, 0x6, 0x1, 0x1, PseudoVSOXEI64_V_M2_M2_MASK }, // 300
  { 0x1, 0x0, 0x1, 0x6, 0x1, 0x2, PseudoVSOXEI64_V_M4_M2_MASK }, // 301
  { 0x1, 0x0, 0x1, 0x6, 0x1, 0x3, PseudoVSOXEI64_V_M8_M2_MASK }, // 302
  { 0x1, 0x0, 0x1, 0x6, 0x2, 0x2, PseudoVSOXEI64_V_M4_M4_MASK }, // 303
  { 0x1, 0x0, 0x1, 0x6, 0x2, 0x3, PseudoVSOXEI64_V_M8_M4_MASK }, // 304
  { 0x1, 0x0, 0x1, 0x6, 0x3, 0x3, PseudoVSOXEI64_V_M8_M8_MASK }, // 305
  { 0x1, 0x0, 0x1, 0x6, 0x5, 0x0, PseudoVSOXEI64_V_M1_MF8_MASK }, // 306
  { 0x1, 0x0, 0x1, 0x6, 0x6, 0x0, PseudoVSOXEI64_V_M1_MF4_MASK }, // 307
  { 0x1, 0x0, 0x1, 0x6, 0x6, 0x1, PseudoVSOXEI64_V_M2_MF4_MASK }, // 308
  { 0x1, 0x0, 0x1, 0x6, 0x7, 0x0, PseudoVSOXEI64_V_M1_MF2_MASK }, // 309
  { 0x1, 0x0, 0x1, 0x6, 0x7, 0x1, PseudoVSOXEI64_V_M2_MF2_MASK }, // 310
  { 0x1, 0x0, 0x1, 0x6, 0x7, 0x2, PseudoVSOXEI64_V_M4_MF2_MASK }, // 311
 };

const VLX_VSXPseudo *getVSXPseudo(uint8_t Masked, uint8_t IsTU, uint8_t Ordered, uint8_t Log2SEW, uint8_t LMUL, uint8_t IndexLMUL) {
  struct KeyType {
    uint8_t Masked;
    uint8_t IsTU;
    uint8_t Ordered;
    uint8_t Log2SEW;
    uint8_t LMUL;
    uint8_t IndexLMUL;
  };
  KeyType Key = {Masked, IsTU, Ordered, Log2SEW, LMUL, IndexLMUL};
  auto Table = makeArrayRef(RISCVVSXTable);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const VLX_VSXPseudo &LHS, const KeyType &RHS) {
      if (LHS.Masked < RHS.Masked)
        return true;
      if (LHS.Masked > RHS.Masked)
        return false;
      if (LHS.IsTU < RHS.IsTU)
        return true;
      if (LHS.IsTU > RHS.IsTU)
        return false;
      if (LHS.Ordered < RHS.Ordered)
        return true;
      if (LHS.Ordered > RHS.Ordered)
        return false;
      if (LHS.Log2SEW < RHS.Log2SEW)
        return true;
      if (LHS.Log2SEW > RHS.Log2SEW)
        return false;
      if (LHS.LMUL < RHS.LMUL)
        return true;
      if (LHS.LMUL > RHS.LMUL)
        return false;
      if (LHS.IndexLMUL < RHS.IndexLMUL)
        return true;
      if (LHS.IndexLMUL > RHS.IndexLMUL)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.Masked != Idx->Masked ||
      Key.IsTU != Idx->IsTU ||
      Key.Ordered != Idx->Ordered ||
      Key.Log2SEW != Idx->Log2SEW ||
      Key.LMUL != Idx->LMUL ||
      Key.IndexLMUL != Idx->IndexLMUL)
    return nullptr;
  return &*Idx;
}
#endif

#ifdef GET_SysRegsList_DECL
const SysReg *lookupSysRegByEncoding(uint16_t Encoding);
const SysReg *lookupSysRegByAltName(StringRef AltName);
const SysReg *lookupSysRegByDeprecatedName(StringRef DeprecatedName);
const SysReg *lookupSysRegByName(StringRef Name);
#endif

#ifdef GET_SysRegsList_IMPL
constexpr SysReg SysRegsList[] = {
  { "ustatus", "ustatus", "", 0x0,  {} , false }, // 0
  { "fflags", "fflags", "", 0x1,  {} , false }, // 1
  { "frm", "frm", "", 0x2,  {} , false }, // 2
  { "fcsr", "fcsr", "", 0x3,  {} , false }, // 3
  { "uie", "uie", "", 0x4,  {} , false }, // 4
  { "utvec", "utvec", "", 0x5,  {} , false }, // 5
  { "vstart", "vstart", "", 0x8,  {} , false }, // 6
  { "vxsat", "vxsat", "", 0x9,  {} , false }, // 7
  { "vxrm", "vxrm", "", 0xA,  {} , false }, // 8
  { "vcsr", "vcsr", "", 0xF,  {} , false }, // 9
  { "seed", "seed", "", 0x15,  {} , false }, // 10
  { "uscratch", "uscratch", "", 0x40,  {} , false }, // 11
  { "uepc", "uepc", "", 0x41,  {} , false }, // 12
  { "ucause", "ucause", "", 0x42,  {} , false }, // 13
  { "utval", "utval", "ubadaddr", 0x43,  {} , false }, // 14
  { "uip", "uip", "", 0x44,  {} , false }, // 15
  { "sstatus", "sstatus", "", 0x100,  {} , false }, // 16
  { "sedeleg", "sedeleg", "", 0x102,  {} , false }, // 17
  { "sideleg", "sideleg", "", 0x103,  {} , false }, // 18
  { "sie", "sie", "", 0x104,  {} , false }, // 19
  { "stvec", "stvec", "", 0x105,  {} , false }, // 20
  { "scounteren", "scounteren", "", 0x106,  {} , false }, // 21
  { "senvcfg", "senvcfg", "", 0x10A,  {} , false }, // 22
  { "sstateen0", "sstateen0", "", 0x10C,  {} , false }, // 23
  { "sstateen1", "sstateen1", "", 0x10D,  {} , false }, // 24
  { "sstateen2", "sstateen2", "", 0x10E,  {} , false }, // 25
  { "sstateen3", "sstateen3", "", 0x10F,  {} , false }, // 26
  { "sscratch", "sscratch", "", 0x140,  {} , false }, // 27
  { "sepc", "sepc", "", 0x141,  {} , false }, // 28
  { "scause", "scause", "", 0x142,  {} , false }, // 29
  { "stval", "stval", "sbadaddr", 0x143,  {} , false }, // 30
  { "sip", "sip", "", 0x144,  {} , false }, // 31
  { "stimecmp", "stimecmp", "", 0x14D,  {} , false }, // 32
  { "stimecmph", "stimecmph", "", 0x15D,  {} , true }, // 33
  { "satp", "satp", "sptbr", 0x180,  {} , false }, // 34
  { "vsstatus", "vsstatus", "", 0x200,  {} , false }, // 35
  { "vsie", "vsie", "", 0x204,  {} , false }, // 36
  { "vstvec", "vstvec", "", 0x205,  {} , false }, // 37
  { "vsscratch", "vsscratch", "", 0x240,  {} , false }, // 38
  { "vsepc", "vsepc", "", 0x241,  {} , false }, // 39
  { "vscause", "vscause", "", 0x242,  {} , false }, // 40
  { "vstval", "vstval", "", 0x243,  {} , false }, // 41
  { "vsip", "vsip", "", 0x244,  {} , false }, // 42
  { "vstimecmp", "vstimecmp", "", 0x24D,  {} , false }, // 43
  { "vstimecmph", "vstimecmph", "", 0x25D,  {} , true }, // 44
  { "vsatp", "vsatp", "", 0x280,  {} , false }, // 45
  { "mstatus", "mstatus", "", 0x300,  {} , false }, // 46
  { "misa", "misa", "", 0x301,  {} , false }, // 47
  { "medeleg", "medeleg", "", 0x302,  {} , false }, // 48
  { "mideleg", "mideleg", "", 0x303,  {} , false }, // 49
  { "mie", "mie", "", 0x304,  {} , false }, // 50
  { "mtvec", "mtvec", "", 0x305,  {} , false }, // 51
  { "mcounteren", "mcounteren", "", 0x306,  {} , false }, // 52
  { "menvcfg", "menvcfg", "", 0x30A,  {} , false }, // 53
  { "mstateen0", "mstateen0", "", 0x30C,  {} , false }, // 54
  { "mstateen1", "mstateen1", "", 0x30D,  {} , false }, // 55
  { "mstateen2", "mstateen2", "", 0x30E,  {} , false }, // 56
  { "mstateen3", "mstateen3", "", 0x30F,  {} , false }, // 57
  { "mstatush", "mstatush", "", 0x310,  {} , true }, // 58
  { "menvcfgh", "menvcfgh", "", 0x31A,  {} , true }, // 59
  { "mstateen0h", "mstateen0h", "", 0x31C,  {} , true }, // 60
  { "mstateen1h", "mstateen1h", "", 0x31D,  {} , true }, // 61
  { "mstateen2h", "mstateen2h", "", 0x31E,  {} , true }, // 62
  { "mstateen3h", "mstateen3h", "", 0x31F,  {} , true }, // 63
  { "mcountinhibit", "mucounteren", "", 0x320,  {} , false }, // 64
  { "mhpmevent3", "mhpmevent3", "", 0x323,  {} , false }, // 65
  { "mhpmevent4", "mhpmevent4", "", 0x324,  {} , false }, // 66
  { "mhpmevent5", "mhpmevent5", "", 0x325,  {} , false }, // 67
  { "mhpmevent6", "mhpmevent6", "", 0x326,  {} , false }, // 68
  { "mhpmevent7", "mhpmevent7", "", 0x327,  {} , false }, // 69
  { "mhpmevent8", "mhpmevent8", "", 0x328,  {} , false }, // 70
  { "mhpmevent9", "mhpmevent9", "", 0x329,  {} , false }, // 71
  { "mhpmevent10", "mhpmevent10", "", 0x32A,  {} , false }, // 72
  { "mhpmevent11", "mhpmevent11", "", 0x32B,  {} , false }, // 73
  { "mhpmevent12", "mhpmevent12", "", 0x32C,  {} , false }, // 74
  { "mhpmevent13", "mhpmevent13", "", 0x32D,  {} , false }, // 75
  { "mhpmevent14", "mhpmevent14", "", 0x32E,  {} , false }, // 76
  { "mhpmevent15", "mhpmevent15", "", 0x32F,  {} , false }, // 77
  { "mhpmevent16", "mhpmevent16", "", 0x330,  {} , false }, // 78
  { "mhpmevent17", "mhpmevent17", "", 0x331,  {} , false }, // 79
  { "mhpmevent18", "mhpmevent18", "", 0x332,  {} , false }, // 80
  { "mhpmevent19", "mhpmevent19", "", 0x333,  {} , false }, // 81
  { "mhpmevent20", "mhpmevent20", "", 0x334,  {} , false }, // 82
  { "mhpmevent21", "mhpmevent21", "", 0x335,  {} , false }, // 83
  { "mhpmevent22", "mhpmevent22", "", 0x336,  {} , false }, // 84
  { "mhpmevent23", "mhpmevent23", "", 0x337,  {} , false }, // 85
  { "mhpmevent24", "mhpmevent24", "", 0x338,  {} , false }, // 86
  { "mhpmevent25", "mhpmevent25", "", 0x339,  {} , false }, // 87
  { "mhpmevent26", "mhpmevent26", "", 0x33A,  {} , false }, // 88
  { "mhpmevent27", "mhpmevent27", "", 0x33B,  {} , false }, // 89
  { "mhpmevent28", "mhpmevent28", "", 0x33C,  {} , false }, // 90
  { "mhpmevent29", "mhpmevent29", "", 0x33D,  {} , false }, // 91
  { "mhpmevent30", "mhpmevent30", "", 0x33E,  {} , false }, // 92
  { "mhpmevent31", "mhpmevent31", "", 0x33F,  {} , false }, // 93
  { "mscratch", "mscratch", "", 0x340,  {} , false }, // 94
  { "mepc", "mepc", "", 0x341,  {} , false }, // 95
  { "mcause", "mcause", "", 0x342,  {} , false }, // 96
  { "mtval", "mtval", "mbadaddr", 0x343,  {} , false }, // 97
  { "mip", "mip", "", 0x344,  {} , false }, // 98
  { "mtinst", "mtinst", "", 0x34A,  {} , false }, // 99
  { "mtval2", "mtval2", "", 0x34B,  {} , false }, // 100
  { "pmpcfg0", "pmpcfg0", "", 0x3A0,  {} , false }, // 101
  { "pmpcfg1", "pmpcfg1", "", 0x3A1,  {} , true }, // 102
  { "pmpcfg2", "pmpcfg2", "", 0x3A2,  {} , false }, // 103
  { "pmpcfg3", "pmpcfg3", "", 0x3A3,  {} , true }, // 104
  { "pmpcfg4", "pmpcfg4", "", 0x3A4,  {} , false }, // 105
  { "pmpcfg5", "pmpcfg5", "", 0x3A5,  {} , true }, // 106
  { "pmpcfg6", "pmpcfg6", "", 0x3A6,  {} , false }, // 107
  { "pmpcfg7", "pmpcfg7", "", 0x3A7,  {} , true }, // 108
  { "pmpcfg8", "pmpcfg8", "", 0x3A8,  {} , false }, // 109
  { "pmpcfg9", "pmpcfg9", "", 0x3A9,  {} , true }, // 110
  { "pmpcfg10", "pmpcfg10", "", 0x3AA,  {} , false }, // 111
  { "pmpcfg11", "pmpcfg11", "", 0x3AB,  {} , true }, // 112
  { "pmpcfg12", "pmpcfg12", "", 0x3AC,  {} , false }, // 113
  { "pmpcfg13", "pmpcfg13", "", 0x3AD,  {} , true }, // 114
  { "pmpcfg14", "pmpcfg14", "", 0x3AE,  {} , false }, // 115
  { "pmpcfg15", "pmpcfg15", "", 0x3AF,  {} , true }, // 116
  { "pmpaddr0", "pmpaddr0", "", 0x3B0,  {} , false }, // 117
  { "pmpaddr1", "pmpaddr1", "", 0x3B1,  {} , false }, // 118
  { "pmpaddr2", "pmpaddr2", "", 0x3B2,  {} , false }, // 119
  { "pmpaddr3", "pmpaddr3", "", 0x3B3,  {} , false }, // 120
  { "pmpaddr4", "pmpaddr4", "", 0x3B4,  {} , false }, // 121
  { "pmpaddr5", "pmpaddr5", "", 0x3B5,  {} , false }, // 122
  { "pmpaddr6", "pmpaddr6", "", 0x3B6,  {} , false }, // 123
  { "pmpaddr7", "pmpaddr7", "", 0x3B7,  {} , false }, // 124
  { "pmpaddr8", "pmpaddr8", "", 0x3B8,  {} , false }, // 125
  { "pmpaddr9", "pmpaddr9", "", 0x3B9,  {} , false }, // 126
  { "pmpaddr10", "pmpaddr10", "", 0x3BA,  {} , false }, // 127
  { "pmpaddr11", "pmpaddr11", "", 0x3BB,  {} , false }, // 128
  { "pmpaddr12", "pmpaddr12", "", 0x3BC,  {} , false }, // 129
  { "pmpaddr13", "pmpaddr13", "", 0x3BD,  {} , false }, // 130
  { "pmpaddr14", "pmpaddr14", "", 0x3BE,  {} , false }, // 131
  { "pmpaddr15", "pmpaddr15", "", 0x3BF,  {} , false }, // 132
  { "pmpaddr16", "pmpaddr16", "", 0x3C0,  {} , false }, // 133
  { "pmpaddr17", "pmpaddr17", "", 0x3C1,  {} , false }, // 134
  { "pmpaddr18", "pmpaddr18", "", 0x3C2,  {} , false }, // 135
  { "pmpaddr19", "pmpaddr19", "", 0x3C3,  {} , false }, // 136
  { "pmpaddr20", "pmpaddr20", "", 0x3C4,  {} , false }, // 137
  { "pmpaddr21", "pmpaddr21", "", 0x3C5,  {} , false }, // 138
  { "pmpaddr22", "pmpaddr22", "", 0x3C6,  {} , false }, // 139
  { "pmpaddr23", "pmpaddr23", "", 0x3C7,  {} , false }, // 140
  { "pmpaddr24", "pmpaddr24", "", 0x3C8,  {} , false }, // 141
  { "pmpaddr25", "pmpaddr25", "", 0x3C9,  {} , false }, // 142
  { "pmpaddr26", "pmpaddr26", "", 0x3CA,  {} , false }, // 143
  { "pmpaddr27", "pmpaddr27", "", 0x3CB,  {} , false }, // 144
  { "pmpaddr28", "pmpaddr28", "", 0x3CC,  {} , false }, // 145
  { "pmpaddr29", "pmpaddr29", "", 0x3CD,  {} , false }, // 146
  { "pmpaddr30", "pmpaddr30", "", 0x3CE,  {} , false }, // 147
  { "pmpaddr31", "pmpaddr31", "", 0x3CF,  {} , false }, // 148
  { "pmpaddr32", "pmpaddr32", "", 0x3D0,  {} , false }, // 149
  { "pmpaddr33", "pmpaddr33", "", 0x3D1,  {} , false }, // 150
  { "pmpaddr34", "pmpaddr34", "", 0x3D2,  {} , false }, // 151
  { "pmpaddr35", "pmpaddr35", "", 0x3D3,  {} , false }, // 152
  { "pmpaddr36", "pmpaddr36", "", 0x3D4,  {} , false }, // 153
  { "pmpaddr37", "pmpaddr37", "", 0x3D5,  {} , false }, // 154
  { "pmpaddr38", "pmpaddr38", "", 0x3D6,  {} , false }, // 155
  { "pmpaddr39", "pmpaddr39", "", 0x3D7,  {} , false }, // 156
  { "pmpaddr40", "pmpaddr40", "", 0x3D8,  {} , false }, // 157
  { "pmpaddr41", "pmpaddr41", "", 0x3D9,  {} , false }, // 158
  { "pmpaddr42", "pmpaddr42", "", 0x3DA,  {} , false }, // 159
  { "pmpaddr43", "pmpaddr43", "", 0x3DB,  {} , false }, // 160
  { "pmpaddr44", "pmpaddr44", "", 0x3DC,  {} , false }, // 161
  { "pmpaddr45", "pmpaddr45", "", 0x3DD,  {} , false }, // 162
  { "pmpaddr46", "pmpaddr46", "", 0x3DE,  {} , false }, // 163
  { "pmpaddr47", "pmpaddr47", "", 0x3DF,  {} , false }, // 164
  { "pmpaddr48", "pmpaddr48", "", 0x3E0,  {} , false }, // 165
  { "pmpaddr49", "pmpaddr49", "", 0x3E1,  {} , false }, // 166
  { "pmpaddr50", "pmpaddr50", "", 0x3E2,  {} , false }, // 167
  { "pmpaddr51", "pmpaddr51", "", 0x3E3,  {} , false }, // 168
  { "pmpaddr52", "pmpaddr52", "", 0x3E4,  {} , false }, // 169
  { "pmpaddr53", "pmpaddr53", "", 0x3E5,  {} , false }, // 170
  { "pmpaddr54", "pmpaddr54", "", 0x3E6,  {} , false }, // 171
  { "pmpaddr55", "pmpaddr55", "", 0x3E7,  {} , false }, // 172
  { "pmpaddr56", "pmpaddr56", "", 0x3E8,  {} , false }, // 173
  { "pmpaddr57", "pmpaddr57", "", 0x3E9,  {} , false }, // 174
  { "pmpaddr58", "pmpaddr58", "", 0x3EA,  {} , false }, // 175
  { "pmpaddr59", "pmpaddr59", "", 0x3EB,  {} , false }, // 176
  { "pmpaddr60", "pmpaddr60", "", 0x3EC,  {} , false }, // 177
  { "pmpaddr61", "pmpaddr61", "", 0x3ED,  {} , false }, // 178
  { "pmpaddr62", "pmpaddr62", "", 0x3EE,  {} , false }, // 179
  { "pmpaddr63", "pmpaddr63", "", 0x3EF,  {} , false }, // 180
  { "scontext", "scontext", "", 0x5A8,  {} , false }, // 181
  { "hstatus", "hstatus", "", 0x600,  {} , false }, // 182
  { "hedeleg", "hedeleg", "", 0x602,  {} , false }, // 183
  { "hideleg", "hideleg", "", 0x603,  {} , false }, // 184
  { "hie", "hie", "", 0x604,  {} , false }, // 185
  { "htimedelta", "htimedelta", "", 0x605,  {} , false }, // 186
  { "hcounteren", "hcounteren", "", 0x606,  {} , false }, // 187
  { "hgeie", "hgeie", "", 0x607,  {} , false }, // 188
  { "henvcfg", "henvcfg", "", 0x60A,  {} , false }, // 189
  { "hstateen0", "hstateen0", "", 0x60C,  {} , false }, // 190
  { "hstateen1", "hstateen1", "", 0x60D,  {} , false }, // 191
  { "hstateen2", "hstateen2", "", 0x60E,  {} , false }, // 192
  { "hstateen3", "hstateen3", "", 0x60F,  {} , false }, // 193
  { "htimedeltah", "htimedeltah", "", 0x615,  {} , true }, // 194
  { "henvcfgh", "henvcfgh", "", 0x61A,  {} , true }, // 195
  { "hstateen0h", "hstateen0h", "", 0x61C,  {} , true }, // 196
  { "hstateen1h", "hstateen1h", "", 0x61D,  {} , true }, // 197
  { "hstateen2h", "hstateen2h", "", 0x61E,  {} , true }, // 198
  { "hstateen3h", "hstateen3h", "", 0x61F,  {} , true }, // 199
  { "htval", "htval", "", 0x643,  {} , false }, // 200
  { "hip", "hip", "", 0x644,  {} , false }, // 201
  { "hvip", "hvip", "", 0x645,  {} , false }, // 202
  { "htinst", "htinst", "", 0x64A,  {} , false }, // 203
  { "hgatp", "hgatp", "", 0x680,  {} , false }, // 204
  { "hcontext", "hcontext", "", 0x6A8,  {} , false }, // 205
  { "mhpmevent3h", "mhpmevent3h", "", 0x723,  {} , true }, // 206
  { "mhpmevent4h", "mhpmevent4h", "", 0x724,  {} , true }, // 207
  { "mhpmevent5h", "mhpmevent5h", "", 0x725,  {} , true }, // 208
  { "mhpmevent6h", "mhpmevent6h", "", 0x726,  {} , true }, // 209
  { "mhpmevent7h", "mhpmevent7h", "", 0x727,  {} , true }, // 210
  { "mhpmevent8h", "mhpmevent8h", "", 0x728,  {} , true }, // 211
  { "mhpmevent9h", "mhpmevent9h", "", 0x729,  {} , true }, // 212
  { "mhpmevent10h", "mhpmevent10h", "", 0x72A,  {} , true }, // 213
  { "mhpmevent11h", "mhpmevent11h", "", 0x72B,  {} , true }, // 214
  { "mhpmevent12h", "mhpmevent12h", "", 0x72C,  {} , true }, // 215
  { "mhpmevent13h", "mhpmevent13h", "", 0x72D,  {} , true }, // 216
  { "mhpmevent14h", "mhpmevent14h", "", 0x72E,  {} , true }, // 217
  { "mhpmevent15h", "mhpmevent15h", "", 0x72F,  {} , true }, // 218
  { "mhpmevent16h", "mhpmevent16h", "", 0x730,  {} , true }, // 219
  { "mhpmevent17h", "mhpmevent17h", "", 0x731,  {} , true }, // 220
  { "mhpmevent18h", "mhpmevent18h", "", 0x732,  {} , true }, // 221
  { "mhpmevent19h", "mhpmevent19h", "", 0x733,  {} , true }, // 222
  { "mhpmevent20h", "mhpmevent20h", "", 0x734,  {} , true }, // 223
  { "mhpmevent21h", "mhpmevent21h", "", 0x735,  {} , true }, // 224
  { "mhpmevent22h", "mhpmevent22h", "", 0x736,  {} , true }, // 225
  { "mhpmevent23h", "mhpmevent23h", "", 0x737,  {} , true }, // 226
  { "mhpmevent24h", "mhpmevent24h", "", 0x738,  {} , true }, // 227
  { "mhpmevent25h", "mhpmevent25h", "", 0x739,  {} , true }, // 228
  { "mhpmevent26h", "mhpmevent26h", "", 0x73A,  {} , true }, // 229
  { "mhpmevent27h", "mhpmevent27h", "", 0x73B,  {} , true }, // 230
  { "mhpmevent28h", "mhpmevent28h", "", 0x73C,  {} , true }, // 231
  { "mhpmevent29h", "mhpmevent29h", "", 0x73D,  {} , true }, // 232
  { "mhpmevent30h", "mhpmevent30h", "", 0x73E,  {} , true }, // 233
  { "mhpmevent31h", "mhpmevent31h", "", 0x73F,  {} , true }, // 234
  { "mseccfg", "mseccfg", "", 0x747,  {} , false }, // 235
  { "mseccfgh", "mseccfgh", "", 0x757,  {} , true }, // 236
  { "tselect", "tselect", "", 0x7A0,  {} , false }, // 237
  { "tdata1", "tdata1", "", 0x7A1,  {} , false }, // 238
  { "tdata2", "tdata2", "", 0x7A2,  {} , false }, // 239
  { "tdata3", "tdata3", "", 0x7A3,  {} , false }, // 240
  { "mcontext", "mcontext", "", 0x7A8,  {} , false }, // 241
  { "dcsr", "dcsr", "", 0x7B0,  {} , false }, // 242
  { "dpc", "dpc", "", 0x7B1,  {} , false }, // 243
  { "dscratch0", "dscratch", "", 0x7B2,  {} , false }, // 244
  { "dscratch1", "dscratch1", "", 0x7B3,  {} , false }, // 245
  { "mcycle", "mcycle", "", 0xB00,  {} , false }, // 246
  { "minstret", "minstret", "", 0xB02,  {} , false }, // 247
  { "mhpmcounter3", "mhpmcounter3", "", 0xB03,  {} , false }, // 248
  { "mhpmcounter4", "mhpmcounter4", "", 0xB04,  {} , false }, // 249
  { "mhpmcounter5", "mhpmcounter5", "", 0xB05,  {} , false }, // 250
  { "mhpmcounter6", "mhpmcounter6", "", 0xB06,  {} , false }, // 251
  { "mhpmcounter7", "mhpmcounter7", "", 0xB07,  {} , false }, // 252
  { "mhpmcounter8", "mhpmcounter8", "", 0xB08,  {} , false }, // 253
  { "mhpmcounter9", "mhpmcounter9", "", 0xB09,  {} , false }, // 254
  { "mhpmcounter10", "mhpmcounter10", "", 0xB0A,  {} , false }, // 255
  { "mhpmcounter11", "mhpmcounter11", "", 0xB0B,  {} , false }, // 256
  { "mhpmcounter12", "mhpmcounter12", "", 0xB0C,  {} , false }, // 257
  { "mhpmcounter13", "mhpmcounter13", "", 0xB0D,  {} , false }, // 258
  { "mhpmcounter14", "mhpmcounter14", "", 0xB0E,  {} , false }, // 259
  { "mhpmcounter15", "mhpmcounter15", "", 0xB0F,  {} , false }, // 260
  { "mhpmcounter16", "mhpmcounter16", "", 0xB10,  {} , false }, // 261
  { "mhpmcounter17", "mhpmcounter17", "", 0xB11,  {} , false }, // 262
  { "mhpmcounter18", "mhpmcounter18", "", 0xB12,  {} , false }, // 263
  { "mhpmcounter19", "mhpmcounter19", "", 0xB13,  {} , false }, // 264
  { "mhpmcounter20", "mhpmcounter20", "", 0xB14,  {} , false }, // 265
  { "mhpmcounter21", "mhpmcounter21", "", 0xB15,  {} , false }, // 266
  { "mhpmcounter22", "mhpmcounter22", "", 0xB16,  {} , false }, // 267
  { "mhpmcounter23", "mhpmcounter23", "", 0xB17,  {} , false }, // 268
  { "mhpmcounter24", "mhpmcounter24", "", 0xB18,  {} , false }, // 269
  { "mhpmcounter25", "mhpmcounter25", "", 0xB19,  {} , false }, // 270
  { "mhpmcounter26", "mhpmcounter26", "", 0xB1A,  {} , false }, // 271
  { "mhpmcounter27", "mhpmcounter27", "", 0xB1B,  {} , false }, // 272
  { "mhpmcounter28", "mhpmcounter28", "", 0xB1C,  {} , false }, // 273
  { "mhpmcounter29", "mhpmcounter29", "", 0xB1D,  {} , false }, // 274
  { "mhpmcounter30", "mhpmcounter30", "", 0xB1E,  {} , false }, // 275
  { "mhpmcounter31", "mhpmcounter31", "", 0xB1F,  {} , false }, // 276
  { "mcycleh", "mcycleh", "", 0xB80,  {} , true }, // 277
  { "minstreth", "minstreth", "", 0xB82,  {} , true }, // 278
  { "mhpmcounter3h", "mhpmcounter3h", "", 0xB83,  {} , true }, // 279
  { "mhpmcounter4h", "mhpmcounter4h", "", 0xB84,  {} , true }, // 280
  { "mhpmcounter5h", "mhpmcounter5h", "", 0xB85,  {} , true }, // 281
  { "mhpmcounter6h", "mhpmcounter6h", "", 0xB86,  {} , true }, // 282
  { "mhpmcounter7h", "mhpmcounter7h", "", 0xB87,  {} , true }, // 283
  { "mhpmcounter8h", "mhpmcounter8h", "", 0xB88,  {} , true }, // 284
  { "mhpmcounter9h", "mhpmcounter9h", "", 0xB89,  {} , true }, // 285
  { "mhpmcounter10h", "mhpmcounter10h", "", 0xB8A,  {} , true }, // 286
  { "mhpmcounter11h", "mhpmcounter11h", "", 0xB8B,  {} , true }, // 287
  { "mhpmcounter12h", "mhpmcounter12h", "", 0xB8C,  {} , true }, // 288
  { "mhpmcounter13h", "mhpmcounter13h", "", 0xB8D,  {} , true }, // 289
  { "mhpmcounter14h", "mhpmcounter14h", "", 0xB8E,  {} , true }, // 290
  { "mhpmcounter15h", "mhpmcounter15h", "", 0xB8F,  {} , true }, // 291
  { "mhpmcounter16h", "mhpmcounter16h", "", 0xB90,  {} , true }, // 292
  { "mhpmcounter17h", "mhpmcounter17h", "", 0xB91,  {} , true }, // 293
  { "mhpmcounter18h", "mhpmcounter18h", "", 0xB92,  {} , true }, // 294
  { "mhpmcounter19h", "mhpmcounter19h", "", 0xB93,  {} , true }, // 295
  { "mhpmcounter20h", "mhpmcounter20h", "", 0xB94,  {} , true }, // 296
  { "mhpmcounter21h", "mhpmcounter21h", "", 0xB95,  {} , true }, // 297
  { "mhpmcounter22h", "mhpmcounter22h", "", 0xB96,  {} , true }, // 298
  { "mhpmcounter23h", "mhpmcounter23h", "", 0xB97,  {} , true }, // 299
  { "mhpmcounter24h", "mhpmcounter24h", "", 0xB98,  {} , true }, // 300
  { "mhpmcounter25h", "mhpmcounter25h", "", 0xB99,  {} , true }, // 301
  { "mhpmcounter26h", "mhpmcounter26h", "", 0xB9A,  {} , true }, // 302
  { "mhpmcounter27h", "mhpmcounter27h", "", 0xB9B,  {} , true }, // 303
  { "mhpmcounter28h", "mhpmcounter28h", "", 0xB9C,  {} , true }, // 304
  { "mhpmcounter29h", "mhpmcounter29h", "", 0xB9D,  {} , true }, // 305
  { "mhpmcounter30h", "mhpmcounter30h", "", 0xB9E,  {} , true }, // 306
  { "mhpmcounter31h", "mhpmcounter31h", "", 0xB9F,  {} , true }, // 307
  { "cycle", "cycle", "", 0xC00,  {} , false }, // 308
  { "time", "time", "", 0xC01,  {} , false }, // 309
  { "instret", "instret", "", 0xC02,  {} , false }, // 310
  { "hpmcounter3", "hpmcounter3", "", 0xC03,  {} , false }, // 311
  { "hpmcounter4", "hpmcounter4", "", 0xC04,  {} , false }, // 312
  { "hpmcounter5", "hpmcounter5", "", 0xC05,  {} , false }, // 313
  { "hpmcounter6", "hpmcounter6", "", 0xC06,  {} , false }, // 314
  { "hpmcounter7", "hpmcounter7", "", 0xC07,  {} , false }, // 315
  { "hpmcounter8", "hpmcounter8", "", 0xC08,  {} , false }, // 316
  { "hpmcounter9", "hpmcounter9", "", 0xC09,  {} , false }, // 317
  { "hpmcounter10", "hpmcounter10", "", 0xC0A,  {} , false }, // 318
  { "hpmcounter11", "hpmcounter11", "", 0xC0B,  {} , false }, // 319
  { "hpmcounter12", "hpmcounter12", "", 0xC0C,  {} , false }, // 320
  { "hpmcounter13", "hpmcounter13", "", 0xC0D,  {} , false }, // 321
  { "hpmcounter14", "hpmcounter14", "", 0xC0E,  {} , false }, // 322
  { "hpmcounter15", "hpmcounter15", "", 0xC0F,  {} , false }, // 323
  { "hpmcounter16", "hpmcounter16", "", 0xC10,  {} , false }, // 324
  { "hpmcounter17", "hpmcounter17", "", 0xC11,  {} , false }, // 325
  { "hpmcounter18", "hpmcounter18", "", 0xC12,  {} , false }, // 326
  { "hpmcounter19", "hpmcounter19", "", 0xC13,  {} , false }, // 327
  { "hpmcounter20", "hpmcounter20", "", 0xC14,  {} , false }, // 328
  { "hpmcounter21", "hpmcounter21", "", 0xC15,  {} , false }, // 329
  { "hpmcounter22", "hpmcounter22", "", 0xC16,  {} , false }, // 330
  { "hpmcounter23", "hpmcounter23", "", 0xC17,  {} , false }, // 331
  { "hpmcounter24", "hpmcounter24", "", 0xC18,  {} , false }, // 332
  { "hpmcounter25", "hpmcounter25", "", 0xC19,  {} , false }, // 333
  { "hpmcounter26", "hpmcounter26", "", 0xC1A,  {} , false }, // 334
  { "hpmcounter27", "hpmcounter27", "", 0xC1B,  {} , false }, // 335
  { "hpmcounter28", "hpmcounter28", "", 0xC1C,  {} , false }, // 336
  { "hpmcounter29", "hpmcounter29", "", 0xC1D,  {} , false }, // 337
  { "hpmcounter30", "hpmcounter30", "", 0xC1E,  {} , false }, // 338
  { "hpmcounter31", "hpmcounter31", "", 0xC1F,  {} , false }, // 339
  { "vl", "vl", "", 0xC20,  {} , false }, // 340
  { "vtype", "vtype", "", 0xC21,  {} , false }, // 341
  { "vlenb", "vlenb", "", 0xC22,  {} , false }, // 342
  { "cycleh", "cycleh", "", 0xC80,  {} , true }, // 343
  { "timeh", "timeh", "", 0xC81,  {} , true }, // 344
  { "instreth", "instreth", "", 0xC82,  {} , true }, // 345
  { "hpmcounter3h", "hpmcounter3h", "", 0xC83,  {} , true }, // 346
  { "hpmcounter4h", "hpmcounter4h", "", 0xC84,  {} , true }, // 347
  { "hpmcounter5h", "hpmcounter5h", "", 0xC85,  {} , true }, // 348
  { "hpmcounter6h", "hpmcounter6h", "", 0xC86,  {} , true }, // 349
  { "hpmcounter7h", "hpmcounter7h", "", 0xC87,  {} , true }, // 350
  { "hpmcounter8h", "hpmcounter8h", "", 0xC88,  {} , true }, // 351
  { "hpmcounter9h", "hpmcounter9h", "", 0xC89,  {} , true }, // 352
  { "hpmcounter10h", "hpmcounter10h", "", 0xC8A,  {} , true }, // 353
  { "hpmcounter11h", "hpmcounter11h", "", 0xC8B,  {} , true }, // 354
  { "hpmcounter12h", "hpmcounter12h", "", 0xC8C,  {} , true }, // 355
  { "hpmcounter13h", "hpmcounter13h", "", 0xC8D,  {} , true }, // 356
  { "hpmcounter14h", "hpmcounter14h", "", 0xC8E,  {} , true }, // 357
  { "hpmcounter15h", "hpmcounter15h", "", 0xC8F,  {} , true }, // 358
  { "hpmcounter16h", "hpmcounter16h", "", 0xC90,  {} , true }, // 359
  { "hpmcounter17h", "hpmcounter17h", "", 0xC91,  {} , true }, // 360
  { "hpmcounter18h", "hpmcounter18h", "", 0xC92,  {} , true }, // 361
  { "hpmcounter19h", "hpmcounter19h", "", 0xC93,  {} , true }, // 362
  { "hpmcounter20h", "hpmcounter20h", "", 0xC94,  {} , true }, // 363
  { "hpmcounter21h", "hpmcounter21h", "", 0xC95,  {} , true }, // 364
  { "hpmcounter22h", "hpmcounter22h", "", 0xC96,  {} , true }, // 365
  { "hpmcounter23h", "hpmcounter23h", "", 0xC97,  {} , true }, // 366
  { "hpmcounter24h", "hpmcounter24h", "", 0xC98,  {} , true }, // 367
  { "hpmcounter25h", "hpmcounter25h", "", 0xC99,  {} , true }, // 368
  { "hpmcounter26h", "hpmcounter26h", "", 0xC9A,  {} , true }, // 369
  { "hpmcounter27h", "hpmcounter27h", "", 0xC9B,  {} , true }, // 370
  { "hpmcounter28h", "hpmcounter28h", "", 0xC9C,  {} , true }, // 371
  { "hpmcounter29h", "hpmcounter29h", "", 0xC9D,  {} , true }, // 372
  { "hpmcounter30h", "hpmcounter30h", "", 0xC9E,  {} , true }, // 373
  { "hpmcounter31h", "hpmcounter31h", "", 0xC9F,  {} , true }, // 374
  { "scountovf", "scountovf", "", 0xDA0,  {} , false }, // 375
  { "hgeip", "hgeip", "", 0xE12,  {} , false }, // 376
  { "mvendorid", "mvendorid", "", 0xF11,  {} , false }, // 377
  { "marchid", "marchid", "", 0xF12,  {} , false }, // 378
  { "mimpid", "mimpid", "", 0xF13,  {} , false }, // 379
  { "mhartid", "mhartid", "", 0xF14,  {} , false }, // 380
  { "mconfigptr", "mconfigptr", "", 0xF15,  {} , false }, // 381
 };

const SysReg *lookupSysRegByEncoding(uint16_t Encoding) {
  struct KeyType {
    uint16_t Encoding;
  };
  KeyType Key = {Encoding};
  auto Table = makeArrayRef(SysRegsList);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const SysReg &LHS, const KeyType &RHS) {
      if (LHS.Encoding < RHS.Encoding)
        return true;
      if (LHS.Encoding > RHS.Encoding)
        return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.Encoding != Idx->Encoding)
    return nullptr;
  return &*Idx;
}

const SysReg *lookupSysRegByAltName(StringRef AltName) {
  struct IndexType {
    const char * AltName;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { "CYCLE", 308 },
    { "CYCLEH", 343 },
    { "DCSR", 242 },
    { "DPC", 243 },
    { "DSCRATCH", 244 },
    { "DSCRATCH1", 245 },
    { "FCSR", 3 },
    { "FFLAGS", 1 },
    { "FRM", 2 },
    { "HCONTEXT", 205 },
    { "HCOUNTEREN", 187 },
    { "HEDELEG", 183 },
    { "HENVCFG", 189 },
    { "HENVCFGH", 195 },
    { "HGATP", 204 },
    { "HGEIE", 188 },
    { "HGEIP", 376 },
    { "HIDELEG", 184 },
    { "HIE", 185 },
    { "HIP", 201 },
    { "HPMCOUNTER10", 318 },
    { "HPMCOUNTER10H", 353 },
    { "HPMCOUNTER11", 319 },
    { "HPMCOUNTER11H", 354 },
    { "HPMCOUNTER12", 320 },
    { "HPMCOUNTER12H", 355 },
    { "HPMCOUNTER13", 321 },
    { "HPMCOUNTER13H", 356 },
    { "HPMCOUNTER14", 322 },
    { "HPMCOUNTER14H", 357 },
    { "HPMCOUNTER15", 323 },
    { "HPMCOUNTER15H", 358 },
    { "HPMCOUNTER16", 324 },
    { "HPMCOUNTER16H", 359 },
    { "HPMCOUNTER17", 325 },
    { "HPMCOUNTER17H", 360 },
    { "HPMCOUNTER18", 326 },
    { "HPMCOUNTER18H", 361 },
    { "HPMCOUNTER19", 327 },
    { "HPMCOUNTER19H", 362 },
    { "HPMCOUNTER20", 328 },
    { "HPMCOUNTER20H", 363 },
    { "HPMCOUNTER21", 329 },
    { "HPMCOUNTER21H", 364 },
    { "HPMCOUNTER22", 330 },
    { "HPMCOUNTER22H", 365 },
    { "HPMCOUNTER23", 331 },
    { "HPMCOUNTER23H", 366 },
    { "HPMCOUNTER24", 332 },
    { "HPMCOUNTER24H", 367 },
    { "HPMCOUNTER25", 333 },
    { "HPMCOUNTER25H", 368 },
    { "HPMCOUNTER26", 334 },
    { "HPMCOUNTER26H", 369 },
    { "HPMCOUNTER27", 335 },
    { "HPMCOUNTER27H", 370 },
    { "HPMCOUNTER28", 336 },
    { "HPMCOUNTER28H", 371 },
    { "HPMCOUNTER29", 337 },
    { "HPMCOUNTER29H", 372 },
    { "HPMCOUNTER3", 311 },
    { "HPMCOUNTER30", 338 },
    { "HPMCOUNTER30H", 373 },
    { "HPMCOUNTER31", 339 },
    { "HPMCOUNTER31H", 374 },
    { "HPMCOUNTER3H", 346 },
    { "HPMCOUNTER4", 312 },
    { "HPMCOUNTER4H", 347 },
    { "HPMCOUNTER5", 313 },
    { "HPMCOUNTER5H", 348 },
    { "HPMCOUNTER6", 314 },
    { "HPMCOUNTER6H", 349 },
    { "HPMCOUNTER7", 315 },
    { "HPMCOUNTER7H", 350 },
    { "HPMCOUNTER8", 316 },
    { "HPMCOUNTER8H", 351 },
    { "HPMCOUNTER9", 317 },
    { "HPMCOUNTER9H", 352 },
    { "HSTATEEN0", 190 },
    { "HSTATEEN0H", 196 },
    { "HSTATEEN1", 191 },
    { "HSTATEEN1H", 197 },
    { "HSTATEEN2", 192 },
    { "HSTATEEN2H", 198 },
    { "HSTATEEN3", 193 },
    { "HSTATEEN3H", 199 },
    { "HSTATUS", 182 },
    { "HTIMEDELTA", 186 },
    { "HTIMEDELTAH", 194 },
    { "HTINST", 203 },
    { "HTVAL", 200 },
    { "HVIP", 202 },
    { "INSTRET", 310 },
    { "INSTRETH", 345 },
    { "MARCHID", 378 },
    { "MCAUSE", 96 },
    { "MCONFIGPTR", 381 },
    { "MCONTEXT", 241 },
    { "MCOUNTEREN", 52 },
    { "MCYCLE", 246 },
    { "MCYCLEH", 277 },
    { "MEDELEG", 48 },
    { "MENVCFG", 53 },
    { "MENVCFGH", 59 },
    { "MEPC", 95 },
    { "MHARTID", 380 },
    { "MHPMCOUNTER10", 255 },
    { "MHPMCOUNTER10H", 286 },
    { "MHPMCOUNTER11", 256 },
    { "MHPMCOUNTER11H", 287 },
    { "MHPMCOUNTER12", 257 },
    { "MHPMCOUNTER12H", 288 },
    { "MHPMCOUNTER13", 258 },
    { "MHPMCOUNTER13H", 289 },
    { "MHPMCOUNTER14", 259 },
    { "MHPMCOUNTER14H", 290 },
    { "MHPMCOUNTER15", 260 },
    { "MHPMCOUNTER15H", 291 },
    { "MHPMCOUNTER16", 261 },
    { "MHPMCOUNTER16H", 292 },
    { "MHPMCOUNTER17", 262 },
    { "MHPMCOUNTER17H", 293 },
    { "MHPMCOUNTER18", 263 },
    { "MHPMCOUNTER18H", 294 },
    { "MHPMCOUNTER19", 264 },
    { "MHPMCOUNTER19H", 295 },
    { "MHPMCOUNTER20", 265 },
    { "MHPMCOUNTER20H", 296 },
    { "MHPMCOUNTER21", 266 },
    { "MHPMCOUNTER21H", 297 },
    { "MHPMCOUNTER22", 267 },
    { "MHPMCOUNTER22H", 298 },
    { "MHPMCOUNTER23", 268 },
    { "MHPMCOUNTER23H", 299 },
    { "MHPMCOUNTER24", 269 },
    { "MHPMCOUNTER24H", 300 },
    { "MHPMCOUNTER25", 270 },
    { "MHPMCOUNTER25H", 301 },
    { "MHPMCOUNTER26", 271 },
    { "MHPMCOUNTER26H", 302 },
    { "MHPMCOUNTER27", 272 },
    { "MHPMCOUNTER27H", 303 },
    { "MHPMCOUNTER28", 273 },
    { "MHPMCOUNTER28H", 304 },
    { "MHPMCOUNTER29", 274 },
    { "MHPMCOUNTER29H", 305 },
    { "MHPMCOUNTER3", 248 },
    { "MHPMCOUNTER30", 275 },
    { "MHPMCOUNTER30H", 306 },
    { "MHPMCOUNTER31", 276 },
    { "MHPMCOUNTER31H", 307 },
    { "MHPMCOUNTER3H", 279 },
    { "MHPMCOUNTER4", 249 },
    { "MHPMCOUNTER4H", 280 },
    { "MHPMCOUNTER5", 250 },
    { "MHPMCOUNTER5H", 281 },
    { "MHPMCOUNTER6", 251 },
    { "MHPMCOUNTER6H", 282 },
    { "MHPMCOUNTER7", 252 },
    { "MHPMCOUNTER7H", 283 },
    { "MHPMCOUNTER8", 253 },
    { "MHPMCOUNTER8H", 284 },
    { "MHPMCOUNTER9", 254 },
    { "MHPMCOUNTER9H", 285 },
    { "MHPMEVENT10", 72 },
    { "MHPMEVENT10H", 213 },
    { "MHPMEVENT11", 73 },
    { "MHPMEVENT11H", 214 },
    { "MHPMEVENT12", 74 },
    { "MHPMEVENT12H", 215 },
    { "MHPMEVENT13", 75 },
    { "MHPMEVENT13H", 216 },
    { "MHPMEVENT14", 76 },
    { "MHPMEVENT14H", 217 },
    { "MHPMEVENT15", 77 },
    { "MHPMEVENT15H", 218 },
    { "MHPMEVENT16", 78 },
    { "MHPMEVENT16H", 219 },
    { "MHPMEVENT17", 79 },
    { "MHPMEVENT17H", 220 },
    { "MHPMEVENT18", 80 },
    { "MHPMEVENT18H", 221 },
    { "MHPMEVENT19", 81 },
    { "MHPMEVENT19H", 222 },
    { "MHPMEVENT20", 82 },
    { "MHPMEVENT20H", 223 },
    { "MHPMEVENT21", 83 },
    { "MHPMEVENT21H", 224 },
    { "MHPMEVENT22", 84 },
    { "MHPMEVENT22H", 225 },
    { "MHPMEVENT23", 85 },
    { "MHPMEVENT23H", 226 },
    { "MHPMEVENT24", 86 },
    { "MHPMEVENT24H", 227 },
    { "MHPMEVENT25", 87 },
    { "MHPMEVENT25H", 228 },
    { "MHPMEVENT26", 88 },
    { "MHPMEVENT26H", 229 },
    { "MHPMEVENT27", 89 },
    { "MHPMEVENT27H", 230 },
    { "MHPMEVENT28", 90 },
    { "MHPMEVENT28H", 231 },
    { "MHPMEVENT29", 91 },
    { "MHPMEVENT29H", 232 },
    { "MHPMEVENT3", 65 },
    { "MHPMEVENT30", 92 },
    { "MHPMEVENT30H", 233 },
    { "MHPMEVENT31", 93 },
    { "MHPMEVENT31H", 234 },
    { "MHPMEVENT3H", 206 },
    { "MHPMEVENT4", 66 },
    { "MHPMEVENT4H", 207 },
    { "MHPMEVENT5", 67 },
    { "MHPMEVENT5H", 208 },
    { "MHPMEVENT6", 68 },
    { "MHPMEVENT6H", 209 },
    { "MHPMEVENT7", 69 },
    { "MHPMEVENT7H", 210 },
    { "MHPMEVENT8", 70 },
    { "MHPMEVENT8H", 211 },
    { "MHPMEVENT9", 71 },
    { "MHPMEVENT9H", 212 },
    { "MIDELEG", 49 },
    { "MIE", 50 },
    { "MIMPID", 379 },
    { "MINSTRET", 247 },
    { "MINSTRETH", 278 },
    { "MIP", 98 },
    { "MISA", 47 },
    { "MSCRATCH", 94 },
    { "MSECCFG", 235 },
    { "MSECCFGH", 236 },
    { "MSTATEEN0", 54 },
    { "MSTATEEN0H", 60 },
    { "MSTATEEN1", 55 },
    { "MSTATEEN1H", 61 },
    { "MSTATEEN2", 56 },
    { "MSTATEEN2H", 62 },
    { "MSTATEEN3", 57 },
    { "MSTATEEN3H", 63 },
    { "MSTATUS", 46 },
    { "MSTATUSH", 58 },
    { "MTINST", 99 },
    { "MTVAL", 97 },
    { "MTVAL2", 100 },
    { "MTVEC", 51 },
    { "MUCOUNTEREN", 64 },
    { "MVENDORID", 377 },
    { "PMPADDR0", 117 },
    { "PMPADDR1", 118 },
    { "PMPADDR10", 127 },
    { "PMPADDR11", 128 },
    { "PMPADDR12", 129 },
    { "PMPADDR13", 130 },
    { "PMPADDR14", 131 },
    { "PMPADDR15", 132 },
    { "PMPADDR16", 133 },
    { "PMPADDR17", 134 },
    { "PMPADDR18", 135 },
    { "PMPADDR19", 136 },
    { "PMPADDR2", 119 },
    { "PMPADDR20", 137 },
    { "PMPADDR21", 138 },
    { "PMPADDR22", 139 },
    { "PMPADDR23", 140 },
    { "PMPADDR24", 141 },
    { "PMPADDR25", 142 },
    { "PMPADDR26", 143 },
    { "PMPADDR27", 144 },
    { "PMPADDR28", 145 },
    { "PMPADDR29", 146 },
    { "PMPADDR3", 120 },
    { "PMPADDR30", 147 },
    { "PMPADDR31", 148 },
    { "PMPADDR32", 149 },
    { "PMPADDR33", 150 },
    { "PMPADDR34", 151 },
    { "PMPADDR35", 152 },
    { "PMPADDR36", 153 },
    { "PMPADDR37", 154 },
    { "PMPADDR38", 155 },
    { "PMPADDR39", 156 },
    { "PMPADDR4", 121 },
    { "PMPADDR40", 157 },
    { "PMPADDR41", 158 },
    { "PMPADDR42", 159 },
    { "PMPADDR43", 160 },
    { "PMPADDR44", 161 },
    { "PMPADDR45", 162 },
    { "PMPADDR46", 163 },
    { "PMPADDR47", 164 },
    { "PMPADDR48", 165 },
    { "PMPADDR49", 166 },
    { "PMPADDR5", 122 },
    { "PMPADDR50", 167 },
    { "PMPADDR51", 168 },
    { "PMPADDR52", 169 },
    { "PMPADDR53", 170 },
    { "PMPADDR54", 171 },
    { "PMPADDR55", 172 },
    { "PMPADDR56", 173 },
    { "PMPADDR57", 174 },
    { "PMPADDR58", 175 },
    { "PMPADDR59", 176 },
    { "PMPADDR6", 123 },
    { "PMPADDR60", 177 },
    { "PMPADDR61", 178 },
    { "PMPADDR62", 179 },
    { "PMPADDR63", 180 },
    { "PMPADDR7", 124 },
    { "PMPADDR8", 125 },
    { "PMPADDR9", 126 },
    { "PMPCFG0", 101 },
    { "PMPCFG1", 102 },
    { "PMPCFG10", 111 },
    { "PMPCFG11", 112 },
    { "PMPCFG12", 113 },
    { "PMPCFG13", 114 },
    { "PMPCFG14", 115 },
    { "PMPCFG15", 116 },
    { "PMPCFG2", 103 },
    { "PMPCFG3", 104 },
    { "PMPCFG4", 105 },
    { "PMPCFG5", 106 },
    { "PMPCFG6", 107 },
    { "PMPCFG7", 108 },
    { "PMPCFG8", 109 },
    { "PMPCFG9", 110 },
    { "SATP", 34 },
    { "SCAUSE", 29 },
    { "SCONTEXT", 181 },
    { "SCOUNTEREN", 21 },
    { "SCOUNTOVF", 375 },
    { "SEDELEG", 17 },
    { "SEED", 10 },
    { "SENVCFG", 22 },
    { "SEPC", 28 },
    { "SIDELEG", 18 },
    { "SIE", 19 },
    { "SIP", 31 },
    { "SSCRATCH", 27 },
    { "SSTATEEN0", 23 },
    { "SSTATEEN1", 24 },
    { "SSTATEEN2", 25 },
    { "SSTATEEN3", 26 },
    { "SSTATUS", 16 },
    { "STIMECMP", 32 },
    { "STIMECMPH", 33 },
    { "STVAL", 30 },
    { "STVEC", 20 },
    { "TDATA1", 238 },
    { "TDATA2", 239 },
    { "TDATA3", 240 },
    { "TIME", 309 },
    { "TIMEH", 344 },
    { "TSELECT", 237 },
    { "UCAUSE", 13 },
    { "UEPC", 12 },
    { "UIE", 4 },
    { "UIP", 15 },
    { "USCRATCH", 11 },
    { "USTATUS", 0 },
    { "UTVAL", 14 },
    { "UTVEC", 5 },
    { "VCSR", 9 },
    { "VL", 340 },
    { "VLENB", 342 },
    { "VSATP", 45 },
    { "VSCAUSE", 40 },
    { "VSEPC", 39 },
    { "VSIE", 36 },
    { "VSIP", 42 },
    { "VSSCRATCH", 38 },
    { "VSSTATUS", 35 },
    { "VSTART", 6 },
    { "VSTIMECMP", 43 },
    { "VSTIMECMPH", 44 },
    { "VSTVAL", 41 },
    { "VSTVEC", 37 },
    { "VTYPE", 341 },
    { "VXRM", 8 },
    { "VXSAT", 7 },
  };

  struct KeyType {
    std::string AltName;
  };
  KeyType Key = {AltName.upper()};
  auto Table = makeArrayRef(Index);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const IndexType &LHS, const KeyType &RHS) {
      int CmpAltName = StringRef(LHS.AltName).compare(RHS.AltName);
      if (CmpAltName < 0) return true;
      if (CmpAltName > 0) return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.AltName != Idx->AltName)
    return nullptr;
  return &SysRegsList[Idx->_index];
}

const SysReg *lookupSysRegByDeprecatedName(StringRef DeprecatedName) {
  struct IndexType {
    const char * DeprecatedName;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { "", 0 },
    { "", 1 },
    { "", 2 },
    { "", 3 },
    { "", 4 },
    { "", 5 },
    { "", 6 },
    { "", 7 },
    { "", 8 },
    { "", 9 },
    { "", 10 },
    { "", 11 },
    { "", 12 },
    { "", 13 },
    { "", 15 },
    { "", 16 },
    { "", 17 },
    { "", 18 },
    { "", 19 },
    { "", 20 },
    { "", 21 },
    { "", 22 },
    { "", 23 },
    { "", 24 },
    { "", 25 },
    { "", 26 },
    { "", 27 },
    { "", 28 },
    { "", 29 },
    { "", 31 },
    { "", 32 },
    { "", 33 },
    { "", 35 },
    { "", 36 },
    { "", 37 },
    { "", 38 },
    { "", 39 },
    { "", 40 },
    { "", 41 },
    { "", 42 },
    { "", 43 },
    { "", 44 },
    { "", 45 },
    { "", 46 },
    { "", 47 },
    { "", 48 },
    { "", 49 },
    { "", 50 },
    { "", 51 },
    { "", 52 },
    { "", 53 },
    { "", 54 },
    { "", 55 },
    { "", 56 },
    { "", 57 },
    { "", 58 },
    { "", 59 },
    { "", 60 },
    { "", 61 },
    { "", 62 },
    { "", 63 },
    { "", 64 },
    { "", 65 },
    { "", 66 },
    { "", 67 },
    { "", 68 },
    { "", 69 },
    { "", 70 },
    { "", 71 },
    { "", 72 },
    { "", 73 },
    { "", 74 },
    { "", 75 },
    { "", 76 },
    { "", 77 },
    { "", 78 },
    { "", 79 },
    { "", 80 },
    { "", 81 },
    { "", 82 },
    { "", 83 },
    { "", 84 },
    { "", 85 },
    { "", 86 },
    { "", 87 },
    { "", 88 },
    { "", 89 },
    { "", 90 },
    { "", 91 },
    { "", 92 },
    { "", 93 },
    { "", 94 },
    { "", 95 },
    { "", 96 },
    { "", 98 },
    { "", 99 },
    { "", 100 },
    { "", 101 },
    { "", 102 },
    { "", 103 },
    { "", 104 },
    { "", 105 },
    { "", 106 },
    { "", 107 },
    { "", 108 },
    { "", 109 },
    { "", 110 },
    { "", 111 },
    { "", 112 },
    { "", 113 },
    { "", 114 },
    { "", 115 },
    { "", 116 },
    { "", 117 },
    { "", 118 },
    { "", 119 },
    { "", 120 },
    { "", 121 },
    { "", 122 },
    { "", 123 },
    { "", 124 },
    { "", 125 },
    { "", 126 },
    { "", 127 },
    { "", 128 },
    { "", 129 },
    { "", 130 },
    { "", 131 },
    { "", 132 },
    { "", 133 },
    { "", 134 },
    { "", 135 },
    { "", 136 },
    { "", 137 },
    { "", 138 },
    { "", 139 },
    { "", 140 },
    { "", 141 },
    { "", 142 },
    { "", 143 },
    { "", 144 },
    { "", 145 },
    { "", 146 },
    { "", 147 },
    { "", 148 },
    { "", 149 },
    { "", 150 },
    { "", 151 },
    { "", 152 },
    { "", 153 },
    { "", 154 },
    { "", 155 },
    { "", 156 },
    { "", 157 },
    { "", 158 },
    { "", 159 },
    { "", 160 },
    { "", 161 },
    { "", 162 },
    { "", 163 },
    { "", 164 },
    { "", 165 },
    { "", 166 },
    { "", 167 },
    { "", 168 },
    { "", 169 },
    { "", 170 },
    { "", 171 },
    { "", 172 },
    { "", 173 },
    { "", 174 },
    { "", 175 },
    { "", 176 },
    { "", 177 },
    { "", 178 },
    { "", 179 },
    { "", 180 },
    { "", 181 },
    { "", 182 },
    { "", 183 },
    { "", 184 },
    { "", 185 },
    { "", 186 },
    { "", 187 },
    { "", 188 },
    { "", 189 },
    { "", 190 },
    { "", 191 },
    { "", 192 },
    { "", 193 },
    { "", 194 },
    { "", 195 },
    { "", 196 },
    { "", 197 },
    { "", 198 },
    { "", 199 },
    { "", 200 },
    { "", 201 },
    { "", 202 },
    { "", 203 },
    { "", 204 },
    { "", 205 },
    { "", 206 },
    { "", 207 },
    { "", 208 },
    { "", 209 },
    { "", 210 },
    { "", 211 },
    { "", 212 },
    { "", 213 },
    { "", 214 },
    { "", 215 },
    { "", 216 },
    { "", 217 },
    { "", 218 },
    { "", 219 },
    { "", 220 },
    { "", 221 },
    { "", 222 },
    { "", 223 },
    { "", 224 },
    { "", 225 },
    { "", 226 },
    { "", 227 },
    { "", 228 },
    { "", 229 },
    { "", 230 },
    { "", 231 },
    { "", 232 },
    { "", 233 },
    { "", 234 },
    { "", 235 },
    { "", 236 },
    { "", 237 },
    { "", 238 },
    { "", 239 },
    { "", 240 },
    { "", 241 },
    { "", 242 },
    { "", 243 },
    { "", 244 },
    { "", 245 },
    { "", 246 },
    { "", 247 },
    { "", 248 },
    { "", 249 },
    { "", 250 },
    { "", 251 },
    { "", 252 },
    { "", 253 },
    { "", 254 },
    { "", 255 },
    { "", 256 },
    { "", 257 },
    { "", 258 },
    { "", 259 },
    { "", 260 },
    { "", 261 },
    { "", 262 },
    { "", 263 },
    { "", 264 },
    { "", 265 },
    { "", 266 },
    { "", 267 },
    { "", 268 },
    { "", 269 },
    { "", 270 },
    { "", 271 },
    { "", 272 },
    { "", 273 },
    { "", 274 },
    { "", 275 },
    { "", 276 },
    { "", 277 },
    { "", 278 },
    { "", 279 },
    { "", 280 },
    { "", 281 },
    { "", 282 },
    { "", 283 },
    { "", 284 },
    { "", 285 },
    { "", 286 },
    { "", 287 },
    { "", 288 },
    { "", 289 },
    { "", 290 },
    { "", 291 },
    { "", 292 },
    { "", 293 },
    { "", 294 },
    { "", 295 },
    { "", 296 },
    { "", 297 },
    { "", 298 },
    { "", 299 },
    { "", 300 },
    { "", 301 },
    { "", 302 },
    { "", 303 },
    { "", 304 },
    { "", 305 },
    { "", 306 },
    { "", 307 },
    { "", 308 },
    { "", 309 },
    { "", 310 },
    { "", 311 },
    { "", 312 },
    { "", 313 },
    { "", 314 },
    { "", 315 },
    { "", 316 },
    { "", 317 },
    { "", 318 },
    { "", 319 },
    { "", 320 },
    { "", 321 },
    { "", 322 },
    { "", 323 },
    { "", 324 },
    { "", 325 },
    { "", 326 },
    { "", 327 },
    { "", 328 },
    { "", 329 },
    { "", 330 },
    { "", 331 },
    { "", 332 },
    { "", 333 },
    { "", 334 },
    { "", 335 },
    { "", 336 },
    { "", 337 },
    { "", 338 },
    { "", 339 },
    { "", 340 },
    { "", 341 },
    { "", 342 },
    { "", 343 },
    { "", 344 },
    { "", 345 },
    { "", 346 },
    { "", 347 },
    { "", 348 },
    { "", 349 },
    { "", 350 },
    { "", 351 },
    { "", 352 },
    { "", 353 },
    { "", 354 },
    { "", 355 },
    { "", 356 },
    { "", 357 },
    { "", 358 },
    { "", 359 },
    { "", 360 },
    { "", 361 },
    { "", 362 },
    { "", 363 },
    { "", 364 },
    { "", 365 },
    { "", 366 },
    { "", 367 },
    { "", 368 },
    { "", 369 },
    { "", 370 },
    { "", 371 },
    { "", 372 },
    { "", 373 },
    { "", 374 },
    { "", 375 },
    { "", 376 },
    { "", 377 },
    { "", 378 },
    { "", 379 },
    { "", 380 },
    { "", 381 },
    { "MBADADDR", 97 },
    { "SBADADDR", 30 },
    { "SPTBR", 34 },
    { "UBADADDR", 14 },
  };

  struct KeyType {
    std::string DeprecatedName;
  };
  KeyType Key = {DeprecatedName.upper()};
  auto Table = makeArrayRef(Index);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const IndexType &LHS, const KeyType &RHS) {
      int CmpDeprecatedName = StringRef(LHS.DeprecatedName).compare(RHS.DeprecatedName);
      if (CmpDeprecatedName < 0) return true;
      if (CmpDeprecatedName > 0) return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.DeprecatedName != Idx->DeprecatedName)
    return nullptr;
  return &SysRegsList[Idx->_index];
}

const SysReg *lookupSysRegByName(StringRef Name) {
  struct IndexType {
    const char * Name;
    unsigned _index;
  };
  static const struct IndexType Index[] = {
    { "CYCLE", 308 },
    { "CYCLEH", 343 },
    { "DCSR", 242 },
    { "DPC", 243 },
    { "DSCRATCH0", 244 },
    { "DSCRATCH1", 245 },
    { "FCSR", 3 },
    { "FFLAGS", 1 },
    { "FRM", 2 },
    { "HCONTEXT", 205 },
    { "HCOUNTEREN", 187 },
    { "HEDELEG", 183 },
    { "HENVCFG", 189 },
    { "HENVCFGH", 195 },
    { "HGATP", 204 },
    { "HGEIE", 188 },
    { "HGEIP", 376 },
    { "HIDELEG", 184 },
    { "HIE", 185 },
    { "HIP", 201 },
    { "HPMCOUNTER10", 318 },
    { "HPMCOUNTER10H", 353 },
    { "HPMCOUNTER11", 319 },
    { "HPMCOUNTER11H", 354 },
    { "HPMCOUNTER12", 320 },
    { "HPMCOUNTER12H", 355 },
    { "HPMCOUNTER13", 321 },
    { "HPMCOUNTER13H", 356 },
    { "HPMCOUNTER14", 322 },
    { "HPMCOUNTER14H", 357 },
    { "HPMCOUNTER15", 323 },
    { "HPMCOUNTER15H", 358 },
    { "HPMCOUNTER16", 324 },
    { "HPMCOUNTER16H", 359 },
    { "HPMCOUNTER17", 325 },
    { "HPMCOUNTER17H", 360 },
    { "HPMCOUNTER18", 326 },
    { "HPMCOUNTER18H", 361 },
    { "HPMCOUNTER19", 327 },
    { "HPMCOUNTER19H", 362 },
    { "HPMCOUNTER20", 328 },
    { "HPMCOUNTER20H", 363 },
    { "HPMCOUNTER21", 329 },
    { "HPMCOUNTER21H", 364 },
    { "HPMCOUNTER22", 330 },
    { "HPMCOUNTER22H", 365 },
    { "HPMCOUNTER23", 331 },
    { "HPMCOUNTER23H", 366 },
    { "HPMCOUNTER24", 332 },
    { "HPMCOUNTER24H", 367 },
    { "HPMCOUNTER25", 333 },
    { "HPMCOUNTER25H", 368 },
    { "HPMCOUNTER26", 334 },
    { "HPMCOUNTER26H", 369 },
    { "HPMCOUNTER27", 335 },
    { "HPMCOUNTER27H", 370 },
    { "HPMCOUNTER28", 336 },
    { "HPMCOUNTER28H", 371 },
    { "HPMCOUNTER29", 337 },
    { "HPMCOUNTER29H", 372 },
    { "HPMCOUNTER3", 311 },
    { "HPMCOUNTER30", 338 },
    { "HPMCOUNTER30H", 373 },
    { "HPMCOUNTER31", 339 },
    { "HPMCOUNTER31H", 374 },
    { "HPMCOUNTER3H", 346 },
    { "HPMCOUNTER4", 312 },
    { "HPMCOUNTER4H", 347 },
    { "HPMCOUNTER5", 313 },
    { "HPMCOUNTER5H", 348 },
    { "HPMCOUNTER6", 314 },
    { "HPMCOUNTER6H", 349 },
    { "HPMCOUNTER7", 315 },
    { "HPMCOUNTER7H", 350 },
    { "HPMCOUNTER8", 316 },
    { "HPMCOUNTER8H", 351 },
    { "HPMCOUNTER9", 317 },
    { "HPMCOUNTER9H", 352 },
    { "HSTATEEN0", 190 },
    { "HSTATEEN0H", 196 },
    { "HSTATEEN1", 191 },
    { "HSTATEEN1H", 197 },
    { "HSTATEEN2", 192 },
    { "HSTATEEN2H", 198 },
    { "HSTATEEN3", 193 },
    { "HSTATEEN3H", 199 },
    { "HSTATUS", 182 },
    { "HTIMEDELTA", 186 },
    { "HTIMEDELTAH", 194 },
    { "HTINST", 203 },
    { "HTVAL", 200 },
    { "HVIP", 202 },
    { "INSTRET", 310 },
    { "INSTRETH", 345 },
    { "MARCHID", 378 },
    { "MCAUSE", 96 },
    { "MCONFIGPTR", 381 },
    { "MCONTEXT", 241 },
    { "MCOUNTEREN", 52 },
    { "MCOUNTINHIBIT", 64 },
    { "MCYCLE", 246 },
    { "MCYCLEH", 277 },
    { "MEDELEG", 48 },
    { "MENVCFG", 53 },
    { "MENVCFGH", 59 },
    { "MEPC", 95 },
    { "MHARTID", 380 },
    { "MHPMCOUNTER10", 255 },
    { "MHPMCOUNTER10H", 286 },
    { "MHPMCOUNTER11", 256 },
    { "MHPMCOUNTER11H", 287 },
    { "MHPMCOUNTER12", 257 },
    { "MHPMCOUNTER12H", 288 },
    { "MHPMCOUNTER13", 258 },
    { "MHPMCOUNTER13H", 289 },
    { "MHPMCOUNTER14", 259 },
    { "MHPMCOUNTER14H", 290 },
    { "MHPMCOUNTER15", 260 },
    { "MHPMCOUNTER15H", 291 },
    { "MHPMCOUNTER16", 261 },
    { "MHPMCOUNTER16H", 292 },
    { "MHPMCOUNTER17", 262 },
    { "MHPMCOUNTER17H", 293 },
    { "MHPMCOUNTER18", 263 },
    { "MHPMCOUNTER18H", 294 },
    { "MHPMCOUNTER19", 264 },
    { "MHPMCOUNTER19H", 295 },
    { "MHPMCOUNTER20", 265 },
    { "MHPMCOUNTER20H", 296 },
    { "MHPMCOUNTER21", 266 },
    { "MHPMCOUNTER21H", 297 },
    { "MHPMCOUNTER22", 267 },
    { "MHPMCOUNTER22H", 298 },
    { "MHPMCOUNTER23", 268 },
    { "MHPMCOUNTER23H", 299 },
    { "MHPMCOUNTER24", 269 },
    { "MHPMCOUNTER24H", 300 },
    { "MHPMCOUNTER25", 270 },
    { "MHPMCOUNTER25H", 301 },
    { "MHPMCOUNTER26", 271 },
    { "MHPMCOUNTER26H", 302 },
    { "MHPMCOUNTER27", 272 },
    { "MHPMCOUNTER27H", 303 },
    { "MHPMCOUNTER28", 273 },
    { "MHPMCOUNTER28H", 304 },
    { "MHPMCOUNTER29", 274 },
    { "MHPMCOUNTER29H", 305 },
    { "MHPMCOUNTER3", 248 },
    { "MHPMCOUNTER30", 275 },
    { "MHPMCOUNTER30H", 306 },
    { "MHPMCOUNTER31", 276 },
    { "MHPMCOUNTER31H", 307 },
    { "MHPMCOUNTER3H", 279 },
    { "MHPMCOUNTER4", 249 },
    { "MHPMCOUNTER4H", 280 },
    { "MHPMCOUNTER5", 250 },
    { "MHPMCOUNTER5H", 281 },
    { "MHPMCOUNTER6", 251 },
    { "MHPMCOUNTER6H", 282 },
    { "MHPMCOUNTER7", 252 },
    { "MHPMCOUNTER7H", 283 },
    { "MHPMCOUNTER8", 253 },
    { "MHPMCOUNTER8H", 284 },
    { "MHPMCOUNTER9", 254 },
    { "MHPMCOUNTER9H", 285 },
    { "MHPMEVENT10", 72 },
    { "MHPMEVENT10H", 213 },
    { "MHPMEVENT11", 73 },
    { "MHPMEVENT11H", 214 },
    { "MHPMEVENT12", 74 },
    { "MHPMEVENT12H", 215 },
    { "MHPMEVENT13", 75 },
    { "MHPMEVENT13H", 216 },
    { "MHPMEVENT14", 76 },
    { "MHPMEVENT14H", 217 },
    { "MHPMEVENT15", 77 },
    { "MHPMEVENT15H", 218 },
    { "MHPMEVENT16", 78 },
    { "MHPMEVENT16H", 219 },
    { "MHPMEVENT17", 79 },
    { "MHPMEVENT17H", 220 },
    { "MHPMEVENT18", 80 },
    { "MHPMEVENT18H", 221 },
    { "MHPMEVENT19", 81 },
    { "MHPMEVENT19H", 222 },
    { "MHPMEVENT20", 82 },
    { "MHPMEVENT20H", 223 },
    { "MHPMEVENT21", 83 },
    { "MHPMEVENT21H", 224 },
    { "MHPMEVENT22", 84 },
    { "MHPMEVENT22H", 225 },
    { "MHPMEVENT23", 85 },
    { "MHPMEVENT23H", 226 },
    { "MHPMEVENT24", 86 },
    { "MHPMEVENT24H", 227 },
    { "MHPMEVENT25", 87 },
    { "MHPMEVENT25H", 228 },
    { "MHPMEVENT26", 88 },
    { "MHPMEVENT26H", 229 },
    { "MHPMEVENT27", 89 },
    { "MHPMEVENT27H", 230 },
    { "MHPMEVENT28", 90 },
    { "MHPMEVENT28H", 231 },
    { "MHPMEVENT29", 91 },
    { "MHPMEVENT29H", 232 },
    { "MHPMEVENT3", 65 },
    { "MHPMEVENT30", 92 },
    { "MHPMEVENT30H", 233 },
    { "MHPMEVENT31", 93 },
    { "MHPMEVENT31H", 234 },
    { "MHPMEVENT3H", 206 },
    { "MHPMEVENT4", 66 },
    { "MHPMEVENT4H", 207 },
    { "MHPMEVENT5", 67 },
    { "MHPMEVENT5H", 208 },
    { "MHPMEVENT6", 68 },
    { "MHPMEVENT6H", 209 },
    { "MHPMEVENT7", 69 },
    { "MHPMEVENT7H", 210 },
    { "MHPMEVENT8", 70 },
    { "MHPMEVENT8H", 211 },
    { "MHPMEVENT9", 71 },
    { "MHPMEVENT9H", 212 },
    { "MIDELEG", 49 },
    { "MIE", 50 },
    { "MIMPID", 379 },
    { "MINSTRET", 247 },
    { "MINSTRETH", 278 },
    { "MIP", 98 },
    { "MISA", 47 },
    { "MSCRATCH", 94 },
    { "MSECCFG", 235 },
    { "MSECCFGH", 236 },
    { "MSTATEEN0", 54 },
    { "MSTATEEN0H", 60 },
    { "MSTATEEN1", 55 },
    { "MSTATEEN1H", 61 },
    { "MSTATEEN2", 56 },
    { "MSTATEEN2H", 62 },
    { "MSTATEEN3", 57 },
    { "MSTATEEN3H", 63 },
    { "MSTATUS", 46 },
    { "MSTATUSH", 58 },
    { "MTINST", 99 },
    { "MTVAL", 97 },
    { "MTVAL2", 100 },
    { "MTVEC", 51 },
    { "MVENDORID", 377 },
    { "PMPADDR0", 117 },
    { "PMPADDR1", 118 },
    { "PMPADDR10", 127 },
    { "PMPADDR11", 128 },
    { "PMPADDR12", 129 },
    { "PMPADDR13", 130 },
    { "PMPADDR14", 131 },
    { "PMPADDR15", 132 },
    { "PMPADDR16", 133 },
    { "PMPADDR17", 134 },
    { "PMPADDR18", 135 },
    { "PMPADDR19", 136 },
    { "PMPADDR2", 119 },
    { "PMPADDR20", 137 },
    { "PMPADDR21", 138 },
    { "PMPADDR22", 139 },
    { "PMPADDR23", 140 },
    { "PMPADDR24", 141 },
    { "PMPADDR25", 142 },
    { "PMPADDR26", 143 },
    { "PMPADDR27", 144 },
    { "PMPADDR28", 145 },
    { "PMPADDR29", 146 },
    { "PMPADDR3", 120 },
    { "PMPADDR30", 147 },
    { "PMPADDR31", 148 },
    { "PMPADDR32", 149 },
    { "PMPADDR33", 150 },
    { "PMPADDR34", 151 },
    { "PMPADDR35", 152 },
    { "PMPADDR36", 153 },
    { "PMPADDR37", 154 },
    { "PMPADDR38", 155 },
    { "PMPADDR39", 156 },
    { "PMPADDR4", 121 },
    { "PMPADDR40", 157 },
    { "PMPADDR41", 158 },
    { "PMPADDR42", 159 },
    { "PMPADDR43", 160 },
    { "PMPADDR44", 161 },
    { "PMPADDR45", 162 },
    { "PMPADDR46", 163 },
    { "PMPADDR47", 164 },
    { "PMPADDR48", 165 },
    { "PMPADDR49", 166 },
    { "PMPADDR5", 122 },
    { "PMPADDR50", 167 },
    { "PMPADDR51", 168 },
    { "PMPADDR52", 169 },
    { "PMPADDR53", 170 },
    { "PMPADDR54", 171 },
    { "PMPADDR55", 172 },
    { "PMPADDR56", 173 },
    { "PMPADDR57", 174 },
    { "PMPADDR58", 175 },
    { "PMPADDR59", 176 },
    { "PMPADDR6", 123 },
    { "PMPADDR60", 177 },
    { "PMPADDR61", 178 },
    { "PMPADDR62", 179 },
    { "PMPADDR63", 180 },
    { "PMPADDR7", 124 },
    { "PMPADDR8", 125 },
    { "PMPADDR9", 126 },
    { "PMPCFG0", 101 },
    { "PMPCFG1", 102 },
    { "PMPCFG10", 111 },
    { "PMPCFG11", 112 },
    { "PMPCFG12", 113 },
    { "PMPCFG13", 114 },
    { "PMPCFG14", 115 },
    { "PMPCFG15", 116 },
    { "PMPCFG2", 103 },
    { "PMPCFG3", 104 },
    { "PMPCFG4", 105 },
    { "PMPCFG5", 106 },
    { "PMPCFG6", 107 },
    { "PMPCFG7", 108 },
    { "PMPCFG8", 109 },
    { "PMPCFG9", 110 },
    { "SATP", 34 },
    { "SCAUSE", 29 },
    { "SCONTEXT", 181 },
    { "SCOUNTEREN", 21 },
    { "SCOUNTOVF", 375 },
    { "SEDELEG", 17 },
    { "SEED", 10 },
    { "SENVCFG", 22 },
    { "SEPC", 28 },
    { "SIDELEG", 18 },
    { "SIE", 19 },
    { "SIP", 31 },
    { "SSCRATCH", 27 },
    { "SSTATEEN0", 23 },
    { "SSTATEEN1", 24 },
    { "SSTATEEN2", 25 },
    { "SSTATEEN3", 26 },
    { "SSTATUS", 16 },
    { "STIMECMP", 32 },
    { "STIMECMPH", 33 },
    { "STVAL", 30 },
    { "STVEC", 20 },
    { "TDATA1", 238 },
    { "TDATA2", 239 },
    { "TDATA3", 240 },
    { "TIME", 309 },
    { "TIMEH", 344 },
    { "TSELECT", 237 },
    { "UCAUSE", 13 },
    { "UEPC", 12 },
    { "UIE", 4 },
    { "UIP", 15 },
    { "USCRATCH", 11 },
    { "USTATUS", 0 },
    { "UTVAL", 14 },
    { "UTVEC", 5 },
    { "VCSR", 9 },
    { "VL", 340 },
    { "VLENB", 342 },
    { "VSATP", 45 },
    { "VSCAUSE", 40 },
    { "VSEPC", 39 },
    { "VSIE", 36 },
    { "VSIP", 42 },
    { "VSSCRATCH", 38 },
    { "VSSTATUS", 35 },
    { "VSTART", 6 },
    { "VSTIMECMP", 43 },
    { "VSTIMECMPH", 44 },
    { "VSTVAL", 41 },
    { "VSTVEC", 37 },
    { "VTYPE", 341 },
    { "VXRM", 8 },
    { "VXSAT", 7 },
  };

  struct KeyType {
    std::string Name;
  };
  KeyType Key = {Name.upper()};
  auto Table = makeArrayRef(Index);
  auto Idx = std::lower_bound(Table.begin(), Table.end(), Key,
    [](const IndexType &LHS, const KeyType &RHS) {
      int CmpName = StringRef(LHS.Name).compare(RHS.Name);
      if (CmpName < 0) return true;
      if (CmpName > 0) return false;
      return false;
    });

  if (Idx == Table.end() ||
      Key.Name != Idx->Name)
    return nullptr;
  return &SysRegsList[Idx->_index];
}
#endif

#undef GET_RISCVOpcodesList_DECL
#undef GET_RISCVOpcodesList_IMPL
#undef GET_RISCVVIntrinsicsTable_DECL
#undef GET_RISCVVIntrinsicsTable_IMPL
#undef GET_RISCVVLETable_DECL
#undef GET_RISCVVLETable_IMPL
#undef GET_RISCVVLSEGTable_DECL
#undef GET_RISCVVLSEGTable_IMPL
#undef GET_RISCVVLXSEGTable_DECL
#undef GET_RISCVVLXSEGTable_IMPL
#undef GET_RISCVVLXTable_DECL
#undef GET_RISCVVLXTable_IMPL
#undef GET_RISCVVPseudosTable_DECL
#undef GET_RISCVVPseudosTable_IMPL
#undef GET_RISCVVSETable_DECL
#undef GET_RISCVVSETable_IMPL
#undef GET_RISCVVSSEGTable_DECL
#undef GET_RISCVVSSEGTable_IMPL
#undef GET_RISCVVSXSEGTable_DECL
#undef GET_RISCVVSXSEGTable_IMPL
#undef GET_RISCVVSXTable_DECL
#undef GET_RISCVVSXTable_IMPL
#undef GET_SysRegsList_DECL
#undef GET_SysRegsList_IMPL
