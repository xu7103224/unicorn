#pragma once
/*
 *  i386 translation
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "unicorn/platform.h"
#include <signal.h>

#include "qemu/host-utils.h"
#include "cpu.h"
#include "tcgop.h"
#include "exec/cpu_ldst.h"

#include "exec/helper-proto.h"
#include "exec/helper-gen.h"

#include "uc_priv.h"

#define PREFIX_REPZ   0x01
#define PREFIX_REPNZ  0x02
#define PREFIX_LOCK   0x04
#define PREFIX_DATA   0x08
#define PREFIX_ADR    0x10
#define PREFIX_VEX    0x20

#ifdef TARGET_X86_64
#define CODE64(s) ((s)->code64)
#define REX_X(s) ((s)->rex_x)
#define REX_B(s) ((s)->rex_b)
#else
#define CODE64(s) 0
#define REX_X(s) 0
#define REX_B(s) 0
#endif

#ifdef TARGET_X86_64
# define ctztl  ctz64
# define clztl  clz64
#else
# define ctztl  ctz32
# define clztl  clz32
#endif

#include "exec/gen-icount.h"

typedef struct DisasContext {
	/* current insn context */
	int override; /* -1 if no override */
	int prefix;
	TCGMemOp aflag;
	TCGMemOp dflag;
	target_ulong pc; /* pc = eip + cs_base */
	int is_jmp; /* 1 = means jump (stop translation), 2 means CPU
				   static state change (stop translation) */
				   /* current block context */
	target_ulong cs_base; /* base of CS segment */
	int pe;     /* protected mode */
	int code32; /* 32 bit code segment */
#ifdef TARGET_X86_64
	int lma;    /* long mode active */
	int code64; /* 64 bit code segment */
	int rex_x, rex_b;
#endif
	int vex_l;  /* vex vector length */
	int vex_v;  /* vex vvvv register, without 1's compliment.  */
	int ss32;   /* 32 bit stack segment */
	CCOp cc_op;  /* current CC operation */
	CCOp last_cc_op;  /* Unicorn: last CC operation. Save this to see if cc_op has changed */
	bool cc_op_dirty;
	int addseg; /* non zero if either DS/ES/SS have a non zero base */
	int f_st;   /* currently unused */
	int vm86;   /* vm86 mode */
	int cpl;
	int iopl;
	int tf;     /* TF cpu flag */
	int singlestep_enabled; /* "hardware" single step enabled */
	int jmp_opt; /* use direct block chaining for direct jumps */
	int mem_index; /* select memory access functions */
	uint64_t flags; /* all execution flags */
	struct TranslationBlock* tb;
	int popl_esp_hack; /* for correct popl with esp base handling */
	int rip_offset; /* only used in x86_64, but left for simplicity */
	int cpuid_features;
	int cpuid_ext_features;
	int cpuid_ext2_features;
	int cpuid_ext3_features;
	int cpuid_7_0_ebx_features;
	struct uc_struct* uc;

	// Unicorn
	target_ulong prev_pc; /* save address of the previous instruction */
} DisasContext;

void gen_eob(DisasContext* s);
void gen_jmp(DisasContext* s, target_ulong eip);
void gen_jmp_tb(DisasContext* s, target_ulong eip, int tb_num);
void gen_op(DisasContext* s, int op, TCGMemOp ot, int d);

/* i386 arith/logic operations */
enum {
	OP_ADDL,
	OP_ORL,
	OP_ADCL,
	OP_SBBL,
	OP_ANDL,
	OP_SUBL,
	OP_XORL,
	OP_CMPL,
};

/* i386 shift ops */
enum {
	OP_ROL,
	OP_ROR,
	OP_RCL,
	OP_RCR,
	OP_SHL,
	OP_SHR,
	OP_SHL1, /* undocumented */
	OP_SAR = 7,
};

enum {
	JCC_O,
	JCC_B,
	JCC_Z,
	JCC_BE,
	JCC_S,
	JCC_P,
	JCC_L,
	JCC_LE,
};

enum {
	/* I386 int registers */
	OR_EAX,   /* MUST be even numbered */
	OR_ECX,
	OR_EDX,
	OR_EBX,
	OR_ESP,
	OR_EBP,
	OR_ESI,
	OR_EDI,

	OR_TMP0 = 16,    /* temporary operand register */
	OR_TMP1,
	OR_A0, /* temporary register used when doing address evaluation */
};

enum {
	USES_CC_DST = 1,
	USES_CC_SRC = 2,
	USES_CC_SRC2 = 4,
	USES_CC_SRCT = 8,
};

/* Bit set if the global variable is live after setting CC_OP to X.  */
const uint8_t cc_op_live[CC_OP_NB] = {
#ifdef _MSC_VER
	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_DYNAMIC, /* must use dynamic code to get cc_op */
	USES_CC_SRC, // CC_OP_EFLAGS,  /* all cc are explicitly computed, CC_SRC = flags */

	USES_CC_DST | USES_CC_SRC, // CC_OP_MULB, /* modify all flags, C, O = (CC_SRC != 0) */
	USES_CC_DST | USES_CC_SRC, // CC_OP_MULW,
	USES_CC_DST | USES_CC_SRC, // CC_OP_MULL,
	USES_CC_DST | USES_CC_SRC, // CC_OP_MULQ,

	USES_CC_DST | USES_CC_SRC, // CC_OP_ADDB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
	USES_CC_DST | USES_CC_SRC, // CC_OP_ADDW,
	USES_CC_DST | USES_CC_SRC, // CC_OP_ADDL,
	USES_CC_DST | USES_CC_SRC, // CC_OP_ADDQ,

	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCW,
	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCL,
	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCQ,

	USES_CC_DST | USES_CC_SRC | USES_CC_SRCT, // CC_OP_SUBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
	USES_CC_DST | USES_CC_SRC | USES_CC_SRCT, // CC_OP_SUBW,
	USES_CC_DST | USES_CC_SRC | USES_CC_SRCT, // CC_OP_SUBL,
	USES_CC_DST | USES_CC_SRC | USES_CC_SRCT, // CC_OP_SUBQ,

	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_SBBB, /* modify all flags, CC_DST = res, CC_SRC = src1 */
	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_SBBW,
	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_SBBL,
	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_SBBQ,

	USES_CC_DST, // CC_OP_LOGICB, /* modify all flags, CC_DST = res */
	USES_CC_DST, // CC_OP_LOGICW,
	USES_CC_DST, // CC_OP_LOGICL,
	USES_CC_DST, // CC_OP_LOGICQ,

	USES_CC_DST | USES_CC_SRC, // CC_OP_INCB, /* modify all flags except, CC_DST = res, CC_SRC = C */
	USES_CC_DST | USES_CC_SRC, // CC_OP_INCW,
	USES_CC_DST | USES_CC_SRC, // CC_OP_INCL,
	USES_CC_DST | USES_CC_SRC, // CC_OP_INCQ,

	USES_CC_DST | USES_CC_SRC, // CC_OP_DECB, /* modify all flags except, CC_DST = res, CC_SRC = C  */
	USES_CC_DST | USES_CC_SRC, // CC_OP_DECW,
	USES_CC_DST | USES_CC_SRC, // CC_OP_DECL,
	USES_CC_DST | USES_CC_SRC, // CC_OP_DECQ,

	USES_CC_DST | USES_CC_SRC, // CC_OP_SHLB, /* modify all flags, CC_DST = res, CC_SRC.msb = C */
	USES_CC_DST | USES_CC_SRC, // CC_OP_SHLW,
	USES_CC_DST | USES_CC_SRC, // CC_OP_SHLL,
	USES_CC_DST | USES_CC_SRC, // CC_OP_SHLQ,

	USES_CC_DST | USES_CC_SRC, // CC_OP_SARB, /* modify all flags, CC_DST = res, CC_SRC.lsb = C */
	USES_CC_DST | USES_CC_SRC, // CC_OP_SARW,
	USES_CC_DST | USES_CC_SRC, // CC_OP_SARL,
	USES_CC_DST | USES_CC_SRC, // CC_OP_SARQ,

	USES_CC_DST | USES_CC_SRC, // CC_OP_BMILGB, /* Z,S via CC_DST, C = SRC==0; O=0; P,A undefined */
	USES_CC_DST | USES_CC_SRC, // CC_OP_BMILGW,
	USES_CC_DST | USES_CC_SRC, // CC_OP_BMILGL,
	USES_CC_DST | USES_CC_SRC, // CC_OP_BMILGQ,

	USES_CC_DST | USES_CC_SRC, // CC_OP_ADCX, /* CC_DST = C, CC_SRC = rest.  */
	USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADOX, /* CC_DST = O, CC_SRC = rest.  */
	USES_CC_DST | USES_CC_SRC | USES_CC_SRC2, // CC_OP_ADCOX, /* CC_DST = C, CC_SRC2 = O, CC_SRC = rest.  */

	0, // CC_OP_CLR, /* Z set, all other flags clear.  */
#else
	[CC_OP_DYNAMIC] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
	[CC_OP_EFLAGS] = USES_CC_SRC,
	[CC_OP_MULB ... CC_OP_MULQ] = USES_CC_DST | USES_CC_SRC,
	[CC_OP_ADDB ... CC_OP_ADDQ] = USES_CC_DST | USES_CC_SRC,
	[CC_OP_ADCB ... CC_OP_ADCQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
	[CC_OP_SUBB ... CC_OP_SUBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRCT,
	[CC_OP_SBBB ... CC_OP_SBBQ] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
	[CC_OP_LOGICB ... CC_OP_LOGICQ] = USES_CC_DST,
	[CC_OP_INCB ... CC_OP_INCQ] = USES_CC_DST | USES_CC_SRC,
	[CC_OP_DECB ... CC_OP_DECQ] = USES_CC_DST | USES_CC_SRC,
	[CC_OP_SHLB ... CC_OP_SHLQ] = USES_CC_DST | USES_CC_SRC,
	[CC_OP_SARB ... CC_OP_SARQ] = USES_CC_DST | USES_CC_SRC,
	[CC_OP_BMILGB ... CC_OP_BMILGQ] = USES_CC_DST | USES_CC_SRC,
	[CC_OP_ADCX] = USES_CC_DST | USES_CC_SRC,
	[CC_OP_ADOX] = USES_CC_SRC | USES_CC_SRC2,
	[CC_OP_ADCOX] = USES_CC_DST | USES_CC_SRC | USES_CC_SRC2,
	[CC_OP_CLR] = 0,
#endif
};

inline void gen_jmp_im(DisasContext* s, target_ulong pc);

void set_cc_op(DisasContext* s, CCOp op);

void gen_update_cc_op(DisasContext* s);

void fpu_update_ip(CPUX86State* env, target_ulong pc);

#ifdef TARGET_X86_64

#define NB_OP_SIZES 4

#else /* !TARGET_X86_64 */

#define NB_OP_SIZES 3

#endif /* !TARGET_X86_64 */

#if defined(HOST_WORDS_BIGENDIAN)
#define REG_B_OFFSET (sizeof(target_ulong) - 1)
#define REG_H_OFFSET (sizeof(target_ulong) - 2)
#define REG_W_OFFSET (sizeof(target_ulong) - 2)
#define REG_L_OFFSET (sizeof(target_ulong) - 4)
#define REG_LH_OFFSET (sizeof(target_ulong) - 8)
#else
#define REG_B_OFFSET 0
#define REG_H_OFFSET 1
#define REG_W_OFFSET 0
#define REG_L_OFFSET 0
#define REG_LH_OFFSET 4
#endif

/* In instruction encodings for byte register accesses the
 * register number usually indicates "low 8 bits of register N";
 * however there are some special cases where N 4..7 indicates
 * [AH, CH, DH, BH], ie "bits 15..8 of register N-4". Return
 * true for this special case, false otherwise.
 */
inline bool byte_reg_is_xH(int x86_64_hregs, int reg);


/* Select the size of a push/pop operation.  */
inline TCGMemOp mo_pushpop(DisasContext* s, TCGMemOp ot);


/* Select only size 64 else 32.  Used for SSE operand sizes.  */
inline TCGMemOp mo_64_32(TCGMemOp ot);


/* Select size 8 if lsb of B is clear, else OT.  Used for decoding
   byte vs word opcodes.  */
inline TCGMemOp mo_b_d(int b, TCGMemOp ot);


/* Select size 8 if lsb of B is clear, else OT capped at 32.
   Used for decoding operand size of port opcodes.  */
inline TCGMemOp mo_b_d32(int b, TCGMemOp ot);

void gen_op_mov_reg_v(TCGContext* s, TCGMemOp ot, int reg, TCGv t0);


inline void gen_op_mov_v_reg(TCGContext* s, TCGMemOp ot, TCGv t0, int reg);


inline void gen_op_movl_A0_reg(TCGContext* s, int reg);

inline void gen_op_addl_A0_im(TCGContext* s, int32_t val);


#ifdef TARGET_X86_64
inline void gen_op_addq_A0_im(TCGContext* s, int64_t val);

#endif

void gen_add_A0_im(DisasContext* s, int val);


inline void gen_op_jmp_v(TCGContext* s, TCGv dest);

inline void gen_op_add_reg_im(TCGContext* s, TCGMemOp size, int reg, int32_t val);


inline void gen_op_add_reg_T0(TCGContext* s, TCGMemOp size, int reg);

inline void gen_op_addl_A0_reg_sN(TCGContext* s, int shift, int reg);


inline void gen_op_movl_A0_seg(TCGContext* s, int reg);

inline void gen_op_addl_A0_seg(DisasContext* s, int reg);


#ifdef TARGET_X86_64
inline void gen_op_movq_A0_seg(TCGContext* s, int reg);


inline void gen_op_addq_A0_seg(TCGContext* s, int reg);


inline void gen_op_movq_A0_reg(TCGContext* s, int reg);


inline void gen_op_addq_A0_reg_sN(TCGContext* s, int shift, int reg);

#endif

inline void gen_op_ld_v(DisasContext* s, int idx, TCGv t0, TCGv a0);


inline void gen_op_st_v(DisasContext* s, int idx, TCGv t0, TCGv a0);


inline void gen_op_st_rm_T0_A0(DisasContext* s, int idx, int d);


inline void gen_jmp_im(DisasContext* s, target_ulong pc);


inline void gen_string_movl_A0_ESI(DisasContext* s);


inline void gen_string_movl_A0_EDI(DisasContext* s);


inline void gen_op_movl_T0_Dshift(TCGContext* s, TCGMemOp ot);

static TCGv gen_ext_tl(TCGContext* s, TCGv dst, TCGv src, TCGMemOp size, bool sign);

void gen_extu(TCGContext* s, TCGMemOp ot, TCGv reg);

void gen_exts(TCGContext* s, TCGMemOp ot, TCGv reg);

inline void gen_op_jnz_ecx(TCGContext* s, TCGMemOp size, int label1);

inline void gen_op_jz_ecx(TCGContext* s, TCGMemOp size, int label1);

void gen_helper_in_func(TCGContext* s, TCGMemOp ot, TCGv v, TCGv_i32 n);

void gen_helper_out_func(TCGContext* s, TCGMemOp ot, TCGv_i32 v, TCGv_i32 n);

void gen_check_io(DisasContext* s, TCGMemOp ot, target_ulong cur_eip,
	uint32_t svm_flags);

inline void gen_movs(DisasContext* s, TCGMemOp ot);

void gen_op_update1_cc(TCGContext* s);

void gen_op_update2_cc(TCGContext* s);

void gen_op_update3_cc(TCGContext* s, TCGv reg);

inline void gen_op_testl_T0_T1_cc(TCGContext* s);

void gen_op_update_neg_cc(TCGContext* s);

/* compute all eflags to cc_src */
void gen_compute_eflags(DisasContext* s);

typedef struct CCPrepare {
	TCGCond cond;
	TCGv reg;
	TCGv reg2;
	target_ulong imm;
	target_ulong mask;
	bool use_reg2;
	bool no_setcond;
} CCPrepare;

inline CCPrepare ccprepare_make(TCGCond cond,
	TCGv reg, TCGv reg2,
	target_ulong imm, target_ulong mask,
	bool use_reg2, bool no_setcond);

/* compute eflags.C to reg */
static CCPrepare gen_prepare_eflags_c(DisasContext* s, TCGv reg);

/* compute eflags.P to reg */
static CCPrepare gen_prepare_eflags_p(DisasContext* s, TCGv reg);

/* compute eflags.S to reg */
static CCPrepare gen_prepare_eflags_s(DisasContext* s, TCGv reg);
/* compute eflags.O to reg */
static CCPrepare gen_prepare_eflags_o(DisasContext* s, TCGv reg);

/* compute eflags.Z to reg */
static CCPrepare gen_prepare_eflags_z(DisasContext* s, TCGv reg);

/* perform a conditional store into register 'reg' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used. */
static CCPrepare gen_prepare_cc(DisasContext* s, int b, TCGv reg);

void gen_setcc1(DisasContext* s, int b, TCGv reg);

inline void gen_compute_eflags_c(DisasContext* s, TCGv reg);

/* generate a conditional jump to label 'l1' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used. */
inline void gen_jcc1_noeob(DisasContext* s, int b, int l1);

/* Generate a conditional jump to label 'l1' according to jump opcode
   value 'b'. In the fast case, T0 is guaranted not to be used.
   A translation block must end soon.  */
inline void gen_jcc1(DisasContext* s, int b, int l1);

/* XXX: does not work with gdbstub "ice" single step - not a
   serious problem */
inline int gen_jz_ecx_string(DisasContext* s, target_ulong next_eip);

inline void gen_stos(DisasContext* s, TCGMemOp ot);

inline void gen_lods(DisasContext* s, TCGMemOp ot);

inline void gen_scas(DisasContext* s, TCGMemOp ot);

inline void gen_cmps(DisasContext* s, TCGMemOp ot);

inline void gen_ins(DisasContext* s, TCGMemOp ot);

inline void gen_outs(DisasContext* s, TCGMemOp ot);

/* same method as Valgrind : we generate jumps to current or next
   instruction */
#define GEN_REPZ(op)                                                          \
inline void gen_repz_ ## op(DisasContext *s, TCGMemOp ot,              \
                                 target_ulong cur_eip, target_ulong next_eip);

#define GEN_REPZ2(op)                                                         \
inline void gen_repz_ ## op(DisasContext *s, TCGMemOp ot,					\
                                   target_ulong cur_eip,                      \
                                   target_ulong next_eip,                     \
                                   int nz);                                    

GEN_REPZ(movs)
GEN_REPZ(stos)
GEN_REPZ(lods)
GEN_REPZ(ins)
GEN_REPZ(outs)
GEN_REPZ2(scas)
GEN_REPZ2(cmps)

void gen_helper_fp_arith_ST0_FT0(TCGContext* s, int op);

/* NOTE the exception in "r" op ordering */
void gen_helper_fp_arith_STN_ST0(TCGContext* s, int op, int opreg);

/* if d == OR_TMP0, it means memory operand (address in A0) */
void gen_op(DisasContext* s, int op, TCGMemOp ot, int d);

/* if d == OR_TMP0, it means memory operand (address in A0) */
void gen_inc(DisasContext* s, TCGMemOp ot, int d, int c);

void gen_shift_flags(DisasContext* s, TCGMemOp ot, TCGv result,
	TCGv shm1, TCGv count, bool is_right);

void gen_shift_rm_T1(DisasContext* s, TCGMemOp ot, int op1,
	int is_right, int is_arith);

void gen_shift_rm_im(DisasContext* s, TCGMemOp ot, int op1, int op2,
	int is_right, int is_arith);

void gen_rot_rm_T1(DisasContext* s, TCGMemOp ot, int op1, int is_right);

void gen_rot_rm_im(DisasContext* s, TCGMemOp ot, int op1, int op2,
	int is_right);

/* XXX: add faster immediate = 1 case */
void gen_rotc_rm_T1(DisasContext* s, TCGMemOp ot, int op1,
	int is_right);

/* XXX: add faster immediate case */
void gen_shiftd_rm_T1(DisasContext* s, TCGMemOp ot, int op1,
	bool is_right, TCGv count_in);

void gen_shift(DisasContext* s1, int op, TCGMemOp ot, int d, int s);

void gen_shifti(DisasContext* s, int op, TCGMemOp ot, int d, int c);

void gen_lea_modrm(CPUX86State* env, DisasContext* s, int modrm);

void gen_nop_modrm(CPUX86State* env, DisasContext* s, int modrm);

/* used for LEA and MOV AX, mem */
void gen_add_A0_ds_seg(DisasContext* s);

/* generate modrm memory load or store of 'reg'. TMP0 is used if reg ==
   OR_TMP0 */
void gen_ldst_modrm(CPUX86State* env, DisasContext* s, int modrm,
	TCGMemOp ot, int reg, int is_store);

inline uint32_t insn_get(CPUX86State* env, DisasContext* s, TCGMemOp ot);

inline int insn_const_size(TCGMemOp ot);

inline void gen_goto_tb(DisasContext* s, int tb_num, target_ulong eip);

inline void gen_jcc(DisasContext* s, int b,
	target_ulong val, target_ulong next_eip);

void gen_cmovcc1(CPUX86State* env, DisasContext* s, TCGMemOp ot, int b,
	int modrm, int reg);

inline void gen_op_movl_T0_seg(TCGContext* s, int seg_reg);

inline void gen_op_movl_seg_T0_vm(TCGContext* s, int seg_reg);

/* move T0 to seg_reg and compute if the CPU state may change. Never
   call this function with seg_reg == R_CS */
void gen_movl_seg_T0(DisasContext* s, int seg_reg, target_ulong cur_eip);

inline int svm_is_rep(int prefixes);

inline void
gen_svm_check_intercept_param(DisasContext* s, target_ulong pc_start,
	uint32_t type, uint64_t param);

inline void
gen_svm_check_intercept(DisasContext* s, target_ulong pc_start, uint64_t type);

inline void gen_stack_update(DisasContext* s, int addend);

/* Generate a push. It depends on ss32, addseg and dflag.  */
void gen_push_v(DisasContext* s, TCGv val);

/* two step pop is necessary for precise exceptions */
TCGMemOp gen_pop_T0(DisasContext* s);

void gen_pop_update(DisasContext* s, TCGMemOp ot);

void gen_stack_A0(DisasContext* s);
/* NOTE: wrap around in 16 bit not fully handled */

void gen_pusha(DisasContext* s);

/* NOTE: wrap around in 16 bit not fully handled */
void gen_popa(DisasContext* s);

void gen_enter(DisasContext* s, int esp_addend, int level);

void gen_exception(DisasContext* s, int trapno, target_ulong cur_eip);

/* an interrupt is different from an exception because of the
   privilege checks */
void gen_interrupt(DisasContext* s, int intno,
	target_ulong cur_eip, target_ulong next_eip);

void gen_debug(DisasContext* s, target_ulong cur_eip);

/* generate a generic end of block. Trace exception is also generated
   if needed */
void gen_eob(DisasContext* s);

/* generate a jump to eip. No segment change must happen before as a
   direct call to the next block may occur */
void gen_jmp_tb(DisasContext* s, target_ulong eip, int tb_num);

void gen_jmp(DisasContext* s, target_ulong eip);

inline void gen_ldq_env_A0(DisasContext* s, int offset);

inline void gen_stq_env_A0(DisasContext* s, int offset);

inline void gen_ldo_env_A0(DisasContext* s, int offset);

inline void gen_sto_env_A0(DisasContext* s, int offset);

inline void gen_op_movo(TCGContext* s, int d_offset, int s_offset);

inline void gen_op_movq(TCGContext* s, int d_offset, int s_offset);

inline void gen_op_movl(TCGContext* s, int d_offset, int s_offset);

inline void gen_op_movq_env_0(TCGContext* s, int d_offset);

typedef void (*SSEFunc_i_ep)(TCGContext* s, TCGv_i32 val, TCGv_ptr env, TCGv_ptr reg);
typedef void (*SSEFunc_l_ep)(TCGContext* s, TCGv_i64 val, TCGv_ptr env, TCGv_ptr reg);
typedef void (*SSEFunc_0_epi)(TCGContext* s, TCGv_ptr env, TCGv_ptr reg, TCGv_i32 val);
typedef void (*SSEFunc_0_epl)(TCGContext* s, TCGv_ptr env, TCGv_ptr reg, TCGv_i64 val);
typedef void (*SSEFunc_0_epp)(TCGContext* s, TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b);
typedef void (*SSEFunc_0_eppi)(TCGContext* s, TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b,
	TCGv_i32 val);
typedef void (*SSEFunc_0_ppi)(TCGContext* s, TCGv_ptr reg_a, TCGv_ptr reg_b, TCGv_i32 val);
typedef void (*SSEFunc_0_eppt)(TCGContext* s, TCGv_ptr env, TCGv_ptr reg_a, TCGv_ptr reg_b,
	TCGv val);

#define SSE_SPECIAL ((void *)1)
#define SSE_DUMMY ((void *)2)

#define MMX_OP2(x) { gen_helper_ ## x ## _mmx, gen_helper_ ## x ## _xmm }
#define SSE_FOP(x) { gen_helper_ ## x ## ps, gen_helper_ ## x ## pd, \
                     gen_helper_ ## x ## ss, gen_helper_ ## x ## sd, }

const SSEFunc_0_epp sse_op_table1[256][4] = {
	// filler: 0x00 - 0x0e
	{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},{0},

	/* 3DNow! extensions */
	{ SSE_DUMMY }, /* femms */
	{ SSE_DUMMY }, /* pf. . . */

	/* pure SSE operations */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movups, movupd, movss, movsd */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movups, movupd, movss, movsd */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movlps, movlpd, movsldup, movddup */
	{ SSE_SPECIAL, SSE_SPECIAL },  /* movlps, movlpd */
	{ gen_helper_punpckldq_xmm, gen_helper_punpcklqdq_xmm },
	{ gen_helper_punpckhdq_xmm, gen_helper_punpckhqdq_xmm },
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },  /* movhps, movhpd, movshdup */
	{ SSE_SPECIAL, SSE_SPECIAL },  /* movhps, movhpd */

	// filler: 0x18 - 0x27
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},

	/* pure SSE operations */
	{ SSE_SPECIAL, SSE_SPECIAL },  /* movaps, movapd */
	{ SSE_SPECIAL, SSE_SPECIAL },  /* movaps, movapd */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvtpi2ps, cvtpi2pd, cvtsi2ss, cvtsi2sd */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movntps, movntpd, movntss, movntsd */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvttps2pi, cvttpd2pi, cvttsd2si, cvttss2si */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* cvtps2pi, cvtpd2pi, cvtsd2si, cvtss2si */
	{ gen_helper_ucomiss, gen_helper_ucomisd },
	{ gen_helper_comiss, gen_helper_comisd },

	// filler: 0x30 - 0x37
	{0},{0},{0},{0},{0},{0},{0},{0},

	/* SSSE3, SSE4, MOVBE, CRC32, BMI1, BMI2, ADX.  */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },
	{0},	// filler: 0x39
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },

	// filler: 0x3b - 0x4f
	{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},

	/* pure SSE operations */
	{ SSE_SPECIAL, SSE_SPECIAL }, /* movmskps, movmskpd */
	SSE_FOP(sqrt),
	{ gen_helper_rsqrtps, NULL, gen_helper_rsqrtss, NULL },
	{ gen_helper_rcpps, NULL, gen_helper_rcpss, NULL },
	{ gen_helper_pand_xmm, gen_helper_pand_xmm }, /* andps, andpd */
	{ gen_helper_pandn_xmm, gen_helper_pandn_xmm }, /* andnps, andnpd */
	{ gen_helper_por_xmm, gen_helper_por_xmm }, /* orps, orpd */
	{ gen_helper_pxor_xmm, gen_helper_pxor_xmm }, /* xorps, xorpd */
	SSE_FOP(add),
	SSE_FOP(mul),
	{ gen_helper_cvtps2pd, gen_helper_cvtpd2ps,
	  gen_helper_cvtss2sd, gen_helper_cvtsd2ss },
	{ gen_helper_cvtdq2ps, gen_helper_cvtps2dq, gen_helper_cvttps2dq },
	SSE_FOP(sub),
	SSE_FOP(min),
	SSE_FOP(div),
	SSE_FOP(max),

	/* MMX ops and their SSE extensions */
	MMX_OP2(punpcklbw),
	MMX_OP2(punpcklwd),
	MMX_OP2(punpckldq),
	MMX_OP2(packsswb),
	MMX_OP2(pcmpgtb),
	MMX_OP2(pcmpgtw),
	MMX_OP2(pcmpgtl),
	MMX_OP2(packuswb),
	MMX_OP2(punpckhbw),
	MMX_OP2(punpckhwd),
	MMX_OP2(punpckhdq),
	MMX_OP2(packssdw),
	{ NULL, gen_helper_punpcklqdq_xmm },
	{ NULL, gen_helper_punpckhqdq_xmm },
	{ SSE_SPECIAL, SSE_SPECIAL }, /* movd mm, ea */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movq, movdqa, , movqdu */
	{ (SSEFunc_0_epp)gen_helper_pshufw_mmx,
	  (SSEFunc_0_epp)gen_helper_pshufd_xmm,
	  (SSEFunc_0_epp)gen_helper_pshufhw_xmm,
	  (SSEFunc_0_epp)gen_helper_pshuflw_xmm }, /* XXX: casts */
	{ SSE_SPECIAL, SSE_SPECIAL }, /* shiftw */
	{ SSE_SPECIAL, SSE_SPECIAL }, /* shiftd */
	{ SSE_SPECIAL, SSE_SPECIAL }, /* shiftq */
	MMX_OP2(pcmpeqb),
	MMX_OP2(pcmpeqw),
	MMX_OP2(pcmpeql),
	{ SSE_DUMMY }, /* emms */
	{ NULL, SSE_SPECIAL, NULL, SSE_SPECIAL }, /* extrq_i, insertq_i */
	{ NULL, gen_helper_extrq_r, NULL, gen_helper_insertq_r },
	{0},{0}, // filler: 0x7a - 0x7b
	{ NULL, gen_helper_haddpd, NULL, gen_helper_haddps },
	{ NULL, gen_helper_hsubpd, NULL, gen_helper_hsubps },
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movd, movd, , movq */
	{ SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL }, /* movq, movdqa, movdqu */

	// filler: 0x80 - 0xc1
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},

	SSE_FOP(cmpeq),

	// filler: 0xc3
	{0},

	/* MMX ops and their SSE extensions */
	{ SSE_SPECIAL, SSE_SPECIAL }, /* pinsrw */
	{ SSE_SPECIAL, SSE_SPECIAL }, /* pextrw */

	{ (SSEFunc_0_epp)gen_helper_shufps,
	  (SSEFunc_0_epp)gen_helper_shufpd }, /* XXX: casts */

	// filler: 0xc7 - 0xcf
	{0}, {0},{0},{0},{0},{0},{0},{0},{0},

	/* MMX ops and their SSE extensions */
	{ NULL, gen_helper_addsubpd, NULL, gen_helper_addsubps },
	MMX_OP2(psrlw),
	MMX_OP2(psrld),
	MMX_OP2(psrlq),
	MMX_OP2(paddq),
	MMX_OP2(pmullw),
	{ NULL, SSE_SPECIAL, SSE_SPECIAL, SSE_SPECIAL },
	{ SSE_SPECIAL, SSE_SPECIAL }, /* pmovmskb */
	MMX_OP2(psubusb),
	MMX_OP2(psubusw),
	MMX_OP2(pminub),
	MMX_OP2(pand),
	MMX_OP2(paddusb),
	MMX_OP2(paddusw),
	MMX_OP2(pmaxub),
	MMX_OP2(pandn),
	MMX_OP2(pavgb),
	MMX_OP2(psraw),
	MMX_OP2(psrad),
	MMX_OP2(pavgw),
	MMX_OP2(pmulhuw),
	MMX_OP2(pmulhw),
	{ NULL, gen_helper_cvttpd2dq, gen_helper_cvtdq2pd, gen_helper_cvtpd2dq },
	{ SSE_SPECIAL , SSE_SPECIAL },  /* movntq, movntq */
	MMX_OP2(psubsb),
	MMX_OP2(psubsw),
	MMX_OP2(pminsw),
	MMX_OP2(por),
	MMX_OP2(paddsb),
	MMX_OP2(paddsw),
	MMX_OP2(pmaxsw),
	MMX_OP2(pxor),
	{ NULL, NULL, NULL, SSE_SPECIAL }, /* lddqu */
	MMX_OP2(psllw),
	MMX_OP2(pslld),
	MMX_OP2(psllq),
	MMX_OP2(pmuludq),
	MMX_OP2(pmaddwd),
	MMX_OP2(psadbw),
	{ (SSEFunc_0_epp)gen_helper_maskmov_mmx,
	  (SSEFunc_0_epp)gen_helper_maskmov_xmm }, /* XXX: casts */
	MMX_OP2(psubb),
	MMX_OP2(psubw),
	MMX_OP2(psubl),
	MMX_OP2(psubq),
	MMX_OP2(paddb),
	MMX_OP2(paddw),
	MMX_OP2(paddl),

	// filler: 0xff
	{0},
};

const SSEFunc_0_epp sse_op_table2[3 * 8][2] = {
#ifdef _MSC_VER
	{0},{0},
	MMX_OP2(psrlw),
	{0},
	MMX_OP2(psraw),
	{0},
	MMX_OP2(psllw),
	{0},{0},{0},
	MMX_OP2(psrld),
	{0},
	MMX_OP2(psrad),
	{0},
	MMX_OP2(pslld),
	{0},{0},{0},
	MMX_OP2(psrlq),
	{ NULL, gen_helper_psrldq_xmm },
	{0},{0},
	MMX_OP2(psllq),
	{ NULL, gen_helper_pslldq_xmm },
#else
	[0 + 2] = MMX_OP2(psrlw),
	[0 + 4] = MMX_OP2(psraw),
	[0 + 6] = MMX_OP2(psllw),
	[8 + 2] = MMX_OP2(psrld),
	[8 + 4] = MMX_OP2(psrad),
	[8 + 6] = MMX_OP2(pslld),
	[16 + 2] = MMX_OP2(psrlq),
	[16 + 3] = { NULL, gen_helper_psrldq_xmm },
	[16 + 6] = MMX_OP2(psllq),
	[16 + 7] = { NULL, gen_helper_pslldq_xmm },
#endif
};

const SSEFunc_0_epi sse_op_table3ai[] = {
	gen_helper_cvtsi2ss,
	gen_helper_cvtsi2sd
};

#ifdef TARGET_X86_64
const SSEFunc_0_epl sse_op_table3aq[] = {
	gen_helper_cvtsq2ss,
	gen_helper_cvtsq2sd
};
#endif

const SSEFunc_i_ep sse_op_table3bi[] = {
	gen_helper_cvttss2si,
	gen_helper_cvtss2si,
	gen_helper_cvttsd2si,
	gen_helper_cvtsd2si
};

#ifdef TARGET_X86_64
const SSEFunc_l_ep sse_op_table3bq[] = {
	gen_helper_cvttss2sq,
	gen_helper_cvtss2sq,
	gen_helper_cvttsd2sq,
	gen_helper_cvtsd2sq
};
#endif

const SSEFunc_0_epp sse_op_table4[8][4] = {
	SSE_FOP(cmpeq),
	SSE_FOP(cmplt),
	SSE_FOP(cmple),
	SSE_FOP(cmpunord),
	SSE_FOP(cmpneq),
	SSE_FOP(cmpnlt),
	SSE_FOP(cmpnle),
	SSE_FOP(cmpord),
};

const SSEFunc_0_epp sse_op_table5[256] = {
#ifdef _MSC_VER
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},      // filler: 0x00 - 0x0b
	gen_helper_pi2fw,
	gen_helper_pi2fd,
	{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0}, // filler: 0x0e - 0x01b
	gen_helper_pf2iw,
	gen_helper_pf2id,
	// filler: 0x1e - 0x89
	{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},
	gen_helper_pfnacc,
	{0},{0},{0},    // filler: 0x8b - 0x8d
	gen_helper_pfpnacc,
	{0},            // filler: 0x8f
	gen_helper_pfcmpge,
	{0},{0},{0},    // filler: 0x91 - 0x93
	gen_helper_pfmin,
	{0},            // filler: 0x95
	gen_helper_pfrcp,
	gen_helper_pfrsqrt,
	{0},{0},        // filler: 0x98 - 0x99
	gen_helper_pfsub,
	{0},{0},{0},    // filler: 0x9b - 0x9d
	gen_helper_pfadd,
	{0},            // filler: 0x9f
	gen_helper_pfcmpgt,
	{0},{0},{0},    // filler: 0xa1 - 0xa3
	gen_helper_pfmax,
	{0},            // filler: 0xa5
	gen_helper_movq, /* pfrcpit1; no need to actually increase precision */
	gen_helper_movq, /* pfrsqit1 */
	{0},{0},        // filler: 0xa8 - 0xa9
	gen_helper_pfsubr,
	{0},{0},{0},    // filler: 0xab - 0xad
	gen_helper_pfacc,
	{0},            // filler: 0xaf
	gen_helper_pfcmpeq,
	{0},{0},{0},    // filler: 0xb1 - 0xb3
	gen_helper_pfmul,
	{0},            // filler: 0xb5
	gen_helper_movq, /* pfrcpit2 */
	gen_helper_pmulhrw_mmx,
	{0},{0},{0},    // filler: 0xb8 - 0xba
	gen_helper_pswapd,
	{0},{0},{0},    // filler: 0xbc - 0xbe
	gen_helper_pavgb_mmx, /* pavgusb */
	// filler: 0xc0 - 0xff
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
	{0},{0},{0},{0},{0},{0},{0},{0}, {0},{0},{0},{0},{0},{0},{0},{0},
#else
	[0x0c] = gen_helper_pi2fw,
	[0x0d] = gen_helper_pi2fd,
	[0x1c] = gen_helper_pf2iw,
	[0x1d] = gen_helper_pf2id,
	[0x8a] = gen_helper_pfnacc,
	[0x8e] = gen_helper_pfpnacc,
	[0x90] = gen_helper_pfcmpge,
	[0x94] = gen_helper_pfmin,
	[0x96] = gen_helper_pfrcp,
	[0x97] = gen_helper_pfrsqrt,
	[0x9a] = gen_helper_pfsub,
	[0x9e] = gen_helper_pfadd,
	[0xa0] = gen_helper_pfcmpgt,
	[0xa4] = gen_helper_pfmax,
	[0xa6] = gen_helper_movq, /* pfrcpit1; no need to actually increase precision */
	[0xa7] = gen_helper_movq, /* pfrsqit1 */
	[0xaa] = gen_helper_pfsubr,
	[0xae] = gen_helper_pfacc,
	[0xb0] = gen_helper_pfcmpeq,
	[0xb4] = gen_helper_pfmul,
	[0xb6] = gen_helper_movq, /* pfrcpit2 */
	[0xb7] = gen_helper_pmulhrw_mmx,
	[0xbb] = gen_helper_pswapd,
	[0xbf] = gen_helper_pavgb_mmx /* pavgusb */
#endif
};

struct SSEOpHelper_epp {
	SSEFunc_0_epp op[2];
	uint32_t ext_mask;
};

struct SSEOpHelper_eppi {
	SSEFunc_0_eppi op[2];
	uint32_t ext_mask;
};

#define SSSE3_OP(x) { MMX_OP2(x), CPUID_EXT_SSSE3 }
#define SSE41_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_SSE41 }
#define SSE42_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_SSE42 }
#define SSE41_SPECIAL { { NULL, SSE_SPECIAL }, CPUID_EXT_SSE41 }
#define PCLMULQDQ_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, \
        CPUID_EXT_PCLMULQDQ }
#define AESNI_OP(x) { { NULL, gen_helper_ ## x ## _xmm }, CPUID_EXT_AES }

const struct SSEOpHelper_epp sse_op_table6[256] = {
	SSSE3_OP(pshufb),
	SSSE3_OP(phaddw),
	SSSE3_OP(phaddd),
	SSSE3_OP(phaddsw),
	SSSE3_OP(pmaddubsw),
	SSSE3_OP(phsubw),
	SSSE3_OP(phsubd),
	SSSE3_OP(phsubsw),
	SSSE3_OP(psignb),
	SSSE3_OP(psignw),
	SSSE3_OP(psignd),
	SSSE3_OP(pmulhrsw),
	{{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x0c - 0x0f
	SSE41_OP(pblendvb),
	{{0},0},{{0},0},{{0},0},     // filler: 0x11 - 0x13
	SSE41_OP(blendvps),
	SSE41_OP(blendvpd),
	{{0},0},             // filler: 0x16
	SSE41_OP(ptest),
	{{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x18 - 0x1b
	SSSE3_OP(pabsb),
	SSSE3_OP(pabsw),
	SSSE3_OP(pabsd),
	{{0},0},             // filler: 0x1f
	SSE41_OP(pmovsxbw),
	SSE41_OP(pmovsxbd),
	SSE41_OP(pmovsxbq),
	SSE41_OP(pmovsxwd),
	SSE41_OP(pmovsxwq),
	SSE41_OP(pmovsxdq),
	{{0},0},{{0},0},         // filler: 0x26 - 0x27
	SSE41_OP(pmuldq),
	SSE41_OP(pcmpeqq),
	SSE41_SPECIAL, /* movntqda */
	SSE41_OP(packusdw),
	{{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x2c - 0x2f
	SSE41_OP(pmovzxbw),
	SSE41_OP(pmovzxbd),
	SSE41_OP(pmovzxbq),
	SSE41_OP(pmovzxwd),
	SSE41_OP(pmovzxwq),
	SSE41_OP(pmovzxdq),
	{{0},0},             // filler: 0x36
	SSE42_OP(pcmpgtq),
	SSE41_OP(pminsb),
	SSE41_OP(pminsd),
	SSE41_OP(pminuw),
	SSE41_OP(pminud),
	SSE41_OP(pmaxsb),
	SSE41_OP(pmaxsd),
	SSE41_OP(pmaxuw),
	SSE41_OP(pmaxud),
	SSE41_OP(pmulld),
	SSE41_OP(phminposuw),
	// filler: 0x42 - 0xda
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},
	AESNI_OP(aesimc),
	AESNI_OP(aesenc),
	AESNI_OP(aesenclast),
	AESNI_OP(aesdec),
	AESNI_OP(aesdeclast),
	// filler: 0xe0 - 0xff
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
};

const struct SSEOpHelper_eppi sse_op_table7[256] = {
#ifdef _MSC_VER
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x00 - 0x07
	SSE41_OP(roundps),
	SSE41_OP(roundpd),
	SSE41_OP(roundss),
	SSE41_OP(roundsd),
	SSE41_OP(blendps),
	SSE41_OP(blendpd),
	SSE41_OP(pblendw),
	SSSE3_OP(palignr),
	{{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x10 - 0x13
	SSE41_SPECIAL, /* pextrb */
	SSE41_SPECIAL, /* pextrw */
	SSE41_SPECIAL, /* pextrd/pextrq */
	SSE41_SPECIAL, /* extractps */
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, // filler: 0x18 - 0x1f
	SSE41_SPECIAL, /* pinsrb */
	SSE41_SPECIAL, /* insertps */
	SSE41_SPECIAL, /* pinsrd/pinsrq */
	// filler: 0x23 - 0x3f
							{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	SSE41_OP(dpps),
	SSE41_OP(dppd),
	SSE41_OP(mpsadbw),
	{{0},0}, // filler: 0x43
	PCLMULQDQ_OP(pclmulqdq),
	// filler: 0x45 - 0x5f
											{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	SSE42_OP(pcmpestrm),
	SSE42_OP(pcmpestri),
	SSE42_OP(pcmpistrm),
	SSE42_OP(pcmpistri),
	// filler: 0x64 - 0xde
									{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	AESNI_OP(aeskeygenassist),
	// filler: 0xe0 - 0xff
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
	{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0}, {{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},{{0},0},
#else
	[0x08] = SSE41_OP(roundps),
	[0x09] = SSE41_OP(roundpd),
	[0x0a] = SSE41_OP(roundss),
	[0x0b] = SSE41_OP(roundsd),
	[0x0c] = SSE41_OP(blendps),
	[0x0d] = SSE41_OP(blendpd),
	[0x0e] = SSE41_OP(pblendw),
	[0x0f] = SSSE3_OP(palignr),
	[0x14] = SSE41_SPECIAL, /* pextrb */
	[0x15] = SSE41_SPECIAL, /* pextrw */
	[0x16] = SSE41_SPECIAL, /* pextrd/pextrq */
	[0x17] = SSE41_SPECIAL, /* extractps */
	[0x20] = SSE41_SPECIAL, /* pinsrb */
	[0x21] = SSE41_SPECIAL, /* insertps */
	[0x22] = SSE41_SPECIAL, /* pinsrd/pinsrq */
	[0x40] = SSE41_OP(dpps),
	[0x41] = SSE41_OP(dppd),
	[0x42] = SSE41_OP(mpsadbw),
	[0x44] = PCLMULQDQ_OP(pclmulqdq),
	[0x60] = SSE42_OP(pcmpestrm),
	[0x61] = SSE42_OP(pcmpestri),
	[0x62] = SSE42_OP(pcmpistrm),
	[0x63] = SSE42_OP(pcmpistri),
	[0xdf] = AESNI_OP(aeskeygenassist),
#endif
};

void gen_sse(CPUX86State* env, DisasContext* s, int b,
	target_ulong pc_start, int rex_r);

// Unicorn: sync EFLAGS on demand
void sync_eflags(DisasContext* s, TCGContext* tcg_ctx);

/*
void restore_eflags(DisasContext *s, TCGContext *tcg_ctx)
{
	TCGv **cpu_T = (TCGv **)tcg_ctx->cpu_T;
	TCGv_ptr cpu_env = tcg_ctx->cpu_env;

	tcg_gen_ld_tl(tcg_ctx, *cpu_T[0], cpu_env, offsetof(CPUX86State, eflags));
	gen_helper_write_eflags(tcg_ctx, cpu_env, *cpu_T[0],
			tcg_const_i32(tcg_ctx, (TF_MASK | AC_MASK | ID_MASK | NT_MASK) & 0xffff));
	set_cc_op(s, CC_OP_EFLAGS);
}
*/

/* convert one instruction. s->is_jmp is set if the translation must
   be stopped. Return the next pc value */
target_ulong disas_insn(CPUX86State* env, DisasContext* s,
	target_ulong pc_start);   // qq

void optimize_flags_init(struct uc_struct* uc);

/* generate intermediate code in gen_opc_buf and gen_opparam_buf for
   basic block 'tb'. If search_pc is TRUE, also generate PC
   information for each intermediate instruction. */
inline void gen_intermediate_code_internal(uint8_t* gen_opc_cc_op,
	X86CPU* cpu,
	TranslationBlock* tb,
	bool search_pc);

void gen_intermediate_code(CPUX86State* env, TranslationBlock* tb);

void gen_intermediate_code_pc(CPUX86State* env, TranslationBlock* tb);

void restore_state_to_opc(CPUX86State* env, TranslationBlock* tb, int pc_pos);
