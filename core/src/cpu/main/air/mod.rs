pub mod register;

use core::borrow::Borrow;
use p3_air::Air;
use p3_air::AirBuilder;
use p3_air::AirBuilderWithPublicValues;
use p3_air::BaseAir;
use p3_field::AbstractField;
use p3_matrix::Matrix;

use crate::air::BaseAirBuilder;
use crate::air::PublicValues;
use crate::air::SP1AirBuilder;
use crate::air::Word;
use crate::air::SP1_PROOF_NUM_PV_ELTS;
use crate::bytes::ByteOpcode;
use crate::cpu::main::columns::{CpuCols, NUM_CPU_COLS};
use crate::cpu::CpuChip;
use crate::memory::MemoryCols;

use super::columns::eval_channel_selectors;
use super::columns::OPCODE_SELECTORS_COL_MAP;

impl<AB> Air<AB> for CpuChip
where
    AB: SP1AirBuilder + AirBuilderWithPublicValues,
    AB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &CpuCols<AB::Var> = (*local).borrow();
        let next: &CpuCols<AB::Var> = (*next).borrow();
        let public_values_slice: [AB::Expr; SP1_PROOF_NUM_PV_ELTS] =
            core::array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<AB::Expr>, AB::Expr> =
            public_values_slice.as_slice().borrow();

        // Program constraints.
        builder.send_program(
            local.pc,
            local.instruction,
            local.selectors,
            local.shard,
            local.is_real,
        );

        // Compute some flags for which type of instruction we are dealing with.
        let is_memory_instruction: AB::Expr = local.selectors.is_memory_instruction::<AB>();
        let is_branch_instruction: AB::Expr = local.selectors.is_branch_instruction::<AB>();
        let is_alu_instruction: AB::Expr = local.selectors.is_alu_instruction::<AB>();
        let is_jump_instruction = local.selectors.is_jal + local.selectors.is_jalr;

        // Register constraints.
        self.eval_registers::<AB>(builder, local, is_branch_instruction.clone());

        // Channel constraints.
        eval_channel_selectors(
            builder,
            &local.channel_selectors,
            &next.channel_selectors,
            local.channel,
            local.is_real,
            next.is_real,
        );

        // ALU instructions.
        builder.send_alu(
            local.instruction.opcode,
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            local.shard,
            local.channel,
            local.nonce,
            is_alu_instruction,
        );

        // Verify all non ALU instructions in the cpu aux table.
        builder.send_instruction(
            local.clk,
            local.shard,
            local.channel,
            local.pc,
            local.next_pc,
            local.selectors,
            local.op_a_prev_val(),
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            local.instruction.op_a_0,
            local.is_halt,
            is_branch_instruction.clone()
                + is_jump_instruction.clone()
                + is_memory_instruction.clone()
                + local.selectors.is_auipc
                + local.selectors.is_ecall,
        );

        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.next_pc, next.pc);

        // If we're halting (e.g. next_pc == 0) and it's a transition, then the next.is_real should be 0.
        builder
            .when_transition()
            .when(local.is_halt + local.selectors.is_unimpl)
            .assert_zero(next.is_real);

        // Check that the shard and clk is updated correctly.
        self.eval_shard_clk(builder, local, next);

        // Check public values constraints.  Note that the public value's exit value and commit/commit_deferred_proofs
        // related values are checked in eval_halt and eval_commit.
        self.eval_public_values(builder, local, next, public_values);

        // Check that the is_real flag is correct.
        self.eval_is_real(builder, local, next);

        // Check that when `is_real=0` that all flags that send interactions are zero.
        local
            .selectors
            .into_iter()
            .enumerate()
            .for_each(|(i, selector)| {
                if i == OPCODE_SELECTORS_COL_MAP.imm_b {
                    builder
                        .when(AB::Expr::one() - local.is_real)
                        .assert_one(local.selectors.imm_b);
                } else if i == OPCODE_SELECTORS_COL_MAP.imm_c {
                    builder
                        .when(AB::Expr::one() - local.is_real)
                        .assert_one(local.selectors.imm_c);
                } else {
                    builder
                        .when(AB::Expr::one() - local.is_real)
                        .assert_zero(selector);
                }
            });
    }
}

impl CpuChip {
    /// Constraints related to the shard and clk.
    ///
    /// This method ensures that all of the shard values are the same and that the clk starts at 0
    /// and is transitioned apporpriately.  It will also check that shard values are within 16 bits
    /// and clk values are within 24 bits.  Those range checks are needed for the memory access
    /// timestamp check, which assumes those values are within 2^24.  See [`MemoryAirBuilder::verify_mem_access_ts`].
    pub(crate) fn eval_shard_clk<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Verify that all shard values are the same.
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(local.shard, next.shard);

        // Verify that the shard value is within 16 bits.
        builder.send_byte(
            AB::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            local.shard,
            AB::Expr::zero(),
            AB::Expr::zero(),
            local.shard,
            local.channel,
            local.is_real,
        );

        // Verify that the first row has a clk value of 0.
        builder.when_first_row().assert_zero(local.clk);

        // Verify that the clk increments are correct.  Most clk increment should be 4, but for some
        // precompiles, there are additional cycles.
        let num_extra_cycles = self.get_num_extra_ecall_cycles::<AB>(local);

        // We already assert that `local.clk < 2^24`. `num_extra_cycles` is an entry of a word and
        // therefore less than `2^8`, this means that the sum cannot overflow in a 31 bit field.
        let expected_next_clk =
            local.clk + AB::Expr::from_canonical_u32(4) + num_extra_cycles.clone();

        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(expected_next_clk.clone(), next.clk);

        // Range check that the clk is within 24 bits using it's limb values.
        builder.eval_range_check_24bits(
            local.clk,
            local.clk_16bit_limb,
            local.clk_8bit_limb,
            local.shard,
            local.channel,
            local.is_real,
        );
    }

    /// Constraints related to the public values.
    pub(crate) fn eval_public_values<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
        public_values: &PublicValues<Word<AB::Expr>, AB::Expr>,
    ) {
        // Verify the public value's shard.
        builder
            .when(local.is_real)
            .assert_eq(public_values.execution_shard.clone(), local.shard);

        // Verify the public value's start pc.
        builder
            .when_first_row()
            .assert_eq(public_values.start_pc.clone(), local.pc);

        // Verify the public value's next pc.  We need to handle two cases:
        // 1. The last real row is a transition row.
        // 2. The last real row is the last row.

        // If the last real row is a transition row, verify the public value's next pc.
        builder
            .when_transition()
            .when(local.is_real - next.is_real)
            .assert_eq(public_values.next_pc.clone(), local.next_pc);

        // If the last real row is the last row, verify the public value's next pc.
        builder
            .when_last_row()
            .when(local.is_real)
            .assert_eq(public_values.next_pc.clone(), local.next_pc);
    }

    /// Constraints related to the is_real column.
    ///
    /// This method checks that the is_real column is a boolean.  It also checks that the first row
    /// is 1 and once its 0, it never changes value.
    pub(crate) fn eval_is_real<AB: SP1AirBuilder>(
        &self,
        builder: &mut AB,
        local: &CpuCols<AB::Var>,
        next: &CpuCols<AB::Var>,
    ) {
        // Check the is_real flag.  It should be 1 for the first row.  Once its 0, it should never
        // change value.
        builder.assert_bool(local.is_real);
        builder.when_first_row().assert_one(local.is_real);
        builder
            .when_transition()
            .when_not(local.is_real)
            .assert_zero(next.is_real);
    }

    /// Returns the number of extra cycles from an ECALL instruction.
    pub(crate) fn get_num_extra_ecall_cycles<AB: SP1AirBuilder>(
        &self,
        local: &CpuCols<AB::Var>,
    ) -> AB::Expr {
        let is_ecall_instruction = local.selectors.is_ecall_instruction::<AB>();

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        let num_extra_cycles = syscall_code[2];

        num_extra_cycles * is_ecall_instruction.clone()
    }
}

impl<F> BaseAir<F> for CpuChip {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }
}