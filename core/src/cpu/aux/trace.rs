use std::{array, borrow::BorrowMut};

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::{PrimeField, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelBridge, ParallelIterator, ParallelSlice};
use tracing::instrument;

use crate::{
    air::{MachineAir, Word, WORD_SIZE},
    alu::{self, create_alu_lookups, AluEvent},
    bytes::{event::ByteRecord, ByteLookupEvent, ByteOpcode},
    cpu::{CpuAuxChip, CpuEvent},
    runtime::Register::X0,
    runtime::{ExecutionRecord, Opcode, Program, SyscallCode},
};

use super::columns::{CpuAuxCols, NUM_CPU_AUX_COLS};

impl<F: PrimeField32> MachineAir<F> for CpuAuxChip {
    type Record = ExecutionRecord;

    type Program = Program;

    fn name(&self) -> String {
        "CPUAux".to_string()
    }

    fn generate_trace(
        &self,
        input: &ExecutionRecord,
        _: &mut ExecutionRecord,
    ) -> RowMajorMatrix<F> {
        let filtered_cpu_events = input
            .cpu_events
            .iter()
            .filter(|event| Self::add_to_cpu_aux_chip(event))
            .collect_vec();

        let num_real_rows = filtered_cpu_events.len();
        let mut rows = vec![F::zero(); num_real_rows * NUM_CPU_AUX_COLS];

        let chunk_size = std::cmp::max(num_real_rows / num_cpus::get(), 1);
        rows.chunks_mut(chunk_size * NUM_CPU_AUX_COLS)
            .enumerate()
            .par_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_CPU_AUX_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut CpuAuxCols<F> = row.borrow_mut();
                        self.event_to_row(
                            filtered_cpu_events[idx],
                            &input.nonce_lookup,
                            &mut Vec::new(),
                            cols,
                        );
                    });
            });

        let padded_nb_rows = if num_real_rows < 16 {
            16
        } else {
            num_real_rows.next_power_of_two()
        };
        rows.resize(padded_nb_rows * NUM_CPU_AUX_COLS, F::zero());

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows, NUM_CPU_AUX_COLS)
    }

    #[instrument(
        name = "generate cpu opcode specific dependencies",
        level = "debug",
        skip_all
    )]
    fn generate_dependencies(&self, input: &ExecutionRecord, output: &mut ExecutionRecord) {
        // Generate the trace rows for each event.
        let filtered_cpu_events = input
            .cpu_events
            .iter()
            .filter(|event| Self::add_to_cpu_aux_chip(event))
            .collect_vec();

        let chunk_size = std::cmp::max(filtered_cpu_events.len() / num_cpus::get(), 1);

        let (alu_events, blu_events): (Vec<_>, Vec<_>) = filtered_cpu_events
            .par_chunks(chunk_size)
            .map(|ops: &[&CpuEvent]| {
                let mut alu = HashMap::new();
                let mut blu = HashMap::new();
                ops.iter().for_each(|op| {
                    let mut row = [F::zero(); NUM_CPU_AUX_COLS];
                    let cols: &mut CpuAuxCols<F> = row.as_mut_slice().borrow_mut();
                    let alu_events = self.event_to_row::<F>(op, &HashMap::new(), &mut blu, cols);
                    alu_events.into_iter().for_each(|(key, value)| {
                        alu.entry(key).or_insert(Vec::default()).extend(value);
                    });
                });
                (alu, blu)
            })
            .unzip();

        for alu_events_chunk in alu_events.into_iter() {
            output.add_alu_events(alu_events_chunk);
        }

        output.add_sharded_byte_lookup_events(blu_events.iter().collect_vec());
    }

    fn included(&self, input: &Self::Record) -> bool {
        let first_event = input
            .cpu_events
            .iter()
            .find(|event| Self::add_to_cpu_aux_chip(event));

        first_event.is_some()
    }
}

impl CpuAuxChip {
    fn add_to_cpu_aux_chip(event: &CpuEvent) -> bool {
        let instruction = event.instruction;
        instruction.is_branch_instruction()
            || instruction.is_jump_instruction()
            || instruction.is_memory_instruction()
            || instruction.is_ecall_instruction()
            || instruction.opcode == Opcode::AUIPC
    }

    /// Create a row from an event.
    fn event_to_row<F: PrimeField32>(
        &self,
        event: &CpuEvent,
        nonce_lookup: &HashMap<usize, u32>,
        blu_events: &mut impl ByteRecord,
        cols: &mut CpuAuxCols<F>,
    ) -> HashMap<Opcode, Vec<alu::AluEvent>> {
        let mut new_alu_events = HashMap::new();

        cols.clk = F::from_canonical_u32(event.clk);
        cols.shard = F::from_canonical_u32(event.shard);
        cols.channel = F::from_canonical_u32(event.channel);

        // Populate basic fields.
        cols.pc = F::from_canonical_u32(event.pc);
        cols.next_pc = F::from_canonical_u32(event.next_pc);
        cols.selectors.populate(event.instruction);

        if let Some(record) = event.a_record {
            cols.op_a_val = record.value().into();
            cols.op_a_prev_val = record.prev_value().into();
        } else {
            cols.op_a_val = event.a.into();
        }

        if let Some(record) = event.b_record {
            cols.op_b_val = record.value().into();
        } else {
            cols.op_b_val = event.b.into();
        }

        if let Some(record) = event.c_record {
            cols.op_c_val = record.value().into();
        } else {
            cols.op_c_val = event.c.into();
        }

        cols.op_a_0 = F::from_bool(event.instruction.op_a == X0 as u32);

        self.populate_branch(cols, event, &mut new_alu_events, nonce_lookup);
        self.populate_jump(cols, event, &mut new_alu_events, nonce_lookup);
        self.populate_auipc(cols, event, &mut new_alu_events, nonce_lookup);
        self.populate_memory(cols, event, &mut new_alu_events, blu_events, nonce_lookup);
        self.populate_ecall(cols, event, nonce_lookup);

        // Assert that the instruction is not a no-op.
        cols.is_real = F::one();

        new_alu_events
    }

    /// Populate columns related to AUIPC.
    fn populate_auipc<F: PrimeField>(
        &self,
        cols: &mut CpuAuxCols<F>,
        event: &CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
        nonce_lookup: &HashMap<usize, u32>,
    ) {
        if matches!(event.instruction.opcode, Opcode::AUIPC) {
            let auipc_columns = cols.opcode_specific_columns.auipc_mut();

            auipc_columns.pc = Word::from(event.pc);
            auipc_columns.pc_range_checker.populate(event.pc);

            let add_event = AluEvent {
                lookup_id: event.auipc_lookup_id,
                shard: event.shard,
                channel: event.channel,
                opcode: Opcode::ADD,
                a: event.a,
                b: event.pc,
                c: event.b,
                sub_lookups: create_alu_lookups(),
            };
            auipc_columns.auipc_nonce = F::from_canonical_u32(
                nonce_lookup
                    .get(&event.auipc_lookup_id)
                    .copied()
                    .unwrap_or_default(),
            );

            alu_events
                .entry(Opcode::ADD)
                .and_modify(|op_new_events| op_new_events.push(add_event))
                .or_insert(vec![add_event]);
        }
    }

    /// Populates columns related to branching.
    fn populate_branch<F: PrimeField>(
        &self,
        cols: &mut CpuAuxCols<F>,
        event: &CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
        nonce_lookup: &HashMap<usize, u32>,
    ) {
        if event.instruction.is_branch_instruction() {
            let branch_columns = cols.opcode_specific_columns.branch_mut();

            let a_eq_b = event.a == event.b;

            let use_signed_comparison =
                matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);

            let a_lt_b = if use_signed_comparison {
                (event.a as i32) < (event.b as i32)
            } else {
                event.a < event.b
            };
            let a_gt_b = if use_signed_comparison {
                (event.a as i32) > (event.b as i32)
            } else {
                event.a > event.b
            };

            let alu_op_code = if use_signed_comparison {
                Opcode::SLT
            } else {
                Opcode::SLTU
            };

            // Add the ALU events for the comparisons
            let lt_comp_event = AluEvent {
                lookup_id: event.branch_lt_lookup_id,
                shard: event.shard,
                channel: event.channel,
                opcode: alu_op_code,
                a: a_lt_b as u32,
                b: event.a,
                c: event.b,
                sub_lookups: create_alu_lookups(),
            };
            branch_columns.a_lt_b_nonce = F::from_canonical_u32(
                nonce_lookup
                    .get(&event.branch_lt_lookup_id)
                    .copied()
                    .unwrap_or_default(),
            );

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(lt_comp_event))
                .or_insert(vec![lt_comp_event]);

            let gt_comp_event = AluEvent {
                lookup_id: event.branch_gt_lookup_id,
                shard: event.shard,
                channel: event.channel,
                opcode: alu_op_code,
                a: a_gt_b as u32,
                b: event.b,
                c: event.a,
                sub_lookups: create_alu_lookups(),
            };
            branch_columns.a_gt_b_nonce = F::from_canonical_u32(
                nonce_lookup
                    .get(&event.branch_gt_lookup_id)
                    .copied()
                    .unwrap_or_default(),
            );

            alu_events
                .entry(alu_op_code)
                .and_modify(|op_new_events| op_new_events.push(gt_comp_event))
                .or_insert(vec![gt_comp_event]);

            branch_columns.a_eq_b = F::from_bool(a_eq_b);
            branch_columns.a_lt_b = F::from_bool(a_lt_b);
            branch_columns.a_gt_b = F::from_bool(a_gt_b);

            let branching = match event.instruction.opcode {
                Opcode::BEQ => a_eq_b,
                Opcode::BNE => !a_eq_b,
                Opcode::BLT | Opcode::BLTU => a_lt_b,
                Opcode::BGE | Opcode::BGEU => a_eq_b || a_gt_b,
                _ => unreachable!(),
            };

            let next_pc = event.pc.wrapping_add(event.c);
            branch_columns.pc = Word::from(event.pc);
            branch_columns.next_pc = Word::from(next_pc);
            branch_columns.pc_range_checker.populate(event.pc);
            branch_columns.next_pc_range_checker.populate(next_pc);

            if branching {
                cols.branching = F::one();

                let add_event = AluEvent {
                    lookup_id: event.branch_add_lookup_id,
                    shard: event.shard,
                    channel: event.channel,
                    opcode: Opcode::ADD,
                    a: next_pc,
                    b: event.pc,
                    c: event.c,
                    sub_lookups: create_alu_lookups(),
                };
                branch_columns.next_pc_nonce = F::from_canonical_u32(
                    nonce_lookup
                        .get(&event.branch_add_lookup_id)
                        .copied()
                        .unwrap_or_default(),
                );

                alu_events
                    .entry(Opcode::ADD)
                    .and_modify(|op_new_events| op_new_events.push(add_event))
                    .or_insert(vec![add_event]);
            } else {
                cols.not_branching = F::one();
            }
        }
    }

    /// Populate columns related to jumping.
    fn populate_jump<F: PrimeField>(
        &self,
        cols: &mut CpuAuxCols<F>,
        event: &CpuEvent,
        alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
        nonce_lookup: &HashMap<usize, u32>,
    ) {
        if event.instruction.is_jump_instruction() {
            let jump_columns = cols.opcode_specific_columns.jump_mut();

            match event.instruction.opcode {
                Opcode::JAL => {
                    let next_pc = event.pc.wrapping_add(event.b);
                    jump_columns.op_a_range_checker.populate(event.a);
                    jump_columns.pc = Word::from(event.pc);
                    jump_columns.pc_range_checker.populate(event.pc);
                    jump_columns.next_pc = Word::from(next_pc);
                    jump_columns.next_pc_range_checker.populate(next_pc);

                    let add_event = AluEvent {
                        lookup_id: event.jump_jal_lookup_id,
                        shard: event.shard,
                        channel: event.channel,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.pc,
                        c: event.b,
                        sub_lookups: create_alu_lookups(),
                    };
                    jump_columns.jal_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(&event.jump_jal_lookup_id)
                            .copied()
                            .unwrap_or_default(),
                    );

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                Opcode::JALR => {
                    let next_pc = event.b.wrapping_add(event.c);
                    jump_columns.op_a_range_checker.populate(event.a);
                    jump_columns.next_pc = Word::from(next_pc);
                    jump_columns.next_pc_range_checker.populate(next_pc);

                    let add_event = AluEvent {
                        lookup_id: event.jump_jalr_lookup_id,
                        shard: event.shard,
                        channel: event.channel,
                        opcode: Opcode::ADD,
                        a: next_pc,
                        b: event.b,
                        c: event.c,
                        sub_lookups: create_alu_lookups(),
                    };
                    jump_columns.jalr_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(&event.jump_jalr_lookup_id)
                            .copied()
                            .unwrap_or_default(),
                    );

                    alu_events
                        .entry(Opcode::ADD)
                        .and_modify(|op_new_events| op_new_events.push(add_event))
                        .or_insert(vec![add_event]);
                }
                _ => unreachable!(),
            }
        }
    }

    /// Populates columns related to memory.
    fn populate_memory<F: PrimeField32>(
        &self,
        cols: &mut CpuAuxCols<F>,
        event: &CpuEvent,
        new_alu_events: &mut HashMap<Opcode, Vec<alu::AluEvent>>,
        blu_events: &mut impl ByteRecord,
        nonce_lookup: &HashMap<usize, u32>,
    ) {
        if !matches!(
            event.instruction.opcode,
            Opcode::LB
                | Opcode::LH
                | Opcode::LW
                | Opcode::LBU
                | Opcode::LHU
                | Opcode::SB
                | Opcode::SH
                | Opcode::SW
        ) {
            return;
        }

        // Populate memory accesses for reading from memory.
        assert_eq!(event.memory_record.is_some(), event.memory.is_some());
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        if let Some(record) = event.memory_record {
            memory_columns
                .memory_access
                .populate(event.channel, record, blu_events)
        }

        // Populate addr_word and addr_aligned columns.
        let memory_columns = cols.opcode_specific_columns.memory_mut();
        let memory_addr = event.b.wrapping_add(event.c);
        let aligned_addr = memory_addr - memory_addr % WORD_SIZE as u32;
        memory_columns.addr_word = memory_addr.into();
        memory_columns.addr_word_range_checker.populate(memory_addr);
        memory_columns.addr_aligned = F::from_canonical_u32(aligned_addr);

        // Populate the aa_least_sig_byte_decomp columns.
        assert!(aligned_addr % 4 == 0);
        let aligned_addr_ls_byte = (aligned_addr & 0x000000FF) as u8;
        let bits: [bool; 8] = array::from_fn(|i| aligned_addr_ls_byte & (1 << i) != 0);
        memory_columns.aa_least_sig_byte_decomp = array::from_fn(|i| F::from_bool(bits[i + 2]));

        // Add event to ALU check to check that addr == b + c
        let add_event = AluEvent {
            lookup_id: event.memory_add_lookup_id,
            shard: event.shard,
            channel: event.channel,
            opcode: Opcode::ADD,
            a: memory_addr,
            b: event.b,
            c: event.c,
            sub_lookups: create_alu_lookups(),
        };
        new_alu_events
            .entry(Opcode::ADD)
            .and_modify(|op_new_events| op_new_events.push(add_event))
            .or_insert(vec![add_event]);
        memory_columns.addr_word_nonce = F::from_canonical_u32(
            nonce_lookup
                .get(&event.memory_add_lookup_id)
                .copied()
                .unwrap_or_default(),
        );

        // Populate memory offsets.
        let addr_offset = (memory_addr % WORD_SIZE as u32) as u8;
        memory_columns.addr_offset = F::from_canonical_u8(addr_offset);
        memory_columns.offset_is_one = F::from_bool(addr_offset == 1);
        memory_columns.offset_is_two = F::from_bool(addr_offset == 2);
        memory_columns.offset_is_three = F::from_bool(addr_offset == 3);

        // If it is a load instruction, set the unsigned_mem_val column.
        let mem_value = event.memory_record.unwrap().value();
        if matches!(
            event.instruction.opcode,
            Opcode::LB | Opcode::LBU | Opcode::LH | Opcode::LHU | Opcode::LW
        ) {
            match event.instruction.opcode {
                Opcode::LB | Opcode::LBU => {
                    cols.unsigned_mem_val =
                        (mem_value.to_le_bytes()[addr_offset as usize] as u32).into();
                }
                Opcode::LH | Opcode::LHU => {
                    let value = match (addr_offset >> 1) % 2 {
                        0 => mem_value & 0x0000FFFF,
                        1 => (mem_value & 0xFFFF0000) >> 16,
                        _ => unreachable!(),
                    };
                    cols.unsigned_mem_val = value.into();
                }
                Opcode::LW => {
                    cols.unsigned_mem_val = mem_value.into();
                }
                _ => unreachable!(),
            }

            // For the signed load instructions, we need to check if the loaded value is negative.
            if matches!(event.instruction.opcode, Opcode::LB | Opcode::LH) {
                let most_sig_mem_value_byte: u8;
                let sign_value: u32;
                if matches!(event.instruction.opcode, Opcode::LB) {
                    sign_value = 256;
                    most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[0];
                } else {
                    // LHU case
                    sign_value = 65536;
                    most_sig_mem_value_byte = cols.unsigned_mem_val.to_u32().to_le_bytes()[1];
                };

                for i in (0..8).rev() {
                    memory_columns.most_sig_byte_decomp[i] =
                        F::from_canonical_u8(most_sig_mem_value_byte >> i & 0x01);
                }
                if memory_columns.most_sig_byte_decomp[7] == F::one() {
                    cols.mem_value_is_neg = F::one();
                    let sub_event = AluEvent {
                        lookup_id: event.memory_sub_lookup_id,
                        channel: event.channel,
                        shard: event.shard,
                        opcode: Opcode::SUB,
                        a: event.a,
                        b: cols.unsigned_mem_val.to_u32(),
                        c: sign_value,
                        sub_lookups: create_alu_lookups(),
                    };
                    cols.unsigned_mem_val_nonce = F::from_canonical_u32(
                        nonce_lookup
                            .get(&event.memory_sub_lookup_id)
                            .copied()
                            .unwrap_or_default(),
                    );

                    new_alu_events
                        .entry(Opcode::SUB)
                        .and_modify(|op_new_events| op_new_events.push(sub_event))
                        .or_insert(vec![sub_event]);
                }
            }
        }

        // Add event to byte lookup for byte range checking each byte in the memory addr
        let addr_bytes = memory_addr.to_le_bytes();
        for byte_pair in addr_bytes.chunks_exact(2) {
            blu_events.add_byte_lookup_event(ByteLookupEvent {
                shard: event.shard,
                channel: event.channel,
                opcode: ByteOpcode::U8Range,
                a1: 0,
                a2: 0,
                b: byte_pair[0] as u32,
                c: byte_pair[1] as u32,
            });
        }
    }

    /// Populate columns related to ECALL.
    fn populate_ecall<F: PrimeField>(
        &self,
        cols: &mut CpuAuxCols<F>,
        event: &CpuEvent,
        nonce_lookup: &HashMap<usize, u32>,
    ) {
        if cols.selectors.is_ecall == F::one() {
            // The send_to_table column is the 1st entry of the op_a_access column prev_value field.
            // Look at `ecall_eval` in cpu/air/mod.rs for the corresponding constraint and explanation.
            let ecall_cols = cols.opcode_specific_columns.ecall_mut();

            let prev_value: Word<F> = if let Some(record) = event.a_record {
                record.prev_value().into()
            } else {
                panic!("expected a memory record for ecall instructions");
            };

            let (send_to_table, syscall_id) = (prev_value[1], prev_value[0]);

            cols.ecall_mul_send_to_table = cols.selectors.is_ecall * send_to_table;

            // Populate `is_enter_unconstrained`.
            ecall_cols
                .is_enter_unconstrained
                .populate_from_field_element(
                    syscall_id
                        - F::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                );

            // Populate `is_hint_len`.
            ecall_cols.is_hint_len.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
            );

            // Populate `is_halt`.
            ecall_cols.is_halt.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HALT.syscall_id()),
            );

            // Populate `is_commit`.
            ecall_cols.is_commit.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
            );

            // Populate `is_commit_deferred_proofs`.
            ecall_cols
                .is_commit_deferred_proofs
                .populate_from_field_element(
                    syscall_id
                        - F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
                );

            // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and digest word.
            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id())
                || syscall_id
                    == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                let digest_idx = cols.op_b_val.to_u32() as usize;
                ecall_cols.index_bitmap[digest_idx] = F::one();
            }

            // Write the syscall nonce.
            ecall_cols.syscall_nonce = F::from_canonical_u32(
                nonce_lookup
                    .get(&event.syscall_lookup_id)
                    .copied()
                    .unwrap_or_default(),
            );

            let is_halt = syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id());
            cols.is_halt = F::from_bool(is_halt);

            // For halt and commit deferred proofs syscalls, we need to baby bear range check one of
            // it's operands.
            if is_halt {
                ecall_cols.operand_to_check = event.b.into();
                ecall_cols.operand_range_check_cols.populate(event.b);
                cols.ecall_range_check_operand = F::one();
            }

            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                ecall_cols.operand_to_check = event.c.into();
                ecall_cols.operand_range_check_cols.populate(event.c);
                cols.ecall_range_check_operand = F::one();
            }
        }
    }
}