// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! LLVM blocks corresponding to checked typed control instructions.

use crate::stateful::{Binary, CheckedProgram, Step};
use crate::{MAX_EVENTS, MAX_STATE_KEY_BYTES, MAX_STATE_KEYS, Operator};
use std::fmt::Write;

fn load(ir: &mut String, index: usize, role: &str, register: usize, count: usize) -> String {
    let name = format!("%s{index}_{role}");
    let _ = writeln!(
        ir,
        "  {name}_ptr = getelementptr [{count} x i64], ptr %registers, i64 0, i64 {register}\n  {name} = load i64, ptr {name}_ptr, align 8"
    );
    name
}
fn store(ir: &mut String, index: usize, register: usize, value: &str, count: usize) {
    let _ = writeln!(
        ir,
        "  %s{index}_destination = getelementptr [{count} x i64], ptr %registers, i64 0, i64 {register}\n  store i64 {value}, ptr %s{index}_destination, align 8"
    );
}
fn slot(ir: &mut String, index: usize, array: &str, key: &str) -> String {
    let name = format!("%s{index}_{array}_slot");
    let _ = writeln!(ir, "  {name} = getelementptr i64, ptr %{array}, i64 {key}");
    name
}
fn bounds(ir: &mut String, index: usize, key: &str) {
    let _ = writeln!(
        ir,
        "  %s{index}_in_bounds = icmp ult i64 {key}, %state_count\n  br i1 %s{index}_in_bounds, label %bounded{index}, label %bounds_error\nbounded{index}:"
    );
}
fn authorize(ir: &mut String, index: usize, key: &str) {
    bounds(ir, index, key);
    let access = slot(ir, index, "access", key);
    let _ = writeln!(
        ir,
        "  %s{index}_access = load i64, ptr {access}, align 8\n  %s{index}_authorized = icmp ne i64 %s{index}_access, 0\n  br i1 %s{index}_authorized, label %allowed{index}, label %access_denied\nallowed{index}:"
    );
}

pub(crate) const CONTRACT_SIGNATURE: &str = "define i32 @trocto_contract(i64 %input, i64 %fuel, i64 %height, i64 %state_count, ptr %key_words, ptr %key_lengths, ptr %caller, ptr %state, ptr %present, ptr %access, ptr %written, ptr %events, ptr %event_count, ptr %output, ptr %used) {\nentry:\n";

pub(crate) fn initialize(ir: &mut String, minimum: usize) {
    let _ = writeln!(
        ir,
        "  %count_minimum = icmp uge i64 %state_count, {minimum}\n  %count_maximum = icmp ule i64 %state_count, {MAX_STATE_KEYS}\n  %count_valid = and i1 %count_minimum, %count_maximum\n  br i1 %count_valid, label %validate_loop, label %invalid_context\nvalidate_loop:\n  %validate_index = phi i64 [0, %entry], [%validate_next, %validate_slot]\n  %validate_more = icmp ult i64 %validate_index, %state_count\n  br i1 %validate_more, label %validate_slot, label %context_valid\nvalidate_slot:\n  %initial_present_ptr = getelementptr i64, ptr %present, i64 %validate_index\n  %initial_access_ptr = getelementptr i64, ptr %access, i64 %validate_index\n  %initial_written_ptr = getelementptr i64, ptr %written, i64 %validate_index\n  %initial_length_ptr = getelementptr i64, ptr %key_lengths, i64 %validate_index\n  %initial_present = load i64, ptr %initial_present_ptr, align 8\n  %initial_access = load i64, ptr %initial_access_ptr, align 8\n  %initial_length = load i64, ptr %initial_length_ptr, align 8\n  %initial_flags = or i64 %initial_present, %initial_access\n  %valid_flags = icmp ule i64 %initial_flags, 1\n  %nonempty_key = icmp uge i64 %initial_length, 1\n  %bounded_key = icmp ule i64 %initial_length, {MAX_STATE_KEY_BYTES}\n  %valid_key = and i1 %nonempty_key, %bounded_key\n  %valid_slot = and i1 %valid_flags, %valid_key\n  store i64 0, ptr %initial_written_ptr, align 8\n  %validate_next = add i64 %validate_index, 1\n  br i1 %valid_slot, label %validate_loop, label %invalid_context\ncontext_valid:\n  store i64 0, ptr %event_count, align 8"
    );
}

// One exhaustive lowering table keeps source opcode semantics visible together.
#[allow(clippy::too_many_lines)]
pub(crate) fn generate(program: &CheckedProgram) -> String {
    let registers = program.registers;
    let locals = program.locals.max(1);
    let mut ir = String::from(
        "; Trocto language 2, dynamic metering 2. Checked source only.\nsource_filename = \"trocto-v2\"\ndeclare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64)\ndeclare { i64, i1 } @llvm.usub.with.overflow.i64(i64, i64)\ndeclare { i64, i1 } @llvm.umul.with.overflow.i64(i64, i64)\n",
    );
    ir.push_str(CONTRACT_SIGNATURE);
    let _ = writeln!(
        ir,
        "  %registers = alloca [{registers} x i64], align 8\n  %locals = alloca [{locals} x i64], align 8\n  %spent = alloca i64, align 8\n  store i64 0, ptr %spent, align 8\n  store i64 0, ptr %event_count, align 8"
    );
    initialize(&mut ir, program.keys.len());
    ir.push_str("  br label %step0\n");
    for (index, instruction) in program.instructions.iter().enumerate() {
        let next = index + 1;
        let _ = writeln!(ir, "step{index}:");
        if instruction.charged() {
            let _ = writeln!(
                ir,
                "  %fuel_used{index} = load i64, ptr %spent, align 8\n  %fuel_available{index} = icmp ult i64 %fuel_used{index}, %fuel\n  br i1 %fuel_available{index}, label %operation{index}, label %fuel_exhausted\noperation{index}:\n  %fuel_next{index} = add i64 %fuel_used{index}, 1\n  store i64 %fuel_next{index}, ptr %spent, align 8"
            );
        }
        match *instruction {
            Step::Constant { destination, value } => {
                store(&mut ir, index, destination, &value.to_string(), registers);
            }
            Step::Input { destination } => store(&mut ir, index, destination, "%input", registers),
            Step::Load { destination, local } => {
                let _ = writeln!(
                    ir,
                    "  %s{index}_local = getelementptr [{locals} x i64], ptr %locals, i64 0, i64 {local}\n  %s{index}_loaded = load i64, ptr %s{index}_local, align 8"
                );
                store(
                    &mut ir,
                    index,
                    destination,
                    &format!("%s{index}_loaded"),
                    registers,
                );
            }
            Step::Store { local, source, .. } => {
                let value = load(&mut ir, index, "value", source, registers);
                let _ = writeln!(
                    ir,
                    "  %s{index}_local = getelementptr [{locals} x i64], ptr %locals, i64 0, i64 {local}\n  store i64 {value}, ptr %s{index}_local, align 8"
                );
            }
            Step::Move {
                destination,
                source,
            } => {
                let value = load(&mut ir, index, "value", source, registers);
                store(&mut ir, index, destination, &value, registers);
            }
            Step::Not {
                destination,
                source,
            } => {
                let value = load(&mut ir, index, "operand", source, registers);
                let _ = writeln!(
                    ir,
                    "  %s{index}_not = icmp eq i64 {value}, 0\n  %s{index}_value = zext i1 %s{index}_not to i64"
                );
                store(
                    &mut ir,
                    index,
                    destination,
                    &format!("%s{index}_value"),
                    registers,
                );
            }
            Step::Binary {
                destination,
                operator,
                left,
                right,
            } => {
                let left = load(&mut ir, index, "left", left, registers);
                let right = load(&mut ir, index, "right", right, registers);
                match operator {
                    Binary::Arithmetic(Operator::Add | Operator::Subtract | Operator::Multiply) => {
                        let intrinsic = match operator {
                            Binary::Arithmetic(Operator::Add) => "uadd",
                            Binary::Arithmetic(Operator::Subtract) => "usub",
                            _ => "umul",
                        };
                        let _ = writeln!(
                            ir,
                            "  %s{index}_pair = call {{ i64, i1 }} @llvm.{intrinsic}.with.overflow.i64(i64 {left}, i64 {right})\n  %s{index}_value = extractvalue {{ i64, i1 }} %s{index}_pair, 0\n  %s{index}_overflow = extractvalue {{ i64, i1 }} %s{index}_pair, 1\n  br i1 %s{index}_overflow, label %overflow, label %arithmetic{index}\narithmetic{index}:"
                        );
                    }
                    Binary::Arithmetic(Operator::Divide | Operator::Remainder) => {
                        let operation = if matches!(operator, Binary::Arithmetic(Operator::Divide))
                        {
                            "udiv"
                        } else {
                            "urem"
                        };
                        let _ = writeln!(
                            ir,
                            "  %s{index}_zero = icmp eq i64 {right}, 0\n  br i1 %s{index}_zero, label %division_zero, label %arithmetic{index}\narithmetic{index}:\n  %s{index}_value = {operation} i64 {left}, {right}"
                        );
                    }
                    _ => {
                        let comparison = match operator {
                            Binary::Equal => "eq",
                            Binary::NotEqual => "ne",
                            Binary::Less => "ult",
                            Binary::LessEqual => "ule",
                            Binary::Greater => "ugt",
                            _ => "uge",
                        };
                        let _ = writeln!(
                            ir,
                            "  %s{index}_condition = icmp {comparison} i64 {left}, {right}\n  %s{index}_value = zext i1 %s{index}_condition to i64"
                        );
                    }
                }
                store(
                    &mut ir,
                    index,
                    destination,
                    &format!("%s{index}_value"),
                    registers,
                );
            }
            Step::Branch { condition, yes, no } => {
                let condition = load(&mut ir, index, "condition", condition, registers);
                let _ = writeln!(
                    ir,
                    "  %s{index}_branch = icmp ne i64 {condition}, 0\n  br i1 %s{index}_branch, label %step{yes}, label %step{no}"
                );
                continue;
            }
            Step::Jump(target) => {
                let _ = writeln!(ir, "  br label %step{target}");
                continue;
            }
            Step::Return(source) => {
                let value = load(&mut ir, index, "return", source, registers);
                let _ = writeln!(
                    ir,
                    "  store i64 {value}, ptr %output, align 8\n  %s{index}_returned_fuel = load i64, ptr %spent, align 8\n  store i64 %s{index}_returned_fuel, ptr %used, align 8\n  ret i32 0"
                );
                continue;
            }
            Step::Height { destination } => {
                store(&mut ir, index, destination, "%height", registers);
            }
            Step::Caller {
                destination,
                index: limb,
            } => {
                let pointer = slot(&mut ir, index, "caller", &limb.to_string());
                let _ = writeln!(ir, "  %s{index}_value = load i64, ptr {pointer}, align 8");
                store(
                    &mut ir,
                    index,
                    destination,
                    &format!("%s{index}_value"),
                    registers,
                );
            }
            Step::KeyCount { destination } => {
                store(&mut ir, index, destination, "%state_count", registers);
            }
            Step::KeyWord {
                destination,
                key,
                word,
            } => {
                let key = load(&mut ir, index, "key", key, registers);
                bounds(&mut ir, index, &key);
                let length = slot(&mut ir, index, "key_lengths", &key);
                let _ = writeln!(
                    ir,
                    "  %s{index}_length = load i64, ptr {length}, align 8\n  %s{index}_address = icmp eq i64 %s{index}_length, 32\n  br i1 %s{index}_address, label %address{index}, label %bounds_error\naddress{index}:\n  %s{index}_word_base = mul i64 {key}, 4\n  %s{index}_word_index = add i64 %s{index}_word_base, {word}"
                );
                let pointer = slot(
                    &mut ir,
                    index,
                    "key_words",
                    &format!("%s{index}_word_index"),
                );
                let _ = writeln!(ir, "  %s{index}_value = load i64, ptr {pointer}, align 8");
                store(
                    &mut ir,
                    index,
                    destination,
                    &format!("%s{index}_value"),
                    registers,
                );
            }
            Step::Get { destination, key } | Step::GetAt { destination, key } => {
                let key = if matches!(instruction, Step::GetAt { .. }) {
                    load(&mut ir, index, "key", key, registers)
                } else {
                    key.to_string()
                };
                authorize(&mut ir, index, &key);
                let present = slot(&mut ir, index, "present", &key);
                let state = slot(&mut ir, index, "state", &key);
                let _ = writeln!(
                    ir,
                    "  %s{index}_present = load i64, ptr {present}, align 8\n  %s{index}_exists = icmp ne i64 %s{index}_present, 0\n  %s{index}_stored = load i64, ptr {state}, align 8\n  %s{index}_value = select i1 %s{index}_exists, i64 %s{index}_stored, i64 0"
                );
                store(
                    &mut ir,
                    index,
                    destination,
                    &format!("%s{index}_value"),
                    registers,
                );
            }
            Step::Set { key, source } | Step::SetAt { key, source } => {
                let key = if matches!(instruction, Step::SetAt { .. }) {
                    load(&mut ir, index, "key", key, registers)
                } else {
                    key.to_string()
                };
                authorize(&mut ir, index, &key);
                let value = load(&mut ir, index, "value", source, registers);
                let state = slot(&mut ir, index, "state", &key);
                let present = slot(&mut ir, index, "present", &key);
                let written = slot(&mut ir, index, "written", &key);
                let _ = writeln!(
                    ir,
                    "  store i64 {value}, ptr {state}, align 8\n  store i64 1, ptr {present}, align 8\n  store i64 1, ptr {written}, align 8"
                );
            }
            Step::Delete { key } | Step::DeleteAt { key } => {
                let key = if matches!(instruction, Step::DeleteAt { .. }) {
                    load(&mut ir, index, "key", key, registers)
                } else {
                    key.to_string()
                };
                authorize(&mut ir, index, &key);
                let state = slot(&mut ir, index, "state", &key);
                let present = slot(&mut ir, index, "present", &key);
                let written = slot(&mut ir, index, "written", &key);
                let _ = writeln!(
                    ir,
                    "  store i64 0, ptr {state}, align 8\n  store i64 0, ptr {present}, align 8\n  store i64 1, ptr {written}, align 8"
                );
            }
            Step::Emit { topic, data } => {
                let topic = load(&mut ir, index, "topic_value", topic, registers);
                let data = load(&mut ir, index, "data_value", data, registers);
                let _ = writeln!(
                    ir,
                    "  %s{index}_count = load i64, ptr %event_count, align 8\n  %s{index}_capacity = icmp ult i64 %s{index}_count, {MAX_EVENTS}\n  br i1 %s{index}_capacity, label %event{index}, label %event_limit\nevent{index}:\n  %s{index}_event_index = mul i64 %s{index}_count, 2\n  %s{index}_topic_ptr = getelementptr i64, ptr %events, i64 %s{index}_event_index\n  %s{index}_data_ptr = getelementptr i64, ptr %s{index}_topic_ptr, i64 1\n  store i64 {topic}, ptr %s{index}_topic_ptr, align 8\n  store i64 {data}, ptr %s{index}_data_ptr, align 8\n  %s{index}_next_count = add i64 %s{index}_count, 1\n  store i64 %s{index}_next_count, ptr %event_count, align 8"
                );
            }
        }
        let _ = writeln!(ir, "  br label %step{next}");
    }
    let end = program.instructions.len();
    let _ = writeln!(
        ir,
        "step{end}:\n  ret i32 6\nfuel_exhausted:\n  ret i32 1\noverflow:\n  ret i32 2\ndivision_zero:\n  ret i32 3\naccess_denied:\n  ret i32 4\nevent_limit:\n  ret i32 5\ninvalid_context:\n  ret i32 6\nbounds_error:\n  ret i32 7\n}}"
    );
    ir.push_str(
        "define i32 @trocto_call(i64 %input, i64 %fuel, ptr %output, ptr %used) {\nentry:\n",
    );
    if program.context {
        ir.push_str("  ret i32 6\n}\n");
    } else {
        ir.push_str("  %count = alloca i64, align 8\n  %status = call i32 @trocto_contract(i64 %input, i64 %fuel, i64 0, i64 0, ptr null, ptr null, ptr null, ptr null, ptr null, ptr null, ptr null, ptr null, ptr %count, ptr %output, ptr %used)\n  ret i32 %status\n}\n");
    }
    ir
}
