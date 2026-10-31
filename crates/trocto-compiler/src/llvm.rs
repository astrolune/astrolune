// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Native LLVM IR with explicit fuel and checked arithmetic control flow.

use std::fmt::Write;

use crate::{Instruction, Operator};

pub(crate) fn generate(instructions: &[Instruction], result: usize) -> String {
    let mut ir = String::from(
        "; Trocto language 1, metering 1. Generated from checked source.\n\
         source_filename = \"trocto-v1\"\n\
         declare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64)\n\
         declare { i64, i1 } @llvm.usub.with.overflow.i64(i64, i64)\n\
         declare { i64, i1 } @llvm.umul.with.overflow.i64(i64, i64)\n\
         define i32 @trocto_call(i64 %input, i64 %fuel, ptr %output, ptr %used) {\n\
         entry:\n  br label %step0\n",
    );
    for (index, instruction) in instructions.iter().enumerate() {
        let next = index + 1;
        let _ = writeln!(
            ir,
            "step{index}:\n  %fuel_ok{index} = icmp uge i64 %fuel, {next}\n  \
             br i1 %fuel_ok{index}, label %value{index}, label %fuel_exhausted\nvalue{index}:"
        );
        match *instruction {
            Instruction::Constant(value) => {
                let _ = writeln!(ir, "  %v{index} = add i64 0, {value}");
            }
            Instruction::Input => {
                let _ = writeln!(ir, "  %v{index} = add i64 %input, 0");
            }
            Instruction::Copy(source) => {
                let _ = writeln!(ir, "  %v{index} = add i64 %v{source}, 0");
            }
            Instruction::Binary {
                operator,
                left,
                right,
            } => match operator {
                Operator::Add | Operator::Subtract | Operator::Multiply => {
                    let intrinsic = match operator {
                        Operator::Add => "uadd",
                        Operator::Subtract => "usub",
                        _ => "umul",
                    };
                    let _ = writeln!(
                        ir,
                        "  %pair{index} = call {{ i64, i1 }} @llvm.{intrinsic}.with.overflow.i64(i64 \
                         %v{left}, i64 %v{right})\n  %v{index} = extractvalue {{ i64, i1 }} \
                         %pair{index}, 0\n  %overflow{index} = extractvalue {{ i64, i1 }} \
                         %pair{index}, 1\n  br i1 %overflow{index}, label %overflow, label \
                         %step{next}"
                    );
                    continue;
                }
                Operator::Divide | Operator::Remainder => {
                    let operation = if matches!(operator, Operator::Divide) {
                        "udiv"
                    } else {
                        "urem"
                    };
                    let _ = writeln!(
                        ir,
                        "  %zero{index} = icmp eq i64 %v{right}, 0\n  br i1 %zero{index}, label \
                         %division_zero, label %divide{index}\ndivide{index}:\n  %v{index} = \
                         {operation} i64 %v{left}, %v{right}"
                    );
                }
            },
        }
        let _ = writeln!(ir, "  br label %step{next}");
    }
    let count = instructions.len();
    let _ = writeln!(
        ir,
        "step{count}:\n  store i64 %v{result}, ptr %output, align 8\n  store i64 {count}, ptr \
         %used, align 8\n  ret i32 0\nfuel_exhausted:\n  ret i32 1\noverflow:\n  ret i32 \
         2\ndivision_zero:\n  ret i32 3\n}}"
    );
    ir.push_str(crate::stateful_llvm::CONTRACT_SIGNATURE);
    crate::stateful_llvm::initialize(&mut ir, 0);
    ir.push_str("  %status = call i32 @trocto_call(i64 %input, i64 %fuel, ptr %output, ptr %used)\n  ret i32 %status\ninvalid_context:\n  ret i32 6\n}\n");
    ir
}
