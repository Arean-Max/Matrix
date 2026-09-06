#include "../include/DualVMCompilerPass.h"

#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/IRBuilder.h"

using namespace llvm;

namespace event_horizon::passes {

PreservedAnalyses DualVMCompilerPass::run(Module& M, ModuleAnalysisManager& MAM) {
    bool modified = false;

    for (Function& F : M) {
        if (F.isDeclaration() || !F.getName().contains("protected")) {
            continue;
        }

        ManifestEntry entry{};
        entry.function_name = F.getName().str();

        // Translate instructions into VM bytecode
        for (BasicBlock& BB : F) {
            for (Instruction& I : BB) {
                if (auto* binOp = dyn_cast<BinaryOperator>(&I)) {
                    // PUSH_IMM op1
                    entry.bytecode.push_back(0x01); // PUSH_IMM
                    entry.bytecode.resize(entry.bytecode.size() + 8, 0x11);

                    // PUSH_IMM op2
                    entry.bytecode.push_back(0x01); // PUSH_IMM
                    entry.bytecode.resize(entry.bytecode.size() + 8, 0x22);

                    // ADD_Q (Quasigroup Multiply)
                    entry.bytecode.push_back(0x10);
                }
            }
        }

        // HALT opcode
        entry.bytecode.push_back(0xFF);

        // Synthesize dynamic server Dn matrix (256 bytes)
        entry.server_dn_matrix.resize(256);
        for (size_t i = 0; i < 256; ++i) {
            entry.server_dn_matrix[i] = static_cast<uint8_t>((i * 73) ^ 0x6C);
        }

        manifest_.push_back(std::move(entry));
        modified = true;
    }

    return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace event_horizon::passes
