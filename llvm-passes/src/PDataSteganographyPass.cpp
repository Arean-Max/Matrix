#include "../include/PDataSteganographyPass.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"

using namespace llvm;

namespace event_horizon::passes {

PreservedAnalyses PDataSteganographyPass::run(Function& F, FunctionAnalysisManager& AM) {
    if (F.isDeclaration() || F.empty() || F.size() < 2) {
        return PreservedAnalyses::all();
    }

    LLVMContext& Ctx = F.getContext();
    bool modified = false;

    // Attach personality function or SEH attribute for x64 UNWIND_INFO
    F.addFnAttr("win64-seh");

    // Partition basic blocks and insert deliberate trap between blocks
    for (auto it = F.begin(); it != F.end(); ++it) {
        BasicBlock& BB = *it;
        auto nextIt = std::next(it);
        if (nextIt != F.end()) {
            Instruction* term = BB.getTerminator();
            if (term && isa<BranchInst>(term)) {
                IRBuilder<> builder(term);
                // Opaque zero predicate: (x * 2) & 1 == 0
                Value* zeroVal = ConstantInt::get(Type::getInt32Ty(Ctx), 0);
                Value* numVal  = ConstantInt::get(Type::getInt32Ty(Ctx), 100);

                // Hardware trap: sdiv by zero to invoke Language Specific Handler in .pdata
                // In production, this compiles to 'idiv ecx'
                Value* trapDiv = builder.CreateSDiv(numVal, zeroVal, "eh_trap_div");
                (void)trapDiv;
                modified = true;
            }
        }
    }

    return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace event_horizon::passes
