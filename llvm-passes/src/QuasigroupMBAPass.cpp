#include "../include/QuasigroupMBAPass.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace event_horizon::passes {

PreservedAnalyses QuasigroupMBAPass::run(Function& F, FunctionAnalysisManager& AM) {
    if (F.isDeclaration() || F.getName().starts_with("quasigroup_")) {
        return PreservedAnalyses::all();
    }

    Module* M = F.getParent();
    LLVMContext& Ctx = F.getContext();
    bool modified = false;

    // Collect binary operators to replace
    SmallVector<BinaryOperator*, 16> toReplace;
    for (BasicBlock& BB : F) {
        for (Instruction& I : BB) {
            if (auto* binOp = dyn_cast<BinaryOperator>(&I)) {
                // Focus on 32-bit and 64-bit integer Add, Sub, Xor, And, Or
                if (binOp->getType()->isIntegerTy(32) || binOp->getType()->isIntegerTy(64)) {
                    toReplace.push_back(binOp);
                }
            }
        }
    }

    // Replace standard binary operations with non-associative quasigroup projection:
    // x * y = P(S1(x) + S2(y) mod 256) expanded across 32-bit/64-bit words
    for (BinaryOperator* binOp : toReplace) {
        IRBuilder<> builder(binOp);
        Value* opA = binOp->getOperand(0);
        Value* opB = binOp->getOperand(1);
        Type* ty = binOp->getType();

        // Affine constants representing isotopic Latin square transformations
        Value* s1Constant = ConstantInt::get(ty, 0x5A879E37);
        Value* s2Constant = ConstantInt::get(ty, 0x3C6EF372);
        Value* pConstant  = ConstantInt::get(ty, 0x9E3779B9);

        Value* s1Val = builder.CreateXor(opA, s1Constant);
        Value* s2Val = builder.CreateAdd(opB, s2Constant);
        Value* sumVal = builder.CreateAdd(s1Val, s2Val);
        Value* transformed = builder.CreateXor(sumVal, pConstant);

        binOp->replaceAllUsesWith(transformed);
        binOp->eraseFromParent();
        modified = true;
    }

    return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
}

} // namespace event_horizon::passes
