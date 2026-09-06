#include "../include/SymbolicExplosionPass.h"

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"

using namespace llvm;

namespace event_horizon::passes {

PreservedAnalyses SymbolicExplosionPass::run(Function& F, FunctionAnalysisManager& AM) {
    if (F.isDeclaration() || F.empty()) {
        return PreservedAnalyses::all();
    }

    LLVMContext& Ctx = F.getContext();
    BasicBlock& entryBB = F.getEntryBlock();
    IRBuilder<> builder(&*entryBB.getFirstInsertionPt());

    // Allocate 64-bit symbolic state accumulator
    Type* i64Ty = Type::getInt64Ty(Ctx);
    Type* i32Ty = Type::getInt32Ty(Ctx);

    AllocaInst* accAlloc = builder.CreateAlloca(i64Ty, nullptr, "eh_sym_acc");
    builder.CreateStore(ConstantInt::get(i64Ty, 0x1337C0DE84920482ULL), accAlloc);

    // Pick first argument as entropy seed, or constant if no args
    Value* seedVal = ConstantInt::get(i64Ty, 0x5A5A5A5A12345678ULL);
    if (!F.arg_empty() && F.getArg(0)->getType()->isIntegerTy()) {
        seedVal = builder.CreateZExtOrTrunc(F.getArg(0), i64Ty);
    }

    // Synthesize 64-iteration branching sink loop
    Function* parentF = &F;
    BasicBlock* loopCondBB = BasicBlock::Create(Ctx, "eh_sym_cond", parentF);
    BasicBlock* loopBodyBB = BasicBlock::Create(Ctx, "eh_sym_body", parentF);
    BasicBlock* branchTrueBB = BasicBlock::Create(Ctx, "eh_sym_t", parentF);
    BasicBlock* branchFalseBB = BasicBlock::Create(Ctx, "eh_sym_f", parentF);
    BasicBlock* loopMergeBB = BasicBlock::Create(Ctx, "eh_sym_merge", parentF);
    BasicBlock* loopExitBB = BasicBlock::Create(Ctx, "eh_sym_exit", parentF);

    // Entry jumps to loop condition
    AllocaInst* idxAlloc = builder.CreateAlloca(i32Ty, nullptr, "eh_sym_idx");
    builder.CreateStore(ConstantInt::get(i32Ty, 0), idxAlloc);
    builder.CreateBr(loopCondBB);

    // Condition BB
    IRBuilder<> condBuilder(loopCondBB);
    Value* currentIdx = condBuilder.CreateLoad(i32Ty, idxAlloc, "idx");
    Value* isLess = condBuilder.CreateICmpSLT(currentIdx, ConstantInt::get(i32Ty, 64), "cmp");
    condBuilder.CreateCondBr(isLess, loopBodyBB, loopExitBB);

    // Body BB: test bit i of seedVal
    IRBuilder<> bodyBuilder(loopBodyBB);
    Value* idx64 = bodyBuilder.CreateZExt(currentIdx, i64Ty);
    Value* shifted = bodyBuilder.CreateLShr(seedVal, idx64);
    Value* bit = bodyBuilder.CreateAnd(shifted, ConstantInt::get(i64Ty, 1));
    Value* isOne = bodyBuilder.CreateICmpNE(bit, ConstantInt::get(i64Ty, 0));
    bodyBuilder.CreateCondBr(isOne, branchTrueBB, branchFalseBB);

    // True branch: acc = (acc * 31) ^ table_A[i]
    IRBuilder<> tBuilder(branchTrueBB);
    Value* accT = tBuilder.CreateLoad(i64Ty, accAlloc);
    Value* mulT = tBuilder.CreateMul(accT, ConstantInt::get(i64Ty, 31));
    Value* xorT = tBuilder.CreateXor(mulT, idx64);
    tBuilder.CreateStore(xorT, accAlloc);
    tBuilder.CreateBr(loopMergeBB);

    // False branch: acc = (acc * 17) ^ table_B[i]
    IRBuilder<> fBuilder(branchFalseBB);
    Value* accF = fBuilder.CreateLoad(i64Ty, accAlloc);
    Value* mulF = fBuilder.CreateMul(accF, ConstantInt::get(i64Ty, 17));
    Value* xorF = fBuilder.CreateXor(mulF, ConstantInt::get(i64Ty, 0x9E3779B9));
    fBuilder.CreateStore(xorF, accAlloc);
    fBuilder.CreateBr(loopMergeBB);

    // Merge BB: idx++ and jump back
    IRBuilder<> mergeBuilder(loopMergeBB);
    Value* nextIdx = mergeBuilder.CreateAdd(currentIdx, ConstantInt::get(i32Ty, 1));
    mergeBuilder.CreateStore(nextIdx, idxAlloc);
    mergeBuilder.CreateBr(loopCondBB);

    // Loop Exit: split entry block continuation
    IRBuilder<> exitBuilder(loopExitBB);
    // Connect to original code in entry block
    Instruction* originalFirst = &*entryBB.getFirstInsertionPt();
    exitBuilder.CreateBr(&entryBB);

    return PreservedAnalyses::none();
}

} // namespace event_horizon::passes
