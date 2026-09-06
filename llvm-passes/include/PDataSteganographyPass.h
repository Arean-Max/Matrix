#pragma once

#include "llvm/IR/PassManager.h"

namespace event_horizon::passes {

class PDataSteganographyPass : public llvm::PassInfoMixin<PDataSteganographyPass> {
public:
    llvm::PreservedAnalyses run(llvm::Function& F, llvm::FunctionAnalysisManager& AM);
    static bool isRequired() { return true; }
};

} // namespace event_horizon::passes
