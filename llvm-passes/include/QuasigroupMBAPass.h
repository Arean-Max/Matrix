#pragma once

#include "llvm/IR/PassManager.h"

namespace event_horizon::passes {

class QuasigroupMBAPass : public llvm::PassInfoMixin<QuasigroupMBAPass> {
public:
    llvm::PreservedAnalyses run(llvm::Function& F, llvm::FunctionAnalysisManager& AM);
    static bool isRequired() { return true; }
};

} // namespace event_horizon::passes
