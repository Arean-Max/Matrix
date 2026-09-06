#pragma once

#include "llvm/IR/PassManager.h"
#include <vector>
#include <string>

namespace event_horizon::passes {

struct ManifestEntry {
    std::string function_name;
    std::vector<uint8_t> bytecode;
    std::vector<uint8_t> server_dn_matrix;
};

class DualVMCompilerPass : public llvm::PassInfoMixin<DualVMCompilerPass> {
public:
    llvm::PreservedAnalyses run(llvm::Module& M, llvm::ModuleAnalysisManager& MAM);
    static bool isRequired() { return true; }

    const std::vector<ManifestEntry>& GetManifest() const { return manifest_; }

private:
    std::vector<ManifestEntry> manifest_;
};

} // namespace event_horizon::passes
