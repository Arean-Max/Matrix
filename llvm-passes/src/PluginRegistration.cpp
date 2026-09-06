#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"

#include "../include/QuasigroupMBAPass.h"
#include "../include/SymbolicExplosionPass.h"
#include "../include/DualVMCompilerPass.h"
#include "../include/PDataSteganographyPass.h"

using namespace llvm;

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION,
        "EventHorizonHeterogeneousPasses",
        "v12.0",
        [](PassBuilder& PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager& FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "eh-quasigroup-mba") {
                        FPM.addPass(event_horizon::passes::QuasigroupMBAPass());
                        return true;
                    }
                    if (Name == "eh-symbolic-explosion") {
                        FPM.addPass(event_horizon::passes::SymbolicExplosionPass());
                        return true;
                    }
                    if (Name == "eh-pdata-stego") {
                        FPM.addPass(event_horizon::passes::PDataSteganographyPass());
                        return true;
                    }
                    return false;
                }
            );

            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager& MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "eh-dual-vm") {
                        MPM.addPass(event_horizon::passes::DualVMCompilerPass());
                        return true;
                    }
                    return false;
                }
            );
        }
    };
}
