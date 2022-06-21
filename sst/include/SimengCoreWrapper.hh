#ifdef SIMENG_ENABLE_SST
#include <sst/core/sst_config.h>
#include <sst/core/component.h>

#include <chrono>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include "simeng/AlwaysNotTakenPredictor.hh"
#include "simeng/BTBPredictor.hh"
#include "simeng/BTB_BWTPredictor.hh"
#include "simeng/Core.hh"
#include "simeng/Elf.hh"
#include "simeng/FixedLatencyMemoryInterface.hh"
#include "simeng/FlatMemoryInterface.hh"
#include "simeng/ModelConfig.hh"
#include "simeng/SpecialFileDirGen.hh"
#include "simeng/arch/Architecture.hh"
#include "simeng/arch/aarch64/Architecture.hh"
#include "simeng/arch/aarch64/Instruction.hh"
#include "simeng/arch/aarch64/MicroDecoder.hh"
#include "simeng/kernel/Linux.hh"
#include "simeng/models/emulation/Core.hh"
#include "simeng/models/inorder/Core.hh"
#include "simeng/models/outoforder/Core.hh"
#include "simeng/pipeline/A64FXPortAllocator.hh"
#include "simeng/pipeline/BalancedPortAllocator.hh"
#include "simeng/version.hh"

using namespace SST;

namespace SST {
    namespace SSTSimeng {
        class SimengCoreWrapper: public SST::Component {
            public:
                SimengCoreWrapper(SST::ComponentId_t id, SST::Params& params);
                ~SimengCoreWrapper();

                void setup();
                void finish();

                void init(unsigned int phase);
                bool clockTick( SST::Cycle_t currentCycle );

                SST_ELI_REGISTER_COMPONENT(
                    SimengCoreWrapper,
                    "sstsimeng",
                    "simengcore",
                    SST_ELI_ELEMENT_VERSION( 1, 0, 0 ),
                    "Simeng core wrapper for SST",
                    COMPONENT_CATEGORY_PROCESSOR
                )

                SST_ELI_DOCUMENT_PARAMS(
                { "config", "Path to Simeng config file (YAML)", "../configs/a64fx.yaml" }
                )
            private:
                // SST properties
                SST::Output output;
                TimeConverter* clock;
                
                // Simeng properties
                std::unique_ptr<simeng::Core> core;
                std::string config_path;
                std::string executable_path;
                std::string executable_args;
                uint64_t cache_line_size;
                std::unique_ptr<simeng::kernel::LinuxProcess> process;
                std::unique_ptr<simeng::kernel::Linux> kernel;
                char* process_memory;
                std::unique_ptr<simeng::arch::Architecture> arch;
                std::unique_ptr<simeng::MemoryInterface> instruction_memory;
                std::unique_ptr<simeng::BranchPredictor> predictor;
                std::unique_ptr<simeng::pipeline::PortAllocator> port_allocator;
                // Replace with SST memory model
                std::unique_ptr<simeng::MemoryInterface> data_memory;
                int iterations;
                int vitrual_counter;
                double timer_modulo;
                int size;
                std::chrono::high_resolution_clock::time_point start_time;

                void fabricateSimengCore();
        };
    }
}
#endif