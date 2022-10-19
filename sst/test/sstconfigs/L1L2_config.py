import sst
import sys

componentlist = (
    "memHierarchy.BroadcastShim",
    "memHierarchy.Bus",
    "memHierarchy.Cache",
    "memHierarchy.CoherentMemController",
    "memHierarchy.DirectoryController",
    "memHierarchy.MemController",
    "memHierarchy.ScratchCPU",
    "memHierarchy.Scratchpad",
    "memHierarchy.Sieve",
    "memHierarchy.multithreadL1",
    "memHierarchy.standardCPU",
    "memHierarchy.streamCPU",
    "memHierarchy.trivialCPU",
    "memHierarchy.DelayBuffer",
    "memHierarchy.IncoherentController",
    "memHierarchy.L1CoherenceController",
    "memHierarchy.L1IncoherentController",
    "memHierarchy.MESICacheDirectoryCoherenceController",
    "memHierarchy.MESICoherenceController",
    "memHierarchy.MemLink",
    "memHierarchy.MemNIC",
    "memHierarchy.MemNICFour",
    "memHierarchy.MemNetBridge",
    "memHierarchy.MemoryManagerSieve",
    "memHierarchy.Messier",
    "memHierarchy.defCustomCmdHandler",
    "memHierarchy.cramsim",
    "memHierarchy.emptyCacheListener",
    "memHierarchy.extMemBackendConvertor",
    "memHierarchy.fifoTransactionQ",
    "memHierarchy.flagMemBackendConvertor",
    "memHierarchy.goblinHMCSim",
    "memHierarchy.hash.linear",
    "memHierarchy.hash.none",
    "memHierarchy.hash.xor",
    "memHierarchy.memInterface",
    "memHierarchy.networkMemoryInspector",
    "memHierarchy.reorderByRow",
    "memHierarchy.reorderSimple",
    "memHierarchy.reorderTransactionQ",
    "memHierarchy.replacement.lfu",
    "memHierarchy.replacement.lru",
    "memHierarchy.replacement.mru",
    "memHierarchy.replacement.nmru",
    "memHierarchy.replacement.rand",
    "memHierarchy.scratchInterface",
    "memHierarchy.simpleDRAM",
    "memHierarchy.simpleMem",
    "memHierarchy.simpleMemBackendConvertor",
    "memHierarchy.simpleMemScratchBackendConvertor",
    "memHierarchy.simplePagePolicy",
    "memHierarchy.standardInterface",
    "memHierarchy.timeoutPagePolicy",
    "memHierarchy.timingDRAM",
    "memHierarchy.vaultsim"
)


DEBUG_L1 = 0
DEBUG_MEM = 0
DEBUG_LEVEL = 0

print(sys.argv)
print(len(sys.argv))

# Define the simulation components
cpu = sst.Component("core", "sstsimeng.simengcore")
cpu.addParams({
    "simeng_config_path": "/home/rahat/asimov/SimEng/configs/sst-cores/a64fx-sst.yaml",
    "executable_path": "",
    "executable_args": "",
    "clock" : "2GHz",
    "max_addr_memory": 2*1024*1024*1024-1,
    "cache_line_width": "64",
    "source": sys.argv[2],
    "assemble_with_source": sys.argv[1] == "src",
})

iface = cpu.setSubComponent("memory", "memHierarchy.standardInterface")

l1cache = sst.Component("l1cache.msi", "memHierarchy.Cache")
l1cache.addParams({
    "access_latency_cycles" : "4",
    "cache_frequency" : "2Ghz",
    "replacement_policy" : "lru",
    "coherence_protocol" : "MSI",
    "associativity" : "4",
    "cache_line_size" : "64",
    "cache_size" : "1KiB",
    "L1" : "1",
    "debug": "1",
    "debug_level" : "10",
    "verbose": "2"
})
l2cache = sst.Component("l2cache.msi.inclus", "memHierarchy.Cache")
l2cache.addParams({
    "access_latency_cycles" : "10",
    "cache_frequency" : "1.8Ghz",
    "replacement_policy" : "lru",
    "coherence_protocol" : "MSI",
    "associativity" : "8",
    "cache_line_size" : "64",
    "cache_size" : "16 KiB",
    "debug_level" : "10",
    "debug": "1"
})
memctrl = sst.Component("memory", "memHierarchy.MemController")
memctrl.addParams({
    "clock" : "1GHz",
    "backend.access_time" : "100 ns",
    "debug_level" : "10",
    "addr_range_end" : 2*1024*1024*1024-1,
})
    
memory = memctrl.setSubComponent("backend", "memHierarchy.simpleMem")
memory.addParams({
    "access_time" : "100 ns",
    "mem_size" : "2GiB",
})

# Enable statistics
sst.setStatisticLoadLevel(7)
sst.setStatisticOutput("sst.statOutputConsole")
for a in componentlist:
    sst.enableAllStatisticsForComponentType(a)

# Define the simulation links
link_cpu_l1cache = sst.Link("link_cpu_l1cache_link")
link_cpu_l1cache.connect( (iface, "port", "10ps"), (l1cache, "high_network_0", "10ps") )
link_l1cache_l2cache = sst.Link("link_l1cache_l2cache_link")
link_l1cache_l2cache.connect( (l1cache, "low_network_0", "100ps"), (l2cache, "high_network_0", "100ps") )
link_mem_bus = sst.Link("link_mem_bus_link")
link_mem_bus.connect( (l2cache, "low_network_0", "100ps"), (memctrl, "direct_link", "100ps") )
