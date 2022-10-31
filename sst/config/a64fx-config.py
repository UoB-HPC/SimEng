import sst

DEBUG_L1 = 0
DEBUG_L2 = 0
DEBUG_MEM = 0
DEBUG_LEVEL = 0

# This SST configuration file represents the memory model for the Fujitsu A64fx processor.
# Reference: https://github.com/fujitsu/A64FX/blob/master/doc/A64FX_Microarchitecture_Manual_en_1.8.pdf

# Cache line size of L1 & L2 in A64FX in bytes.
A64FX_CLW = 256
# Clock Frequency of A64FX.
A64FX_CLOCK = "2GHz"
# Size of L1 cache in A64fx.
A64FX_L1_SIZE = "64KiB"
# Size of L2 cache in A64fx.
A64FX_L2_SIZE = "8MiB"
# Set associativity of A64FX L1
A64FX_SA_L1 = 4
# Set associativity of A64FX L2
A64FX_SA_L2 = 16
# Hit latency of A64FX L1 cache (cycles).
A64FX_HL_L1 = 5
# Hit latency of A64FX L2 cache (cycles).
A64FX_HL_L2 = 46
# Cohenrence protocol of A64FX caches.
A64FX_COHP = "MESI"
# L1 & L2 cache type of A64FX.
A64FX_CACHE_TYPE = "inclusive"
# Throughput of L1 to L2 per core in A64FX. (bytes per cycle)
A64FX_L1TOL2_PC_TPUT = "32B"
# Throughput of L1 to CPU per core in A64FX. Value of 0 indicates infinity. (bytes per cycle)
A64FX_L1TOCPU_PC_TPUT = "0B"
# Throughput of L2 to Memory per CMG in A64FX. (bytes per cycle)
A64FX_L2TOMEMORY_PCMG_TPUT = "64B"
# Throughput of L2 to L1 per core in A64FX. (bytes per cycle)
A64FX_L2TOL1_PC_TPUT = "64B"

# --------------------------------------------- SSTSimEng Core ---------------------------------------

# Using sst-info sstsimeng.simengcore to get all cache parameters, ports and subcomponent slots.
cpu = sst.Component("core", "sstsimeng.simengcore")
cpu.addParams({
    "simeng_config_path": "<PATH TO A64FX SIMENG MODEL CONFIG>",
    "executable_path": "<PATH TO EXECUTABLE BINARY>",
    "executable_args": "",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": 2*1024*1024*1024-1,
    "cache_line_width": A64FX_CLW,
})

# Instantiating the StandardInterface which communicates with the SST memory model.
interface = cpu.setSubComponent("memory", "memHierarchy.standardInterface")

# --------------------------------------------- SSTSimEng Core ---------------------------------------


# --------------------------------------------- L1 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l1cache = sst.Component("a64fx.l1cache", "memHierarchy.Cache")
l1cache.addParams({
      "L1" : 1,
      "cache_type": A64FX_CACHE_TYPE,
      "access_latency_cycles" : A64FX_HL_L1,
      "cache_frequency" : A64FX_CLOCK,
      "associativity" : A64FX_SA_L1,
      "cache_line_size" : A64FX_CLW,
      "cache_size" : A64FX_L1_SIZE,
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "coherence_protocol": A64FX_COHP,
      "request_link_width": A64FX_L1TOL2_PC_TPUT,
      "response_link_width": A64FX_L1TOCPU_PC_TPUT
})
# Set MESI L1 coherence controller to the "coherence" slot
coherence_controller = l1cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy = l1cache.setSubcomponent("replacement", "memHierarchy.replacement.lru", 0)

# --------------------------------------------- L1 Cache ---------------------------------------------


# --------------------------------------------- L2 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l2cache = sst.Component("a64fx.l1cache", "memHierarchy.Cache")
l2cache.addParams({
      "L1" : 0,
      "cache_type": A64FX_CACHE_TYPE,
      "access_latency_cycles" : A64FX_HL_L2,
      "cache_frequency" : A64FX_CLOCK,
      "associativity" : A64FX_SA_L2,
      "cache_line_size" : A64FX_CLW,
      "cache_size" : A64FX_L2_SIZE,
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "coherence_protocol": A64FX_COHP,
      "request_link_width": A64FX_L2TOMEMORY_PCMG_TPUT,
      "response_link_width": A64FX_L2TOL1_PC_TPUT,
})
# Set MESI L2 coherence controller to the "coherence" slot
coherence_controller = l1cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy = l1cache.setSubcomponent("replacement", "memHierarchy.replacement.lru", 0)

# --------------------------------------------- L2 Cache ---------------------------------------------