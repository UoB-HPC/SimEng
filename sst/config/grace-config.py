import sst

DEBUG_L1 = 0
DEBUG_L2 = 0
DEBUG_L3 = 0
DEBUG_MEM = 0
DEBUG_LEVEL = 0


# ------------------------------------------------ Utility -------------------------------------------

def getMemoryProps(memory_size: int, si: str):
      props = {
            "start_addr": 0,
            "end_addr": 0,
            "size": ""
      }
      props["size"] = "%s%s" % (memory_size , si)
      if si == "GiB":
            props["end_addr"] = memory_size * 1024 * 1024 * 1024 - 1
      elif si == "MiB":
            props["end_addr"] = memory_size * 1024 * 1024 - 1
      elif si == "KiB":
            props["end_addr"] = memory_size * 1024 - 1
      elif si == "B":
            props["end_addr"] = memory_size - 1
      else:
            raise Exception("Unknown SI units provided to getMemoryProps")
      return props

# ------------------------------------------------ Utility -------------------------------------------



# ------------------------------------------- Grace Properties ---------------------------------------

# This SST configuration file represents the memory model for the NVIDIA Grace processor.
# The following resources were used to determine the configuration:
# - https://resources.nvidia.com/en-us-grace-cpu/grace-hopper-superchip
# - https://developer.nvidia.com/blog/nvidia-grace-cpu-superchip-architecture-in-depth/
# - https://hc2023.hotchips.org/assets/program/conference/day1/CPU1/HC2023.Arm.MagnusBruce.v04.FINAL.pdf
# - https://chipsandcheese.com/2024/07/31/grace-hopper-nvidias-halfway-apu/
# - https://chipsandcheese.com/2023/09/11/hot-chips-2023-arms-neoverse-v2/

# Cache line size of L1 & L2 in Grace in bytes.
GRACE_CLW = 64
# Clock Frequency of Grace.
GRACE_CLOCK = "3.4GHz" # Peak boost
# Size of L1 cache in Grace.
GRACE_L1_SIZE = "64KiB"
# Size of L2 cache in Grace.
GRACE_L2_SIZE = "1MiB"
# Size of L3 cache in Grace.
GRACE_L3_SIZE = "114MiB"
# Set associativity of Grace L1
GRACE_SA_L1 = 4 
# Set associativity of Grace L2
GRACE_SA_L2 = 8
# Set associativity of Grace L3
GRACE_SA_L3 = 12
# Hit latency of Grace L1 cache (cycles).
GRACE_HL_L1 = 2 # 4 cycles (-2 due to SimEng overhead)
# Hit latency of Grace L2 cache (cycles).
GRACE_HL_L2 = 8 # 10 cycles (-2 due to SimEng overhead)
# Hit latency of Grace L3 cache (cycles).
GRACE_HL_L3 = 123 # 125 cycles (-2 due to SimEng overhead)
# Coherence protocol of Grace caches.
GRACE_COHP = "MESI"                                                                                         # Guess
# L1 & L2 cache type of Grace.
GRACE_CACHE_TYPE_L1_L2 = "inclusive"
# L3 cache type of Grace.
GRACE_CACHE_TYPE_L3 = "inclusive"                                                                           # Guess

# Throughput of L1 to CPU per core in Grace. Value of 0 indicates infinity. (bytes per cycle)
GRACE_L1TOCPU_PC_TPUT = "48B"
# Throughput of L1 to L2 per core in Grace. (bytes per cycle)
GRACE_L1TOL2_PC_TPUT = "128B"
# Throughput of L2 to L3 per core in Grace. (bytes per cycle)
GRACE_L2TOL3_PC_TPUT = "32B"
# Throughput of L3 to Memory in Grace. (bytes per cycle)
GRACE_L3TOMEM_TPUT = "64B"                                                                                  # Guess - 1 cache line per cycle?
# Throughput of Memory to L3 in Grace. (bytes per cycle)
GRACE_MEMTOL3_TPUT = "64B"                                                                                  # Guess - 1 cache line per cycle?
# Throughput of L3 to L2 per core in Grace. (bytes per cycle)
GRACE_L3TOL2_PC_TPUT = "32B"
# Throughput of L2 to L1 per core in Grace. (bytes per cycle)
GRACE_L2TOL1_PC_TPUT = "64B"

# Grace Memory access time.
GRACE_MEM_ACCESS = "203.3ns"

# Prefetcher to use
PREFETCHER = "cassini.NextBlockPrefetcher"

# ------------------------------------------- Grace Properties ---------------------------------------


# ---------------------------------------------- Variables -------------------------------------------

memprops = getMemoryProps(8, "GiB")

# ---------------------------------------------- Variables -------------------------------------------


# --------------------------------------------- SSTSimEng Core ---------------------------------------

# Using sst-info sstsimeng.simengcore to get all cache parameters, ports and subcomponent slots.
cpu = sst.Component("core", "sstsimeng.simengcore")
cpu.addParams({
    "simeng_config_path": "/Users/fw17231/Documents/SimEng/SimEng/configs/grace.yaml",
    "executable_path": "/Users/fw17231/Documents/SimEng/simeng-benchmarks/binaries/miniBUDE/openmp/bude-gcc10.3.0-armv8.4-a+sve",
    "executable_args": "--deck /Users/fw17231/Documents/SimEng/simeng-benchmarks/src/miniBUDE/data/bm1 -n 64 -i 2",
    "clock" : GRACE_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": GRACE_CLW,
})

# Instantiating the StandardInterface which communicates with the SST memory model.
interface = cpu.setSubComponent("memory", "memHierarchy.standardInterface")

# --------------------------------------------- SSTSimEng Core ---------------------------------------


# --------------------------------------------- L1 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l1cache = sst.Component("GRACE.l1cache", "memHierarchy.Cache")
l1cache.addParams({
      "L1" : 1,
      "cache_type": GRACE_CACHE_TYPE_L1_L2,
      "access_latency_cycles" : GRACE_HL_L1,
      "cache_frequency" : GRACE_CLOCK,
      "associativity" : GRACE_SA_L1,
      "cache_line_size" : GRACE_CLW,
      "cache_size" : GRACE_L1_SIZE,
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "coherence_protocol": GRACE_COHP,
      "request_link_width": GRACE_L1TOL2_PC_TPUT,
      "response_link_width": GRACE_L1TOCPU_PC_TPUT,
      "mshr_latency_cycles": 1,
      "tag_access_latency": 1,
      "llsc_block_cycles": 1000,
})
# Set MESI L1 coherence controller to the "coherence" slot
coherence_controller_l1 = l1cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy_l1 = l1cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0) # Grace uses dynamic RRIP

prefetcher_l1 = l1cache.setSubComponent("prefetcher", PREFETCHER)
prefetcher_l1.addParams({
 "cache_line_size": GRACE_CLW,
 "aggressiveness": 1,
})

# --------------------------------------------- L1 Cache ---------------------------------------------


# --------------------------------------------- L2 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l2cache = sst.Component("GRACE.l2cache", "memHierarchy.Cache")
l2cache.addParams({
      "L1" : 0,
      "cache_type": GRACE_CACHE_TYPE_L1_L2,
      "access_latency_cycles" : GRACE_HL_L2,
      "cache_frequency" : GRACE_CLOCK,
      "associativity" : GRACE_SA_L2,
      "cache_line_size" : GRACE_CLW,
      "cache_size" : GRACE_L2_SIZE,
      "debug" : DEBUG_L2,
      "debug_level" : DEBUG_LEVEL,
      "coherence_protocol": GRACE_COHP,
      "max_requests_per_cycle": 4,
      "request_link_width": GRACE_L2TOL3_PC_TPUT,
      "response_link_width": GRACE_L2TOL1_PC_TPUT,
      "mshr_latency_cycles": 1,
      "tag_access_latency": 1,
      "llsc_block_cycles": 1000,
})
# Set MESI L2 coherence controller to the "coherence" slot
coherence_controller_l2 = l2cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_inclusive")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy_l2 = l2cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0) # Grace uses 6-state RRIP

prefetcher_l2 = l2cache.setSubComponent("prefetcher", PREFETCHER)
prefetcher_l2.addParams({
      "cache_line_size": GRACE_CLW,
      "aggressiveness": 1,
})

# --------------------------------------------- L2 Cache ---------------------------------------------


# --------------------------------------------- L3 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l3cache = sst.Component("GRACE.l3cache", "memHierarchy.Cache")
l3cache.addParams({
      "L1" : 0,
      "cache_type": GRACE_CACHE_TYPE_L3,
      "access_latency_cycles" : GRACE_HL_L3,
      "cache_frequency" : GRACE_CLOCK,
      "associativity" : GRACE_SA_L3,
      "cache_line_size" : GRACE_CLW,
      "cache_size" : GRACE_L3_SIZE,
      "debug" : DEBUG_L3,
      "debug_level" : DEBUG_LEVEL,
      "coherence_protocol": GRACE_COHP,
      "max_requests_per_cycle": 1,
      "request_link_width": GRACE_L3TOMEM_TPUT,
      "response_link_width": GRACE_L3TOL2_PC_TPUT,
      "mshr_latency_cycles": 1,
      "tag_access_latency": 1,
      "llsc_block_cycles": 1000,
})
# Set MESI L3 coherence controller to the "coherence" slot
coherence_controller_l3 = l3cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_inclusive")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy_l3 = l3cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0) # Policy unknown

prefetcher_l3 = l3cache.setSubComponent("prefetcher", PREFETCHER)
prefetcher_l3.addParams({
      "cache_line_size": GRACE_CLW,
      "aggressiveness": 1,
})

# --------------------------------------------- L3 Cache ---------------------------------------------



# ----------------------------------- Memory Backend & Controller -------------------------------------

memory_controller = sst.Component("GRACE.memorycontroller", "memHierarchy.MemController")
memory_controller.addParams({
      "clock": GRACE_CLOCK,
      "backend.access_time": GRACE_MEM_ACCESS,
      "request_width": GRACE_MEMTOL3_TPUT,
      "debug": DEBUG_MEM,
      "debug_level": DEBUG_LEVEL,
      "addr_range_start": memprops["start_addr"],
      "addr_range_end": memprops["end_addr"]
})

memory_backend = memory_controller.setSubComponent("backend", "memHierarchy.simpleMem")
memory_backend.addParams({
      "access_time": GRACE_MEM_ACCESS,
      "mem_size": memprops["size"],
      "request_width": GRACE_MEMTOL3_TPUT,
})

# ----------------------------------- Memory Backend & Controller -------------------------------------

# sst.setStatisticLoadLevel(7)
# sst.setStatisticOutput("sst.statOutputConsole")
# sst.enableStatisticsForComponentName("GRACE.l1cache", ["TotalEventsReceived","CacheHits", "CacheMisses", "prefetch_useful", "prefetch_evict", "prefetch_inv", "prefetch_coherence_miss", "prefetch_redundant"])
# sst.enableStatisticsForComponentName("GRACE.l2cache", ["TotalEventsReceived","CacheHits", "CacheMisses", "prefetch_useful", "prefetch_evict", "prefetch_inv", "prefetch_coherence_miss", "prefetch_redundant"])

# ---------------------------------------------- Links ------------------------------------------------

link_cpu_l1cache = sst.Link("link_cpu_l1cache_link")
link_cpu_l1cache.connect( (interface, "port", "1ps"), (l1cache, "high_network_0", "1ps") )
link_l1cache_l2cache = sst.Link("link_l1cache_l2cache_link")
link_l1cache_l2cache.connect( (l1cache, "low_network_0", "1ps"), (l2cache, "high_network_0", "1ps") )
link_l2cache_l3cache = sst.Link("link_l2cache_l3cache_link")
link_l2cache_l3cache.connect( (l2cache, "low_network_0", "1ps"), (l3cache, "high_network_0", "1ps") )
link_mem_bus = sst.Link("link_mem_bus_link")
link_mem_bus.connect( (l3cache, "low_network_0", "1ps"), (memory_controller, "direct_link", "1ps") )

# ---------------------------------------------- Links ------------------------------------------------