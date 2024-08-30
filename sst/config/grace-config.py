import sst

DEBUG_L1 = 0
DEBUG_L2 = 0
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

# Cache line size of L1 & L2 in Grace in bytes.
GRACE_CLW = 64
# Clock Frequency of Grace.
GRACE_CLOCK = "3.4GHz"
# Size of L1 cache in Grace.
GRACE_L1_SIZE = "64KiB"
# Size of L2 cache in Grace.
GRACE_L2_SIZE = "1MiB"


# Set associativity of Grace L1
GRACE_SA_L1 = 4
# Set associativity of Grace L2
GRACE_SA_L2 = 16
# Hit latency of Grace L1 cache (cycles).
GRACE_HL_L1 = 3 # 5 cycles (-2 due to SimEng overhead)
# Hit latency of Grace L2 cache (cycles).
GRACE_HL_L2 = 44 # 46-56 cycles (-2 due to SimEng overhead)
# Coherence protocol of Grace caches.
GRACE_COHP = "MESI"
# L1 & L2 cache type of Grace.
GRACE_CACHE_TYPE = "inclusive"
# Throughput of L1 to L2 per core in Grace. (bytes per cycle)
GRACE_L1TOL2_PC_TPUT = "32B"
# Throughput of L1 to CPU per core in Grace. Value of 0 indicates infinity. (bytes per cycle)
GRACE_L1TOCPU_PC_TPUT = "128B"
# Throughput of L2 to Memory per CMG in Grace. (bytes per cycle)
GRACE_L2TOMEM_PCMG_TPUT = "64B"
# Throughput of L2 to L1 per core in Grace. (bytes per cycle)
GRACE_L2TOL1_PC_TPUT = "64B"
# Throughput of Memory to L2 per CMG in Grace. (bytes per cycle)
GRACE_MEMTOL2_PCMG_TPUT = "128B"
# Grace Memory access time.
GRACE_MEM_ACCESS = "135.5ns"

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
    "simeng_config_path": "<PATH TO GRACE SIMENG MODEL CONFIG>",
    "executable_path": "<PATH TO EXECUTABLE BINARY>",
    "executable_args": "",
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
      "cache_type": GRACE_CACHE_TYPE,
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
replacement_policy_l1 = l1cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

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
      "cache_type": GRACE_CACHE_TYPE,
      "access_latency_cycles" : GRACE_HL_L2,
      "cache_frequency" : GRACE_CLOCK,
      "associativity" : GRACE_SA_L2,
      "cache_line_size" : GRACE_CLW,
      "cache_size" : GRACE_L2_SIZE,
      "debug" : DEBUG_L2,
      "debug_level" : DEBUG_LEVEL,
      "coherence_protocol": GRACE_COHP,
      "max_requests_per_cycle": 4,
      "request_link_width": GRACE_L2TOMEM_PCMG_TPUT,
      "response_link_width": GRACE_L2TOL1_PC_TPUT,
      "mshr_latency_cycles": 1,
      "tag_access_latency": 1,
      "llsc_block_cycles": 1000,
})
# Set MESI L2 coherence controller to the "coherence" slot
coherence_controller_l2 = l2cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_inclusive")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy_l2 = l2cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

prefetcher_l2 = l2cache.setSubComponent("prefetcher", PREFETCHER)
prefetcher_l2.addParams({
      "cache_line_size": GRACE_CLW,
      "aggressiveness": 1,
})

# --------------------------------------------- L2 Cache ---------------------------------------------


# ----------------------------------- Memory Backend & Controller -------------------------------------

memory_controller = sst.Component("GRACE.memorycontroller", "memHierarchy.MemController")
memory_controller.addParams({
      "clock": GRACE_CLOCK,
      "backend.access_time": GRACE_MEM_ACCESS,
      "request_width": GRACE_MEMTOL2_PCMG_TPUT,
      "debug": DEBUG_MEM,
      "debug_level": DEBUG_LEVEL,
      "addr_range_start": memprops["start_addr"],
      "addr_range_end": memprops["end_addr"]
})

memory_backend = memory_controller.setSubComponent("backend", "memHierarchy.simpleMem")
memory_backend.addParams({
      "access_time": GRACE_MEM_ACCESS,
      "mem_size": memprops["size"],
      "request_width": 128,
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
link_mem_bus = sst.Link("link_mem_bus_link")
link_mem_bus.connect( (l2cache, "low_network_0", "1ps"), (memory_controller, "direct_link", "1ps") )

# ---------------------------------------------- Links ------------------------------------------------