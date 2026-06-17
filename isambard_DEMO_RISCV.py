import sst
import sys

DEBUG_L1 = 0
DEBUG_L2 = 0
DEBUG_MEM = 0
DEBUG_LEVEL = 10


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


# ------------------------------------------- DEMO_RISCV Properties ---------------------------------------

# This SST configuration file represents the memory model for the Fujitsu DEMO_RISCV processor.
# Reference: https://github.com/fujitsu/DEMO_RISCV/blob/master/doc/DEMO_RISCV_Microarchitecture_Manual_en_1.8.pdf

# Cache line size of L1 & L2 in DEMO_RISCV in bytes.
DEMO_RISCV_CLW = 256
# Clock Frequency of DEMO_RISCV.
DEMO_RISCV_CLOCK = "2.5GHz"
# Size of L1 cache in DEMO_RISCV.
DEMO_RISCV_L1_SIZE = "64KiB"
# Size of L2 cache in DEMO_RISCV.
DEMO_RISCV_L2_SIZE = "8MiB"
# Set associativity of DEMO_RISCV L1
DEMO_RISCV_SA_L1 = 4
# Set associativity of DEMO_RISCV L2
DEMO_RISCV_SA_L2 = 16
# Hit latency of DEMO_RISCV L1 cache (cycles).
DEMO_RISCV_HL_L1 = 4
# Hit latency of DEMO_RISCV L2 cache (cycles).
DEMO_RISCV_HL_L2 = 44
# Cohenrence protocol of DEMO_RISCV caches.
DEMO_RISCV_COHP = "MESI"
# L1 & L2 cache type of DEMO_RISCV.
DEMO_RISCV_CACHE_TYPE = "inclusive"
# Throughput of L1 to L2 per core in DEMO_RISCV. (bytes per cycle)
DEMO_RISCV_L1TOL2_PC_TPUT = "32B"
# Throughput of L1 to CPU per core in DEMO_RISCV. Value of 0 indicates infinity. (bytes per cycle)
DEMO_RISCV_L1TOCPU_PC_TPUT = "128B"
# Throughput of L2 to Memory per CMG in DEMO_RISCV. (bytes per cycle)
DEMO_RISCV_L2TOMEM_PCMG_TPUT = "64B"
# Throughput of L2 to L1 per core in DEMO_RISCV. (bytes per cycle)
DEMO_RISCV_L2TOL1_PC_TPUT = "64B"
# Throughput of Memory to L2 per CMG in DEMO_RISCV. (bytes per cycle)
DEMO_RISCV_MEMTOL2_PCMG_TPUT = "128B"
# DEMO_RISCV Memory access time.
DEMO_RISCV_MEM_ACCESS = "135ns"

# ------------------------------------------- DEMO_RISCV Properties ---------------------------------------


# ---------------------------------------------- Variables -------------------------------------------

memprops = getMemoryProps(3, "GiB")

# ---------------------------------------------- Variables -------------------------------------------


# --------------------------------------------- SSTSimEng OS ---------------------------------------

# Using sst-info sstsimeng.simos to get all cache parameters, ports and subcomponent slots.
simos = sst.Component("simos", "sstsimeng.simos")
simos.addParams({
    "num_cores": 1,
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/configs/DEMO_RISCV.yaml",
    "executable_path": sys.argv[1],
    "executable_args": ' '.join(sys.argv[2:]),
    "clock" : DEMO_RISCV_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": DEMO_RISCV_CLW,
    "debug": False,
})
os_dataInterface = simos.setSubComponent("dataMemory", "memHierarchy.standardInterface")
os_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
os_instrInterface = simos.setSubComponent("instrMemory", "memHierarchy.standardInterface")
os_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
simos.setRank(0, 0)

os_l1Dcache = sst.Component("os.l1Dcache0", "memHierarchy.Cache")
os_l1Dcache.addParams({
        "L1": 1,
        "cache_type": DEMO_RISCV_CACHE_TYPE,
        "access_latency_cycles": DEMO_RISCV_HL_L1,
        "cache_frequency": DEMO_RISCV_CLOCK,
        "associativity": DEMO_RISCV_SA_L1,
        "cache_line_size": DEMO_RISCV_CLW,
        "cache_size": DEMO_RISCV_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": DEMO_RISCV_COHP,
        "request_link_width": DEMO_RISCV_L1TOL2_PC_TPUT,
        "response_link_width": DEMO_RISCV_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 1,
        "llsc_block_cycles": 1000,
})
coherence_controller_os_l1D = os_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_os_l1D = os_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_os_l1D = os_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_os_l1D.addParams({"cache_line_size": DEMO_RISCV_CLW})
os_l1Dcache.setRank(0, 0)

os_l1Icache = sst.Component("os.l1Icache0", "memHierarchy.Cache")
os_l1Icache.addParams({
        "L1": 1,
        "cache_type": DEMO_RISCV_CACHE_TYPE,
        "access_latency_cycles": DEMO_RISCV_HL_L1,
        "cache_frequency": DEMO_RISCV_CLOCK,
        "associativity": DEMO_RISCV_SA_L1,
        "cache_line_size": DEMO_RISCV_CLW,
        "cache_size": DEMO_RISCV_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": DEMO_RISCV_COHP,
        "request_link_width": DEMO_RISCV_L1TOL2_PC_TPUT,
        "response_link_width": DEMO_RISCV_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 1,
        "llsc_block_cycles": 1000,
})
coherence_controller_os_l1I = os_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_os_l1I = os_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_os_l1I = os_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_os_l1I.addParams({"cache_line_size": DEMO_RISCV_CLW})
os_l1Icache.setRank(0, 0)

# --------------------------------------------- SSTSimEng OS ---------------------------------------


# --------------------------------------------- SSTSimEng Cores --------------------------------------

#Core0
cpu0 = sst.Component("core0", "sstsimeng.simengcore")
cpu0.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/configs/DEMO_RISCV.yaml",
    "clock" : DEMO_RISCV_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": DEMO_RISCV_CLW,
    "debug": False,
})
c0_dataInterface = cpu0.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c0_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c0_instrInterface = cpu0.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c0_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu0.setRank(0, 0)

c0_l1Dcache = sst.Component("c0.l1Dcache", "memHierarchy.Cache")
c0_l1Dcache.addParams({
        "L1": 1,
        "cache_type": DEMO_RISCV_CACHE_TYPE,
        "access_latency_cycles": DEMO_RISCV_HL_L1,
        "cache_frequency": DEMO_RISCV_CLOCK,
        "associativity": DEMO_RISCV_SA_L1,
        "cache_line_size": DEMO_RISCV_CLW,
        "cache_size": DEMO_RISCV_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": DEMO_RISCV_COHP,
        "request_link_width": DEMO_RISCV_L1TOL2_PC_TPUT,
        "response_link_width": DEMO_RISCV_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 1,
        "llsc_block_cycles": 1000,
})
coherence_controller_c0_l1D = c0_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c0_l1D = c0_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c0_l1D = c0_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c0_l1D.addParams({
    "cache_line_size": DEMO_RISCV_CLW,                 #Size of the cache line the prefetcher is attached to
    "aggressiveness": 3                                #Number of entries to keep for historical comparison
})
c0_l1Dcache.setRank(1, 0)

c0_l1Icache = sst.Component("c0.l1Icache", "memHierarchy.Cache")
c0_l1Icache.addParams({
        "L1": 1,
        "cache_type": DEMO_RISCV_CACHE_TYPE,
        "access_latency_cycles": DEMO_RISCV_HL_L1,
        "cache_frequency": DEMO_RISCV_CLOCK,
        "associativity": DEMO_RISCV_SA_L1,
        "cache_line_size": DEMO_RISCV_CLW,
        "cache_size": DEMO_RISCV_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": DEMO_RISCV_COHP,
        "request_link_width": DEMO_RISCV_L1TOL2_PC_TPUT,
        "response_link_width": DEMO_RISCV_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 1,
        "llsc_block_cycles": 1000,
})
coherence_controller_c0_l1I = c0_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c0_l1I = c0_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c0_l1I = c0_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c0_l1I.addParams({
    "cache_line_size": DEMO_RISCV_CLW,                 #Size of the cache line the prefetcher is attached to
    "aggressiveness": 3                                #Number of entries to keep for historical comparison
})
c0_l1Icache.setRank(1, 0)

# --------------------------------------------- SSTSimEng Cores --------------------------------------


# -------------------------------------------- L1-L2 BUSES --------------------------------------------

bus_0_l1_l2 = sst.Component("bus_0_l1_l2", "memHierarchy.Bus")
bus_0_l1_l2.addParams({
      "bus_frequency" : DEMO_RISCV_CLOCK,
})
bus_0_l1_l2.setRank(0, 0)

# -------------------------------------------- L1-L2 BUSES --------------------------------------------


# --------------------------------------------- L2 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l2cache_0 = sst.Component("core.l2cache0", "memHierarchy.Cache")
l2cache_0.addParams({
        "L1": 0,
        "cache_type": DEMO_RISCV_CACHE_TYPE,
        "access_latency_cycles": DEMO_RISCV_HL_L2,
        "cache_frequency": DEMO_RISCV_CLOCK,
        "associativity": DEMO_RISCV_SA_L2,
        "cache_line_size": DEMO_RISCV_CLW,
        "cache_size": DEMO_RISCV_L2_SIZE,
        "debug": DEBUG_L2,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": DEMO_RISCV_COHP,
        "request_link_width": DEMO_RISCV_L2TOMEM_PCMG_TPUT,
        "response_link_width": DEMO_RISCV_L2TOL1_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 1,
        "llsc_block_cycles": 1000,
})
# Set MESI L2 coherence controller to the "coherence" slot
coherence_controller_l2_0 = l2cache_0.setSubComponent("coherence", "memHierarchy.coherence.mesi_inclusive")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy_l2_0 = l2cache_0.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_l2cache_0 = l2cache_0.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_l2cache_0.addParams({
    "cache_line_size": DEMO_RISCV_CLW,                 #Size of the cache line the prefetcher is attached to
    "aggressiveness": 3                                #Number of entries to keep for historical comparison
})
l2cache_0.setRank(0, 0)

# --------------------------------------------- L2 Cache ---------------------------------------------


# -------------------------------------------- L2-MEM BUS ----------------------------------------------

# bus_l2_mem = sst.Component("bus_l2_mem", "memHierarchy.Bus")
# bus_l2_mem.addParams({
#       "bus_frequency" : DEMO_RISCV_CLOCK,
# })
# bus_l2_mem.setRank(0, 0)

# -------------------------------------------- L2-MEM BUS ----------------------------------------------


# -------------------------------------------- L3 CACHE ----------------------------------------------


# l3cache = sst.Component("core.l3cache", "memHierarchy.Cache")
# l3cache.addParams({
#         "L1": 0,
#         "cache_type": DEMO_RISCV_CACHE_TYPE,
#         "access_latency_cycles": DEMO_RISCV_HL_L2,
#         "cache_frequency": DEMO_RISCV_CLOCK,
#         "associativity": DEMO_RISCV_SA_L2,
#         "cache_line_size": DEMO_RISCV_CLW,
#         "cache_size": "64MiB",
#         "debug": DEBUG_L2,
#         "debug_level": DEBUG_LEVEL,
#         "coherence_protocol": DEMO_RISCV_COHP,
#         "request_link_width": DEMO_RISCV_L2TOMEM_PCMG_TPUT,
#         "response_link_width": DEMO_RISCV_L2TOL1_PC_TPUT,
#         "mshr_latency_cycles": 1,
#         "tag_access_latency": 37,
#         "llsc_block_cycles": 1000,
# })
# coherence_controller_l3= l3cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_inclusive")
# replacement_policy_l3 = l3cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
# prefetcher_l3cache = l3cache.setSubComponent("prefetcher", "cassini.StridePrefetcher")
# prefetcher_l3cache.addParams({
#     "cache_line_size": DEMO_RISCV_CLW,                 #Size of the cache line the prefetcher is attached to
#     "history": 16,                                #Number of entries to keep for historical comparison
#     "reach": 2,                                   #Reach (how far forward the prefetcher should fetch lines)
#     "detect_range": 4,                            #Range to detect addresses over in request counts
#     "address_count": 64,                          #Number of addresses to keep in prefetch table
#     "page_size": 4096,                            #Page size for this controller
#     "overrun_page_boundaries": 0,                 #Allow prefetcher to run over page boundaries, 0 is no, 1 is yes
# })
# l3cache.setRank(0, 0)

# -------------------------------------------- L3 CACHE ----------------------------------------------


# ----------------------------------- Memory Backend & Controller -------------------------------------

memory_controller = sst.Component("DEMO_RISCV.memorycontroller", "memHierarchy.MemController")
memory_controller.addParams({
      "clock": DEMO_RISCV_CLOCK,
      "backend.access_time": DEMO_RISCV_MEM_ACCESS,
      "request_width": DEMO_RISCV_MEMTOL2_PCMG_TPUT,
      "debug": DEBUG_MEM,
      "debug_level": DEBUG_LEVEL,
      "verbose": 2,
      "addr_range_start": memprops["start_addr"],
      "addr_range_end": memprops["end_addr"]
})
memory_backend = memory_controller.setSubComponent("backend", "memHierarchy.simpleMem")
memory_backend.addParams({
      "access_time": DEMO_RISCV_MEM_ACCESS,
      "mem_size": memprops["size"],
      "request_width": 128,
      "debug": DEBUG_MEM,
      "debug_level": DEBUG_LEVEL,
})
memory_controller.setRank(0, 0)

# ----------------------------------- Memory Backend & Controller -------------------------------------


# ---------------------------------------------- NETWORK ----------------------------------------------

verb_params = { "verbose" : 6 }
net_params = {
  "input_buf_size" : "512B",
  "output_buf_size" : "512B",
  "link_bw" : "1GB/s"
}

os_noc = simos.setSubComponent("noc", "sstsimeng.SimEngNOC")
os_noc.addParams(verb_params)
os_netInterface = os_noc.setSubComponent("interface", "merlin.linkcontrol")
os_netInterface.addParams(net_params)

c0_noc = cpu0.setSubComponent("noc", "sstsimeng.SimEngNOC")
c0_noc.addParams(verb_params)
c0_netInterface = c0_noc.setSubComponent("interface", "merlin.linkcontrol")
c0_netInterface.addParams(net_params)

router = sst.Component("router", "merlin.hr_router")
router.setSubComponent("topology", "merlin.singlerouter")
router.addParams(net_params)
router.addParams({
    "xbar_bw" : "1GB/s",
    "flit_size" : "32B",
    "num_ports" : "2",
    "id" : 0
})
router.setRank(0, 0)

# ---------------------------------------------- NETWORK ----------------------------------------------


# ---------------------------------------------- Links ------------------------------------------------

link_os_l1Dcache = sst.Link("link_os_l1Dcache_link")
link_os_l1Dcache.connect( (os_dataInterface, "port", "1ps"), (os_l1Dcache, "high_network_0", "1ps") )
link_os_l1Icache = sst.Link("link_os_l1Icache_link")
link_os_l1Icache.connect( (os_instrInterface, "port", "1ps"), (os_l1Icache, "high_network_0", "1ps") )
link_os_router = sst.Link("link_os_router")
link_os_router.connect((os_netInterface, "rtr_port", "1ps"), (router, "port0", "1ps"))

link_os_l1D_l2bus = sst.Link("link_os_l1D_l2bus_link")
link_os_l1D_l2bus.connect( (os_l1Dcache, "low_network_0", "1ps"), (bus_0_l1_l2, "high_network_0", "1ps") )
link_os_l1I_l2bus = sst.Link("link_os_l1I_l2bus_link")
link_os_l1I_l2bus.connect( (os_l1Icache, "low_network_0", "1ps"), (bus_0_l1_l2, "high_network_1", "1ps") )


link_c0_l1Dcache = sst.Link("link_c0_l1Dcache_link")
link_c0_l1Dcache.connect( (c0_dataInterface, "port", "1ps"), (c0_l1Dcache, "high_network_0", "1ps") )
link_c0_l1Icache = sst.Link("link_c0_l1Icache_link")
link_c0_l1Icache.connect( (c0_instrInterface, "port", "1ps"), (c0_l1Icache, "high_network_0", "1ps") )
link_c0_router = sst.Link("link_c0_router")
link_c0_router.connect((c0_netInterface, "rtr_port", "1ps"), (router, "port1", "1ps"))

link_c0_l1D_l2bus = sst.Link("link_c0_l1D_l2bus_link")
link_c0_l1D_l2bus.connect( (c0_l1Dcache, "low_network_0", "1ps"), (bus_0_l1_l2, "high_network_2", "1ps") )
link_c0_l1I_l2bus = sst.Link("link_c0_l1I_l2bus_link")
link_c0_l1I_l2bus.connect( (c0_l1Icache, "low_network_0", "1ps"), (bus_0_l1_l2, "high_network_3", "1ps") )


link_bus_0_l2 = sst.Link("link_bus_0_l2_link")
link_bus_0_l2.connect( (bus_0_l1_l2, "low_network_0", "1ps"), (l2cache_0, "high_network_0", "1ps") )


# link_l2_0_mem_bus = sst.Link("link_l2_0_mem_bus_link")
# link_l2_0_mem_bus.connect( (l2cache_0, "low_network_0", "1ps"), (bus_l2_mem, "high_network_0", "1ps") )


# link_bus_l3 = sst.Link("link_bus_l3_link")
# link_bus_l3.connect( (bus_l2_mem, "low_network_0", "1ps"), (l3cache, "high_network_0", "1ps") )


link_l3_mem = sst.Link("link_l3_mem_link")
link_l3_mem.connect( (l2cache_0, "low_network_0", "1ps"), (memory_controller, "direct_link", "1ps") )

# ---------------------------------------------- Links ------------------------------------------------



# ------------------------------------------- Statistics ---------------------------------------------

sst.setStatisticOutput("sst.statOutputCSV", {"filepath":"stats.csv", "separator":","})
sst.setStatisticLoadLevel(10)
sst.enableStatisticsForComponentType("memHierarchy.Cache",["CacheHits", "CacheMisses", "prefetches_issued", "miss_events_processed", "hit_events_processed", "prefetches_canceled_by_page_boundary", "prefetches_canceled_by_history", "prefetch_opportunities", "prefetch_useful", "prefetch_evict", "prefetch_inv", "prefetch_coherence_miss", "prefetch_redundant"], {}, True)
sst.enableAllStatisticsForComponentType("sstsimeng.simengcore", {}, True)

# ------------------------------------------- Statistics ---------------------------------------------


