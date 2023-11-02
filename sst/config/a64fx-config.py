import sst

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

# ranks = sst.getMPIRankCount()

# print(ranks)


# ------------------------------------------- A64FX Properties ---------------------------------------

# This SST configuration file represents the memory model for the Fujitsu A64fx processor.
# Reference: https://github.com/fujitsu/A64FX/blob/master/doc/A64FX_Microarchitecture_Manual_en_1.8.pdf

# Cache line size of L1 & L2 in A64FX in bytes.
A64FX_CLW = 256
# Clock Frequency of A64FX.
A64FX_CLOCK = "1.8GHz"
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
A64FX_HL_L2 = 56
# Cohenrence protocol of A64FX caches.
A64FX_COHP = "MESI"
# L1 & L2 cache type of A64FX.
A64FX_CACHE_TYPE = "inclusive"
# Throughput of L1 to L2 per core in A64FX. (bytes per cycle)
A64FX_L1TOL2_PC_TPUT = "32B"
# Throughput of L1 to CPU per core in A64FX. Value of 0 indicates infinity. (bytes per cycle)
A64FX_L1TOCPU_PC_TPUT = "128B"
# Throughput of L2 to Memory per CMG in A64FX. (bytes per cycle)
A64FX_L2TOMEM_PCMG_TPUT = "64B"
# Throughput of L2 to L1 per core in A64FX. (bytes per cycle)
A64FX_L2TOL1_PC_TPUT = "64B"
# Throughput of Memory to L2 per CMG in A64FX. (bytes per cycle)
A64FX_MEMTOL2_PCMG_TPUT = 128
# A64FX Memory access time.
A64FX_MEM_ACCESS = "144.5ns"

# ------------------------------------------- A64FX Properties ---------------------------------------


# ---------------------------------------------- Variables -------------------------------------------

memprops = getMemoryProps(3, "GiB")

# ---------------------------------------------- Variables -------------------------------------------


# --------------------------------------------- SSTSimEng OS ---------------------------------------

# Using sst-info sstsimeng.simos to get all cache parameters, ports and subcomponent slots.
simos = sst.Component("simos", "sstsimeng.simos")
simos.addParams({
    "num_cores": 2,
    "simeng_config_path": "/Users/jj16791/workspace/SimEng/configs/a64fx.yaml",
    "executable_path": "/Users/jj16791/workspace/simeng-benchmarks/binaries/miniBUDE/openmp/minibude_gcc10.3.0_armv8.4",
    "executable_args": "-n 128 -i 1 --deck /Users/jj16791/workspace/simeng-benchmarks/Data_Files/miniBUDE/bm1",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})

# Instantiating the StandardInterface which communicates with the SST memory model.
dataInterface0 = simos.setSubComponent("dataMemory", "memHierarchy.standardInterface")
dataInterface0.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
instrInterface0 = simos.setSubComponent("instrMemory", "memHierarchy.standardInterface")
instrInterface0.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})

simos.setRank(0, 0)

os_l1Dcache = sst.Component("a64fx.l1Dcache0", "memHierarchy.Cache")
os_l1Dcache.addParams({
        "L1": 1,
        "cache_type": A64FX_CACHE_TYPE,
        "access_latency_cycles": A64FX_HL_L1,
        "cache_frequency": A64FX_CLOCK,
        "associativity": A64FX_SA_L1,
        "cache_line_size": A64FX_CLW,
        "cache_size": A64FX_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": A64FX_COHP,
        "request_link_width": A64FX_L1TOL2_PC_TPUT,
        "response_link_width": A64FX_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 2,
})

coherence_controller_os_l1D = os_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_os_l1D = os_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

prefetcher_os_l1D = os_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_os_l1D.addParams({"cache_line_size": A64FX_CLW})

os_l1Dcache.setRank(0, 0)

os_l1Icache = sst.Component("a64fx.l1Icache0", "memHierarchy.Cache")
os_l1Icache.addParams({
        "L1": 1,
        "cache_type": A64FX_CACHE_TYPE,
        "access_latency_cycles": A64FX_HL_L1,
        "cache_frequency": A64FX_CLOCK,
        "associativity": A64FX_SA_L1,
        "cache_line_size": A64FX_CLW,
        "cache_size": A64FX_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": A64FX_COHP,
        "request_link_width": A64FX_L1TOL2_PC_TPUT,
        "response_link_width": A64FX_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 2,
})

coherence_controller_os_l1I = os_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_os_l1I = os_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

prefetcher_os_l1I = os_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_os_l1I.addParams({"cache_line_size": A64FX_CLW})

os_l1Icache.setRank(0, 0)

# --------------------------------------------- SSTSimEng OS ---------------------------------------


# --------------------------------------------- SSTSimEng Core ---------------------------------------

cpu0 = sst.Component("core0", "sstsimeng.simengcore")
cpu0.addParams({
    "simeng_config_path": "/Users/jj16791/workspace/SimEng/configs/a64fx.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})

dataInterface1 = cpu0.setSubComponent("dataMemory", "memHierarchy.standardInterface")
dataInterface1.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
instrInterface1 = cpu0.setSubComponent("instrMemory", "memHierarchy.standardInterface")
instrInterface1.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})

cpu0.setRank(1, 0)

c0_l1Dcache = sst.Component("a64fx.l1Dcache1", "memHierarchy.Cache")
c0_l1Dcache.addParams({
        "L1": 1,
        "cache_type": A64FX_CACHE_TYPE,
        "access_latency_cycles": A64FX_HL_L1,
        "cache_frequency": A64FX_CLOCK,
        "associativity": A64FX_SA_L1,
        "cache_line_size": A64FX_CLW,
        "cache_size": A64FX_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": A64FX_COHP,
        "request_link_width": A64FX_L1TOL2_PC_TPUT,
        "response_link_width": A64FX_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 2,
})

coherence_controller_c0_l1D = c0_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c0_l1D = c0_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

prefetcher_c0_l1D = c0_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c0_l1D.addParams({"cache_line_size": A64FX_CLW})

c0_l1Dcache.setRank(1, 0)

c0_l1Icache = sst.Component("a64fx.l1Icache1", "memHierarchy.Cache")
c0_l1Icache.addParams({
        "L1": 1,
        "cache_type": A64FX_CACHE_TYPE,
        "access_latency_cycles": A64FX_HL_L1,
        "cache_frequency": A64FX_CLOCK,
        "associativity": A64FX_SA_L1,
        "cache_line_size": A64FX_CLW,
        "cache_size": A64FX_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": A64FX_COHP,
        "request_link_width": A64FX_L1TOL2_PC_TPUT,
        "response_link_width": A64FX_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 2,
})

coherence_controller_c0_l1I = c0_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c0_l1I = c0_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

prefetcher_c0_l1I = c0_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c0_l1I.addParams({"cache_line_size": A64FX_CLW})

c0_l1Icache.setRank(1, 0)

cpu1 = sst.Component("core1", "sstsimeng.simengcore")
cpu1.addParams({
    "simeng_config_path": "/Users/jj16791/workspace/SimEng/configs/a64fx.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})

cpu1.setRank(2, 0)

dataInterface2 = cpu1.setSubComponent("dataMemory", "memHierarchy.standardInterface")
dataInterface2.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
instrInterface2 = cpu1.setSubComponent("instrMemory", "memHierarchy.standardInterface")
instrInterface2.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})

c1_l1Dcache = sst.Component("a64fx.l1Dcache2", "memHierarchy.Cache")
c1_l1Dcache.addParams({
        "L1": 1,
        "cache_type": A64FX_CACHE_TYPE,
        "access_latency_cycles": A64FX_HL_L1,
        "cache_frequency": A64FX_CLOCK,
        "associativity": A64FX_SA_L1,
        "cache_line_size": A64FX_CLW,
        "cache_size": A64FX_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": A64FX_COHP,
        "request_link_width": A64FX_L1TOL2_PC_TPUT,
        "response_link_width": A64FX_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 2,
})

coherence_controller_c1_l1D = c1_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c1_l1D = c1_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

prefetcher_c1_l1D = c1_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c1_l1D.addParams({"cache_line_size": A64FX_CLW})

c1_l1Dcache.setRank(2, 0)

c1_l1Icache = sst.Component("a64fx.l1Icache2", "memHierarchy.Cache")
c1_l1Icache.addParams({
        "L1": 1,
        "cache_type": A64FX_CACHE_TYPE,
        "access_latency_cycles": A64FX_HL_L1,
        "cache_frequency": A64FX_CLOCK,
        "associativity": A64FX_SA_L1,
        "cache_line_size": A64FX_CLW,
        "cache_size": A64FX_L1_SIZE,
        "debug": DEBUG_L1,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": A64FX_COHP,
        "request_link_width": A64FX_L1TOL2_PC_TPUT,
        "response_link_width": A64FX_L1TOCPU_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 2,
})

coherence_controller_c1_l1I = c1_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c1_l1I = c1_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

prefetcher_c1_l1I = c1_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c1_l1I.addParams({"cache_line_size": A64FX_CLW})

c1_l1Icache.setRank(2, 0)

# --------------------------------------------- SSTSimEng Core ---------------------------------------


# --------------------------------------------- L1-L2 BUS ---------------------------------------------

bus = sst.Component("bus", "memHierarchy.Bus")
bus.addParams({
      "bus_frequency" : A64FX_CLOCK,
})

bus.setRank(0, 0)

# --------------------------------------------- L1-L2 BUS ---------------------------------------------


# --------------------------------------------- L2 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l2cache = sst.Component("core.l2cache", "memHierarchy.Cache")
l2cache.addParams({
        "L1": 0,
        "cache_type": A64FX_CACHE_TYPE,
        "access_latency_cycles": A64FX_HL_L2,
        "cache_frequency": A64FX_CLOCK,
        "associativity": A64FX_SA_L2,
        "cache_line_size": A64FX_CLW,
        "cache_size": A64FX_L2_SIZE,
        "debug": DEBUG_L2,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": A64FX_COHP,
        "request_link_width": A64FX_L2TOMEM_PCMG_TPUT,
        "response_link_width": A64FX_L2TOL1_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 37,
})
# Set MESI L2 coherence controller to the "coherence" slot
coherence_controller_l2 = l2cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_inclusive")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy_l2 = l2cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

l2cachePre = l2cache.setSubComponent("prefetcher", "cassini.StridePrefetcher")
l2cachePre.addParams({
    'cache_line_size': A64FX_CLW,                 #Size of the cache line the prefetcher is attached to
    'history': 16,                                #Number of entries to keep for historical comparison
    'reach': 2,                                   #Reach (how far forward the prefetcher should fetch lines)
    'detect_range': 4,                            #Range to detect addresses over in request counts
    'address_count': 64,                          #Number of addresses to keep in prefetch table
    'page_size': 4096,                            #Page size for this controller
    'overrun_page_boundaries': 0,                 #Allow prefetcher to run over page boundaries, 0 is no, 1 is yes
})

l2cache.setRank(0, 0)

# --------------------------------------------- L2 Cache ---------------------------------------------


# ---------------------------------------------- NETWORK ----------------------------------------------

verb_params = { "verbose" : 6 }
net_params = {
  "input_buf_size" : "512B",
  "output_buf_size" : "512B",
  "link_bw" : "1GB/s"
}

noc0 = simos.setSubComponent("noc", "sstsimeng.SimEngNOC")
noc0.addParams(verb_params)
netInterface0 = noc0.setSubComponent("interface", "merlin.linkcontrol")
netInterface0.addParams(net_params)

noc1 = cpu0.setSubComponent("noc", "sstsimeng.SimEngNOC")
noc1.addParams(verb_params)
netInterface1 = noc1.setSubComponent("interface", "merlin.linkcontrol")
netInterface1.addParams(net_params)

noc2 = cpu1.setSubComponent("noc", "sstsimeng.SimEngNOC")
noc2.addParams(verb_params)
netInterface2 = noc2.setSubComponent("interface", "merlin.linkcontrol")
netInterface2.addParams(net_params)

router = sst.Component("router", "merlin.hr_router")
router.setSubComponent("topology", "merlin.singlerouter")
router.addParams(net_params)
router.addParams({
    "xbar_bw" : "1GB/s",
    "flit_size" : "32B",
    "num_ports" : "3",
    "id" : 0
})

router.setRank(0, 0)

# ---------------------------------------------- NETWORK ----------------------------------------------


# ----------------------------------- Memory Backend & Controller -------------------------------------

memory_controller = sst.Component("a64fx.memorycontroller", "memHierarchy.MemController")
memory_controller.addParams({
      "clock": A64FX_CLOCK,
      "backend.access_time": A64FX_MEM_ACCESS,
      "request_width": A64FX_MEMTOL2_PCMG_TPUT,
      "debug": DEBUG_MEM,
      "debug_level": DEBUG_LEVEL,
      "verbose": 2,
      "addr_range_start": memprops["start_addr"],
      "addr_range_end": memprops["end_addr"]
})

memory_backend = memory_controller.setSubComponent("backend", "memHierarchy.simpleMem")
memory_backend.addParams({
      "access_time": A64FX_MEM_ACCESS,
      "mem_size": memprops["size"],
      "request_width": 128,
      "debug": DEBUG_MEM,
      "debug_level": DEBUG_LEVEL,
})

memory_controller.setRank(0, 0)

# ----------------------------------- Memory Backend & Controller -------------------------------------


# ---------------------------------------------- Links ------------------------------------------------

link_os_l1Dcache = sst.Link("link_os_l1Dcache_link")
link_os_l1Dcache.connect( (dataInterface0, "port", "1ps"), (os_l1Dcache, "high_network_0", "1ps") )
link_os_l1Icache = sst.Link("link_os_l1Icache_link")
link_os_l1Icache.connect( (instrInterface0, "port", "1ps"), (os_l1Icache, "high_network_0", "1ps") )
link_os_router = sst.Link("link_os_router")
link_os_router.connect((netInterface0, "rtr_port", "1ps"), (router, "port0", "1ps"))

link_cpu0_l1Dcache = sst.Link("link_cpu0_l1Dcache_link")
link_cpu0_l1Dcache.connect( (dataInterface1, "port", "1ps"), (c0_l1Dcache, "high_network_0", "1ps") )
link_cpu0_l1Icache = sst.Link("link_cpu0_l1Icache_link")
link_cpu0_l1Icache.connect( (instrInterface1, "port", "1ps"), (c0_l1Icache, "high_network_0", "1ps") )
link_cpu0_router = sst.Link("link_cpu0_router")
link_cpu0_router.connect((netInterface1, "rtr_port", "1ps"), (router, "port1", "1ps"))

link_cpu1_l1Dcache = sst.Link("link_cpu1_l1Dcache_link")
link_cpu1_l1Dcache.connect( (dataInterface2, "port", "1ps"), (c1_l1Dcache, "high_network_0", "1ps") )
link_cpu1_l1Icache = sst.Link("link_cpu1_l1Icache_link")
link_cpu1_l1Icache.connect( (instrInterface2, "port", "1ps"), (c1_l1Icache, "high_network_0", "1ps") )
link_cpu1_router = sst.Link("link_cpu1_router")
link_cpu1_router.connect((netInterface2, "rtr_port", "1ps"), (router, "port2", "1ps"))

link_os_l1D_l2bus = sst.Link("link_os_l1D_l2bus_link")
link_os_l1D_l2bus.connect( (os_l1Dcache, "low_network_0", "1ps"), (bus, "high_network_0", "1ps") )
link_os_l1I_l2bus = sst.Link("link_os_l1I_l2bus_link")
link_os_l1I_l2bus.connect( (os_l1Icache, "low_network_0", "1ps"), (bus, "high_network_1", "1ps") )

link_cpu0_l1D_l2bus = sst.Link("link_cpu0_l1D_l2bus_link")
link_cpu0_l1D_l2bus.connect( (c0_l1Dcache, "low_network_0", "1ps"), (bus, "high_network_2", "1ps") )
link_cpu0_l1I_l2bus = sst.Link("link_cpu0_l1I_l2bus_link")
link_cpu0_l1I_l2bus.connect( (c0_l1Icache, "low_network_0", "1ps"), (bus, "high_network_3", "1ps") )

link_cpu1_l1D_l2bus = sst.Link("link_cpu1_l1D_l2bus_link")
link_cpu1_l1D_l2bus.connect( (c1_l1Dcache, "low_network_0", "1ps"), (bus, "high_network_4", "1ps") )
link_cpu1_l1I_l2bus = sst.Link("link_cpu1_l1I_l2bus_link")
link_cpu1_l1I_l2bus.connect( (c1_l1Icache, "low_network_0", "1ps"), (bus, "high_network_5", "1ps") )

link_bus_l2 = sst.Link("link_bus_l2")
link_bus_l2.connect( (bus, "low_network_0", "1ps"), (l2cache, "high_network_0", "1ps") )

link_mem_bus = sst.Link("link_mem_bus_link")
link_mem_bus.connect( (l2cache, "low_network_0", "1ps"), (memory_controller, "direct_link", "1ps") )

# ---------------------------------------------- Links ------------------------------------------------


# ---------------------------------------------- Statistics -------------------------------------------

sst.setStatisticOutput("sst.statoutputcsv")
sst.setStatisticOutputOptions({"filepath": "stats.csv"})
sst.setStatisticLoadLevel(10)
sst.enableAllStatisticsForAllComponents()

# ---------------------------------------------- Statistics -------------------------------------------
