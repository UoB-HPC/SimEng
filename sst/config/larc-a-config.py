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



# ------------------------------------------- LARC Properties ---------------------------------------

# This SST configuration file represents the memory model for the Fujitsu A64fx processor.
# Reference: https://github.com/fujitsu/LARC/blob/master/doc/LARC_Microarchitecture_Manual_en_1.8.pdf

# Cache line size of L1 & L2 in LARC in bytes.
LARC_CLW = 256
# Clock Frequency of LARC.
LARC_CLOCK = "2.2GHz"
# Size of L1 cache in Larc.
LARC_L1_SIZE = "64KiB"
# Size of L2 cache in Larc.
LARC_L2_SIZE = "512MiB"
# Set associativity of LARC L1
LARC_SA_L1 = 4
# Set associativity of LARC L2
LARC_SA_L2 = 16
# Hit latency of LARC L1 cache (cycles).
LARC_HL_L1 = 3
# Hit latency of LARC L2 cache (cycles).
LARC_HL_L2 = 37
# Cohenrence protocol of LARC caches.
LARC_COHP = "MESI"
# L1 & L2 cache type of LARC.
LARC_CACHE_TYPE = "inclusive"
# Throughput of L1 to L2 per core in LARC. (bytes per cycle)
LARC_L1TOL2_PC_TPUT = "32B"
# Throughput of L1 to CPU per core in LARC. Value of 0 indicates infinity. (bytes per cycle)
LARC_L1TOCPU_PC_TPUT = "128B"
# Throughput of L2 to Memory per CMG in LARC. (bytes per cycle)
LARC_L2TOMEM_PCMG_TPUT = "64B"
# Throughput of L2 to L1 per core in LARC. (bytes per cycle)
LARC_L2TOL1_PC_TPUT = "64B"
# Throughput of Memory to L2 per CMG in LARC. (bytes per cycle)
LARC_MEMTOL2_PCMG_TPUT = 128
# LARC Memory access time.
LARC_MEM_ACCESS = "144.5ns"

# ------------------------------------------- LARC Properties ---------------------------------------


# ---------------------------------------------- Variables -------------------------------------------

memprops = getMemoryProps(8, "GiB")

# ---------------------------------------------- Variables -------------------------------------------


# --------------------------------------------- SSTSimEng Core ---------------------------------------

# Using sst-info sstsimeng.simengcore to get all cache parameters, ports and subcomponent slots.
cpu = sst.Component("core", "sstsimeng.simengcore")
cpu.addParams({
    "simeng_config_path": "<PATH TO LARC SIMENG MODEL CONFIG>",
    "executable_path": "<PATH TO EXECUTABLE BINARY>",
    "executable_args": "",
    "clock" : LARC_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": LARC_CLW,
})

# Instantiating the StandardInterface which communicates with the SST memory model.
interface = cpu.setSubComponent("memory", "memHierarchy.standardInterface")

# --------------------------------------------- SSTSimEng Core ---------------------------------------


# --------------------------------------------- L1 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l1cache = sst.Component("larc.l1cache", "memHierarchy.Cache")
l1cache.addParams({
      "L1" : 1,
      "cache_type": LARC_CACHE_TYPE,
      "access_latency_cycles" : LARC_HL_L1,
      "cache_frequency" : LARC_CLOCK,
      "associativity" : LARC_SA_L1,
      "cache_line_size" : LARC_CLW,
      "cache_size" : LARC_L1_SIZE,
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "coherence_protocol": LARC_COHP,
      "request_link_width": LARC_L1TOL2_PC_TPUT,
      "response_link_width": LARC_L1TOCPU_PC_TPUT
})
# Set MESI L1 coherence controller to the "coherence" slot
coherence_controller_l1 = l1cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy_l1 = l1cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

# --------------------------------------------- L1 Cache ---------------------------------------------


# --------------------------------------------- L2 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l2cache = sst.Component("larc.l2cache", "memHierarchy.Cache")
l2cache.addParams({
      "L1" : 0,
      "cache_type": LARC_CACHE_TYPE,
      "access_latency_cycles" : LARC_HL_L2,
      "cache_frequency" : LARC_CLOCK,
      "associativity" : LARC_SA_L2,
      "cache_line_size" : LARC_CLW,
      "cache_size" : LARC_L2_SIZE,
      "debug" : DEBUG_L2,
      "debug_level" : DEBUG_LEVEL,
      "coherence_protocol": LARC_COHP,
      "request_link_width": LARC_L2TOMEM_PCMG_TPUT,
      "response_link_width": LARC_L2TOL1_PC_TPUT,
})
# Set MESI L2 coherence controller to the "coherence" slot
coherence_controller_l2 = l2cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_inclusive")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy_l2 = l2cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)

# --------------------------------------------- L2 Cache ---------------------------------------------


# ----------------------------------- Memory Backend & Controller -------------------------------------

memory_controller = sst.Component("larc.memorycontroller", "memHierarchy.MemController")
memory_controller.addParams({
      "clock": LARC_CLOCK,
      "backend.access_time": LARC_MEM_ACCESS,
      "request_width": LARC_MEMTOL2_PCMG_TPUT,
      "debug": DEBUG_MEM,
      "debug_level": DEBUG_LEVEL,
      "addr_range_start": memprops["start_addr"],
      "addr_range_end": memprops["end_addr"]
})

memory_backend = memory_controller.setSubComponent("backend", "memHierarchy.simpleMem")
memory_backend.addParams({
      "access_time": LARC_MEM_ACCESS,
      "mem_size": memprops["size"],
      "request_width": 128,
})

# ----------------------------------- Memory Backend & Controller -------------------------------------


# ---------------------------------------------- Links ------------------------------------------------

link_cpu_l1cache = sst.Link("link_cpu_l1cache_link")
link_cpu_l1cache.connect( (interface, "port", "50ps"), (l1cache, "high_network_0", "50ps") )
link_l1cache_l2cache = sst.Link("link_l1cache_l2cache_link")
link_l1cache_l2cache.connect( (l1cache, "low_network_0", "50ps"), (l2cache, "high_network_0", "50ps") )
link_mem_bus = sst.Link("link_mem_bus_link")
link_mem_bus.connect( (l2cache, "low_network_0", "300ps"), (memory_controller, "direct_link", "300ps") )

# ---------------------------------------------- Links ------------------------------------------------
