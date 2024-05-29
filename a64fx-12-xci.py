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
A64FX_L2_SIZE = "64MiB"
# Set associativity of A64FX L1
A64FX_SA_L1 = 4
# Set associativity of A64FX L2
A64FX_SA_L2 = 16
# Hit latency of A64FX L1 cache (cycles).
A64FX_HL_L1 = 1
# Hit latency of A64FX L2 cache (cycles).
A64FX_HL_L2 = 1
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
A64FX_MEM_ACCESS = "100ns"

# ------------------------------------------- A64FX Properties ---------------------------------------


# ---------------------------------------------- Variables -------------------------------------------

memprops = getMemoryProps(4, "GiB")

# ---------------------------------------------- Variables -------------------------------------------


# --------------------------------------------- SSTSimEng OS ---------------------------------------

simos = sst.Component("simos", "sstsimeng.simos")
simos.addParams({
    "num_cores": 12,
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "executable_path": "/home/br-jjones/hellocOMP",
    "executable_args": "",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
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
        "llsc_block_cycles": 1000,
})
coherence_controller_os_l1D = os_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_os_l1D = os_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_os_l1D = os_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_os_l1D.addParams({"cache_line_size": A64FX_CLW})
os_l1Dcache.setRank(0, 0)

os_l1Icache = sst.Component("os.l1Icache0", "memHierarchy.Cache")
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
        "llsc_block_cycles": 1000,
})
coherence_controller_os_l1I = os_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_os_l1I = os_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_os_l1I = os_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_os_l1I.addParams({"cache_line_size": A64FX_CLW})
os_l1Icache.setRank(0, 0)

# --------------------------------------------- SSTSimEng OS ---------------------------------------


# --------------------------------------------- SSTSimEng Cores --------------------------------------

#Core0
cpu0 = sst.Component("core0", "sstsimeng.simengcore")
cpu0.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
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
cpu0.setRank(1, 0)

c0_l1Dcache = sst.Component("c0.l1Dcache", "memHierarchy.Cache")
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c0_l1D = c0_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c0_l1D = c0_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c0_l1D = c0_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c0_l1D.addParams({"cache_line_size": A64FX_CLW})
c0_l1Dcache.setRank(1, 0)

c0_l1Icache = sst.Component("c0.l1Icache", "memHierarchy.Cache")
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c0_l1I = c0_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c0_l1I = c0_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c0_l1I = c0_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c0_l1I.addParams({"cache_line_size": A64FX_CLW})
c0_l1Icache.setRank(1, 0)

#Core1
cpu1 = sst.Component("core1", "sstsimeng.simengcore")
cpu1.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c1_dataInterface = cpu1.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c1_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c1_instrInterface = cpu1.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c1_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu1.setRank(2, 0)

c1_l1Dcache = sst.Component("c1.l1Dcache", "memHierarchy.Cache")
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c1_l1D = c1_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c1_l1D = c1_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c1_l1D = c1_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c1_l1D.addParams({"cache_line_size": A64FX_CLW})
c1_l1Dcache.setRank(2, 0)

c1_l1Icache = sst.Component("c1.l1Icache", "memHierarchy.Cache")
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c1_l1I = c1_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c1_l1I = c1_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c1_l1I = c1_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c1_l1I.addParams({"cache_line_size": A64FX_CLW})
c1_l1Icache.setRank(2, 0)

#Core2
cpu2 = sst.Component("core2", "sstsimeng.simengcore")
cpu2.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c2_dataInterface = cpu2.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c2_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c2_instrInterface = cpu2.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c2_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu2.setRank(3, 0)

c2_l1Dcache = sst.Component("c2.l1Dcache", "memHierarchy.Cache")
c2_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c2_l1D = c2_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c2_l1D = c2_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c2_l1D = c2_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c2_l1D.addParams({"cache_line_size": A64FX_CLW})
c2_l1Dcache.setRank(3, 0)

c2_l1Icache = sst.Component("c2.l1Icache", "memHierarchy.Cache")
c2_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c2_l1I = c2_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c2_l1I = c2_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c2_l1I = c2_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c2_l1I.addParams({"cache_line_size": A64FX_CLW})
c2_l1Icache.setRank(3, 0)

#Core3
cpu3 = sst.Component("core3", "sstsimeng.simengcore")
cpu3.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c3_dataInterface = cpu3.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c3_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c3_instrInterface = cpu3.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c3_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu3.setRank(4, 0)

c3_l1Dcache = sst.Component("c3.l1Dcache", "memHierarchy.Cache")
c3_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c3_l1D = c3_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c3_l1D = c3_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c3_l1D = c3_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c3_l1D.addParams({"cache_line_size": A64FX_CLW})
c3_l1Dcache.setRank(4, 0)

c3_l1Icache = sst.Component("c3.l1Icache", "memHierarchy.Cache")
c3_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c3_l1I = c3_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c3_l1I = c3_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c3_l1I = c3_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c3_l1I.addParams({"cache_line_size": A64FX_CLW})
c3_l1Icache.setRank(4, 0)

#Core4
cpu4 = sst.Component("core4", "sstsimeng.simengcore")
cpu4.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c4_dataInterface = cpu4.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c4_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c4_instrInterface = cpu4.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c4_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu4.setRank(5, 0)

c4_l1Dcache = sst.Component("c4.l1Dcache", "memHierarchy.Cache")
c4_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c4_l1D = c4_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c4_l1D = c4_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c4_l1D = c4_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c4_l1D.addParams({"cache_line_size": A64FX_CLW})
c4_l1Dcache.setRank(5, 0)

c4_l1Icache = sst.Component("c4.l1Icache", "memHierarchy.Cache")
c4_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c4_l1I = c4_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c4_l1I = c4_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c4_l1I = c4_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c4_l1I.addParams({"cache_line_size": A64FX_CLW})
c4_l1Icache.setRank(5, 0)

#Core5
cpu5 = sst.Component("core5", "sstsimeng.simengcore")
cpu5.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c5_dataInterface = cpu5.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c5_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c5_instrInterface = cpu5.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c5_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu5.setRank(6, 0)

c5_l1Dcache = sst.Component("c5.l1Dcache", "memHierarchy.Cache")
c5_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c5_l1D = c5_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c5_l1D = c5_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c5_l1D = c5_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c5_l1D.addParams({"cache_line_size": A64FX_CLW})
c5_l1Dcache.setRank(6, 0)

c5_l1Icache = sst.Component("c5.l1Icache", "memHierarchy.Cache")
c5_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c5_l1I = c5_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c5_l1I = c5_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c5_l1I = c5_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c5_l1I.addParams({"cache_line_size": A64FX_CLW})
c5_l1Icache.setRank(6, 0)

#Core6
cpu6 = sst.Component("core6", "sstsimeng.simengcore")
cpu6.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c6_dataInterface = cpu6.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c6_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c6_instrInterface = cpu6.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c6_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu6.setRank(7, 0)

c6_l1Dcache = sst.Component("c6.l1Dcache", "memHierarchy.Cache")
c6_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c6_l1D = c6_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c6_l1D = c6_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c6_l1D = c6_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c6_l1D.addParams({"cache_line_size": A64FX_CLW})
c6_l1Dcache.setRank(7, 0)

c6_l1Icache = sst.Component("c6.l1Icache", "memHierarchy.Cache")
c6_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c6_l1I = c6_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c6_l1I = c6_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c6_l1I = c6_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c6_l1I.addParams({"cache_line_size": A64FX_CLW})
c6_l1Icache.setRank(7, 0)

#Core7
cpu7 = sst.Component("core7", "sstsimeng.simengcore")
cpu7.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c7_dataInterface = cpu7.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c7_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c7_instrInterface = cpu7.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c7_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu7.setRank(8, 0)

c7_l1Dcache = sst.Component("c7.l1Dcache", "memHierarchy.Cache")
c7_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c7_l1D = c7_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c7_l1D = c7_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c7_l1D = c7_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c7_l1D.addParams({"cache_line_size": A64FX_CLW})
c7_l1Dcache.setRank(8, 0)

c7_l1Icache = sst.Component("c7.l1Icache", "memHierarchy.Cache")
c7_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c7_l1I = c7_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c7_l1I = c7_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c7_l1I = c7_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c7_l1I.addParams({"cache_line_size": A64FX_CLW})
c7_l1Icache.setRank(8, 0)

#Core8
cpu8 = sst.Component("core8", "sstsimeng.simengcore")
cpu8.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c8_dataInterface = cpu8.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c8_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c8_instrInterface = cpu8.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c8_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu8.setRank(9, 0)

c8_l1Dcache = sst.Component("c8.l1Dcache", "memHierarchy.Cache")
c8_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c8_l1D = c8_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c8_l1D = c8_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c8_l1D = c8_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c8_l1D.addParams({"cache_line_size": A64FX_CLW})
c8_l1Dcache.setRank(9, 0)

c8_l1Icache = sst.Component("c8.l1Icache", "memHierarchy.Cache")
c8_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c8_l1I = c8_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c8_l1I = c8_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c8_l1I = c8_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c8_l1I.addParams({"cache_line_size": A64FX_CLW})
c8_l1Icache.setRank(9, 0)

#Core9
cpu9 = sst.Component("core9", "sstsimeng.simengcore")
cpu9.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c9_dataInterface = cpu9.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c9_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c9_instrInterface = cpu9.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c9_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu9.setRank(10, 0)

c9_l1Dcache = sst.Component("c9.l1Dcache", "memHierarchy.Cache")
c9_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c9_l1D = c9_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c9_l1D = c9_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c9_l1D = c9_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c9_l1D.addParams({"cache_line_size": A64FX_CLW})
c9_l1Dcache.setRank(10, 0)

c9_l1Icache = sst.Component("c9.l1Icache", "memHierarchy.Cache")
c9_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c9_l1I = c9_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c9_l1I = c9_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c9_l1I = c9_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c9_l1I.addParams({"cache_line_size": A64FX_CLW})
c9_l1Icache.setRank(10, 0)

#Core10
cpu10 = sst.Component("core10", "sstsimeng.simengcore")
cpu10.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c10_dataInterface = cpu10.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c10_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c10_instrInterface = cpu10.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c10_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu10.setRank(11, 0)

c10_l1Dcache = sst.Component("c10.l1Dcache", "memHierarchy.Cache")
c10_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c10_l1D = c10_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c10_l1D = c10_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c10_l1D = c10_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c10_l1D.addParams({"cache_line_size": A64FX_CLW})
c10_l1Dcache.setRank(11, 0)

c10_l1Icache = sst.Component("c10.l1Icache", "memHierarchy.Cache")
c10_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c10_l1I = c10_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c10_l1I = c10_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c10_l1I = c10_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c10_l1I.addParams({"cache_line_size": A64FX_CLW})
c10_l1Icache.setRank(11, 0)

#Core11
cpu11 = sst.Component("core11", "sstsimeng.simengcore")
cpu11.addParams({
    "simeng_config_path": "/home/br-jjones/simulation/SimEng/a64fx-12-xci.yaml",
    "clock" : A64FX_CLOCK,
    "max_addr_memory": memprops["end_addr"],
    "cache_line_width": A64FX_CLW,
    "debug": False,
})
c11_dataInterface = cpu11.setSubComponent("dataMemory", "memHierarchy.standardInterface")
c11_dataInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
c11_instrInterface = cpu11.setSubComponent("instrMemory", "memHierarchy.standardInterface")
c11_instrInterface.addParams({
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "verbose": 2
})
cpu11.setRank(12, 0)

c11_l1Dcache = sst.Component("c11.l1Dcache", "memHierarchy.Cache")
c11_l1Dcache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c11_l1D = c11_l1Dcache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c11_l1D = c11_l1Dcache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c11_l1D = c11_l1Dcache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c11_l1D.addParams({"cache_line_size": A64FX_CLW})
c11_l1Dcache.setRank(12, 0)

c11_l1Icache = sst.Component("c11.l1Icache", "memHierarchy.Cache")
c11_l1Icache.addParams({
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
        "llsc_block_cycles": 1000,
})
coherence_controller_c11_l1I = c11_l1Icache.setSubComponent("coherence", "memHierarchy.coherence.mesi_l1")
replacement_policy_c11_l1I = c11_l1Icache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_c11_l1I = c11_l1Icache.setSubComponent("prefetcher", "cassini.NextBlockPrefetcher")
prefetcher_c11_l1I.addParams({"cache_line_size": A64FX_CLW})
c11_l1Icache.setRank(12, 0)

# --------------------------------------------- SSTSimEng Cores --------------------------------------


# -------------------------------------------- L1-L2 BUSES --------------------------------------------

bus_0_l1_l2 = sst.Component("bus_0_l1_l2", "memHierarchy.Bus")
bus_0_l1_l2.addParams({
      "bus_frequency" : A64FX_CLOCK,
})
bus_0_l1_l2.setRank(0, 0)

# -------------------------------------------- L1-L2 BUSES --------------------------------------------


# --------------------------------------------- L2 Cache ---------------------------------------------

# Using sst-info memHierarchy.Cache to get all cache parameters, ports and subcomponent slots.
l2cache_0 = sst.Component("core.l2cache0", "memHierarchy.Cache")
l2cache_0.addParams({
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
        "llsc_block_cycles": 1000,
})
# Set MESI L2 coherence controller to the "coherence" slot
coherence_controller_l2_0 = l2cache_0.setSubComponent("coherence", "memHierarchy.coherence.mesi_inclusive")
# Set LRU replacement policy to the "replacement" slot.
# index=0 indicates replacement policy is for cache.
replacement_policy_l2_0 = l2cache_0.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_l2cache_0 = l2cache_0.setSubComponent("prefetcher", "cassini.StridePrefetcher")
prefetcher_l2cache_0.addParams({
    "cache_line_size": A64FX_CLW,                 #Size of the cache line the prefetcher is attached to
    "history": 16,                                #Number of entries to keep for historical comparison
    "reach": 2,                                   #Reach (how far forward the prefetcher should fetch lines)
    "detect_range": 4,                            #Range to detect addresses over in request counts
    "address_count": 64,                          #Number of addresses to keep in prefetch table
    "page_size": 4096,                            #Page size for this controller
    "overrun_page_boundaries": 0,                 #Allow prefetcher to run over page boundaries, 0 is no, 1 is yes
})
l2cache_0.setRank(0, 0)

# --------------------------------------------- L2 Cache ---------------------------------------------


# -------------------------------------------- L2-MEM BUS ----------------------------------------------

bus_l2_mem = sst.Component("bus_l2_mem", "memHierarchy.Bus")
bus_l2_mem.addParams({
      "bus_frequency" : A64FX_CLOCK,
})
bus_l2_mem.setRank(0, 0)

# -------------------------------------------- L2-MEM BUS ----------------------------------------------


# -------------------------------------------- L3 CACHE ----------------------------------------------


l3cache = sst.Component("core.l3cache", "memHierarchy.Cache")
l3cache.addParams({
        "L1": 0,
        "cache_type": A64FX_CACHE_TYPE,
        "access_latency_cycles": A64FX_HL_L2,
        "cache_frequency": A64FX_CLOCK,
        "associativity": A64FX_SA_L2,
        "cache_line_size": A64FX_CLW,
        "cache_size": "64MiB",
        "debug": DEBUG_L2,
        "debug_level": DEBUG_LEVEL,
        "coherence_protocol": A64FX_COHP,
        "request_link_width": A64FX_L2TOMEM_PCMG_TPUT,
        "response_link_width": A64FX_L2TOL1_PC_TPUT,
        "mshr_latency_cycles": 1,
        "tag_access_latency": 37,
        "llsc_block_cycles": 1000,
})
coherence_controller_l3= l3cache.setSubComponent("coherence", "memHierarchy.coherence.mesi_inclusive")
replacement_policy_l3 = l3cache.setSubComponent("replacement", "memHierarchy.replacement.lru", 0)
prefetcher_l3cache = l3cache.setSubComponent("prefetcher", "cassini.StridePrefetcher")
prefetcher_l3cache.addParams({
    "cache_line_size": A64FX_CLW,                 #Size of the cache line the prefetcher is attached to
    "history": 16,                                #Number of entries to keep for historical comparison
    "reach": 2,                                   #Reach (how far forward the prefetcher should fetch lines)
    "detect_range": 4,                            #Range to detect addresses over in request counts
    "address_count": 64,                          #Number of addresses to keep in prefetch table
    "page_size": 4096,                            #Page size for this controller
    "overrun_page_boundaries": 0,                 #Allow prefetcher to run over page boundaries, 0 is no, 1 is yes
})
l3cache.setRank(0, 0)

# -------------------------------------------- L3 CACHE ----------------------------------------------


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

c1_noc = cpu1.setSubComponent("noc", "sstsimeng.SimEngNOC")
c1_noc.addParams(verb_params)
c1_netInterface = c1_noc.setSubComponent("interface", "merlin.linkcontrol")
c1_netInterface.addParams(net_params)

c2_noc = cpu2.setSubComponent("noc", "sstsimeng.SimEngNOC")
c2_noc.addParams(verb_params)
c2_netInterface = c2_noc.setSubComponent("interface", "merlin.linkcontrol")
c2_netInterface.addParams(net_params)

c3_noc = cpu3.setSubComponent("noc", "sstsimeng.SimEngNOC")
c3_noc.addParams(verb_params)
c3_netInterface = c3_noc.setSubComponent("interface", "merlin.linkcontrol")
c3_netInterface.addParams(net_params)

c4_noc = cpu4.setSubComponent("noc", "sstsimeng.SimEngNOC")
c4_noc.addParams(verb_params)
c4_netInterface = c4_noc.setSubComponent("interface", "merlin.linkcontrol")
c4_netInterface.addParams(net_params)

c5_noc = cpu5.setSubComponent("noc", "sstsimeng.SimEngNOC")
c5_noc.addParams(verb_params)
c5_netInterface = c5_noc.setSubComponent("interface", "merlin.linkcontrol")
c5_netInterface.addParams(net_params)

c6_noc = cpu6.setSubComponent("noc", "sstsimeng.SimEngNOC")
c6_noc.addParams(verb_params)
c6_netInterface = c6_noc.setSubComponent("interface", "merlin.linkcontrol")
c6_netInterface.addParams(net_params)

c7_noc = cpu7.setSubComponent("noc", "sstsimeng.SimEngNOC")
c7_noc.addParams(verb_params)
c7_netInterface = c7_noc.setSubComponent("interface", "merlin.linkcontrol")
c7_netInterface.addParams(net_params)

c8_noc = cpu8.setSubComponent("noc", "sstsimeng.SimEngNOC")
c8_noc.addParams(verb_params)
c8_netInterface = c8_noc.setSubComponent("interface", "merlin.linkcontrol")
c8_netInterface.addParams(net_params)

c9_noc = cpu9.setSubComponent("noc", "sstsimeng.SimEngNOC")
c9_noc.addParams(verb_params)
c9_netInterface = c9_noc.setSubComponent("interface", "merlin.linkcontrol")
c9_netInterface.addParams(net_params)

c10_noc = cpu10.setSubComponent("noc", "sstsimeng.SimEngNOC")
c10_noc.addParams(verb_params)
c10_netInterface = c10_noc.setSubComponent("interface", "merlin.linkcontrol")
c10_netInterface.addParams(net_params)

c11_noc = cpu11.setSubComponent("noc", "sstsimeng.SimEngNOC")
c11_noc.addParams(verb_params)
c11_netInterface = c11_noc.setSubComponent("interface", "merlin.linkcontrol")
c11_netInterface.addParams(net_params)

router = sst.Component("router", "merlin.hr_router")
router.setSubComponent("topology", "merlin.singlerouter")
router.addParams(net_params)
router.addParams({
    "xbar_bw" : "1GB/s",
    "flit_size" : "32B",
    "num_ports" : "13",
    "id" : 0
})
router.setRank(0, 0)

# ---------------------------------------------- NETWORK ----------------------------------------------


# ---------------------------------------------- Links ------------------------------------------------

link_os_l1Dcache = sst.Link("link_os_l1Dcache_link")
link_os_l1Dcache.connect( (os_dataInterface, "port", "100ns"), (os_l1Dcache, "high_network_0", "100ns") )
link_os_l1Icache = sst.Link("link_os_l1Icache_link")
link_os_l1Icache.connect( (os_instrInterface, "port", "100ns"), (os_l1Icache, "high_network_0", "100ns") )
link_os_router = sst.Link("link_os_router")
link_os_router.connect((os_netInterface, "rtr_port", "100ns"), (router, "port0", "100ns"))

link_os_l1D_l2bus = sst.Link("link_os_l1D_l2bus_link")
link_os_l1D_l2bus.connect( (os_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_0", "100ns") )
link_os_l1I_l2bus = sst.Link("link_os_l1I_l2bus_link")
link_os_l1I_l2bus.connect( (os_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_1", "100ns") )


link_c0_l1Dcache = sst.Link("link_c0_l1Dcache_link")
link_c0_l1Dcache.connect( (c0_dataInterface, "port", "100ns"), (c0_l1Dcache, "high_network_0", "100ns") )
link_c0_l1Icache = sst.Link("link_c0_l1Icache_link")
link_c0_l1Icache.connect( (c0_instrInterface, "port", "100ns"), (c0_l1Icache, "high_network_0", "100ns") )
link_c0_router = sst.Link("link_c0_router")
link_c0_router.connect((c0_netInterface, "rtr_port", "100ns"), (router, "port1", "100ns"))

link_c0_l1D_l2bus = sst.Link("link_c0_l1D_l2bus_link")
link_c0_l1D_l2bus.connect( (c0_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_2", "100ns") )
link_c0_l1I_l2bus = sst.Link("link_c0_l1I_l2bus_link")
link_c0_l1I_l2bus.connect( (c0_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_3", "100ns") )


link_c1_l1Dcache = sst.Link("link_c1_l1Dcache_link")
link_c1_l1Dcache.connect( (c1_dataInterface, "port", "100ns"), (c1_l1Dcache, "high_network_0", "100ns") )
link_c1_l1Icache = sst.Link("link_c1_l1Icache_link")
link_c1_l1Icache.connect( (c1_instrInterface, "port", "100ns"), (c1_l1Icache, "high_network_0", "100ns") )
link_c1_router = sst.Link("link_c1_router")
link_c1_router.connect((c1_netInterface, "rtr_port", "100ns"), (router, "port2", "100ns"))

link_c1_l1D_l2bus = sst.Link("link_c1_l1D_l2bus_link")
link_c1_l1D_l2bus.connect( (c1_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_4", "100ns") )
link_c1_l1I_l2bus = sst.Link("link_c1_l1I_l2bus_link")
link_c1_l1I_l2bus.connect( (c1_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_5", "100ns") )


link_c2_l1Dcache = sst.Link("link_c2_l1Dcache_link")
link_c2_l1Dcache.connect( (c2_dataInterface, "port", "100ns"), (c2_l1Dcache, "high_network_0", "100ns") )
link_c2_l1Icache = sst.Link("link_c2_l1Icache_link")
link_c2_l1Icache.connect( (c2_instrInterface, "port", "100ns"), (c2_l1Icache, "high_network_0", "100ns") )
link_c2_router = sst.Link("link_c2_router")
link_c2_router.connect((c2_netInterface, "rtr_port", "100ns"), (router, "port3", "100ns"))

link_c2_l1D_l2bus = sst.Link("link_c2_l1D_l2bus_link")
link_c2_l1D_l2bus.connect( (c2_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_6", "100ns") )
link_c2_l1I_l2bus = sst.Link("link_c2_l1I_l2bus_link")
link_c2_l1I_l2bus.connect( (c2_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_7", "100ns") )


link_c3_l1Dcache = sst.Link("link_c3_l1Dcache_link")
link_c3_l1Dcache.connect( (c3_dataInterface, "port", "100ns"), (c3_l1Dcache, "high_network_0", "100ns") )
link_c3_l1Icache = sst.Link("link_c3_l1Icache_link")
link_c3_l1Icache.connect( (c3_instrInterface, "port", "100ns"), (c3_l1Icache, "high_network_0", "100ns") )
link_c3_router = sst.Link("link_c3_router")
link_c3_router.connect((c3_netInterface, "rtr_port", "100ns"), (router, "port4", "100ns"))

link_c3_l1D_l2bus = sst.Link("link_c3_l1D_l2bus_link")
link_c3_l1D_l2bus.connect( (c3_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_8", "100ns") )
link_c3_l1I_l2bus = sst.Link("link_c3_l1I_l2bus_link")
link_c3_l1I_l2bus.connect( (c3_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_9", "100ns") )


link_c4_l1Dcache = sst.Link("link_c4_l1Dcache_link")
link_c4_l1Dcache.connect( (c4_dataInterface, "port", "100ns"), (c4_l1Dcache, "high_network_0", "100ns") )
link_c4_l1Icache = sst.Link("link_c4_l1Icache_link")
link_c4_l1Icache.connect( (c4_instrInterface, "port", "100ns"), (c4_l1Icache, "high_network_0", "100ns") )
link_c4_router = sst.Link("link_c4_router")
link_c4_router.connect((c4_netInterface, "rtr_port", "100ns"), (router, "port5", "100ns"))

link_c4_l1D_l2bus = sst.Link("link_c4_l1D_l2bus_link")
link_c4_l1D_l2bus.connect( (c4_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_10", "100ns") )
link_c4_l1I_l2bus = sst.Link("link_c4_l1I_l2bus_link")
link_c4_l1I_l2bus.connect( (c4_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_11", "100ns") )


link_c5_l1Dcache = sst.Link("link_c5_l1Dcache_link")
link_c5_l1Dcache.connect( (c5_dataInterface, "port", "100ns"), (c5_l1Dcache, "high_network_0", "100ns") )
link_c5_l1Icache = sst.Link("link_c5_l1Icache_link")
link_c5_l1Icache.connect( (c5_instrInterface, "port", "100ns"), (c5_l1Icache, "high_network_0", "100ns") )
link_c5_router = sst.Link("link_c5_router")
link_c5_router.connect((c5_netInterface, "rtr_port", "100ns"), (router, "port6", "100ns"))

link_c5_l1D_l2bus = sst.Link("link_c5_l1D_l2bus_link")
link_c5_l1D_l2bus.connect( (c5_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_12", "100ns") )
link_c5_l1I_l2bus = sst.Link("link_c5_l1I_l2bus_link")
link_c5_l1I_l2bus.connect( (c5_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_13", "100ns") )


link_c6_l1Dcache = sst.Link("link_c6_l1Dcache_link")
link_c6_l1Dcache.connect( (c6_dataInterface, "port", "100ns"), (c6_l1Dcache, "high_network_0", "100ns") )
link_c6_l1Icache = sst.Link("link_c6_l1Icache_link")
link_c6_l1Icache.connect( (c6_instrInterface, "port", "100ns"), (c6_l1Icache, "high_network_0", "100ns") )
link_c6_router = sst.Link("link_c6_router")
link_c6_router.connect((c6_netInterface, "rtr_port", "100ns"), (router, "port7", "100ns"))

link_c6_l1D_l2bus = sst.Link("link_c6_l1D_l2bus_link")
link_c6_l1D_l2bus.connect( (c6_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_14", "100ns") )
link_c6_l1I_l2bus = sst.Link("link_c6_l1I_l2bus_link")
link_c6_l1I_l2bus.connect( (c6_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_15", "100ns") )


link_c7_l1Dcache = sst.Link("link_c7_l1Dcache_link")
link_c7_l1Dcache.connect( (c7_dataInterface, "port", "100ns"), (c7_l1Dcache, "high_network_0", "100ns") )
link_c7_l1Icache = sst.Link("link_c7_l1Icache_link")
link_c7_l1Icache.connect( (c7_instrInterface, "port", "100ns"), (c7_l1Icache, "high_network_0", "100ns") )
link_c7_router = sst.Link("link_c7_router")
link_c7_router.connect((c7_netInterface, "rtr_port", "100ns"), (router, "port8", "100ns"))

link_c7_l1D_l2bus = sst.Link("link_c7_l1D_l2bus_link")
link_c7_l1D_l2bus.connect( (c7_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_16", "100ns") )
link_c7_l1I_l2bus = sst.Link("link_c7_l1I_l2bus_link")
link_c7_l1I_l2bus.connect( (c7_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_17", "100ns") )


link_c8_l1Dcache = sst.Link("link_c8_l1Dcache_link")
link_c8_l1Dcache.connect( (c8_dataInterface, "port", "100ns"), (c8_l1Dcache, "high_network_0", "100ns") )
link_c8_l1Icache = sst.Link("link_c8_l1Icache_link")
link_c8_l1Icache.connect( (c8_instrInterface, "port", "100ns"), (c8_l1Icache, "high_network_0", "100ns") )
link_c8_router = sst.Link("link_c8_router")
link_c8_router.connect((c8_netInterface, "rtr_port", "100ns"), (router, "port9", "100ns"))

link_c8_l1D_l2bus = sst.Link("link_c8_l1D_l2bus_link")
link_c8_l1D_l2bus.connect( (c8_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_18", "100ns") )
link_c8_l1I_l2bus = sst.Link("link_c8_l1I_l2bus_link")
link_c8_l1I_l2bus.connect( (c8_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_19", "100ns") )


link_c9_l1Dcache = sst.Link("link_c9_l1Dcache_link")
link_c9_l1Dcache.connect( (c9_dataInterface, "port", "100ns"), (c9_l1Dcache, "high_network_0", "100ns") )
link_c9_l1Icache = sst.Link("link_c9_l1Icache_link")
link_c9_l1Icache.connect( (c9_instrInterface, "port", "100ns"), (c9_l1Icache, "high_network_0", "100ns") )
link_c9_router = sst.Link("link_c9_router")
link_c9_router.connect((c9_netInterface, "rtr_port", "100ns"), (router, "port10", "100ns"))

link_c9_l1D_l2bus = sst.Link("link_c9_l1D_l2bus_link")
link_c9_l1D_l2bus.connect( (c9_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_20", "100ns") )
link_c9_l1I_l2bus = sst.Link("link_c9_l1I_l2bus_link")
link_c9_l1I_l2bus.connect( (c9_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_21", "100ns") )


link_c10_l1Dcache = sst.Link("link_c10_l1Dcache_link")
link_c10_l1Dcache.connect( (c10_dataInterface, "port", "100ns"), (c10_l1Dcache, "high_network_0", "100ns") )
link_c10_l1Icache = sst.Link("link_c10_l1Icache_link")
link_c10_l1Icache.connect( (c10_instrInterface, "port", "100ns"), (c10_l1Icache, "high_network_0", "100ns") )
link_c10_router = sst.Link("link_c10_router")
link_c10_router.connect((c10_netInterface, "rtr_port", "100ns"), (router, "port11", "100ns"))

link_c10_l1D_l2bus = sst.Link("link_c10_l1D_l2bus_link")
link_c10_l1D_l2bus.connect( (c10_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_22", "100ns") )
link_c10_l1I_l2bus = sst.Link("link_c10_l1I_l2bus_link")
link_c10_l1I_l2bus.connect( (c10_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_23", "100ns") )


link_c11_l1Dcache = sst.Link("link_c11_l1Dcache_link")
link_c11_l1Dcache.connect( (c11_dataInterface, "port", "100ns"), (c11_l1Dcache, "high_network_0", "100ns") )
link_c11_l1Icache = sst.Link("link_c11_l1Icache_link")
link_c11_l1Icache.connect( (c11_instrInterface, "port", "100ns"), (c11_l1Icache, "high_network_0", "100ns") )
link_c11_router = sst.Link("link_c11_router")
link_c11_router.connect((c11_netInterface, "rtr_port", "100ns"), (router, "port12", "100ns"))

link_c11_l1D_l2bus = sst.Link("link_c11_l1D_l2bus_link")
link_c11_l1D_l2bus.connect( (c11_l1Dcache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_24", "100ns") )
link_c11_l1I_l2bus = sst.Link("link_c11_l1I_l2bus_link")
link_c11_l1I_l2bus.connect( (c11_l1Icache, "low_network_0", "100ns"), (bus_0_l1_l2, "high_network_25", "100ns") )


link_bus_0_l2 = sst.Link("link_bus_0_l2_link")
link_bus_0_l2.connect( (bus_0_l1_l2, "low_network_0", "100ns"), (l2cache_0, "high_network_0", "100ns") )


link_l2_0_mem_bus = sst.Link("link_l2_0_mem_bus_link")
link_l2_0_mem_bus.connect( (l2cache_0, "low_network_0", "100ns"), (bus_l2_mem, "high_network_0", "100ns") )


link_bus_l3 = sst.Link("link_bus_l3_link")
link_bus_l3.connect( (bus_l2_mem, "low_network_0", "100ns"), (l3cache, "high_network_0", "100ns") )


link_l3_mem = sst.Link("link_l3_mem_link")
link_l3_mem.connect( (l3cache, "low_network_0", "100ns"), (memory_controller, "direct_link", "100ns") )

# ---------------------------------------------- Links ------------------------------------------------



# ------------------------------------------- Statistics ---------------------------------------------

sst.setStatisticOutput("sst.statOutputCSV", {"filepath":"stats.csv", "separator":","})
sst.setStatisticLoadLevel(10)
sst.enableStatisticsForComponentType("memHierarchy.Cache",["CacheHits", "CacheMisses", "prefetches_issued"], {}, True)
sst.enableAllStatisticsForComponentType("sstsimeng.simengcore", {}, True)

# ------------------------------------------- Statistics ---------------------------------------------


