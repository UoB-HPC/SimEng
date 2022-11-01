import sst
import sys

DEBUG_L1 = 0
DEBUG_MEM = 0
DEBUG_LEVEL = 10

clw = "64"

# Define the simulation components
cpu = sst.Component("core", "sstsimeng.simengcore")
cpu.addParams({
    "simeng_config_path": "<PATH TO SIMENG MODEL CONFIG .YAML FILE>",
    "executable_path": "<PATH TO EXECUTABLE BINARY>",
    "executable_args": "",
    "clock" : "2GHz",
    "max_addr_memory": 2*1024*1024*1024-1,
    "cache_line_width": clw,
    "source": "",
    "assemble_with_source": False,
    "heap": "",
    "debug": False
})

iface = cpu.setSubComponent("memory", "memHierarchy.standardInterface")

l1cache = sst.Component("l1cache.msi", "memHierarchy.Cache")
l1cache.addParams({
    "access_latency_cycles" : "4",
    "cache_frequency" : "2Ghz",
    "replacement_policy" : "lru",
    "coherence_protocol" : "MSI",
    "associativity" : "4",
    "cache_line_size" : clw,
    "cache_size" : "1KiB",
    "L1" : "1",
    "debug" : DEBUG_L1,
    "debug_level" : DEBUG_LEVEL,
    "verbose": "2"
})
l2cache = sst.Component("l2cache.msi.inclus", "memHierarchy.Cache")
l2cache.addParams({
    "access_latency_cycles" : "10",
    "cache_frequency" : "1.8Ghz",
    "replacement_policy" : "lru",
    "coherence_protocol" : "MSI",
    "associativity" : "8",
    "cache_line_size" : clw,
    "cache_size" : "16 KiB",
    "debug_level" : "10",
    "debug": "1"
})
memctrl = sst.Component("memory", "memHierarchy.MemController")
memctrl.addParams({
    "clock" : "1GHz",
    "backend.access_time" : "100 ns",
    "debug" : DEBUG_MEM,
    "debug_level" : DEBUG_LEVEL,
    "addr_range_end" : 2*1024*1024*1024-1,
})
    
memory = memctrl.setSubComponent("backend", "memHierarchy.simpleMem")
memory.addParams({
    "access_time" : "100 ns",
    "mem_size" : "2GiB",
})


# Define the simulation links
link_cpu_l1cache = sst.Link("link_cpu_l1cache_link")
link_cpu_l1cache.connect( (iface, "port", "10ps"), (l1cache, "high_network_0", "10ps") )
link_l1cache_l2cache = sst.Link("link_l1cache_l2cache_link")
link_l1cache_l2cache.connect( (l1cache, "low_network_0", "100ps"), (l2cache, "high_network_0", "100ps") )
link_mem_bus = sst.Link("link_mem_bus_link")
link_mem_bus.connect( (l2cache, "low_network_0", "100ps"), (memctrl, "direct_link", "100ps") )
