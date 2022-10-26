import sst
import sys
import os

DEBUG_L1 = 0
DEBUG_MEM = 0
DEBUG_LEVEL = 10

heap = ""
clw = "8"
if len(sys.argv) > 3:
    heap = sys.argv[3]
if len(sys.argv) > 4:
    clw = sys.argv[4]

cpu = sst.Component("core", "sstsimeng.simengcore")
cpu.addParams({
    "simeng_config_path": os.getcwd() + "/configs/sst-cores/a64fx-sst.yaml",
    "executable_path": "",
    "executable_args": "",
    "clock" : "1.8GHz",
    "max_addr_memory": 2*1024*1024*1024-1,
    "cache_line_width": clw,
    "source": sys.argv[2],
    "assemble_with_source": sys.argv[1] == "src",
    "heap": heap,
    "debug": True
})

iface = cpu.setSubComponent("memory", "memHierarchy.standardInterface")

l1cache = sst.Component("l1cache.mesi", "memHierarchy.Cache")
l1cache.addParams({
      "access_latency_cycles" : "2",
      "cache_frequency" : "1.8Ghz",
      "replacement_policy" : "nmru",
      "coherence_protocol" : "MESI",
      "associativity" : "4",
      "cache_line_size" : clw,
      "debug" : DEBUG_L1,
    "debug_level" : DEBUG_LEVEL,
      "verbose": "2",
      "L1" : "1",
      "cache_size" : "64KiB"
})

# Explicitly set the link subcomponents instead of having cache figure them out based on connected port names
l1toC = l1cache.setSubComponent("cpulink", "memHierarchy.MemLink")
l1toM = l1cache.setSubComponent("memlink", "memHierarchy.MemLink")

# Memory controller
memctrl = sst.Component("memory", "memHierarchy.MemController")
memctrl.addParams({
    "clock" : "1.8GHz",
    "request_width" : "64",
    "debug" : DEBUG_MEM,
    "debug_level" : DEBUG_LEVEL,
    "addr_range_end" : 2*1024*1024*1024-1,
})
Mtol1 = memctrl.setSubComponent("cpulink", "memHierarchy.MemLink")

# Memory model
memory = memctrl.setSubComponent("backend", "memHierarchy.simpleMem")
memory.addParams({
      "access_time" : "0ps",
      "mem_size" : "2GiB",
      "request_width": "64"
})

# Define the simulation links
link_cpu_cache_link = sst.Link("link_cpu_cache_link")
link_cpu_cache_link.connect( (iface, "port", "0ps"), (l1toC, "port", "0ps") )
link_mem_bus_link = sst.Link("link_mem_bus_link")
link_mem_bus_link.connect( (l1toM, "port", "0ps"), (Mtol1, "port", "0ps") )

