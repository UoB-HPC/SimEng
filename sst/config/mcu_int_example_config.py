import sst
import os

DEBUG_L1 = 1
DEBUG_MEM = 1
DEBUG_LEVEL = 1

clw = "32"

# Assume this is run from SimEng root dir
simeng_path = os.getcwd()
binary_file = simeng_path + "/share/dhrystone_rv32imc/memory.elf" # Apply the appropriate binary
config_file = simeng_path + "/configs/DEMO_RISCV32_mcu_sst.yaml"

# Define the simulation components
cpu = sst.Component("core", "sstsimeng.simengcore")
cpu.addParams({
    "simeng_config_path": config_file,
    "executable_path": binary_file,
    "executable_args": "",
    "clock" : "1GHz",
    "max_addr_memory": 4*1024*1024*1024-1,
    "cache_line_width": clw,
    "source": "",
    "assemble_with_source": False,
    "heap": "",
    "debug": False
})

iface = cpu.setSubComponent("memory", "memHierarchy.standardInterface")

l1cache = sst.Component("l1cache.mesi", "memHierarchy.Cache")
l1cache.addParams({
      "access_latency_cycles" : "1",
      "cache_frequency" : "1Ghz",
      "replacement_policy" : "nmru",
      "coherence_protocol" : "MESI",
      "associativity" : "4",
      "cache_line_size" : clw,
      "debug" : DEBUG_L1,
      "debug_level" : DEBUG_LEVEL,
      "L1" : "1",
      "cache_size" : "32KiB"
})

# Explicitly set the link subcomponents instead of having cache figure them out based on connected port names
l1toC = l1cache.setSubComponent("cpulink", "memHierarchy.MemLink")
l1toM = l1cache.setSubComponent("memlink", "memHierarchy.MemLink")

# Memory controller
memctrl = sst.Component("memory", "memHierarchy.MemController")
memctrl.addParams({
    "clock" : "1GHz",
    "request_width" : clw,
    "debug" : DEBUG_MEM,
    "debug_level" : DEBUG_LEVEL,
    "addr_range_end" : 4*1024*1024*1024-1,
})
Mtol1 = memctrl.setSubComponent("cpulink", "memHierarchy.MemLink")

# Memory model
memory = memctrl.setSubComponent("backend", "memHierarchy.simpleMem")
memory.addParams({
      "access_time" : "10ns",
      "mem_size" : "4GiB",
      "request_width": clw
})

# Define the simulation links
link_cpu_cache_link = sst.Link("link_cpu_cache_link")
link_cpu_cache_link.connect( (iface, "port", "0ps"), (l1toC, "port", "0ps") )
link_mem_bus_link = sst.Link("link_mem_bus_link")
link_mem_bus_link.connect( (l1toM, "port", "0ps"), (Mtol1, "port", "0ps") )

