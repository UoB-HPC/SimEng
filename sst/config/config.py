import sst

cpu = sst.Component("my-cpu", "sstsimeng.simengcore")
cpu.addParams({
    "config_path": "/home/rahat/asimov/simeng-progs/a64fx.yaml",
    "executable_path": "/home/rahat/asimov/simeng-progs/Rahat",
    "clock": "1GHz"
})
