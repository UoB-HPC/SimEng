import sst

simeng = sst.Component("simengcore", "sstsimeng.simengcore")
simeng.addParams({
    "clock": "1GHz",
    "executable_path": "/home/rahat/asimov/simeng-bin/programs/add",
    "executable_args": "",
})


