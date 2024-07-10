#include "simeng/SpecialFileDirGen.hh"

#include <iostream>

namespace simeng {

SpecialFileDirGen::SpecialFileDirGen() {
  ryml::ConstNodeRef config = config::SimInfo::getConfig();
  // Import all values from config file
  config["CPU-Info"]["Core-Count"] >> core_count;
  config["CPU-Info"]["Socket-Count"] >> socket_count;
  config["CPU-Info"]["SMT"] >> smt;
  config["CPU-Info"]["BogoMIPS"] >> bogoMIPS;
  config["CPU-Info"]["Features"] >> features;
  config["CPU-Info"]["CPU-Implementer"] >> cpu_implementer;
  config["CPU-Info"]["CPU-Architecture"] >> cpu_architecture;
  config["CPU-Info"]["CPU-Variant"] >> cpu_variant;
  config["CPU-Info"]["CPU-Part"] >> cpu_part;
  config["CPU-Info"]["CPU-Revision"] >> cpu_revision;
  config["CPU-Info"]["Package-Count"] >> package_count;
}

void SpecialFileDirGen::RemoveExistingSFDir() {
  const std::string exist_input = "[ ! -d " + specialFilesDir_ + " ]";
  if (system(exist_input.c_str())) {
    const std::string rm_input = "rm -r " + specialFilesDir_;
    system(rm_input.c_str());
  }
  const std::string mk_input = "mkdir " + specialFilesDir_;
  system(mk_input.c_str());
  return;
}

void SpecialFileDirGen::GenerateSFDir() {
  // Define frequently accessed root directories in special file tree
  const std::string proc_dir = specialFilesDir_ + "/proc/";
  const std::string online_dir = specialFilesDir_ + "/sys/devices/system/cpu/";
  const std::string cpu_base_dir =
      specialFilesDir_ + "/sys/devices/system/cpu/cpu";

  system(("mkdir " + proc_dir).c_str());
  system(("mkdir " + specialFilesDir_ + "/sys/").c_str());
  system(("mkdir " + specialFilesDir_ + "/sys/devices/").c_str());
  system(("mkdir " + specialFilesDir_ + "/sys/devices/system/").c_str());
  system(("mkdir " + specialFilesDir_ + "/dev" + " && mkdir " +
          specialFilesDir_ + "/dev/shm")
             .c_str());
  system(("mkdir " + online_dir).c_str());

  // Create '/proc/cpuinfo' file.
  std::ofstream cpuinfo_File(proc_dir + "cpuinfo");
  for (int i = 0; i < core_count * socket_count * smt; i++) {
    cpuinfo_File << "processor\t: " + std::to_string(i) + "\nBogoMIPS\t: " +
                        std::to_string(bogoMIPS).erase(
                            std::to_string(bogoMIPS).length() - 4) +
                        "\nFeatures\t: " + features +
                        "\nCPU implementer\t: " + cpu_implementer +
                        "\nCPU architecture: " +
                        std::to_string(cpu_architecture) +
                        "\nCPU variant\t: " + cpu_variant +
                        "\nCPU part\t: " + cpu_part +
                        "\nCPU revision\t: " + std::to_string(cpu_revision) +
                        "\n\n";
  }
  cpuinfo_File.close();

  // Create '/proc/stat' file.
  std::ofstream stat_File(proc_dir + "stat");
  stat_File << "cpu  0 0 0 0 0 0 0 0 0 0\n";
  for (int i = 0; i < core_count * socket_count * smt; i++) {
    stat_File << "cpu" + std::to_string(i) + " 0 0 0 0 0 0 0 0 0 0\n";
  }
  stat_File << "intr 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 "
               "0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n";
  stat_File << "ctxt 0\n";
  stat_File << "btime 0\n";
  stat_File << "processes 0\n";
  stat_File << "procs_running 1\n";
  stat_File << "procs_blocked 0\n";
  stat_File << "softirq 0 0 0 0 0 0 0 0 0 0 0\n";
  stat_File.close();

  // Create '/proc/meminfo' file
  std::ofstream meminfo_File(proc_dir + "meminfo");
  meminfo_File << "MemTotal:        3221225 kB\n";
  meminfo_File << "MemFree:         3221225 kB\n";
  meminfo_File << "MemAvailable:    3221225 kB\n";
  meminfo_File << "Buffers:               0 kB\n";
  meminfo_File << "Cached:                0 kB\n";
  meminfo_File << "SwapCached:            0 kB\n";
  meminfo_File << "Active:                0 kB\n";
  meminfo_File << "Inactive:              0 kB\n";
  meminfo_File << "Active(anon):          0 kB\n";
  meminfo_File << "Inactive(anon):        0 kB\n";
  meminfo_File << "Active(file):          0 kB\n";
  meminfo_File << "Inactive(file):        0 kB\n";
  meminfo_File << "Unevictable:           0 kB\n";
  meminfo_File << "Mlocked:               0 kB\n";
  meminfo_File << "SwapTotal:             0 kB\n";
  meminfo_File << "SwapFree:              0 kB\n";
  meminfo_File << "Dirty:                 0 kB\n";
  meminfo_File << "Writeback:             0 kB\n";
  meminfo_File << "AnonPages:             0 kB\n";
  meminfo_File << "Mapped:                0 kB\n";
  meminfo_File << "Shmem:                 0 kB\n";
  meminfo_File << "KReclaimable:          0 kB\n";
  meminfo_File << "Slab:                  0 kB\n";
  meminfo_File << "SReclaimable:          0 kB\n";
  meminfo_File << "SUnreclaim:            0 kB\n";
  meminfo_File << "KernelStack:           0 kB\n";
  meminfo_File << "PageTables:            0 kB\n";
  meminfo_File << "NFS_Unstable:          0 kB\n";
  meminfo_File << "Bounce:                0 kB\n";
  meminfo_File << "WritebackTmp:          0 kB\n";
  meminfo_File << "CommitLimit:           0 kB\n";
  meminfo_File << "Committed_AS:          0 kB\n";
  meminfo_File << "VmallocTotal:          0 kB\n";
  meminfo_File << "VmallocUsed:           0 kB\n";
  meminfo_File << "VmallocChunk:          0 kB\n";
  meminfo_File << "Percpu:                0 kB\n";
  meminfo_File << "HardwareCorrupted:     0 kB\n";
  meminfo_File << "AnonHugePages:         0 kB\n";
  meminfo_File << "ShmemHugePages:        0 kB\n";
  meminfo_File << "ShmemPmdMapped:        0 kB\n";
  meminfo_File << "FileHugePages:         0 kB\n";
  meminfo_File << "FilePmdMapped:         0 kB\n";
  meminfo_File << "HugePages_Total:       0\n";
  meminfo_File << "HugePages_Free:        0\n";
  meminfo_File << "HugePages_Rsvd:        0\n";
  meminfo_File << "HugePages_Surp:        0\n";
  meminfo_File << "Hugepagesize:       2048 kB\n";
  meminfo_File << "Hugetlb:               0 kB\n";
  // ---------
  // meminfo_File << "MemTotal:       267773504 kB\n";
  // meminfo_File << "MemFree:        186223168 kB\n";
  // meminfo_File << "MemAvailable:   202928384 kB\n";
  // meminfo_File << "Buffers:               0 kB\n";
  // meminfo_File << "Cached:         31209856 kB\n";
  // meminfo_File << "SwapCached:            0 kB\n";
  // meminfo_File << "Active:         25598080 kB\n";
  // meminfo_File << "Inactive:        7656704 kB\n";
  // meminfo_File << "Active(anon):   25411968 kB\n";
  // meminfo_File << "Inactive(anon):  7466176 kB\n";
  // meminfo_File << "Active(file):     186112 kB\n";
  // meminfo_File << "Inactive(file):   190528 kB\n";
  // meminfo_File << "Unevictable:           0 kB\n";
  // meminfo_File << "Mlocked:               0 kB\n";
  // meminfo_File << "SwapTotal:             0 kB\n";
  // meminfo_File << "SwapFree:              0 kB\n";
  // meminfo_File << "Dirty:                64 kB\n";
  // meminfo_File << "Writeback:             0 kB\n";
  // meminfo_File << "AnonPages:       2049600 kB\n";
  // meminfo_File << "Mapped:           315520 kB\n";
  // meminfo_File << "Shmem:          30833088 kB\n";
  // meminfo_File << "KReclaimable:   18359040 kB\n";
  // meminfo_File << "Slab:           42965120 kB\n";
  // meminfo_File << "SReclaimable:   18359040 kB\n";
  // meminfo_File << "SUnreclaim:     24606080 kB\n";
  // meminfo_File << "KernelStack:      234048 kB\n";
  // meminfo_File << "PageTables:       126080 kB\n";
  // meminfo_File << "NFS_Unstable:          0 kB\n";
  // meminfo_File << "Bounce:                0 kB\n";
  // meminfo_File << "WritebackTmp:          0 kB\n";
  // meminfo_File << "CommitLimit:    133886720 kB\n";
  // meminfo_File << "Committed_AS:   37454912 kB\n";
  // meminfo_File << "VmallocTotal:   133009506240 kB\n";
  // meminfo_File << "VmallocUsed:           0 kB\n";
  // meminfo_File << "VmallocChunk:          0 kB\n";
  // meminfo_File << "Percpu:          1441792 kB\n";
  // meminfo_File << "HardwareCorrupted:     0 kB\n";
  // meminfo_File << "AnonHugePages:         0 kB\n";
  // meminfo_File << "ShmemHugePages:        0 kB\n";
  // meminfo_File << "ShmemPmdMapped:        0 kB\n";
  // meminfo_File << "FileHugePages:         0 kB\n";
  // meminfo_File << "FilePmdMapped:         0 kB\n";
  // meminfo_File << "HugePages_Total:       0\n";
  // meminfo_File << "HugePages_Free:        0\n";
  // meminfo_File << "HugePages_Rsvd:        0\n";
  // meminfo_File << "HugePages_Surp:        0\n";
  // meminfo_File << "Hugepagesize:       2048 kB\n";
  // meminfo_File << "Hugetlb:               0 kB\n";
  meminfo_File.close();

  // Create '/proc/self/status' file
  system(("mkdir " + proc_dir + "self/").c_str());
  std::ofstream status_File(proc_dir + "self/status");
  status_File
      << "Name:   /Users/jj16791/workspace/riken/files/"
         "study2_fugaku_fujitrad37_scalable.libs/lib/ld-linux-aarch64.so.1\n";
  status_File << "Umask:  0002\n";
  status_File << "State:  R (running)\n";
  status_File << "Tgid:   1\n";
  status_File << "Ngid:   1\n";
  status_File << "Pid:    1\n";
  status_File << "PPid:   1\n";
  status_File << "TracerPid:      1\n";
  status_File << "Uid:    1    1    1    1\n";
  status_File << "Gid:    1    1    1    1\n";
  status_File << "FDSize: 1024\n";
  status_File << "Groups: 0 0 0\n";
  status_File << "NStgid: 1\n";
  status_File << "NSpid:  1\n";
  status_File << "NSpgid: 1\n";
  status_File << "NSsid:  1\n";
  status_File << "VmPeak:     3221225 kB\n";
  status_File << "VmSize:     3221225 kB\n";
  status_File << "VmLck:           0 kB\n";
  status_File << "VmPin:           0 kB\n";
  status_File << "VmHWM:       3221225 kB\n";
  status_File << "VmRSS:       3221225 kB\n";
  status_File << "RssAnon:     3221225 kB\n";
  status_File << "RssFile:      3221225 kB\n";
  status_File << "RssShmem:        0 kB\n";
  status_File << "VmData:      10737418 kB\n";
  status_File << "VmStk:         536870 kB\n";
  status_File << "VmExe:         128 kB\n";
  status_File << "VmLib:        10737418 kB\n";
  status_File << "VmPTE:          0 kB\n";
  status_File << "VmPMD:          0 kB\n";
  status_File << "VmSwap:          0 kB\n";
  status_File << "HugetlbPages:          0 kB        # 4.4\n";
  status_File << "CoreDumping:   0                       # 4.15\n";
  status_File << "Threads:        1\n";
  status_File << "SigQ:   0/0\n";
  status_File << "SigPnd: 0000000000000000\n";
  status_File << "ShdPnd: 0000000000000000\n";
  status_File << "SigBlk: 0000000000000000\n";
  status_File << "SigIgn: 0000000000000000\n";
  status_File << "SigCgt: 0000000000000000\n";
  status_File << "CapInh: 0000000000000000\n";
  status_File << "CapPrm: 0000000000000000\n";
  status_File << "CapEff: 0000000000000000\n";
  status_File << "CapBnd: ffffffffffffffff\n";
  status_File << "CapAmb: 0000000000000000\n";
  status_File << "NoNewPrivs:     0\n";
  status_File << "Seccomp:        0\n";
  status_File << "Seccomp_filters:        0\n";
  status_File << "Speculation_Store_Bypass:       vulnerable\n";
  status_File << "Cpus_allowed:   00000001\n";
  status_File << "Cpus_allowed_list:      0\n";
  status_File << "Mems_allowed:   0\n";
  status_File << "Mems_allowed_list:      0\n";
  status_File << "voluntary_ctxt_switches:        0\n";
  status_File << "nonvoluntary_ctxt_switches:     0\n";
  status_File.close();

  // Create '/sys/devices/system/cpu/online' file.
  std::ofstream online_File(online_dir + "online");
  online_File << "0-" + std::to_string(core_count * socket_count * smt - 1) +
                     "\n";
  online_File.close();

  // Create sub directory for each CPU core and required files.
  for (int i = 0; i < core_count * socket_count * smt; i++) {
    system(("mkdir " + cpu_base_dir + std::to_string(i) + "/").c_str());
    system(
        ("mkdir " + cpu_base_dir + std::to_string(i) + "/topology/").c_str());
  }

  // Create '/sys/devices/system/cpu/cpuX/topology/{core_id,
  // physical_package_id}' files
  uint64_t cores_per_package = core_count / package_count;
  uint64_t current_package_id = 0;
  for (int s = 0; s < socket_count; s++) {
    for (int c = 0; c < core_count; c++) {
      if (c % cores_per_package == 0 && c != 0) {
        current_package_id += 1;
      }
      for (int t = 0; t < smt; t++) {
        // core_id File generation
        std::ofstream core_id_file(
            cpu_base_dir +
            std::to_string(c + (t * core_count) + (s * smt * core_count)) +
            "/topology/core_id");
        core_id_file << (c % cores_per_package) +
                            (s * core_count * socket_count * smt)
                     << "\n";
        core_id_file.close();

        // physical_package_id File generation
        std::ofstream phys_package_id_file(
            cpu_base_dir +
            std::to_string(c + (t * core_count) + (s * smt * core_count)) +
            "/topology/physical_package_id");
        phys_package_id_file << current_package_id << "\n";
        phys_package_id_file.close();
      }
    }
    current_package_id += 1;
  }

  return;
}
}  // namespace simeng
