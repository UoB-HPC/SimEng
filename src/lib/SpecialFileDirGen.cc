#include "simeng/SpecialFileDirGen.hh"

#include <iostream>

namespace simeng {

SpecialFileDirGen::SpecialFileDirGen() {
  ryml::Tree config = config::SimInfo::getConfig();
  // Import all values from config file
  core_count =
      config::SimInfo::getValue<uint64_t>(config["CPU-Info"]["Core-Count"]);
  socket_count =
      config::SimInfo::getValue<uint64_t>(config["CPU-Info"]["Socket-Count"]);
  smt = config::SimInfo::getValue<uint64_t>(config["CPU-Info"]["SMT"]);
  bogoMIPS = config::SimInfo::getValue<float>(config["CPU-Info"]["BogoMIPS"]);
  features =
      config::SimInfo::getValue<std::string>(config["CPU-Info"]["Features"]);
  cpu_implementer = config::SimInfo::getValue<std::string>(
      config["CPU-Info"]["CPU-Implementer"]);
  cpu_architecture = config::SimInfo::getValue<uint64_t>(
      config["CPU-Info"]["CPU-Architecture"]);
  cpu_variant =
      config::SimInfo::getValue<std::string>(config["CPU-Info"]["CPU-Variant"]);
  cpu_part =
      config::SimInfo::getValue<std::string>(config["CPU-Info"]["CPU-Part"]);
  cpu_revision =
      config::SimInfo::getValue<uint64_t>(config["CPU-Info"]["CPU-Revision"]);
  package_count =
      config::SimInfo::getValue<uint64_t>(config["CPU-Info"]["Package-Count"]);
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
