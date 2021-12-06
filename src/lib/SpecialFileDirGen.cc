#include "simeng/SpecialFileDirGen.hh"

namespace simeng {

SpecialFileDirGen::SpecialFileDirGen(YAML::Node config) {
  // Import all values from config file
  core_count = config["CPU-Info"]["Core-Count"].as<uint64_t>();
  socket_count = config["CPU-Info"]["Socket-Count"].as<uint64_t>();
  smt = config["CPU-Info"]["SMT"].as<uint64_t>();
  bogoMIPS = config["CPU-Info"]["BogoMIPS"].as<float>();
  features = config["CPU-Info"]["Features"].as<std::string>();
  cpu_implementer = config["CPU-Info"]["CPU-Implementer"].as<std::string>();
  cpu_architecture = config["CPU-Info"]["CPU-Architecture"].as<uint64_t>();
  cpu_variant = config["CPU-Info"]["CPU-Variant"].as<std::string>();
  cpu_part = config["CPU-Info"]["CPU-Part"].as<std::string>();
  cpu_revision = config["CPU-Info"]["CPU-Revision"].as<uint64_t>();
  package_count = config["CPU-Info"]["Package-Count"].as<uint64_t>();
}

void SpecialFileDirGen::RemoveExistingSFDir() {
  std::filesystem::remove_all(specialFilesParentDir_ + "/specialFiles/");
  return;
}

void SpecialFileDirGen::GenerateSFDir() {
  // Define frequently accessed root directories in special file tree
  const std::string proc_dir = specialFilesParentDir_ + "/specialFiles/proc/";
  const std::string online_dir =
      specialFilesParentDir_ + "/specialFiles/sys/devices/system/cpu/";
  const std::string cpu_base_dir =
      specialFilesParentDir_ + "/specialFiles/sys/devices/system/cpu/cpu";

  // Create special file directory structure
  std::filesystem::create_directory(specialFilesParentDir_ + "/specialFiles/");
  std::filesystem::create_directory(specialFilesParentDir_ +
                                    "/specialFiles/proc/");
  std::filesystem::create_directory(specialFilesParentDir_ +
                                    "/specialFiles/sys/");
  std::filesystem::create_directory(specialFilesParentDir_ +
                                    "/specialFiles/sys/devices/");
  std::filesystem::create_directory(specialFilesParentDir_ +
                                    "/specialFiles/sys/devices/system/");
  std::filesystem::create_directory(specialFilesParentDir_ +
                                    "/specialFiles/sys/devices/system/cpu/");

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
    std::filesystem::create_directory(cpu_base_dir + std::to_string(i) + "/");
    std::filesystem::create_directory(cpu_base_dir + std::to_string(i) +
                                      "/topology/");
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
                            (s * core_count * socket_count * smt);
        core_id_file.close();

        // physical_package_id File generation
        std::ofstream phys_package_id_file(
            cpu_base_dir +
            std::to_string(c + (t * core_count) + (s * smt * core_count)) +
            "/topology/physical_package_id");
        phys_package_id_file << current_package_id;
        phys_package_id_file.close();
      }
    }
    current_package_id += 1;
  }

  return;
}
}  // namespace simeng