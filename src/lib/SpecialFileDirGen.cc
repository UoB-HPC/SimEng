#include "simeng/SpecialFileDirGen.hh"

#include <iostream>

namespace simeng {

SpecialFileDirGen::SpecialFileDirGen(ryml::ConstNodeRef config)
    : coreCount_(config["CPU-Info"]["Core-Count"].as<uint64_t>()),
      socketCount_(config["CPU-Info"]["Socket-Count"].as<uint64_t>()),
      smt_(config["CPU-Info"]["SMT"].as<uint64_t>()),
      bogoMIPS_(config["CPU-Info"]["BogoMIPS"].as<float>()),
      features_(config["CPU-Info"]["Features"].as<std::string>()),
      cpuImplementer_(config["CPU-Info"]["CPU-Implementer"].as<std::string>()),
      cpuArchitecture_(config["CPU-Info"]["CPU-Architecture"].as<uint64_t>()),
      cpuVariant_(config["CPU-Info"]["CPU-Variant"].as<std::string>()),
      cpuPart_(config["CPU-Info"]["CPU-Part"].as<std::string>()),
      cpuRevision_(config["CPU-Info"]["CPU-Revision"].as<uint64_t>()),
      packageCount_(config["CPU-Info"]["Package-Count"].as<uint64_t>()) {}

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
  for (int i = 0; i < coreCount_ * socketCount_ * smt_; i++) {
    cpuinfo_File << "processor\t: " + std::to_string(i) + "\nBogoMIPS\t: " +
                        std::to_string(bogoMIPS_).erase(
                            std::to_string(bogoMIPS_).length() - 4) +
                        "\nFeatures\t: " + features_ +
                        "\nCPU implementer\t: " + cpuImplementer_ +
                        "\nCPU architecture: " +
                        std::to_string(cpuArchitecture_) +
                        "\nCPU variant\t: " + cpuVariant_ +
                        "\nCPU part\t: " + cpuPart_ +
                        "\nCPU revision\t: " + std::to_string(cpuRevision_) +
                        "\n\n";
  }
  cpuinfo_File.close();

  // Create '/proc/stat' file.
  std::ofstream stat_File(proc_dir + "stat");
  stat_File << "cpu  0 0 0 0 0 0 0 0 0 0\n";
  for (int i = 0; i < coreCount_ * socketCount_ * smt_; i++) {
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
  online_File << "0-" + std::to_string(coreCount_ * socketCount_ * smt_ - 1) +
                     "\n";
  online_File.close();

  // Create sub directory for each CPU core and required files.
  for (int i = 0; i < coreCount_ * socketCount_ * smt_; i++) {
    system(("mkdir " + cpu_base_dir + std::to_string(i) + "/").c_str());
    system(
        ("mkdir " + cpu_base_dir + std::to_string(i) + "/topology/").c_str());
  }

  // Create '/sys/devices/system/cpu/cpuX/topology/{core_id,
  // physical_package_id}' files
  uint64_t cores_per_package = coreCount_ / packageCount_;
  uint64_t current_package_id = 0;
  for (int s = 0; s < socketCount_; s++) {
    for (int c = 0; c < coreCount_; c++) {
      if (c % cores_per_package == 0 && c != 0) {
        current_package_id += 1;
      }
      for (int t = 0; t < smt_; t++) {
        // core_id File generation
        std::ofstream core_id_file(
            cpu_base_dir +
            std::to_string(c + (t * coreCount_) + (s * smt_ * coreCount_)) +
            "/topology/core_id");
        core_id_file << (c % cores_per_package) +
                            (s * coreCount_ * socketCount_ * smt_);
        core_id_file.close();

        // physical_package_id File generation
        std::ofstream phys_package_id_file(
            cpu_base_dir +
            std::to_string(c + (t * coreCount_) + (s * smt_ * coreCount_)) +
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