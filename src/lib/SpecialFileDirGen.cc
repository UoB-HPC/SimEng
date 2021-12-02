#include "simeng/SpecialFileDirGen.hh"

namespace simeng {

SpecialFileDirGen::SpecialFileDirGen(YAML::Node config) {
  // Import all values from config file
  core_count = config["CPU-Info"]["Core-Count"].as<uint64_t>();
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
  const std::string cpuinfo_dir =
      specialFilesParentDir_ + "/specialFiles/proc/";
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

  // Create 'online' file
  std::ofstream online_File(online_dir + "online");
  online_File << "0-" + std::to_string(core_count - 1) + "\n";
  online_File.close();

  // Create 'cpuinfo' file
  std::ofstream cpuinfo_File(cpuinfo_dir + "cpuinfo");
  for (int i = 0; i < core_count; i++) {
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

  // Create sub dir for each CPU core and required files
  for (int i = 0; i < core_count; i++) {
    std::filesystem::create_directory(cpu_base_dir + std::to_string(i) + "/");
    std::filesystem::create_directory(cpu_base_dir + std::to_string(i) +
                                      "/topology/");

    // Create 'physical_package_id' files

    // Create 'core_id' files
  }

  return;
}
}  // namespace simeng