#include "sstsimengtest.hh"

TEST_GROUP(TG5, "Running_benchmarks_on_SSTSimEng", "fastL1ForBinaries.py");

TEST_CASE(TG5, "Running_stream_triad", appendBinDirPath("stream_t")) {
  std::cout << capturedStdout << std::endl;
}

TEST_CASE(TG5, "Running_stream_triad_sve", appendBinDirPath("stream_t_sve")) {
  std::cout << capturedStdout << std::endl;
}