#include "sstsimengtest.hh"

TEST_GROUP(TG5, "Running_benchmarks_on_SSTSimEng", "fastL1ForBinaries.py");

TEST_CASE(TG5, "Running_stream_triad", appendBinDirPath("stream_t")) {
  Parser p = Parser(capturedStdout);
  std::vector<std::string> outputLines = p.getOutputLines();
  STR_CONTAINS(outputLines[0], "Solution Validates");
}

TEST_CASE(TG5, "Running_stream_triad_sve", appendBinDirPath("stream_t_sve")) {
  Parser p = Parser(capturedStdout);
  std::vector<std::string> outputLines = p.getOutputLines();
  STR_CONTAINS(outputLines[0], "Solution Validates");
}

// Very basic test cases for cachebw. Since cachebw requires arg size to
// accurately hit cache levels, More benchmark tests should be added as and when
// more cache models are added. These test cases will only test whether cachebw
// works on SSTSimEng or not.
TEST_CASE(TG5, "Running_cachebw_static", appendBinDirPath("cachebw_static"),
          "args=32 100") {
  Parser p = Parser(capturedStdout);
  std::vector<std::string> outputLines = p.getOutputLines();
  STR_CONTAINS(outputLines[0], "n");
  STR_CONTAINS(outputLines[0], "reps");
  STR_CONTAINS(outputLines[0], "bytes");
  STR_CONTAINS(outputLines[0], "bandwidth");
}

TEST_CASE(TG5, "Running_cachebw_static_sve",
          appendBinDirPath("cachebw_static_sve"), "args=32 100") {
  Parser p = Parser(capturedStdout);
  std::vector<std::string> outputLines = p.getOutputLines();
  STR_CONTAINS(outputLines[0], "n");
  STR_CONTAINS(outputLines[0], "reps");
  STR_CONTAINS(outputLines[0], "bytes");
  STR_CONTAINS(outputLines[0], "bandwidth");
}
