#include "sstsimengtest.hh"

// Only load and store instructions of various types and basic arithmetic
// instructions are checked as LLVM assembly will only be used by the SST
// testing framework, which only tests loads and stores.

TEST_GROUP(TG0, "SSTSimEng_correctly_assembles_instructions_using_LLVM",
           "a64fx-config.py", "withSrc=True",
           R"(source=
  ldr x0, [x1]
  )")
TEST_CASE(TG0, "Test_asssembly_of_simple_instructions") {
  // size_t pos = capturedStdout.find("[SimEng] retired:");
  // std::string retired = "";
  // Extract the retired: <count> string from capturedStdout.
  // for (size_t y = pos; y < capturedStdout.length(); y++) {
  //   if (capturedStdout[y] != '\n') {
  //     retired += capturedStdout[y];
  //   } else {
  //     break;
  //   }
  // }
  // Extract retired instruction count from "retired: <count>" string and cast
  // to uint64_t.
  // Subtract 18 (length of the prefix: "[SimEng] retired:") from retired string
  // to obtain the length of the substring containing the numeric value
  // representing the total number of retired instructions.
  // size_t len = retired.length() - 18;
  // uint64_t retiredCount = std::stoull(retired.substr(18, len));
  // std::cout << "Total instructions retired: " << retiredCount << std::endl;
  // This should be equal to the total number of instructions in the test case.
  // EXPECT_EQ(retiredCount, (uint64_t)38);
  std::cout << capturedStdout << std::endl;
}
