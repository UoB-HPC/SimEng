#pragma once

#include <memory>

#include "framework/output.hh"

/**
 * A Singleton class which records total number of tests, total failures and
 * total successes.
 */
class Stats {
 private:
  Stats() {}
  /** Total number of test cases. */
  uint64_t testCount_ = 0;
  /** Total number of test case failures. */
  uint64_t failures_ = 0;
  /** Total number test case successes. */
  uint64_t success_ = 0;

 public:
  /** This method returns the singleton instance of the Stats class. */
  static std::unique_ptr<Stats>& getInstance() {
    static std::unique_ptr<Stats> ptr;
    if (ptr == nullptr) {
      ptr = std::unique_ptr<Stats>(new Stats());
    }
    return ptr;
  }
  /** This method increments the total test count. */
  void recordTest() { testCount_++; }
  /** This method increments the total failure count. */
  void recordFailure() { failures_++; }
  /** This method increments the total sucess count. */
  void recordSuccess() { success_++; }
  /** This method returns the total test count. */
  uint64_t getTestCount() { return testCount_; }
  /** This method returns the total failure count. */
  uint64_t getFailureCount() { return failures_; }
  /** This method returns the total success count. */
  uint64_t getSuccessCount() { return success_; }
  /** This method prints the all statistics stored by the Stats class. */
  void printStats() {
    Output output;
    output.output("", 0, Formatter::bold("\nStats:"));
    output.output(" ", 4,
                  "Total Tests:", Formatter::blue(std::to_string(testCount_)));
    output.output(" ", 4, "Tests Passed:",
                  Formatter::bright_green(std::to_string(success_)));
    output.output(" ", 4, "Tests Failed:",
                  Formatter::bright_red(std::to_string(failures_)));
  }
};