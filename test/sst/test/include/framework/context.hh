#pragma once

#include <functional>
#include <string>

using TestFunc = std::function<void(std::string)>;

/**
 * This struct stores the filename and line number of the
 * TEST_CASE.
 */
struct SourceInfo {
  SourceInfo(const char* fl_name, uint64_t ln_num)
      : fname_(fl_name), lnum_(ln_num){};
  SourceInfo() : fname_(NULL), lnum_(0){};

  const char* fname_;
  uint64_t lnum_;
};

/**
 * This class represents a test case, it stores all contextual information
 * regarding the test case. The TEST_CASE Macro ultimately leads to the creation
 * of a TestContext. TextContext(s) are run inside Runner(s).
 */
class TestContext {
 private:
  /** The name of the test case passed using the TEST_CASE macro. */
  std::string tname_;
  /** The function which contains all the testable logic. */
  TestFunc tfn_;
  /** The source of the test case. */
  SourceInfo tsinfo_;

 public:
  /** Constructor used to a TestContext by the TEST_CASE macro. */
  TestContext(TestFunc fn, const SourceInfo& info, std::string tname) {
    tsinfo_ = info;
    tname_ = tname;
    tfn_ = fn;
  };

  /** Constructor used to create an empty TestContext. */
  TestContext() {
    tsinfo_ = SourceInfo{};
    tname_ = "";
  };
  /** Returns the name of the test case. */
  std::string getTestCaseName() const { return tname_; }

  /** Returns the name of the file the test is written in. */
  std::string getTestCaseSrcFile() const { return std::string(tsinfo_.fname_); }

  /** Returns the TestFunc of the test case. */
  TestFunc getTestCaseFn() const { return tfn_; }

  /** Returns the line where the test exists. */
  uint64_t getTestCaseLineNum() const { return tsinfo_.lnum_; }
};
