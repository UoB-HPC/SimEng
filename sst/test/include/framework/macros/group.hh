#pragma once

#include <algorithm>

#include "framework/context.hh"
#include "framework/macros/util.hh"
#include "framework/registry.hh"
#include "framework/runner.hh"

// This MACRO instantiates the SourceInfo struct needed for TestContext.
#define MAKE_TEST_SOURCE \
  SourceInfo { __FILE__, static_cast<uint64_t>(__LINE__) }

// This MACRO uses the concat MACRO internally as calling CONCAT inside CONCAT
// leads to preprocessing errors.
#define CONSTRUCT_UNQIUE_GROUP_NAME(counter) CONCAT(Test_Group_, counter)

// This internal MACRO expands to define the class implementation of a
// TEST_GROUP.
#define CONSTRUCT_GROUP_COMPLETE(ClassName, groupName, sstConfigFile, ...)  \
  class ClassName : public Group<ClassName> {                               \
    static const bool registered_;                                          \
                                                                            \
   private:                                                                 \
    const GroupConfig config_ = GroupConfig{                                \
        groupName, std::vector<std::string>{SST_INSTALL_DIR, sstConfigFile, \
                                            __VA_ARGS__}};                  \
                                                                            \
   public:                                                                  \
    const GroupConfig& getGroupConfig() { return config_; }                 \
    static std::string getGroupName() { return groupName; }                 \
    FACTORY(ClassName)                                                      \
  };                                                                        \
  REGISTER(ClassName, groupName, __FILE__)

// This MACRO expands to define all source code required for a TEST_GROUP
#define TEST_GROUP(ClassName, groupName, sstConfigFile, ...) \
  CONSTRUCT_GROUP_COMPLETE(ClassName, groupName, sstConfigFile, __VA_ARGS__)

// This MACRO uses the concat MACRO internally as calling CONCAT inside CONCAT
// leads to preprocessing errors.
#define CREATE_UNIQUE_TEST_NAME_G(tname, counter) CONCAT(tname, counter)

// This MACRO creates a unique test name from the class name.
#define CREATE_TEST_NAME_G(ClassName) \
  CREATE_UNIQUE_TEST_NAME_G(CONCAT(ClassName, TEST_CASE), __COUNTER__)

// This MACRO expands to define all logic which creates and registers the
// TestContext related to a TEST_CASE to a TEST_GROUP.
#define REGISTER_TC_G(ClassName, TestName, ptr, counter, TestCaseName, ...) \
  std::unique_ptr<TestContext> CREATE_UNIQUE_TEST_NAME_G(                   \
      ClassName, CONCAT(counter, ptr)) =                                    \
      std::make_unique<TestContext>(&TestName, MAKE_TEST_SOURCE,            \
                                    TestCaseName);                          \
  const bool CONCAT(TestName, _registered_) = ClassName::registerTest(      \
      CREATE_UNIQUE_TEST_NAME_G(ClassName, CONCAT(counter, ptr)),           \
      ClassName::getGroupName(), std::vector<std::string>{__VA_ARGS__});

// Internal MACRO called inside TEST_CASE MACRO which declares and registers the
// TEST_CASE.
#define CREATE_TEST_CASE_G(ClassName, TestName, TestCaseName, ...)   \
  void TestName(std::string capturedStdout);                         \
  REGISTER_TC_G(ClassName, TestName, ptr, __COUNTER__, TestCaseName, \
                __VA_ARGS__)                                         \
  void TestName(std::string capturedStdout)

// This MACRO expands to define all source code required for the TEST_CASE
#define TEST_CASE(ClassName, TestCaseName, ...)                              \
  CREATE_TEST_CASE_G(ClassName, CREATE_TEST_NAME_G(ClassName), TestCaseName, \
                     __VA_ARGS__)
