#pragma once

#include <algorithm>

#include "framework/context.hh"
#include "framework/macros/util.hh"
#include "framework/registry.hh"
#include "framework/runner.hh"

#define MAKE_TEST_SOURCE \
  SourceInfo { __FILE__, static_cast<uint64_t>(__LINE__) }

#define CONSTRUCT_UNQIUE_GROUP_NAME(counter) CONCAT(Test_Group_, counter)

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

#define TEST_GROUP(ClassName, groupName, sstConfigFile, ...) \
  CONSTRUCT_GROUP_COMPLETE(ClassName, groupName, sstConfigFile, __VA_ARGS__)

#define CREATE_UNIQUE_TEST_NAME_G(tname, counter) CONCAT(tname, counter)

#define CREATE_TEST_NAME_G(ClassName) \
  CREATE_UNIQUE_TEST_NAME_G(CONCAT(ClassName, _TEST_CASE_), __COUNTER__)

#define REGISTER_TC_G(ClassName, TestName, ptr, TestCaseName, ...)     \
  std::unique_ptr<TestContext> CONCAT(ClassName, ptr) =                \
      std::make_unique<TestContext>(&TestName, MAKE_TEST_SOURCE,       \
                                    TestCaseName);                     \
  const bool CONCAT(TestName, _registered_) = ClassName::registerTest( \
      CONCAT(ClassName, ptr), ClassName::getGroupName(),               \
      std::vector<std::string>{__VA_ARGS__});

#define CREATE_TEST_CASE_G(ClassName, TestName, TestCaseName, ...)            \
  void TestName(std::string capturedStdout);                                  \
  REGISTER_TC_G(ClassName, TestName, CONCAT(ptr_, __COUNTER__), TestCaseName, \
                __VA_ARGS__)                                                  \
  void TestName(std::string capturedStdout)

#define TEST_CASE(ClassName, TestCaseName, ...)                              \
  CREATE_TEST_CASE_G(ClassName, CREATE_TEST_NAME_G(ClassName), TestCaseName, \
                     __VA_ARGS__)
