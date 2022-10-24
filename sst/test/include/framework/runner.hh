#pragma once

#include <functional>
#include <iostream>
#include <string>

#include "framework/context.hh"
#include "framework/handlers.hh"
#include "framework/process.hh"
#include "framework/registry.hh"
#include "framework/stats.hh"
#include "framework/uid.hh"

/**
 * A Runner is an interface which is able to run a test case.
 * Runner(s) are registered in the registry and invoked during
 * runtime.
 */
class Runner {
 public:
  Runner() {}
  /** Method used to run the test(s) inside a runner. */
  virtual void run(){};
  /**
   * Returns the current executing TestContext.
   * The TestContext for a Group changes everytime a new test is run
   */
  virtual std::unique_ptr<TestContext>& getCurrContext() {
    std::unique_ptr<TestContext> ptr = std::make_unique<TestContext>();
    return ptr;
  };
};

/** GroupConfig used to provide configuration options to a Group. */
struct GroupConfig {
  GroupConfig() : groupStr_(""), execArgs_(std::vector<std::string>()){};
  GroupConfig(std::string groupStr, std::vector<std::string> execArgs)
      : groupStr_(groupStr), execArgs_(execArgs) {}

  /** String used to describe the test group. */
  std::string groupStr_;
  std::vector<std::string> execArgs_;
};

/**
 * A Group represents a collection of test cases. In a group a test case is
 * refereneced through it's context. The Group template is template with the
 * name to class extending Group. This is called the "Curiously recurring
 * template pattern" and in this use case it allows the polymorphic children of
 * Group to have individual and different static contexts.
 *
 * For example:
 * class A : public Group<A> and class B : public Group<B>
 * will have different static contexts even if the static contexts are invoked
 * through polymorphic parent references i.e.
 * Runner runner1 = myClassA();
 * Runner runner2 = myClassB();
 * runner1.run() will use a different static context and runner2.run() will use
 * a different static context. This enables us to register TEST_CASE(s) to
 * different TEST_GROUP(s) while maintaining isolation among TEST_GROUP(s).
 */

template <typename T>
class Group : public Runner {
  using TestCtxs = std::vector<std::unique_ptr<TestContext>>;
  using Args = std::vector<std::vector<std::string>>;

 private:
  /**
   * Added to remove compiler warning for getGroupConfig base
   * implementation.
   */
  const GroupConfig emptyConfig_ = GroupConfig{};

  /** TextContext of the currently executing test. */
  std::unique_ptr<TestContext> ctx_;
  /** Output class used to capture stdout of testcases and output to stdout. */
  Output output_;

  /** Method which returns all TextContext(s) registered to a Group. */
  static std::unique_ptr<TestCtxs>& getTestCtxs() {
    /** Static unique_ptr to the a vector of TextContext(s). */
    static std::unique_ptr<TestCtxs> instance;
    if (instance == nullptr) {
      instance = std::unique_ptr<TestCtxs>(new TestCtxs);
    }
    return instance;
  }

  /**
   * Method which returns all arguments passed individual test cases registered
   * to a Group.
   */
  static std::unique_ptr<Args>& getArgs() {
    static std::unique_ptr<Args> vec;
    if (vec == nullptr) {
      vec = std::unique_ptr<Args>(new Args);
    }
    return vec;
  }

 public:
  /** This method is used to execute all test cases in a Group. */
  void run() {
    std::unique_ptr<TestCtxs>& tctxs_ = getTestCtxs();
    std::unique_ptr<Args>& args = getArgs();
    const GroupConfig& config = getGroupConfig();

    std::unique_ptr<ExceptionHandler>& handler =
        ExceptionHandler::getInstance();

    std::unique_ptr<Stats>& stats = Stats::getInstance();
    Process process = Process(config.execArgs_);

    output_.group(config.groupStr_);
    output_.setIndent(4);
    for (size_t x = 0; x < tctxs_->size(); x++) {
      bool fail = true;
      try {
        auto arg = args->at(x);
        ctx_ = std::move(tctxs_->at(x));

        // Run the SST binary with additional args (if any).
        process.runExecAndCaptureStdout(arg);
        // Register context with the exception handler.
        handler->registerContext(ctx_.get());
        stats->recordTest();
        // Start capturing stdout.
        output_.captureStdCout();
        // Pass the captured output from SST to the TEST_CASE.
        ctx_->getTestCaseFn()(process.getStdOutCapture());
        fail = false;
      } catch (const std::exception& e) {
        // On exception reset the stdout buffer first and then handle the
        // exception.
        output_.resetStdCoutBuffer();
        handler->handleTestRuntimeException(e, output_);
      } catch (const ExprEval& expr) {
        // On exception reset the stdout buffer first and then handle the
        // exception.
        output_.resetStdCoutBuffer();
        handler->handleExpressionException(expr, output_);
      } catch (const ProcessException& procExcp) {
        // On exception reset the stdout buffer first and then handle the
        // exception.
        handler->handleProcessException(procExcp);
      }
      // reset the stdout buffer.
      output_.resetStdCoutBuffer();
      if (fail) {
        stats->recordFailure();
        continue;
      }
      stats->recordSuccess();
      // Output passing testcase.
      output_.pass(ctx_.get());
      // print captured out of the TEST_CASE not the SST executable i.e. any
      // std::cout calls inside TEST_CASE, for e.g.
      // TEST_CASE { std::cout << "Print" << std::endl }
      output_.printCapturedStdCout();
    }
  };

  /**
   * Method used to register TestContext and additional arguments to a
   * TEST_CASE.
   */
  static bool registerTest(std::unique_ptr<TestContext>& ctx, std::string gname,
                           std::vector<std::string> arg) {
    std::string tname = ctx->getTestCaseName();
    uint64_t line = ctx->getTestCaseLineNum();
    std::string fname = ctx->getTestCaseSrcFile();

    UidRegistry::validateTestName(gname, tname, fname, line);

    getTestCtxs()->push_back(std::move(ctx));
    getArgs()->push_back(arg);
    return true;
  };

  /** Returns the TestContext of the current executing test case. */
  std::unique_ptr<TestContext>& getCurrContext() { return ctx_; };

  /**
   * This method returns a reference of GroupConfig. This method gets overriden
   * by TEST_GROUP Macro with the config defined in the source code.
   */
  virtual const GroupConfig& getGroupConfig() { return emptyConfig_; }
};