#pragma once

#include <memory>

#include "framework/context.hh"
#include "framework/expression.hh"
#include "framework/output.hh"
#include "framework/process.hh"

/**
 * This Singleton class is used to handle all exceptions that could happen
 * within a TEST_CASE.
 */
class ExceptionHandler {
 private:
  /** TestContext of the currently running TEST_CASE. */
  TestContext* ctx_;
  ExceptionHandler(){};

 public:
  /**
   * This method returns the singleton instance of the ExceptionHandler
   * class.
   */
  static std::unique_ptr<ExceptionHandler>& getInstance() {
    static std::unique_ptr<ExceptionHandler> ptr;
    if (ptr == nullptr) {
      ptr = std::unique_ptr<ExceptionHandler>(new ExceptionHandler());
    }
    return ptr;
  }
  /** This method handles any runtime errors that can happen when the logic
   * inside a TEST_CASE is executed. This method calls exit(EXIT_FAILURE) and
   * terminates the execution of the test suite.
   */
  void handleTestRuntimeException(const std::exception& e,
                                  const Output& output = Output()) {
    std::string excpStr = e.what();
    output.fail(ctx_);
    output.output("", 8, Formatter::bold_bright_red("Runtime error: "));
    output.output("", 8, excpStr);
    output.printCapturedStdCout();
    std::exit(EXIT_FAILURE);
  }

  /**
   * This method handles any exception raised by an Expression inside a
   * TEST_CASE.
   */
  void handleExpressionException(const ExprEval& expr,
                                 const Output& output = Output()) {
    output.fail(ctx_);
    output.output("", 8, Formatter::bold("Expression failed: "),
                  ctx_->getTestCaseSrcFile(), ":", expr.exprLineNum_);
    output.output("", 8, Formatter::blue(expr.exprString_));
    output.printCapturedStdCout();
  }

  /**
   * This method handles ProcessException thrown by the Process class upon
   * encountering errors/exceptions inside the child process.
   */
  void handleProcessException(const ProcessException& procExcp,
                              const Output& output = Output()) {
    output.output("", 0, procExcp.errString_);
    if (procExcp.stdoutStr_ != "") output.output("", 4, procExcp.stdoutStr_);
    if (procExcp.stderrStr_ != "") output.output("", 4, procExcp.stderrStr_);
  }
  /**
   * This method registers the TestContext of the currently running test case
   * to the exception handler.
   */
  void registerContext(TestContext* ctx) { ctx_ = ctx; };
};

/**
 * This class is used to throw ExprEval exceptions upon encounting a failing
 * expression.
 */
class ExpressionHandler {
 public:
  ExpressionHandler(){};
  /** This method is used to handle all Unary Expressions. */
  void handleExpression(BaseExpr expr, std::string exprSource,
                        uint64_t lineNum) {
    handleExpression(expr.makeUnaryExprEval(), exprSource, lineNum);
  };
  /** This method is used to handle all Expression that have been evaluated. */
  void handleExpression(ExprEval exprRes, std::string exprSource,
                        uint64_t lineNum) {
    exprRes.exprString_ = exprSource;
    exprRes.exprLineNum_ = lineNum;
    if (!exprRes.result_) {
      throw exprRes;
    };
    return;
  };
};