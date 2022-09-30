#pragma once

#include "framework/expression.hh"
#include "framework/handlers.hh"
#include "framework/macros/util.hh"

#define GENERIC_EXPECT_WITH_LINE(A, OP, B, line, SRC)      \
  {                                                        \
    ExpressionHandler handler = ExpressionHandler();       \
    handler.handleExpression(ExprBuilder() << A OP B, SRC, \
                             static_cast<uint64_t>(line)); \
  }

#define GENERIC_STR_MATCHER_WITH_LINE(A, OP, B, line, SRC)         \
  {                                                                \
    ExpressionHandler handler = ExpressionHandler();               \
    handler.handleExpression((StrExprBuilder() << A << B).OP, SRC, \
                             static_cast<uint64_t>(line));         \
  }

#define GENERIC_STR_MATCHER(A, OP, B, SRC) \
  GENERIC_STR_MATCHER_WITH_LINE(A, OP, B, __LINE__, SRC)

#define GENERIC_EXPECT(A, OP, B, SRC) \
  GENERIC_EXPECT_WITH_LINE(A, OP, B, __LINE__, SRC)

#define EXPECT_EQ(A, B) GENERIC_EXPECT(A, ==, B, STRINGIFY(EXPECT_EQ(A, B)))
#define EXPECT_GT(A, B) GENERIC_EXPECT(A, >, B, STRINGIFY(EXPECT_GT(A, B)))
#define EXPECT_LT(A, B) GENERIC_EXPECT(A, <, B, STRINGIFY(EXPECT_LT(A, B)))
#define EXPECT_GTE(A, B) GENERIC_EXPECT(A, >=, B, STRINGIFY(EXPECT_GTE(A, B)))
#define EXPECT_LTE(A, B) GENERIC_EXPECT(A, <=, B, STRINGIFY(EXPECT_LTE(A, B)))
#define EXPECT_NEQ(A, B) GENERIC_EXPECT(A, !=, B, STRINGIFY(EXPECT_NEQ(A, B)))

#define STR_EQ(A, B) \
  GENERIC_STR_MATCHER(A, compareEqual(), B, STRINGIFY(STR_EQ(A, B)))
#define STR_NOT_EQ(A, B) \
  GENERIC_STR_MATCHER(A, compareNotEqual(), B, STRINGIFY(STR_NOT_EQ(A, B)))
#define STR_STARTS_WITH(A, B) \
  GENERIC_STR_MATCHER(A, startsWith(), B, STRINGIFY(STR_STARTSWITH(A, B)))
#define STR_CONTAINS(A, B) \
  GENERIC_STR_MATCHER(A, contains(), B, STRINGIFY(STR_CONTAINS(A, B)))