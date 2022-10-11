#include "sstsimengtest.hh"

TEST_GROUP(TG1, "Demo group tests", "config.py")
TEST_CASE(TG1, "TC1") { std::cout << capturedStdout << std::endl; }