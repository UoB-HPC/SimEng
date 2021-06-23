#!/bin/bash

module swap PrgEnv-cray PrgEnv-gnu
module use /lustre/projects/bristol/modules-a64fx/modulefiles/
module load llvm/11.0

git-clang-format --diff origin/main --extensions cc,hh > FORMATTING

# Check whether any source files were modified
if grep 'no modified files to format' FORMATTING
then
    exit 0
fi

# Check whether any formatting changes are necessary
if grep 'clang-format did not modify any files' FORMATTING
then
    exit 0
fi

echo ""
echo "Code formatting issues detected (see below)."
echo ""
cat FORMATTING
exit 1