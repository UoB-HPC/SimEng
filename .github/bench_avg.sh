#!/bin/bash

###############################################
# - Make sure SimEng is built first.
# - Only averages 1 benchmark over 10 runs as each run is pretty consistent
# - USAGE: ./bench_avg.sh [relative path to benchmark binary]
###############################################
# SOME OPTIONS YOU MIGHT LIKE:
#../../simeng-benchmarks/binaries/CloverLeaf/openmp/cloverleaf_gcc10.3.0_armv8.4+sve -> [40667.65 ms avg on github runner]
#../../simeng-benchmarks/binaries/miniBUDE/openmp/minibude_gcc10.3.0_armv8.4+sve -> [63.38 ms avg on github runner]
#../../simeng-benchmarks/binaries/STREAM/stream_gcc10.3.0_armv8.4+sve -> [7396.88 ms average on github runner]
#../../simeng-benchmarks/binaries/TeaLeaf/3d/tealeaf_gcc10.3.0_armv8.4+sve -> [56.09 ms average on github runner]
###############################################


# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <benchmark_parent_directory> <benchmark name e.g. cloverleaf_gcc10.3.0_armv8.4+sve> <Datafile path e.g. /simeng-benchmarks/Data_Files/CloverLeaf>"
    exit 1
fi

benchmark_path="$1"
benchmark_name="$2"
datafile_path="$3"

if [ $datafile_path ]; then
    datafile_path = "-n 64 -i 1 --deck $datafile_path"
fi

output_file="benchmark_output.txt"
total_time=0
runs=1

echo "$GITHUB_WORKSPACE"

# Loop to run the benchmark 10 times
for (( i=1; i<=runs; i++ ))
do  
    # Run the benchmark and redirect output to a file
    simeng $GITHUB_WORKSPACE/configs/a64fx.yaml $benchmark_path/$benchmark_name $datafile_path  > "$output_file"
    
    # Extract the time in milliseconds from the output
    current_time=$(grep 'ticks in' "$output_file" | awk '{print substr($6, 1, length($6)-2)}')
    
    # Add the extracted time to the total time
    total_time=$(echo "$total_time + $current_time" | bc)
    
    echo "Run $i: $current_time ms"
done

# Calculate the average time
average_time=$(echo "scale=2; $total_time / $runs" | bc)

echo "Average time over $runs runs: $average_time ms"

# Clean up the output file
rm "$output_file"