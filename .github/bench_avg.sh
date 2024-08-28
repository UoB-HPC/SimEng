#!/bin/bash

###############################################
# - Make sure SimEng is built first.
# - Only averages 1 benchmark over 10 runs as each run is pretty consistent
# - USAGE: ./bench_avg.sh [relative path to benchmark binary]
###############################################
# SOME OPTIONS YOU MIGHT LIKE:
#../../simeng-benchmarks/binaries/CloverLeaf/openmp/cloverleaf_gcc10.3.0_armv8.4+sve -> 10times average 38115.10 ms -> 100times 38799.21 ms
#../../simeng-benchmarks/binaries/miniBUDE/openmp/minibude_gcc10.3.0_armv8.4+sve ->100times 53.37ms
#../../simeng-benchmarks/binaries/STREAM/stream_gcc10.3.0_armv8.4+sve -> 100times 5671.59 ms
#../../simeng-benchmarks/binaries/TeaLeaf/3d/tealeaf_gcc10.3.0_armv8.4+sve -> 100times  44.17 ms
###############################################


# Check if the correct number of arguments is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <benchmark_file_path>"
    exit 1
fi

benchmark_path="$1"
output_file="benchmark_output.txt"
total_time=0
runs=100

# Loop to run the benchmark 10 times
for (( i=1; i<=runs; i++ ))
do
    # Run the benchmark and redirect output to a file
    simeng ./configs/a64fx.yaml "$benchmark_path" > "$output_file"
    
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