#!/bin/bash

# Build script for Bitchat C++

set -e

echo "=== Building Bitchat C++ ==="

# Create build directory
mkdir -p build
cd build

# Configure with CMake
echo "Configuring with CMake..."
cmake ..

# Build
echo "Building..."
make -j$(nproc)

echo "=== Build complete ==="
echo "Executable: build/bin/bitchat"
