# LZ4 CMake Configuration

CPMAddPackage(
    NAME lz4
    GITHUB_REPOSITORY lz4/lz4
    VERSION 1.10.0
    DOWNLOAD_ONLY TRUE
)

# Define source files
set(LZ4_SOURCES
    # Protocol sources
    ${lz4_SOURCE_DIR}/lib/lz4.c
)

# Create  static library
add_library(lz4 STATIC ${LZ4_SOURCES})

# Set include directories
target_include_directories(lz4 PUBLIC ${lz4_SOURCE_DIR}/lib)
