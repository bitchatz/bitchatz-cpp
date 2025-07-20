# noise-c CMake configuration
# This file integrates the noise-c library into the project

# Set noise-c source directory
set(NOISE_C_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/vendor/noise-c)

# Define noise-c include directories
set(NOISE_C_INCLUDE_DIRS
    ${NOISE_C_SOURCE_DIR}/include
    ${NOISE_C_SOURCE_DIR}/src
    ${NOISE_C_SOURCE_DIR}/src/protocol
)

# Define noise-c header files
set(NOISE_C_HEADERS
    # Main headers
    ${NOISE_C_SOURCE_DIR}/include/noise/keys.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protobufs.h

    # Protocol headers
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/buffer.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/cipherstate.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/constants.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/dhstate.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/errors.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/handshakestate.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/hashstate.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/names.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/randstate.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/signstate.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/symmetricstate.h
    ${NOISE_C_SOURCE_DIR}/include/noise/protocol/util.h

    # Keys headers
    ${NOISE_C_SOURCE_DIR}/include/noise/keys/certificate.h
    ${NOISE_C_SOURCE_DIR}/include/noise/keys/loader.h
)

# Detect architecture for Goldilocks
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(GOLDILOCKS_ARCH "arch_x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(GOLDILOCKS_ARCH "arch_ref64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(GOLDILOCKS_ARCH "arch_arm_32")
else()
    set(GOLDILOCKS_ARCH "arch_ref64")
endif()

# Define noise-c source files
set(NOISE_C_SOURCES
    # Protocol sources
    ${NOISE_C_SOURCE_DIR}/src/protocol/cipherstate.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/dhstate.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/errors.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/handshakestate.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/hashstate.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/internal.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/names.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/patterns.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/randstate.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/rand_os.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/signstate.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/symmetricstate.c
    ${NOISE_C_SOURCE_DIR}/src/protocol/util.c

    # Keys sources
    ${NOISE_C_SOURCE_DIR}/src/keys/certificate.c
    ${NOISE_C_SOURCE_DIR}/src/keys/loader.c

    # Protobufs sources
    ${NOISE_C_SOURCE_DIR}/src/protobufs/protobufs.c

    # Backend sources (OpenSSL)
    ${NOISE_C_SOURCE_DIR}/src/backend/openssl/cipher-aesgcm.c

    # Reference backend sources (fallback)
    #${NOISE_C_SOURCE_DIR}/src/backend/ref/cipher-aesgcm.c
    ${NOISE_C_SOURCE_DIR}/src/backend/ref/cipher-chachapoly.c
    ${NOISE_C_SOURCE_DIR}/src/backend/ref/dh-curve25519.c
    ${NOISE_C_SOURCE_DIR}/src/backend/ref/dh-curve448.c
    ${NOISE_C_SOURCE_DIR}/src/backend/ref/dh-newhope.c
    ${NOISE_C_SOURCE_DIR}/src/backend/ref/hash-blake2b.c
    ${NOISE_C_SOURCE_DIR}/src/backend/ref/hash-blake2s.c
    ${NOISE_C_SOURCE_DIR}/src/backend/ref/hash-sha256.c
    ${NOISE_C_SOURCE_DIR}/src/backend/ref/hash-sha512.c
    ${NOISE_C_SOURCE_DIR}/src/backend/ref/sign-ed25519.c

    # Crypto sources
    ${NOISE_C_SOURCE_DIR}/src/crypto/aes/rijndael-alg-fst.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/blake2/blake2b.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/blake2/blake2s.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/chacha/chacha.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/curve448/curve448.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/donna/poly1305-donna.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/ghash/ghash.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/newhope/batcher.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/newhope/error_correction.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/newhope/fips202.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/newhope/newhope.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/newhope/ntt.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/newhope/poly.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/newhope/precomp.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/newhope/reduce.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/newhope/crypto_stream_chacha20.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/sha2/sha256.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/sha2/sha512.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/ed25519/ed25519.c

    # Goldilocks sources (Curve448) - architecture-specific
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/p448/${GOLDILOCKS_ARCH}/p448.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/p448/f_arithmetic.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/p448/magic.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/arithmetic.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/barrett_field.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/crandom.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/ec_point.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/goldilocks.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/scalarmul.c
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/sha512.c
)

# Define noise-c compile definitions
set(NOISE_C_COMPILE_DEFINITIONS
    USE_OPENSSL=1
    ED25519_CUSTOMHASH
    ED25519_CUSTOMRANDOM
)

# Add architecture-specific definitions
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    list(APPEND NOISE_C_COMPILE_DEFINITIONS
        __ARM_NEON__
        __aarch64__
        POLY1305_64BIT
    )
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    list(APPEND NOISE_C_COMPILE_DEFINITIONS
        __X86_64__
        __amd64__
        POLY1305_64BIT
    )
endif()

# Create noise-c static library
add_library(noise-c STATIC ${NOISE_C_SOURCES} ${NOISE_C_HEADERS})

# Set include directories for noise-c
target_include_directories(noise-c PUBLIC
    ${NOISE_C_INCLUDE_DIRS}
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/include
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/p448
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src/p448/${GOLDILOCKS_ARCH}
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/src
    ${NOISE_C_SOURCE_DIR}/src/crypto/goldilocks/include
)

# Add protocol directory specifically for internal.h
target_include_directories(noise-c PRIVATE
    ${NOISE_C_SOURCE_DIR}/src/protocol
    ${NOISE_C_SOURCE_DIR}/include/noise/keys
)

# Set compile definitions for noise-c
target_compile_definitions(noise-c PRIVATE ${NOISE_C_COMPILE_DEFINITIONS})



# Set compile options for noise-c
target_compile_options(noise-c PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-unused-variable
    -Wno-unused-function
    -Wno-expansion-to-defined
)

# Link OpenSSL to noise-c
target_link_libraries(noise-c PUBLIC OpenSSL::SSL OpenSSL::Crypto)

# Set C standard for noise-c (it's written in C)
set_target_properties(noise-c PROPERTIES
    C_STANDARD 99
    C_STANDARD_REQUIRED ON
)

# Print noise-c configuration info
message(STATUS "noise-c source directory: ${NOISE_C_SOURCE_DIR}")
message(STATUS "noise-c include directories: ${NOISE_C_INCLUDE_DIRS}")
message(STATUS "noise-c backend: OpenSSL")
message(STATUS "noise-c Goldilocks architecture: ${GOLDILOCKS_ARCH}")
