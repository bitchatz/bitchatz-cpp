# CPack configuration
set(CPACK_PACKAGE_NAME "bitchat")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A secure and private chat application")
set(CPACK_PACKAGE_VENDOR "Paulo Coutinho")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "0")
set(CPACK_PACKAGE_VERSION_PATCH "0")

# Set package generator based on platform
if(APPLE)
    set(CPACK_GENERATOR "ZIP")
    set(CPACK_PACKAGE_FILE_NAME "bitchat-${CPACK_PACKAGE_VERSION}-macos")
elseif(WIN32)
    set(CPACK_GENERATOR "ZIP")
    set(CPACK_PACKAGE_FILE_NAME "bitchat-${CPACK_PACKAGE_VERSION}-windows")
elseif(UNIX AND NOT APPLE)
    set(CPACK_GENERATOR "ZIP")
    set(CPACK_PACKAGE_FILE_NAME "bitchat-${CPACK_PACKAGE_VERSION}-linux")
endif()

# Include CPack
include(CPack)
