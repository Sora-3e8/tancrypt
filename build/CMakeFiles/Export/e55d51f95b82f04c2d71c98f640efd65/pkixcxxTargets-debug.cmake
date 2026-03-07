#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "pkixcxx::pkixcxx" for configuration "Debug"
set_property(TARGET pkixcxx::pkixcxx APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(pkixcxx::pkixcxx PROPERTIES
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/pkixcxx/libpkixcxx.so"
  IMPORTED_SONAME_DEBUG "libpkixcxx.so"
  )

list(APPEND _cmake_import_check_targets pkixcxx::pkixcxx )
list(APPEND _cmake_import_check_files_for_pkixcxx::pkixcxx "${_IMPORT_PREFIX}/lib/pkixcxx/libpkixcxx.so" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
