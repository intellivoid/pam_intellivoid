cmake_minimum_required(VERSION 3.20.0)

# Force external build
if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR} AND NOT WIN32)
	message(FATAL_ERROR "You can not use CMake to build from the root of it's source tree! Remove the CMakeCache.txt file from this directory, then create a separate directory (either below this directory or elsewhere), and then re-run CMake from there.")
endif(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR} AND NOT WIN32)

# set a default build type if none was specified
set(default_build_type "Release")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE
	  STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
	"Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)

# Cmake module path (if exists)
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

# Find clang (if the system has it)
find_program(CLANG clang)
find_program(CLANGXX clang++)

# prefer clang instead of gcc (or whatever shit compiler they're using) This can be disabled with
# the NO_CLANG option
option(NO_CLANG "Don't prefer clang for compilation" OFF)
if (NOT NO_CLANG)
	if (CLANG)
		set(CMAKE_C_COMPILER ${CLANG})
	endif (CLANG)

	# In case we need to compile C++ in the future (which I doubt we will)
	if (CLANGXX)
		set(CMAKE_CXX_COMPILER ${CLANGXX})
	endif (CLANGXX)
endif (NOT NO_CLANG)

# Force colored compiler output on ninja
if (${CMAKE_GENERATOR} STREQUAL "Ninja")
	if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
		add_compile_options (-fdiagnostics-color=always)
	elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
		add_compile_options (-fcolor-diagnostics)
	endif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
endif (${CMAKE_GENERATOR} STREQUAL "Ninja")

project(pam_intellivoid
		VERSION 1.0.0
		DESCRIPTION "Pluggable Authentication Module (PAM) for Intrusion Detection and Warnings on intellivoid production servers"
		LANGUAGES CXX C
	)

add_compile_options(-pipe -Wall -Wextra -Wshadow -fPIC -Werror=format-security -Werror=implicit-function-declaration -Wsign-conversion -Wfloat-conversion -Wsign-compare -Wno-unused-parameter -Wno-unused-result -Wimplicit-fallthrough -fvisibility=hidden)
add_link_options(-rdynamic -Wl,-z,defs -Wl,-z,now -Wl,-z,relro)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -static-libasan")
	# set(LDFLAGS "${LDFLAGS} -fsanitize=address -static-libasan -l:libclang_rt.asan-x86_64.a")
elseif (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
	# Hardening
	add_compile_options(-fstack-clash-protection -fstack-protector-strong -mcet -fcf-protection)
	add_definitions(-D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS)
endif (CMAKE_BUILD_TYPE STREQUAL "Debug")

# Check for platform-specific things we need
include (CheckTypeSize)
include (CheckIncludeFile)
include (CheckLibraryExists)
include (CheckFunctionExists)
include (CheckCXXSourceCompiles)
include (CheckCXXCompilerFlag)
include (ExternalProject)
include (FetchContent)

check_type_size(int8_t HAVE_INT8_T)
check_type_size(uint8_t HAVE_UINT8_T)
check_type_size(int16_t HAVE_INT16_T)
check_type_size(uint16_t HAVE_UINT16_T)
check_type_size(uint32_t HAVE_UINT32_T)
check_type_size(int64_t HAVE_INT64_T)
check_type_size(uint64_t HAVE_UINT64_T)
check_type_size("long long" HAVE_LONG_LONG)
check_type_size("unsigned long long" HAVE_UNSIGNED_LONG_LONG)
check_type_size(size_t HAVE_SIZE_T)
check_type_size(time_t HAVE_TIME_T)
check_type_size("long double" HAVE_LONG_DOUBLE)

check_type_size(u_int8_t HAVE_U_INT8_T)
check_type_size(u_int16_t HAVE_U_INT16_T)
check_type_size(u_int32_t HAVE_U_INT32_T)
check_type_size(u_int64_t HAVE_U_INT64_T)

# Find PAM
find_package(PAM REQUIRED)

message(STATUS "Fetching embedFiglet")
FetchContent_Declare(
	embedFiglet
	GIT_REPOSITORY https://github.com/ebertolazzi/embedFiglet.git
	GIT_TAG 8decd8e4273a9b8ec6e4154be688a9ea058ddd0f
)
message(STATUS "Fetching embedFiglet - Done")

message(STATUS "Fetching fmtlib")
FetchContent_Declare(
	fmtlib
	GIT_REPOSITORY https://github.com/fmtlib/fmt
	GIT_TAG 8.0.1
)
message(STATUS "Fetching fmtlib - Done")

# Make all the projects available
FetchContent_MakeAvailable(embedFiglet fmtlib)

# Add our include directories
include_directories(
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_BINARY_DIR}
	${PAM_INCLUDE_DIR}
	${embedFiglet_SOURCE_DIR}/src/
	${fmtlib_SOURCE_DIR}/include/
)

set_source_files_properties(${SOURCE_FILES} PROPERTIES LANGUAGE CXX)

add_library(${PROJECT_NAME} MODULE src/pam_sysinfo.cpp src/statfs_types.cpp src/libTitanium.cpp)
set_target_properties(${PROJECT_NAME}
	PROPERTIES
		LINKER_LANGUAGE CXX
		PREFIX ""
		LINK_FLAGS "${LDFLAGS}"
		CXX_STANDARD 20
		CXX_STANDARD_REQUIRED YES
		CXX_EXTENSIONS NO
)
target_compile_options(${PROJECT_NAME} PRIVATE ${CFLAGS})

target_compile_features(${PROJECT_NAME}
	PRIVATE
		cxx_thread_local
		cxx_user_literals
		cxx_variadic_macros
		cxx_variadic_templates
		cxx_rvalue_references
		cxx_right_angle_brackets
		cxx_range_for
		cxx_noexcept
		cxx_long_long_type
		cxx_lambdas
		cxx_deleted_functions
		cxx_delegating_constructors
		cxx_auto_type
		cxx_decltype
		cxx_constexpr
	PUBLIC
		cxx_nullptr
)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	target_link_libraries(${PROJECT_NAME} ${PAM_LIBRARIES} embedFiglet_linux_static_debug fmt)
elseif (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")	
	target_link_libraries(${PROJECT_NAME} ${PAM_LIBRARIES} embedFiglet_linux_static fmt)
endif (CMAKE_BUILD_TYPE STREQUAL "Debug")

# Install the module
install(TARGETS ${PROJECT_NAME}
	DESTINATION lib/security
)

# cpack shit
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VENDOR "Intellivoid")
set(CPACK_PACKAGE_CONTACT "Justin Crawford <Justin@intellivoid.net>")
set(CPACK_PACKAGE_DESCRIPTION ${CMAKE_PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_HOMEPAGE_URL "https://intellivoid.net/")
set(CPACK_VERBATIM_VARIABLES true)
set(CPACK_STRIP_FILES TRUE)
set(CPACK_PACKAGE_VERSION_MAJOR ${CMAKE_PROJECT_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${CMAKE_PROJECT_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${CMAKE_PROJECT_VERSION_PATCH})
include(CPack)

