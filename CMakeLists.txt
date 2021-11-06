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

project(pam_intellivoid
		VERSION 1.0.0
		DESCRIPTION "Pluggable Authentication Module (PAM) for Intrusion Detection and Warnings on intellivoid production servers"
		LANGUAGES CXX C
	)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wshadow -fPIC -Wsign-conversion -Wfloat-conversion -Wsign-compare -Wno-unused-parameter -Wno-unused-result -Wimplicit-fallthrough -rdynamic -fvisibility=hidden")

# Hardening
add_definitions(-D_FORTIFY_SOURCE=2)

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

# Make all the projects available
FetchContent_MakeAvailable(embedFiglet)

# Add our include directories
include_directories(
	${CMAKE_SOURCE_DIR}/src
	${CMAKE_BINARY_DIR}
	${PAM_INCLUDE_DIR}
	${embedFiglet_SOURCE_DIR}/src/
)

set_source_files_properties(${SOURCE_FILES} PROPERTIES LANGUAGE CXX)

add_library(${PROJECT_NAME} MODULE src/pam_sysinfo.cpp src/libTitanium.cpp)

set_target_properties(${PROJECT_NAME}
	PROPERTIES
		LINKER_LANGUAGE CXX
		PREFIX ""
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

target_link_libraries(${PROJECT_NAME} ${PAM_LIBRARIES} embedFiglet_linux_static)

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

