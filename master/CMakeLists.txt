cmake_minimum_required(VERSION 3.15)
project(SentinelDashboard)

# Tell CMake we are using C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Create the executable from dashboard.cpp
add_executable(dashboard dashboard.cpp)

# Link Windows libraries needed for window manipulation (User32)
target_link_libraries(dashboard PRIVATE user32.lib)

# CRITICAL: Force the compiler to drop the finished dashboard.exe 
# directly into your master folder!
set_target_properties(dashboard PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)