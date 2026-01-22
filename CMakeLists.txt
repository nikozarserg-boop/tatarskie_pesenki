cmake_minimum_required(VERSION 3.16)
project(CPPProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB SOURCES "src/*.cpp")

if(WIN32)
    set(RESOURCES "src/app.rc")
else()
    set(RESOURCES "")
endif()

# Добавляем модуль безопасности
list(APPEND SOURCES "src/security.cpp")

if(WIN32)
    add_executable(tatarskiespesenki WIN32 ${SOURCES} ${RESOURCES})
else()
    add_executable(tatarskiespesenki ${SOURCES} ${RESOURCES})
endif()

# Линкуем библиотеки для каждой платформы
if(WIN32)
    target_link_libraries(tatarskiespesenki PRIVATE ntdll gdi32 user32)
elseif(APPLE)
    target_link_libraries(tatarskiespesenki PRIVATE "-framework Cocoa" "-framework CoreGraphics")
else()
    # Linux - ищем X11
    find_package(X11 REQUIRED)
    target_link_libraries(tatarskiespesenki PRIVATE ${X11_LIBRARIES})
    include_directories(${X11_INCLUDE_DIR})
endif()

set_target_properties(tatarskiespesenki PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(WIN32)
    add_custom_command(TARGET tatarskiespesenki POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E rename
        "${CMAKE_BINARY_DIR}/bin/tatarskiespesenki.exe"
        "${CMAKE_BINARY_DIR}/bin/tatarskie_pesenki.exe"
    )
    add_custom_command(TARGET tatarskiespesenki POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
        "${CMAKE_BINARY_DIR}/bin/tatarskie_pesenki.exe"
        "${CMAKE_BINARY_DIR}/../dist/tatarskie_pesenki.exe"
    )
else()
    add_custom_command(TARGET tatarskiespesenki POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E rename
        "${CMAKE_BINARY_DIR}/bin/tatarskiespesenki"
        "${CMAKE_BINARY_DIR}/bin/tatarskie_pesenki"
    )
endif()
