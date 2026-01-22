cmake_minimum_required(VERSION 3.16)
project(CPPProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ПОЛИМОРФИЗМ: ГЕНЕРАЦИЯ УНИКАЛЬНЫХ СИГНАТУР
include(cmake/GeneratePolymorphism.cmake)
generate_polymorphic_header("${CMAKE_BINARY_DIR}/polymorphic_config.h")

# Флаги удаления следов компилятора и отладочной информации
if(MSVC)
    # Для Microsoft Visual C++
    string(REGEX REPLACE "/DEBUG" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Oi /Ot /GL /Gm- /Gy /fp:fast /arch:AVX2")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /SUBSYSTEM:WINDOWS /LTCG /OPT:REF /OPT:ICF /STRIP")
elseif(MINGW)
    # Для MinGW на Windows
    # Оптимизация
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native")
    
    # Удаление debug информации и frame pointer
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fomit-frame-pointer")
    
    # Статическое линковние библиотек GCC и стандартной библиотеки C++
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
    
    # Предпочитаем статические библиотеки
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".lib" ${CMAKE_FIND_LIBRARY_SUFFIXES})
    
    # Инструменты линкера (удаление символов и мёртвого кода)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s -Wl,--gc-sections")
else()
    # Для GCC и Clang на Linux/macOS
    # Оптимизация
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native")
    
    # Удаление debug информации и frame pointer
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fomit-frame-pointer")
    
    # Полное статическое линковние всех библиотек
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc -static-libstdc++")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    
    # Предпочитаем статические библиотеки
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".lib" ${CMAKE_FIND_LIBRARY_SUFFIXES})
    
    # Удаление версионной информации и комментариев
    if(UNIX AND NOT APPLE)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wl,--strip-debug -Wl,--remove-section=.comment -Wl,--remove-section=.note*")
    endif()
    
    # Инструменты линкера (удаление символов и мёртвого кода)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -s -Wl,--gc-sections")
endif()

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR})

file(GLOB SOURCES "src/*.cpp")

if(WIN32)
    set(RESOURCES "src/app.rc")
else()
    set(RESOURCES "")
endif()

# Добавляем модуль безопасности и отключения монитора
list(APPEND SOURCES "src/security.cpp")
list(APPEND SOURCES "src/TurnOffMonitor.cpp")

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
