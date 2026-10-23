cmake_minimum_required(VERSION 3.16)
project(TrafficSNF VERSION 0.1.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Настройки C++ и Qt генераторов
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ---------------------------------------------------------------------------
# Поиск Qt 6
# ---------------------------------------------------------------------------
find_package(Qt6 6.2 REQUIRED COMPONENTS Core Gui Widgets)

# ---------------------------------------------------------------------------
# Поиск Npcap / libpcap (с автопоиском в типичных путях на Windows)
# ---------------------------------------------------------------------------
find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h pcap/pcap.h
    HINTS 
        ${PCAP_ROOT} 
        ENV PCAP_ROOT
        "C:/npcap-sdk"
        "C:/Program Files/Npcap SDK"
    PATH_SUFFIXES include Include
)

find_library(PCAP_LIBRARY
    NAMES wpcap pcap
    HINTS 
        ${PCAP_ROOT} 
        ENV PCAP_ROOT
        "C:/npcap-sdk"
        "C:/Program Files/Npcap SDK"
    PATH_SUFFIXES lib/x64 Lib/x64 lib Lib
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
    REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR
)

if(NOT PCAP_FOUND)
    message(FATAL_ERROR
        "Npcap SDK / libpcap не найден!\n"
        "1. Скачай Npcap SDK (zip) с https://npcap.com/#download\n"
        "2. Распакуй, например, в 'C:/npcap-sdk'\n"
        "3. Или передай путь через CMake: -DPCAP_ROOT=C:/твой/путь/к/sdk"
    )
endif()

add_library(pcap_imported UNKNOWN IMPORTED)
set_target_properties(pcap_imported PROPERTIES
    IMPORTED_LOCATION             "${PCAP_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
)

# ---------------------------------------------------------------------------
# Таргет приложения
# ---------------------------------------------------------------------------
add_executable(TrafficSNF
    src/main.cpp
    src/mainwindow.h
    src/mainwindow.cpp
    src/mainwindow.ui
    src/core/packet_types.h
    src/core/sniffer_worker.h
    src/core/sniffer_worker.cpp
)

target_include_directories(TrafficSNF PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core
)

target_link_libraries(TrafficSNF PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    pcap_imported
)

if(WIN32)
    # На Windows для работы с сокетами и пакетами линкуем ws2_32
    target_link_libraries(TrafficSNF PRIVATE ws2_32)
endif()

target_compile_definitions(TrafficSNF PRIVATE QT_DISABLE_DEPRECATED_BEFORE=0x060000)

if(MSVC)
    target_compile_options(TrafficSNF PRIVATE /W4 /permissive-)
else()
    target_compile_options(TrafficSNF PRIVATE -Wall -Wextra)
endif()