cmake_minimum_required(VERSION 3.6)
project(PacketAnalyzer)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES
        src/funkcje.c
        src/funkcje.h
        src/naglowki.h
        src/PacketAnalyzer.c)

add_executable(PacketAnalyzer ${SOURCE_FILES})
