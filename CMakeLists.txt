cmake_minimum_required (VERSION 2.6)
project (twofactor_auth)

set(sources
twofactor_auth.cpp
)

set(headers
twofactor_auth.h
)

add_library(twofactor_auth SHARED ${sources} ${headers})
