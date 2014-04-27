cmake_minimum_required (VERSION 2.6)
project (pam_twofactor_auth)

set(sources
pam_twofactor_auth.cpp
)

set(headers
pam_twofactor_auth.h
)

add_library(pam_twofactor_auth SHARED ${sources} ${headers})
set_target_properties(pam_twofactor_auth PROPERTIES PREFIX "")
