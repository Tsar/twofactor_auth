cmake_minimum_required (VERSION 2.6)
project (pam_twofactor_auth)


# PAM two factor auth module

set(ptfa_sources
pam_twofactor_auth.cpp
)

set(ptfa_headers
pam_twofactor_auth.h
)

add_library(pam_twofactor_auth SHARED ${ptfa_sources} ${ptfa_headers})
set_target_properties(pam_twofactor_auth PROPERTIES PREFIX "")


# AES generator

set(aesgen_sources
aes_generate.cpp
)

add_executable(aes_generate ${aesgen_sources})
target_link_libraries(aes_generate crypto)
