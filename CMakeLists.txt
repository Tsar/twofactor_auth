cmake_minimum_required (VERSION 2.6)
project (pam_twofactor_auth)


# PAM two factor auth module

set(ptfa_sources
pam_twofactor_auth.cpp
encoding.cpp
)

set(ptfa_headers
pam_twofactor_auth.h
encoding.h
)

add_library(pam_twofactor_auth SHARED ${ptfa_sources} ${ptfa_headers})
target_link_libraries(pam_twofactor_auth crypto)
set_target_properties(pam_twofactor_auth PROPERTIES PREFIX "")


# AES generator

set(aesgen_sources
aes_generate.cpp
encoding.cpp
)

set(aesgen_headers
encoding.h
)

add_executable(aes_generate ${aesgen_sources} ${aesgen_headers})
target_link_libraries(aes_generate crypto)
