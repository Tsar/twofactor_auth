#include "pam_twofactor_auth.h"

#include <syslog.h>
#include <security/pam_ext.h>

#include <iostream>
#include <fstream>
#include <boost/unordered_map.hpp>

typedef boost::unordered_map<std::string, std::string> U2SN_MAP_TYPE;

bool isThereDeviceWithSerial(std::string const& sn, std::string& dev) {
    // TODO: implement this function

    return false;
}

bool loadUserToSNMap(U2SN_MAP_TYPE& u2sn) {
    std::ifstream f("/etc/u2sn");
    if (!f.good())
        return false;
    std::string u, sn;
    while (f.good()) {
        f >> u >> sn;
        u2sn.insert(std::make_pair(u, sn));
    }
    f.close();
    return true;
}

void printErrorToCErrAndPamSyslog(pam_handle_t* pamh, std::string const& errMsg) {
    std::cerr << "pam_twofactor_auth: " << errMsg << std::endl;
    pam_syslog(pamh, LOG_ERR, "%s", errMsg.c_str());
}

int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    //return PAM_SUCCESS;

    // TODO: maybe wait for any UDB device to be connected here?

    const char* user;
    int res = pam_get_user(pamh, &user, 0);
    if (res != PAM_SUCCESS) {
        printErrorToCErrAndPamSyslog(pamh, std::string("pam_get_user() failed: ") + pam_strerror(pamh, res));
        return PAM_USER_UNKNOWN;
    }

    U2SN_MAP_TYPE u2sn;
    if (!loadUserToSNMap(u2sn)) {
        printErrorToCErrAndPamSyslog(pamh, "Load of user-to-serial-number map failed");
        return PAM_AUTHINFO_UNAVAIL;
    }

    U2SN_MAP_TYPE::const_iterator it = u2sn.find(user);
    if (it == u2sn.end()) {
        printErrorToCErrAndPamSyslog(pamh, std::string("No user '") + user + "' in user-to-serial-number map");
        return PAM_USER_UNKNOWN;
    }

    std::string sn = it->second;
    std::string dev;
    if (!isThereDeviceWithSerial(sn, dev)) {
        printErrorToCErrAndPamSyslog(pamh, "No device with serial number '" + sn + "' is connected");
        return PAM_CRED_INSUFFICIENT;
    }

    // TODO: everything else

    //pam_get_authtok()

    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

#ifdef PAM_STATIC
struct pam_module _pam_unix_auth_modstruct = {
    "pam_twofactor_auth",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL,
};
#endif
