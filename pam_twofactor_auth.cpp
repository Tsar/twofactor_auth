#include "pam_twofactor_auth.h"

#include <syslog.h>
#include <security/pam_ext.h>

#include <stdlib.h>
#include <dirent.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <set>
#include <map>

typedef std::map<std::string, std::string> U2SN_MAP_TYPE;

bool startsWith(const std::string& str, const std::string& tmpl) {
    return str.length() >= tmpl.length() && str.substr(0, tmpl.length()) == tmpl;
}

std::string getDeviceBySerialNumber(std::string const& sn) {
    std::string path("/dev/disk/by-id");
    DIR* dirp = opendir(path.c_str());
    dirent* dp;
    std::string ans = "";
    while ((dp = readdir(dirp)) != NULL) {
        std::string str(dp->d_name);
        if (startsWith(str, "usb") && str.find(sn) != std::string::npos) {
            char buf[256];
            int len = readlink((path + "/" + str).c_str(), buf, 256);
            buf[len] = 0;
            realpath((path + "/" + buf).c_str(), buf);
            ans = std::string(buf);
            if (!(ans[ans.length() - 1] >= '0' && ans[ans.length() - 1] <= '9')) {
                break;
            }
        }
    }
    closedir(dirp);
    return ans;
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

bool askForPassword(pam_handle_t* pamh, std::string& password) {
    pam_conv* conv;

    int res = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    if (res != PAM_SUCCESS) {
        printErrorToCErrAndPamSyslog(pamh, std::string("pam_get_item() failed: ") + pam_strerror(pamh, res));
        return false;
    }
    if (conv == 0 || conv->conv == 0) {
        printErrorToCErrAndPamSyslog(pamh, "'conv' or 'conv->conv' is zero-pointer");
        return false;
    }

    pam_response* resp;
    pam_message* msg = new pam_message[1];
    msg[0].msg_style = PAM_PROMPT_ECHO_OFF;
    msg[0].msg = "Password for 'ptfa.key': ";

    res = conv->conv(1, (const pam_message**)&msg, &resp, conv->appdata_ptr);
    delete[] msg;
    if (res != PAM_SUCCESS) {
        printErrorToCErrAndPamSyslog(pamh, std::string("conv->conv failed: ") + pam_strerror(pamh, res));
        return false;
    }
    if (resp == 0 || resp[0].resp == 0) {
        printErrorToCErrAndPamSyslog(pamh, "'resp' or 'resp[0].resp' is zero-pointer");
        return false;
    }

    password = resp[0].resp;
    free(&resp[0]);

    return true;
}

int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char** argv) {
    //return PAM_SUCCESS;

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
    std::string dev = getDeviceBySerialNumber(sn);
    if (dev.length() == 0) {
        printErrorToCErrAndPamSyslog(pamh, "No device with serial number '" + sn + "' is connected");
        return PAM_CRED_INSUFFICIENT;
    }

    std::set<std::string> usbPartitions;
    DIR* devDir;
    if ((devDir = opendir("/dev/")) != 0) {
        dirent* devDirEntry;
        while ((devDirEntry = readdir(devDir)) != 0) {
            std::string fileName = std::string("/dev/") + devDirEntry->d_name;
            if (fileName.length() > dev.length() && startsWith(fileName, dev)) {
                usbPartitions.insert(fileName);
            }
        }
        closedir(devDir);
    } else {
        printErrorToCErrAndPamSyslog(pamh, "Error while trying to access '/dev' directory");
        return PAM_AUTHINFO_UNAVAIL;
    }

    if (usbPartitions.size() == 0) {
        usbPartitions.insert(dev);
    }

    bool keyFileFound = false;

    std::ifstream mtab("/etc/mtab");
    if (!mtab.good()) {
        printErrorToCErrAndPamSyslog(pamh, "Could not open '/etc/mtab', maybe it does not exist");
        return PAM_AUTHINFO_UNAVAIL;
    }
    while (mtab.good()) {
        std::string mtabLine, mtabDev, mtabMountPoint;
        getline(mtab, mtabLine);
        std::istringstream mtabLineISS(mtabLine);
        mtabLineISS >> mtabDev >> mtabMountPoint;
        if (usbPartitions.find(mtabDev) != usbPartitions.end()) {
            usbPartitions.erase(mtabDev);
            std::string keyFileName = mtabMountPoint + "/ptfa.key";
            if (std::ifstream(keyFileName.c_str()) != 0) {
                // TODO: read the key file

                keyFileFound = true;
                break;
            }
        }
    }
    mtab.close();

    if (!keyFileFound) {
        for (std::set<std::string>::const_iterator it = usbPartitions.begin(); it != usbPartitions.end(); ++it) {
            if (system("umount /tmp/ptfa_temporary_mount_point 2> /dev/null") == 0)
                system("rm -rf /tmp/ptfa_temporary_mount_point");

            system("mkdir /tmp/ptfa_temporary_mount_point");
            std::string mountCmd = "mount " + *it + " /tmp/ptfa_temporary_mount_point";
            int mountRes = system(mountCmd.c_str());
            if (mountRes != 0)
                continue;

            if (std::ifstream("/tmp/ptfa_temporary_mount_point/ptfa.key") != 0) {
                // TODO: read the key file

                keyFileFound = true;
                break;
            }
        }

        if (system("umount /tmp/ptfa_temporary_mount_point 2> /dev/null") == 0)
            system("rm -rf /tmp/ptfa_temporary_mount_point");
    }

    if (!keyFileFound) {
        printErrorToCErrAndPamSyslog(pamh, "No 'ptfa.key' file found on any accessible partition of '" + dev + "'");
        return PAM_CRED_INSUFFICIENT;
    }

    std::string password;
    if (!askForPassword(pamh, password)) {
        return PAM_AUTHINFO_UNAVAIL;
    }

    /**
      TODO:
       - decrypt key using password;
       - if decryption in previous step fails, than ask for password again until decryption is done successfully or number of tries is exceeded;
     */

    // Temporaty line for testing
    std::string decryptedKey = password;

    res = pam_set_item(pamh, PAM_AUTHTOK, decryptedKey.c_str());
    if (res != PAM_SUCCESS) {
        printErrorToCErrAndPamSyslog(pamh, "Failed to set auth token to decrypted key's value");
    }

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
