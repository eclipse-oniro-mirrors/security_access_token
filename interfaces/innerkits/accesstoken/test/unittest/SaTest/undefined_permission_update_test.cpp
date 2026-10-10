/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "undefined_permission_update_test.h"

#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <memory>
#include <sched.h>
#include <csignal>
#include <sstream>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>

#include "access_token.h"
#include "access_token_basic_type.h"
#include "access_token_db_operator.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "atm_data_type.h"
#include "generic_values.h"
#include "hap_token_info.h"
#include "iservice_registry.h"
#include "permission_def.h"
#include "permission_map.h"
#include "permission_state_full.h"
#include "system_ability_definition.h"
#include "test_common.h"
#include "token_field_const.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* ACCESSTOKEN_SERVICE_PROCESS_NAME = "accesstoken_service";
constexpr const char* PERM_DEFINITION_EXT_FILE = "/system/etc/access_token/accesstoken_permission_definition_ext.txt";
constexpr const char* ACCESS_TOKEN_CONFIG_DIR = "/system/etc/access_token";
constexpr const char* RESET_PERM_DEF_VERSION = "0";
constexpr const char* TEST_BUNDLE_NAME = "perm_definition_ext_test_bundle";
constexpr int32_t LOAD_SA_TIMEOUT_MS = 10000;
constexpr uint32_t WAIT_SLEEP_MS = 200;
constexpr uint32_t MAX_WAIT_MS = 20 * 1000;
constexpr uint32_t WAIT_SERVICE_START_MS = 3 * 1000;
constexpr uint32_t WAIT_KILL_CHECK_MS = 100;
constexpr uint32_t TRY_KILL_TIMES = 4;
constexpr int32_t CHILD_EXIT_OPEN_NS_FAILED = 1;
constexpr int32_t CHILD_EXIT_SETNS_FAILED = 2;
constexpr int32_t CHILD_EXIT_MOUNT_FAILED = 3;
constexpr mode_t STAGING_DIR_MODE = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

constexpr const char* STAGING_DIR = "/data/service/el1/public/access_token/at_test_cfg";
constexpr const char* STAGING_EXT_FILE =
    "/data/service/el1/public/access_token/at_test_cfg/accesstoken_permission_definition_ext.txt";
}

static uint64_t g_selfTokenId = 0;
static AccessTokenID g_installedTokenId = INVALID_TOKENID;

static bool FindDisabledSystemGrantPermission(std::string& permissionName)
{
    size_t totalPermissions = GetDefPermissionsSize();
    for (uint32_t code = 0; code < totalPermissions; ++code) {
        std::string permission = TransferOpcodeToPermission(code);
        if (permission.empty()) {
            continue;
        }
        PermissionBriefDef briefDef;
        if (!GetPermissionBriefDef(permission, briefDef)) {
            continue;
        }
        if (briefDef.grantMode == GrantMode::SYSTEM_GRANT && !briefDef.isEnable) {
            permissionName = permission;
            return true;
        }
    }
    return false;
}

static bool IsFileExist(const std::string& path)
{
    return access(path.c_str(), F_OK) == 0;
}

static pid_t GetAccessTokenServicePid()
{
    DIR* dir = opendir("/proc");
    if (dir == nullptr) {
        return -1;
    }
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) {
            continue;
        }
        int pid = atoi(entry->d_name);
        if (pid <= 0) {
            continue;
        }
        std::string cmdlinePath = "/proc/" + std::to_string(pid) + "/cmdline";
        std::ifstream file(cmdlinePath);
        std::string cmdline;
        std::getline(file, cmdline, '\0');
        file.close();
        if (cmdline == ACCESSTOKEN_SERVICE_PROCESS_NAME) {
            closedir(dir);
            return static_cast<pid_t>(pid);
        }
    }
    closedir(dir);
    return -1;
}

static std::string GetProcRootPath(const std::string& basePath)
{
    pid_t pid = GetAccessTokenServicePid();
    if (pid > 0) {
        return "/proc/" + std::to_string(pid) + "/root" + basePath;
    }
    return basePath;
}

static bool BindMountInServiceNs(pid_t pid, const std::string& src, const std::string& dst, bool doMount)
{
    if (pid <= 0) {
        return false;
    }
    std::string nsPath = "/proc/" + std::to_string(pid) + "/ns/mnt";
    const char* nsPathC = nsPath.c_str();
    const char* srcC = src.c_str();
    const char* dstC = dst.c_str();

    pid_t child = fork();
    if (child < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "fork failed, errno=%{public}d.", errno);
        return false;
    }
    if (child == 0) {
        int targetFd = open(nsPathC, O_RDONLY | O_CLOEXEC);
        if (targetFd < 0) {
            LOGW(ATM_DOMAIN, ATM_TAG, "open ns failed: %{public}s, errno=%{public}d", nsPathC, errno);
            _exit(CHILD_EXIT_OPEN_NS_FAILED);
        }
        int setnsRet = setns(targetFd, CLONE_NEWNS);
        close(targetFd);
        if (setnsRet != 0) {
            LOGW(ATM_DOMAIN, ATM_TAG, "setns failed: %{public}s, errno=%{public}d", nsPathC, errno);
            _exit(CHILD_EXIT_SETNS_FAILED);
        }
        int ret;
        if (doMount) {
            ret = ::mount(srcC, dstC, nullptr, MS_BIND, nullptr);
            if (ret != 0) {
                LOGW(ATM_DOMAIN, ATM_TAG, "Bind mount failed: %{public}s -> %{public}s, errno=%{public}d",
                    srcC, dstC, errno);
            }
        } else {
            ret = umount(dstC);
            if (ret != 0) {
                LOGW(ATM_DOMAIN, ATM_TAG, "Unmount failed: %{public}s, errno=%{public}d", dstC, errno);
            }
        }
        _exit(ret == 0 ? EXIT_SUCCESS : CHILD_EXIT_MOUNT_FAILED);
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "waitpid failed, errno=%{public}d.", errno);
        return false;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool ReadFileContent(const std::string& path, std::string& content)
{
    std::ifstream file(path);
    if (!file.is_open()) {
        return false;
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    content = buffer.str();
    file.close();
    return true;
}

static bool WriteFileContent(const std::string& path, const std::string& content)
{
    std::ofstream file(path, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file << content;
    bool success = file.good();
    file.close();
    return success;
}

static bool CopyDirFlat(const std::string& srcDir, const std::string& dstDir)
{
    DIR* dir = opendir(srcDir.c_str());
    if (dir == nullptr) {
        return false;
    }
    struct dirent* entry;
    bool ok = true;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) {
            continue;
        }
        std::string srcFile = srcDir + "/" + entry->d_name;
        std::string dstFile = dstDir + "/" + entry->d_name;
        std::string content;
        if (!ReadFileContent(srcFile, content)) {
            ok = false;
            continue;
        }
        if (!WriteFileContent(dstFile, content)) {
            ok = false;
        }
    }
    closedir(dir);
    return ok;
}

static void CleanDirFlat(const std::string& dirPath)
{
    DIR* dir = opendir(dirPath.c_str());
    if (dir == nullptr) {
        return;
    }
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_REG) {
            continue;
        }
        std::string filePath = dirPath + "/" + entry->d_name;
        if (remove(filePath.c_str()) != 0 && errno != ENOENT) {
            LOGW(ATM_DOMAIN, ATM_TAG, "CleanDirFlat remove failed: %{public}s, errno=%{public}d.",
                filePath.c_str(), errno);
        }
    }
    closedir(dir);
}

class PermDefinitionExtFileGuard {
public:
    explicit PermDefinitionExtFileGuard(const std::string& extFilePath) : extFilePath_(extFilePath)
    {
        targetDir_ = ACCESS_TOKEN_CONFIG_DIR;
        stagingDir_ = STAGING_DIR;
        stagingExtFile_ = STAGING_EXT_FILE;

        std::string svcPath = GetProcRootPath(extFilePath_);
        existed_ = IsFileExist(svcPath);
        if (existed_) {
            existed_ = ReadFileContent(svcPath, originalContent_);
        }

        std::string svcDir = GetProcRootPath(targetDir_);
        if (remove(stagingDir_.c_str()) != 0 && errno != ENOENT) {
            LOGW(ATM_DOMAIN, ATM_TAG, "remove staging dir failed: %{public}s, errno=%{public}d.",
                stagingDir_.c_str(), errno);
        }
        if (mkdir(stagingDir_.c_str(), STAGING_DIR_MODE) != 0 && errno != EEXIST) {
            LOGW(ATM_DOMAIN, ATM_TAG, "mkdir staging dir failed: %{public}s, errno=%{public}d.",
                stagingDir_.c_str(), errno);
        }
        CopyDirFlat(svcDir, stagingDir_);
        WriteFileContent(stagingExtFile_, existed_ ? originalContent_ : std::string());

        pid_t pid = GetAccessTokenServicePid();
        mounted_ = BindMountInServiceNs(pid, stagingDir_, targetDir_, true);
        if (!mounted_) {
            LOGW(ATM_DOMAIN, ATM_TAG, "Failed to bind mount %{public}s to %{public}s in service namespace",
                stagingDir_.c_str(), targetDir_.c_str());
        }
    }

    ~PermDefinitionExtFileGuard()
    {
        Restore();
    }

    const std::string& GetOriginalContent() const
    {
        return originalContent_;
    }

    bool IsMounted() const
    {
        return mounted_;
    }

    bool Write(const std::string& content)
    {
        return WriteFileContent(stagingExtFile_, content);
    }

    bool Restore()
    {
        if (restored_) {
            return true;
        }
        WriteFileContent(stagingExtFile_, existed_ ? originalContent_ : std::string());
        if (mounted_) {
            pid_t pid = GetAccessTokenServicePid();
            mounted_ = !BindMountInServiceNs(pid, std::string(), targetDir_, false);
        }
        if (!mounted_) {
            CleanDirFlat(stagingDir_);
            rmdir(stagingDir_.c_str());
        }
        restored_ = !mounted_;
        return restored_;
    }

    PermDefinitionExtFileGuard(const PermDefinitionExtFileGuard&) = delete;
    PermDefinitionExtFileGuard& operator=(const PermDefinitionExtFileGuard&) = delete;

private:
    std::string extFilePath_;
    std::string targetDir_;
    std::string stagingDir_;
    std::string stagingExtFile_;
    bool existed_ = false;
    std::string originalContent_;
    bool mounted_ = false;
    bool restored_ = false;
};

static bool SetPermissionDefinitionVersion(const std::string& version)
{
    GenericValues delValue;
    delValue.Put(TokenFiledConst::FIELD_NAME, PERM_DEF_VERSION);
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_NAME, PERM_DEF_VERSION);
    addValue.Put(TokenFiledConst::FIELD_VALUE, version);
    DelInfo delInfo;
    delInfo.delType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    delInfo.delValue = delValue;
    AddInfo addInfo;
    addInfo.addType = AtmDataType::ACCESSTOKEN_SYSTEM_CONFIG;
    addInfo.addValues.emplace_back(addValue);
    return AccessTokenDbOperator::DeleteAndInsertValues({ delInfo }, { addInfo }) == RET_SUCCESS;
}

static bool RestartAccesstokenService()
{
    MockNativeToken mock(ACCESSTOKEN_SERVICE_PROCESS_NAME);
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    pid_t svcPid = GetAccessTokenServicePid();
    if (svcPid > 0) {
        kill(svcPid, SIGKILL);
        for (uint32_t i = 0; i < TRY_KILL_TIMES; ++i) {
            if (GetAccessTokenServicePid() != svcPid) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_KILL_CHECK_MS));
        }
    }
    sptr<IRemoteObject> object = samgr->LoadSystemAbility(ACCESS_TOKEN_MANAGER_SERVICE_ID, LOAD_SA_TIMEOUT_MS);
    return object != nullptr;
}

static bool WaitForAccessTokenServiceReady()
{
    uint32_t elapsedMs = 0;
    while (elapsedMs < MAX_WAIT_MS) {
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_SLEEP_MS));
        elapsedMs += WAIT_SLEEP_MS;
        if (TestCommon::GetNativeTokenIdFromProcess(ACCESSTOKEN_SERVICE_PROCESS_NAME) != INVALID_TOKENID) {
            return true;
        }
    }
    return false;
}

static AccessTokenID InstallSystemCoreHap(const std::string& permission)
{
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "perm_definition_ext_test_appid",
        .apiVersion = TestCommon::DEFAULT_API_VERSION,
        .isSystemApp = true,
        .appDistributionType = "debug",
    };

    PermissionStateFull permState = {
        .permissionName = permission,
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PERMISSION_GRANTED},
        .grantFlags = {PERMISSION_SYSTEM_FIXED},
    };

    HapPolicyParams policyParams = {
        .apl = APL_SYSTEM_CORE,
        .domain = "accesstoken_test_domain",
        .permList = {},
        .permStateList = { permState },
        .aclRequestedList = {},
        .preAuthorizationInfo = {},
    };

    AccessTokenIDEx tokenIdEx = {0};
    int32_t ret = TestCommon::AllocTestHapToken(infoParams, policyParams, tokenIdEx);
    if (ret != RET_SUCCESS) {
        return INVALID_TOKENID;
    }
    return tokenIdEx.tokenIdExStruct.tokenID;
}

void UndefinedPermissionUpdateTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);
}

void UndefinedPermissionUpdateTest::TearDownTestCase()
{
    if (g_installedTokenId != INVALID_TOKENID) {
        TestCommon::DeleteTestHapToken(g_installedTokenId);
        g_installedTokenId = INVALID_TOKENID;
    }
    SetSelfTokenID(g_selfTokenId);
    TestCommon::ResetTestEvironment();
}

void UndefinedPermissionUpdateTest::SetUp()
{}

void UndefinedPermissionUpdateTest::TearDown()
{}

/**
 * @tc.name: UndefinedPermissionUpdateTest001
 * @tc.desc: a disabled system_grant permission becomes an undefined permission after
 *           hap installation and stays denied; after it is enabled by
 *           permission_definition_ext, the permission_definition_version in
 *           system_config_table is reset to 0 and the service is restarted, the
 *           undefined permission is refreshed to granted.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(UndefinedPermissionUpdateTest, UndefinedPermissionUpdateTest001, TestSize.Level1)
{
    std::string permissionA;
    ASSERT_TRUE(FindDisabledSystemGrantPermission(permissionA));
    ASSERT_FALSE(permissionA.empty());
    LOGI(ATM_DOMAIN, ATM_TAG, "found disabled system_grant permission: %{public}s.", permissionA.c_str());

    g_installedTokenId = InstallSystemCoreHap(permissionA);
    ASSERT_NE(g_installedTokenId, INVALID_TOKENID);

    EXPECT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(g_installedTokenId, permissionA));

    PermDefinitionExtFileGuard fileGuard(PERM_DEFINITION_EXT_FILE);
    ASSERT_TRUE(fileGuard.IsMounted()) << "bind mount failed, service cannot see staging file edits";

    std::string newContent = fileGuard.GetOriginalContent();
    if (!newContent.empty() && newContent.back() != '\n') {
        newContent.push_back('\n');
    }
    newContent.append(permissionA);
    newContent.push_back('\n');
    ASSERT_TRUE(fileGuard.Write(newContent));

    ASSERT_TRUE(SetPermissionDefinitionVersion(RESET_PERM_DEF_VERSION));

    ASSERT_TRUE(RestartAccesstokenService());
    ASSERT_TRUE(WaitForAccessTokenServiceReady());

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_SERVICE_START_MS));
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(g_installedTokenId, permissionA));

    ASSERT_TRUE(fileGuard.Restore());

    ASSERT_TRUE(RestartAccesstokenService());
    ASSERT_TRUE(WaitForAccessTokenServiceReady());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
