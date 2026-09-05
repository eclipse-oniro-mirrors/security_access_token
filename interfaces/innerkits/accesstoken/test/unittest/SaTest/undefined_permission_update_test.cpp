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
#include <chrono>
#include <cstdio>
#include <fstream>
#include <memory>
#include <sstream>
#include <thread>

#include "access_token.h"
#include "access_token_basic_type.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "iservice_registry.h"
#include "permission_def.h"
#include "permission_map.h"
#include "permission_state_full.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_predicates.h"
#include "rdb_store.h"
#include "system_ability_definition.h"
#include "test_common.h"
#include "token_setproc.h"
#include "transaction.h"
#include "values_bucket.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* PERM_DEFINITION_EXT_FILE = "/system/etc/access_token/accesstoken_permission_definition_ext.txt";
constexpr const char* ACCESS_TOKEN_DB_PATH = "/data/service/el1/public/access_token/access_token.db";
constexpr const char* PERM_DEF_VERSION_NAME = "permission_definition_version";
constexpr const char* SYSTEM_CONFIG_TABLE = "system_config_table";
constexpr const char* TEST_BUNDLE_NAME = "perm_definition_ext_test_bundle";
constexpr int32_t ACCESS_TOKEN_DB_VERSION = 11;
constexpr int32_t ACCESS_TOKEN_DB_CLEAR_MEMORY_SIZE = 4;
constexpr int32_t LOAD_SA_TIMEOUT_MS = 10000;
constexpr uint32_t WAIT_SLEEP_MS = 200;
constexpr uint32_t MAX_WAIT_MS = 20 * 1000;
}

class TestRdbOpenCallback : public NativeRdb::RdbOpenCallback {
public:
    int32_t OnCreate(NativeRdb::RdbStore& rdbStore) override
    {
        (void)rdbStore;
        return NativeRdb::E_OK;
    }

    int32_t OnUpgrade(NativeRdb::RdbStore& rdbStore, int32_t currentVersion, int32_t targetVersion) override
    {
        (void)rdbStore;
        (void)currentVersion;
        (void)targetVersion;
        return NativeRdb::E_OK;
    }
};

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

class PermDefinitionExtFileGuard {
public:
    explicit PermDefinitionExtFileGuard(const std::string& path) : path_(path)
    {
        existed_ = IsFileExist(path_);
        if (existed_) {
            existed_ = ReadFileContent(path_, originalContent_);
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

    bool Restore()
    {
        if (restored_) {
            return true;
        }
        if (existed_) {
            restored_ = WriteFileContent(path_, originalContent_);
        } else {
            restored_ = (remove(path_.c_str()) == 0);
        }
        return restored_;
    }

    PermDefinitionExtFileGuard(const PermDefinitionExtFileGuard&) = delete;
    PermDefinitionExtFileGuard& operator=(const PermDefinitionExtFileGuard&) = delete;

private:
    std::string path_;
    bool existed_ = false;
    std::string originalContent_;
    bool restored_ = false;
};

static bool SetPermissionDefinitionVersion(const std::string& version)
{
    NativeRdb::RdbStoreConfig config(ACCESS_TOKEN_DB_PATH);
    (void)config.SetBundleName("access_token");
    config.SetLocalOnly(true);
    config.SetSecurityLevel(NativeRdb::SecurityLevel::S3);
    config.SetAllowRebuild(true);
    config.SetHaMode(NativeRdb::HAMode::MAIN_REPLICA);
    config.SetClearMemorySize(ACCESS_TOKEN_DB_CLEAR_MEMORY_SIZE);

    int32_t errCode = NativeRdb::E_OK;
    TestRdbOpenCallback callback;
    std::shared_ptr<NativeRdb::RdbStore> store =
        NativeRdb::RdbHelper::GetRdbStore(config, ACCESS_TOKEN_DB_VERSION, callback, errCode);
    if (store == nullptr || errCode != NativeRdb::E_OK) {
        return false;
    }

    NativeRdb::RdbPredicates deletePredicates(SYSTEM_CONFIG_TABLE);
    deletePredicates.EqualTo("name", PERM_DEF_VERSION_NAME);
    NativeRdb::ValuesBucket addValue;
    addValue.PutString("name", PERM_DEF_VERSION_NAME);
    addValue.PutString("value", version);

    auto transactionResult = store->CreateTransaction(NativeRdb::Transaction::DEFERRED);
    if (transactionResult.second == nullptr || transactionResult.first != NativeRdb::E_OK) {
        return false;
    }
    auto deleteResult = transactionResult.second->Delete(deletePredicates);
    if (deleteResult.first != NativeRdb::E_OK) {
        transactionResult.second->Rollback();
        return false;
    }
    std::vector<NativeRdb::ValuesBucket> buckets;
    buckets.emplace_back(addValue);
    auto insertResult = transactionResult.second->BatchInsert(SYSTEM_CONFIG_TABLE, buckets);
    if (insertResult.first != NativeRdb::E_OK || insertResult.second <= 0) {
        transactionResult.second->Rollback();
        return false;
    }
    return transactionResult.second->Commit() == NativeRdb::E_OK;
}

static bool RestartAccesstokenService()
{
    MockNativeToken mock("accesstoken_service");
    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return false;
    }
    int32_t unloadRet = samgr->UnloadSystemAbility(ACCESS_TOKEN_MANAGER_SERVICE_ID);
    if (unloadRet != 0) {
        LOGW(ATM_DOMAIN, ATM_TAG, "UnloadSystemAbility failed, ret=%{public}d.", unloadRet);
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
        if (TestCommon::GetNativeTokenIdFromProcess("accesstoken_service") != INVALID_TOKENID) {
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

    std::string newContent = fileGuard.GetOriginalContent();
    if (!newContent.empty() && newContent.back() != '\n') {
        newContent.push_back('\n');
    }
    newContent.append(permissionA);
    newContent.push_back('\n');
    ASSERT_TRUE(WriteFileContent(PERM_DEFINITION_EXT_FILE, newContent));

    ASSERT_TRUE(SetPermissionDefinitionVersion("0"));

    ASSERT_TRUE(RestartAccesstokenService());
    ASSERT_TRUE(WaitForAccessTokenServiceReady());
    EXPECT_EQ(PERMISSION_GRANTED, AccessTokenKit::VerifyAccessToken(g_installedTokenId, permissionA));

    ASSERT_TRUE(fileGuard.Restore());

    ASSERT_TRUE(RestartAccesstokenService());
    ASSERT_TRUE(WaitForAccessTokenServiceReady());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
