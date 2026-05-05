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

#include "accesstoken_manager_service_test.h"

#include <algorithm>
#include <unistd.h>

#include "access_token_error.h"
#include "accesstoken_info_manager.h"
#include "claw_auth_info_parcel.h"
#include "claw_ticket_manager.h"
#include "claw_token_info_manager.h"
#include "cli_info_parcel.h"
#include "cli_permissions_result_parcel.h"
#include "generic_values.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "permission_dialog_result_parcel.h"
#include "permission_map_fence.h"
#include "saf_agent_fence.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t USER_ID = 100;
constexpr int32_t INST_INDEX = 0;
constexpr int32_t API_VERSION_9 = 9;
const std::string DEFAULT_AGENT_ID = "1001";
const std::string CUSTOM_SCREEN_CAPTURE = "ohos.permission.CUSTOM_SCREEN_CAPTURE";
const std::string ACCESS_SYSTEM_SETTINGS = "ohos.permission.ACCESS_SYSTEM_SETTINGS";
const std::string LOCATION_PERMISSION = "ohos.permission.LOCATION";
const std::string WIFI_PERMISSION = "ohos.permission.GET_WIFI_INFO";
const std::string CAMERA_PERMISSION = "ohos.permission.CAMERA";
const std::string MICROPHONE_PERMISSION = "ohos.permission.MICROPHONE";
const std::string AUDIO_PERMISSION = "ohos.permission.MANAGE_AUDIO_CONFIG";
const std::string PUSH_PERMISSION = "ohos.permission.ACCESS_PUSH_SERVICE";
const std::string KERNEL_PLUGIN_PERMISSION = "ohos.permission.kernel.SUPPORT_PLUGIN";
const std::string WRITE_CALENDAR_PERMISSION = "ohos.permission.WRITE_CALENDAR";

PermissionStatus BuildStatus(const std::string& name, int grantStatus, uint32_t flag)
{
    return { .permissionName = name, .grantStatus = grantStatus, .grantFlag = flag };
}

PermissionStatus BuildGrantedStatus(const std::string& name, uint32_t flag = PERMISSION_USER_SET)
{
    return BuildStatus(name, PERMISSION_GRANTED, flag);
}

PermissionStatus BuildDeniedStatus(const std::string& name, uint32_t flag = PERMISSION_USER_FIXED)
{
    return BuildStatus(name, PERMISSION_DENIED, flag);
}

PermissionStatus BuildInitialStatus(const std::string& name)
{
    return BuildStatus(name, PERMISSION_DENIED, PERMISSION_DEFAULT_FLAG);
}

PermissionStatus BuildAllowThisTimeStatus(const std::string& name)
{
    return BuildStatus(name, PERMISSION_GRANTED, PERMISSION_ALLOW_THIS_TIME);
}

std::vector<std::string> BuildMockTypeARuntimePermissions()
{
    return {
        LOCATION_PERMISSION,
        WIFI_PERMISSION,
        CAMERA_PERMISSION,
        MICROPHONE_PERMISSION,
        AUDIO_PERMISSION,
        PUSH_PERMISSION,
        KERNEL_PLUGIN_PERMISSION,
    };
}

std::map<std::string, std::vector<std::string>> BuildCliRuntimeMockMap()
{
        return {
        { CUSTOM_SCREEN_CAPTURE, BuildMockTypeARuntimePermissions() },
        { ACCESS_SYSTEM_SETTINGS, { ACCESS_SYSTEM_SETTINGS } },
    };
}

std::map<std::string, std::vector<std::string>> BuildCliCommandMockMap()
{
    return {
        { "location:query", { CUSTOM_SCREEN_CAPTURE } },
        { "settings:set", { ACCESS_SYSTEM_SETTINGS } },
        { "camera:capture", { CAMERA_PERMISSION } },
    };
}

CliInfo BuildCliInfo(const std::string& cliName, const std::string& subCliName)
{
    return { .cliName = cliName, .subCliName = subCliName };
}

CliInfoParcel BuildCliInfoParcel(const std::string& cliName, const std::string& subCliName)
{
    CliInfoParcel parcel;
    parcel.cliInfo = BuildCliInfo(cliName, subCliName);
    return parcel;
}

CliAuthInfoParcel BuildCliAuthInfoParcel(
    const CliInfo& cliInfo, const std::vector<std::string>& permissions, const std::vector<bool>& results)
{
    CliAuthInfoParcel parcel;
    parcel.info.cliInfo = cliInfo;
    parcel.info.permissionNames = permissions;
    parcel.info.authorizationResults = results;
    return parcel;
}

uint64_t CreateServiceTestToken(
    const std::string& bundleName, bool isSystemApp, const std::vector<PermissionStatus>& permStates,
    AccessTokenID& tokenId)
{
    HapInfoParams hapInfo = {
        .userID = USER_ID,
        .bundleName = bundleName,
        .instIndex = INST_INDEX,
        .dlpType = static_cast<int>(HapDlpType::DLP_COMMON),
        .apiVersion = API_VERSION_9,
        .isSystemApp = isSystemApp,
        .appIDDesc = bundleName,
    };
    HapPolicy hapPolicy = { .apl = APL_SYSTEM_BASIC, .domain = "test.domain", .permStateList = permStates };
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        hapInfo, hapPolicy, tokenIdEx, undefValues);
    if (ret != RET_SUCCESS) {
        tokenId = INVALID_TOKENID;
        return 0;
    }
    tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    return tokenIdEx.tokenIDEx;
}

std::vector<PermissionStatus> BuildQueryPermissionStates()
{
    return { BuildGrantedStatus("ohos.permission.QUERY_TOOL_PERMISSIONS", PERMISSION_SYSTEM_FIXED) };
}

std::vector<PermissionStatus> BuildManagePermissionStates()
{
    return { BuildGrantedStatus("ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS", PERMISSION_SYSTEM_FIXED) };
}

std::vector<PermissionStatus> BuildQueryAndManagePermissionStates()
{
    return {
        BuildGrantedStatus("ohos.permission.QUERY_TOOL_PERMISSIONS", PERMISSION_SYSTEM_FIXED),
        BuildGrantedStatus("ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS", PERMISSION_SYSTEM_FIXED),
    };
}

bool ContainsPermission(const std::vector<std::string>& permissions, const std::string& permission)
{
    return std::find(permissions.begin(), permissions.end(), permission) != permissions.end();
}

std::vector<PermissionStatus> BuildMockTypeANoDialogStates()
{
        return {
        BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE),
        BuildDeniedStatus(LOCATION_PERMISSION),
        BuildGrantedStatus(WIFI_PERMISSION, PERMISSION_SYSTEM_FIXED),
        BuildGrantedStatus(CAMERA_PERMISSION, PERMISSION_SYSTEM_FIXED),
        BuildGrantedStatus(MICROPHONE_PERMISSION, PERMISSION_SYSTEM_FIXED),
        BuildGrantedStatus(AUDIO_PERMISSION, PERMISSION_SYSTEM_FIXED),
        BuildDeniedStatus(PUSH_PERMISSION, PERMISSION_FIXED_FOR_SECURITY_POLICY),
        BuildGrantedStatus(KERNEL_PLUGIN_PERMISSION, PERMISSION_SYSTEM_FIXED),
    };
}

std::vector<PermissionStatus> BuildMockTypeADeniedOnlyStates()
{
    auto permStates = BuildMockTypeANoDialogStates();
    for (auto& permission : permStates) {
        if (permission.permissionName == PUSH_PERMISSION) {
            permission = BuildGrantedStatus(PUSH_PERMISSION, PERMISSION_SYSTEM_FIXED);
        }
    }
    return permStates;
}

std::vector<PermissionStatus> BuildMockTypeARestrictedOnlyStates()
{
    auto permStates = BuildMockTypeANoDialogStates();
    for (auto& permission : permStates) {
        if (permission.permissionName == LOCATION_PERMISSION) {
            permission = BuildGrantedStatus(LOCATION_PERMISSION, PERMISSION_SYSTEM_FIXED);
        }
    }
    return permStates;
}

class SelfTokenGuard final {
public:
    SelfTokenGuard() : tokenId_(GetSelfTokenID()) {}
    ~SelfTokenGuard()
    {
        SetSelfTokenID(tokenId_);
    }

private:
    uint64_t tokenId_;
};

class TokenCleaner final {
public:
    void Add(AccessTokenID tokenId)
    {
        if (tokenId != INVALID_TOKENID) {
            tokenIds_.emplace_back(tokenId);
        }
    }

    ~TokenCleaner()
    {
        for (auto tokenId : tokenIds_) {
            (void)AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId);
        }
    }

private:
    std::vector<AccessTokenID> tokenIds_;
};

void PrepareMockEnvironment(
    const std::map<std::string, std::vector<std::string>>& commandMap = BuildCliCommandMockMap())
{
    ResetMockCounter();
    SetMockCommandPermissionsForTest(commandMap);
    SetMockCliRuntimePermissionsForTest(BuildCliRuntimeMockMap());
}

PermissionDialogResultParcel QueryCliPermissionRequestInfo(
    AccessTokenManagerService& service, uint64_t callerTokenId, const std::vector<CliInfoParcel>& cliInfos)
{
    SelfTokenGuard guard;
    SetSelfTokenID(callerTokenId);
    PermissionDialogResultParcel result;
    EXPECT_EQ(RET_SUCCESS, service.GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, cliInfos, result));
    return result;
}

CliPermissionsResultParcel QueryCliPermissions(AccessTokenManagerService& service, uint64_t callerTokenId,
    AccessTokenID hostTokenId, const std::vector<CliInfoParcel>& cliInfos)
{
    SelfTokenGuard guard;
    SetSelfTokenID(callerTokenId);
    CliPermissionsResultParcel result;
    EXPECT_EQ(RET_SUCCESS, service.GetCliPermissions(hostTokenId, DEFAULT_AGENT_ID, cliInfos, result));
    return result;
}

ToolAuthResultParcel GenerateCliAuthResult(AccessTokenManagerService& service, uint64_t callerTokenId,
    AccessTokenID hostTokenId, const std::vector<CliAuthInfoParcel>& authInfos)
{
    SelfTokenGuard guard;
    SetSelfTokenID(callerTokenId);
    ToolAuthResultParcel result;
    EXPECT_EQ(RET_SUCCESS, service.GenerateCliAuthResult(hostTokenId, DEFAULT_AGENT_ID, authInfos, result));
    return result;
}

AccessTokenID InitCliToolToken(AccessTokenID hostTokenId, const std::string& challenge, const CliInfo& cliInfo,
    std::vector<std::string>& kernelPermList)
{
    CliInitInfo initInfo = { .hostTokenId = hostTokenId, .challenge = challenge, .cliInfo = cliInfo };
    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS,
        ToolTokenInfoManager::GetInstance().InitCliToken(initInfo, getpid(), tokenIdEx, kernelPermList));
    return tokenIdEx.tokenIdExStruct.tokenID;
}

void VerifyRuntimePermission(AccessTokenID tokenId, const std::string& permissionName, int32_t expected)
{
    EXPECT_EQ(expected, ToolTokenInfoManager::GetInstance().VerifyToolAccessToken(tokenId, permissionName));
}

void VerifyCliTokenBasics(
    AccessTokenID toolTokenId, AccessTokenID hostTokenId, const std::string& cliName, const std::string& subCliName)
{
    CliTokenInfo tokenInfo;
    ASSERT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().GetCliTokenInfo(toolTokenId, tokenInfo));
    EXPECT_EQ(hostTokenId, tokenInfo.hostTokenId);
    EXPECT_EQ(cliName, tokenInfo.cliName);
    EXPECT_EQ(subCliName, tokenInfo.subCliName);

    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    ASSERT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().GetHostTokenId(toolTokenId, queriedHostTokenId));
    EXPECT_EQ(hostTokenId, queriedHostTokenId);
}

void VerifyDirectMappingResult(AccessTokenManagerService& service, const std::vector<PermissionStatus>& hostPerms,
    const std::string& cliPermission, bool cliGranted, int32_t expected)
{
    AccessTokenID callerTokenId32 = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullCallerTokenId = CreateServiceTestToken(
        "tooltoken_three_dep_mock_caller", true, BuildManagePermissionStates(), callerTokenId32);
    uint64_t fullHostTokenId = CreateServiceTestToken("tooltoken_three_dep_mock_host", true, hostPerms, hostTokenId);
    ASSERT_NE(0, fullCallerTokenId);
    ASSERT_NE(0, fullHostTokenId);
    cleaner.Add(callerTokenId32);
    cleaner.Add(hostTokenId);

    auto authResult = GenerateCliAuthResult(service, fullCallerTokenId, hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { cliPermission }, { cliGranted }) });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    ASSERT_FALSE(authResult.result.authResults[0].empty());

    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        hostTokenId, authResult.result.authResults[0], BuildCliInfo("settings", "set"), kernelPermList);
    VerifyRuntimePermission(toolTokenId, cliPermission, expected);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}
} // namespace

class ToolTokenMockTest : public AccessTokenManagerServiceTest {
public:
    static void SetUpTestCase()
    {
        AccessTokenManagerServiceTest::SetUpTestCase();
    }

    static void TearDownTestCase()
    {
        AccessTokenManagerServiceTest::TearDownTestCase();
    }

    void SetUp() override
    {
        AccessTokenManagerServiceTest::SetUp();
        ClearMockCliRuntimePermissionsForTest();
        ResetMockCounter();
        (void)ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid());
    }

    void TearDown() override
    {
        ClearMockCliRuntimePermissionsForTest();
        ResetMockCounter();
        (void)ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid());
        AccessTokenManagerServiceTest::TearDown();
    }
};

/**
 * @tc.name: GetCliPermissionRequestInfo_003
 * @tc.desc: Test undeclared CLI Permission returns no-dialog not-declared detail.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_003, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_003", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(*atManagerService_, fullTokenId,
        { BuildCliInfoParcel("location", "query") });
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_FALSE(detail.needPermissionDialog);
    ASSERT_EQ(1, static_cast<int32_t>(detail.permissionNameList.size()));
    EXPECT_EQ(CUSTOM_SCREEN_CAPTURE, detail.permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(detail.statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED, detail.statusList[0]);
    EXPECT_TRUE(detail.authResult.empty());
}

/**
 * @tc.name: GetCliPermissionRequestInfo_004
 * @tc.desc: Test denied runtime permission is returned in dialog detail with challenge.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_004, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    for (const auto& permission : BuildMockTypeADeniedOnlyStates()) {
        permStates.emplace_back(permission);
    }
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_004", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(*atManagerService_, fullTokenId,
        { BuildCliInfoParcel("location", "query") });
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_FALSE(detail.needPermissionDialog);
    EXPECT_FALSE(detail.authResult.empty());
    ASSERT_EQ(1, static_cast<int32_t>(detail.permissionNameList.size()));
    EXPECT_EQ(LOCATION_PERMISSION, detail.permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(detail.statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_DENIED, detail.statusList[0]);
}

/**
 * @tc.name: GetCliPermissionRequestInfo_006
 * @tc.desc: Test undecided runtime permission triggers dialog and no auth result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_006, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE));
    permStates.emplace_back(BuildInitialStatus(CAMERA_PERMISSION));
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_006", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(*atManagerService_, fullTokenId,
        { BuildCliInfoParcel("location", "query") });
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_TRUE(detail.needPermissionDialog);
    EXPECT_TRUE(detail.authResult.empty());
    EXPECT_FALSE(ContainsPermission(detail.permissionNameList, CAMERA_PERMISSION));
}

/**
 * @tc.name: GetCliPermissionRequestInfo_009
 * @tc.desc: Test restricted runtime permission is returned in dialog detail.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_009, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    for (const auto& permission : BuildMockTypeARestrictedOnlyStates()) {
        permStates.emplace_back(permission);
    }
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_009", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(*atManagerService_, fullTokenId,
        { BuildCliInfoParcel("location", "query") });
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_FALSE(detail.needPermissionDialog);
    EXPECT_FALSE(detail.authResult.empty());
    ASSERT_EQ(1, static_cast<int32_t>(detail.permissionNameList.size()));
    EXPECT_EQ(PUSH_PERMISSION, detail.permissionNameList[0]);
    ASSERT_EQ(1, static_cast<int32_t>(detail.statusList.size()));
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_RESTRICTED, detail.statusList[0]);
}

/**
 * @tc.name: GetCliPermissionRequestInfo_011
 * @tc.desc: Test all resolved runtime permissions produce no dialog and non-empty auth result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_011, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE));
    for (const auto& permission : BuildMockTypeARuntimePermissions()) {
        permStates.emplace_back(BuildGrantedStatus(permission, PERMISSION_SYSTEM_FIXED));
    }
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_011", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(*atManagerService_, fullTokenId,
        { BuildCliInfoParcel("location", "query") });
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_FALSE(detail.needPermissionDialog);
    EXPECT_TRUE(detail.permissionNameList.empty());
    EXPECT_TRUE(detail.statusList.empty());
    EXPECT_FALSE(detail.authResult.empty());
}

/**
 * @tc.name: GetCliPermissionRequestInfo_013
 * @tc.desc: Test batch CLI details preserve order and independent auth results.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_013, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS));
    permStates.emplace_back(BuildInitialStatus(WRITE_CALENDAR_PERMISSION));
    for (const auto& permission : BuildMockTypeANoDialogStates()) {
        permStates.emplace_back(permission);
    }
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_013", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);
    auto commandMap = BuildCliCommandMockMap();
    commandMap["camera:capture"] = {WRITE_CALENDAR_PERMISSION};
    PrepareMockEnvironment(commandMap);

    auto result = QueryCliPermissionRequestInfo(*atManagerService_, fullTokenId, {
        BuildCliInfoParcel("settings", "set"),
        BuildCliInfoParcel("camera", "capture"),
        BuildCliInfoParcel("location", "query"),
    });
    ASSERT_EQ(3, static_cast<int32_t>(result.result.detailList.size()));
    EXPECT_FALSE(result.result.detailList[0].needPermissionDialog);
    EXPECT_TRUE(result.result.detailList[1].needPermissionDialog);
    EXPECT_FALSE(result.result.detailList[2].needPermissionDialog);
    EXPECT_FALSE(result.result.detailList[0].authResult.empty());
    EXPECT_TRUE(result.result.detailList[1].authResult.empty());
    EXPECT_FALSE(result.result.detailList[2].authResult.empty());
    EXPECT_NE(result.result.detailList[0].authResult, result.result.detailList[2].authResult);
}

/**
 * @tc.name: GetCliPermissionRequestInfo_014
 * @tc.desc: Test permissionNameList and statusList keep index alignment.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_014, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE));
    permStates.emplace_back(BuildDeniedStatus(LOCATION_PERMISSION));
    permStates.emplace_back(BuildDeniedStatus(PUSH_PERMISSION, PERMISSION_FIXED_FOR_SECURITY_POLICY));
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_014", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(*atManagerService_, fullTokenId,
        { BuildCliInfoParcel("location", "query") });
    const auto& detail = result.result.detailList[0];
    ASSERT_EQ(detail.permissionNameList.size(), detail.statusList.size());
    ASSERT_EQ(2, static_cast<int32_t>(detail.permissionNameList.size()));
    EXPECT_EQ(LOCATION_PERMISSION, detail.permissionNameList[0]);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_DENIED, detail.statusList[0]);
    EXPECT_EQ(PUSH_PERMISSION, detail.permissionNameList[1]);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_RESTRICTED, detail.statusList[1]);
}

/**
 * @tc.name: GetCliPermissionRequestInfo_015
 * @tc.desc: Test no-dialog authResult from prequery can be consumed by InitCliToken.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_015, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto permStates = BuildQueryPermissionStates();
    permStates.emplace_back(BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS, PERMISSION_SYSTEM_FIXED));
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_015", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(*atManagerService_, fullTokenId,
        { BuildCliInfoParcel("settings", "set") });
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_FALSE(detail.needPermissionDialog);
    EXPECT_TRUE(detail.permissionNameList.empty());
    EXPECT_TRUE(detail.statusList.empty());
    ASSERT_FALSE(detail.authResult.empty());

    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        tokenId, detail.authResult, BuildCliInfo("settings", "set"), kernelPermList);
    VerifyRuntimePermission(toolTokenId, ACCESS_SYSTEM_SETTINGS, PERMISSION_GRANTED);
    VerifyCliTokenBasics(toolTokenId, tokenId, "settings", "set");
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GetCliPermissionRequestInfo_016
 * @tc.desc: Test MockTypeA no-dialog authResult can be consumed by InitCliToken.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_016, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto permStates = BuildQueryPermissionStates();
    for (const auto& permission : BuildMockTypeANoDialogStates()) {
        permStates.emplace_back(permission);
    }
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_016", true, permStates, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(*atManagerService_, fullTokenId,
        { BuildCliInfoParcel("location", "query") });
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_FALSE(detail.needPermissionDialog);
    ASSERT_FALSE(detail.authResult.empty());
    ASSERT_EQ(2, static_cast<int32_t>(detail.permissionNameList.size()));
    EXPECT_EQ(LOCATION_PERMISSION, detail.permissionNameList[0]);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_DENIED, detail.statusList[0]);
    EXPECT_EQ(PUSH_PERMISSION, detail.permissionNameList[1]);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_RESTRICTED, detail.statusList[1]);

    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        tokenId, detail.authResult, BuildCliInfo("location", "query"), kernelPermList);
    VerifyRuntimePermission(toolTokenId, LOCATION_PERMISSION, PERMISSION_DENIED);
    VerifyRuntimePermission(toolTokenId, WIFI_PERMISSION, PERMISSION_GRANTED);
    VerifyRuntimePermission(toolTokenId, CAMERA_PERMISSION, PERMISSION_GRANTED);
    VerifyRuntimePermission(toolTokenId, MICROPHONE_PERMISSION, PERMISSION_GRANTED);
    VerifyRuntimePermission(toolTokenId, AUDIO_PERMISSION, PERMISSION_GRANTED);
    VerifyRuntimePermission(toolTokenId, PUSH_PERMISSION, PERMISSION_DENIED);
    EXPECT_TRUE(ContainsPermission(kernelPermList, KERNEL_PLUGIN_PERMISSION));
    VerifyCliTokenBasics(toolTokenId, tokenId, "location", "query");
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GetCliPermissions_006
 * @tc.desc: Test undeclared CLI Permission and granted self-mapped system permission in one batch.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_006, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_006_caller", true, BuildManagePermissionStates(), callerTokenId);
    auto hostPerms = std::vector<PermissionStatus> { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_006_host", true, hostPerms, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(*atManagerService_, callerFullTokenId, hostTokenId, {
        BuildCliInfoParcel("location", "query"),
        BuildCliInfoParcel("settings", "set"),
    });
    ASSERT_EQ(2, static_cast<int32_t>(result.result.permList.size()));
    const auto& detail0 = result.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ(CUSTOM_SCREEN_CAPTURE, detail0.requiredCliPermission);
    EXPECT_EQ((PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED), detail0.cliPermissionStatus);
    EXPECT_TRUE(detail0.usedPermissions.empty());
    const auto& detail1 = result.result.permList[1].requiredCliPermissions[0];
    EXPECT_EQ(ACCESS_SYSTEM_SETTINGS, detail1.requiredCliPermission);
    EXPECT_EQ((PermissionDecisionStatus::NO_DIALOG_GRANTED), detail1.cliPermissionStatus);
}

/**
 * @tc.name: GetCliPermissions_008
 * @tc.desc: Test MockTypeA returns full usedPermissions list with granted CLI Permission.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_008, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_008_caller", true, BuildManagePermissionStates(), callerTokenId);
    auto hostPerms = std::vector<PermissionStatus> { BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE) };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_008_host", true, hostPerms, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(*atManagerService_, callerFullTokenId, hostTokenId,
        { BuildCliInfoParcel("location", "query") });
    const auto& detail = result.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ((PermissionDecisionStatus::NO_DIALOG_GRANTED), detail.cliPermissionStatus);
    EXPECT_EQ(BuildMockTypeARuntimePermissions(), detail.usedPermissions);
}

/**
 * @tc.name: GetCliPermissions_009
 * @tc.desc: Test MockTypeA returns NEED_PERMISSION_DIALOG when a runtime permission is undecided.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_009, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_009_caller", true, BuildManagePermissionStates(), callerTokenId);
    auto hostPerms = std::vector<PermissionStatus> {
        BuildAllowThisTimeStatus(CUSTOM_SCREEN_CAPTURE),
        BuildDeniedStatus(LOCATION_PERMISSION),
        BuildGrantedStatus(WIFI_PERMISSION),
        BuildInitialStatus(CAMERA_PERMISSION),
        BuildDeniedStatus(PUSH_PERMISSION, PERMISSION_FIXED_FOR_SECURITY_POLICY),
    };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_009_host", true, hostPerms, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(*atManagerService_, callerFullTokenId, hostTokenId,
        { BuildCliInfoParcel("location", "query") });
    const auto& detail = result.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ((PermissionDecisionStatus::NEED_PERMISSION_DIALOG), detail.cliPermissionStatus);
    EXPECT_EQ(BuildMockTypeARuntimePermissions(), detail.usedPermissions);
}

/**
 * @tc.name: GetCliPermissions_013
 * @tc.desc: Test allow-this-time CLI Permission resolves to NO_DIALOG_CLI_PERMISSION_RESOLVED.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_013, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_013_caller", true, BuildManagePermissionStates(), callerTokenId);
    auto hostPerms = std::vector<PermissionStatus> { BuildAllowThisTimeStatus(CUSTOM_SCREEN_CAPTURE) };
    for (const auto& permission : BuildMockTypeARuntimePermissions()) {
        hostPerms.emplace_back(BuildGrantedStatus(permission, PERMISSION_SYSTEM_FIXED));
    }
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_013_host", true, hostPerms, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(*atManagerService_, callerFullTokenId, hostTokenId,
        { BuildCliInfoParcel("location", "query") });
    const auto& detail = result.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ((PermissionDecisionStatus::NO_DIALOG_CLI_PERMISSION_RESOLVED),
        detail.cliPermissionStatus);
    EXPECT_EQ(BuildMockTypeARuntimePermissions(), detail.usedPermissions);
}

/**
 * @tc.name: GetCliPermissions_016
 * @tc.desc: Test batch CLI permission results preserve order and content.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_016, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_016_caller", true, BuildManagePermissionStates(), callerTokenId);
    auto hostPerms = std::vector<PermissionStatus> {
        BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS),
        BuildInitialStatus(CAMERA_PERMISSION),
        BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE),
        BuildDeniedStatus(LOCATION_PERMISSION),
    };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_016_host", true, hostPerms, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(*atManagerService_, callerFullTokenId, hostTokenId, {
        BuildCliInfoParcel("settings", "set"),
        BuildCliInfoParcel("camera", "capture"),
        BuildCliInfoParcel("location", "query"),
    });
    ASSERT_EQ(3, static_cast<int32_t>(result.result.permList.size()));
    EXPECT_EQ(ACCESS_SYSTEM_SETTINGS,
        result.result.permList[0].requiredCliPermissions[0].requiredCliPermission);
    EXPECT_EQ(CAMERA_PERMISSION, result.result.permList[1].requiredCliPermissions[0].requiredCliPermission);
    EXPECT_EQ(CUSTOM_SCREEN_CAPTURE, result.result.permList[2].requiredCliPermissions[0].requiredCliPermission);
}

/**
 * @tc.name: GenerateCliAuthResult_001
 * @tc.desc: Test MockTypeA with granted CLI Permission resolves mixed runtime permissions.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_001, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_001_caller", true, BuildManagePermissionStates(), callerTokenId);
    auto hostPerms = std::vector<PermissionStatus> {
        BuildDeniedStatus(LOCATION_PERMISSION),
        BuildGrantedStatus(WIFI_PERMISSION),
        BuildInitialStatus(CAMERA_PERMISSION),
        BuildDeniedStatus(PUSH_PERMISSION, PERMISSION_FIXED_FOR_SECURITY_POLICY),
    };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_001_host", true, hostPerms, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto authResult = GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("location", "query"), { CUSTOM_SCREEN_CAPTURE }, { true }) });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        hostTokenId, authResult.result.authResults[0], BuildCliInfo("location", "query"), kernelPermList);
    VerifyRuntimePermission(toolTokenId, LOCATION_PERMISSION, PERMISSION_DENIED);
    VerifyRuntimePermission(toolTokenId, WIFI_PERMISSION, PERMISSION_GRANTED);
    VerifyRuntimePermission(toolTokenId, CAMERA_PERMISSION, PERMISSION_GRANTED);
    VerifyRuntimePermission(toolTokenId, MICROPHONE_PERMISSION, PERMISSION_GRANTED);
    VerifyRuntimePermission(toolTokenId, AUDIO_PERMISSION, PERMISSION_GRANTED);
    VerifyRuntimePermission(toolTokenId, PUSH_PERMISSION, PERMISSION_DENIED);
    EXPECT_TRUE(ContainsPermission(kernelPermList, KERNEL_PLUGIN_PERMISSION));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GenerateCliAuthResult_002
 * @tc.desc: Test MockTypeA with denied CLI Permission keeps only no-dialog granted runtime permissions.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_002, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_002_caller", true, BuildManagePermissionStates(), callerTokenId);
    auto hostPerms = std::vector<PermissionStatus> {
        BuildDeniedStatus(LOCATION_PERMISSION),
        BuildGrantedStatus(WIFI_PERMISSION),
        BuildInitialStatus(CAMERA_PERMISSION),
        BuildDeniedStatus(PUSH_PERMISSION, PERMISSION_FIXED_FOR_SECURITY_POLICY),
    };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_002_host", true, hostPerms, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto authResult = GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("location", "query"), { CUSTOM_SCREEN_CAPTURE }, { false }) });
    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        hostTokenId, authResult.result.authResults[0], BuildCliInfo("location", "query"), kernelPermList);
    VerifyRuntimePermission(toolTokenId, LOCATION_PERMISSION, PERMISSION_DENIED);
    VerifyRuntimePermission(toolTokenId, WIFI_PERMISSION, PERMISSION_GRANTED);
    VerifyRuntimePermission(toolTokenId, CAMERA_PERMISSION, PERMISSION_DENIED);
    VerifyRuntimePermission(toolTokenId, MICROPHONE_PERMISSION, PERMISSION_DENIED);
    VerifyRuntimePermission(toolTokenId, AUDIO_PERMISSION, PERMISSION_DENIED);
    VerifyRuntimePermission(toolTokenId, PUSH_PERMISSION, PERMISSION_DENIED);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GenerateCliAuthResult_003
 * @tc.desc: Test self-mapped granted system permission remains granted.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_003, TestSize.Level1)
{
    VerifyDirectMappingResult(*atManagerService_,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, ACCESS_SYSTEM_SETTINGS, true, PERMISSION_GRANTED);
}

/**
 * @tc.name: GenerateCliAuthResult_004
 * @tc.desc: Test granted system permission is not downgraded by CLI denied result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_004, TestSize.Level1)
{
    VerifyDirectMappingResult(*atManagerService_,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, ACCESS_SYSTEM_SETTINGS, false, PERMISSION_GRANTED);
}

/**
 * @tc.name: GenerateCliAuthResult_005
 * @tc.desc: Test initial-state system permission follows granted CLI authorization result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_005, TestSize.Level1)
{
    VerifyDirectMappingResult(
        *atManagerService_, { BuildInitialStatus(CAMERA_PERMISSION) }, CAMERA_PERMISSION, true, PERMISSION_GRANTED);
}

/**
 * @tc.name: GenerateCliAuthResult_006
 * @tc.desc: Test initial-state system permission follows denied CLI authorization result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_006, TestSize.Level1)
{
    VerifyDirectMappingResult(
        *atManagerService_, { BuildInitialStatus(CAMERA_PERMISSION) }, CAMERA_PERMISSION, false, PERMISSION_DENIED);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
