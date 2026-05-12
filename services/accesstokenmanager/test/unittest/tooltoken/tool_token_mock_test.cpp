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
#include "permission_map.h"
#include "permission_map_fence.h"
#include "saf_agent_fence.h"
#include "token_setproc.h"
#include "user_policy_manager.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t USER_ID = 100;
constexpr int32_t INST_INDEX = 0;
constexpr int32_t API_VERSION_9 = 9;
constexpr int32_t ROOT_UID = 0;
constexpr const char* MANAGE_TOOL_CALLER_PROCESS = "aimgr";
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

std::string BuildInvalidAgentId()
{
    return std::string(50, 'a'); // 50 is invalid agent size
}

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
        { CAMERA_PERMISSION, { CAMERA_PERMISSION } },
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

std::string BuildCliAuthInfoMessage(
    const CliInfo& cliInfo, const std::vector<std::string>& permissions, const std::vector<bool>& results)
{
    std::string message = "{\"cliInfo\":{\"cliName\":\"" + cliInfo.cliName +
        "\",\"subCliName\":\"" + cliInfo.subCliName + "\"},\"permissionNames\":[";
    for (size_t i = 0; i < permissions.size(); ++i) {
        if (i > 0) {
            message += ",";
        }
        message += "\"" + permissions[i] + "\"";
    }
    message += "],\"authorizationResults\":[";
    for (size_t i = 0; i < results.size(); ++i) {
        if (i > 0) {
            message += ",";
        }
        message += results[i] ? "\"true\"" : "\"false\"";
    }
    message += "]}";
    return message;
}

void MockSingleCliAuthChallenge(
    const CliAuthInfoParcel& authInfo, const std::string& challenge, const std::string& ticket)
{
    SetMockGenerateTicketResult({ {
        BuildCliAuthInfoMessage(
            authInfo.info.cliInfo, authInfo.info.permissionNames, authInfo.info.authorizationResults),
            challenge,
            ticket,
        } }, RET_SUCCESS);
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

AccessTokenID GetManageToolCallerTokenId()
{
    return AccessTokenInfoManager::GetInstance().GetNativeTokenId(MANAGE_TOOL_CALLER_PROCESS);
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

class UidGuard final {
public:
    UidGuard() : uid_(getuid()) {}
    ~UidGuard()
    {
        (void)setuid(uid_);
    }

private:
    uint32_t uid_;
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

class UserPolicyCleaner final {
public:
    explicit UserPolicyCleaner(const std::string& permission)
        : permission_(permission), callerToken_(GetSelfTokenID())
    {}
    ~UserPolicyCleaner()
    {
        std::vector<UserPolicyChange> userPolicyList;
        (void)UserPolicyManager::GetInstance().ClearUserPolicy({ permission_ }, callerToken_, userPolicyList);
    }

private:
    std::string permission_;
    AccessTokenID callerToken_;
};

struct InitCliTokenRequest {
    uint64_t callerTokenId = 0;
    uint32_t callerUid = 0;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    std::string challenge;
    CliInfo cliInfo;
};

struct InitCliTokenResult {
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
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

int32_t GenerateCliAuthResultRet(AccessTokenManagerService& service, uint64_t callerTokenId, AccessTokenID hostTokenId,
    const std::vector<CliAuthInfoParcel>& authInfos, ToolAuthResultParcel& result)
{
    SelfTokenGuard guard;
    SetSelfTokenID(callerTokenId);
    return service.GenerateCliAuthResult(hostTokenId, DEFAULT_AGENT_ID, authInfos, result);
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

int32_t InitCliToolTokenRet(
    AccessTokenManagerService& service, const InitCliTokenRequest& request, InitCliTokenResult& result)
{
    SelfTokenGuard tokenGuard;
    UidGuard uidGuard;
    SetSelfTokenID(request.callerTokenId);
    (void)setuid(request.callerUid);
    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = request.hostTokenId,
        .challenge = request.challenge,
        .cliInfo = request.cliInfo,
    };
    return service.InitCliToken(initInfoParcel, result.fullTokenId, result.kernelPermIdlList);
}

int32_t GetCliTokenInfoRet(AccessTokenManagerService& service, uint64_t callerTokenId, AccessTokenID tokenId,
    CliInfoResultParcel& infoParcel)
{
    SelfTokenGuard guard;
    SetSelfTokenID(callerTokenId);
    return service.GetCliTokenInfo(tokenId, infoParcel);
}

int32_t GetHostTokenIdRet(
    AccessTokenManagerService& service, uint64_t callerTokenId, AccessTokenID toolTokenId, AccessTokenID& hostTokenId)
{
    SelfTokenGuard guard;
    SetSelfTokenID(callerTokenId);
    return service.GetHostTokenId(toolTokenId, hostTokenId);
}

std::string GenerateSingleCliAuthChallenge(AccessTokenManagerService& service, uint64_t callerTokenId,
    AccessTokenID hostTokenId, const CliAuthInfoParcel& authInfo)
{
    auto authResult = GenerateCliAuthResult(service, callerTokenId, hostTokenId, { authInfo });
    EXPECT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    EXPECT_FALSE(authResult.result.authResults[0].empty());
    return authResult.result.authResults[0];
}

AccessTokenID InitCliToolTokenByService(
    AccessTokenManagerService& service, const InitCliTokenRequest& request, InitCliTokenResult& result)
{
    EXPECT_EQ(RET_SUCCESS, InitCliToolTokenRet(service, request, result));
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = result.fullTokenId;
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
 * @tc.name: GetCliPermissionRequestInfo_001
 * @tc.desc: Test invalid agentID returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_001, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullTokenId = CreateServiceTestToken(
        "tooltoken_prequery_001", true, BuildQueryPermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(fullTokenId);
    PermissionDialogResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissionRequestInfo(
            BuildInvalidAgentId(), { BuildCliInfoParcel("location", "query") }, result));
    EXPECT_TRUE(result.result.detailList.empty());
}

/**
 * @tc.name: GetCliPermissionRequestInfo_002
 * @tc.desc: Test empty cliInfoList returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_002, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullTokenId = CreateServiceTestToken(
        "tooltoken_prequery_002", true, BuildQueryPermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(fullTokenId);
    PermissionDialogResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, {}, result));
    EXPECT_TRUE(result.result.detailList.empty());
}

/**
 * @tc.name: GetCliPermissionRequestInfo_005
 * @tc.desc: Test non-system caller returns not-system-app.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_005, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullTokenId = CreateServiceTestToken(
        "tooltoken_prequery_005", false, BuildQueryPermissionStates(), tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(fullTokenId);
    PermissionDialogResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, { BuildCliInfoParcel("location", "query") }, result));
    EXPECT_TRUE(result.result.detailList.empty());
}

/**
 * @tc.name: GetCliPermissionRequestInfo_007
 * @tc.desc: Test caller without QUERY_TOOL_PERMISSIONS returns permission-denied.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_007, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_007", true, {}, tokenId);
    ASSERT_NE(0, fullTokenId);
    cleaner.Add(tokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(fullTokenId);
    PermissionDialogResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GetCliPermissionRequestInfo(
            DEFAULT_AGENT_ID, { BuildCliInfoParcel("location", "query") }, result));
    EXPECT_TRUE(result.result.detailList.empty());
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
 * @tc.name: GetCliPermissions_001
 * @tc.desc: Test INVALID_TOKENID hostTokenId returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_001, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_001_caller", true, BuildManagePermissionStates(), callerTokenId);
    ASSERT_NE(0, callerFullTokenId);
    cleaner.Add(callerTokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(callerFullTokenId);
    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissions(
            INVALID_TOKENID, DEFAULT_AGENT_ID, { BuildCliInfoParcel("location", "query") }, result));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_002
 * @tc.desc: Test non-HAP hostTokenId returns token-not-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_002, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_002_caller", true, BuildManagePermissionStates(), callerTokenId);
    ASSERT_NE(0, callerFullTokenId);
    cleaner.Add(callerTokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(callerFullTokenId);
    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissions(GetManageToolCallerTokenId(), DEFAULT_AGENT_ID,
            { BuildCliInfoParcel("location", "query") }, result));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_003
 * @tc.desc: Test invalid agentID returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_003, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_003_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_003_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(callerFullTokenId);
    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissions(
            hostTokenId, BuildInvalidAgentId(), { BuildCliInfoParcel("location", "query") }, result));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_004
 * @tc.desc: Test empty cliInfoList returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_004, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_004_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_004_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(callerFullTokenId);
    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissions(hostTokenId, DEFAULT_AGENT_ID, {}, result));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_005
 * @tc.desc: Test non-system caller returns not-system-app.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_005, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_005_caller", false, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_005_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(callerFullTokenId);
    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
        atManagerService_->GetCliPermissions(
            hostTokenId, DEFAULT_AGENT_ID, { BuildCliInfoParcel("location", "query") }, result));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_007
 * @tc.desc: Test caller without MANAGE_TOOL_RUNTIME_PERMISSIONS returns permission-denied.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_007, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken("tooltoken_query_007_caller", true, {}, callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_007_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(callerFullTokenId);
    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        atManagerService_->GetCliPermissions(
            hostTokenId, DEFAULT_AGENT_ID, { BuildCliInfoParcel("location", "query") }, result));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_011
 * @tc.desc: Test permanently granted CLI Permission returns granted status and mapped permissions.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_011, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_query_011_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_011_host", true,
        { BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE, PERMISSION_SYSTEM_FIXED) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();
    SetMockCliRuntimePermissionsForTest(
        { { CUSTOM_SCREEN_CAPTURE, { LOCATION_PERMISSION, CAMERA_PERMISSION } } });

    auto result = QueryCliPermissions(*atManagerService_, callerFullTokenId, hostTokenId,
        { BuildCliInfoParcel("location", "query") });
    const auto& detail = result.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ(CUSTOM_SCREEN_CAPTURE, detail.requiredCliPermission);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_GRANTED, detail.cliPermissionStatus);
    EXPECT_EQ((std::vector<std::string> { LOCATION_PERMISSION, CAMERA_PERMISSION }), detail.usedPermissions);
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
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
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

/**
 * @tc.name: GenerateCliAuthResult_013
 * @tc.desc: Test invalid hostTokenId returns invalid-param or token-not-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_013, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_013_caller", true, BuildManagePermissionStates(), callerTokenId);
    ASSERT_NE(0, callerFullTokenId);
    cleaner.Add(callerTokenId);

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, GenerateCliAuthResultRet(
        *atManagerService_, callerFullTokenId, INVALID_TOKENID,
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true }) }, result));
}

/**
 * @tc.name: GenerateCliAuthResult_014
 * @tc.desc: Test empty authInfoList returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_014, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_014_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_014_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        GenerateCliAuthResultRet(*atManagerService_, callerFullTokenId, hostTokenId, {}, result));
}

/**
 * @tc.name: GenerateCliAuthResult_015
 * @tc.desc: Test mismatched permissionNames and authorizationResults returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_015, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_015_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_015_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, GenerateCliAuthResultRet(*atManagerService_, callerFullTokenId,
        hostTokenId, { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, {}) },
        result));
}

/**
 * @tc.name: GenerateCliAuthResult_007
 * @tc.desc: Test undeclared required CLI Permission returns filtered empty challenge result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_007, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_007_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_007_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("location", "query"), { CUSTOM_SCREEN_CAPTURE }, { true }) });
    ASSERT_EQ(1, static_cast<int32_t>(result.result.authResults.size()));
    EXPECT_FALSE(result.result.authResults[0].empty());

    InitCliTokenResult initResult;
    InitCliTokenRequest request = {
        .callerTokenId = GetSelfTokenID(),
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = result.result.authResults[0],
        .cliInfo = BuildCliInfo("location", "query"),
    };
    EXPECT_EQ(RET_SUCCESS, InitCliToolTokenRet(*atManagerService_, request, initResult));
}

/**
 * @tc.name: GenerateCliAuthResult_008
 * @tc.desc: Test non-system caller returns not-system-app.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_008, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_008_caller", false, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_008_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP, GenerateCliAuthResultRet(*atManagerService_,
        callerFullTokenId, hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true }) }, result));
    EXPECT_TRUE(result.result.authResults.empty());
}

/**
 * @tc.name: GenerateCliAuthResult_009
 * @tc.desc: Test caller without MANAGE_TOOL_RUNTIME_PERMISSIONS returns permission-denied.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_009, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken("tooltoken_auth_009_caller", true, {}, callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_009_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, GenerateCliAuthResultRet(*atManagerService_,
        callerFullTokenId, hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true }) }, result));
    EXPECT_TRUE(result.result.authResults.empty());
}

/**
 * @tc.name: GenerateCliAuthResult_010
 * @tc.desc: Test single valid CliAuthInfo returns one non-empty challenge result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_010, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_010_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_010_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "auth_010_challenge", "auth_010_ticket");

    auto result =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(result.result.authResults.size()));
    EXPECT_EQ("auth_010_challenge", result.result.authResults[0]);
}

/**
 * @tc.name: GenerateCliAuthResult_011
 * @tc.desc: Test non-HAP hostTokenId returns token-not-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_011, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_011_caller", true, BuildManagePermissionStates(), callerTokenId);
    ASSERT_NE(0, callerFullTokenId);
    cleaner.Add(callerTokenId);

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, GenerateCliAuthResultRet(*atManagerService_,
        callerFullTokenId, GetManageToolCallerTokenId(),
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true }) }, result));
    EXPECT_TRUE(result.result.authResults.empty());
}

/**
 * @tc.name: GenerateCliAuthResult_012
 * @tc.desc: Test invalid agentID returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_012, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_auth_012_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_012_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(callerFullTokenId);
    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GenerateCliAuthResult(hostTokenId, BuildInvalidAgentId(),
            { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true }) },
            result));
    EXPECT_TRUE(result.result.authResults.empty());
}

/**
 * @tc.name: InitCliToken_009
 * @tc.desc: Test InitCliToken fails when challenge does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_009, TestSize.Level1)
{
    uint64_t serviceCallerTokenId = GetSelfTokenID();
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_init_009_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(hostTokenId);

    InitCliTokenResult initResult;
    InitCliTokenRequest request = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = "not_exist_challenge",
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        InitCliToolTokenRet(*atManagerService_, request, initResult));
}

/**
 * @tc.name: InitCliToken_010
 * @tc.desc: Test consumed challenge cannot be reused after successful initialization.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_010, TestSize.Level1)
{
    uint64_t serviceCallerTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_init_010_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_010_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_010_challenge", "init_010_ticket");
    std::string challenge =
        GenerateSingleCliAuthChallenge(*atManagerService_, callerFullTokenId, hostTokenId, authInfo);
    InitCliTokenResult initResult;
    InitCliTokenRequest request = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    InitCliTokenResult secondInitResult;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        InitCliToolTokenRet(*atManagerService_, request, secondInitResult));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_011
 * @tc.desc: Test mismatched cliInfo fails and original challenge can retry with correct cliInfo.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_011, TestSize.Level1)
{
    uint64_t serviceCallerTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_init_011_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_011_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_011_challenge", "init_011_ticket");
    std::string challenge =
        GenerateSingleCliAuthChallenge(*atManagerService_, callerFullTokenId, hostTokenId, authInfo);
    InitCliTokenRequest failedRequest = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "wrong"),
    };
    InitCliTokenResult failedInitResult;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        InitCliToolTokenRet(*atManagerService_, failedRequest, failedInitResult));

    InitCliTokenRequest request = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_016
 * @tc.desc: Test mismatched hostTokenId fails and original challenge can retry with correct hostTokenId.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_016, TestSize.Level1)
{
    uint64_t serviceCallerTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    AccessTokenID otherHostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_init_016_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_016_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    uint64_t otherHostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_016_other_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, otherHostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    ASSERT_NE(0, otherHostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);
    cleaner.Add(otherHostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_016_challenge", "init_016_ticket");
    std::string challenge =
        GenerateSingleCliAuthChallenge(*atManagerService_, callerFullTokenId, hostTokenId, authInfo);

    InitCliTokenRequest failedRequest = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = otherHostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult failedInitResult;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        InitCliToolTokenRet(*atManagerService_, failedRequest, failedInitResult));

    InitCliTokenRequest request = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_012
 * @tc.desc: Test repeated creation in the same pid returns already-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_012, TestSize.Level1)
{
    uint64_t serviceCallerTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_init_012_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_012_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_012_first_challenge", "init_012_first_ticket");
    std::string firstChallenge =
        GenerateSingleCliAuthChallenge(*atManagerService_, callerFullTokenId, hostTokenId, authInfo);
    InitCliTokenRequest firstRequest = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = firstChallenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult firstInitResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, firstRequest, firstInitResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    MockSingleCliAuthChallenge(authInfo, "init_012_second_challenge", "init_012_second_ticket");
    std::string secondChallenge =
        GenerateSingleCliAuthChallenge(*atManagerService_, callerFullTokenId, hostTokenId, authInfo);
    InitCliTokenRequest secondRequest = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = secondChallenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult secondInitResult;
    EXPECT_EQ(AccessTokenError::ERR_TOOL_TOKEN_ALREADY_EXIST,
        InitCliToolTokenRet(*atManagerService_, secondRequest, secondInitResult));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_013
 * @tc.desc: Test token can be rebuilt after deletion.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_013, TestSize.Level1)
{
    uint64_t serviceCallerTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_init_013_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_013_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_013_first_challenge", "init_013_first_ticket");
    std::string firstChallenge =
        GenerateSingleCliAuthChallenge(*atManagerService_, callerFullTokenId, hostTokenId, authInfo);
    InitCliTokenRequest firstRequest = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = firstChallenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult firstInitResult;
    AccessTokenID firstTokenId = InitCliToolTokenByService(*atManagerService_, firstRequest, firstInitResult);
    ASSERT_NE(INVALID_TOKENID, firstTokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));

    MockSingleCliAuthChallenge(authInfo, "init_013_second_challenge", "init_013_second_ticket");
    std::string secondChallenge =
        GenerateSingleCliAuthChallenge(*atManagerService_, callerFullTokenId, hostTokenId, authInfo);
    InitCliTokenRequest secondRequest = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = secondChallenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult secondInitResult;
    AccessTokenID secondTokenId = InitCliToolTokenByService(*atManagerService_, secondRequest, secondInitResult);
    ASSERT_NE(INVALID_TOKENID, secondTokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_014
 * @tc.desc: Test empty permissionNames challenge creates a no-permission token.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_014, TestSize.Level1)
{
    uint64_t serviceCallerTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_init_014_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_init_014_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "mock_empty_perm_challenge", "mock_empty_perm_ticket");
    ToolAuthResultParcel authResult =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    ASSERT_FALSE(authResult.result.authResults[0].empty());

    InitCliTokenRequest request = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    EXPECT_TRUE(initResult.kernelPermIdlList.empty());
    VerifyRuntimePermission(tokenId, LOCATION_PERMISSION, PERMISSION_DENIED);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_015
 * @tc.desc: Test non-root uid is denied and challenge remains retryable.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_015, TestSize.Level1)
{
    uint64_t serviceCallerTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_init_015_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_015_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_015_challenge", "init_015_ticket");
    std::string challenge =
        GenerateSingleCliAuthChallenge(*atManagerService_, callerFullTokenId, hostTokenId, authInfo);
    InitCliTokenRequest failedRequest = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = 1234,
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult failedInitResult;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        InitCliToolTokenRet(*atManagerService_, failedRequest, failedInitResult));

    InitCliTokenRequest request = {
        .callerTokenId = serviceCallerTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: DeleteToolTokenByPid_003
 * @tc.desc: Test deleting the same pid twice returns token-not-exist on the second call.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, DeleteToolTokenByPid_003, TestSize.Level1)
{
    uint64_t shellTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_delete_003_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_delete_003_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "delete_003_challenge", "delete_003_ticket");
    ToolAuthResultParcel authResult =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    InitCliTokenRequest request = {
        .callerTokenId = shellTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GetCliTokenInfo_004
 * @tc.desc: Test deleted and non-existent token return token-not-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliTokenInfo_004, TestSize.Level1)
{
    uint64_t shellTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_getcli_004_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_getcli_004_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "getcli_004_challenge", "getcli_004_ticket");
    ToolAuthResultParcel authResult =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    InitCliTokenRequest request = {
        .callerTokenId = shellTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));

    CliInfoResultParcel infoParcel;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        GetCliTokenInfoRet(*atManagerService_, shellTokenId, tokenId, infoParcel));
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        GetCliTokenInfoRet(*atManagerService_, shellTokenId, INVALID_TOKENID, infoParcel));
}

/**
 * @tc.name: GetHostTokenId_004
 * @tc.desc: Test deleted tool token returns token-not-exist when querying host token.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetHostTokenId_004, TestSize.Level1)
{
    uint64_t shellTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_gethost_004_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_gethost_004_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "gethost_004_challenge", "gethost_004_ticket");
    ToolAuthResultParcel authResult =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    InitCliTokenRequest request = {
        .callerTokenId = shellTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));

    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        GetHostTokenIdRet(*atManagerService_, shellTokenId, tokenId, queriedHostTokenId));
}

/**
 * @tc.name: GetHostTokenId_005
 * @tc.desc: Test existing non-tool token returns invalid-param when querying host token.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetHostTokenId_005, TestSize.Level1)
{
    uint64_t shellTokenId = GetSelfTokenID();
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_gethost_005_host", true, {}, hostTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(hostTokenId);

    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        GetHostTokenIdRet(*atManagerService_, shellTokenId, hostTokenId, queriedHostTokenId));
}

/**
 * @tc.name: GetHostTokenId_006
 * @tc.desc: Test unauthorized caller querying host token returns permission-denied.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetHostTokenId_006, TestSize.Level1)
{
    uint64_t shellTokenId = GetSelfTokenID();
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID unauthorizedTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_gethost_006_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t unauthorizedFullTokenId =
        CreateServiceTestToken("tooltoken_gethost_006_unauth", false, {}, unauthorizedTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_gethost_006_host", true, {}, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, unauthorizedFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(unauthorizedTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "gethost_006_challenge", "gethost_006_ticket");
    ToolAuthResultParcel authResult =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    InitCliTokenRequest request = {
        .callerTokenId = shellTokenId,
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    setuid(1234); // 1234 is invalid uid
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        GetHostTokenIdRet(*atManagerService_, unauthorizedFullTokenId, tokenId, queriedHostTokenId));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: UpdateRestrictedFlag_001
 * @tc.desc: Test UpdateRestrictedFlag returns token-not-exist when tool token is absent.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, UpdateRestrictedFlag_001, TestSize.Level1)
{
    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode(CAMERA_PERMISSION, permCode));

    bool hasFlagChanged = true;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        ToolTokenInfoManager::GetInstance().UpdateRestrictedFlag(INVALID_TOKENID, permCode, true, hasFlagChanged));
    EXPECT_FALSE(hasFlagChanged);
}

/**
 * @tc.name: UpdateRestrictedFlag_002
 * @tc.desc: Test UpdateRestrictedFlag updates an existing tool token and reports whether flag changed.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, UpdateRestrictedFlag_002, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_restricted_flag_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_restricted_flag_host", true,
        { BuildGrantedStatus(CAMERA_PERMISSION, PERMISSION_SYSTEM_FIXED) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), { CAMERA_PERMISSION }, { true });
    MockSingleCliAuthChallenge(authInfo, "restricted_flag_challenge", "restricted_flag_ticket");
    ToolAuthResultParcel authResult =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    InitCliTokenRequest request = {
        .callerTokenId = GetSelfTokenID(),
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode(CAMERA_PERMISSION, permCode));
    bool hasFlagChanged = false;
    EXPECT_EQ(RET_SUCCESS,
        ToolTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, hasFlagChanged));
    EXPECT_TRUE(hasFlagChanged);
    VerifyRuntimePermission(tokenId, CAMERA_PERMISSION, PERMISSION_DENIED);

    hasFlagChanged = true;
    EXPECT_EQ(RET_SUCCESS,
        ToolTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, hasFlagChanged));
    EXPECT_FALSE(hasFlagChanged);

    hasFlagChanged = false;
    EXPECT_EQ(RET_SUCCESS,
        ToolTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, false, hasFlagChanged));
    EXPECT_TRUE(hasFlagChanged);
    VerifyRuntimePermission(tokenId, CAMERA_PERMISSION, PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: RefreshUserPolicyFlag_001
 * @tc.desc: Test RefreshUserPolicyFlag handles empty change list.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, RefreshUserPolicyFlag_001, TestSize.Level1)
{
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().RefreshUserPolicyFlag({}));
}

/**
 * @tc.name: RefreshUserPolicyFlag_002
 * @tc.desc: Test RefreshUserPolicyFlag restricts and restores an existing tool token.
 * @tc.type: FUNC
 */
#ifdef SUPPORT_MANAGE_USER_POLICY
HWTEST_F(ToolTokenMockTest, RefreshUserPolicyFlag_002, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_user_policy_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_user_policy_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS, PERMISSION_SYSTEM_FIXED) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "user_policy_challenge", "user_policy_ticket");
    ToolAuthResultParcel authResult =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    InitCliTokenRequest request = {
        .callerTokenId = GetSelfTokenID(),
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS, PERMISSION_GRANTED);

    std::vector<UserPolicyChange> userPolicyList;
    UserPermissionPolicy policy = {
        .permissionName = ACCESS_SYSTEM_SETTINGS,
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = false
    };
    EXPECT_EQ(RET_SUCCESS,
        UserPolicyManager::GetInstance().SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().RefreshUserPolicyFlag(userPolicyList));
    VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS, PERMISSION_DENIED);

    EXPECT_EQ(RET_SUCCESS,
        UserPolicyManager::GetInstance().ClearUserPolicy({ ACCESS_SYSTEM_SETTINGS }, GetSelfTokenID(), userPolicyList));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().RefreshUserPolicyFlag(userPolicyList));
    VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS, PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliTokenUserPolicy_001
 * @tc.desc: Test InitCliToken applies existing user policy restricted flag during token initialization.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliTokenUserPolicy_001, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_init_user_policy_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_init_user_policy_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS, PERMISSION_SYSTEM_FIXED) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    std::vector<UserPolicyChange> userPolicyList;
    UserPermissionPolicy policy = {
        .permissionName = ACCESS_SYSTEM_SETTINGS,
        .userPolicyList = {{ .userId = USER_ID, .isRestricted = true }},
        .isPersist = false
    };
    ASSERT_EQ(RET_SUCCESS,
        UserPolicyManager::GetInstance().SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    UserPolicyCleaner policyCleaner(ACCESS_SYSTEM_SETTINGS);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_user_policy_challenge", "init_user_policy_ticket");
    ToolAuthResultParcel authResult =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));

    InitCliTokenRequest request = {
        .callerTokenId = GetSelfTokenID(),
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS, PERMISSION_DENIED);

    policy.userPolicyList[0].isRestricted = false;
    ASSERT_EQ(RET_SUCCESS,
        UserPolicyManager::GetInstance().SetUserPolicy({ policy }, GetSelfTokenID(), userPolicyList));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().RefreshUserPolicyFlag(userPolicyList));
    VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS, PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: RefreshUserPolicyFlag_003
 * @tc.desc: Test RefreshUserPolicyFlag skips permissions not requested by a tool token.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, RefreshUserPolicyFlag_003, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId = CreateServiceTestToken(
        "tooltoken_user_policy_missing_perm_caller", true, BuildManagePermissionStates(), callerTokenId);
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_user_policy_missing_perm_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS, PERMISSION_SYSTEM_FIXED) }, hostTokenId);
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    cleaner.Add(callerTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "missing_perm_challenge", "missing_perm_ticket");
    ToolAuthResultParcel authResult =
        GenerateCliAuthResult(*atManagerService_, callerFullTokenId, hostTokenId, { authInfo });
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    InitCliTokenRequest request = {
        .callerTokenId = GetSelfTokenID(),
        .callerUid = ROOT_UID,
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    InitCliTokenResult initResult;
    AccessTokenID tokenId = InitCliToolTokenByService(*atManagerService_, request, initResult);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS, PERMISSION_GRANTED);

    uint32_t missingPermCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode(CAMERA_PERMISSION, missingPermCode));
    UserPolicyChange missingPermChange {
        .permCode = missingPermCode,
        .isPersist = false,
        .changedUserList = { USER_ID }
    };
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().RefreshUserPolicyFlag({ missingPermChange }));
    VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS, PERMISSION_GRANTED);

    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}
#endif
}
}
}
