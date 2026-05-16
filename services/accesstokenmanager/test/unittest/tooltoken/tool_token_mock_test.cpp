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

#include <algorithm>
#include <unistd.h>
#include <gtest/gtest.h>

#define private public
#include "accesstoken_manager_service.h"
#undef private

#include "access_token_error.h"
#include "accesstoken_info_manager.h"
#include "claw_ticket_manager.h"
#include "claw_token_info_manager.h"
#include "cli_info_parcel.h"
#include "cli_permissions_result_parcel.h"
#include "generic_values.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "mock_permission.h"
#include "permission_dialog_result_parcel.h"
#include "permission_map.h"
#include "permission_map_fence.h"
#include "saf_agent_fence.h"
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t USER_ID = 100;
constexpr int32_t INST_INDEX = 0;
constexpr int32_t API_VERSION_9 = 9;
constexpr int32_t ROOT_UID = 0;
const std::string DEFAULT_AGENT_ID = "1001";
const std::string CUSTOM_SCREEN_CAPTURE = "ohos.permission.CUSTOM_SCREEN_CAPTURE";
const std::string ACCESS_SYSTEM_SETTINGS = "ohos.permission.ACCESS_SYSTEM_SETTINGS";
const std::string LOCATION_PERMISSION = "ohos.permission.LOCATION";
const std::string WIFI_PERMISSION = "ohos.permission.GET_WIFI_INFO";
const std::string CAMERA_PERMISSION = "ohos.permission.CAMERA";
const std::string MICROPHONE_PERMISSION = "ohos.permission.MICROPHONE";
const std::string AUDIO_PERMISSION = "ohos.permission.MANAGE_AUDIO_CONFIG";
const std::string PUSH_PERMISSION = "ohos.permission.ACCESS_PUSH_SERVICE";
const std::string MANAGE_TOOL_RUNTIME_PERMISSIONS = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS";
const std::string MANAGE_USER_POLICY = "ohos.permission.MANAGE_USER_POLICY";
const std::string KERNEL_PLUGIN_PERMISSION = "ohos.permission.kernel.SUPPORT_PLUGIN";
const std::string WRITE_CALENDAR_PERMISSION = "ohos.permission.WRITE_CALENDAR";
uint64_t g_selfShellTokenId = 0;

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
    const std::string& bundleName, bool isSystemApp, const std::vector<PermissionStatus>& permStates)
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
        return 0;
    }
    return tokenIdEx.tokenIDEx;
}

AccessTokenID GetTokenIdFromFullTokenId(uint64_t fullTokenId)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIDEx = fullTokenId;
    return tokenIdEx.tokenIdExStruct.tokenID;
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

AccessTokenID GetNativeProcessTokenId()
{
    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    GTEST_LOG_(INFO) << "tokenId" << tokenId;
    return tokenId;
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

struct CliPermissionRequestInfoQueryResult {
    PermissionDialogResultParcel info;
    AccessTokenID callerTokenId = INVALID_TOKENID;
};

struct CliPermissionsQueryResult {
    CliPermissionsResultParcel info;
    AccessTokenID callerTokenId = INVALID_TOKENID;
};

void PrepareMockEnvironment(
    const std::map<std::string, std::vector<std::string>>& commandMap = BuildCliCommandMockMap())
{
    ResetMockCounter();
    SetMockCommandPermissionsForTest(commandMap);
    SetMockCliRuntimePermissionsForTest(BuildCliRuntimeMockMap());
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

int32_t VerifyRuntimePermission(AccessTokenID tokenId, const std::string& permissionName)
{
    return ToolTokenInfoManager::GetInstance().VerifyToolAccessToken(tokenId, permissionName);
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

} // namespace

class ToolTokenMockTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_selfShellTokenId = GetSelfTokenID();
        TestCommon::SetTestEvironment(g_selfShellTokenId);
    }

    static void TearDownTestCase()
    {
        TestCommon::ResetTestEvironment();
        SetSelfTokenID(g_selfShellTokenId);
    }

    void SetUp() override
    {
        atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
        EXPECT_NE(nullptr, atManagerService_);
        atManagerService_->Initialize();

        ClearMockCliRuntimePermissionsForTest();
        ResetMockCounter();
        manageToolCallerIndex_ = 0;
        (void)ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid());
    }

    void TearDown() override
    {
        ClearMockCliRuntimePermissionsForTest();
        ResetMockCounter();
        (void)ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid());
        DelayedSingleton<AccessTokenManagerService>::DestroyInstance();
        atManagerService_ = nullptr;
    }

public:
    std::shared_ptr<AccessTokenManagerService> atManagerService_;

protected:
    CliPermissionRequestInfoQueryResult QueryCliPermissionRequestInfo(
        const std::vector<PermissionStatus>& permStates, const std::vector<CliInfoParcel>& cliInfos,
        TokenCleaner& cleaner)
    {
        CliPermissionRequestInfoQueryResult result;
        uint64_t callerFullTokenId = CreateServiceTestToken("tooltoken_prequery_caller", true, permStates);
        EXPECT_NE(0, callerFullTokenId);
        if (callerFullTokenId == 0) {
            return result;
        }
        result.callerTokenId = GetTokenIdFromFullTokenId(callerFullTokenId);
        cleaner.Add(result.callerTokenId);

        SelfTokenGuard guard;
        SetSelfTokenID(callerFullTokenId);
        EXPECT_EQ(RET_SUCCESS, atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, cliInfos, result.info));
        return result;
    }

    CliPermissionsQueryResult QueryCliPermissions(
        AccessTokenID hostTokenId, const std::vector<CliInfoParcel>& cliInfos, TokenCleaner& cleaner)
    {
        CliPermissionsQueryResult result;
        uint64_t callerFullTokenId =
            CreateServiceTestToken("tooltoken_query_caller", true, BuildManagePermissionStates());
        EXPECT_NE(0, callerFullTokenId);
        if (callerFullTokenId == 0) {
            return result;
        }
        result.callerTokenId = GetTokenIdFromFullTokenId(callerFullTokenId);
        cleaner.Add(result.callerTokenId);

        SelfTokenGuard guard;
        SetSelfTokenID(callerFullTokenId);
        EXPECT_EQ(RET_SUCCESS, atManagerService_->GetCliPermissions(hostTokenId, DEFAULT_AGENT_ID, cliInfos,
            result.info));
        return result;
    }

    ToolAuthResultParcel GenerateCliAuthResult(
        AccessTokenID hostTokenId, const std::vector<CliAuthInfoParcel>& authInfos, TokenCleaner& cleaner)
    {
        uint64_t callerFullTokenId = CreateServiceTestToken(
            "tooltoken_manage_caller_" + std::to_string(++manageToolCallerIndex_), true,
            BuildManagePermissionStates());
        EXPECT_NE(0, callerFullTokenId);
        if (callerFullTokenId == 0) {
            return {};
        }
        cleaner.Add(GetTokenIdFromFullTokenId(callerFullTokenId));

        SelfTokenGuard guard;
        SetSelfTokenID(callerFullTokenId);
        ToolAuthResultParcel result;
        EXPECT_EQ(RET_SUCCESS, atManagerService_->GenerateCliAuthResult(hostTokenId, DEFAULT_AGENT_ID, authInfos,
            result));
        return result;
    }

    ToolAuthResultParcel GenerateSkillAuthResult(
        AccessTokenID hostTokenId, const std::vector<SkillAuthInfoParcel>& authInfos, TokenCleaner& cleaner)
    {
        uint64_t callerFullTokenId = CreateServiceTestToken(
            "tooltoken_manage_caller_" + std::to_string(++manageToolCallerIndex_), true,
            BuildManagePermissionStates());
        EXPECT_NE(0, callerFullTokenId);
        if (callerFullTokenId == 0) {
            return {};
        }
        cleaner.Add(GetTokenIdFromFullTokenId(callerFullTokenId));

        SelfTokenGuard guard;
        SetSelfTokenID(callerFullTokenId);
        ToolAuthResultParcel result;
        EXPECT_EQ(RET_SUCCESS, atManagerService_->GenerateSkillAuthResult(hostTokenId, DEFAULT_AGENT_ID, authInfos,
            result));
        return result;
    }

    int32_t QueryCliPermissionsRet(AccessTokenID hostTokenId, const std::string& agentId,
        const std::vector<CliInfoParcel>& cliInfos, CliPermissionsResultParcel result, TokenCleaner& cleaner)
    {
        uint64_t callerFullTokenId =
            CreateServiceTestToken("tooltoken_query_caller", true, BuildManagePermissionStates());
        EXPECT_NE(0, callerFullTokenId);
        if (callerFullTokenId == 0) {
            return AccessTokenError::ERR_TOKENID_CREATE_FAILED;
        }
        cleaner.Add(GetTokenIdFromFullTokenId(callerFullTokenId));

        SelfTokenGuard guard;
        SetSelfTokenID(callerFullTokenId);
        return atManagerService_->GetCliPermissions(hostTokenId, agentId, cliInfos, result);
    }

    int32_t GenerateCliAuthResultRet(AccessTokenID hostTokenId, const std::vector<CliAuthInfoParcel>& authInfos,
        ToolAuthResultParcel& result, TokenCleaner& cleaner)
    {
        uint64_t callerFullTokenId = CreateServiceTestToken(
            "tooltoken_manage_caller_" + std::to_string(++manageToolCallerIndex_), true,
            BuildManagePermissionStates());
        EXPECT_NE(0, callerFullTokenId);
        if (callerFullTokenId == 0) {
            return AccessTokenError::ERR_TOKENID_CREATE_FAILED;
        }
        cleaner.Add(GetTokenIdFromFullTokenId(callerFullTokenId));

        SelfTokenGuard guard;
        SetSelfTokenID(callerFullTokenId);
        return atManagerService_->GenerateCliAuthResult(hostTokenId, DEFAULT_AGENT_ID, authInfos, result);
    }

    int32_t InitCliToolTokenRet(const CliInitInfoParcel& initInfoParcel, uint64_t& fullTokenId,
        std::vector<PermissionWithValueIdl>& kernelPermIdlList)
    {
        UidGuard uidGuard;
        (void)setuid(ROOT_UID);
        return atManagerService_->InitCliToken(initInfoParcel, fullTokenId, kernelPermIdlList);
    }

#ifdef SUPPORT_MANAGE_USER_POLICY
    int32_t SetUserPolicyRet(const std::vector<UserPermissionPolicyIdl>& userPermissionList)
    {
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant(MANAGE_USER_POLICY);
        return atManagerService_->SetUserPolicy(userPermissionList);
    }

    int32_t ClearUserPolicyRet(const std::vector<std::string>& permissionList)
    {
        MockToken mock(g_selfShellTokenId, "accesstoken_service", false);
        mock.Grant(MANAGE_USER_POLICY);
        return atManagerService_->ClearUserPolicy(permissionList);
    }
#endif

    std::string GenerateSingleCliAuthChallenge(
        AccessTokenID hostTokenId, const CliAuthInfoParcel& authInfo, TokenCleaner& cleaner)
    {
        auto authResult = GenerateCliAuthResult(hostTokenId, { authInfo }, cleaner);
        EXPECT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
        EXPECT_FALSE(authResult.result.authResults[0].empty());
        return authResult.result.authResults[0];
    }

    uint32_t manageToolCallerIndex_ = 0;
};

/**
 * @tc.name: GetCliPermissionRequestInfo_001
 * @tc.desc: Test undeclared CLI Permission returns no-dialog not-declared detail.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_001, TestSize.Level1)
{
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(permStates,
        { BuildCliInfoParcel("location", "query") }, cleaner).info;
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
 * @tc.name: GetCliPermissionRequestInfo_002
 * @tc.desc: Test invalid agentID returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_002, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_002", true, BuildQueryPermissionStates());
    ASSERT_NE(0, fullTokenId);
    tokenId = GetTokenIdFromFullTokenId(fullTokenId);
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
 * @tc.name: GetCliPermissionRequestInfo_003
 * @tc.desc: Test empty cliInfoList returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_003, TestSize.Level1)
{
    AccessTokenID tokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullTokenId = CreateServiceTestToken("tooltoken_prequery_003", true, BuildQueryPermissionStates());
    ASSERT_NE(0, fullTokenId);
    tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    cleaner.Add(tokenId);

    SelfTokenGuard guard;
    SetSelfTokenID(fullTokenId);
    PermissionDialogResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        atManagerService_->GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, {}, result));
    EXPECT_TRUE(result.result.detailList.empty());
}

/**
 * @tc.name: GetCliPermissionRequestInfo_004
 * @tc.desc: Test denied runtime permission is returned in dialog detail with challenge.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_004, TestSize.Level1)
{
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    for (const auto& permission : BuildMockTypeADeniedOnlyStates()) {
        permStates.emplace_back(permission);
    }
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(permStates,
        { BuildCliInfoParcel("location", "query") }, cleaner).info;
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
 * @tc.name: GetCliPermissionRequestInfo_005
 * @tc.desc: Test undecided runtime permission triggers dialog and no auth result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_005, TestSize.Level1)
{
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE));
    permStates.emplace_back(BuildInitialStatus(CAMERA_PERMISSION));
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(permStates,
        { BuildCliInfoParcel("location", "query") }, cleaner).info;
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_TRUE(detail.needPermissionDialog);
    EXPECT_TRUE(detail.authResult.empty());
    EXPECT_FALSE(ContainsPermission(detail.permissionNameList, CAMERA_PERMISSION));
}

/**
 * @tc.name: GetCliPermissionRequestInfo_006
 * @tc.desc: Test restricted runtime permission is returned in dialog detail.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_006, TestSize.Level1)
{
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    for (const auto& permission : BuildMockTypeARestrictedOnlyStates()) {
        permStates.emplace_back(permission);
    }
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(permStates,
        { BuildCliInfoParcel("location", "query") }, cleaner).info;
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
 * @tc.name: GetCliPermissionRequestInfo_007
 * @tc.desc: Test all resolved runtime permissions produce no dialog and non-empty auth result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_007, TestSize.Level1)
{
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE));
    for (const auto& permission : BuildMockTypeARuntimePermissions()) {
        permStates.emplace_back(BuildGrantedStatus(permission, PERMISSION_SYSTEM_FIXED));
    }
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(permStates,
        { BuildCliInfoParcel("location", "query") }, cleaner).info;
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_FALSE(detail.needPermissionDialog);
    EXPECT_TRUE(detail.permissionNameList.empty());
    EXPECT_TRUE(detail.statusList.empty());
    EXPECT_FALSE(detail.authResult.empty());
}

/**
 * @tc.name: GetCliPermissionRequestInfo_008
 * @tc.desc: Test batch CLI details preserve order and independent auth results.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_008, TestSize.Level1)
{
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS));
    permStates.emplace_back(BuildInitialStatus(WRITE_CALENDAR_PERMISSION));
    for (const auto& permission : BuildMockTypeANoDialogStates()) {
        permStates.emplace_back(permission);
    }
    auto commandMap = BuildCliCommandMockMap();
    commandMap["camera:capture"] = {WRITE_CALENDAR_PERMISSION};
    PrepareMockEnvironment(commandMap);

    auto result = QueryCliPermissionRequestInfo(permStates, {
        BuildCliInfoParcel("settings", "set"),
        BuildCliInfoParcel("camera", "capture"),
        BuildCliInfoParcel("location", "query"),
    }, cleaner).info;
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
 * @tc.name: GetCliPermissionRequestInfo_009
 * @tc.desc: Test permissionNameList and statusList keep index alignment.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_009, TestSize.Level1)
{
    TokenCleaner cleaner;
    auto permStates = BuildQueryAndManagePermissionStates();
    permStates.emplace_back(BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE));
    permStates.emplace_back(BuildDeniedStatus(LOCATION_PERMISSION));
    permStates.emplace_back(BuildDeniedStatus(PUSH_PERMISSION, PERMISSION_FIXED_FOR_SECURITY_POLICY));
    PrepareMockEnvironment();

    auto result = QueryCliPermissionRequestInfo(permStates,
        { BuildCliInfoParcel("location", "query") }, cleaner).info;
    const auto& detail = result.result.detailList[0];
    ASSERT_EQ(detail.permissionNameList.size(), detail.statusList.size());
    ASSERT_EQ(2, static_cast<int32_t>(detail.permissionNameList.size()));
    EXPECT_EQ(LOCATION_PERMISSION, detail.permissionNameList[0]);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_DENIED, detail.statusList[0]);
    EXPECT_EQ(PUSH_PERMISSION, detail.permissionNameList[1]);
    EXPECT_EQ(PermissionDecisionStatus::NO_DIALOG_RESTRICTED, detail.statusList[1]);
}

/**
 * @tc.name: GetCliPermissionRequestInfo_010
 * @tc.desc: Test no-dialog authResult from prequery can be consumed by InitCliToken.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_010, TestSize.Level1)
{
    TokenCleaner cleaner;
    auto permStates = BuildQueryPermissionStates();
    permStates.emplace_back(BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS, PERMISSION_SYSTEM_FIXED));
    PrepareMockEnvironment();

    auto queryResult = QueryCliPermissionRequestInfo(permStates,
        { BuildCliInfoParcel("settings", "set") }, cleaner);
    const auto& result = queryResult.info;
    ASSERT_EQ(1, static_cast<int32_t>(result.result.detailList.size()));
    const auto& detail = result.result.detailList[0];
    EXPECT_FALSE(detail.needPermissionDialog);
    EXPECT_TRUE(detail.permissionNameList.empty());
    EXPECT_TRUE(detail.statusList.empty());
    ASSERT_FALSE(detail.authResult.empty());

    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        queryResult.callerTokenId, detail.authResult, BuildCliInfo("settings", "set"), kernelPermList);
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, ACCESS_SYSTEM_SETTINGS));
    VerifyCliTokenBasics(toolTokenId, queryResult.callerTokenId, "settings", "set");
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GetCliPermissionRequestInfo_011
 * @tc.desc: Test MockTypeA no-dialog authResult can be consumed by InitCliToken.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissionRequestInfo_011, TestSize.Level1)
{
    TokenCleaner cleaner;
    auto permStates = BuildQueryPermissionStates();
    for (const auto& permission : BuildMockTypeANoDialogStates()) {
        permStates.emplace_back(permission);
    }
    PrepareMockEnvironment();

    auto queryResult = QueryCliPermissionRequestInfo(permStates,
        { BuildCliInfoParcel("location", "query") }, cleaner);
    const auto& result = queryResult.info;
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
        queryResult.callerTokenId, detail.authResult, BuildCliInfo("location", "query"), kernelPermList);
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, LOCATION_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, WIFI_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, CAMERA_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, MICROPHONE_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, AUDIO_PERMISSION));
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, PUSH_PERMISSION));
    EXPECT_TRUE(ContainsPermission(kernelPermList, KERNEL_PLUGIN_PERMISSION));
    VerifyCliTokenBasics(toolTokenId, queryResult.callerTokenId, "location", "query");
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GetCliPermissions_001
 * @tc.desc: Test undeclared CLI Permission and granted self-mapped system permission in one batch.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_001, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto hostPerms = std::vector<PermissionStatus> { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_001_host", true, hostPerms);
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(hostTokenId, {
        BuildCliInfoParcel("location", "query"),
        BuildCliInfoParcel("settings", "set"),
    }, cleaner).info;
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
 * @tc.name: GetCliPermissions_002
 * @tc.desc: Test MockTypeA returns full usedPermissions list with granted CLI Permission.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_002, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto hostPerms = std::vector<PermissionStatus> { BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE) };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_002_host", true, hostPerms);
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(hostTokenId, { BuildCliInfoParcel("location", "query") }, cleaner).info;
    const auto& detail = result.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ((PermissionDecisionStatus::NO_DIALOG_GRANTED), detail.cliPermissionStatus);
    EXPECT_EQ(BuildMockTypeARuntimePermissions(), detail.usedPermissions);
}

/**
 * @tc.name: GetCliPermissions_003
 * @tc.desc: Test MockTypeA returns NEED_PERMISSION_DIALOG when a runtime permission is undecided.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_003, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto hostPerms = std::vector<PermissionStatus> {
        BuildAllowThisTimeStatus(CUSTOM_SCREEN_CAPTURE),
        BuildDeniedStatus(LOCATION_PERMISSION),
        BuildGrantedStatus(WIFI_PERMISSION),
        BuildInitialStatus(CAMERA_PERMISSION),
        BuildDeniedStatus(PUSH_PERMISSION, PERMISSION_FIXED_FOR_SECURITY_POLICY),
    };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_003_host", true, hostPerms);
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(hostTokenId, { BuildCliInfoParcel("location", "query") }, cleaner).info;
    const auto& detail = result.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ((PermissionDecisionStatus::NEED_PERMISSION_DIALOG), detail.cliPermissionStatus);
    EXPECT_EQ(BuildMockTypeARuntimePermissions(), detail.usedPermissions);
}

/**
 * @tc.name: GetCliPermissions_004
 * @tc.desc: Test allow-this-time CLI Permission resolves to NO_DIALOG_CLI_PERMISSION_RESOLVED.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_004, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto hostPerms = std::vector<PermissionStatus> { BuildAllowThisTimeStatus(CUSTOM_SCREEN_CAPTURE) };
    for (const auto& permission : BuildMockTypeARuntimePermissions()) {
        hostPerms.emplace_back(BuildGrantedStatus(permission, PERMISSION_SYSTEM_FIXED));
    }
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_004_host", true, hostPerms);
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(hostTokenId, { BuildCliInfoParcel("location", "query") }, cleaner).info;
    const auto& detail = result.result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ((PermissionDecisionStatus::NO_DIALOG_CLI_PERMISSION_RESOLVED),
        detail.cliPermissionStatus);
    EXPECT_EQ(BuildMockTypeARuntimePermissions(), detail.usedPermissions);
}

/**
 * @tc.name: GetCliPermissions_005
 * @tc.desc: Test batch CLI permission results preserve order and content.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_005, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto hostPerms = std::vector<PermissionStatus> {
        BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS),
        BuildInitialStatus(CAMERA_PERMISSION),
        BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE),
        BuildDeniedStatus(LOCATION_PERMISSION),
    };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_005_host", true, hostPerms);
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = QueryCliPermissions(hostTokenId, {
        BuildCliInfoParcel("settings", "set"),
        BuildCliInfoParcel("camera", "capture"),
        BuildCliInfoParcel("location", "query"),
    }, cleaner).info;
    ASSERT_EQ(3, static_cast<int32_t>(result.result.permList.size()));
    EXPECT_EQ(ACCESS_SYSTEM_SETTINGS,
        result.result.permList[0].requiredCliPermissions[0].requiredCliPermission);
    EXPECT_EQ(CAMERA_PERMISSION, result.result.permList[1].requiredCliPermissions[0].requiredCliPermission);
    EXPECT_EQ(CUSTOM_SCREEN_CAPTURE, result.result.permList[2].requiredCliPermissions[0].requiredCliPermission);
}

/**
 * @tc.name: GetCliPermissions_006
 * @tc.desc: Test INVALID_TOKENID hostTokenId returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_006, TestSize.Level1)
{
    TokenCleaner cleaner;
    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        QueryCliPermissionsRet(
            INVALID_TOKENID, DEFAULT_AGENT_ID, { BuildCliInfoParcel("location", "query") }, result, cleaner));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_007
 * @tc.desc: Test non-HAP hostTokenId returns token-not-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_007, TestSize.Level1)
{
    TokenCleaner cleaner;
    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST, QueryCliPermissionsRet(
        GetNativeProcessTokenId(), DEFAULT_AGENT_ID, { BuildCliInfoParcel("location", "query") }, result, cleaner));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_008
 * @tc.desc: Test invalid agentID returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_008, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_008_host", true, {});
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        QueryCliPermissionsRet(
            hostTokenId, BuildInvalidAgentId(), { BuildCliInfoParcel("location", "query") }, result, cleaner));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_009
 * @tc.desc: Test empty cliInfoList returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_009, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_009_host", true, {});
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    CliPermissionsResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        QueryCliPermissionsRet(hostTokenId, DEFAULT_AGENT_ID, {}, result, cleaner));
    EXPECT_TRUE(result.result.permList.empty());
}

/**
 * @tc.name: GetCliPermissions_010
 * @tc.desc: Test permanently granted CLI Permission returns granted status and mapped permissions.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliPermissions_010, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_query_010_host", true,
        { BuildGrantedStatus(CUSTOM_SCREEN_CAPTURE, PERMISSION_SYSTEM_FIXED) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();
    SetMockCliRuntimePermissionsForTest(
        { { CUSTOM_SCREEN_CAPTURE, { LOCATION_PERMISSION, CAMERA_PERMISSION } } });

    auto result = QueryCliPermissions(hostTokenId, { BuildCliInfoParcel("location", "query") }, cleaner).info;
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
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto hostPerms = std::vector<PermissionStatus> {
        BuildDeniedStatus(LOCATION_PERMISSION),
        BuildGrantedStatus(WIFI_PERMISSION),
        BuildInitialStatus(CAMERA_PERMISSION),
        BuildDeniedStatus(PUSH_PERMISSION, PERMISSION_FIXED_FOR_SECURITY_POLICY),
    };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_001_host", true, hostPerms);
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto authResult = GenerateCliAuthResult(hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("location", "query"), { CUSTOM_SCREEN_CAPTURE }, { true }) }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        hostTokenId, authResult.result.authResults[0], BuildCliInfo("location", "query"), kernelPermList);
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, LOCATION_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, WIFI_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, CAMERA_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, MICROPHONE_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, AUDIO_PERMISSION));
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, PUSH_PERMISSION));
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
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    auto hostPerms = std::vector<PermissionStatus> {
        BuildDeniedStatus(LOCATION_PERMISSION),
        BuildGrantedStatus(WIFI_PERMISSION),
        BuildInitialStatus(CAMERA_PERMISSION),
        BuildDeniedStatus(PUSH_PERMISSION, PERMISSION_FIXED_FOR_SECURITY_POLICY),
    };
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_002_host", true, hostPerms);
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto authResult = GenerateCliAuthResult(hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("location", "query"), { CUSTOM_SCREEN_CAPTURE }, { false }) }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        hostTokenId, authResult.result.authResults[0], BuildCliInfo("location", "query"), kernelPermList);
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, LOCATION_PERMISSION));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, WIFI_PERMISSION));
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, CAMERA_PERMISSION));
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, MICROPHONE_PERMISSION));
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, AUDIO_PERMISSION));
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, PUSH_PERMISSION));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GenerateCliAuthResult_003
 * @tc.desc: Test self-mapped granted system permission remains granted.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_003, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullHostTokenId = CreateServiceTestToken(
        "tooltoken_auth_003_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, fullHostTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(fullHostTokenId);
    cleaner.Add(hostTokenId);

    auto authResult = GenerateCliAuthResult(hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true }) }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    ASSERT_FALSE(authResult.result.authResults[0].empty());

    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        hostTokenId, authResult.result.authResults[0], BuildCliInfo("settings", "set"), kernelPermList);
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, ACCESS_SYSTEM_SETTINGS));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GenerateCliAuthResult_004
 * @tc.desc: Test granted system permission is not downgraded by CLI denied result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_004, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullHostTokenId = CreateServiceTestToken(
        "tooltoken_auth_004_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, fullHostTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(fullHostTokenId);
    cleaner.Add(hostTokenId);

    auto authResult = GenerateCliAuthResult(hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { false }) }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    ASSERT_FALSE(authResult.result.authResults[0].empty());

    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        hostTokenId, authResult.result.authResults[0], BuildCliInfo("settings", "set"), kernelPermList);
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, ACCESS_SYSTEM_SETTINGS));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GenerateCliAuthResult_005
 * @tc.desc: Test initial-state system permission follows granted CLI authorization result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_005, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullHostTokenId = CreateServiceTestToken(
        "tooltoken_auth_005_host", true, { BuildInitialStatus(CAMERA_PERMISSION) });
    ASSERT_NE(0, fullHostTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(fullHostTokenId);
    cleaner.Add(hostTokenId);

    auto authResult = GenerateCliAuthResult(hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { CAMERA_PERMISSION }, { true }) }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    ASSERT_FALSE(authResult.result.authResults[0].empty());

    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        hostTokenId, authResult.result.authResults[0], BuildCliInfo("settings", "set"), kernelPermList);
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(toolTokenId, CAMERA_PERMISSION));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GenerateCliAuthResult_006
 * @tc.desc: Test initial-state system permission follows denied CLI authorization result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_006, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t fullHostTokenId = CreateServiceTestToken(
        "tooltoken_auth_006_host", true, { BuildInitialStatus(CAMERA_PERMISSION) });
    ASSERT_NE(0, fullHostTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(fullHostTokenId);
    cleaner.Add(hostTokenId);

    auto authResult = GenerateCliAuthResult(hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { CAMERA_PERMISSION }, { false }) }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    ASSERT_FALSE(authResult.result.authResults[0].empty());

    std::vector<std::string> kernelPermList;
    AccessTokenID toolTokenId = InitCliToolToken(
        hostTokenId, authResult.result.authResults[0], BuildCliInfo("settings", "set"), kernelPermList);
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(toolTokenId, CAMERA_PERMISSION));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GenerateCliAuthResult_007
 * @tc.desc: Test invalid hostTokenId returns invalid-param or token-not-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_007, TestSize.Level1)
{
    TokenCleaner cleaner;

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, GenerateCliAuthResultRet(
        INVALID_TOKENID,
        { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true }) },
        result, cleaner));
}

/**
 * @tc.name: GenerateCliAuthResult_008
 * @tc.desc: Test empty authInfoList returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_008, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_008_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        GenerateCliAuthResultRet(hostTokenId, {}, result, cleaner));
}

/**
 * @tc.name: GenerateCliAuthResult_009
 * @tc.desc: Test mismatched permissionNames and authorizationResults returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_009, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_009_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        GenerateCliAuthResultRet(hostTokenId,
            { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, {}) },
            result, cleaner));
}

/**
 * @tc.name: GenerateCliAuthResult_010
 * @tc.desc: Test undeclared required CLI Permission returns filtered empty challenge result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_010, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_010_host", true, {});
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();

    auto result = GenerateCliAuthResult(hostTokenId,
        { BuildCliAuthInfoParcel(BuildCliInfo("location", "query"), { CUSTOM_SCREEN_CAPTURE }, { true }) }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(result.result.authResults.size()));
    EXPECT_FALSE(result.result.authResults[0].empty());

    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = result.result.authResults[0],
        .cliInfo = BuildCliInfo("location", "query"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    EXPECT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
}

/**
 * @tc.name: GenerateCliAuthResult_011
 * @tc.desc: Test single valid CliAuthInfo returns one non-empty challenge result.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_011, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_012_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);
    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "auth_010_challenge", "auth_010_ticket");

    auto result = GenerateCliAuthResult(hostTokenId, { authInfo }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(result.result.authResults.size()));
    EXPECT_EQ("auth_010_challenge", result.result.authResults[0]);
}

/**
 * @tc.name: GenerateCliAuthResult_012
 * @tc.desc: Test non-HAP hostTokenId returns token-not-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_012, TestSize.Level1)
{
    TokenCleaner cleaner;

    ToolAuthResultParcel result;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        GenerateCliAuthResultRet(GetNativeProcessTokenId(),
            { BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true }) },
            result, cleaner));
    EXPECT_TRUE(result.result.authResults.empty());
}

/**
 * @tc.name: GenerateCliAuthResult_013
 * @tc.desc: Test invalid agentID returns invalid-param.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GenerateCliAuthResult_013, TestSize.Level1)
{
    AccessTokenID callerTokenId = INVALID_TOKENID;
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t callerFullTokenId =
        CreateServiceTestToken("tooltoken_auth_012_caller", true, BuildManagePermissionStates());
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_auth_013_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, callerFullTokenId);
    ASSERT_NE(0, hostFullTokenId);
    callerTokenId = GetTokenIdFromFullTokenId(callerFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
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
 * @tc.name: InitCliToken_001
 * @tc.desc: Test InitCliToken fails when challenge does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_001, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_init_001_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = "not_exist_challenge",
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
}

/**
 * @tc.name: InitCliToken_002
 * @tc.desc: Test consumed challenge cannot be reused after successful initialization.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_002, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_002_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_010_challenge", "init_010_ticket");
    std::string challenge = GenerateSingleCliAuthChallenge(hostTokenId, authInfo, cleaner);
    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    uint64_t secondFullTokenId = 0;
    std::vector<PermissionWithValueIdl> secondKernelPermIdlList;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        InitCliToolTokenRet(initInfoParcel, secondFullTokenId, secondKernelPermIdlList));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_003
 * @tc.desc: Test mismatched cliInfo fails and original challenge can retry with correct cliInfo.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_003, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_003_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_011_challenge", "init_011_ticket");
    std::string challenge = GenerateSingleCliAuthChallenge(hostTokenId, authInfo, cleaner);
    CliInitInfoParcel failedInitInfoParcel;
    failedInitInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "wrong"),
    };
    uint64_t failedFullTokenId = 0;
    std::vector<PermissionWithValueIdl> failedKernelPermIdlList;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        InitCliToolTokenRet(failedInitInfoParcel, failedFullTokenId, failedKernelPermIdlList));

    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_004
 * @tc.desc: Test mismatched hostTokenId fails and original challenge can retry with correct hostTokenId.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_004, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    AccessTokenID otherHostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_004_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    uint64_t otherHostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_004_other_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, hostFullTokenId);
    ASSERT_NE(0, otherHostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    otherHostTokenId = GetTokenIdFromFullTokenId(otherHostFullTokenId);
    cleaner.Add(hostTokenId);
    cleaner.Add(otherHostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_016_challenge", "init_016_ticket");
    std::string challenge = GenerateSingleCliAuthChallenge(hostTokenId, authInfo, cleaner);

    CliInitInfoParcel failedInitInfoParcel;
    failedInitInfoParcel.cliInitInfo = {
        .hostTokenId = otherHostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t failedFullTokenId = 0;
    std::vector<PermissionWithValueIdl> failedKernelPermIdlList;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        InitCliToolTokenRet(failedInitInfoParcel, failedFullTokenId, failedKernelPermIdlList));

    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = challenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_005
 * @tc.desc: Test repeated creation in the same pid returns already-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_005, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_005_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_012_first_challenge", "init_012_first_ticket");
    std::string firstChallenge = GenerateSingleCliAuthChallenge(hostTokenId, authInfo, cleaner);
    CliInitInfoParcel firstInitInfoParcel;
    firstInitInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = firstChallenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t firstFullTokenId = 0;
    std::vector<PermissionWithValueIdl> firstKernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(firstInitInfoParcel, firstFullTokenId, firstKernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(firstFullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    MockSingleCliAuthChallenge(authInfo, "init_012_second_challenge", "init_012_second_ticket");
    std::string secondChallenge = GenerateSingleCliAuthChallenge(hostTokenId, authInfo, cleaner);
    CliInitInfoParcel secondInitInfoParcel;
    secondInitInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = secondChallenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t secondFullTokenId = 0;
    std::vector<PermissionWithValueIdl> secondKernelPermIdlList;
    EXPECT_EQ(AccessTokenError::ERR_TOOL_TOKEN_ALREADY_EXIST,
        InitCliToolTokenRet(secondInitInfoParcel, secondFullTokenId, secondKernelPermIdlList));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_006
 * @tc.desc: Test token can be rebuilt after deletion.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_006, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken(
        "tooltoken_init_0063_host", true, { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "init_013_first_challenge", "init_013_first_ticket");
    std::string firstChallenge = GenerateSingleCliAuthChallenge(hostTokenId, authInfo, cleaner);
    CliInitInfoParcel firstInitInfoParcel;
    firstInitInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = firstChallenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t firstFullTokenId = 0;
    std::vector<PermissionWithValueIdl> firstKernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(firstInitInfoParcel, firstFullTokenId, firstKernelPermIdlList));
    AccessTokenID firstTokenId = GetTokenIdFromFullTokenId(firstFullTokenId);
    ASSERT_NE(INVALID_TOKENID, firstTokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));

    MockSingleCliAuthChallenge(authInfo, "init_013_second_challenge", "init_013_second_ticket");
    std::string secondChallenge = GenerateSingleCliAuthChallenge(hostTokenId, authInfo, cleaner);
    CliInitInfoParcel secondInitInfoParcel;
    secondInitInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = secondChallenge,
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t secondFullTokenId = 0;
    std::vector<PermissionWithValueIdl> secondKernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(secondInitInfoParcel, secondFullTokenId, secondKernelPermIdlList));
    AccessTokenID secondTokenId = GetTokenIdFromFullTokenId(secondFullTokenId);
    ASSERT_NE(INVALID_TOKENID, secondTokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: InitCliToken_007
 * @tc.desc: Test empty permissionNames challenge creates a no-permission token.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, InitCliToken_007, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_init_007_host", true, {});
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "mock_empty_perm_challenge", "mock_empty_perm_ticket");
    ToolAuthResultParcel authResult = GenerateCliAuthResult(hostTokenId, { authInfo }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    ASSERT_FALSE(authResult.result.authResults[0].empty());

    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    EXPECT_TRUE(kernelPermIdlList.empty());
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(tokenId, LOCATION_PERMISSION));
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: DeleteToolTokenByPid_001
 * @tc.desc: Test deleting the same pid twice returns token-not-exist on the second call.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, DeleteToolTokenByPid_001, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_delete_001_host", true, {});
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "delete_003_challenge", "delete_003_ticket");
    ToolAuthResultParcel authResult = GenerateCliAuthResult(hostTokenId, { authInfo }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GetCliTokenInfo_001
 * @tc.desc: Test deleted and non-existent token return token-not-exist.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetCliTokenInfo_001, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_getcli_001_host", true, {});
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "getcli_004_challenge", "getcli_004_ticket");
    ToolAuthResultParcel authResult = GenerateCliAuthResult(hostTokenId, { authInfo }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    int32_t deleteRet = ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid());
    EXPECT_EQ(RET_SUCCESS, deleteRet);
    CliTokenInfo tokenInfo;

    CliTokenInfo infoParcel;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        ToolTokenInfoManager::GetInstance().GetCliTokenInfo(tokenId, infoParcel));
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        ToolTokenInfoManager::GetInstance().GetCliTokenInfo(INVALID_TOKENID, infoParcel));
}

/**
 * @tc.name: GetHostTokenId_001
 * @tc.desc: Test deleted tool token returns token-not-exist when querying host token.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetHostTokenId_001, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_gethost_001_host", true, {});
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "gethost_004_challenge", "gethost_004_ticket");
    ToolAuthResultParcel authResult = GenerateCliAuthResult(hostTokenId, { authInfo }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));

    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        ToolTokenInfoManager::GetInstance().GetHostTokenId(tokenId, queriedHostTokenId));
}

/**
 * @tc.name: GetHostTokenId_002
 * @tc.desc: Test existing non-tool token returns invalid-param when querying host token.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetHostTokenId_002, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_gethost_002_host", true, {});
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    AccessTokenID queriedHostTokenId = INVALID_TOKENID;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        ToolTokenInfoManager::GetInstance().GetHostTokenId(hostTokenId, queriedHostTokenId));
}

/**
 * @tc.name: GetUserId_001
 * @tc.desc: Test querying user id validates token type and returns the user id of an existing tool token.
 * @tc.type: FUNC
 */
HWTEST_F(ToolTokenMockTest, GetUserId_001, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_getuser_001_host", true, {});
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    int32_t userId = -1;
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID, ToolTokenInfoManager::GetInstance().GetUserId(hostTokenId, userId));

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), {}, {});
    MockSingleCliAuthChallenge(authInfo, "getuser_001_challenge", "getuser_001_ticket");
    ToolAuthResultParcel authResult = GenerateCliAuthResult(hostTokenId, { authInfo }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID toolTokenId = GetTokenIdFromFullTokenId(fullTokenId);
    ASSERT_NE(INVALID_TOKENID, toolTokenId);

    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().GetUserId(toolTokenId, userId));
    EXPECT_EQ(USER_ID, userId);

    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        ToolTokenInfoManager::GetInstance().GetUserId(toolTokenId, userId));
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
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_restricted_flag_host", true,
        { BuildGrantedStatus(CAMERA_PERMISSION, PERMISSION_SYSTEM_FIXED) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo = BuildCliAuthInfoParcel(BuildCliInfo("camera", "capture"), { CAMERA_PERMISSION }, { true });
    MockSingleCliAuthChallenge(authInfo, "restricted_flag_challenge", "restricted_flag_ticket");
    ToolAuthResultParcel authResult = GenerateCliAuthResult(hostTokenId, { authInfo }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("camera", "capture"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);

    uint32_t permCode = 0;
    ASSERT_TRUE(TransferPermissionToOpcode(CAMERA_PERMISSION, permCode));
    bool hasFlagChanged = false;
    EXPECT_EQ(RET_SUCCESS,
        ToolTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, hasFlagChanged));
    EXPECT_TRUE(hasFlagChanged);
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(tokenId, CAMERA_PERMISSION));

    hasFlagChanged = true;
    EXPECT_EQ(RET_SUCCESS,
        ToolTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, true, hasFlagChanged));
    EXPECT_FALSE(hasFlagChanged);

    hasFlagChanged = false;
    EXPECT_EQ(RET_SUCCESS,
        ToolTokenInfoManager::GetInstance().UpdateRestrictedFlag(tokenId, permCode, false, hasFlagChanged));
    EXPECT_TRUE(hasFlagChanged);
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(tokenId, CAMERA_PERMISSION));

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
 * @tc.desc: Test service user policy refresh covers tool token policy branches.
 * @tc.type: FUNC
 */
#ifdef SUPPORT_MANAGE_USER_POLICY
HWTEST_F(ToolTokenMockTest, RefreshUserPolicyFlag_002, TestSize.Level1)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    TokenCleaner cleaner;
    uint64_t hostFullTokenId = CreateServiceTestToken("tooltoken_user_policy_host", true,
        { BuildGrantedStatus(ACCESS_SYSTEM_SETTINGS, PERMISSION_SYSTEM_FIXED) });
    ASSERT_NE(0, hostFullTokenId);
    hostTokenId = GetTokenIdFromFullTokenId(hostFullTokenId);
    cleaner.Add(hostTokenId);

    PrepareMockEnvironment();
    auto authInfo =
        BuildCliAuthInfoParcel(BuildCliInfo("settings", "set"), { ACCESS_SYSTEM_SETTINGS }, { true });
    MockSingleCliAuthChallenge(authInfo, "user_policy_challenge", "user_policy_ticket");
    ToolAuthResultParcel authResult = GenerateCliAuthResult(hostTokenId, { authInfo }, cleaner);
    ASSERT_EQ(1, static_cast<int32_t>(authResult.result.authResults.size()));
    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo = {
        .hostTokenId = hostTokenId,
        .challenge = authResult.result.authResults[0],
        .cliInfo = BuildCliInfo("settings", "set"),
    };
    uint64_t fullTokenId = 0;
    std::vector<PermissionWithValueIdl> kernelPermIdlList;
    ASSERT_EQ(RET_SUCCESS, InitCliToolTokenRet(initInfoParcel, fullTokenId, kernelPermIdlList));
    AccessTokenID tokenId = GetTokenIdFromFullTokenId(fullTokenId);
    ASSERT_NE(INVALID_TOKENID, tokenId);
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(hostTokenId, ACCESS_SYSTEM_SETTINGS));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS));

    UserPermissionPolicyIdl policy;
    policy.permissionName = ACCESS_SYSTEM_SETTINGS;
    policy.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    policy.isPersist = false;
    EXPECT_EQ(RET_SUCCESS, SetUserPolicyRet({ policy }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(hostTokenId, ACCESS_SYSTEM_SETTINGS));
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS));

    policy.userPolicyList = {{ .userId = USER_ID + 1, .isRestricted = true }};
    EXPECT_EQ(RET_SUCCESS, SetUserPolicyRet({ policy }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(hostTokenId, ACCESS_SYSTEM_SETTINGS));
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS));

    policy.userPolicyList = {{ .userId = USER_ID, .isRestricted = false }};
    EXPECT_EQ(RET_SUCCESS, SetUserPolicyRet({ policy }));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(hostTokenId, ACCESS_SYSTEM_SETTINGS));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS));

    policy.permissionName = CAMERA_PERMISSION;
    policy.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    EXPECT_EQ(RET_SUCCESS, SetUserPolicyRet({ policy }));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(hostTokenId, ACCESS_SYSTEM_SETTINGS));
    EXPECT_EQ(PERMISSION_GRANTED, VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS));

    policy.permissionName = ACCESS_SYSTEM_SETTINGS;
    policy.userPolicyList = {{ .userId = USER_ID, .isRestricted = true }};
    EXPECT_EQ(RET_SUCCESS, SetUserPolicyRet({ policy }));
    EXPECT_EQ(PERMISSION_DENIED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(hostTokenId, ACCESS_SYSTEM_SETTINGS));
    EXPECT_EQ(PERMISSION_DENIED, VerifyRuntimePermission(tokenId, ACCESS_SYSTEM_SETTINGS));

    EXPECT_EQ(RET_SUCCESS, ToolTokenInfoManager::GetInstance().DeleteToolTokenByPid(getpid()));
    policy.userPolicyList = {{ .userId = USER_ID, .isRestricted = false }};
    EXPECT_EQ(RET_SUCCESS, SetUserPolicyRet({ policy }));
    EXPECT_EQ(PERMISSION_GRANTED,
        AccessTokenInfoManager::GetInstance().VerifyAccessToken(hostTokenId, ACCESS_SYSTEM_SETTINGS));

    EXPECT_EQ(RET_SUCCESS, ClearUserPolicyRet({ ACCESS_SYSTEM_SETTINGS }));
    EXPECT_EQ(RET_SUCCESS, ClearUserPolicyRet({ CAMERA_PERMISSION }));
}
#endif
}
}
}
