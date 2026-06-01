/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accesstoken_deny_test.h"

#include <unistd.h>

#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "claw_permission_info.h"
#include "mock_permission.h"
#include "test_common.h"
#include "token_setproc.h"
#ifdef TOKEN_SYNC_ENABLE
#include "token_sync_kit_interface.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t RANDOM_TOKENID = 123;
static constexpr int32_t RANDOM_USERID = 10001;
static constexpr int32_t INVALID_UID = 1234;
static constexpr const char* MANAGE_RUNTIME_CALLER_PROCESS = "com.ohos.permissionmanager";
static const std::string DEFAULT_AGENT_ID = "1001";
static const std::string QUERY_TOOL_PERMISSIONS = "ohos.permission.QUERY_TOOL_PERMISSIONS";
static const std::string MANAGE_TOOL_TOKENID = "ohos.permission.MANAGE_TOOL_TOKENID";
static const std::string MANAGE_TOOL_RUNTIME_PERMISSIONS = "ohos.permission.MANAGE_TOOL_RUNTIME_PERMISSIONS";
static uint64_t g_selfTokenId = 0;
static AccessTokenIDEx g_testTokenIDEx = {0};
static int32_t g_selfUid;

static HapPolicyParams g_PolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
};

static HapInfoParams g_InfoParms = {
    .userID = 1,
    .bundleName = "ohos.test.bundle",
    .instIndex = 0,
    .appIDDesc = "test.bundle",
    .isSystemApp = true
};

CliInfo BuildCliInfo()
{
    return {
        .cliName = "camera",
        .subCliName = "capture",
    };
}

SkillInfo BuildSkillInfo()
{
    return {
        .skillName = "camera_skill",
        .bundleName = "ohos.test.skill",
        .moduleName = "entry",
    };
}

CliAuthInfo BuildCliAuthInfo()
{
    return {
        .cliInfo = BuildCliInfo(),
        .permissionNames = {"ohos.permission.CAMERA"},
        .authorizationResults = {true},
    };
}

SkillAuthInfo BuildSkillAuthInfo()
{
    return {
        .skillInfo = BuildSkillInfo(),
        .permissionNames = {"ohos.permission.CAMERA"},
        .authorizationResults = {true},
    };
}

void RestoreSelfCaller()
{
    EXPECT_EQ(0, setuid(g_selfUid));
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

#ifdef TOKEN_SYNC_ENABLE
static const int32_t FAKE_SYNC_RET = 0xabcdef;
class TokenSyncCallbackImpl : public TokenSyncKitInterface {
    int32_t GetRemoteHapTokenInfo(const std::string& deviceID, AccessTokenID tokenID) const override
    {
        return FAKE_SYNC_RET;
    };

    int32_t DeleteRemoteHapTokenInfo(AccessTokenID tokenID) const override
    {
        return FAKE_SYNC_RET;
    };

    int32_t UpdateRemoteHapTokenInfo(const HapTokenInfoForSync& tokenInfo) const override
    {
        return FAKE_SYNC_RET;
    };
};
#endif
}
using namespace testing::ext;

void AccessTokenDenyTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    g_selfUid = getuid();
    TestCommon::SetTestEvironment(g_selfTokenId);
}

void AccessTokenDenyTest::TearDownTestCase()
{
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
    GTEST_LOG_(INFO) << "PermStateChangeCallback,  tokenID is " << GetSelfTokenID();
    GTEST_LOG_(INFO) << "PermStateChangeCallback,  uid is " << getuid();
}

void AccessTokenDenyTest::SetUp()
{
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_testTokenIDEx.tokenIDEx));
    setuid(1234); // 1234: UID
}

void AccessTokenDenyTest::TearDown()
{
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
}

#ifdef SUPPORT_MANAGE_USER_POLICY
/**
 * @tc.name: SetUserPolicy001
 * @tc.desc: SetUserPolicy without authorized.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenDenyTest, SetUserPolicy001, TestSize.Level0)
{
    UserPermissionPolicy policy;
    policy.permissionName = "ohos.permission.INTERNET";
    UserPolicy userPolicy;
    userPolicy.userId = 100; // 100 is userId
    userPolicy.isRestricted = true;
    policy.userPolicyList.emplace_back(userPolicy);
    std::vector<UserPermissionPolicy> permPolicyList = { policy };
    int32_t ret = AccessTokenKit::SetUserPolicy(permPolicyList);
    EXPECT_EQ(ret, AccessTokenError::ERR_PERMISSION_DENIED);
}

/**
 * @tc.name: ClearUserPolicy001
 * @tc.desc: ClearUserPolicy without authorized.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenDenyTest, ClearUserPolicy001, TestSize.Level0)
{
    int32_t ret = AccessTokenKit::ClearUserPolicy({ "ohos.permission.INTERNET" });
    EXPECT_EQ(ret, AccessTokenError::ERR_PERMISSION_DENIED);
}

/**
 * @tc.name: UpdatePolicyWhiteList001
 * @tc.desc: UpdatePolicyWhiteList without authorized.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenDenyTest, UpdatePolicyWhiteList001, TestSize.Level0)
{
    RestoreSelfCaller();
    MockToken mock(g_selfTokenId, "com.ohos.permissionmanager", true);
    ASSERT_NE(INVALID_TOKENID, mock.GetTokenId()) << mock.GetMockErrorMsg();
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(g_testTokenIDEx.tokenIDEx));
    EXPECT_EQ(0, setuid(INVALID_UID));

    int32_t ret = AccessTokenKit::UpdatePolicyWhiteList(
        mock.GetTokenId(), "ohos.permission.INTERNET", ADD);
    EXPECT_EQ(ret, AccessTokenError::ERR_PERMISSION_DENIED);

    RestoreSelfCaller();
}

/**
 * @tc.name: GetPolicyWhiteList001
 * @tc.desc: GetPolicyWhiteList without authorized.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenDenyTest, GetPolicyWhiteList001, TestSize.Level0)
{
    std::vector<AccessTokenID> tokenIdList;
    int32_t ret = AccessTokenKit::GetPolicyWhiteList("ohos.permission.INTERNET", tokenIdList);
    EXPECT_EQ(ret, AccessTokenError::ERR_PERMISSION_DENIED);
}
#endif

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: AllocHapToken with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, AllocHapToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_InfoParms, g_PolicyPrams);
    ASSERT_EQ(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: InitHapToken001
 * @tc.desc: InitHapToken with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, InitHapToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    int32_t ret = AccessTokenKit::InitHapToken(g_InfoParms, g_PolicyPrams, tokenIdEx);
    ASSERT_NE(ret, RET_SUCCESS);
}

/**
 * @tc.name: AllocLocalTokenID001
 * @tc.desc: AllocLocalTokenID with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, AllocLocalTokenID001, TestSize.Level0)
{
    std::string remoteDevice = "remote device";
    AccessTokenID tokenId = RANDOM_TOKENID;
    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(remoteDevice, tokenId);
    AccessTokenID localTokenId = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(INVALID_TOKENID, localTokenId);
}

/**
 * @tc.name: UpdateHapToken001
 * @tc.desc: UpdateHapToken with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, UpdateHapToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = RANDOM_TOKENID;
    UpdateHapInfoParams info;
    info.appIDDesc = "appId desc";
    info.apiVersion = 9;
    info.isSystemApp = false;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_PolicyPrams));
}

/**
 * @tc.name: DeleteToken001
 * @tc.desc: DeleteToken with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, DeleteToken001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteToken(tokenId));
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: GetHapTokenID with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetHapTokenID001, TestSize.Level0)
{
    int32_t userID = 0;
    std::string bundleName = "test";
    int32_t instIndex = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
    ASSERT_EQ(INVALID_TOKENID, tokenId);
}

/**
 * @tc.name: GetHapTokenInfo001
 * @tc.desc: GetHapTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetHapTokenInfo001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    HapTokenInfo tokenInfo;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo));
}

/**
 * @tc.name: GetNativeTokenInfo001
 * @tc.desc: GetNativeTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetNativeTokenInfo001, TestSize.Level0)
{
    AccessTokenID tokenId = 805920561; //805920561 is a native tokenId.
    NativeTokenInfo tokenInfo;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo));
}

/**
 * @tc.name: GetReqPermissions001
 * @tc.desc: GetReqPermissions with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetReqPermissions001, TestSize.Level0)
{
    std::vector<PermissionStateFull> permStatList;
    AccessTokenID tokenID = RANDOM_TOKENID;

    // no permission
    ASSERT_EQ(
        AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetReqPermissions(tokenID, permStatList, false));
}

/**
 * @tc.name: GetPermissionFlag001
 * @tc.desc: GetPermissionFlag with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetPermissionFlag001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    std::string permission = "ohos.permission.CAMERA";
    uint32_t flag;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetPermissionFlag(tokenId, permission, flag));
}

/**
 * @tc.name: SetPermissionRequestToggleStatus001
 * @tc.desc: SetPermissionRequestToggleStatus with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, SetPermissionRequestToggleStatus001, TestSize.Level0)
{
    int32_t userID = RANDOM_USERID;
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    std::string permission = "ohos.permission.CAMERA";

    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::SetPermissionRequestToggleStatus(
        permission, status, userID));
}

/**
 * @tc.name: GetPermissionRequestToggleStatus001
 * @tc.desc: GetPermissionRequestToggleStatus with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetPermissionRequestToggleStatus001, TestSize.Level0)
{
    int32_t userID = RANDOM_USERID;
    uint32_t status;
    std::string permission = "ohos.permission.CAMERA";

    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetPermissionRequestToggleStatus(
        permission, status, userID));
}

/**
 * @tc.name: GrantPermission001
 * @tc.desc: GrantPermission with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GrantPermission001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GrantPermission(tokenId, permission, PERMISSION_USER_FIXED));
}

/**
 * @tc.name: RevokePermission001
 * @tc.desc: RevokePermission with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, RevokePermission001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::RevokePermission(tokenId, permission, PERMISSION_USER_FIXED));
}

/**
 * @tc.name: ClearUserGrantedPermissionState001
 * @tc.desc: ClearUserGrantedPermissionState with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, ClearUserGrantedPermissionState001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::ClearUserGrantedPermissionState(tokenId));
}

class CbCustomizeTest1 : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest1(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }
    ~CbCustomizeTest1() {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
    }
};

/**
 * @tc.name: RegisterPermStateChangeCallback001
 * @tc.desc: RegisterPermStateChangeCallback with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, RegisterPermStateChangeCallback001, TestSize.Level0)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest1>(scopeInfo);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));
}

/**
 * @tc.name: UnregisterPermStateChangeCallback001
 * @tc.desc: UnRegisterPermStateChangeCallback with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, UnregisterPermStateChangeCallback001, TestSize.Level0)
{
    setuid(g_selfUid);

    PermissionStateFull testState = {
        .permissionName = "ohos.permission.GET_SENSITIVE_PERMISSIONS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED},
        .grantFlags = {1}
    };
    HapPolicyParams policyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permStateList = {testState},
        .aclRequestedList = {"ohos.permission.GET_SENSITIVE_PERMISSIONS"}
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, TestCommon::AllocTestHapToken(g_InfoParms, policyPrams, tokenIdEx));
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest1>(scopeInfo);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(g_testTokenIDEx.tokenIDEx));

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));

    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(tokenIdEx.tokenIDEx));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));

    setuid(g_selfUid);
    EXPECT_EQ(RET_SUCCESS, TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: GetNativeTokenId001
 * @tc.desc: Verify the GetNativeTokenId abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenDenyTest, GetNativeTokenId001, TestSize.Level0)
{
    std::string processName = "hdcd";
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId(processName);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
}

/**
 * @tc.name: DumpTokenInfo001
 * @tc.desc: Verify the DumpTokenInfo abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenDenyTest, DumpTokenInfo001, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = RANDOM_TOKENID;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("", dumpInfo);
}

#if defined(SPM_DATA_ENABLE) && defined(IS_SUPPORT_HAP_RUNNING)
/**
 * @tc.name: CheckHapSignInfoTest001
 * @tc.desc: CheckHapSignInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, CheckHapSignInfoTest001, TestSize.Level0)
{
    std::string path = "/data/not/exist/test.hap";
    BundleHapList hapList;
    hapList.hapPaths.emplace_back(path);
    hapList.isPreInstalled = false;
    hapList.userId = 100;
    int32_t sessionId = 0;
    std::vector<TrustedBundleInfo> bundleInfo;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::CheckHapSignInfo(hapList, sessionId, bundleInfo));
}

/**
 * @tc.name: CheckHapPermissionInfoTest001
 * @tc.desc: CheckHapPermissionInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, CheckHapPermissionInfoTest001, TestSize.Level0)
{
    int32_t sessionId = 123;
    InstallTypeEnum type = TYPE_INSTALL;
    HapInfoCheckResult result;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::CheckHapPermissionInfo(sessionId, type, result));
}

/**
 * @tc.name: PrepareHapIdentityTest001
 * @tc.desc: PrepareHapIdentity with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, PrepareHapIdentityTest001, TestSize.Level0)
{
    int32_t sessionId = 0;

    HapBaseInfo baseInfo;
    baseInfo.userID = 100;
    baseInfo.bundleName = "PrepareHapIdentityTest001";
    baseInfo.instIndex = 0;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    Identity identity;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::PrepareHapIdentity(sessionId, baseInfo, bundlePolicy, identity));
}

/**
 * @tc.name: UpdateHapPolicyTest001
 * @tc.desc: UpdateHapPolicy with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, UpdateHapPolicyTest001, TestSize.Level0)
{
    int32_t sessionId = 123;
    int32_t tokenId = 123;

    BundlePolicy bundlePolicy;
    bundlePolicy.dlpType = DLP_COMMON;
    bundlePolicy.isDebugGrant = false;

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::UpdateHapPolicy(sessionId, tokenId, bundlePolicy));
}

/**
 * @tc.name: FinishInstallTest001
 * @tc.desc: FinishInstall with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, FinishInstallTest001, TestSize.Level0)
{
    int32_t sessionId = 123;
    std::map<std::string, std::string> modulePathMap;

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::FinishInstall(sessionId, false, modulePathMap));
}

/**
 * @tc.name: GetCacheSignInfoBySessionIdTest001
 * @tc.desc: GetCacheSignInfoBySessionId with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetCacheSignInfoBySessionIdTest001, TestSize.Level0)
{
    int32_t sessionId = 123;
    std::vector<TrustedBundleInfo> bundleInfo;

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GetCacheSignInfoBySessionId(sessionId, bundleInfo));
}

/**
 * @tc.name: GetHapSignInfoTest001
 * @tc.desc: GetHapSignInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetHapSignInfoTest001, TestSize.Level0)
{
    std::string bundleName = "GetHapSignInfoTest001";
    std::vector<TrustedBundleInfo> bundleInfo;

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetHapSignInfo(bundleName, bundleInfo));
}
#endif

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetHapTokenInfoFromRemote001
 * @tc.desc: GetHapTokenInfoFromRemote with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetHapTokenInfoFromRemote001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetHapTokenInfoFromRemote(tokenId, hapSync));
}

/**
 * @tc.name: SetRemoteHapTokenInfo001
 * @tc.desc: SetRemoteHapTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, SetRemoteHapTokenInfo001, TestSize.Level0)
{
    std::string device = "device";
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::SetRemoteHapTokenInfo(device, hapSync));
}

/**
 * @tc.name: DeleteRemoteToken001
 * @tc.desc: DeleteRemoteToken with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, DeleteRemoteToken001, TestSize.Level0)
{
    std::string device = "device";
    AccessTokenID tokenId = RANDOM_TOKENID;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteRemoteToken(device, tokenId));
}

/**
 * @tc.name: GetRemoteNativeTokenID001
 * @tc.desc: GetRemoteNativeTokenID with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetRemoteNativeTokenID001, TestSize.Level0)
{
    std::string device = "device";
    AccessTokenID tokenId = RANDOM_TOKENID;
    ASSERT_EQ(INVALID_TOKENID, AccessTokenKit::GetRemoteNativeTokenID(device, tokenId));
}

/**
 * @tc.name: DeleteRemoteDeviceTokens001
 * @tc.desc: DeleteRemoteDeviceTokens with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, DeleteRemoteDeviceTokens001, TestSize.Level0)
{
    std::string device = "device";
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteRemoteDeviceTokens(device));
}

HWTEST_F(AccessTokenDenyTest, RegisterTokenSyncCallback001, TestSize.Level0)
{
    std::shared_ptr<TokenSyncKitInterface> callback = std::make_shared<TokenSyncCallbackImpl>();
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::RegisterTokenSyncCallback(callback));
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::UnRegisterTokenSyncCallback());
}
#endif

/**
 * @tc.name: SetPermDialogCap001
 * @tc.desc: SetPermDialogCap with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, SetPermDialogCap001, TestSize.Level0)
{
    HapBaseInfo hapBaseInfo;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
}

/**
 * @tc.name: GrantPermissionForSpecifiedTime001
 * @tc.desc: GrantPermissionForSpecifiedTime with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GrantPermissionForSpecifiedTime001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    std::string permission = "permission";
    uint32_t onceTime = 1;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, permission, onceTime));
}

/**
 * @tc.name: GetKernelPermissions001
 * @tc.desc: GetKernelPermissions with permission denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetKernelPermissions001, TestSize.Level0)
{
    AccessTokenID tokenId = RANDOM_TOKENID;
    std::vector<PermissionWithValue> kernelPermList;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetKernelPermissions(tokenId, kernelPermList));
}

/**
 * @tc.name: InitCliToken001
 * @tc.desc: InitCliToken with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, InitCliToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    EXPECT_EQ(0, setuid(INVALID_UID));
    CliInitInfo initInfo = {
        .hostTokenId = RANDOM_TOKENID,
        .challenge = "challenge",
        .cliInfo = BuildCliInfo(),
    };
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::InitCliToken(initInfo, tokenIdEx, kernelPermList));
    EXPECT_EQ(0, setuid(g_selfUid));
}

/**
 * @tc.name: InitSkillToken001
 * @tc.desc: InitSkillToken with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, InitSkillToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<PermissionWithValue> kernelPermList;
    EXPECT_EQ(0, setuid(INVALID_UID));
    SkillInitInfo initInfo = {
        .hostTokenId = RANDOM_TOKENID,
        .challenge = "challenge",
        .skillInfo = BuildSkillInfo(),
    };
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::InitSkillToken(initInfo, tokenIdEx, kernelPermList));
    EXPECT_EQ(0, setuid(g_selfUid));
}

/**
 * @tc.name: DeleteToolTokenByPid001
 * @tc.desc: DeleteToolTokenByPid with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, DeleteToolTokenByPid001, TestSize.Level0)
{
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteToolTokenByPid(getpid()));

    RestoreSelfCaller();
    MockToken mock(g_selfTokenId, "accesstoken_service", false);
    mock.Revoke(MANAGE_TOOL_TOKENID);

    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteToolTokenByPid(getpid()));
}

/**
 * @tc.name: GetCliTokenInfo001
 * @tc.desc: GetCliTokenInfo with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetCliTokenInfo001, TestSize.Level0)
{
    CliTokenInfo tokenInfo;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetCliTokenInfo(RANDOM_TOKENID, tokenInfo));
}

/**
 * @tc.name: GetSkillTokenInfo001
 * @tc.desc: GetSkillTokenInfo with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetSkillTokenInfo001, TestSize.Level0)
{
    SkillTokenInfo tokenInfo;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GetSkillTokenInfo(RANDOM_TOKENID, tokenInfo));
}

/**
 * @tc.name: GetHostTokenId001
 * @tc.desc: GetHostTokenId with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetHostTokenId001, TestSize.Level0)
{
    AccessTokenID hostTokenId = INVALID_TOKENID;
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GetHostTokenId(RANDOM_TOKENID, hostTokenId));
}

/**
 * @tc.name: GetCliPermissionRequestInfo001
 * @tc.desc: GetCliPermissionRequestInfo with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetCliPermissionRequestInfo001, TestSize.Level0)
{
    RestoreSelfCaller();
    PermissionDialogResult result;
    {
        MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, false);
        EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
            AccessTokenKit::GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, { BuildCliInfo() }, result));
    }

    MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    caller.Revoke(QUERY_TOOL_PERMISSIONS);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GetCliPermissionRequestInfo(DEFAULT_AGENT_ID, { BuildCliInfo() }, result));
}

/**
 * @tc.name: GetSkillPermissionRequestInfo001
 * @tc.desc: GetSkillPermissionRequestInfo with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetSkillPermissionRequestInfo001, TestSize.Level0)
{
    RestoreSelfCaller();
    PermissionDialogResult result;
    {
        MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, false);
        EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
            AccessTokenKit::GetSkillPermissionRequestInfo(DEFAULT_AGENT_ID, { BuildSkillInfo() }, result));
    }

    MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    caller.Revoke(QUERY_TOOL_PERMISSIONS);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GetSkillPermissionRequestInfo(DEFAULT_AGENT_ID, { BuildSkillInfo() }, result));
}

/**
 * @tc.name: GetCliPermissions001
 * @tc.desc: GetCliPermissions with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetCliPermissions001, TestSize.Level0)
{
    RestoreSelfCaller();
    MockToken host(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    CliPermissionsResult result;
    {
        MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, false);
        EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
            AccessTokenKit::GetCliPermissions(host.GetTokenId(), DEFAULT_AGENT_ID, { BuildCliInfo() }, result));
    }

    MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    caller.Revoke(MANAGE_TOOL_RUNTIME_PERMISSIONS);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GetCliPermissions(host.GetTokenId(), DEFAULT_AGENT_ID, { BuildCliInfo() }, result));
}

/**
 * @tc.name: GetSkillPermissions001
 * @tc.desc: GetSkillPermissions with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetSkillPermissions001, TestSize.Level0)
{
    RestoreSelfCaller();
    MockToken host(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    SkillPermissionsResult result;
    {
        MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, false);
        EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
            AccessTokenKit::GetSkillPermissions(host.GetTokenId(), DEFAULT_AGENT_ID, { BuildSkillInfo() }, result));
    }

    MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    caller.Revoke(MANAGE_TOOL_RUNTIME_PERMISSIONS);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GetSkillPermissions(host.GetTokenId(), DEFAULT_AGENT_ID, { BuildSkillInfo() }, result));
}

/**
 * @tc.name: GenerateCliAuthResult001
 * @tc.desc: GenerateCliAuthResult with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GenerateCliAuthResult001, TestSize.Level0)
{
    RestoreSelfCaller();
    MockToken host(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    ToolAuthResult result;
    {
        MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, false);
        EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
            AccessTokenKit::GenerateCliAuthResult(host.GetTokenId(), DEFAULT_AGENT_ID, { BuildCliAuthInfo() }, result));
    }

    MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    caller.Revoke(MANAGE_TOOL_RUNTIME_PERMISSIONS);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GenerateCliAuthResult(host.GetTokenId(), DEFAULT_AGENT_ID, { BuildCliAuthInfo() }, result));
}

/**
 * @tc.name: GenerateSkillAuthResult001
 * @tc.desc: GenerateSkillAuthResult with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GenerateSkillAuthResult001, TestSize.Level0)
{
    RestoreSelfCaller();
    MockToken host(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    ToolAuthResult result;
    {
        MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, false);
        EXPECT_EQ(AccessTokenError::ERR_NOT_SYSTEM_APP,
            AccessTokenKit::GenerateSkillAuthResult(host.GetTokenId(), DEFAULT_AGENT_ID,
                { BuildSkillAuthInfo() }, result));
    }

    MockToken caller(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    caller.Revoke(MANAGE_TOOL_RUNTIME_PERMISSIONS);
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::GenerateSkillAuthResult(host.GetTokenId(), DEFAULT_AGENT_ID, { BuildSkillAuthInfo() }, result));
}

/**
 * @tc.name: DeleteIdentityAbnormalTest001
 * @tc.desc: DeleteIdentity without ohos.permission.MANAGE_HAP_TOKENID returns ERR_PERMISSION_DENIED
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, DeleteIdentityAbnormalTest001, TestSize.Level0)
{
    RestoreSelfCaller();

    // Create a HAP token for testing
    HapInfoParams info = {
        .userID = 100,
        .bundleName = "test.delete.identity.bundle",
        .instIndex = 0,
        .appIDDesc = "test.delete.identity.appid",
        .apiVersion = 8,
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.delete.identity.domain",
    };

    MockToken mock(g_selfTokenId, MANAGE_RUNTIME_CALLER_PROCESS, true);
    mock.Grant("ohos.permission.MANAGE_HAP_TOKENID");

    // Create mock token with MANAGE_HAP_TOKENID permission
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::InitHapToken(info, policy, tokenIdEx));
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // With permission, DeleteIdentity should succeed
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteIdentity(tokenID, info.bundleName, ReservedType::NONE));

    // Restore token for next test (re-create it)
    ASSERT_NE(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::InitHapToken(info, policy, tokenIdEx));
    tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    // Set UID to non-zero to enable permission check
    uid_t uid = getuid();
    setuid(1000);  // Set to non-zero UID
    ASSERT_EQ(0, setuid(1000));

    // Revoke the permission
    mock.Revoke("ohos.permission.MANAGE_HAP_TOKENID");

    // Without permission and with non-zero UID, DeleteIdentity should return ERR_PERMISSION_DENIED
    EXPECT_EQ(AccessTokenError::ERR_PERMISSION_DENIED,
        AccessTokenKit::DeleteIdentity(tokenID, info.bundleName, ReservedType::NONE));

    // Restore UID and clean up
    ASSERT_EQ(0, setuid(uid));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
