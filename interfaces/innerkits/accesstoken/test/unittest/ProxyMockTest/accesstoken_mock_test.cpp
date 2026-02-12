/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "accesstoken_mock_test.h"
#include <thread>
#include "access_token_error.h"
#include "permission_grant_info.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static AccessTokenID g_testTokenId = 123;  // 123: tokenId
static constexpr int32_t DEFAULT_API_VERSION = 8;
HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test1",
    .apiVersion = DEFAULT_API_VERSION
};
HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
};
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
void AccessTokenMockTest::SetUpTestCase()
{
}

void AccessTokenMockTest::TearDownTestCase()
{
}

void AccessTokenMockTest::SetUp()
{
}

void AccessTokenMockTest::TearDown()
{
}

/**
 * @tc.name: InitHapToken001
 * @tc.desc: InitHapToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, InitHapToken001, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    int32_t ret = AccessTokenKit::InitHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(ret, AccessTokenError::ERR_SERVICE_ABNORMAL);
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: AllocHapToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, AllocHapToken001, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: AllocLocalTokenID001
 * @tc.desc: AllocLocalTokenID with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, AllocLocalTokenID001, TestSize.Level4)
{
    std::string remoteDevice = "remote device";
    AccessTokenID tokenId = 123; // 123: tokenId
    AccessTokenIDEx idEx = {0};
    idEx.tokenIDEx = AccessTokenKit::AllocLocalTokenID(remoteDevice, tokenId);
    AccessTokenID localTokenId = idEx.tokenIdExStruct.tokenID;
    ASSERT_EQ(INVALID_TOKENID, localTokenId);
}

/**
 * @tc.name: UpdateHapToken001
 * @tc.desc: UpdateHapToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, UpdateHapToken001, TestSize.Level4)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = 123;
    UpdateHapInfoParams info;
    info.appIDDesc = "appId desc";
    info.apiVersion = 9;
    info.isSystemApp = false;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL,
        AccessTokenKit::UpdateHapToken(tokenIdEx, info, g_infoManagerTestPolicyPrams));
}

/**
 * @tc.name: DeleteToken001
 * @tc.desc: DeleteToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, DeleteToken001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::DeleteToken(tokenId));
}

/**
 * @tc.name: GetTokenType001
 * @tc.desc: GetTokenType with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetTokenType001, TestSize.Level4)
{
    AccessTokenID tokenId = 123; // 123: tokenId
    ASSERT_EQ(TOKEN_INVALID, AccessTokenKit::GetTokenType(tokenId));


    FullTokenID fullTokenId = 123; // 123: tokenId
    ASSERT_EQ(TOKEN_INVALID, AccessTokenKit::GetTokenType(fullTokenId));
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: GetHapTokenID with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetHapTokenID001, TestSize.Level4)
{
    int32_t userID = 0;
    std::string bundleName = "test";
    int32_t instIndex = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
    ASSERT_EQ(INVALID_TOKENID, tokenId);
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: GetHapTokenIDEx with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetHapTokenIDEx001, TestSize.Level4)
{
    int32_t userID = 0;
    std::string bundleName = "test";
    int32_t instIndex = 0;
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(userID, bundleName, instIndex);
    ASSERT_EQ(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}

/**
 * @tc.name: GetHapTokenInfo001
 * @tc.desc: GetHapTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetHapTokenInfo001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    HapTokenInfo tokenInfo;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo));
}

/**
 * @tc.name: GetNativeTokenInfo001
 * @tc.desc: GetNativeTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetNativeTokenInfo001, TestSize.Level4)
{
    AccessTokenID tokenId = 805920561; //805920561 is a native tokenId.
    NativeTokenInfo tokenInfo;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo));
}

/**
 * @tc.name: VerifyAccessToken001
 * @tc.desc: VerifyAccessToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, VerifyAccessToken001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, permission));
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(tokenId, permission, true));
}

/**
 * @tc.name: VerifyAccessToken002
 * @tc.desc: VerifyAccessToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, VerifyAccessToken002, TestSize.Level4)
{
    AccessTokenID callerTokenID = 123;
    AccessTokenID firstTokenID = 456;
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(callerTokenID, firstTokenID, permission));
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(callerTokenID, firstTokenID, permission, true));
}

/**
 * @tc.name: VerifyAccessTokenWithList001
 * @tc.desc: VerifyAccessTokenWithList with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, VerifyAccessTokenWithList001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<int32_t> permStateList;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL,
        AccessTokenKit::VerifyAccessToken(tokenId, permissionList, permStateList, true));

    permStateList.clear();
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL,
        AccessTokenKit::VerifyAccessToken(tokenId, permissionList, permStateList, false));
}

/**
 * @tc.name: GetDefPermission001
 * @tc.desc: GetDefPermission with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetDefPermission001, TestSize.Level4)
{
    std::string permission = "ohos.permission.CAMERA";
    PermissionDef def;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetDefPermission(permission, def));
}

/**
 * @tc.name: GetReqPermissions001
 * @tc.desc: GetReqPermissions with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetReqPermissions001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    std::vector<PermissionStateFull> permList;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetReqPermissions(tokenId, permList, false));
}

/**
 * @tc.name: GetTokenIDByUserID001
 * @tc.desc: GetTokenIDByUserID with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetTokenIDByUserID001, TestSize.Level4)
{
    int32_t userID = 1;
    std::unordered_set<AccessTokenID> tokenIdList;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetTokenIDByUserID(userID, tokenIdList));
}

/**
 * @tc.name: GetPermissionFlag001
 * @tc.desc: GetPermissionFlag with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetPermissionFlag001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    std::string permission = "ohos.permission.CAMERA";
    uint32_t flag;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetPermissionFlag(tokenId, permission, flag));
}

/**
 * @tc.name: SetPermissionRequestToggleStatus001
 * @tc.desc: SetPermissionRequestToggleStatus with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, SetPermissionRequestToggleStatus001, TestSize.Level4)
{
    int32_t userID = 123;
    std::string permission = "ohos.permission.CAMERA";
    uint32_t status = PermissionRequestToggleStatus::CLOSED;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::SetPermissionRequestToggleStatus(permission,
        status, userID));
}

/**
 * @tc.name: GetPermissionRequestToggleStatus001
 * @tc.desc: GetPermissionRequestToggleStatus with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetPermissionRequestToggleStatus001, TestSize.Level4)
{
    int32_t userID = 123;
    std::string permission = "ohos.permission.CAMERA";
    uint32_t status;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetPermissionRequestToggleStatus(permission,
        status, userID));
}

/**
 * @tc.name: GetSelfPermissionStatus001
 * @tc.desc: GetSelfPermissionStatus with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetSelfPermissionStatus001, TestSize.Level4)
{
    std::string permission = "ohos.permission.CAMERA";
    PermissionOper status;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetSelfPermissionStatus(permission, status));
}

/**
 * @tc.name: GetSelfPermissionsState001
 * @tc.desc: GetSelfPermissionsState with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetSelfPermissionsState001, TestSize.Level4)
{
    std::vector<PermissionListState> permList;
    PermissionGrantInfo info;
    ASSERT_EQ(INVALID_OPER, AccessTokenKit::GetSelfPermissionsState(permList, info));
}

/**
 * @tc.name: GetPermissionsStatus001
 * @tc.desc: GetPermissionsStatus with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetPermissionsStatus001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    std::vector<PermissionListState> permsList;
    PermissionListState perm = {
        .permissionName = "ohos.permission.testPermDef1",
        .state = SETTING_OPER
    };
    permsList.emplace_back(perm);
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL,
        AccessTokenKit::GetPermissionsStatus(tokenId, permsList));
}

/**
 * @tc.name: GrantPermission001
 * @tc.desc: GrantPermission with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GrantPermission001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL,
        AccessTokenKit::GrantPermission(tokenId, permission, PERMISSION_USER_FIXED));
}

/**
 * @tc.name: RevokePermission001
 * @tc.desc: RevokePermission with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, RevokePermission001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL,
        AccessTokenKit::RevokePermission(tokenId, permission, PERMISSION_USER_FIXED));
}

/**
 * @tc.name: ClearUserGrantedPermissionState001
 * @tc.desc: ClearUserGrantedPermissionState with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, ClearUserGrantedPermissionState001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::ClearUserGrantedPermissionState(tokenId));
}

class CbCustomizeTest : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }
    ~CbCustomizeTest() {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
    }
};

/**
 * @tc.name: RegisterPermStateChangeCallback001
 * @tc.desc: RegisterPermStateChangeCallback with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, RegisterPermStateChangeCallback001, TestSize.Level4)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {GetSelfTokenID()};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
}

/**
 * @tc.name: RegisterSelfPermStateChangeCallback001
 * @tc.desc: RegisterSelfPermStateChangeCallback with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, RegisterSelfPermStateChangeCallback001, TestSize.Level4)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::RegisterSelfPermStateChangeCallback(callbackPtr));
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
}

/**
 * @tc.name: ReloadNativeTokenInfo001
 * @tc.desc: ReloadNativeTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, ReloadNativeTokenInfo001, TestSize.Level4)
{
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::ReloadNativeTokenInfo());
}

/**
 * @tc.name: GetNativeTokenId001
 * @tc.desc: Verify the GetNativeTokenId abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenMockTest, GetNativeTokenId001, TestSize.Level4)
{
    std::string processName = "hdcd";
    AccessTokenID tokenID = AccessTokenKit::GetNativeTokenId(processName);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetHapTokenInfoFromRemote001
 * @tc.desc: GetHapTokenInfoFromRemote with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetHapTokenInfoFromRemote001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetHapTokenInfoFromRemote(tokenId, hapSync));
}

/**
 * @tc.name: SetRemoteHapTokenInfo001
 * @tc.desc: SetRemoteHapTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, SetRemoteHapTokenInfo001, TestSize.Level4)
{
    std::string device = "device";
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::SetRemoteHapTokenInfo(device, hapSync));
}

/**
 * @tc.name: DeleteRemoteToken001
 * @tc.desc: DeleteRemoteToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, DeleteRemoteToken001, TestSize.Level4)
{
    std::string device = "device";
    AccessTokenID tokenId = 123;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::DeleteRemoteToken(device, tokenId));
}

/**
 * @tc.name: GetRemoteNativeTokenID001
 * @tc.desc: GetRemoteNativeTokenID with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetRemoteNativeTokenID001, TestSize.Level4)
{
    std::string device = "device";
    AccessTokenID tokenId = 123;
    ASSERT_EQ(INVALID_TOKENID, AccessTokenKit::GetRemoteNativeTokenID(device, tokenId));
}

/**
 * @tc.name: DeleteRemoteDeviceTokens001
 * @tc.desc: DeleteRemoteDeviceTokens with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, DeleteRemoteDeviceTokens001, TestSize.Level4)
{
    std::string device = "device";
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::DeleteRemoteDeviceTokens(device));
}

/**
 * @tc.name: RegisterTokenSyncCallback001
 * @tc.desc: RegisterTokenSyncCallback with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, RegisterTokenSyncCallback001, TestSize.Level4)
{
    std::shared_ptr<TokenSyncKitInterface> callback = std::make_shared<TokenSyncCallbackImpl>();
    EXPECT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::RegisterTokenSyncCallback(callback));
    EXPECT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::UnRegisterTokenSyncCallback());
}
#endif

/**
 * @tc.name: DumpTokenInfo001
 * @tc.desc: DumpTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, DumpTokenInfo001, TestSize.Level4)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = 123;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("", dumpInfo);
}

/**
 * @tc.name: SetPermDialogCap001
 * @tc.desc: SetPermDialogCap with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, SetPermDialogCap001, TestSize.Level4)
{
    HapBaseInfo hapBaseInfo;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
}

/**
 * @tc.name: GetPermissionManagerInfo001
 * @tc.desc: GetPermissionManagerInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetPermissionManagerInfo001, TestSize.Level4)
{
    PermissionGrantInfo info;
    AccessTokenKit::GetPermissionManagerInfo(info);
    ASSERT_EQ(true, info.grantBundleName.empty());
}

/**
 * @tc.name: GrantPermissionForSpecifiedTime001
 * @tc.desc: GrantPermissionForSpecifiedTime with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GrantPermissionForSpecifiedTime001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    std::string permission = "permission";
    uint32_t onceTime = 1;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL,
        AccessTokenKit::GrantPermissionForSpecifiedTime(tokenId, permission, onceTime));
}

/**
 * @tc.name: RequestAppPermOnSettingTest001
 * @tc.desc: RequestAppPermOnSetting with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, RequestAppPermOnSettingTest001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::RequestAppPermOnSetting(tokenId));
}

/**
 * @tc.name: GetKernelPermissions001
 * @tc.desc: GetKernelPermissions with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetKernelPermissions001, TestSize.Level4)
{
    AccessTokenID tokenId = 123;
    std::vector<PermissionWithValue> kernelPermList;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetKernelPermissions(tokenId, kernelPermList));
}

/**
 * @tc.name: GetPermissionUsedType001
 * @tc.desc: GetPermissionUsedType with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetPermissionUsedType001, TestSize.Level4)
{
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(PermUsedTypeEnum::INVALID_USED_TYPE, AccessTokenKit::GetPermissionUsedType(g_testTokenId, permission));
}

/**
 * @tc.name: GetVersion001
 * @tc.desc: GetVersion with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetVersion001, TestSize.Level4)
{
    uint32_t version;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetVersion(version));
}

/**
 * @tc.name: GetHapTokenInfoExtension001
 * @tc.desc: GetHapTokenInfoExtension with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetHapTokenInfoExtension001, TestSize.Level4)
{
    HapTokenInfoExt hapInfoExt;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL,
        AccessTokenKit::GetHapTokenInfoExtension(g_testTokenId, hapInfoExt));
}

#ifdef SUPPORT_MANAGE_USER_POLICY
/**
 * @tc.name: SetUserPolicy001
 * @tc.desc: SetUserPolicy with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, SetUserPolicy001, TestSize.Level4)
{
    UserPermissionPolicy policy = {
        .permissionName = "ohos.permission.INTERNET",
        .userPolicyList = {
            {
                .userId = 101,
                .isRestricted = true
            }
        } // 101: userId
    };
    std::vector<UserPermissionPolicy> policyList;
    policyList.emplace_back(policy);
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::SetUserPolicy(policyList));
}

/**
 * @tc.name: ClearUserPolicy001
 * @tc.desc: ClearUserPolicy with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, ClearUserPolicy001, TestSize.Level4)
{
    std::vector<std::string> permissionList;
    permissionList.emplace_back("ohos.permission.INTERNET");
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::ClearUserPolicy(permissionList));
}
#endif

/**
 * @tc.name: GetReqPermissionByName001
 * @tc.desc: GetReqPermissionByName with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetReqPermissionByName001, TestSize.Level4)
{
    std::string value;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL,
        AccessTokenKit::GetReqPermissionByName(g_testTokenId, "ohos.permission.CAMERA", value));
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
/**
 * @tc.name: RegisterSecCompEnhance001
 * @tc.desc: RegisterSecCompEnhance with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, RegisterSecCompEnhance001, TestSize.Level4)
{
    SecCompEnhanceData data;
    data.callback = nullptr;
    data.challenge = 0;
    data.seqNum = 0;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::RegisterSecCompEnhance(data));
}

/**
 * @tc.name: UpdateSecCompEnhance001
 * @tc.desc: UpdateSecCompEnhance with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, UpdateSecCompEnhance001, TestSize.Level4)
{
    std::string value;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::UpdateSecCompEnhance(getpid(), 1));
}

/**
 * @tc.name: GetSecCompEnhance001
 * @tc.desc: GetSecCompEnhance with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, GetSecCompEnhance001, TestSize.Level4)
{
    SecCompEnhanceData data;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetSecCompEnhance(getpid(), data));
}
#endif

/**
 * @tc.name: SetPermissionStatusWithPolicy001
 * @tc.desc: SetPermissionStatusWithPolicy with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, SetPermissionStatusWithPolicy001, TestSize.Level4)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    int32_t ret = RET_SUCCESS;
    ret = AccessTokenKit::SetPermissionStatusWithPolicy(
        g_testTokenId, permList, PERMISSION_GRANTED, PERMISSION_FIXED_BY_ADMIN_POLICY);
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, ret);
}

/**
 * @tc.name: QueryPermissionInfosByPerm001
 * @tc.desc: QueryStatusByPermission by permission list with valid parameters and proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, QueryPermissionInfosByPerm001, TestSize.Level4)
{
    std::vector<std::string> permissionList = {"ohos.permission.CAMERA"};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByPermission(permissionList, permissionInfoList);
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}

/**
 * @tc.name: QueryPermissionInfosByToken001
 * @tc.desc: QueryStatusByTokenID by TokenID list with valid parameters and proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenMockTest, QueryPermissionInfosByToken001, TestSize.Level4)
{
    std::vector<AccessTokenID> tokenIDList = {g_testTokenId};
    std::vector<PermissionStatus> permissionInfoList;

    int32_t ret = AccessTokenKit::QueryStatusByTokenID(tokenIDList, permissionInfoList);
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, ret);
    ASSERT_TRUE(permissionInfoList.empty());
}
}  // namespace AccessToken
}  // namespace Security
}
