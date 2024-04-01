/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "accesstoken_kit_test.h"
#include <thread>
#include "access_token_error.h"
#include "permission_grant_info.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
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
}
void AccessTokenKitTest::SetUpTestCase()
{
}

void AccessTokenKitTest::TearDownTestCase()
{
}

void AccessTokenKitTest::SetUp()
{
}

void AccessTokenKitTest::TearDown()
{
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: AllocHapToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, AllocHapToken001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, AllocLocalTokenID001, TestSize.Level1)
{
    std::string remoteDevice = "remote device";
    AccessTokenID tokenId = 123;
    AccessTokenID localTokenId = AccessTokenKit::AllocLocalTokenID(remoteDevice, tokenId);
    ASSERT_EQ(INVALID_TOKENID, localTokenId);
}

/**
 * @tc.name: UpdateHapToken001
 * @tc.desc: UpdateHapToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, UpdateHapToken001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, DeleteToken001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, GetTokenType001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    ASSERT_EQ(TOKEN_INVALID, AccessTokenKit::GetTokenType(tokenId));
}

/**
 * @tc.name: CheckNativeDCap001
 * @tc.desc: CheckNativeDCap with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, CheckNativeDCap001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    const std::string dcap = "AT_CAP";
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::CheckNativeDCap(tokenId, dcap));
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: GetHapTokenID with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenID001, TestSize.Level1)
{
    int32_t userID = 0;
    std::string bundleName = "test";
    int32_t instIndex = 0;
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
    ASSERT_EQ(INVALID_TOKENID, tokenId);
}

/**
 * @tc.name: GetHapTokenInfo001
 * @tc.desc: GetHapTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetHapTokenInfo001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, GetNativeTokenInfo001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    NativeTokenInfo tokenInfo;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo));
}

/**
 * @tc.name: VerifyAccessToken001
 * @tc.desc: VerifyAccessToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, VerifyAccessToken001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, VerifyAccessToken002, TestSize.Level1)
{
    AccessTokenID callerTokenID = 123;
    AccessTokenID firstTokenID = 456;
    std::string permission = "ohos.permission.CAMERA";
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(callerTokenID, firstTokenID, permission));
    ASSERT_EQ(PERMISSION_DENIED, AccessTokenKit::VerifyAccessToken(callerTokenID, firstTokenID, permission, true));
}

/**
 * @tc.name: GetDefPermission001
 * @tc.desc: GetDefPermission with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetDefPermission001, TestSize.Level1)
{
    std::string permission = "ohos.permission.CAMERA";
    PermissionDef def;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetDefPermission(permission, def));
}

/**
 * @tc.name: GetDefPermissions001
 * @tc.desc: GetDefPermissions with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetDefPermissions001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    std::vector<PermissionDef> permList;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetDefPermissions(tokenId, permList));
}

/**
 * @tc.name: GetReqPermissions001
 * @tc.desc: GetReqPermissions with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetReqPermissions001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    std::vector<PermissionStateFull> permList;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetReqPermissions(tokenId, permList, false));
}

/**
 * @tc.name: DumpPermDefInfo001
 * @tc.desc: DumpPermDefInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, DumpPermDefInfo001, TestSize.Level1)
{
    std::string dumpInfo = "";
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::DumpPermDefInfo(dumpInfo));
}

/**
 * @tc.name: GetPermissionFlag001
 * @tc.desc: GetPermissionFlag with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetPermissionFlag001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, SetPermissionRequestToggleStatus001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, GetPermissionRequestToggleStatus001, TestSize.Level1)
{
    int32_t userID = 123;
    std::string permission = "ohos.permission.CAMERA";
    uint32_t status;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetPermissionRequestToggleStatus(permission,
        status, userID));
}

/**
 * @tc.name: GetSelfPermissionsState001
 * @tc.desc: GetSelfPermissionsState with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetSelfPermissionsState001, TestSize.Level1)
{
    std::vector<PermissionListState> permList;
    PermissionGrantInfo info;
    ASSERT_EQ(INVALID_OPER, AccessTokenKit::GetSelfPermissionsState(permList, info));
}

/**
 * @tc.name: GrantPermission001
 * @tc.desc: GrantPermission with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GrantPermission001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, RevokePermission001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, ClearUserGrantedPermissionState001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, RegisterPermStateChangeCallback001, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));
}

/**
 * @tc.name: ReloadNativeTokenInfo001
 * @tc.desc: ReloadNativeTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, ReloadNativeTokenInfo001, TestSize.Level1)
{
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::ReloadNativeTokenInfo());
}

/**
 * @tc.name: GetNativeTokenId001
 * @tc.desc: Verify the GetNativeTokenId abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenKitTest, GetNativeTokenId001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, GetHapTokenInfoFromRemote001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetHapTokenInfoFromRemote(tokenId, hapSync));
}

/**
 * @tc.name: GetAllNativeTokenInfo001
 * @tc.desc: GetAllNativeTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, GetAllNativeTokenInfo001, TestSize.Level1)
{
    std::vector<NativeTokenInfoForSync> nativeTokenInfosRes;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::GetAllNativeTokenInfo(nativeTokenInfosRes));
}

/**
 * @tc.name: SetRemoteHapTokenInfo001
 * @tc.desc: SetRemoteHapTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, SetRemoteHapTokenInfo001, TestSize.Level1)
{
    std::string device = "device";
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::SetRemoteHapTokenInfo(device, hapSync));
}

/**
 * @tc.name: SetRemoteNativeTokenInfo001
 * @tc.desc: SetRemoteNativeTokenInfo with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, SetRemoteNativeTokenInfo001, TestSize.Level1)
{
    std::string device = "device";
    std::vector<NativeTokenInfoForSync> nativeToken;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::SetRemoteNativeTokenInfo(device, nativeToken));
}

/**
 * @tc.name: DeleteRemoteToken001
 * @tc.desc: DeleteRemoteToken with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, DeleteRemoteToken001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, GetRemoteNativeTokenID001, TestSize.Level1)
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
HWTEST_F(AccessTokenKitTest, DeleteRemoteDeviceTokens001, TestSize.Level1)
{
    std::string device = "device";
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::DeleteRemoteDeviceTokens(device));
}
#endif

/**
 * @tc.name: SetPermDialogCap001
 * @tc.desc: SetPermDialogCap with proxy is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenKitTest, SetPermDialogCap001, TestSize.Level1)
{
    HapBaseInfo hapBaseInfo;
    ASSERT_EQ(AccessTokenError::ERR_SERVICE_ABNORMAL, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
}
}  // namespace AccessToken
}  // namespace Security
}
