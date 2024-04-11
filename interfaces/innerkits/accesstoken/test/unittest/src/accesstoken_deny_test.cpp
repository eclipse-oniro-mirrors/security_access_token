/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "token_setproc.h"
#include "token_sync_kit_interface.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static AccessTokenID g_selfTokenId = 0;
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
}
using namespace testing::ext;

void AccessTokenDenyTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    g_selfUid = getuid();
}

void AccessTokenDenyTest::TearDownTestCase()
{
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    GTEST_LOG_(INFO) << "PermStateChangeCallback,  tokenID is " << GetSelfTokenID();
    GTEST_LOG_(INFO) << "PermStateChangeCallback,  uid is " << getuid();
}

void AccessTokenDenyTest::SetUp()
{
    AccessTokenKit::AllocHapToken(g_InfoParms, g_PolicyPrams);

    g_testTokenIDEx = AccessTokenKit::GetHapTokenIDEx(g_InfoParms.userID,
                                                      g_InfoParms.bundleName,
                                                      g_InfoParms.instIndex);
    ASSERT_NE(INVALID_TOKENID, g_testTokenIDEx.tokenIDEx);
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_testTokenIDEx.tokenIDEx));
    setuid(1234); // 1234: UID
}

void AccessTokenDenyTest::TearDown()
{
    setuid(g_selfUid);
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    setuid(g_selfUid);
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: AllocHapToken with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, AllocHapToken001, TestSize.Level1)
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
HWTEST_F(AccessTokenDenyTest, InitHapToken001, TestSize.Level1)
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
HWTEST_F(AccessTokenDenyTest, AllocLocalTokenID001, TestSize.Level1)
{
    std::string remoteDevice = "remote device";
    AccessTokenID tokenId = 123;
    AccessTokenID localTokenId = AccessTokenKit::AllocLocalTokenID(remoteDevice, tokenId);
    ASSERT_EQ(INVALID_TOKENID, localTokenId);
}

/**
 * @tc.name: UpdateHapToken001
 * @tc.desc: UpdateHapToken with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, UpdateHapToken001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = 123;
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
HWTEST_F(AccessTokenDenyTest, DeleteToken001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteToken(tokenId));
}

/**
 * @tc.name: CheckNativeDCap001
 * @tc.desc: CheckNativeDCap with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, CheckNativeDCap001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    const std::string dcap = "AT_CAP";
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::CheckNativeDCap(tokenId, dcap));
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: GetHapTokenID with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetHapTokenID001, TestSize.Level1)
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
HWTEST_F(AccessTokenDenyTest, GetHapTokenInfo001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    HapTokenInfo tokenInfo;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo));
}

/**
 * @tc.name: GetNativeTokenInfo001
 * @tc.desc: GetNativeTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetNativeTokenInfo001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    NativeTokenInfo tokenInfo;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo));
}

/**
 * @tc.name: GetPermissionFlag001
 * @tc.desc: GetPermissionFlag with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetPermissionFlag001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
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
HWTEST_F(AccessTokenDenyTest, SetPermissionRequestToggleStatus001, TestSize.Level1)
{
    int32_t userID = 123;
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
HWTEST_F(AccessTokenDenyTest, GetPermissionRequestToggleStatus001, TestSize.Level1)
{
    int32_t userID = 123;
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
HWTEST_F(AccessTokenDenyTest, GrantPermission001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
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
HWTEST_F(AccessTokenDenyTest, RevokePermission001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
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
HWTEST_F(AccessTokenDenyTest, ClearUserGrantedPermissionState001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
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
HWTEST_F(AccessTokenDenyTest, RegisterPermStateChangeCallback001, TestSize.Level1)
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
HWTEST_F(AccessTokenDenyTest, UnregisterPermStateChangeCallback001, TestSize.Level1)
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
        .permList = {},
        .permStateList = {testState}
    };
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_InfoParms, policyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));

    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {"ohos.permission.CAMERA"};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest1>(scopeInfo);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr));

    EXPECT_EQ(0, SetSelfTokenID(g_testTokenIDEx.tokenIDEx));

    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));

    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr));

    setuid(g_selfUid);
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: ReloadNativeTokenInfo001
 * @tc.desc: ReloadNativeTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, ReloadNativeTokenInfo001, TestSize.Level1)
{
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::ReloadNativeTokenInfo());
}

/**
 * @tc.name: GetNativeTokenId001
 * @tc.desc: Verify the GetNativeTokenId abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenDenyTest, GetNativeTokenId001, TestSize.Level1)
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
HWTEST_F(AccessTokenDenyTest, DumpTokenInfo001, TestSize.Level1)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = 123;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    ASSERT_EQ("", dumpInfo);
}

/**
 * @tc.name: DumpPermDefInfo001
 * @tc.desc: Verify the DumpPermDefInfo abnormal branch return nullptr proxy.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(AccessTokenDenyTest, DumpPermDefInfo001, TestSize.Level1)
{
    std::string dumpInfo;
    int32_t res = AccessTokenKit::DumpPermDefInfo(dumpInfo);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, res);
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetHapTokenInfoFromRemote001
 * @tc.desc: GetHapTokenInfoFromRemote with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetHapTokenInfoFromRemote001, TestSize.Level1)
{
    AccessTokenID tokenId = 123;
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetHapTokenInfoFromRemote(tokenId, hapSync));
}

/**
 * @tc.name: GetAllNativeTokenInfo001
 * @tc.desc: GetAllNativeTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetAllNativeTokenInfo001, TestSize.Level1)
{
    std::vector<NativeTokenInfoForSync> nativeTokenInfosRes;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::GetAllNativeTokenInfo(nativeTokenInfosRes));
}

/**
 * @tc.name: SetRemoteHapTokenInfo001
 * @tc.desc: SetRemoteHapTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, SetRemoteHapTokenInfo001, TestSize.Level1)
{
    std::string device = "device";
    HapTokenInfoForSync hapSync;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::SetRemoteHapTokenInfo(device, hapSync));
}

/**
 * @tc.name: SetRemoteNativeTokenInfo001
 * @tc.desc: SetRemoteNativeTokenInfo with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, SetRemoteNativeTokenInfo001, TestSize.Level1)
{
    std::string device = "device";
    std::vector<NativeTokenInfoForSync> nativeToken;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::SetRemoteNativeTokenInfo(device, nativeToken));
}

/**
 * @tc.name: DeleteRemoteToken001
 * @tc.desc: DeleteRemoteToken with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, DeleteRemoteToken001, TestSize.Level1)
{
    std::string device = "device";
    AccessTokenID tokenId = 123;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteRemoteToken(device, tokenId));
}

/**
 * @tc.name: GetRemoteNativeTokenID001
 * @tc.desc: GetRemoteNativeTokenID with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, GetRemoteNativeTokenID001, TestSize.Level1)
{
    std::string device = "device";
    AccessTokenID tokenId = 123;
    ASSERT_EQ(INVALID_TOKENID, AccessTokenKit::GetRemoteNativeTokenID(device, tokenId));
}

/**
 * @tc.name: DeleteRemoteDeviceTokens001
 * @tc.desc: DeleteRemoteDeviceTokens with no permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDenyTest, DeleteRemoteDeviceTokens001, TestSize.Level1)
{
    std::string device = "device";
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::DeleteRemoteDeviceTokens(device));
}

HWTEST_F(AccessTokenDenyTest, RegisterTokenSyncCallback001, TestSize.Level1)
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
HWTEST_F(AccessTokenDenyTest, SetPermDialogCap001, TestSize.Level1)
{
    HapBaseInfo hapBaseInfo;
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_DENIED, AccessTokenKit::SetPermDialogCap(hapBaseInfo, true));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

