/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "security_component_grant_test.h"
#include <thread>

#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "permission_grant_info.h"
#include "nativetoken_kit.h"
#include "softbus_bus_center.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static const std::string TEST_BUNDLE_NAME = "ohos";
static const std::string TEST_PKG_NAME = "com.softbus.test";
static const std::string TEST_PERMISSION = "ohos.permission.DISTRIBUTED_DATASYNC";
static const std::string TEST_PERMISSION_NOT_REQUESTED = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
static const int TEST_USER_ID = 0;

PermissionStateFull g_infoManagerTestState1 = {
    .permissionName = TEST_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"local5"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0},
};

HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test5"
};

HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain5",
    .permList = {},
    .permStateList = {g_infoManagerTestState1}
};

void NativeTokenGet()
{
    uint64_t fullTokenId;
    const char **perms = new const char *[4];
    perms[0] = "ohos.permission.DISTRIBUTED_DATASYNC";
    perms[2] = "ohos.permission.REVOKE_SENSITIVE_PERMISSIONS"; // 2 means the index.
    perms[1] = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
    perms[3] = "ohos.permission.GET_SENSITIVE_PERMISSIONS"; // 3 means the index.

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 4,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.processName = "TestCase";
    fullTokenId = GetAccessTokenId(&infoInstance);
    EXPECT_EQ(0, SetSelfTokenID(fullTokenId));
    AccessTokenKit::ReloadNativeTokenInfo();
    delete[] perms;
}
}

void SecurityComponentGrantTest::SetUpTestCase()
{
    // make test case clean
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);

    NativeTokenGet();
}

void SecurityComponentGrantTest::TearDownTestCase()
{
}

void SecurityComponentGrantTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();
}

void SecurityComponentGrantTest::TearDown()
{
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId_));
}

void SecurityComponentGrantTest::DeleteTestToken() const
{
}

AccessTokenID SecurityComponentGrantTest::AllocTestToken() const
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

/**
 * @tc.name: SecurityComponentGrantTest001
 * @tc.desc: test security component grant when user has not operated.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest001, TestSize.Level1)
{
    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);
    int32_t res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    uint32_t flag;
    res = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_NE(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);
    res = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);
    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: SecurityComponentGrantTest002
 * @tc.desc: test security component grant when user has granted.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest002, TestSize.Level1)
{
    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // user grant
    int32_t res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);

    // security component grant
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);
    uint32_t flag;
    res = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);
    res = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);
    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: SecurityComponentGrantTest003
 * @tc.desc: test security component grant when system has operated.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest003, TestSize.Level1)
{
    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // system grant
    int32_t res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_GRANTED_BY_POLICY);
    ASSERT_EQ(res, RET_SUCCESS);

    // security component grant
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);
    uint32_t flag;
    AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);
    res = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: SecurityComponentGrantTest004
 * @tc.desc: test security component grant when user has revoked.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest004, TestSize.Level1)
{
    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // user revoke
    int32_t res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    // security component grant
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_NE(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);

    uint32_t flag;
    res = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);
    AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: SecurityComponentGrantTest005
 * @tc.desc: test user has grant after security component grant.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest005, TestSize.Level1)
{
    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // security component grant
    int32_t res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    // user grant
    uint32_t flag;
    res = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_NE(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: SecurityComponentGrantTest006
 * @tc.desc: test user has revoked after security component grant.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest006, TestSize.Level1)
{
    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // security component grant
    int32_t res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    uint32_t flag;
    res = AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_NE(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // user revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);
    AccessTokenKit::GetPermissionFlag(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: SecurityComponentGrantTest007
 * @tc.desc: test permission pop-up after security component grant.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest007, TestSize.Level1)
{
    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);
    AccessTokenID nativeTokenID = GetSelfTokenID();
    // security component grant
    int32_t res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    PermissionOper result;
    PermissionListState perm1 = {
        .permissionName = TEST_PERMISSION,
        .state = SETTING_OPER,
    };
    std::vector<PermissionListState> permList;
    permList.emplace_back(perm1);
    // check to pop up
    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    PermissionGrantInfo info;
    result = AccessTokenKit::GetSelfPermissionsState(permList, info);
    ASSERT_EQ(result, DYNAMIC_OPER);

    // check not to pop up
    EXPECT_EQ(0, SetSelfTokenID(nativeTokenID));
    AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);

    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    result = AccessTokenKit::GetSelfPermissionsState(permList, info);
    ASSERT_EQ(result, PASS_OPER);

    // security component revoke
    EXPECT_EQ(0, SetSelfTokenID(nativeTokenID));
    AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: SecurityComponentGrantTest008
 * @tc.desc: test permission pop-up after security component grant.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest008, TestSize.Level1)
{
    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // security component grant
    int32_t res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    // security component grant repeat
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);

    // security component revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);

    // security component revoke repeat
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

class CbCustomizeTest : public PermStateChangeCallbackCustomize {
public:
    explicit CbCustomizeTest(const PermStateChangeScope &scopeInfo)
        : PermStateChangeCallbackCustomize(scopeInfo)
    {
    }

    ~CbCustomizeTest()
    {}

    virtual void PermStateChangeCallback(PermStateChangeInfo& result)
    {
        ready2_ = true;
    }

    bool ready2_ = false;
};

/**
 * @tc.name: SecurityComponentGrantTest009
 * @tc.desc: test permission pop-up after security component grant.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest009, TestSize.Level1)
{
    PermStateChangeScope scopeInfo9;
    scopeInfo9.permList = {TEST_PERMISSION};
    scopeInfo9.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo9);
    callbackPtr->ready2_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // security component grant
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    // user grant
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(callbackPtr->ready2_, false);

    // security component revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    // security component revoke repeat
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_NE(res, RET_SUCCESS);
    ASSERT_EQ(callbackPtr->ready2_, false);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: SecurityComponentGrantTest010
 * @tc.desc: test permission pop-up after security component grant.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest010, TestSize.Level1)
{
    PermStateChangeScope scopeInfo10;
    scopeInfo10.permList = {TEST_PERMISSION};
    scopeInfo10.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo10);
    callbackPtr->ready2_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // security component grant
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    // user revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    // security component revoke
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_NE(res, RET_SUCCESS);
    ASSERT_EQ(callbackPtr->ready2_, false);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

/**
 * @tc.name: SecurityComponentGrantTest011
 * @tc.desc: test permission pop-up after security component grant.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, SecurityComponentGrantTest011, TestSize.Level1)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {TEST_PERMISSION_NOT_REQUESTED};
    scopeInfo.tokenIDs = {};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready2_ = false;

    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);

    // security component grant a not requested permission
    res = AccessTokenKit::GrantPermission(tokenID, TEST_PERMISSION_NOT_REQUESTED, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NOT_REQUESTED, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    // security component revoke
    res = AccessTokenKit::RevokePermission(tokenID, TEST_PERMISSION_NOT_REQUESTED, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(callbackPtr->ready2_, true);

    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NOT_REQUESTED, false);
    ASSERT_EQ(status, PERMISSION_DENIED);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = AccessTokenKit::DeleteToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}
