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
#include "test_common.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static const std::string TEST_PERMISSION = "ohos.permission.DISTRIBUTED_DATASYNC";
static const std::string TEST_PERMISSION_NOT_REQUESTED = "ohos.permission.GRANT_SENSITIVE_PERMISSIONS";
static uint64_t g_selfShellTokenId = 0;
static MockHapToken* g_mock = nullptr;
PermissionStateFull g_infoManagerTestState1 = {
    .permissionName = TEST_PERMISSION,
    .isGeneral = true,
    .resDeviceID = {"local5"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {0},
};

HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "security_component_grant_test",
    .instIndex = 0,
    .appIDDesc = "test5"
};

HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain5",
    .permStateList = {g_infoManagerTestState1}
};
}

void SecurityComponentGrantTest::SetUpTestCase()
{
    g_selfShellTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfShellTokenId);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.MANAGE_HAP_TOKENID");
    reqPerm.emplace_back("ohos.permission.GET_SENSITIVE_PERMISSIONS");
    reqPerm.emplace_back("ohos.permission.REVOKE_SENSITIVE_PERMISSIONS");
    reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    g_mock = new (std::nothrow) MockHapToken("SecurityComponentGrantTest", reqPerm, true);

    GTEST_LOG_(INFO) << "SecurityComponentGrantTest,  tokenID is " << g_selfShellTokenId;
    GTEST_LOG_(INFO) << "SecurityComponentGrantTest,  sel is " << GetSelfTokenID();
    // make test case clean
    AccessTokenIDEx tokenIdEx = TestCommon::GetHapTokenIdFromBundle(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    TestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
}

void SecurityComponentGrantTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    TestCommon::ResetTestEvironment();
    SetSelfTokenID(g_selfShellTokenId);
}

void SecurityComponentGrantTest::SetUp()
{
}

void SecurityComponentGrantTest::TearDown()
{
}

AccessTokenID SecurityComponentGrantTest::AllocTestToken() const
{
    AccessTokenIDEx tokenIdEx = {0};
    EXPECT_EQ(RET_SUCCESS,
        TestCommon::AllocTestHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx));
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
    int32_t res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    uint32_t flag = 0;
    res = TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_NE(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);
    res = TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);
    res = TestCommon::DeleteTestHapToken(tokenID);
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
    int32_t res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);

    // security component grant
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);
    uint32_t flag = 0;
    res = TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);
    res = TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);
    res = TestCommon::DeleteTestHapToken(tokenID);
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
    int32_t res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_GRANTED_BY_POLICY);
    ASSERT_EQ(res, RET_SUCCESS);

    // security component grant
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);
    uint32_t flag = 0;
    TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);
    res = TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    res = TestCommon::DeleteTestHapToken(tokenID);
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
    int32_t res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    // security component grant
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_NE(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);

    uint32_t flag = 0;
    res = TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);
    TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    res = TestCommon::DeleteTestHapToken(tokenID);
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
    int32_t res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    // user grant
    uint32_t flag = 0;
    res = TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_NE(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    res = TestCommon::DeleteTestHapToken(tokenID);
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
    int32_t res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    uint32_t flag = 0;
    res = TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(res, RET_SUCCESS);
    ASSERT_NE(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // user revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);
    TestCommon::GetPermissionFlagByTest(tokenID, TEST_PERMISSION, flag);
    ASSERT_EQ(((static_cast<uint32_t>(flag)) & PERMISSION_COMPONENT_SET), 0);

    // security component revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_DENIED);

    res = TestCommon::DeleteTestHapToken(tokenID);
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
    uint64_t selfToken = GetSelfTokenID();
    MockNativeToken mock("foundation");
    AccessTokenID tokenID = AllocTestToken();
    ASSERT_NE(tokenID, INVALID_TOKENID);
    AccessTokenID nativeTokenID = GetSelfTokenID();
    // security component grant
    int32_t res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
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
    TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);

    EXPECT_EQ(0, SetSelfTokenID(tokenID));
    result = AccessTokenKit::GetSelfPermissionsState(permList, info);
    ASSERT_EQ(result, PASS_OPER);

    // security component revoke
    EXPECT_EQ(0, SetSelfTokenID(nativeTokenID));
    TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);

    res = TestCommon::DeleteTestHapToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);

    EXPECT_EQ(0, SetSelfTokenID(nativeTokenID));
    EXPECT_EQ(0, SetSelfTokenID(selfToken));
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
    int32_t res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    // security component grant repeat
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);

    // security component revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);

    // security component revoke repeat
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);

    res = TestCommon::DeleteTestHapToken(tokenID);
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
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    // user grant
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(callbackPtr->ready2_, false);

    // security component revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    // security component revoke repeat
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_NE(res, RET_SUCCESS);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(callbackPtr->ready2_, false);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = TestCommon::DeleteTestHapToken(tokenID);
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
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    // user revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_USER_FIXED);
    ASSERT_EQ(res, RET_SUCCESS);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    // security component revoke
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION, PERMISSION_COMPONENT_SET);
    ASSERT_NE(res, RET_SUCCESS);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(callbackPtr->ready2_, false);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = TestCommon::DeleteTestHapToken(tokenID);
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
    res = TestCommon::GrantPermissionByTest(tokenID, TEST_PERMISSION_NOT_REQUESTED, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(callbackPtr->ready2_, true);
    callbackPtr->ready2_ = false;

    int32_t status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NOT_REQUESTED, false);
    ASSERT_EQ(status, PERMISSION_GRANTED);

    // security component revoke
    res = TestCommon::RevokePermissionByTest(tokenID, TEST_PERMISSION_NOT_REQUESTED, PERMISSION_COMPONENT_SET);
    ASSERT_EQ(res, RET_SUCCESS);
    usleep(500000); // 500000us = 0.5s
    ASSERT_EQ(callbackPtr->ready2_, true);

    status = AccessTokenKit::VerifyAccessToken(tokenID, TEST_PERMISSION_NOT_REQUESTED, false);
    ASSERT_EQ(status, PERMISSION_DENIED);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    res = TestCommon::DeleteTestHapToken(tokenID);
    ASSERT_EQ(res, RET_SUCCESS);
}

#ifdef SECURITY_COMPONENT_ENHANCE_ENABLE
/**
 * @tc.name: RegisterSecCompEnhance001
 * @tc.desc: AccessTokenKit:: function test register enhance data
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(SecurityComponentGrantTest, RegisterSecCompEnhance001, TestSize.Level1)
{
    SecCompEnhanceData data;
    data.callback = nullptr;
    data.challenge = 0;
    data.seqNum = 0;
    EXPECT_EQ(PrivacyError::ERR_WRITE_PARCEL_FAILED, AccessTokenKit::RegisterSecCompEnhance(data));

    // StateChangeCallback is not the real callback of SecCompEnhance, but it does not effect the final result.
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    data.callback = new (std::nothrow) StateChangeCallback(callbackPtr);
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::RegisterSecCompEnhance(data));

    MockNativeToken mock("security_component_service");
    SecCompEnhanceData data1;
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::GetSecCompEnhance(getpid(), data1));
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::GetSecCompEnhance(0, data1));
    EXPECT_EQ(RET_SUCCESS, AccessTokenKit::UpdateSecCompEnhance(getpid(), 1));
    EXPECT_NE(RET_SUCCESS, AccessTokenKit::UpdateSecCompEnhance(0, 1));
}
#endif
