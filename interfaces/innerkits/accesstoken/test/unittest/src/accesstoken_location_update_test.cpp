/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "accesstoken_location_update_test.h"

#include "access_token.h"
#include "accesstoken_kit.h"
#include "hap_token_info.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t TEST_USER_ID = 100;
static std::string TEST_BUNDLE_NAME = "accesstoken_location_update_test";
static constexpr int32_t TEST_INST_INDEX = 0;
static constexpr int32_t DEFAULT_API_VERSION = 8;
const std::string LOCATION = "ohos.permission.LOCATION";
const std::string APPROXIMATELY_LOCATION = "ohos.permission.APPROXIMATELY_LOCATION";

PermissionStateFull g_locationTestStateVague01 = {
    .permissionName = APPROXIMATELY_LOCATION,
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};
PermissionStateFull g_locationTestStateVague02 = {
    .permissionName = APPROXIMATELY_LOCATION,
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};

PermissionStateFull g_locationTestStateAccurate = {
    .permissionName = LOCATION,
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};
}

void AccessTokenLocationUpdateTest::SetUpTestCase()
{
    setuid(0);
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX);
    AccessTokenKit::DeleteToken(tokenId);
}

void AccessTokenLocationUpdateTest::TearDownTestCase()
{
}

void AccessTokenLocationUpdateTest::SetUp()
{
    selfTokenId_ = GetSelfTokenID();
}

void AccessTokenLocationUpdateTest::TearDown()
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, TEST_INST_INDEX);
    AccessTokenKit::DeleteToken(tokenId);
    SetSelfTokenID(selfTokenId_);
}

AccessTokenIDEx AllocHapToken(std::vector<PermissionStateFull>& permissionStateFulls)
{
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = TEST_INST_INDEX,
        .appIDDesc = "location_test",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = true,
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain",
        .permStateList = {g_locationTestStateAccurate}
    };

    for (auto& permissionStateFull:permissionStateFulls) {
        policy.permStateList.emplace_back(permissionStateFull);
    }

    return AccessTokenKit::AllocHapToken(info, policy);
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
        ready_ = true;
        GTEST_LOG_(INFO) << "PermStateChangeCallback,  tokenID is " << result.tokenID;
    }

    bool ready_;
};

/**
 * @tc.name: VerifyAccessToken001
 * @tc.desc: In the case of fuzzy location authorization:
 *           1. test the granting and reclaiming of precise location permissions
 *           2. test the callback notification
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenLocationUpdateTest, VerifyAccessToken001, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague01);

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    GTEST_LOG_(INFO) << "AccessTokenLocationUpdateTest#VerifyAccessToken001,  tokenID is " << tokenID;

    int ret = AccessTokenKit::VerifyAccessToken(tokenID, APPROXIMATELY_LOCATION);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenKit::VerifyAccessToken(tokenID, LOCATION);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    //register
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {LOCATION};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    ret = AccessTokenKit::GrantPermission(tokenID, LOCATION, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, LOCATION);
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    usleep(500000); // 500000us = 0.5s
    EXPECT_TRUE(callbackPtr->ready_);

    callbackPtr->ready_ = false;

    ret = AccessTokenKit::RevokePermission(tokenID, LOCATION, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, LOCATION);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    usleep(500000); // 500000us = 0.5s
    EXPECT_TRUE(callbackPtr->ready_);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}

/**
 * @tc.name: GetSelfPermissionsState002
 * @tc.desc: In the case of fuzzy location prohibition:
 *           1. test the granting and reclaiming of precise location permissions
 *           2. test the callback notification
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenLocationUpdateTest, VerifyAccessToken002, TestSize.Level1)
{
    std::vector<PermissionStateFull> permissionStateFulls;
    permissionStateFulls.emplace_back(g_locationTestStateVague02);

    AccessTokenIDEx tokenIdEx = AllocHapToken(permissionStateFulls);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    GTEST_LOG_(INFO) << "AccessTokenLocationUpdateTest#VerifyAccessToken002,  tokenID is " << tokenID;

    int ret = AccessTokenKit::VerifyAccessToken(tokenID, APPROXIMATELY_LOCATION);
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, LOCATION);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    //register
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {LOCATION};
    scopeInfo.tokenIDs = {tokenID};
    auto callbackPtr = std::make_shared<CbCustomizeTest>(scopeInfo);
    callbackPtr->ready_ = false;
    int32_t res = AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);

    ret = AccessTokenKit::GrantPermission(tokenID, LOCATION, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, LOCATION);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    usleep(500000); // 500000us = 0.5s
    EXPECT_FALSE(callbackPtr->ready_);

    ret = AccessTokenKit::RevokePermission(tokenID, LOCATION, PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenKit::VerifyAccessToken(tokenID, LOCATION);
    ASSERT_EQ(PERMISSION_DENIED, ret);

    usleep(500000); // 500000us = 0.5s
    EXPECT_FALSE(callbackPtr->ready_);

    res = AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr);
    ASSERT_EQ(RET_SUCCESS, res);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
