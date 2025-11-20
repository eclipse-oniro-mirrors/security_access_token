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

#include "privacy_kit_coverage_test.h"

#include <chrono>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "on_permission_used_record_callback_stub.h"
#include "parameter.h"
#define private public
#include "perm_active_status_change_callback.h"
#include "privacy_manager_client.h"
#include "state_change_callback.h"
#undef private
#include "permission_map.h"
#include "active_change_response_parcel.h"
#include "perm_active_status_change_callback_stub.h"
#include "perm_setproc.h"
#include "privacy_error.h"
#include "privacy_kit.h"
#include "privacy_test_common.h"
#include "state_change_callback_stub.h"
#include "string_ex.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

static AccessTokenID g_nativeToken = 0;
static AccessTokenID g_shellToken = 0;
static MockHapToken* g_mock = nullptr;

static constexpr uint32_t RANDOM_PID = 123;

static PermissionStateFull g_infoManagerTestStateA = {
    .permissionName = "ohos.permission.CAMERA",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};
static HapPolicyParams g_policyPramsA = {
    .apl = APL_NORMAL,
    .domain = "test.domain.A",
};
static HapInfoParams g_infoParmsA = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleA",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleA"
};

static PermissionStateFull g_infoManagerTestStateB = {
    .permissionName = "ohos.permission.MICROPHONE",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};
static HapPolicyParams g_policyPramsB = {
    .apl = APL_NORMAL,
    .domain = "test.domain.B",
};
static HapInfoParams g_infoParmsB = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleB",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleB"
};

static PermissionStateFull g_infoManagerTestStateC = {
    .permissionName = "ohos.permission.PERMISSION_USED_STATS",
    .isGeneral = true,
    .resDeviceID = {"localC"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};
static HapInfoParams g_infoParmsC = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleC",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleC",
    .isSystemApp = true,
};
static HapPolicyParams g_policyPramsC = {
    .apl = APL_NORMAL,
    .domain = "test.domain.C",
    .permList = {},
    .permStateList = {g_infoManagerTestStateC}
};

static HapInfoParams g_infoParmsD = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleD",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleD",
    .isSystemApp = true,
};
static HapPolicyParams g_policyPramsD = {
    .apl = APL_NORMAL,
    .domain = "test.domain.C",
    .permList = {},
    .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB}
};

static HapPolicyParams g_policyPramsE = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB}
};
static HapInfoParams g_infoParmsE = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleE",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleE"
};

static HapPolicyParams g_policyPramsF = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {},
    .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB}
};
static HapInfoParams g_infoParmsF = {
    .userID = 1,
    .bundleName = "ohos.privacy_test.bundleF",
    .instIndex = 0,
    .appIDDesc = "privacy_test.bundleF"
};

static AccessTokenID g_selfTokenId = 0;
static AccessTokenID g_tokenIdA = 0;
static AccessTokenID g_tokenIdB = 0;
static AccessTokenID g_tokenIdC = 0;
static AccessTokenID g_tokenIdE = 0;
static AccessTokenID g_tokenIdF = 0;

static void DeleteTestToken()
{
    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsA.userID, g_infoParmsA.bundleName, g_infoParmsA.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsB.userID, g_infoParmsB.bundleName, g_infoParmsB.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsC.userID, g_infoParmsC.bundleName, g_infoParmsC.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsE.userID, g_infoParmsE.bundleName, g_infoParmsE.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);

    tokenIdEx = PrivacyTestCommon::GetHapTokenIdFromBundle(
        g_infoParmsF.userID, g_infoParmsF.bundleName, g_infoParmsF.instIndex);
    PrivacyTestCommon::DeleteTestHapToken(tokenIdEx.tokenIdExStruct.tokenID);
    PrivacyKit::RemovePermissionUsedRecords(tokenIdEx.tokenIdExStruct.tokenID);
}

void PrivacyKitTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    g_mock = new (std::nothrow) MockHapToken("PrivacyKitMockTest", reqPerm, true);

    g_nativeToken = PrivacyTestCommon::GetNativeTokenIdFromProcess("privacy_service");
    g_shellToken = PrivacyTestCommon::GetNativeTokenIdFromProcess("hdcd");

    DeleteTestToken();
}

void PrivacyKitTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    SetSelfTokenID(g_selfTokenId);
    PrivacyTestCommon::ResetTestEvironment();
}

void PrivacyKitTest::SetUp()
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsA, g_policyPramsA);
    g_tokenIdA = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdA);

    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsB, g_policyPramsB);
    g_tokenIdB = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdB);

    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsC, g_policyPramsC);
    g_tokenIdC = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdC);

    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsE, g_policyPramsE);
    g_tokenIdE = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdE);

    tokenIdEx = PrivacyTestCommon::AllocTestHapToken(g_infoParmsF, g_policyPramsF);
    g_tokenIdF = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(INVALID_TOKENID, g_tokenIdF);
}

void PrivacyKitTest::TearDown()
{
    DeleteTestToken();
}

class CbCustomizeTest4 : public StateCustomizedCbk {
public:
    CbCustomizeTest4()
    {}

    ~CbCustomizeTest4()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {}
};

/**
 * @tc.name: SystemAbilityStatusChangeListener001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issue2901
 */
HWTEST_F(PrivacyKitTest, SystemAbilityStatusChangeListener001, TestSize.Level0)
{
    EXPECT_EQ(PrivacyManagerClient::GetInstance().isSubscribeSA_, false);
    PrivacyManagerClient::GetInstance().OnRemoteDiedHandle();
    EXPECT_EQ(PrivacyManagerClient::GetInstance().isSubscribeSA_, true);
}

/**
 * @tc.name: SystemAbilityStatusChangeListener002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issue2901
 */
HWTEST_F(PrivacyKitTest, SystemAbilityStatusChangeListener002, TestSize.Level0)
{
    OHOS::sptr<OHOS::ISystemAbilityStatusChange> statusChangeListener =
        new (std::nothrow) SystemAbilityStatusChangeListener(nullptr);
    ASSERT_NE(statusChangeListener, nullptr);
    statusChangeListener->OnAddSystemAbility(0, "");
    statusChangeListener->OnRemoveSystemAbility(0, "");
}

/**
 * @tc.name: SystemAbilityStatusChangeListener001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issue2901
 */
HWTEST_F(PrivacyKitTest, OnAddPrivacySa001, TestSize.Level0)
{
    EXPECT_EQ(PrivacyManagerClient::GetInstance().cacheList_.size(), 0);
    auto callbackPtr = std::make_shared<CbCustomizeTest4>();
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", callbackPtr, RANDOM_PID));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().cacheList_.size(), 1);
    EXPECT_NE(0, PrivacyKit::StartUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", callbackPtr, RANDOM_PID));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().cacheList_.size(), 1);

    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(g_tokenIdA, "ohos.permission.CAMERA"));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().cacheList_.size(), 2);

    // when the proxy is equal
    PrivacyManagerClient::GetInstance().OnAddPrivacySa();

    PrivacyManagerClient::GetInstance().OnRemoteDiedHandle();

    // when the proxy is not equal
    PrivacyManagerClient::GetInstance().OnAddPrivacySa();

    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdE, "ohos.permission.CAMERA", RANDOM_PID));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().cacheList_.size(), 1);
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(g_tokenIdA, "ohos.permission.CAMERA"));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().cacheList_.size(), 0);
}