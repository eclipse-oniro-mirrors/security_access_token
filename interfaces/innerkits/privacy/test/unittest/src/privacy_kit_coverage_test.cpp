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

#ifdef REMOTE_PRIVACY_ENABLE
/**
 * @tc.name: SystemAbilityStatusChangeListener002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require: issues3049
 */
HWTEST_F(PrivacyKitTest, OnAddPrivacySa002, TestSize.Level0)
{
    RemoteCallerInfo info;
    info.remoteDeviceId = "ididid";
    info.remoteDeviceName = "namename";

    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 0);
    EXPECT_EQ(0, PrivacyKit::StartRemoteUsingPermission(info, "ohos.permission.CAMERA"));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 1);
    EXPECT_EQ(0, PrivacyKit::StartRemoteUsingPermission(info, "ohos.permission.CAMERA"));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 2);
    EXPECT_EQ(0, PrivacyKit::StartRemoteUsingPermission(info, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 3);

    // when the proxy is equal
    PrivacyManagerClient::GetInstance().OnAddPrivacySa();

    PrivacyManagerClient::GetInstance().OnRemoteDiedHandle();

    // when the proxy is not equal
    PrivacyManagerClient::GetInstance().OnAddPrivacySa();

    EXPECT_EQ(0, PrivacyKit::StopRemoteUsingPermission(info, "ohos.permission.CAMERA"));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 2);
    EXPECT_EQ(0, PrivacyKit::StopRemoteUsingPermission(info, "ohos.permission.CAMERA"));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 1);
    EXPECT_EQ(0, PrivacyKit::StopRemoteUsingPermission(info, "ohos.permission.MICROPHONE"));
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 0);
}

/**
 * @tc.name: SystemAbilityStatusChangeListener003
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, OnAddPrivacySa003, TestSize.Level0)
{
    RemotePermissionUsedInfo usedInfo;
    usedInfo.remoteDeviceId = "ididid";
    usedInfo.remoteDeviceName = "namename";
    usedInfo.permissionName = "ohos.permission.CAMERA";
    PrivacyManagerClient::GetInstance().remoteCacheList_.emplace_back(usedInfo);
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 1);

    RemoteCallerInfo info;
    info.remoteDeviceId = "ididid2222";
    info.remoteDeviceName = "namename";

    PrivacyManagerClient::GetInstance().DeleteRemoteInputCache(info, "ohos.permission.CAMERA");
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 1);
    info.remoteDeviceId = "ididid";

    PrivacyManagerClient::GetInstance().DeleteRemoteInputCache(info, "ohos.permission.MICROPHONE");
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 1);

    PrivacyManagerClient::GetInstance().DeleteRemoteInputCache(info, "ohos.permission.CAMERA");
    EXPECT_EQ(PrivacyManagerClient::GetInstance().remoteCacheList_.size(), 0);
}
#endif

#ifdef PRIVACY_BUNDLE_START_STOP_ENABLE
/**
 * @tc.name: SystemAbilityStatusChangeListener004
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, OnAddPrivacySa004, TestSize.Level0)
{
    const std::string bundleName = g_infoParmsE.bundleName;
    const std::string permissionName = "ohos.permission.CAMERA";

    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().bundleCacheList_.size());
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(bundleName, permissionName));
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().bundleCacheList_.size());
    EXPECT_EQ(ERR_PERMISSION_ALREADY_START_USING, PrivacyKit::StartUsingPermission(bundleName, permissionName));
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().bundleCacheList_.size());

    PrivacyManagerClient::GetInstance().OnAddPrivacySa();
    PrivacyManagerClient::GetInstance().OnRemoteDiedHandle();
    PrivacyManagerClient::GetInstance().OnAddPrivacySa();

    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(bundleName, permissionName));
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().bundleCacheList_.size());
}

/**
 * @tc.name: BundleClientCache001
 * @tc.desc: Verify bundle cache is created after successful bundle start.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, BundleClientCache001, TestSize.Level0)
{
    const std::string bundleName = g_infoParmsE.bundleName;
    const std::string permissionName = "ohos.permission.CAMERA";

    PrivacyManagerClient::GetInstance().bundleCacheList_.clear();
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().bundleCacheList_.size());
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(bundleName, permissionName));
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().bundleCacheList_.size());
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(bundleName, permissionName));
}

/**
 * @tc.name: BundleClientCache002
 * @tc.desc: Verify bundle cache is removed after bundle stop.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, BundleClientCache002, TestSize.Level0)
{
    const std::string bundleName = g_infoParmsE.bundleName;
    const std::string permissionName = "ohos.permission.CAMERA";

    PrivacyManagerClient::GetInstance().bundleCacheList_.clear();
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(bundleName, permissionName));
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().bundleCacheList_.size());
    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(bundleName, permissionName));
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().bundleCacheList_.size());
}

/**
 * @tc.name: BundleClientRetry003
 * @tc.desc: Verify OnAddPrivacySa replays bundle cache without duplicating entries.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, BundleClientRetry003, TestSize.Level0)
{
    const std::string bundleName = g_infoParmsE.bundleName;
    const std::string permissionName = "ohos.permission.CAMERA";

    PrivacyManagerClient::GetInstance().bundleCacheList_.clear();
    EXPECT_EQ(0, PrivacyKit::StartUsingPermission(bundleName, permissionName));
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().bundleCacheList_.size());

    PrivacyManagerClient::GetInstance().OnAddPrivacySa();
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().bundleCacheList_.size());

    EXPECT_EQ(0, PrivacyKit::StopUsingPermission(bundleName, permissionName));
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().bundleCacheList_.size());
}
#endif

class CbActiveTest : public PermActiveStatusCustomizedCbk {
public:
    explicit CbActiveTest(const std::vector<std::string>& permList) : PermActiveStatusCustomizedCbk(permList) {}
    ~CbActiveTest() {}
    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override {}
};

class CbDisableTest : public DisablePolicyChangeCallback {
public:
    explicit CbDisableTest(const std::vector<std::string>& permList) : DisablePolicyChangeCallback(permList) {}
    ~CbDisableTest() {}
    void PermDisablePolicyCallback(const PermDisablePolicyInfo& info) override {}
};

/**
 * @tc.name: ReRegisterPermActiveStatusCallback001
 * @tc.desc: ReRegisterPermActiveStatusCallback with empty activeCbkMap_.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, ReRegisterPermActiveStatusCallback001, TestSize.Level0)
{
    PrivacyManagerClient::GetInstance().activeCbkMap_.clear();
    // empty map: loop body not executed
    PrivacyManagerClient::GetInstance().ReRegisterPermActiveStatusCallback();
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().activeCbkMap_.size());
}

/**
 * @tc.name: ReRegisterPermActiveStatusCallback002
 * @tc.desc: ReRegisterPermActiveStatusCallback with a valid callback entry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, ReRegisterPermActiveStatusCallback002, TestSize.Level0)
{
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbActiveTest>(permList);
    ASSERT_NE(nullptr, callbackPtr);
    EXPECT_EQ(0, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::ALL));
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().activeCbkMap_.size());

    // re-register path executes; server rejects duplicate via death-recipient, client maps unchanged
    PrivacyManagerClient::GetInstance().ReRegisterPermActiveStatusCallback();
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().activeCbkMap_.size());

    EXPECT_EQ(0, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().activeCbkMap_.size());
}

/**
 * @tc.name: ReRegisterPermActiveStatusCallback003
 * @tc.desc: ReRegisterPermActiveStatusCallback skips null callback entry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, ReRegisterPermActiveStatusCallback003, TestSize.Level0)
{
    // first null: (entry.first == nullptr) short-circuits the ||
    std::shared_ptr<PermActiveStatusCustomizedCbk> nullKey = nullptr;
    PrivacyManagerClient::GetInstance().activeCbkMap_[nullKey] = {nullptr, CallbackRegisterType::ALL};

    // first non-null but second.callback null: covers (entry.second.callback == nullptr)
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto validKey = std::make_shared<CbActiveTest>(permList);
    PrivacyManagerClient::GetInstance().activeCbkMap_[validKey] = {nullptr, CallbackRegisterType::ALL};
    EXPECT_EQ(2, PrivacyManagerClient::GetInstance().activeCbkMap_.size());

    // both null-callback entries skipped via continue
    PrivacyManagerClient::GetInstance().ReRegisterPermActiveStatusCallback();
    EXPECT_EQ(2, PrivacyManagerClient::GetInstance().activeCbkMap_.size());

    PrivacyManagerClient::GetInstance().activeCbkMap_.erase(nullKey);
    PrivacyManagerClient::GetInstance().activeCbkMap_.erase(validKey);
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().activeCbkMap_.size());
}

/**
 * @tc.name: ReRegisterPermDisablePolicyCallback001
 * @tc.desc: ReRegisterPermDisablePolicyCallback with empty disableCbkMap_.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, ReRegisterPermDisablePolicyCallback001, TestSize.Level0)
{
    PrivacyManagerClient::GetInstance().disableCbkMap_.clear();
    PrivacyManagerClient::GetInstance().ReRegisterPermDisablePolicyCallback();
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().disableCbkMap_.size());
}

/**
 * @tc.name: ReRegisterPermDisablePolicyCallback002
 * @tc.desc: ReRegisterPermDisablePolicyCallback with a valid callback entry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, ReRegisterPermDisablePolicyCallback002, TestSize.Level0)
{
    MockNativeToken mock("accesstoken_service");
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto callbackPtr = std::make_shared<CbDisableTest>(permList);
    ASSERT_NE(nullptr, callbackPtr);
    EXPECT_EQ(0, PrivacyKit::RegisterPermDisablePolicyCallback(callbackPtr));
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().disableCbkMap_.size());

    PrivacyManagerClient::GetInstance().ReRegisterPermDisablePolicyCallback();
    EXPECT_EQ(1, PrivacyManagerClient::GetInstance().disableCbkMap_.size());

    EXPECT_EQ(0, PrivacyKit::UnRegisterPermDisablePolicyCallback(callbackPtr));
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().disableCbkMap_.size());
}

/**
 * @tc.name: ReRegisterPermDisablePolicyCallback003
 * @tc.desc: ReRegisterPermDisablePolicyCallback skips null callback entry.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyKitTest, ReRegisterPermDisablePolicyCallback003, TestSize.Level0)
{
    // first null: (entry.first == nullptr) short-circuits the ||
    std::shared_ptr<DisablePolicyChangeCallback> nullKey = nullptr;
    OHOS::sptr<PermDisablePolicyChangeCallback> nullVal = nullptr;
    PrivacyManagerClient::GetInstance().disableCbkMap_[nullKey] = nullVal;

    // first non-null but second null: covers (entry.second == nullptr)
    std::vector<std::string> permList = {"ohos.permission.CAMERA"};
    auto validKey = std::make_shared<CbDisableTest>(permList);
    PrivacyManagerClient::GetInstance().disableCbkMap_[validKey] = nullptr;
    EXPECT_EQ(2, PrivacyManagerClient::GetInstance().disableCbkMap_.size());

    PrivacyManagerClient::GetInstance().ReRegisterPermDisablePolicyCallback();
    EXPECT_EQ(2, PrivacyManagerClient::GetInstance().disableCbkMap_.size());

    PrivacyManagerClient::GetInstance().disableCbkMap_.erase(nullKey);
    PrivacyManagerClient::GetInstance().disableCbkMap_.erase(validKey);
    EXPECT_EQ(0, PrivacyManagerClient::GetInstance().disableCbkMap_.size());
}
