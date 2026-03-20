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

#include "privacy_bundle_using_test.h"

#include <cstring>
#include <unistd.h>

#include "parameter.h"
#include "privacy_error.h"
#include "privacy_kit.h"
#include "privacy_test_common.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t VALUE_MAX_LEN = 32;
uint64_t g_selfTokenId = 0;
constexpr const char* PERMISSION_USED_STATS = "ohos.permission.PERMISSION_USED_STATS";
constexpr const char* TEST_BUNDLE_NAME = "ohos.test.bundle";
constexpr const char* TEST_PERMISSION_NAME = "ohos.permission.CAMERA";
constexpr const char* EDM_CAMERA_MUTE_KEY = "persist.edm.camera_disable";
constexpr size_t INVALID_NAME_LENGTH = 257;

AccessTokenID CreateGrantedHapToken(const std::string& bundleName, const std::string& permissionName)
{
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = bundleName,
        .instIndex = 0,
        .appIDDesc = "AccessTokenBundleUsingTestAppID",
        .apiVersion = PrivacyTestCommon::DEFAULT_API_VERSION,
        .isSystemApp = true,
        .appDistributionType = "",
    };

    HapPolicyParams policyParams = {
        .apl = APL_NORMAL,
        .domain = "accesstoken_test_domain",
    };

    PermissionDef permDefResult;
    if (AccessTokenKit::GetDefPermission(permissionName, permDefResult) == RET_SUCCESS) {
        PermissionStateFull permState = {
            .permissionName = permissionName,
            .isGeneral = true,
            .resDeviceID = {"local_test_device"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
        };
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(permissionName);
        }
    }

    AccessTokenIDEx tokenIdEx = PrivacyTestCommon::AllocTestHapToken(infoParams, policyParams);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

const CurrUsingPermInfo* FindUsingInfo(
    const std::vector<CurrUsingPermInfo>& infoList, AccessTokenID tokenID, const std::string& permissionName)
{
    for (const auto& info : infoList) {
        if ((info.tokenID == tokenID) && (info.permissionName == permissionName)) {
            return &info;
        }
    }
    return nullptr;
}

const CurrUsingPermInfo* FindBundleUsingInfo(
    const std::vector<CurrUsingPermInfo>& infoList, const std::string& bundleName, const std::string& permissionName)
{
    for (const auto& info : infoList) {
        if ((info.bundleName == bundleName) && (info.permissionName == permissionName)) {
            return &info;
        }
    }
    return nullptr;
}

const CurrUsingPermInfo* FindRemoteUsingInfo(const std::vector<CurrUsingPermInfo>& infoList,
    const std::string& deviceId, const std::string& permissionName)
{
    for (const auto& info : infoList) {
        if (info.isRemote && (info.deviceId == deviceId) && (info.permissionName == permissionName)) {
            return &info;
        }
    }
    return nullptr;
}

int32_t SetDisablePolicyAsEdm(const std::string& permissionName, bool isDisable)
{
    MockNativeToken mock("edm");
    return PrivacyKit::SetDisablePolicy(permissionName, isDisable);
}

class BundleActiveStatusCallbackTest : public PermActiveStatusCustomizedCbk {
public:
    explicit BundleActiveStatusCallbackTest(const std::vector<std::string>& permList)
        : PermActiveStatusCustomizedCbk(permList)
    {}

    ~BundleActiveStatusCallbackTest() override = default;

    void ActiveStatusChangeCallback(ActiveChangeResponse& result) override
    {
        callTimes_++;
        type_ = result.type;
        callingTokenID_ = result.callingTokenID;
        tokenID_ = result.tokenID;
        permissionName_ = result.permissionName;
        bundleName_ = result.bundleName;
    }

    int32_t callTimes_ = 0;
    ActiveChangeType type_ = PERM_INACTIVE;
    AccessTokenID callingTokenID_ = INVALID_TOKENID;
    AccessTokenID tokenID_ = INVALID_TOKENID;
    std::string permissionName_;
    std::string bundleName_;
};
}

void BundleUsingTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);
}

void BundleUsingTest::TearDownTestCase()
{
    SetSelfTokenID(g_selfTokenId);
    PrivacyTestCommon::ResetTestEvironment();
}
void BundleUsingTest::SetUp() {}
void BundleUsingTest::TearDown()
{
    (void)PrivacyKit::StopUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME);
}

/**
 * @tc.name: BundleUsingtest001
 * @tc.desc: Verify bundle using interfaces with invalid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest001, TestSize.Level1)
{
    std::string longBundle(INVALID_NAME_LENGTH, 'a');
    std::string longPerm(INVALID_NAME_LENGTH, 'a');
    EXPECT_EQ(ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission("", TEST_PERMISSION_NAME));
    EXPECT_EQ(ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(longBundle, TEST_PERMISSION_NAME));
    EXPECT_EQ(ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(TEST_BUNDLE_NAME, ""));
    EXPECT_EQ(ERR_PARAM_INVALID, PrivacyKit::StartUsingPermission(TEST_BUNDLE_NAME, longPerm));

    EXPECT_EQ(ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission("", TEST_PERMISSION_NAME));
    EXPECT_EQ(ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(longBundle, TEST_PERMISSION_NAME));
    EXPECT_EQ(ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(TEST_BUNDLE_NAME, ""));
    EXPECT_EQ(ERR_PARAM_INVALID, PrivacyKit::StopUsingPermission(TEST_BUNDLE_NAME, longPerm));
}

/**
 * @tc.name: BundleUsingtest002
 * @tc.desc: Verify bundle start and stop succeed for system app with permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest002, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest002", reqPerm, true);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
}

/**
 * @tc.name: BundleUsingtest003
 * @tc.desc: Verify bundle start and stop are rejected for non-system app.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest003, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest003", reqPerm, false);

    EXPECT_EQ(ERR_NOT_SYSTEM_APP, PrivacyKit::StartUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
    EXPECT_EQ(ERR_NOT_SYSTEM_APP, PrivacyKit::StopUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
}

/**
 * @tc.name: BundleUsingtest004
 * @tc.desc: Verify bundle start and stop are denied without permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest004, TestSize.Level1)
{
    std::vector<std::string> reqPerm;
    MockHapToken mock("BundleUsingtest004", reqPerm, true);

    EXPECT_EQ(ERR_PERMISSION_DENIED, PrivacyKit::StartUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
    EXPECT_EQ(ERR_PERMISSION_DENIED, PrivacyKit::StopUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
}

/**
 * @tc.name: BundleUsingtest005
 * @tc.desc: Verify bundle repeat start and repeat stop return expected errors.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest005, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest005", reqPerm, true);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
    EXPECT_EQ(ERR_PERMISSION_ALREADY_START_USING,
        PrivacyKit::StartUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
    EXPECT_EQ(ERR_PERMISSION_NOT_START_USING,
        PrivacyKit::StopUsingPermission(TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
}

/**
 * @tc.name: BundleUsingtest006
 * @tc.desc: Verify bundle start and stop return permission not exist for unsupported permission name.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest006, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest006", reqPerm, true);
    const std::string noexistPerm = "ohos.permission.TEST";

    EXPECT_EQ(ERR_PERMISSION_NOT_EXIST, PrivacyKit::StartUsingPermission(TEST_BUNDLE_NAME, noexistPerm));
    EXPECT_EQ(ERR_PERMISSION_NOT_EXIST, PrivacyKit::StopUsingPermission(TEST_BUNDLE_NAME, noexistPerm));
}

/**
 * @tc.name: BundleUsingtest007
 * @tc.desc: Verify bundle callback is not triggered by mute and restart is blocked by EDM policy after stop.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest007, TestSize.Level1)
{
    char value[VALUE_MAX_LEN] = {0};
    GetParameter(EDM_CAMERA_MUTE_KEY, "", value, VALUE_MAX_LEN - 1);
    std::string muteState(value);

    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest007", reqPerm, true);
    std::vector<std::string> permList = {TEST_PERMISSION_NAME};
    auto callbackPtr = std::make_shared<BundleActiveStatusCallbackTest>(permList);
    const std::string bundleName = "ohos.test.bundle.callback.mute";
    AccessTokenID callingTokenID = static_cast<AccessTokenID>(GetSelfTokenID());

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::ALL));
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(1, callbackPtr->callTimes_);
    EXPECT_EQ(PERM_ACTIVE_IN_FOREGROUND, callbackPtr->type_);
    EXPECT_EQ(callingTokenID, callbackPtr->callingTokenID_);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), callbackPtr->permissionName_);
    EXPECT_EQ(bundleName, callbackPtr->bundleName_);

    ASSERT_EQ(0, SetParameter(EDM_CAMERA_MUTE_KEY, "true"));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(1, callbackPtr->callTimes_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(2, callbackPtr->callTimes_);
    EXPECT_EQ(PERM_INACTIVE, callbackPtr->type_);
    EXPECT_EQ(callingTokenID, callbackPtr->callingTokenID_);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), callbackPtr->permissionName_);
    EXPECT_EQ(bundleName, callbackPtr->bundleName_);

    EXPECT_EQ(ERR_EDM_POLICY_CHECK_FAILED, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(2, callbackPtr->callTimes_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));

    EXPECT_EQ(0, SetParameter(EDM_CAMERA_MUTE_KEY, muteState.c_str()));
}

/**
 * @tc.name: BundleUsingtest008
 * @tc.desc: Verify bundle callback is not triggered by disable policy and restart is blocked after stop.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest008, TestSize.Level1)
{
    bool disableBackup = false;
    {
        MockNativeToken mock("accesstoken_service");
        ASSERT_EQ(RET_SUCCESS, PrivacyKit::GetDisablePolicy(TEST_PERMISSION_NAME, disableBackup));
    }

    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest008", reqPerm, true);
    std::vector<std::string> permList = {TEST_PERMISSION_NAME};
    auto callbackPtr = std::make_shared<BundleActiveStatusCallbackTest>(permList);
    const std::string bundleName = "ohos.test.bundle.callback.disable";
    AccessTokenID callingTokenID = static_cast<AccessTokenID>(GetSelfTokenID());

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::ALL));
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(1, callbackPtr->callTimes_);
    EXPECT_EQ(PERM_ACTIVE_IN_FOREGROUND, callbackPtr->type_);
    EXPECT_EQ(callingTokenID, callbackPtr->callingTokenID_);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), callbackPtr->permissionName_);
    EXPECT_EQ(bundleName, callbackPtr->bundleName_);

    ASSERT_EQ(RET_SUCCESS, SetDisablePolicyAsEdm(TEST_PERMISSION_NAME, true));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(1, callbackPtr->callTimes_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(2, callbackPtr->callTimes_);
    EXPECT_EQ(PERM_INACTIVE, callbackPtr->type_);
    EXPECT_EQ(callingTokenID, callbackPtr->callingTokenID_);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), callbackPtr->permissionName_);
    EXPECT_EQ(bundleName, callbackPtr->bundleName_);

    EXPECT_EQ(ERR_EDM_POLICY_CHECK_FAILED, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(2, callbackPtr->callTimes_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));

    ASSERT_EQ(RET_SUCCESS, SetDisablePolicyAsEdm(TEST_PERMISSION_NAME, disableBackup));
}

/**
 * @tc.name: BundleUsingtest009
 * @tc.desc: Verify GetCurrUsingPermInfo does not return bundle records when nothing is started.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest009, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest009", reqPerm, true);

    std::vector<CurrUsingPermInfo> infoList;
    {
        MockNativeToken mockQuery("audio_server");
        EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetCurrUsingPermInfo(infoList));
    }
    EXPECT_EQ(nullptr, FindBundleUsingInfo(infoList, TEST_BUNDLE_NAME, TEST_PERMISSION_NAME));
}

/**
 * @tc.name: BundleUsingtest010
 * @tc.desc: Verify bundle only start/stop affects GetCurrUsingPermInfo and CheckPermissionInUse.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest010, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest010", reqPerm, true);
    const std::string bundleName = "ohos.test.bundle.query";

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));

    std::vector<CurrUsingPermInfo> infoList;
    {
        MockNativeToken mockQuery("audio_server");
        EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetCurrUsingPermInfo(infoList));
    }
    const CurrUsingPermInfo* info = FindBundleUsingInfo(infoList, bundleName, TEST_PERMISSION_NAME);
    ASSERT_NE(nullptr, info);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), info->permissionName);
    EXPECT_EQ(bundleName, info->bundleName);

    bool isUsing = false;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::CheckPermissionInUse(TEST_PERMISSION_NAME, isUsing));
    EXPECT_TRUE(isUsing);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleName, TEST_PERMISSION_NAME));

    infoList.clear();
    {
        MockNativeToken mockQuery("audio_server");
        EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetCurrUsingPermInfo(infoList));
    }
    EXPECT_EQ(nullptr, FindBundleUsingInfo(infoList, bundleName, TEST_PERMISSION_NAME));

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::CheckPermissionInUse(TEST_PERMISSION_NAME, isUsing));
    EXPECT_FALSE(isUsing);
}

/**
 * @tc.name: BundleUsingtest011
 * @tc.desc: Verify CheckPermissionInUse with token only start and stop.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest011, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest011", reqPerm, true);
    AccessTokenID tokenID = CreateGrantedHapToken("ohos.test.bundle.token.only", TEST_PERMISSION_NAME);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(tokenID, TEST_PERMISSION_NAME));

    bool isUsing = false;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::CheckPermissionInUse(TEST_PERMISSION_NAME, isUsing));
    EXPECT_TRUE(isUsing);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(tokenID, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::CheckPermissionInUse(TEST_PERMISSION_NAME, isUsing));
    EXPECT_FALSE(isUsing);

    EXPECT_EQ(RET_SUCCESS, PrivacyTestCommon::DeleteTestHapToken(tokenID));
}

/**
 * @tc.name: BundleUsingtest012
 * @tc.desc: Verify bundle and token together affect GetCurrUsingPermInfo and CheckPermissionInUse.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest012, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest012", reqPerm, true);
    AccessTokenID callingTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
 
    AccessTokenID tokenID = CreateGrantedHapToken("ohos.test.bundle.token", TEST_PERMISSION_NAME);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission("ohos.test.bundle.mixed", TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(tokenID, TEST_PERMISSION_NAME));

    std::vector<CurrUsingPermInfo> infoList;
    {
        MockNativeToken mockQuery("audio_server");
        EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetCurrUsingPermInfo(infoList));
    }
    const CurrUsingPermInfo* bundleInfo = FindBundleUsingInfo(
        infoList, "ohos.test.bundle.mixed", TEST_PERMISSION_NAME);
    ASSERT_NE(nullptr, bundleInfo);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), bundleInfo->permissionName);
    EXPECT_EQ("ohos.test.bundle.mixed", bundleInfo->bundleName);
    EXPECT_EQ(PERM_ACTIVE_IN_FOREGROUND, bundleInfo->type);
    const CurrUsingPermInfo* info = FindUsingInfo(infoList, tokenID, TEST_PERMISSION_NAME);
    EXPECT_NE(nullptr, info);
    if (info != nullptr) {
        EXPECT_EQ(callingTokenID, info->callingTokenID);
        EXPECT_EQ(tokenID, info->tokenID);
        EXPECT_EQ(std::string(TEST_PERMISSION_NAME), info->permissionName);
        EXPECT_EQ(-1, info->pid); // -1: bundle start does not carry pid
        EXPECT_EQ("", info->deviceId);
        EXPECT_EQ(NORMAL_TYPE, info->usedType);
        EXPECT_FALSE(info->isRemote);
    }

    bool isUsing = false;
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::CheckPermissionInUse(TEST_PERMISSION_NAME, isUsing));
    EXPECT_TRUE(isUsing);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(tokenID, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::CheckPermissionInUse(TEST_PERMISSION_NAME, isUsing));
    EXPECT_TRUE(isUsing);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission("ohos.test.bundle.mixed", TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::CheckPermissionInUse(TEST_PERMISSION_NAME, isUsing));
    EXPECT_FALSE(isUsing);

    EXPECT_EQ(RET_SUCCESS, PrivacyTestCommon::DeleteTestHapToken(tokenID));
}

#ifdef REMOTE_PRIVACY_ENABLE
/**
 * @tc.name: BundleUsingtest013
 * @tc.desc: Verify bundle, token and remote together affect GetCurrUsingPermInfo and CheckPermissionInUse.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest013, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest013", reqPerm, true);
    AccessTokenID callingTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    AccessTokenID tokenID = CreateGrantedHapToken("ohos.test.bundle.token.remote", TEST_PERMISSION_NAME);
    ASSERT_NE(INVALID_TOKENID, tokenID);
    const std::string bundleName = "ohos.test.bundle.remote.mixed";
    RemoteCallerInfo remoteInfo = {"remote_device_id", "remote_device_name"};
    auto startRemote = [&remoteInfo]() { MockNativeToken mockRemote("camera_service");
        return PrivacyKit::StartRemoteUsingPermission(remoteInfo, TEST_PERMISSION_NAME); };
    auto stopRemote = [&remoteInfo]() { MockNativeToken mockRemote("camera_service");
        return PrivacyKit::StopRemoteUsingPermission(remoteInfo, TEST_PERMISSION_NAME); };
    auto checkInfo = [&](const std::vector<CurrUsingPermInfo>& infoList) {
        const CurrUsingPermInfo* bundleInfo = FindBundleUsingInfo(infoList, bundleName, TEST_PERMISSION_NAME);
        ASSERT_NE(nullptr, bundleInfo);
        EXPECT_EQ(bundleName, bundleInfo->bundleName);
        const CurrUsingPermInfo* tokenInfo = FindUsingInfo(infoList, tokenID, TEST_PERMISSION_NAME);
        ASSERT_NE(nullptr, tokenInfo);
        EXPECT_EQ(callingTokenID, tokenInfo->callingTokenID);
        const CurrUsingPermInfo* remoteUsingInfo =
            FindRemoteUsingInfo(infoList, remoteInfo.remoteDeviceId, TEST_PERMISSION_NAME);
        ASSERT_NE(nullptr, remoteUsingInfo);
        EXPECT_TRUE(remoteUsingInfo->isRemote);
    };
    auto checkUsing = [](bool expected) {
        bool isUsing = false;
        EXPECT_EQ(RET_SUCCESS, PrivacyKit::CheckPermissionInUse(TEST_PERMISSION_NAME, isUsing));
        EXPECT_EQ(expected, isUsing);
    };
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(tokenID, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, startRemote());
    std::vector<CurrUsingPermInfo> infoList;
    { MockNativeToken mockQuery("audio_server"); EXPECT_EQ(RET_SUCCESS, PrivacyKit::GetCurrUsingPermInfo(infoList)); }
    checkInfo(infoList);
    checkUsing(true);
    EXPECT_EQ(RET_SUCCESS, stopRemote());
    checkUsing(true);
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(tokenID, TEST_PERMISSION_NAME));
    checkUsing(true);
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleName, TEST_PERMISSION_NAME));
    checkUsing(false);
    EXPECT_EQ(RET_SUCCESS, PrivacyTestCommon::DeleteTestHapToken(tokenID));
}
#endif

/**
 * @tc.name: BundleUsingtest014
 * @tc.desc: Verify register callback receives bundle start active status change.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest014, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest014", reqPerm, true);
    AccessTokenID callingTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    std::vector<std::string> permList = {TEST_PERMISSION_NAME};
    auto callbackPtr = std::make_shared<BundleActiveStatusCallbackTest>(permList);

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::ALL));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission("ohos.test.bundle.callback", TEST_PERMISSION_NAME));

    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(1, callbackPtr->callTimes_);
    EXPECT_EQ(PERM_ACTIVE_IN_FOREGROUND, callbackPtr->type_);
    EXPECT_EQ(callingTokenID, callbackPtr->callingTokenID_);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), callbackPtr->permissionName_);
    EXPECT_EQ("ohos.test.bundle.callback", callbackPtr->bundleName_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission("ohos.test.bundle.callback", TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: BundleUsingtest015
 * @tc.desc: Verify register callback receives bundle stop active status change.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest015, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest015", reqPerm, true);
    AccessTokenID callingTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    std::vector<std::string> permList = {TEST_PERMISSION_NAME};
    auto callbackPtr = std::make_shared<BundleActiveStatusCallbackTest>(permList);
    const std::string bundleName = "ohos.test.bundle.callback.stop";

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::ALL));
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(2, callbackPtr->callTimes_);
    EXPECT_EQ(PERM_INACTIVE, callbackPtr->type_);
    EXPECT_EQ(callingTokenID, callbackPtr->callingTokenID_);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), callbackPtr->permissionName_);
    EXPECT_EQ(bundleName, callbackPtr->bundleName_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: BundleUsingtest016
 * @tc.desc: Verify TOKEN_ONLY callback does not receive bundle start and stop active status change.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest016, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest016", reqPerm, true);
    std::vector<std::string> permList = {TEST_PERMISSION_NAME};
    auto callbackPtr = std::make_shared<BundleActiveStatusCallbackTest>(permList);
    const std::string bundleName = "ohos.test.bundle.callback.tokenonly";

    ASSERT_EQ(RET_SUCCESS,
        PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::TOKEN_ONLY));
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(0, callbackPtr->callTimes_);

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(0, callbackPtr->callTimes_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: BundleUsingtest017
 * @tc.desc: Verify callback does not receive bundle start and stop when permission does not match.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest017, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest017", reqPerm, true);
    std::vector<std::string> permList = {"ohos.permission.MICROPHONE"};
    auto callbackPtr = std::make_shared<BundleActiveStatusCallbackTest>(permList);
    const std::string bundleName = "ohos.test.bundle.callback.mismatch";

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::ALL));
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(0, callbackPtr->callTimes_);

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(0, callbackPtr->callTimes_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: BundleUsingtest018
 * @tc.desc: Verify callback does not receive bundle start and stop after unregister.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest018, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest018", reqPerm, true);
    std::vector<std::string> permList = {TEST_PERMISSION_NAME};
    auto callbackPtr = std::make_shared<BundleActiveStatusCallbackTest>(permList);
    const std::string bundleName = "ohos.test.bundle.callback.unregister";

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::ALL));
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(0, callbackPtr->callTimes_);

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(0, callbackPtr->callTimes_);
}

/**
 * @tc.name: BundleUsingtest019
 * @tc.desc: Verify callback bundleName matches the actual bundle for multiple bundles.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest019, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest019", reqPerm, true);
    std::vector<std::string> permList = {TEST_PERMISSION_NAME};
    auto callbackPtr = std::make_shared<BundleActiveStatusCallbackTest>(permList);
    const std::string bundleNameA = "ohos.test.bundle.callback.multi.a";
    const std::string bundleNameB = "ohos.test.bundle.callback.multi.b";

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::ALL));
    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleNameA, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(1, callbackPtr->callTimes_);
    EXPECT_EQ(bundleNameA, callbackPtr->bundleName_);

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleNameB, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(2, callbackPtr->callTimes_);
    EXPECT_EQ(bundleNameB, callbackPtr->bundleName_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleNameA, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleNameB, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
}

/**
 * @tc.name: BundleUsingtest020
 * @tc.desc: Verify ALL callback receives both bundle start and token start active status change.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BundleUsingTest, BundleUsingtest020, TestSize.Level1)
{
    std::vector<std::string> reqPerm = {PERMISSION_USED_STATS};
    MockHapToken mock("BundleUsingtest020", reqPerm, true);
    std::vector<std::string> permList = {TEST_PERMISSION_NAME};
    auto callbackPtr = std::make_shared<BundleActiveStatusCallbackTest>(permList);
    const std::string bundleName = "ohos.test.bundle.callback.all";
    AccessTokenID callingTokenID = static_cast<AccessTokenID>(GetSelfTokenID());
    AccessTokenID tokenID = CreateGrantedHapToken("ohos.test.bundle.callback.token", TEST_PERMISSION_NAME);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::RegisterPermActiveStatusCallback(callbackPtr, CallbackRegisterType::ALL));

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(bundleName, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(1, callbackPtr->callTimes_);
    EXPECT_EQ(PERM_ACTIVE_IN_FOREGROUND, callbackPtr->type_);
    EXPECT_EQ(callingTokenID, callbackPtr->callingTokenID_);
    EXPECT_EQ(INVALID_TOKENID, callbackPtr->tokenID_);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), callbackPtr->permissionName_);
    EXPECT_EQ(bundleName, callbackPtr->bundleName_);

    ASSERT_EQ(RET_SUCCESS, PrivacyKit::StartUsingPermission(tokenID, TEST_PERMISSION_NAME));
    usleep(1000000); // 1000000: 1s
    EXPECT_EQ(2, callbackPtr->callTimes_);
    EXPECT_EQ(callingTokenID, callbackPtr->callingTokenID_);
    EXPECT_EQ(tokenID, callbackPtr->tokenID_);
    EXPECT_EQ(std::string(TEST_PERMISSION_NAME), callbackPtr->permissionName_);
    EXPECT_EQ("", callbackPtr->bundleName_);

    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(tokenID, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::StopUsingPermission(bundleName, TEST_PERMISSION_NAME));
    EXPECT_EQ(RET_SUCCESS, PrivacyKit::UnRegisterPermActiveStatusCallback(callbackPtr));
    EXPECT_EQ(RET_SUCCESS, PrivacyTestCommon::DeleteTestHapToken(tokenID));
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
