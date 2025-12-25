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

#include "privacy_multi_thread_test.h"

#include <gtest/hwext/gtest-multithread.h>

#include "privacy_error.h"
#include "privacy_kit.h"
#include "privacy_test_common.h"

using namespace testing::ext;
using namespace testing::mt;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t MAX_HAP_NUM = 100;
constexpr int32_t RET_NO_ERROR = 0;
constexpr int32_t MULTIPLE_COUNT = 10;
static MockHapToken* g_mock = nullptr;
static AccessTokenID g_selfTokenId = 0;
static std::vector<AccessTokenID> g_tokenIdList;
std::vector<std::string> g_permList = {
    "ohos.permission.CAMERA",
    "ohos.permission.MICROPHONE",
    "ohos.permission.APPROXIMATELY_LOCATION",
    "ohos.permission.READ_IMAGEVIDEO",
    "ohos.permission.WRITE_IMAGEVIDEO",
    "ohos.permission.READ_WHOLE_CALENDAR",
    "ohos.permission.WRITE_WHOLE_CALENDAR",
    "ohos.permission.READ_DOCUMENT",
    "ohos.permission.WRITE_DOCUMENT",
    "ohos.permission.ACCESS_BLUETOOTH"
};
}

static void CreateHapTokenList(int32_t hapSize, std::vector<AccessTokenID>& tokenIdList)
{
    HapPolicyParams policyPrams = {
        .apl = APL_NORMAL,
        .domain = "PrivacyMultiThreadTest",
    };
    HapInfoParams infoParms = {
        .userID = 100, // 100: uerId
        .bundleName = "PrivacyMultiThreadTest",
        .instIndex = 0,
        .appIDDesc = "PrivacyMultiThreadTest"
    };
    for (const auto& permission : g_permList) {
        static PermissionStateFull permState = {
            .permissionName = permission,
            .isGeneral = true,
            .resDeviceID = {"local"},
            .grantStatus = {PermissionState::PERMISSION_GRANTED},
            .grantFlags = {1}
        };
        policyPrams.permStateList.emplace_back(permState);
    }
    for (int32_t i = 0; i < hapSize; i++) {
        AccessTokenIDEx tokenIdEx = {0};
        tokenIdEx = PrivacyTestCommon::AllocTestHapToken(infoParms, policyPrams);
        EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
        tokenIdList.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
        infoParms.userID++;
    }
}

static void DeleteHapTokenList(const std::vector<AccessTokenID>& tokenIdList)
{
    for (auto tokenId : tokenIdList) {
        EXPECT_EQ(0, PrivacyTestCommon::DeleteTestHapToken(tokenId));
    }
}

void PrivacyMultiThreadTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    PrivacyTestCommon::SetTestEvironment(g_selfTokenId);

    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.PERMISSION_USED_STATS");
    g_mock = new (std::nothrow) MockHapToken("PrivacyMultiThreadMockTest", reqPerm, true);

    CreateHapTokenList(MAX_HAP_NUM, g_tokenIdList);
}

void PrivacyMultiThreadTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }

    DeleteHapTokenList(g_tokenIdList);
    SetSelfTokenID(g_selfTokenId);
    PrivacyTestCommon::ResetTestEvironment();
}

void PrivacyMultiThreadTest::SetUp()
{
}

void PrivacyMultiThreadTest::TearDown()
{
    for (auto tokenId : g_tokenIdList) {
        PrivacyKit::RemovePermissionUsedRecords(tokenId);
    }
}

/**
 * @tc.name: AddPermissionRecordMultiThreadTest001
 * @tc.desc: test AddPermissionUsedRecord
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(PrivacyMultiThreadTest, AddPermissionRecordMultiThreadTest001, TestSize.Level1, MULTIPLE_COUNT)
{
    GTEST_LOG_(INFO) << "tid: " << gettid();
    for (auto tokenId : g_tokenIdList) {
        for (const auto& permission : g_permList) {
            EXPECT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(tokenId, permission, 1, 0));
        }
    }
}

/**
 * @tc.name: StartAndStopPermissionMultiThreadTest001
 * @tc.desc: test StartUsingPermission and StopUsingPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(PrivacyMultiThreadTest, StartAndStopPermissionMultiThreadTest001, TestSize.Level1, MULTIPLE_COUNT)
{
    GTEST_LOG_(INFO) << "tid: " << gettid();
    int32_t pid = gettid(); // transfer tid to pid
    for (auto tokenId : g_tokenIdList) {
        for (const auto& permission : g_permList) {
            EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(tokenId, permission, pid));
        }
    }
    for (auto tokenId : g_tokenIdList) {
        for (const auto& permission : g_permList) {
            EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(tokenId, permission, pid));
        }
    }
}

class CbCustomizeForMutiThreadTest : public StateCustomizedCbk {
public:
    CbCustomizeForMutiThreadTest()
    {}

    ~CbCustomizeForMutiThreadTest()
    {}

    virtual void StateChangeNotify(AccessTokenID tokenId, bool isShow)
    {}
};

/**
 * @tc.name: StartUsingPermissionMultiThreadTest001
 * @tc.desc: test StartUsingPermission
 * @tc.type: FUNC
 * @tc.require:
 */
HWMTEST_F(PrivacyMultiThreadTest, StartUsingPermissionCallbackMultiThreadTest001, TestSize.Level1, MULTIPLE_COUNT)
{
    GTEST_LOG_(INFO) << "tid: " << gettid();
    int32_t pid = gettid(); // transfer tid to pid
    for (auto tokenId : g_tokenIdList) {
        auto callbackPtr = std::make_shared<CbCustomizeForMutiThreadTest>();
        EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StartUsingPermission(tokenId, "ohos.permission.CAMERA", callbackPtr, pid));
    }
    for (auto tokenId : g_tokenIdList) {
        EXPECT_EQ(RET_NO_ERROR, PrivacyKit::StopUsingPermission(tokenId, "ohos.permission.CAMERA", pid));
    }
}
}  // namespace SecurityComponent
}  // namespace Security
}  // namespace OHOS