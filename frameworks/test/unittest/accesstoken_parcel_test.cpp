/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
 
#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "access_token.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "parcel.h"
#include "permission_state_change_scope_parcel.h"
#include "permission_state_change_info_parcel.h"
#include "permission_state_full.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const std::string TEST_PERMISSION_NAME_ALPHA = "ohos.permission.ALPHA";
static const std::string TEST_PERMISSION_NAME_BETA = "ohos.permission.BETA";
static constexpr AccessTokenID TEST_TOKEN_ID = 10002;
static constexpr int32_t TEST_PERMSTATE_CHANGE_TYPE = 10001;

PermissionDef g_permDefAlpha = {
    .permissionName = TEST_PERMISSION_NAME_ALPHA,
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "annoying",
    .descriptionId = 1
};
PermissionDef g_permDefBeta = {
    .permissionName = TEST_PERMISSION_NAME_BETA,
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "so trouble",
    .descriptionId = 1
};

PermissionStateFull g_permStatAlpha = {
    .permissionName = TEST_PERMISSION_NAME_ALPHA,
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
};
PermissionStateFull g_permStatBeta = {
    .permissionName = TEST_PERMISSION_NAME_BETA,
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};
}
class AccessTokenParcelTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AccessTokenParcelTest::SetUpTestCase(void) {}
void AccessTokenParcelTest::TearDownTestCase(void) {}
void AccessTokenParcelTest::SetUp(void) {}
void AccessTokenParcelTest::TearDown(void) {}

/**
 * @tc.name: HapInfoParcel001
 * @tc.desc: Test HapInfo Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, HapInfoParcel001, TestSize.Level1)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
    };

    Parcel parcel;
    EXPECT_EQ(true, hapinfoParcel.Marshalling(parcel));

    std::shared_ptr<HapInfoParcel> readedData(HapInfoParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(hapinfoParcel.hapInfoParameter.userID, readedData->hapInfoParameter.userID);
    EXPECT_EQ(true, hapinfoParcel.hapInfoParameter.bundleName == readedData->hapInfoParameter.bundleName);
    EXPECT_EQ(hapinfoParcel.hapInfoParameter.instIndex, readedData->hapInfoParameter.instIndex);
    EXPECT_EQ(true, hapinfoParcel.hapInfoParameter.appIDDesc == readedData->hapInfoParameter.appIDDesc);
    EXPECT_EQ(hapinfoParcel.hapInfoParameter.apiVersion, readedData->hapInfoParameter.apiVersion);
}

/**
 * @tc.name: HapPolicyParcel001
 * @tc.desc: Test HapPolicy Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, HapPolicyParcel001, TestSize.Level1)
{
    HapPolicyParcel hapPolicyParcel;

    hapPolicyParcel.hapPolicyParameter.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicyParameter.domain = "test.domain";
    hapPolicyParcel.hapPolicyParameter.permList.emplace_back(g_permDefAlpha);
    hapPolicyParcel.hapPolicyParameter.permList.emplace_back(g_permDefBeta);
    hapPolicyParcel.hapPolicyParameter.permStateList.emplace_back(g_permStatAlpha);
    hapPolicyParcel.hapPolicyParameter.permStateList.emplace_back(g_permStatBeta);

    Parcel parcel;
    EXPECT_EQ(true, hapPolicyParcel.Marshalling(parcel));

    std::shared_ptr<HapPolicyParcel> readedData(HapPolicyParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.apl, readedData->hapPolicyParameter.apl);
    EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.domain, readedData->hapPolicyParameter.domain);
    EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList.size(), readedData->hapPolicyParameter.permList.size());
    EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList.size(),
        readedData->hapPolicyParameter.permStateList.size());

    for(int32_t i = 0; i < hapPolicyParcel.hapPolicyParameter.permList.size(); i++) {
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].permissionName,
            readedData->hapPolicyParameter.permList[i].permissionName);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].bundleName,
            readedData->hapPolicyParameter.permList[i].bundleName);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].grantMode,
            readedData->hapPolicyParameter.permList[i].grantMode);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].availableLevel,
            readedData->hapPolicyParameter.permList[i].availableLevel);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].label,
            readedData->hapPolicyParameter.permList[i].label);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].labelId,
            readedData->hapPolicyParameter.permList[i].labelId);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].description,
            readedData->hapPolicyParameter.permList[i].description);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].descriptionId,
            readedData->hapPolicyParameter.permList[i].descriptionId);
    }

    for(int32_t i = 0; i < hapPolicyParcel.hapPolicyParameter.permStateList.size(); i++) {
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].permissionName,
            readedData->hapPolicyParameter.permStateList[i].permissionName);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].isGeneral,
            readedData->hapPolicyParameter.permStateList[i].isGeneral);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].resDeviceID,
            readedData->hapPolicyParameter.permStateList[i].resDeviceID);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].grantStatus,
            readedData->hapPolicyParameter.permStateList[i].grantStatus);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].grantFlags,
            readedData->hapPolicyParameter.permStateList[i].grantFlags);
    }
}

/**
 * @tc.name: PermissionStateChangeInfoParcel001
 * @tc.desc: Test PermissionStateChangeInfo Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, PermissionStateChangeInfoParcel001, TestSize.Level1)
{
    PermissionStateChangeInfoParcel permissionStateParcel;
    permissionStateParcel.changeInfo.PermStateChangeType = TEST_PERMSTATE_CHANGE_TYPE;
    permissionStateParcel.changeInfo.tokenID = TEST_TOKEN_ID;
    permissionStateParcel.changeInfo.permissionName = TEST_PERMISSION_NAME_ALPHA;

    Parcel parcel;
    EXPECT_EQ(true, permissionStateParcel.Marshalling(parcel));

    std::shared_ptr<PermissionStateChangeInfoParcel> readedData(PermissionStateChangeInfoParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);
    EXPECT_EQ(permissionStateParcel.changeInfo.PermStateChangeType, readedData->changeInfo.PermStateChangeType);
    EXPECT_EQ(permissionStateParcel.changeInfo.tokenID, readedData->changeInfo.tokenID);
    EXPECT_EQ(permissionStateParcel.changeInfo.permissionName, readedData->changeInfo.permissionName);
}

/**
 * @tc.name: PermStateChangeScopeParcel001
 * @tc.desc: Test PermStateChangeScope Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, PermStateChangeScopeParcel001, TestSize.Level1)
{
    PermStateChangeScopeParcel permStateChangeScopeParcel;
    permStateChangeScopeParcel.scope.tokenIDs.emplace_back(TEST_TOKEN_ID);
    permStateChangeScopeParcel.scope.permList.emplace_back(TEST_PERMISSION_NAME_ALPHA);

    Parcel parcel;
    EXPECT_EQ(true, permStateChangeScopeParcel.Marshalling(parcel));

    std::shared_ptr<PermStateChangeScopeParcel> readedData(PermStateChangeScopeParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);
    
    EXPECT_EQ(true,  permStateChangeScopeParcel.scope.tokenIDs.size() == readedData->scope.tokenIDs.size());
    EXPECT_EQ(true,  permStateChangeScopeParcel.scope.permList.size() == readedData->scope.permList.size());

    for(int32_t i = 0; i < readedData->scope.tokenIDs.size(); i++) {
        EXPECT_EQ(permStateChangeScopeParcel.scope.tokenIDs[i], readedData->scope.tokenIDs[i]);
    }
    for(int32_t i = 0; i < readedData->scope.permList.size(); i++) {
        EXPECT_EQ(true, permStateChangeScopeParcel.scope.permList[i] == readedData->scope.permList[i]);
    } 
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS