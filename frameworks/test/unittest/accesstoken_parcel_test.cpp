/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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
#include "atm_tools_param_info_parcel.h"
#include "claw_auth_info_parcel.h"
#include "claw_token_challenge_parcel.h"
#include "cli_info_result_parcel.h"
#include "cli_init_info_parcel.h"
#include "cli_permissions_result_parcel.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "hap_token_info_parcel.h"
#include "hap_token_info_for_sync_parcel.h"
#include "native_token_info_parcel.h"
#include "parcel.h"
#include "parcel_utils.h"
#include "permission_dialog_result_parcel.h"
#include "permission_grant_info_parcel.h"
#include "perm_state_change_scope_parcel.h"
#include "permission_state_change_info_parcel.h"
#include "permission_status_parcel.h"
#include "skill_permissions_result_parcel.h"

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

PermissionStatus g_permStatAlpha = {
    .permissionName = TEST_PERMISSION_NAME_ALPHA,
    .grantStatus = PermissionState::PERMISSION_DENIED,
    .grantFlag = PermissionFlag::PERMISSION_USER_SET
};
PermissionStatus g_permStatBeta = {
    .permissionName = TEST_PERMISSION_NAME_BETA,
    .grantStatus = PermissionState::PERMISSION_GRANTED,
    .grantFlag = PermissionFlag::PERMISSION_SYSTEM_FIXED
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
        .isSystemApp = false,
    };

    Parcel parcel;
    EXPECT_EQ(true, hapinfoParcel.Marshalling(parcel));

    std::shared_ptr<HapInfoParcel> readedData(HapInfoParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);

    EXPECT_EQ(hapinfoParcel.hapInfoParameter.userID, readedData->hapInfoParameter.userID);
    EXPECT_EQ(true, hapinfoParcel.hapInfoParameter.bundleName == readedData->hapInfoParameter.bundleName);
    EXPECT_EQ(hapinfoParcel.hapInfoParameter.instIndex, readedData->hapInfoParameter.instIndex);
    EXPECT_EQ(true, hapinfoParcel.hapInfoParameter.appIDDesc == readedData->hapInfoParameter.appIDDesc);
    EXPECT_EQ(hapinfoParcel.hapInfoParameter.apiVersion, readedData->hapInfoParameter.apiVersion);
    EXPECT_EQ(hapinfoParcel.hapInfoParameter.isSystemApp, readedData->hapInfoParameter.isSystemApp);
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

    hapPolicyParcel.hapPolicy.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicy.domain = "test.domain";
    hapPolicyParcel.hapPolicy.permList.emplace_back(g_permDefAlpha);
    hapPolicyParcel.hapPolicy.permList.emplace_back(g_permDefBeta);
    hapPolicyParcel.hapPolicy.permStateList.emplace_back(g_permStatAlpha);
    hapPolicyParcel.hapPolicy.permStateList.emplace_back(g_permStatBeta);

    Parcel parcel;
    EXPECT_EQ(true, hapPolicyParcel.Marshalling(parcel));

    std::shared_ptr<HapPolicyParcel> readedData(HapPolicyParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);

    EXPECT_EQ(hapPolicyParcel.hapPolicy.apl, readedData->hapPolicy.apl);
    EXPECT_EQ(hapPolicyParcel.hapPolicy.domain, readedData->hapPolicy.domain);
    EXPECT_EQ(hapPolicyParcel.hapPolicy.permList.size(), readedData->hapPolicy.permList.size());
    EXPECT_EQ(hapPolicyParcel.hapPolicy.permStateList.size(),
        readedData->hapPolicy.permStateList.size());

    for (uint32_t i = 0; i < hapPolicyParcel.hapPolicy.permList.size(); i++) {
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permList[i].permissionName,
            readedData->hapPolicy.permList[i].permissionName);
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permList[i].bundleName,
            readedData->hapPolicy.permList[i].bundleName);
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permList[i].grantMode,
            readedData->hapPolicy.permList[i].grantMode);
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permList[i].availableLevel,
            readedData->hapPolicy.permList[i].availableLevel);
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permList[i].label,
            readedData->hapPolicy.permList[i].label);
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permList[i].labelId,
            readedData->hapPolicy.permList[i].labelId);
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permList[i].description,
            readedData->hapPolicy.permList[i].description);
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permList[i].descriptionId,
            readedData->hapPolicy.permList[i].descriptionId);
    }

    for (uint32_t i = 0; i < hapPolicyParcel.hapPolicy.permStateList.size(); i++) {
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permStateList[i].permissionName,
            readedData->hapPolicy.permStateList[i].permissionName);
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permStateList[i].grantStatus,
            readedData->hapPolicy.permStateList[i].grantStatus);
        EXPECT_EQ(hapPolicyParcel.hapPolicy.permStateList[i].grantFlag,
            readedData->hapPolicy.permStateList[i].grantFlag);
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
    permissionStateParcel.changeInfo.permStateChangeType = TEST_PERMSTATE_CHANGE_TYPE;
    permissionStateParcel.changeInfo.tokenID = TEST_TOKEN_ID;
    permissionStateParcel.changeInfo.permissionName = TEST_PERMISSION_NAME_ALPHA;

    Parcel parcel;
    EXPECT_EQ(true, permissionStateParcel.Marshalling(parcel));

    std::shared_ptr<PermissionStateChangeInfoParcel> readedData(PermissionStateChangeInfoParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
    EXPECT_EQ(permissionStateParcel.changeInfo.permStateChangeType, readedData->changeInfo.permStateChangeType);
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
    EXPECT_NE(nullptr, readedData);
    
    EXPECT_EQ(true,  permStateChangeScopeParcel.scope.tokenIDs.size() == readedData->scope.tokenIDs.size());
    EXPECT_EQ(true,  permStateChangeScopeParcel.scope.permList.size() == readedData->scope.permList.size());

    for (uint32_t i = 0; i < readedData->scope.tokenIDs.size(); i++) {
        EXPECT_EQ(permStateChangeScopeParcel.scope.tokenIDs[i], readedData->scope.tokenIDs[i]);
    }
    for (uint32_t i = 0; i < readedData->scope.permList.size(); i++) {
        EXPECT_EQ(true, permStateChangeScopeParcel.scope.permList[i] == readedData->scope.permList[i]);
    }
}

/**
 * @tc.name: HapTokenInfoForSyncParcel001
 * @tc.desc: Test HapTokenInfoForSync Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, HapTokenInfoForSyncParcel001, TestSize.Level1)
{
    HapTokenInfoForSyncParcel hapTokenInfoSync;

    HapTokenInfo hapTokenInfo;
    hapTokenInfo.ver = 0;
    hapTokenInfo.userID = 2;
    hapTokenInfo.bundleName = "bundle1";
    hapTokenInfo.apiVersion = 8;
    hapTokenInfo.instIndex = 0;
    hapTokenInfo.dlpType = 0;
    hapTokenInfo.tokenID = 0x53100000;
    hapTokenInfo.tokenAttr = 0;
    hapTokenInfoSync.hapTokenInfoForSyncParams.baseInfo = hapTokenInfo;
    hapTokenInfoSync.hapTokenInfoForSyncParams.permStateList.emplace_back(g_permStatBeta);

    Parcel parcel;
    EXPECT_EQ(true, hapTokenInfoSync.Marshalling(parcel));
    std::shared_ptr<HapTokenInfoForSyncParcel> readedData(HapTokenInfoForSyncParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
}

static void WriteParcelable(
    Parcel& out, const Parcelable& baseInfoParcel, uint32_t size)
{
    out.WriteParcelable(&baseInfoParcel);
    std::vector<PermissionStatus> permStateList;
    for (uint32_t i = 0; i < size; i++) {
        permStateList.emplace_back(g_permStatBeta);
    }
    uint32_t permStateListSize = permStateList.size();
    out.WriteUint32(permStateListSize);
    for (uint32_t i = 0; i < permStateListSize; i++) {
        PermissionStatusParcel permStateParcel;
        permStateParcel.permState = permStateList[i];
        out.WriteParcelable(&permStateParcel);
    }

    out.WriteParcelable(&baseInfoParcel);
    permStateList.emplace_back(g_permStatBeta);

    permStateListSize = permStateList.size();
    out.WriteUint32(permStateListSize);
    for (uint32_t i = 0; i < permStateListSize; i++) {
        PermissionStatusParcel permStateParcel;
        permStateParcel.permState = permStateList[i];
        out.WriteParcelable(&permStateParcel);
    }
}

/**
 * @tc.name: HapTokenInfoForSyncParcel002
 * @tc.desc: Test HapTokenInfoForSync Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, HapTokenInfoForSyncParcel002, TestSize.Level1)
{
    HapTokenInfoForSyncParcel hapTokenInfoSync;

    HapTokenInfo hapTokenInfo;
    hapTokenInfo.ver = 0;
    hapTokenInfo.userID = 2;
    hapTokenInfo.bundleName = "bundle2";
    hapTokenInfo.apiVersion = 8;
    hapTokenInfo.instIndex = 0;
    hapTokenInfo.dlpType = 0;
    hapTokenInfo.tokenID = 0x53100000;
    hapTokenInfo.tokenAttr = 0;

    Parcel out;
    HapTokenInfoParcel baseInfoParcel;
    baseInfoParcel.hapTokenInfoParams = hapTokenInfo;
    WriteParcelable(out, baseInfoParcel, MAX_PERMLIST_SIZE);

    std::shared_ptr<HapTokenInfoForSyncParcel> readedData(HapTokenInfoForSyncParcel::Unmarshalling(out));
    EXPECT_NE(nullptr, readedData);

    Parcel out1;
    WriteParcelable(out1, baseInfoParcel, MAX_PERMLIST_SIZE + 1);
    std::shared_ptr<HapTokenInfoForSyncParcel> readedData1(HapTokenInfoForSyncParcel::Unmarshalling(out1));
    EXPECT_EQ(true, readedData1 == nullptr);
}

/**
 * @tc.name: PermissionStateFullParcel002
 * @tc.desc: Test permissionStateParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, PermissionStateFullParcel002, TestSize.Level1)
{
    PermissionStatusParcel permissionStateParcel;
    permissionStateParcel.permState.permissionName = "permissionName";
    permissionStateParcel.permState.grantStatus = 1;
    permissionStateParcel.permState.grantFlag = 0;
    permissionStateParcel.permState.timestamp = 123456789;
    Parcel parcel;
    EXPECT_EQ(true, permissionStateParcel.Marshalling(parcel));

    std::shared_ptr<PermissionStatusParcel> readedData(PermissionStatusParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
    EXPECT_EQ(permissionStateParcel.permState.permissionName, readedData->permState.permissionName);
    EXPECT_EQ(permissionStateParcel.permState.grantStatus, readedData->permState.grantStatus);
    EXPECT_EQ(permissionStateParcel.permState.grantFlag, readedData->permState.grantFlag);
    EXPECT_EQ(permissionStateParcel.permState.timestamp, readedData->permState.timestamp);
}

/**
 * @tc.name: PermissionGrantInfoParcel001
 * @tc.desc: Test PermissionGrantInfo Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, PermissionGrantInfoParcel001, TestSize.Level1)
{
    PermissionGrantInfoParcel permissionGrantInfoParcel;
    permissionGrantInfoParcel.info.grantBundleName = "com.ohos.permissionmanager";
    permissionGrantInfoParcel.info.grantAbilityName = "com.ohos.permissionmanager.GrantAbility";

    Parcel parcel;
    EXPECT_EQ(true, permissionGrantInfoParcel.Marshalling(parcel));
    std::shared_ptr<PermissionGrantInfoParcel> readedData(PermissionGrantInfoParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
}

/**
 * @tc.name: AtmToolsParamInfoParcel001
 * @tc.desc: Test AtmToolsParamInfo Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, AtmToolsParamInfoParcel001, TestSize.Level1)
{
    AtmToolsParamInfoParcel atmToolsParamInfoParcel;
    atmToolsParamInfoParcel.info.tokenId = INVALID_TOKENID;
    atmToolsParamInfoParcel.info.permissionName = "ohos.permission.CAMERA";
    atmToolsParamInfoParcel.info.bundleName = "com.ohos.parceltest";
    atmToolsParamInfoParcel.info.permissionName = "test_service";

    Parcel parcel;
    EXPECT_EQ(true, atmToolsParamInfoParcel.Marshalling(parcel));
    std::shared_ptr<AtmToolsParamInfoParcel> readedData(AtmToolsParamInfoParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
}

/**
 * @tc.name: PermissionDialogResultParcel001
 * @tc.desc: Test PermissionDialogResultParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, PermissionDialogResultParcel001, TestSize.Level1)
{
    PermissionDialogResultParcel resultParcel;
    PermissionDialogDetail detail;
    detail.needPermissionDialog = false;
    detail.permissionNameList = {"ohos.permission.CAMERA", "ohos.permission.LOCATION"};
    detail.statusList = {
        PermissionDecisionStatus::NO_DIALOG_DENIED,
        PermissionDecisionStatus::NO_DIALOG_RESTRICTED
    };
    detail.authResult = "authResult";
    resultParcel.result.detailList = {detail};

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<PermissionDialogResultParcel> readedData(
        PermissionDialogResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    ASSERT_EQ(1, static_cast<int32_t>(readedData->result.detailList.size()));
    EXPECT_FALSE(readedData->result.detailList[0].needPermissionDialog);
    EXPECT_EQ(detail.permissionNameList, readedData->result.detailList[0].permissionNameList);
    EXPECT_EQ(detail.statusList, readedData->result.detailList[0].statusList);
    EXPECT_EQ(detail.authResult, readedData->result.detailList[0].authResult);
}

/**
 * @tc.name: PermissionDialogResultParcel002
 * @tc.desc: Test PermissionDialogResultParcel Unmarshalling with malformed parcel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, PermissionDialogResultParcel002, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(1));
    EXPECT_TRUE(parcel.WriteBool(false));

    std::shared_ptr<PermissionDialogResultParcel> readedData(
        PermissionDialogResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

HWTEST_F(AccessTokenParcelTest, PermissionDialogResultParcel003, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(MAX_COMMAND_LIST_SIZE + 1));

    std::shared_ptr<PermissionDialogResultParcel> readedData(
        PermissionDialogResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

HWTEST_F(AccessTokenParcelTest, PermissionDialogResultParcel004, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(1));
    EXPECT_TRUE(parcel.WriteBool(false));
    std::vector<std::string> permissionNames;
    EXPECT_TRUE(parcel.WriteStringVector(permissionNames));
    EXPECT_TRUE(parcel.WriteUint32(MAX_PERMLIST_SIZE + 1));

    std::shared_ptr<PermissionDialogResultParcel> readedData(
        PermissionDialogResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

HWTEST_F(AccessTokenParcelTest, PermissionDialogResultParcel005, TestSize.Level1)
{
    PermissionDialogResultParcel resultParcel;
    PermissionDialogDetail detail;
    detail.needPermissionDialog = false;
    detail.authResult = "authResult";
    resultParcel.result.detailList.assign(MAX_COMMAND_LIST_SIZE, detail);

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<PermissionDialogResultParcel> readedData(
        PermissionDialogResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    EXPECT_EQ(MAX_COMMAND_LIST_SIZE, static_cast<int32_t>(readedData->result.detailList.size()));
}

HWTEST_F(AccessTokenParcelTest, PermissionDialogResultParcel006, TestSize.Level1)
{
    PermissionDialogResultParcel resultParcel;
    PermissionDialogDetail detail;
    detail.needPermissionDialog = false;
    detail.permissionNameList.assign(MAX_PERMLIST_SIZE, "ohos.permission.CAMERA");
    detail.statusList.assign(MAX_PERMLIST_SIZE, PermissionDecisionStatus::NO_DIALOG_GRANTED);
    detail.authResult = "authResult";
    resultParcel.result.detailList = {detail};

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<PermissionDialogResultParcel> readedData(
        PermissionDialogResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    EXPECT_EQ(MAX_PERMLIST_SIZE, static_cast<int32_t>(readedData->result.detailList[0].statusList.size()));
}

/**
 * @tc.name: CliPermissionsResultParcel001
 * @tc.desc: Test CliPermissionsResultParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, CliPermissionsResultParcel001, TestSize.Level1)
{
    CliPermissionsResultParcel resultParcel;
    CliPermissionDetail detail;
    detail.requiredCliPermission = "ohos.permission.POWER_MANAGER";
    detail.cliPermissionStatus = PermissionDecisionStatus::NO_DIALOG_GRANTED;
    detail.usedPermissions = {"ohos.permission.POWER_MANAGER"};
    CliCommandPermissionResult commandResult;
    commandResult.requiredCliPermissions = {detail};
    resultParcel.result.permList = {commandResult};

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<CliPermissionsResultParcel> readedData(CliPermissionsResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    ASSERT_EQ(1, static_cast<int32_t>(readedData->result.permList.size()));
    ASSERT_EQ(1, static_cast<int32_t>(readedData->result.permList[0].requiredCliPermissions.size()));
    const auto& readDetail = readedData->result.permList[0].requiredCliPermissions[0];
    EXPECT_EQ(detail.requiredCliPermission, readDetail.requiredCliPermission);
    EXPECT_EQ(detail.cliPermissionStatus, readDetail.cliPermissionStatus);
    EXPECT_EQ(detail.usedPermissions, readDetail.usedPermissions);
}

/**
 * @tc.name: CliPermissionsResultParcel002
 * @tc.desc: Test CliPermissionsResultParcel Unmarshalling with malformed parcel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, CliPermissionsResultParcel002, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(1));
    EXPECT_TRUE(parcel.WriteUint32(1));
    EXPECT_TRUE(parcel.WriteString("ohos.permission.POWER_MANAGER"));

    std::shared_ptr<CliPermissionsResultParcel> readedData(
        CliPermissionsResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

HWTEST_F(AccessTokenParcelTest, CliPermissionsResultParcel003, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(MAX_COMMAND_LIST_SIZE + 1));

    std::shared_ptr<CliPermissionsResultParcel> readedData(
        CliPermissionsResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

HWTEST_F(AccessTokenParcelTest, CliPermissionsResultParcel004, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(1));
    EXPECT_TRUE(parcel.WriteUint32(MAX_PERMLIST_SIZE + 1));

    std::shared_ptr<CliPermissionsResultParcel> readedData(
        CliPermissionsResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

HWTEST_F(AccessTokenParcelTest, CliPermissionsResultParcel005, TestSize.Level1)
{
    CliPermissionsResultParcel resultParcel;
    CliCommandPermissionResult commandResult;
    resultParcel.result.permList.assign(MAX_COMMAND_LIST_SIZE, commandResult);

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<CliPermissionsResultParcel> readedData(
        CliPermissionsResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    EXPECT_EQ(MAX_COMMAND_LIST_SIZE, static_cast<int32_t>(readedData->result.permList.size()));
}

HWTEST_F(AccessTokenParcelTest, CliPermissionsResultParcel006, TestSize.Level1)
{
    CliPermissionsResultParcel resultParcel;
    CliPermissionDetail detail;
    detail.requiredCliPermission = "ohos.permission.POWER_MANAGER";
    detail.cliPermissionStatus = PermissionDecisionStatus::NO_DIALOG_GRANTED;
    CliCommandPermissionResult commandResult;
    commandResult.requiredCliPermissions.assign(MAX_PERMLIST_SIZE, detail);
    resultParcel.result.permList = {commandResult};

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<CliPermissionsResultParcel> readedData(
        CliPermissionsResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    EXPECT_EQ(MAX_PERMLIST_SIZE,
        static_cast<int32_t>(readedData->result.permList[0].requiredCliPermissions.size()));
}

/**
 * @tc.name: SkillPermissionsResultParcel001
 * @tc.desc: Test SkillPermissionsResultParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, SkillPermissionsResultParcel001, TestSize.Level1)
{
    SkillPermissionsResultParcel resultParcel;
    SkillCommandPermissionResult commandResult;
    commandResult.usedPermissions = {"ohos.permission.CAMERA", "ohos.permission.LOCATION"};
    commandResult.statusList = {
        PermissionDecisionStatus::NEED_PERMISSION_DIALOG,
        PermissionDecisionStatus::NO_DIALOG_NOT_DECLARED
    };
    resultParcel.result.permList = {commandResult};

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<SkillPermissionsResultParcel> readedData(
        SkillPermissionsResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    ASSERT_EQ(1, static_cast<int32_t>(readedData->result.permList.size()));
    EXPECT_EQ(commandResult.usedPermissions, readedData->result.permList[0].usedPermissions);
    EXPECT_EQ(commandResult.statusList, readedData->result.permList[0].statusList);
}

HWTEST_F(AccessTokenParcelTest, SkillPermissionsResultParcel002, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(1));
    std::vector<std::string> usedPermissions = {"ohos.permission.CAMERA"};
    EXPECT_TRUE(parcel.WriteStringVector(usedPermissions));

    std::shared_ptr<SkillPermissionsResultParcel> readedData(
        SkillPermissionsResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

HWTEST_F(AccessTokenParcelTest, SkillPermissionsResultParcel003, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(MAX_COMMAND_LIST_SIZE + 1));

    std::shared_ptr<SkillPermissionsResultParcel> readedData(
        SkillPermissionsResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

HWTEST_F(AccessTokenParcelTest, SkillPermissionsResultParcel004, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(1));
    std::vector<std::string> usedPermissions;
    EXPECT_TRUE(parcel.WriteStringVector(usedPermissions));
    EXPECT_TRUE(parcel.WriteUint32(MAX_PERMLIST_SIZE + 1));

    std::shared_ptr<SkillPermissionsResultParcel> readedData(
        SkillPermissionsResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

HWTEST_F(AccessTokenParcelTest, SkillPermissionsResultParcel005, TestSize.Level1)
{
    SkillPermissionsResultParcel resultParcel;
    SkillCommandPermissionResult commandResult;
    resultParcel.result.permList.assign(MAX_COMMAND_LIST_SIZE, commandResult);

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<SkillPermissionsResultParcel> readedData(
        SkillPermissionsResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    EXPECT_EQ(MAX_COMMAND_LIST_SIZE, static_cast<int32_t>(readedData->result.permList.size()));
}

HWTEST_F(AccessTokenParcelTest, SkillPermissionsResultParcel006, TestSize.Level1)
{
    SkillPermissionsResultParcel resultParcel;
    SkillCommandPermissionResult commandResult;
    commandResult.statusList.assign(MAX_PERMLIST_SIZE, PermissionDecisionStatus::NO_DIALOG_GRANTED);
    resultParcel.result.permList = {commandResult};

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<SkillPermissionsResultParcel> readedData(
        SkillPermissionsResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    EXPECT_EQ(MAX_PERMLIST_SIZE, static_cast<int32_t>(readedData->result.permList[0].statusList.size()));
}

/**
 * @tc.name: ClawAuthInfoParcel001
 * @tc.desc: Test CliAuthInfoParcel and SkillAuthInfoParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, ClawAuthInfoParcel001, TestSize.Level1)
{
    CliAuthInfoParcel cliAuthInfoParcel;
    cliAuthInfoParcel.info.cliInfo = {
        .cliName = "camera",
        .subCliName = "capture"
    };
    cliAuthInfoParcel.info.permissionNames = {"ohos.permission.POWER_MANAGER"};
    cliAuthInfoParcel.info.authorizationResults = {true};
    Parcel cliParcel;
    EXPECT_TRUE(cliAuthInfoParcel.Marshalling(cliParcel));
    std::shared_ptr<CliAuthInfoParcel> readCliData(CliAuthInfoParcel::Unmarshalling(cliParcel));
    ASSERT_NE(nullptr, readCliData);
    EXPECT_EQ(cliAuthInfoParcel.info.cliInfo.cliName, readCliData->info.cliInfo.cliName);
    EXPECT_EQ(cliAuthInfoParcel.info.cliInfo.subCliName, readCliData->info.cliInfo.subCliName);
    EXPECT_EQ(cliAuthInfoParcel.info.permissionNames, readCliData->info.permissionNames);
    EXPECT_EQ(cliAuthInfoParcel.info.authorizationResults, readCliData->info.authorizationResults);

    SkillAuthInfoParcel skillAuthInfoParcel;
    skillAuthInfoParcel.info.skillInfo = {
        .skillName = "cameraSkill",
        .bundleName = "com.ohos.claw.demo",
        .moduleName = "entry"
    };
    skillAuthInfoParcel.info.permissionNames = {"ohos.permission.CAMERA"};
    skillAuthInfoParcel.info.authorizationResults = {false};
    Parcel skillParcel;
    EXPECT_TRUE(skillAuthInfoParcel.Marshalling(skillParcel));
    std::shared_ptr<SkillAuthInfoParcel> readSkillData(SkillAuthInfoParcel::Unmarshalling(skillParcel));
    ASSERT_NE(nullptr, readSkillData);
    EXPECT_EQ(skillAuthInfoParcel.info.skillInfo.skillName, readSkillData->info.skillInfo.skillName);
    EXPECT_EQ(skillAuthInfoParcel.info.skillInfo.bundleName, readSkillData->info.skillInfo.bundleName);
    EXPECT_EQ(skillAuthInfoParcel.info.skillInfo.moduleName, readSkillData->info.skillInfo.moduleName);
    EXPECT_EQ(skillAuthInfoParcel.info.permissionNames, readSkillData->info.permissionNames);
    EXPECT_EQ(skillAuthInfoParcel.info.authorizationResults, readSkillData->info.authorizationResults);
}

/**
 * @tc.name: ClawAuthInfoParcel002
 * @tc.desc: Test CliAuthInfoParcel Unmarshalling with malformed parcel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, ClawAuthInfoParcel002, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteString("camera"));

    std::shared_ptr<CliAuthInfoParcel> readedData(CliAuthInfoParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

/**
 * @tc.name: CliInitInfoParcel001
 * @tc.desc: Test CliInitInfoParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, CliInitInfoParcel001, TestSize.Level1)
{
    CliInitInfoParcel initInfoParcel;
    initInfoParcel.cliInitInfo.hostTokenId = TEST_TOKEN_ID;
    initInfoParcel.cliInitInfo.challenge = "challenge";
    initInfoParcel.cliInitInfo.cliInfo = {
        .cliName = "camera",
        .subCliName = "capture"
    };

    Parcel parcel;
    EXPECT_TRUE(initInfoParcel.Marshalling(parcel));
    std::shared_ptr<CliInitInfoParcel> readedData(CliInitInfoParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    EXPECT_EQ(initInfoParcel.cliInitInfo.hostTokenId, readedData->cliInitInfo.hostTokenId);
    EXPECT_EQ(initInfoParcel.cliInitInfo.challenge, readedData->cliInitInfo.challenge);
    EXPECT_EQ(initInfoParcel.cliInitInfo.cliInfo.cliName, readedData->cliInitInfo.cliInfo.cliName);
    EXPECT_EQ(initInfoParcel.cliInitInfo.cliInfo.subCliName, readedData->cliInitInfo.cliInfo.subCliName);
}

/**
 * @tc.name: CliInitInfoParcel002
 * @tc.desc: Test CliInitInfoParcel Unmarshalling with malformed parcel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, CliInitInfoParcel002, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(TEST_TOKEN_ID));
    EXPECT_TRUE(parcel.WriteString("challenge"));
    EXPECT_TRUE(parcel.WriteString("camera"));

    std::shared_ptr<CliInitInfoParcel> readedData(CliInitInfoParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

/**
 * @tc.name: CliInfoResultParcel001
 * @tc.desc: Test CliInfoResultParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, CliInfoResultParcel001, TestSize.Level1)
{
    CliInfoResultParcel infoParcel;
    infoParcel.cliTokenInfo.hostTokenId = TEST_TOKEN_ID;
    infoParcel.cliTokenInfo.userId = 100;
    infoParcel.cliTokenInfo.cliName = "camera";
    infoParcel.cliTokenInfo.subCliName = "capture";

    Parcel parcel;
    EXPECT_TRUE(infoParcel.Marshalling(parcel));
    std::shared_ptr<CliInfoResultParcel> readedData(CliInfoResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    EXPECT_EQ(infoParcel.cliTokenInfo.hostTokenId, readedData->cliTokenInfo.hostTokenId);
    EXPECT_EQ(infoParcel.cliTokenInfo.userId, readedData->cliTokenInfo.userId);
    EXPECT_EQ(infoParcel.cliTokenInfo.cliName, readedData->cliTokenInfo.cliName);
    EXPECT_EQ(infoParcel.cliTokenInfo.subCliName, readedData->cliTokenInfo.subCliName);
}

/**
 * @tc.name: CliInfoResultParcel002
 * @tc.desc: Test CliInfoResultParcel Unmarshalling with malformed parcel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, CliInfoResultParcel002, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(TEST_TOKEN_ID));
    EXPECT_TRUE(parcel.WriteInt32(100));
    EXPECT_TRUE(parcel.WriteString("camera"));

    std::shared_ptr<CliInfoResultParcel> readedData(CliInfoResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}

/**
 * @tc.name: ToolAuthResultParcel001
 * @tc.desc: Test ToolAuthResultParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, ToolAuthResultParcel001, TestSize.Level1)
{
    ToolAuthResultParcel resultParcel;
    resultParcel.result.authResults = {"authResult0", "authResult1"};

    Parcel parcel;
    EXPECT_TRUE(resultParcel.Marshalling(parcel));
    std::shared_ptr<ToolAuthResultParcel> readedData(ToolAuthResultParcel::Unmarshalling(parcel));
    ASSERT_NE(nullptr, readedData);
    EXPECT_EQ(resultParcel.result.authResults, readedData->result.authResults);
}

/**
 * @tc.name: ToolAuthResultParcel002
 * @tc.desc: Test ToolAuthResultParcel Unmarshalling with malformed parcel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenParcelTest, ToolAuthResultParcel002, TestSize.Level1)
{
    Parcel parcel;
    EXPECT_TRUE(parcel.WriteUint32(1));

    std::shared_ptr<ToolAuthResultParcel> readedData(ToolAuthResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(nullptr, readedData);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
