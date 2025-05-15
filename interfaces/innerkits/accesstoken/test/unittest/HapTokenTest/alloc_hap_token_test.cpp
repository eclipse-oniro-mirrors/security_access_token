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

#include "alloc_hap_token_test.h"
#include "gtest/gtest.h"
#include <thread>

#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_common_log.h"
#include "nativetoken_kit.h"
#include "permission_grant_info.h"
#include "permission_state_change_info_parcel.h"
#include "string_ex.h"
#include "test_common.h"
#include "tokenid_kit.h"
#include "token_setproc.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t DEFAULT_API_VERSION = 8;
static uint64_t g_selfTokenId = 0;
static const int32_t INDEX_ZERO = 0;
static const int32_t INDEX_ONE = 1;
static const int INVALID_BUNDLENAME_LEN = 260;
static const int INVALID_APPIDDESC_LEN = 10244;
static const int INVALID_LABEL_LEN = 260;
static const int INVALID_DESCRIPTION_LEN = 260;
static const int INVALID_PERMNAME_LEN = 260;
static const int CYCLE_TIMES = 100;
static const int INVALID_DLP_TYPE = 4;
static MockNativeToken* g_mock;

HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "test3",
    .apiVersion = DEFAULT_API_VERSION,
    .appDistributionType = "enterprise_mdm"
};

PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "ohos.permission.test1",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label3",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1,
    .availableType = MDM
};

PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "ohos.permission.test2",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label3",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1,
};

PermissionStateFull g_infoManagerTestState1 = {
    .permissionName = "ohos.permission.test1",
    .isGeneral = true,
    .resDeviceID = {"local3"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.test2",
    .isGeneral = false,
    .resDeviceID = {"device 1", "device 2"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED, PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1, 2}
};

HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain3",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};
};

void AllocHapTokenTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    TestCommon::SetTestEvironment(g_selfTokenId);

    g_mock = new (std::nothrow) MockNativeToken("foundation");

    // make test case clean
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
}

void AllocHapTokenTest::TearDownTestCase()
{
    if (g_mock != nullptr) {
        delete g_mock;
        g_mock = nullptr;
    }
    EXPECT_EQ(0, SetSelfTokenID(g_selfTokenId));
    TestCommon::ResetTestEvironment();
}

AccessTokenID AllocHapTokenTest::AllocTestToken(
    const HapInfoParams& hapInfo, const HapPolicyParams& hapPolicy) const
{
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfo, hapPolicy);
    return tokenIdEx.tokenIdExStruct.tokenID;
}

unsigned int AllocHapTokenTest::GetAccessTokenID(int userID, const std::string& bundleName, int instIndex)
{
    return AccessTokenKit::GetHapTokenID(userID, bundleName, instIndex);
}

void AllocHapTokenTest::DeleteTestToken() const
{
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    int ret = AccessTokenKit::DeleteToken(tokenID);
    if (tokenID != 0) {
        ASSERT_EQ(RET_SUCCESS, ret);
    }
}

void AllocHapTokenTest::GetDlpFlagTest(const HapInfoParams& info, const HapPolicyParams& policy, int flag)
{
    int32_t ret;
    HapTokenInfo hapTokenInfoRes;
    uint32_t tokenID = GetAccessTokenID(info.userID, info.bundleName, 2);
    if (tokenID != 0) {
        ret = AccessTokenKit::DeleteToken(tokenID);
    }
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(info, policy);
    EXPECT_NE(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    EXPECT_EQ(ret, RET_SUCCESS);
    EXPECT_EQ(hapTokenInfoRes.dlpType, flag);
    if (flag == DLP_COMMON) {
        EXPECT_EQ(AccessTokenKit::GetHapDlpFlag(tokenIdEx.tokenIdExStruct.tokenID), 0);
    } else {
        EXPECT_EQ(AccessTokenKit::GetHapDlpFlag(tokenIdEx.tokenIdExStruct.tokenID), 1);
    }
    ret = AccessTokenKit::DeleteToken(tokenIdEx.tokenIdExStruct.tokenID);
    EXPECT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "tokenID :" << tokenIdEx.tokenIdExStruct.tokenID;
    ret = AccessTokenKit::GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapTokenInfoRes);
    EXPECT_EQ(ret, AccessTokenError::ERR_TOKENID_NOT_EXIST);
}

void AllocHapTokenTest::SetUp()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "SetUp ok.");
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
}

void AllocHapTokenTest::TearDown()
{
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: alloc a tokenId successfully, delete it successfully the first time and fail to delete it again.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken001, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
    ASSERT_NE(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
}

/**
 * @tc.name: AllocHapToken002
 * @tc.desc: alloc a tokenId with the same info and policy repeatly,
 *           tokenId will change.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken002, TestSize.Level0)
{
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    GTEST_LOG_(INFO) << "tokenID :" << tokenID;
    ASSERT_NE(INVALID_TOKENID, tokenID);

    AccessTokenID tokenID1 = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenID1);
    ASSERT_NE(tokenID, tokenID1);
    ASSERT_NE(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID));
    ASSERT_EQ(RET_SUCCESS, AccessTokenKit::DeleteToken(tokenID1));
}

/**
 * @tc.name: AllocHapToken003
 * @tc.desc: cannot alloc a tokenId with invalid bundlename.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken003, TestSize.Level0)
{
    std::string invalidBundleName (INVALID_BUNDLENAME_LEN, 'x');
    std::string bundle = g_infoManagerTestInfoParms.bundleName;

    DeleteTestToken();
    GTEST_LOG_(INFO) << "get hap token info:" << invalidBundleName.length();

    g_infoManagerTestInfoParms.bundleName = invalidBundleName;
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(INVALID_TOKENID, tokenID);

    tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                               g_infoManagerTestInfoParms.bundleName,
                               g_infoManagerTestInfoParms.instIndex);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::DeleteToken(tokenID));

    g_infoManagerTestInfoParms.bundleName = bundle;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken004
 * @tc.desc: cannot alloc a tokenId with invalid apl.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken004, TestSize.Level0)
{
    ATokenAplEnum typeBackUp = g_infoManagerTestPolicyPrams.apl;
    DeleteTestToken();

    g_infoManagerTestPolicyPrams.apl = (ATokenAplEnum)5;
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(INVALID_TOKENID, tokenID);

    tokenID = GetAccessTokenID(g_infoManagerTestInfoParms.userID,
                               g_infoManagerTestInfoParms.bundleName,
                               g_infoManagerTestInfoParms.instIndex);
    ASSERT_EQ(INVALID_TOKENID, tokenID);

    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::DeleteToken(tokenID));
    g_infoManagerTestPolicyPrams.apl = typeBackUp;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken005
 * @tc.desc: can alloc a tokenId when bundlename in permdef is different with bundlename in info.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken005, TestSize.Level0)
{
    std::string backUpPermission = g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName;
    std::string bundleNameBackUp = g_infoManagerTestPolicyPrams.permList[INDEX_ONE].bundleName;
    ATokenAvailableTypeEnum typeBakup = g_infoManagerTestPolicyPrams.permList[INDEX_ONE].availableType;
    DeleteTestToken();

    g_infoManagerTestPolicyPrams.permList[INDEX_ONE].bundleName = "invalid_bundleName";
    g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName = "ohos.permission.testtmp01";
    g_infoManagerTestPolicyPrams.permList[INDEX_ONE].availableType = MDM;
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionDef permDefResult;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName, permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    ASSERT_NE(permDefResult.availableType, MDM);
    ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName, permDefResult);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    g_infoManagerTestPolicyPrams.permList[INDEX_ONE].bundleName  = bundleNameBackUp;
    g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName = backUpPermission;
    g_infoManagerTestPolicyPrams.permList[INDEX_ONE].availableType = typeBakup;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken006
 * @tc.desc: can alloc a tokenId with a invalid permList permissionName.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken006, TestSize.Level0)
{
    std::string backUp = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName;
    DeleteTestToken();

    const std::string invalidPermissionName (INVALID_PERMNAME_LEN, 'x');
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = invalidPermissionName;
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(invalidPermissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName  = backUp;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken007
 * @tc.desc: can alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken007, TestSize.Level0)
{
    std::string backUp = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].bundleName;
    std::string backUpPermission = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName;
    DeleteTestToken();

    const std::string invalidBundleName (INVALID_BUNDLENAME_LEN, 'x');

    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = "ohos.permission.testtmp02";
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].bundleName = invalidBundleName;
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].bundleName  = backUp;
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = backUpPermission;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken008
 * @tc.desc: can alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken008, TestSize.Level0)
{
    std::string backUp = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].label;
    std::string backUpPermission = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName;
    DeleteTestToken();

    const std::string invalidLabel (INVALID_LABEL_LEN, 'x');
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = "ohos.permission.testtmp03";
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].label = invalidLabel;
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].label  = backUp;
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = backUpPermission;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken009
 * @tc.desc: can alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken009, TestSize.Level0)
{
    std::string backUp = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].description;
    std::string backUpPermission = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName;
    DeleteTestToken();

    const std::string invalidDescription (INVALID_DESCRIPTION_LEN, 'x');

    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = "ohos.permission.testtmp04";
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].description = invalidDescription;
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_NE(INVALID_TOKENID, tokenID);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);

    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].description  = backUp;
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = backUpPermission;

    DeleteTestToken();
}

static bool ExistInVector(vector<unsigned int> array, unsigned int value)
{
    vector<unsigned int>::iterator it = find(array.begin(), array.end(), value);
    if (it != array.end()) {
        return true;
    } else {
        return false;
    }
}

/**
 * @tc.name: AllocHapToken010
 * @tc.desc: alloc and delete in a loop.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken010, TestSize.Level0)
{
    int ret;
    bool exist = false;
    int allocFlag = 0;
    int deleteFlag = 0;

    DeleteTestToken();
    vector<unsigned int> obj;
    for (int i = 0; i < CYCLE_TIMES; i++) {
        AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

        exist = ExistInVector(obj, tokenID);
        if (exist) {
            allocFlag = 1;
        }
        obj.push_back(tokenID);

        ret = AccessTokenKit::DeleteToken(tokenID);
        if (RET_SUCCESS != ret) {
            deleteFlag = 1;
        }
    }
    ASSERT_EQ(allocFlag, 0);
    ASSERT_EQ(deleteFlag, 0);
}

/**
 * @tc.name: AllocHapToken011
 * @tc.desc: cannot alloc a tokenId with invalid appIDDesc.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken011, TestSize.Level0)
{
    std::string invalidAppIDDesc (INVALID_APPIDDESC_LEN, 'x');
    std::string backup = g_infoManagerTestInfoParms.appIDDesc;

    DeleteTestToken();

    g_infoManagerTestInfoParms.appIDDesc = invalidAppIDDesc;
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
    g_infoManagerTestInfoParms.appIDDesc = backup;
}

/**
 * @tc.name: AllocHapToken012
 * @tc.desc: cannot alloc a tokenId with invalid bundleName.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken012, TestSize.Level0)
{
    std::string backup = g_infoManagerTestInfoParms.bundleName;

    g_infoManagerTestInfoParms.bundleName = "";
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
    g_infoManagerTestInfoParms.bundleName = backup;
}

/**
 * @tc.name: AllocHapToken013
 * @tc.desc: cannot alloc a tokenId with invalid appIDDesc.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken013, TestSize.Level0)
{
    std::string backup = g_infoManagerTestInfoParms.appIDDesc;

    g_infoManagerTestInfoParms.appIDDesc = "";
    AccessTokenID tokenID = AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    ASSERT_EQ(INVALID_TOKENID, tokenID);
    g_infoManagerTestInfoParms.appIDDesc = backup;
}

/**
 * @tc.name: AllocHapToken014
 * @tc.desc: can alloc a tokenId with permList permissionName as "".
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken014, TestSize.Level0)
{
    std::string backup = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName;

    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = "";
    AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    PermissionDef permDefResultBeta;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, AccessTokenKit::GetDefPermission("", permDefResultBeta));
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = backup;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken015
 * @tc.desc: can alloc a tokenId with permList bundleName as "".
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken015, TestSize.Level0)
{
    std::string backup = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].bundleName;
    std::string backUpPermission = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName;

    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].bundleName = "";
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = "ohos.permission.testtmp05";
    AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    PermissionDef permDefResultBeta;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ONE].permissionName, permDefResultBeta);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIST, ret);
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].bundleName = backup;
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = backUpPermission;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken016
 * @tc.desc: can alloc a tokenId with label as "".
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken016, TestSize.Level0)
{
    std::string backup = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].label;
    std::string backUpPermission = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName;

    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].label = "";
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = "ohos.permission.testtmp06";
    AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    PermissionDef permDefResult;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName, permDefResult);
    ASSERT_EQ(ret, AccessTokenError::ERR_PERMISSION_NOT_EXIST);
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].label = backup;
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = backUpPermission;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken017
 * @tc.desc: cannot alloc a tokenId with invalid permdef.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken017, TestSize.Level0)
{
    std::string backUpPermission = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName;
    std::string backupDec = g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].description;

    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].description = "";
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = "ohos.permission.testtmp07";
    AllocTestToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);

    PermissionDef permDefResult;
    int ret = AccessTokenKit::GetDefPermission(
        g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName, permDefResult);
    ASSERT_EQ(ret, AccessTokenError::ERR_PERMISSION_NOT_EXIST);
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].description = backupDec;
    g_infoManagerTestPolicyPrams.permList[INDEX_ZERO].permissionName = backUpPermission;

    DeleteTestToken();
}

/**
 * @tc.name: AllocHapToken018
 * @tc.desc: alloc a tokenId with vaild dlptype.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken018, TestSize.Level0)
{
    HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {}
    };
    const HapInfoParams infoManagerTestInfoParms1 = {
        .userID = 1,
        .bundleName = "dlp_test1",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "test3",
        .apiVersion = DEFAULT_API_VERSION
    };
    const HapInfoParams infoManagerTestInfoParms2 = {
        .userID = 1,
        .bundleName = "dlp_test2",
        .instIndex = 1,
        .dlpType = DLP_READ,
        .appIDDesc = "test3",
        .apiVersion = DEFAULT_API_VERSION
    };
    const HapInfoParams infoManagerTestInfoParms3 = {
        .userID = 1,
        .bundleName = "dlp_test3",
        .instIndex = 2,
        .dlpType = DLP_FULL_CONTROL,
        .appIDDesc = "test3",
        .apiVersion = DEFAULT_API_VERSION
    };
    GetDlpFlagTest(infoManagerTestInfoParms1, infoManagerTestPolicyPrams, DLP_COMMON);
    GetDlpFlagTest(infoManagerTestInfoParms2, infoManagerTestPolicyPrams, DLP_READ);
    GetDlpFlagTest(infoManagerTestInfoParms3, infoManagerTestPolicyPrams, DLP_FULL_CONTROL);
}

/**
 * @tc.name: AllocHapToken019
 * @tc.desc: cannot alloc a tokenId with invalid dlpType.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AllocHapTokenTest, AllocHapToken019, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {}
    };
    HapInfoParams infoManagerTestInfoParms1 = {
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 4,
        .dlpType = INVALID_DLP_TYPE,
        .appIDDesc = "test3",
        .apiVersion = DEFAULT_API_VERSION
    };

    tokenIdEx = AccessTokenKit::AllocHapToken(infoManagerTestInfoParms1, infoManagerTestPolicyPrams);
    ASSERT_EQ(INVALID_TOKENID, tokenIdEx.tokenIdExStruct.tokenID);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS