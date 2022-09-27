/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_info_manager_test.h"

#include <memory>
#include <string>
#include "accesstoken_info_manager.h"
#include "accesstoken_log.h"
#include "access_token_error.h"
#ifdef SUPPORT_SANDBOX_APP
#define private public
#include "dlp_permission_set_manager.h"
#include "dlp_permission_set_parser.h"
#undef private
#endif
#define private public
#include "permission_manager.h"
#undef private
#include "permission_state_change_callback_stub.h"
#include "string_ex.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenInfoManagerTest"
};
static constexpr uint32_t MAX_CALLBACK_SIZE = 1024;
static constexpr int32_t DEFAULT_API_VERSION = 8;
static PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "open the door",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};

static PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "break the door",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};

static PermissionStateFull g_infoManagerTestState1 = {
    .grantFlags = {1},
    .grantStatus = {1},
    .isGeneral = true,
    .permissionName = "open the door",
    .resDeviceID = {"local"}
};

static PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "break the door",
    .isGeneral = false,
    .grantFlags = {1, 2},
    .grantStatus = {1, 3},
    .resDeviceID = {"device 1", "device 2"}
};

static HapInfoParams g_infoManagerTestInfoParms = {
    .bundleName = "accesstoken_test",
    .userID = 1,
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

static HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

static PermissionStateFull g_infoManagerTestStateA = {
    .grantFlags = {1},
    .grantStatus = {PERMISSION_GRANTED},
    .isGeneral = true,
    .resDeviceID = {"local"}
};
static PermissionStateFull g_infoManagerTestStateB = {
    .grantFlags = {1},
    .grantStatus = {PERMISSION_GRANTED},
    .isGeneral = true,
    .resDeviceID = {"local"}
};
static PermissionStateFull g_infoManagerTestStateC = {
    .grantFlags = {1},
    .grantStatus = {PERMISSION_GRANTED},
    .isGeneral = true,
    .resDeviceID = {"local"}
};
static PermissionStateFull g_infoManagerTestStateD = {
    .grantFlags = {1},
    .grantStatus = {PERMISSION_GRANTED},
    .isGeneral = true,
    .resDeviceID = {"local"}
};

static PermissionDef g_infoManagerPermDef1 = {
    .permissionName = "ohos.permission.MEDIA_LOCATION",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .label = "label",
    .labelId = 1,
    .description = "MEDIA_LOCATION",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};
static PermissionDef g_infoManagerPermDef2 = {
    .permissionName = "ohos.permission.MICROPHONE",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .label = "label",
    .labelId = 1,
    .description = "MICROPHONE",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};
static PermissionDef g_infoManagerPermDef3 = {
    .permissionName = "ohos.permission.READ_CALENDAR",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .label = "label",
    .labelId = 1,
    .description = "READ_CALENDAR",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};
static PermissionDef g_infoManagerPermDef4 = {
    .permissionName = "ohos.permission.READ_CALL_LOG",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .label = "label",
    .labelId = 1,
    .description = "READ_CALL_LOG",
    .descriptionId = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false
};
}

void AccessTokenInfoManagerTest::SetUpTestCase()
{}

void AccessTokenInfoManagerTest::TearDownTestCase()
{}

void AccessTokenInfoManagerTest::SetUp()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService_);
}

void AccessTokenInfoManagerTest::TearDown()
{
    atManagerService_ = nullptr;
}

HWTEST_F(AccessTokenInfoManagerTest, Init001, TestSize.Level1)
{
    AccessTokenInfoManager::GetInstance().Init();
    AccessTokenID getTokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);

    std::string dumpInfo;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(getTokenId, dumpInfo);

    // delete test token
    if (getTokenId != 0) {
        ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(getTokenId));
    }

    ASSERT_EQ(RET_SUCCESS, RET_SUCCESS);
}

/**
 * @tc.name: CreateHapTokenInfo001
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);
    std::string infoDes;
    tokenInfo->ToString(infoDes);
    GTEST_LOG_(INFO) << "get hap token info:" << infoDes.c_str();

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";

    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(nullptr, tokenInfo);
}

/**
 * @tc.name: IsTokenIdExist001
 * @tc.desc: Verify the IsTokenIdExist exist accesstokenid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, IsTokenIdExist001, TestSize.Level1)
{
    AccessTokenID testId = 1;
    ASSERT_EQ(AccessTokenInfoManager::GetInstance().IsTokenIdExist(testId), false);
}

/**
 * @tc.name: GetHapTokenInfo001
 * @tc.desc: Verify the GetHapTokenInfo abnormal and normal branch.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenInfo001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int result;
    HapTokenInfo hapInfo;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    ASSERT_EQ(result, RET_FAILED);

    result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "add a hap token";
    result = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    ASSERT_EQ(result, RET_SUCCESS);
    result = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GetHapTokenInfo001
 * @tc.desc: Verify the GetHapTokenInfo abnormal and normal branch.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapPermissionPolicySet001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(permPolicySet, nullptr);

    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";
    permPolicySet = AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(permPolicySet != nullptr, true);
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GetNativePermissionPolicySet001
 * @tc.desc: Verify the GetNativePermissionPolicySet abnormal branch tokenID is invalid.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, GetNativePermissionPolicySet001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetNativePermissionPolicySet(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(permPolicySet, nullptr);
}

/**
 * @tc.name: RemoveHapTokenInfo001
 * @tc.desc: Verify the RemoveHapTokenInfo abnormal branch tokenID type is not true.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveHapTokenInfo001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID), RET_FAILED);
}

/**
 * @tc.name: CreateHapTokenInfo002
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token twice function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AddHapToken001 fill data");

    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenIDEx tokenIdEx1 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams, tokenIdEx1);
    ASSERT_EQ(RET_FAILED, ret);
    ASSERT_EQ(0, tokenIdEx1.tokenIdExStruct.tokenID);
    GTEST_LOG_(INFO) << "add same hap token";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);

    std::string infoDes;
    tokenInfo->ToString(infoDes);
    GTEST_LOG_(INFO) << "get hap token info:" << infoDes.c_str();

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: Verify the GetHapTokenID by userID/bundleName/instIndex, function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenID001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID getTokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    ASSERT_EQ(tokenIdEx.tokenIdExStruct.tokenID, getTokenId);
    GTEST_LOG_(INFO) << "find hap info";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);
    GTEST_LOG_(INFO) << "remove the token info";

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: UpdateHapToken001
 * @tc.desc: Verify the UpdateHapToken token function.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    HapPolicyParams policy = g_infoManagerTestPolicyPrams;
    policy.apl = APL_SYSTEM_BASIC;
    ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(tokenIdEx.tokenIdExStruct.tokenID,
        std::string("updateAppId"), DEFAULT_API_VERSION, policy);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "update the hap token";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);
    std::string infoDes;
    tokenInfo->ToString(infoDes);
    GTEST_LOG_(INFO) << "get hap token info:" << infoDes.c_str();

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: UpdateHapToken002
 * @tc.desc: Verify the UpdateHapToken token function abnormal branch.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapPolicyParams policy = g_infoManagerTestPolicyPrams;
    policy.apl = APL_SYSTEM_BASIC;
    int ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx.tokenIdExStruct.tokenID, std::string(""), DEFAULT_API_VERSION, policy);
    ASSERT_EQ(RET_FAILED, ret);

    ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx.tokenIdExStruct.tokenID, std::string("updateAppId"), DEFAULT_API_VERSION, policy);
    ASSERT_EQ(RET_FAILED, ret);
}
#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetHapTokenSync001
 * @tc.desc: Verify the GetHapTokenSync token function and abnormal branch.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenSync001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int result;
    result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "add a hap token";

    HapTokenInfoForSync hapSync;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(result, RET_SUCCESS);

    result = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "remove the token info";

    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(result, RET_FAILED);
}

/**
 * @tc.name: GetHapTokenInfoFromRemote001
 * @tc.desc: Verify the GetHapTokenInfoFromRemote token function .
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenInfoFromRemote001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    HapTokenInfoForSync hapSync;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: RemoteHapTest001001
 * @tc.desc: Verify the RemoteHap token function .
 * @tc.type: FUNC
 * @tc.require: issueI5RJBB
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoteHapTest001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    std::string deviceId = "device_1";
    std::string deviceId2 = "device_2";
    AccessTokenID mapID =
        AccessTokenInfoManager::GetInstance().AllocLocalTokenID(deviceId, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(mapID == 0, true);
    HapTokenInfoForSync hapSync;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceId, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceId);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(deviceId2);
    ASSERT_EQ(RET_FAILED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DeleteRemoteToken001
 * @tc.desc: Verify the DeleteRemoteToken normal and abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issueI5RJBB
 */
HWTEST_F(AccessTokenInfoManagerTest, DeleteRemoteToken001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    std::string deviceId = "device_1";
    std::string deviceId2 = "device_2";
    AccessTokenID mapId =
        AccessTokenInfoManager::GetInstance().AllocLocalTokenID(deviceId, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(mapId == 0, true);
    HapTokenInfoForSync hapSync;
    ret = AccessTokenInfoManager::GetInstance().GetHapTokenInfoFromRemote(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceId, hapSync);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceId, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    ret = AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceId2, tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_FAILED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GetUdidByNodeId001
 * @tc.desc: Verify the GetUdidByNodeId abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issue5RJBB
 */
HWTEST_F(AccessTokenInfoManagerTest, GetUdidByNodeId001, TestSize.Level1)
{
    std::string nodeId = "test";
    std::string result = AccessTokenInfoManager::GetInstance().GetUdidByNodeId(nodeId);
    ASSERT_EQ(result.empty(), true);
}

static bool SetRemoteHapTokenInfoTest(const std::string& deviceID, const HapTokenInfo& baseInfo)
{
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(g_infoManagerTestState1);
    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    return RET_SUCCESS == AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo("", remoteTokenInfo);
}

/**
 * @tc.name: SetRemoteHapTokenInfo001
 * @tc.desc: set remote hap token info, token info is wrong
 * @tc.type: FUNC
 * @tc.require: issue5RJBB
 */
HWTEST_F(AccessTokenInfoManagerTest, SetRemoteHapTokenInfo001, TestSize.Level1)
{
    std::string deviceID = "deviceId";
    HapTokenInfo rightBaseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = "deviceId",
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };
    HapTokenInfo wrongBaseInfo = rightBaseInfo;
    std::string wrongStr(10241, 'x');
    
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest("", wrongBaseInfo));

    wrongBaseInfo.apl = (ATokenAplEnum)11; // wrong apl
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.deviceID = wrongStr; // wrong deviceID
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.userID = -1; // wrong userID
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.bundleName = wrongStr; // wrong bundleName
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.tokenID = 0; // wrong tokenID
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.appID = wrongStr; // wrong appID
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.dlpType = (HapDlpType)11;; // wrong dlpType
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.ver = 2; // 2: wrong version
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));

    wrongBaseInfo = rightBaseInfo;
    wrongBaseInfo.tokenID = AccessTokenInfoManager::GetInstance().GetNativeTokenId("hdcd");
    EXPECT_EQ(false, SetRemoteHapTokenInfoTest(deviceID, wrongBaseInfo));
}
#endif
#ifdef SUPPORT_SANDBOX_APP
static void PrepareJsonData1()
{
    std::string testStr = R"({"dlpPermissions":[)"\
        R"({"name":"ohos.permission.CAPTURE_SCREEN","dlpGrantRange":"none"},)"\
        R"({"name":"ohos.permission.CHANGE_ABILITY_ENABLED_STATE","dlpGrantRange":"all"},)"\
        R"({"name":"ohos.permission.CLEAN_APPLICATION_DATA","dlpGrantRange":"full_control"}]})";

    std::vector<PermissionDlpMode> dlpPerms;
    int res = DlpPermissionSetParser::GetInstance().ParserDlpPermsRawData(testStr, dlpPerms);
    if (res != RET_SUCCESS) {
        GTEST_LOG_(INFO) << "ParserDlpPermsRawData failed:";
    }
    for (auto iter = dlpPerms.begin(); iter != dlpPerms.end(); iter++) {
        GTEST_LOG_(INFO) << "iter:" << iter->permissionName.c_str();
    }
    DlpPermissionSetManager::GetInstance().ProcessDlpPermInfos(dlpPerms);
}

/**
 * @tc.name: DlpPermissionConfig001
 * @tc.desc: test DLP_COMMON app with system_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(AccessTokenInfoManagerTest, DlpPermissionConfig001, TestSize.Level1)
{
    PrepareJsonData1();

    g_infoManagerTestStateA.permissionName = "ohos.permission.CAPTURE_SCREEN";
    g_infoManagerTestStateB.permissionName = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
    g_infoManagerTestStateC.permissionName = "ohos.permission.CLEAN_APPLICATION_DATA";
    g_infoManagerTestStateD.permissionName = "ohos.permission.COMMONEVENT_STICKY";

    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .bundleName = "DlpPermissionConfig001",
        .userID = 1,
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest"
    };
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CAPTURE_SCREEN");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CHANGE_ABILITY_ENABLED_STATE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CLEAN_APPLICATION_DATA");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.COMMONEVENT_STICKY");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DlpPermissionConfig002
 * @tc.desc: test DLP_READ app with system_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(AccessTokenInfoManagerTest, DlpPermissionConfig002, TestSize.Level1)
{
    PrepareJsonData1();

    g_infoManagerTestStateA.permissionName = "ohos.permission.CAPTURE_SCREEN";
    g_infoManagerTestStateB.permissionName = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
    g_infoManagerTestStateC.permissionName = "ohos.permission.CLEAN_APPLICATION_DATA";
    g_infoManagerTestStateD.permissionName = "ohos.permission.COMMONEVENT_STICKY";

    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .bundleName = "DlpPermissionConfig002",
        .userID = 1,
        .instIndex = 0,
        .dlpType = DLP_READ,
        .appIDDesc = "testtesttesttest"
    };
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CAPTURE_SCREEN");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CHANGE_ABILITY_ENABLED_STATE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CLEAN_APPLICATION_DATA");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.COMMONEVENT_STICKY");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DlpPermissionConfig003
 * @tc.desc: test DLP_FULL_CONTROL app with system_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(AccessTokenInfoManagerTest, DlpPermissionConfig003, TestSize.Level1)
{
    PrepareJsonData1();

    g_infoManagerTestStateA.permissionName = "ohos.permission.CAPTURE_SCREEN";
    g_infoManagerTestStateB.permissionName = "ohos.permission.CHANGE_ABILITY_ENABLED_STATE";
    g_infoManagerTestStateC.permissionName = "ohos.permission.CLEAN_APPLICATION_DATA";
    g_infoManagerTestStateD.permissionName = "ohos.permission.COMMONEVENT_STICKY";

    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .bundleName = "DlpPermissionConfig003",
        .userID = 1,
        .instIndex = 0,
        .dlpType = DLP_FULL_CONTROL,
        .appIDDesc = "testtesttesttest"
    };
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CAPTURE_SCREEN");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CHANGE_ABILITY_ENABLED_STATE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.CLEAN_APPLICATION_DATA");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(
        tokenID, "ohos.permission.COMMONEVENT_STICKY");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

static void PrepareUserPermState()
{
    g_infoManagerTestStateA.permissionName = "ohos.permission.MEDIA_LOCATION";
    g_infoManagerTestStateA.grantStatus[0] = PERMISSION_DENIED;
    g_infoManagerTestStateB.permissionName = "ohos.permission.MICROPHONE";
    g_infoManagerTestStateB.grantStatus[0] = PERMISSION_DENIED;
    g_infoManagerTestStateC.permissionName = "ohos.permission.READ_CALENDAR";
    g_infoManagerTestStateC.grantStatus[0] = PERMISSION_DENIED;
    g_infoManagerTestStateD.permissionName = "ohos.permission.READ_CALL_LOG";
    g_infoManagerTestStateD.grantStatus[0] = PERMISSION_DENIED;
}

static void PrepareJsonData2()
{
    std::string testStr = R"({"dlpPermissions":[)"\
        R"({"name":"ohos.permission.MEDIA_LOCATION","dlpGrantRange":"none"},)"\
        R"({"name":"ohos.permission.MICROPHONE","dlpGrantRange":"all"},)"\
        R"({"name":"ohos.permission.READ_CALENDAR","dlpGrantRange":"full_control"}]})";

    std::vector<PermissionDlpMode> dlpPerms;
    int res = DlpPermissionSetParser::GetInstance().ParserDlpPermsRawData(testStr, dlpPerms);
    if (res != RET_SUCCESS) {
        GTEST_LOG_(INFO) << "ParserDlpPermsRawData failed:";
    }
    DlpPermissionSetManager::GetInstance().ProcessDlpPermInfos(dlpPerms);
}

/**
 * @tc.name: DlpPermissionConfig004
 * @tc.desc: test DLP_COMMON app with user_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(AccessTokenInfoManagerTest, DlpPermissionConfig004, TestSize.Level1)
{
    PrepareJsonData2();
    PrepareUserPermState();

    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {g_infoManagerPermDef1, g_infoManagerPermDef2,
                     g_infoManagerPermDef3, g_infoManagerPermDef4},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .bundleName = "accesstoken_test",
        .userID = 1,
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest"
    };
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MEDIA_LOCATION", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALENDAR", PERMISSION_USER_FIXED);
    ASSERT_EQ(RET_SUCCESS, ret);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALL_LOG", PERMISSION_USER_FIXED);

    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MEDIA_LOCATION");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALENDAR");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALL_LOG");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DlpPermissionConfig005
 * @tc.desc: test DLP_READ app with user_grant permissions.
 * @tc.type: FUNC
 * @tc.require: SR000GVIGR
 */
HWTEST_F(AccessTokenInfoManagerTest, DlpPermissionConfig005, TestSize.Level1)
{
    PrepareJsonData2();
    PrepareUserPermState();

    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {g_infoManagerPermDef1, g_infoManagerPermDef2,
                     g_infoManagerPermDef3, g_infoManagerPermDef4},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .bundleName = "accesstoken_test",
        .userID = 1,
        .instIndex = 0,
        .dlpType = DLP_READ,
        .appIDDesc = "testtesttesttest"
    };
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MEDIA_LOCATION", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALENDAR", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALL_LOG", PERMISSION_USER_FIXED);

    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MEDIA_LOCATION");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALENDAR");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALL_LOG");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DlpPermissionConfig006
 * @tc.desc: test DLP_FULL_CONTROL app with user_grant permissions.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, DlpPermissionConfig006, TestSize.Level1)
{
    PrepareJsonData2();
    PrepareUserPermState();

    static HapPolicyParams infoManagerTestPolicyPrams = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {g_infoManagerPermDef1, g_infoManagerPermDef2,
                     g_infoManagerPermDef3, g_infoManagerPermDef4},
        .permStateList = {g_infoManagerTestStateA, g_infoManagerTestStateB,
                          g_infoManagerTestStateC, g_infoManagerTestStateD}
    };
    static HapInfoParams infoManagerTestInfoParms = {
        .bundleName = "accesstoken_test",
        .userID = 1,
        .instIndex = 0,
        .dlpType = DLP_FULL_CONTROL,
        .appIDDesc = "testtesttesttest"
    };
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(infoManagerTestInfoParms,
        infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;

    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MEDIA_LOCATION", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.MICROPHONE", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALENDAR", PERMISSION_USER_FIXED);
    PermissionManager::GetInstance().GrantPermission(tokenID,
        "ohos.permission.READ_CALL_LOG", PERMISSION_USER_FIXED);

    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MEDIA_LOCATION");
    ASSERT_EQ(PERMISSION_DENIED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.MICROPHONE");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALENDAR");
    ASSERT_EQ(PERMISSION_GRANTED, ret);
    ret = PermissionManager::GetInstance().VerifyAccessToken(tokenID, "ohos.permission.READ_CALL_LOG");
    ASSERT_EQ(PERMISSION_GRANTED, ret);

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}
#endif

/**
 * @tc.name: Dump001
 * @tc.desc: Dump tokeninfo.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, Dump001, TestSize.Level1)
{
    int fd = -1;
    std::vector<std::u16string> args;

    // fd is 0
    ASSERT_NE(RET_SUCCESS, atManagerService_->Dump(fd, args));

    fd = 123; // 123：valid fd

    // hidumper
    ASSERT_EQ(RET_SUCCESS, atManagerService_->Dump(fd, args));

    // hidumper -h
    args.emplace_back(Str8ToStr16("-h"));
    ASSERT_EQ(RET_SUCCESS, atManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -a
    args.emplace_back(Str8ToStr16("-a"));
    ASSERT_EQ(RET_SUCCESS, atManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    ASSERT_NE(RET_SUCCESS, atManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    args.emplace_back(Str8ToStr16("-1")); // illegal tokenId
    ASSERT_NE(RET_SUCCESS, atManagerService_->Dump(fd, args));

    args.clear();
    // hidumper -t
    args.emplace_back(Str8ToStr16("-t"));
    args.emplace_back(Str8ToStr16("123")); // invalid tokenId
    ASSERT_EQ(RET_SUCCESS, atManagerService_->Dump(fd, args));
}

/**
 * @tc.name: ScopeFilter001
 * @tc.desc: Test filter scopes.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, ScopeFilter001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams, tokenIdEx);

    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    EXPECT_NE(0, tokenId);
    PermStateChangeScope inScopeInfo;
    PermStateChangeScope outScopeInfo;
    PermStateChangeScope emptyScopeInfo;

    // both empty
    inScopeInfo.permList = {};
    inScopeInfo.tokenIDs = {};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.tokenIDs = {123};
    EXPECT_EQ(RET_FAILED, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(true, outScopeInfo.tokenIDs.empty());

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.tokenIDs.clear();
    inScopeInfo.tokenIDs = {123, tokenId, tokenId};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(1, outScopeInfo.tokenIDs.size());

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.tokenIDs.clear();
    inScopeInfo.permList = {"ohos.permission.test"};
    EXPECT_EQ(RET_FAILED, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(true, outScopeInfo.permList.empty());

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.permList.clear();
    inScopeInfo.permList = {"ohos.permission.test", "ohos.permission.CAMERA", "ohos.permission.CAMERA"};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(1, outScopeInfo.permList.size());
    
    outScopeInfo = emptyScopeInfo;
    inScopeInfo.permList.clear();
    inScopeInfo.tokenIDs = {123, tokenId, tokenId};
    inScopeInfo.permList = {"ohos.permission.test", "ohos.permission.CAMERA", "ohos.permission.CAMERA"};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(1, outScopeInfo.tokenIDs.size());
    EXPECT_EQ(1, outScopeInfo.permList.size());

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: AddPermStateChangeCallback001
 * @tc.desc: Test AddPermStateChangeCallback.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, AddPermStateChangeCallback001, TestSize.Level1)
{
    PermStateChangeScope inScopeInfo;
    inScopeInfo.tokenIDs = {123};

    EXPECT_EQ(RET_FAILED, PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, nullptr));

    inScopeInfo.permList = {"ohos.permission.CAMERA"};
    EXPECT_EQ(RET_FAILED, PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, nullptr));
    EXPECT_EQ(RET_FAILED, PermissionManager::GetInstance().RemovePermStateChangeCallback(nullptr));
}

class PermChangeCallback : public PermissionStateChangeCallbackStub {
public:
    PermChangeCallback() = default;
    virtual ~PermChangeCallback() = default;

    void PermStateChangeCallback(PermStateChangeInfo& result) override;
};

void PermChangeCallback::PermStateChangeCallback(PermStateChangeInfo& result)
{
}

/**
 * @tc.name: AddPermStateChangeCallback002
 * @tc.desc: Test AddPermStateChangeCallback with exceed limitation.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, AddPermStateChangeCallback002, TestSize.Level1)
{
    PermStateChangeScope inScopeInfo;
    inScopeInfo.tokenIDs = {};
    inScopeInfo.permList = {"ohos.permission.CAMERA"};
    std::vector<sptr<PermChangeCallback>> callbacks;

    for (size_t i = 0; i < MAX_CALLBACK_SIZE; ++i) {
        sptr<PermChangeCallback> callback = new (std::nothrow) PermChangeCallback();
        ASSERT_NE(nullptr, callback);
        ASSERT_EQ(RET_SUCCESS,
            PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, callback->AsObject()));
        callbacks.emplace_back(callback);
    }

    sptr<PermChangeCallback> callback = new (std::nothrow) PermChangeCallback();
    ASSERT_NE(nullptr, callback);
    ASSERT_NE(RET_SUCCESS,
        PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, callback->AsObject()));

    for (size_t i = 0; i < callbacks.size(); ++i) {
        ASSERT_EQ(RET_SUCCESS,
            PermissionManager::GetInstance().RemovePermStateChangeCallback(callbacks[i]->AsObject()));
    }
}

/**
 * @tc.name: DumpTokenInfo001
 * @tc.desc: Test DumpTokenInfo with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo001, TestSize.Level1)
{
    std::string dumpInfo;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(0, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    dumpInfo.clear();
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(123, dumpInfo);
    EXPECT_EQ("invalid tokenId", dumpInfo);
}

/**
 * @tc.name: UpdateTokenPermissionState001
 * @tc.desc: Test UpdateTokenPermissionState abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issueI5SSXG
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateTokenPermissionState001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenID tokenID = tokenIdEx.tokenIdExStruct.tokenID;
    AccessTokenID invalidTokenId = 1;
    ret = PermissionManager::GetInstance().GrantPermission(
        invalidTokenId, "ohos.permission.READ_CALENDAR", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);

    std::shared_ptr<HapTokenInfoInner> infoPtr =
        AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenID);
    ASSERT_NE(nullptr, infoPtr);
    infoPtr->SetRemote(true);
    ret = PermissionManager::GetInstance().GrantPermission(
        tokenID, "ohos.permission.READ_CALENDAR", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_OPERATE_FAILED, ret);
    infoPtr->SetRemote(false);

    std::shared_ptr<PermissionPolicySet> permPolicySet = infoPtr->GetHapInfoPermissionPolicySet();
    std::shared_ptr<PermissionPolicySet> infoPtrNull =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(invalidTokenId);
    ASSERT_EQ(nullptr, infoPtrNull);
    infoPtr->SetPermissionPolicySet(infoPtrNull);
    ret = PermissionManager::GetInstance().GrantPermission(
        tokenID, "ohos.permission.READ_CALENDAR", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    
    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: DumpTokenInfo002
 * @tc.desc: Test DumpTokenInfo with hap tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams, tokenIdEx);

    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    EXPECT_NE(0, tokenId);
    std::string dumpInfo;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(tokenId, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

/**
 * @tc.name: DumpTokenInfo003
 * @tc.desc: Test DumpTokenInfo with native tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo003, TestSize.Level1)
{
    std::string dumpInfo;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(
        AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service"), dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

/**
 * @tc.name: DumpTokenInfo004
 * @tc.desc: Test DumpTokenInfo with shell tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo004, TestSize.Level1)
{
    std::string dumpInfo;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(
        AccessTokenInfoManager::GetInstance().GetNativeTokenId("hdcd"), dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

/**
 * @tc.name: GrantPermission001
 * @tc.desc: Test GrantPermission abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issueI5SSXG
 */
HWTEST_F(AccessTokenInfoManagerTest, GrantPermission001, TestSize.Level1)
{
    int32_t ret;
    AccessTokenID tokenID = 0;
    ret = PermissionManager::GetInstance().GrantPermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    ret = PermissionManager::GetInstance().GrantPermission(tokenID, "ohos.perm", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);
    int32_t invalidFlag = -1;
    ret = PermissionManager::GetInstance().GrantPermission(tokenID, "ohos.permission.READ_CALENDAR", invalidFlag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}
