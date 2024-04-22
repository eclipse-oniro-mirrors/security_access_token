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

#include <gmock/gmock.h>

#include "accesstoken_id_manager.h"
#include "access_token_error.h"
#define private public
#include "accesstoken_callback_stubs.h"
#include "accesstoken_info_manager.h"
#include "accesstoken_remote_token_manager.h"
#include "libraryloader.h"
#include "token_field_const.h"
#include "token_sync_kit_loader.h"
#include "permission_definition_cache.h"
#include "permission_manager.h"
#include "token_modify_notifier.h"
#undef private
#include "permission_validator.h"
#include "string_ex.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenInfoManagerTest"
};
static constexpr int32_t DEFAULT_API_VERSION = 8;
static constexpr int USER_ID = 100;
static constexpr int INST_INDEX = 0;
static PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "open the door",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "open the door",
    .descriptionId = 1
};

static PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "break the door",
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "break the door",
    .descriptionId = 1
};

static PermissionStateFull g_infoManagerTestState1 = {
    .permissionName = "open the door",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {1},
    .grantFlags = {1}
};

static PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "break the door",
    .isGeneral = false,
    .resDeviceID = {"device 1", "device 2"},
    .grantStatus = {1, 3},
    .grantFlags = {1, 2}
};

static HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

static HapPolicyParams g_infoManagerTestPolicyPrams1 = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

static PermissionStateFull g_permState = {
    .permissionName = "ohos.permission.CAMERA",
    .isGeneral = false,
    .resDeviceID = {"dev-001", "dev-001"},
    .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
};

static const int32_t FAKE_SYNC_RET = 0xabcdef;
class TokenSyncCallbackMock : public TokenSyncCallbackStub {
public:
    TokenSyncCallbackMock() = default;
    virtual ~TokenSyncCallbackMock() = default;

    MOCK_METHOD(int32_t, GetRemoteHapTokenInfo, (const std::string&, AccessTokenID), (override));
    MOCK_METHOD(int32_t, DeleteRemoteHapTokenInfo, (AccessTokenID), (override));
    MOCK_METHOD(int32_t, UpdateRemoteHapTokenInfo, (const HapTokenInfoForSync&), (override));
};
}

void AccessTokenInfoManagerTest::SetUpTestCase()
{
    AccessTokenInfoManager::GetInstance().Init();
}

void AccessTokenInfoManagerTest::TearDownTestCase()
{
    sleep(3); // delay 3 minutes
}

void AccessTokenInfoManagerTest::SetUp()
{
    atManagerService_ = DelayedSingleton<AccessTokenManagerService>::GetInstance();
    EXPECT_NE(nullptr, atManagerService_);
    PermissionDef infoManagerPermDefA = {
        .permissionName = "ohos.permission.CAMERA",
        .bundleName = "accesstoken_test",
        .grantMode = USER_GRANT,
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
    };
    PermissionDefinitionCache::GetInstance().Insert(infoManagerPermDefA, 1);
    PermissionDef infoManagerPermDefB = {
        .permissionName = "ohos.permission.LOCATION",
        .bundleName = "accesstoken_test",
        .grantMode = USER_GRANT,
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
    };
    PermissionDefinitionCache::GetInstance().Insert(infoManagerPermDefB, 1);
}

void AccessTokenInfoManagerTest::TearDown()
{
    atManagerService_ = nullptr;
}

/**
 * @tc.name: HapTokenInfoInner001
 * @tc.desc: HapTokenInfoInner::HapTokenInfoInner.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, HapTokenInfoInner001, TestSize.Level1)
{
    AccessTokenID id = 0x20240112;
    HapTokenInfo info = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.access_token",
        .instIndex = 1,
        .appID = "testtesttesttest",
        .deviceID = "deviceId",
        .tokenID = id,
        .tokenAttr = 0
    };
    std::vector<PermissionStateFull> permStateList;
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>(id, info, permStateList);
    ASSERT_EQ(hap->IsRemote(), false);
    hap->SetRemote(true);
    std::vector<GenericValues> valueList;
    hap->StoreHapInfo(valueList);

    hap->StorePermissionPolicy(valueList);
    ASSERT_EQ(hap->IsRemote(), true);
    hap->SetRemote(false);
    int32_t version = hap->GetApiVersion(5608);
    ASSERT_EQ(static_cast<int32_t>(608), version);
}

/**
 * @tc.name: CreateHapTokenInfo001
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx);
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
 * @tc.name: CreateHapTokenInfo002
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token twice function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "AddHapToken001 fill data");

    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    AccessTokenIDEx tokenIdEx1 = {0};
    ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx1);
    ASSERT_EQ(RET_SUCCESS, ret);
    ASSERT_NE(tokenIdEx.tokenIdExStruct.tokenID, tokenIdEx1.tokenIdExStruct.tokenID);
    GTEST_LOG_(INFO) << "add same hap token";

    std::shared_ptr<HapTokenInfoInner> tokenInfo;
    tokenInfo = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenIdEx1.tokenIdExStruct.tokenID);
    ASSERT_NE(nullptr, tokenInfo);

    std::string infoDes;
    tokenInfo->ToString(infoDes);
    GTEST_LOG_(INFO) << "get hap token info:" << infoDes.c_str();

    ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx1.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: CreateHapTokenInfo003
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test userID invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo003, TestSize.Level1)
{
    HapInfoParams info = {
        .userID = -1
    };
    HapPolicyParams policy;
    AccessTokenIDEx tokenIdEx;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx));
}

/**
 * @tc.name: CreateHapTokenInfo004
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test bundleName invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo004, TestSize.Level1)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = ""
    };
    HapPolicyParams policy;
    AccessTokenIDEx tokenIdEx;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx));
}

/**
 * @tc.name: CreateHapTokenInfo005
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test appIDDesc invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo005, TestSize.Level1)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .appIDDesc = ""
    };
    HapPolicyParams policy;
    AccessTokenIDEx tokenIdEx;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx));
}

/**
 * @tc.name: CreateHapTokenInfo006
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test domain invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo006, TestSize.Level1)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .appIDDesc = "who cares"
    };
    HapPolicyParams policy = {
        .domain = ""
    };
    AccessTokenIDEx tokenIdEx;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx));
}

/**
 * @tc.name: CreateHapTokenInfo007
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test dlpType invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo007, TestSize.Level1)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .dlpType = -1,
        .appIDDesc = "who cares"
    };
    HapPolicyParams policy = {
        .domain = "who cares"
    };
    AccessTokenIDEx tokenIdEx;

    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx));
}

/**
 * @tc.name: CreateHapTokenInfo008
 * @tc.desc: AccessTokenInfoManager::CreateHapTokenInfo function test grant mode invalid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateHapTokenInfo008, TestSize.Level1)
{
    static PermissionDef permDef = {
        .permissionName = "ohos.permission.test",
        .bundleName = "accesstoken_test",
        .grantMode = -1,    // -1:invalid grant mode
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "label",
        .labelId = 1,
        .description = "open the door",
        .descriptionId = 1
    };
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "ohos.com.testtesttest",
        .appIDDesc = ""
    };
    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {permDef}
    };
    AccessTokenIDEx tokenIdEx;
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx));
}

/**
 * @tc.name: InitHapToken001
 * @tc.desc: InitHapToken function test with invalid userID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken001, TestSize.Level1)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = -1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicyParameter.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicyParameter.domain = "test.domain";
    AccessTokenIDEx tokenIdEx;
    ASSERT_EQ(ERR_PARAM_INVALID, atManagerService_->InitHapToken(hapinfoParcel, hapPolicyParcel, tokenIdEx));
}

/**
 * @tc.name: InitHapToken002
 * @tc.desc: InitHapToken function test with invalid userID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken002, TestSize.Level1)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = -1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_READ,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicyParameter.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicyParameter.domain = "test.domain";
    AccessTokenIDEx tokenIdEx;
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, atManagerService_->InitHapToken(hapinfoParcel, hapPolicyParcel, tokenIdEx));
}

/**
 * @tc.name: InitHapToken003
 * @tc.desc: InitHapToken function test with invalid apl permission
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, InitHapToken003, TestSize.Level1)
{
    HapInfoParcel info;
    info.hapInfoParameter = {
        .userID = 0,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .dlpType = DLP_COMMON,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel policy;
    PermissionStateFull permissionStateA = {
        .permissionName = "ohos.permission.GET_ALL_APP_ACCOUNTS",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {1},
        .grantFlags = {1}
    };
    PermissionStateFull permissionStateB = {
        .permissionName = "ohos.permission.PRELOAD_APPLICATION",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {1},
        .grantFlags = {1}
    };
    PermissionStateFull permissionStateC = {
        .permissionName = "ohos.permission.test",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {1},
        .grantFlags = {1}
    };
    policy.hapPolicyParameter = {
        .apl = APL_NORMAL,
        .domain = "test",
        .permList = {},
        .permStateList = { permissionStateA }
    };
    AccessTokenIDEx fullTokenId = {0};
    ASSERT_EQ(ERR_PERM_REQUEST_CFG_FAILED, atManagerService_->InitHapToken(info, policy, fullTokenId));

    policy.hapPolicyParameter.permStateList = { permissionStateB, permissionStateC };
    policy.hapPolicyParameter.aclRequestedList = { "ohos.permission.PRELOAD_APPLICATION" };
    ASSERT_EQ(RET_SUCCESS, atManagerService_->InitHapToken(info, policy, fullTokenId));
}

/**
 * @tc.name: IsTokenIdExist001
 * @tc.desc: Verify the IsTokenIdExist exist accesstokenid.
 * @tc.type: FUNC
 * @tc.require:
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
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenInfo001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int result;
    HapTokenInfo hapInfo;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    ASSERT_EQ(result, ERR_TOKENID_NOT_EXIST);

    result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "add a hap token";
    result = AccessTokenInfoManager::GetInstance().GetHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID, hapInfo);
    ASSERT_EQ(result, RET_SUCCESS);
    result = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "remove the token info";
}

/**
 * @tc.name: GetHapPermissionPolicySet001
 * @tc.desc: Verify the GetHapPermissionPolicySet abnormal and normal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapPermissionPolicySet001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::shared_ptr<PermissionPolicySet> permPolicySet =
        AccessTokenInfoManager::GetInstance().GetHapPermissionPolicySet(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(permPolicySet, nullptr);

    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
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
 * @tc.require:
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
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveHapTokenInfo001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_NE(AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID), RET_SUCCESS);

    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP));
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId)); // count(id) == 0

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId)); // info is null
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);

    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->tokenInfoBasic_.userID = USER_ID;
    info->tokenInfoBasic_.bundleName = "com.ohos.TEST";
    info->tokenInfoBasic_.instIndex = INST_INDEX;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    // count(HapUniqueKey) == 0
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP)); // removed above
    AccessTokenID tokenId2 = 537919486; // 537919486: 001 00 0 000000 11111111111111111110
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    std::string hapUniqueKey = "com.ohos.TEST&" + std::to_string(USER_ID) + "&" + std::to_string(INST_INDEX);
    AccessTokenInfoManager::GetInstance().hapTokenIdMap_[hapUniqueKey] = tokenId2;
    // hapTokenIdMap_[HapUniqueKey] != id
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
    AccessTokenInfoManager::GetInstance().hapTokenIdMap_.erase(hapUniqueKey);

    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
}

/**
 * @tc.name: GetHapTokenID001
 * @tc.desc: Verify the GetHapTokenID by userID/bundleName/instIndex, function.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenID001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    AccessTokenID getTokenId = tokenIdEx.tokenIdExStruct.tokenID;
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
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "add a hap token";

    HapPolicyParams policy = g_infoManagerTestPolicyPrams1;
    policy.apl = APL_SYSTEM_BASIC;
    UpdateHapInfoParams info;
    info.appIDDesc = std::string("updateAppId");
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, info, policy.permStateList, policy.apl, policy.permList);
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
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    HapPolicyParams policy = g_infoManagerTestPolicyPrams1;
    policy.apl = APL_SYSTEM_BASIC;
    UpdateHapInfoParams info;
    info.appIDDesc = std::string("");
    info.apiVersion = DEFAULT_API_VERSION;
    info.isSystemApp = false;
    int ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, info, policy.permStateList, policy.apl, policy.permList);
    ASSERT_EQ(ERR_PARAM_INVALID, ret);

    info.appIDDesc = std::string("updateAppId");
    ret = AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, info, policy.permStateList, policy.apl, policy.permList);
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, ret);
}

/**
 * @tc.name: UpdateHapToken003
 * @tc.desc: AccessTokenInfoManager::UpdateHapToken function test IsRemote_ true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken003, TestSize.Level1)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx.tokenIdExStruct.tokenID = tokenId;
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->isRemote_ = true;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    HapPolicyParams policy;
    UpdateHapInfoParams hapInfoParams;
    hapInfoParams.appIDDesc = "who cares";
    hapInfoParams.apiVersion = DEFAULT_API_VERSION;
    hapInfoParams.isSystemApp = false;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().UpdateHapToken(
        tokenIdEx, hapInfoParams, policy.permStateList, policy.apl, policy.permList));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: GetHapTokenSync001
 * @tc.desc: Verify the GetHapTokenSync token function and abnormal branch.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenSync001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int result;
    result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "add a hap token";

    HapTokenInfoForSync hapSync;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(result, RET_SUCCESS);

    result = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, result);
    GTEST_LOG_(INFO) << "remove the token info";

    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_NE(result, RET_SUCCESS);
}

/**
 * @tc.name: GetHapTokenSync002
 * @tc.desc: AccessTokenInfoManager::GetHapTokenSync function test permSetPtr is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenSync002, TestSize.Level1)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->permPolicySet_ = nullptr;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    HapTokenInfoForSync hapSync;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenId, hapSync));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: GetHapTokenInfoFromRemote001
 * @tc.desc: Verify the GetHapTokenInfoFromRemote token function .
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenInfoFromRemote001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
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
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
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
    ASSERT_EQ(ERR_DEVICE_NOT_EXIST, ret);

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
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
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
    ASSERT_NE(RET_SUCCESS, ret);

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

    return RET_SUCCESS == AccessTokenInfoManager::GetInstance().SetRemoteHapTokenInfo(deviceID, remoteTokenInfo);
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

/**
 * @tc.name: NotifyTokenSyncTask001
 * @tc.desc: TokenModifyNotifier::NotifyTokenSyncTask function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, NotifyTokenSyncTask001, TestSize.Level1)
{
    std::vector<AccessTokenID> modifiedTokenList = TokenModifyNotifier::GetInstance().modifiedTokenList_; // backup
    TokenModifyNotifier::GetInstance().modifiedTokenList_.clear();

    AccessTokenID tokenId = 123; // 123 is random input

    TokenModifyNotifier::GetInstance().modifiedTokenList_.emplace_back(tokenId);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().modifiedTokenList_.size() > 0);
    TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();

    TokenModifyNotifier::GetInstance().modifiedTokenList_ = modifiedTokenList; // recovery
}

/**
 * @tc.name: RegisterTokenSyncCallback001
 * @tc.desc: TokenModifyNotifier::RegisterTokenSyncCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RegisterTokenSyncCallback001, TestSize.Level1)
{
    sptr<TokenSyncCallbackMock> callback = new (std::nothrow) TokenSyncCallbackMock();
    ASSERT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->RegisterTokenSyncCallback(callback->AsObject()));
    EXPECT_NE(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_);
    EXPECT_NE(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackDeathRecipient_);
    
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_)).WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_->GetRemoteHapTokenInfo("", 0));
    
    EXPECT_CALL(*callback, DeleteRemoteHapTokenInfo(testing::_)).WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_->DeleteRemoteHapTokenInfo(0));
    
    HapTokenInfoForSync tokenInfo;
    EXPECT_CALL(*callback, UpdateRemoteHapTokenInfo(testing::_)).WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET,
        TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_->UpdateRemoteHapTokenInfo(tokenInfo));
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UnRegisterTokenSyncCallback());
    EXPECT_EQ(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_);
    EXPECT_EQ(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackDeathRecipient_);
}

/**
 * @tc.name: RegisterTokenSyncCallback002
 * @tc.desc: TokenModifyNotifier::RegisterTokenSyncCallback function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RegisterTokenSyncCallback002, TestSize.Level1)
{
    sptr<TokenSyncCallbackMock> callback = new (std::nothrow) TokenSyncCallbackMock();
    ASSERT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->RegisterTokenSyncCallback(callback->AsObject()));
    EXPECT_NE(nullptr, TokenModifyNotifier::GetInstance().tokenSyncCallbackObject_);
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_))
        .WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance().GetRemoteHapTokenInfo("", 0));

    std::vector<AccessTokenID> modifiedTokenList =
        TokenModifyNotifier::GetInstance().modifiedTokenList_; // backup
    std::vector<AccessTokenID> deleteTokenList = TokenModifyNotifier::GetInstance().deleteTokenList_;
    TokenModifyNotifier::GetInstance().modifiedTokenList_.clear();
    TokenModifyNotifier::GetInstance().deleteTokenList_.clear();

    // add a hap token
    AccessTokenIDEx tokenIdEx = {123};
    int32_t result = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
    EXPECT_EQ(RET_SUCCESS, result);

    HapTokenInfoForSync hapSync;
    result = AccessTokenInfoManager::GetInstance().GetHapTokenSync(tokenIdEx.tokenIdExStruct.tokenID, hapSync);
    ASSERT_EQ(result, RET_SUCCESS);
    TokenModifyNotifier::GetInstance().modifiedTokenList_.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().modifiedTokenList_.size() > 0);
    TokenModifyNotifier::GetInstance().deleteTokenList_.clear();

    EXPECT_CALL(*callback, UpdateRemoteHapTokenInfo(testing::_)) // 0 is a test ret
        .WillOnce(testing::Return(0));
    TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();

    TokenModifyNotifier::GetInstance().deleteTokenList_.emplace_back(tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().deleteTokenList_.size() > 0);
    EXPECT_CALL(*callback, DeleteRemoteHapTokenInfo(testing::_)) // 0 is a test ret
        .WillOnce(testing::Return(0));
    TokenModifyNotifier::GetInstance().NotifyTokenSyncTask();

    TokenModifyNotifier::GetInstance().modifiedTokenList_ = modifiedTokenList; // recovery
    TokenModifyNotifier::GetInstance().deleteTokenList_ = deleteTokenList;
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UnRegisterTokenSyncCallback());
}

/**
 * @tc.name: GetRemoteHapTokenInfo001
 * @tc.desc: TokenModifyNotifier::GetRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetRemoteHapTokenInfo001, TestSize.Level1)
{
    sptr<TokenSyncCallbackMock> callback = new (std::nothrow) TokenSyncCallbackMock();
    ASSERT_NE(nullptr, callback);
    EXPECT_EQ(RET_SUCCESS, atManagerService_->RegisterTokenSyncCallback(callback->AsObject()));
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_))
        .WillOnce(testing::Return(FAKE_SYNC_RET));
    EXPECT_EQ(FAKE_SYNC_RET, TokenModifyNotifier::GetInstance()
        .GetRemoteHapTokenInfo("invalid_id", 0)); // this is a test input
    
    EXPECT_CALL(*callback, GetRemoteHapTokenInfo(testing::_, testing::_))
        .WillOnce(testing::Return(TOKEN_SYNC_OPENSOURCE_DEVICE));
    EXPECT_EQ(TOKEN_SYNC_IPC_ERROR, TokenModifyNotifier::GetInstance()
        .GetRemoteHapTokenInfo("invalid_id", 0)); // this is a test input
    EXPECT_EQ(RET_SUCCESS,
        atManagerService_->UnRegisterTokenSyncCallback());
}
#endif

/**
 * @tc.name: UpdateRemoteHapTokenInfo001
 * @tc.desc: AccessTokenInfoManager::UpdateRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateRemoteHapTokenInfo001, TestSize.Level1)
{
    AccessTokenID mapID = 0;
    HapTokenInfoForSync hapSync;

    // infoPtr is null
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().UpdateRemoteHapTokenInfo(mapID, hapSync));

    mapID = 123; // 123 is random input
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->SetRemote(true);
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[mapID] = info;

    // remote is true
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().UpdateRemoteHapTokenInfo(mapID, hapSync));

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(mapID);
}

/**
 * @tc.name: CreateRemoteHapTokenInfo001
 * @tc.desc: AccessTokenInfoManager::CreateRemoteHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, CreateRemoteHapTokenInfo001, TestSize.Level1)
{
    AccessTokenID mapID = 123; // 123 is random input
    HapTokenInfoForSync hapSync;

    hapSync.baseInfo.tokenID = 123; // 123 is random input
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[123] = info;

    // count(id) exsit
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateRemoteHapTokenInfo(mapID, hapSync));

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(123);
}

/**
 * @tc.name: SetRemoteNativeTokenInfo001
 * @tc.desc: AccessTokenInfoManager::SetRemoteNativeTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, SetRemoteNativeTokenInfo001, TestSize.Level1)
{
    std::string deviceID;
    std::vector<NativeTokenInfoForSync> nativeTokenInfoList;

    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().SetRemoteNativeTokenInfo(deviceID,
        nativeTokenInfoList)); // deviceID invalid

    deviceID = "dev-001";
    NativeTokenInfo info;
    info.apl = ATokenAplEnum::APL_NORMAL;
    info.ver = DEFAULT_TOKEN_VERSION;
    info.processName = "what's this";
    info.dcap = {"what's this"};
    info.tokenID = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    NativeTokenInfoForSync sync;
    sync.baseInfo = info;
    nativeTokenInfoList.emplace_back(sync);

    AccessTokenRemoteDevice device;
    device.DeviceID_ = deviceID;
    // 672137215 is remoteID 123 is mapID
    device.MappingTokenIDPairMap_.insert(std::pair<AccessTokenID, AccessTokenID>(672137215, 123));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_[deviceID] = device;

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetRemoteNativeTokenInfo(deviceID,
        nativeTokenInfoList)); // has maped
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.erase(deviceID);
}

/**
 * @tc.name: DeleteRemoteToken002
 * @tc.desc: AccessTokenInfoManager::DeleteRemoteToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, DeleteRemoteToken002, TestSize.Level1)
{
    std::string deviceID = "dev-001";
    AccessTokenID tokenID = 123; // 123 is random input

    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        AccessTokenInfoManager::GetInstance().DeleteRemoteToken("", tokenID));

    AccessTokenRemoteDevice device;
    device.DeviceID_ = deviceID;
    // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    device.MappingTokenIDPairMap_.insert(std::pair<AccessTokenID, AccessTokenID>(tokenID, 537919487));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_[deviceID] = device;

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(537919487, TOKEN_HAP));
    // hap mapID 537919487 is not exist
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.erase(deviceID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(537919487);

    // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    device.MappingTokenIDPairMap_[tokenID] = 672137215;
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_[deviceID] = device;

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(672137215, TOKEN_NATIVE));
    // native mapID 672137215 is not exist
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.erase(deviceID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(672137215);
}

/**
 * @tc.name: AllocLocalTokenID001
 * @tc.desc: AccessTokenInfoManager::AllocLocalTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AllocLocalTokenID001, TestSize.Level1)
{
    std::string remoteDeviceID;
    AccessTokenID remoteTokenID = 0;

    ASSERT_EQ(static_cast<AccessTokenID>(0), AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID,
        remoteTokenID)); // remoteDeviceID invalid

    // deviceID invalid + tokenID == 0
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(remoteDeviceID, remoteTokenID));

    // deviceID invalid
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(remoteDeviceID));

    remoteDeviceID = "dev-001";
    ASSERT_EQ(static_cast<AccessTokenID>(0), AccessTokenInfoManager::GetInstance().AllocLocalTokenID(remoteDeviceID,
        remoteTokenID)); // remoteTokenID invalid

    // deviceID valid + tokenID == 0
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(remoteDeviceID, remoteTokenID));

    remoteTokenID = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    // deviceID valid + tokenID != 0 + type != native + type != shell
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenInfoManager::GetInstance().GetRemoteNativeTokenID(remoteDeviceID, remoteTokenID));
}

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
 * @tc.name: DumpTokenInfo001
 * @tc.desc: Test DumpTokenInfo with invalid tokenId.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo001, TestSize.Level1)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = static_cast<AccessTokenID>(0);
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    dumpInfo.clear();
    info.tokenId = static_cast<AccessTokenID>(123);
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ("invalid tokenId", dumpInfo);
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
        g_infoManagerTestPolicyPrams1, tokenIdEx);

    tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(0, static_cast<int>(tokenId));
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = tokenId;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(
        tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
    GTEST_LOG_(INFO) << "remove the token info";
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
    AtmToolsParamInfo info;
    info.tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
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
    AtmToolsParamInfo info;
    info.tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("hdcd");
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

/**
 * @tc.name: DumpTokenInfo006
 * @tc.desc: Test DumpTokenInfo with native processName.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo006, TestSize.Level1)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = "hdcd";
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

/**
 * @tc.name: DumpTokenInfo007
 * @tc.desc: Test DumpTokenInfo with hap bundleName.
 * @tc.type: FUNC
 * @tc.require: issueI4V02P
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo007, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx);

    tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(g_infoManagerTestInfoParms.userID,
        g_infoManagerTestInfoParms.bundleName, g_infoManagerTestInfoParms.instIndex);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(0, static_cast<int>(tokenId));
    
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.bundleName = g_infoManagerTestInfoParms.bundleName;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    int32_t ret = AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(
        tokenIdEx.tokenIdExStruct.tokenID);
    ASSERT_EQ(RET_SUCCESS, ret);
}

/**
 * @tc.name: AccessTokenInfoManager001
 * @tc.desc: AccessTokenInfoManager::~AccessTokenInfoManager+Init function test hasInited_ is false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AccessTokenInfoManager001, TestSize.Level1)
{
    AccessTokenInfoManager::GetInstance().hasInited_ = true;
    AccessTokenInfoManager::GetInstance().Init();
    AccessTokenInfoManager::GetInstance().hasInited_ = false;
    ASSERT_EQ(false, AccessTokenInfoManager::GetInstance().hasInited_);
}

/**
 * @tc.name: GetHapUniqueStr001
 * @tc.desc: AccessTokenInfoManager::GetHapUniqueStr function test info is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapUniqueStr001, TestSize.Level1)
{
    std::shared_ptr<HapTokenInfoInner> info = nullptr;
    ASSERT_EQ("", AccessTokenInfoManager::GetInstance().GetHapUniqueStr(info));
}

/**
 * @tc.name: AddHapTokenInfo001
 * @tc.desc: AccessTokenInfoManager::AddHapTokenInfo function test info is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AddHapTokenInfo001, TestSize.Level1)
{
    std::shared_ptr<HapTokenInfoInner> info = nullptr;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddHapTokenInfo(info));
}

/**
 * @tc.name: AddHapTokenInfo002
 * @tc.desc: AccessTokenInfoManager::AddHapTokenInfo function test count(id) > 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AddHapTokenInfo002, TestSize.Level1)
{
    HapInfoParams info = {
        .userID = USER_ID,
        .bundleName = "accesstoken_info_manager_test",
        .instIndex = INST_INDEX,
        .appIDDesc = "accesstoken_info_manager_test"
    };
    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };
    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(info, policy, tokenIdEx));
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    std::shared_ptr<HapTokenInfoInner> infoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddHapTokenInfo(infoPtr));

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: GetHapTokenID002
 * @tc.desc: test GetHapTokenID function abnomal branch
 * @tc.type: FUNC
 * @tc.require: issueI60F1M
 */
HWTEST_F(AccessTokenInfoManagerTest, GetHapTokenID002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = AccessTokenInfoManager::GetInstance().GetHapTokenID(
        USER_ID, "com.ohos.test", INST_INDEX);
    ASSERT_EQ(static_cast<AccessTokenID>(0), tokenIdEx.tokenIDEx);
}

/**
 * @tc.name: AddNativeTokenInfo001
 * @tc.desc: AccessTokenInfoManager::AddNativeTokenInfo function test
 * @tc.type: FUNC
 * @tc.require: issueI62M6G
 */
HWTEST_F(AccessTokenInfoManagerTest, AddNativeTokenInfo001, TestSize.Level1)
{
    std::shared_ptr<NativeTokenInfoInner> info = nullptr;
    ASSERT_EQ(ERR_PARAM_INVALID, AccessTokenInfoManager::GetInstance().AddNativeTokenInfo(info)); // info is null

    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    info = std::make_shared<NativeTokenInfoInner>();
    info->tokenInfoBasic_.tokenID = tokenId;
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenInfoManager::GetInstance().AddNativeTokenInfo(info)); // count(id) > 0

    // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    info->tokenInfoBasic_.tokenID = 672137215;
    info->tokenInfoBasic_.processName = "accesstoken_service";
    // 672137214 is max-1 native tokenId: 001 01 0 000000 11111111111111111110
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[672137214] = info;
    // count(processName) > 0
    ASSERT_EQ(ERR_PROCESS_NOT_EXIST, AccessTokenInfoManager::GetInstance().AddNativeTokenInfo(info));

    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_.erase(672137214);
}

/**
 * @tc.name: RemoveNativeTokenInfo001
 * @tc.desc: AccessTokenInfoManager::RemoveNativeTokenInfo function test
 * @tc.type: FUNC
 * @tc.require: issueI62M6G
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveNativeTokenInfo001, TestSize.Level1)
{
    AccessTokenID tokenId = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId)); // count(id) == 0

    std::shared_ptr<NativeTokenInfoInner> info = std::make_shared<NativeTokenInfoInner>();
    info->isRemote_ = true;
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[tokenId] = info;
    ASSERT_NE(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId)); // remote is true
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_.erase(tokenId);

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_NATIVE));
    info->isRemote_ = false;
    info->tokenInfoBasic_.processName = "testtesttest";
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[tokenId] = info;
    // count(processName) == 0
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId)); // erase in function
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
}

/**
 * @tc.name: TryUpdateExistNativeToken001
 * @tc.desc: AccessTokenInfoManager::TryUpdateExistNativeToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, TryUpdateExistNativeToken001, TestSize.Level1)
{
    std::shared_ptr<NativeTokenInfoInner> infoPtr = nullptr;
    ASSERT_EQ(false, AccessTokenInfoManager::GetInstance().TryUpdateExistNativeToken(infoPtr)); // infoPtr is null
}

/**
 * @tc.name: ProcessNativeTokenInfos001
 * @tc.desc: AccessTokenInfoManager::ProcessNativeTokenInfos function test AddNativeTokenInfo fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, ProcessNativeTokenInfos001, TestSize.Level1)
{
    AccessTokenID tokenId = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    AccessTokenID tokenId2 = 672137214; // 672137214: 001 01 0 000000 11111111111111111110
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;
    std::shared_ptr<NativeTokenInfoInner> info = std::make_shared<NativeTokenInfoInner>();
    info->tokenInfoBasic_.tokenID = tokenId2;
    info->tokenInfoBasic_.processName = "testtesttest";
    ASSERT_NE("", info->tokenInfoBasic_.processName);
    tokenInfos.emplace_back(info);
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[tokenId] = info;
    AccessTokenInfoManager::GetInstance().nativeTokenIdMap_["testtesttest"] = tokenId;
    AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_.erase(tokenId);
    AccessTokenInfoManager::GetInstance().nativeTokenIdMap_.erase("testtesttest");
}

/**
 * @tc.name: Insert001
 * @tc.desc: PermissionDefinitionCache::Insert function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, Insert001, TestSize.Level1)
{
    PermissionDef info = {
        .permissionName = "ohos.permission.CAMERA",
        .bundleName = "com.ohos.test",
        .grantMode = 0,
        .availableLevel = ATokenAplEnum::APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "buzhidao",
        .labelId = 100, // 100 is random input
        .description = "buzhidao",
        .descriptionId = 100 // 100 is random input
    };
    AccessTokenID tokenId = 123; // 123 is random input

    ASSERT_EQ(false, PermissionDefinitionCache::GetInstance().Insert(info, tokenId)); // permission has insert
}

/**
 * @tc.name: IsGrantedModeEqualInner001
 * @tc.desc: PermissionDefinitionCache::IsGrantedModeEqualInner function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, IsGrantedModeEqualInner001, TestSize.Level1)
{
    std::string permissionName = "ohos.permission.CAMERA";
    int grantMode = 0;

    // find permission not reach end
    ASSERT_EQ(true, PermissionDefinitionCache::GetInstance().IsGrantedModeEqualInner(permissionName, grantMode));

    permissionName = "ohos.permission.INVALID";
    // can't find permission
    ASSERT_EQ(false, PermissionDefinitionCache::GetInstance().IsGrantedModeEqualInner(permissionName, grantMode));
}

/**
 * @tc.name: RestorePermDefInfo001
 * @tc.desc: PermissionDefinitionCache::RestorePermDefInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RestorePermDefInfo001, TestSize.Level1)
{
    GenericValues value;
    value.Put(TokenFiledConst::FIELD_AVAILABLE_LEVEL, ATokenAplEnum::APL_INVALID);

    std::vector<GenericValues> values;
    values.emplace_back(value);

    // ret not RET_SUCCESS
    ASSERT_NE(RET_SUCCESS, PermissionDefinitionCache::GetInstance().RestorePermDefInfo(values));
}

/**
 * @tc.name: IsPermissionDefValid001
 * @tc.desc: PermissionValidator::IsPermissionDefValid function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, IsPermissionDefValid001, TestSize.Level1)
{
    PermissionDef permDef = {
        .permissionName = "ohos.permission.TEST",
        .bundleName = "com.ohos.test",
        .grantMode = static_cast<GrantMode>(2),
        .availableLevel = ATokenAplEnum::APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "buzhidao",
        .labelId = 100, // 100 is random input
        .description = "buzhidao",
        .descriptionId = 100 // 100 is random input
    };

    // ret not RET_SUCCESS
    ASSERT_EQ(false, PermissionValidator::IsPermissionDefValid(permDef)); // grant mode invalid

    permDef.grantMode = GrantMode::USER_GRANT;
    permDef.availableType = ATokenAvailableTypeEnum::INVALID;
    ASSERT_EQ(false, PermissionValidator::IsPermissionDefValid(permDef)); // availableType invalid
}

/**
 * @tc.name: IsPermissionStateValid001
 * @tc.desc: PermissionValidator::IsPermissionStateValid function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, IsPermissionStateValid001, TestSize.Level1)
{
    std::string permissionName;
    std::string deviceID = "dev-001";
    int grantState = PermissionState::PERMISSION_DENIED;
    uint32_t grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;

    std::vector<std::string> resDeviceID;
    std::vector<int> grantStates;
    std::vector<uint32_t> grantFlags;

    resDeviceID.emplace_back(deviceID);
    grantStates.emplace_back(grantState);
    grantFlags.emplace_back(grantFlag);

    PermissionStateFull permState = {
        .permissionName = permissionName,
        .isGeneral = false,
        .resDeviceID = resDeviceID,
        .grantStatus = grantStates,
        .grantFlags = grantFlags
    };

    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState)); // permissionName empty

    permState.permissionName = "com.ohos.TEST";
    permState.resDeviceID.emplace_back("dev-002");
    // deviceID nums not equal status nums or flag nums
    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState));

    permState.grantStatus.emplace_back(PermissionState::PERMISSION_DENIED);
    // deviceID nums not equal flag nums
    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState));

    permState.grantFlags.emplace_back(PermissionFlag::PERMISSION_DEFAULT_FLAG);
    ASSERT_EQ(true, PermissionValidator::IsPermissionStateValid(permState));
}

/**
 * @tc.name: FilterInvalidPermissionDef001
 * @tc.desc: PermissionValidator::FilterInvalidPermissionDef function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, FilterInvalidPermissionDef001, TestSize.Level1)
{
    PermissionDef permDef = {
        .permissionName = "ohos.permission.TEST",
        .bundleName = "com.ohos.test",
        .grantMode = GrantMode::SYSTEM_GRANT,
        .availableLevel = ATokenAplEnum::APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "buzhidao",
        .labelId = 100, // 100 is random input
        .description = "buzhidao",
        .descriptionId = 100 // 100 is random input
    };

    std::vector<PermissionDef> permList;
    permList.emplace_back(permDef);
    permList.emplace_back(permDef);

    ASSERT_EQ(static_cast<uint32_t>(2), permList.size());

    std::vector<PermissionDef> result;
    PermissionValidator::FilterInvalidPermissionDef(permList, result); // permDefSet.count != 0
    ASSERT_EQ(static_cast<uint32_t>(1), result.size());
}

/**
 * @tc.name: DeduplicateResDevID001
 * @tc.desc: PermissionValidator::DeduplicateResDevID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, DeduplicateResDevID001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeduplicateResDevID001";
    PermissionStateFull permState = {
        .permissionName = "ohos.permission.TEST",
        .isGeneral = false,
        .resDeviceID = {"dev-001", "dev-001"},
        .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };
    GTEST_LOG_(INFO) << "DeduplicateResDevID001_1";
    ASSERT_EQ(static_cast<uint32_t>(2), permState.resDeviceID.size());

    std::vector<PermissionStateFull> permList;
    permList.emplace_back(permState);
    std::vector<PermissionStateFull> result;
    GTEST_LOG_(INFO) << "DeduplicateResDevID001_2";
    PermissionValidator::FilterInvalidPermissionState(TOKEN_NATIVE, false, permList, result); // resDevId.count != 0
    GTEST_LOG_(INFO) << "DeduplicateResDevID001_3";
    ASSERT_EQ(static_cast<uint32_t>(1), result[0].resDeviceID.size());
}

/**
 * @tc.name: Update001
 * @tc.desc: PermissionPolicySet::Update function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, Update001, TestSize.Level1)
{
    PermissionStateFull perm1 = {
        .permissionName = "ohos.permission.TEST1",
        .isGeneral = false,
        .resDeviceID = {"dev-001", "dev-001"},
        .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };
    PermissionStateFull perm2 = {
        .permissionName = "ohos.permission.TEST2",
        .isGeneral = true,
        .resDeviceID = {"dev-001", "dev-001"},
        .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };
    PermissionStateFull perm3 = {
        .permissionName = "ohos.permission.TEST1",
        .isGeneral = true,
        .resDeviceID = {"dev-001", "dev-001"},
        .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };
    ASSERT_EQ(false, perm1.permissionName == perm2.permissionName);
    ASSERT_EQ(true, perm1.permissionName == perm3.permissionName);
    ASSERT_EQ(false, perm1.isGeneral == perm3.isGeneral);

    AccessTokenID tokenId = 123; // 123 is random input
    std::vector<PermissionStateFull> permStateList1;
    permStateList1.emplace_back(perm1);
    std::vector<PermissionStateFull> permStateList2;
    permStateList1.emplace_back(perm2);
    std::vector<PermissionStateFull> permStateList3;
    permStateList1.emplace_back(perm3);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::BuildPermissionPolicySet(tokenId,
        permStateList1);

    policySet->Update(permStateList2); // iter reach end
    policySet->Update(permStateList3); // permNew.isGeneral != permOld.isGeneral
}

/**
 * @tc.name: RestorePermissionPolicy001
 * @tc.desc: PermissionPolicySet::RestorePermissionPolicy function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RestorePermissionPolicy001, TestSize.Level1)
{
    GenericValues value1;
    value1.Put(TokenFiledConst::FIELD_TOKEN_ID, 123); // 123 is random input
    value1.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, true);
    value1.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.CAMERA");
    value1.Put(TokenFiledConst::FIELD_DEVICE_ID, "dev-001");
    value1.Put(TokenFiledConst::FIELD_GRANT_STATE, static_cast<PermissionState>(3));
    value1.Put(TokenFiledConst::FIELD_GRANT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG);

    AccessTokenID tokenId = 123; // 123 is random input
    std::vector<GenericValues> permStateRes1;
    permStateRes1.emplace_back(value1);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::RestorePermissionPolicy(tokenId,
        permStateRes1); // ret != RET_SUCCESS

    ASSERT_EQ(tokenId, policySet->tokenId_);

    GenericValues value2;
    value2.Put(TokenFiledConst::FIELD_TOKEN_ID, 123); // 123 is random input
    value2.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, true);
    value2.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.CAMERA");
    value2.Put(TokenFiledConst::FIELD_DEVICE_ID, "dev-002");
    value2.Put(TokenFiledConst::FIELD_GRANT_STATE, PermissionState::PERMISSION_DENIED);
    value2.Put(TokenFiledConst::FIELD_GRANT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG);
    GenericValues value3;
    value3.Put(TokenFiledConst::FIELD_TOKEN_ID, 123); // 123 is random input
    value3.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, true);
    value3.Put(TokenFiledConst::FIELD_PERMISSION_NAME, "ohos.permission.CAMERA");
    value3.Put(TokenFiledConst::FIELD_DEVICE_ID, "dev-003");
    value3.Put(TokenFiledConst::FIELD_GRANT_STATE, PermissionState::PERMISSION_DENIED);
    value3.Put(TokenFiledConst::FIELD_GRANT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG);

    std::vector<GenericValues> permStateRes2;
    permStateRes2.emplace_back(value2);
    permStateRes2.emplace_back(value3);

    std::shared_ptr<PermissionPolicySet> policySet2 = PermissionPolicySet::RestorePermissionPolicy(tokenId,
        permStateRes2); // state.permissionName == iter->permissionName
    ASSERT_EQ(static_cast<uint32_t>(2), policySet2->permStateList_[0].resDeviceID.size());
}

/**
 * @tc.name: VerifyPermissionStatus001
 * @tc.desc: PermissionPolicySet::VerifyPermissionStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, VerifyPermissionStatus001, TestSize.Level1)
{
    PermissionStateFull perm = {
        .permissionName = "ohos.permission.TEST",
        .isGeneral = false,
        .resDeviceID = {"dev-001", "dev-001"},
        .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };

    AccessTokenID tokenId = 123; // 123 is random input
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(perm);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::BuildPermissionPolicySet(tokenId,
        permStateList);

    // isGeneral is false
    ASSERT_EQ(PermissionState::PERMISSION_DENIED, policySet->VerifyPermissionStatus("ohos.permission.TEST"));
}

/**
 * @tc.name: QueryPermissionFlag001
 * @tc.desc: PermissionPolicySet::QueryPermissionFlag function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, QueryPermissionFlag001, TestSize.Level1)
{
    PermissionDef def = {
        .permissionName = "ohos.permission.TEST",
        .bundleName = "QueryPermissionFlag001",
        .grantMode = 1,
        .availableLevel = APL_NORMAL,
        .provisionEnable = false,
        .distributedSceneEnable = false,
        .label = "label",
        .labelId = 1,
        .description = "description",
        .descriptionId = 1
    };
    PermissionStateFull perm = {
        .permissionName = "ohos.permission.TEST",
        .isGeneral = false,
        .resDeviceID = {"dev-001", "dev-001"},
        .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };

    AccessTokenID tokenId = 0x280bc140; // 0x280bc140 is random native
    PermissionDefinitionCache::GetInstance().Insert(def, tokenId);
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(perm);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::BuildPermissionPolicySet(tokenId,
        permStateList);

    // perm.permissionName != permissionName
    int flag = 0;
    ASSERT_EQ(ERR_PERMISSION_NOT_EXIST, policySet->QueryPermissionFlag("ohos.permission.TEST1", flag));
    // isGeneral is false
    ASSERT_EQ(ERR_PARAM_INVALID, policySet->QueryPermissionFlag("ohos.permission.TEST", flag));

    perm.isGeneral = true;
    std::shared_ptr<PermissionPolicySet> policySet1 = PermissionPolicySet::BuildPermissionPolicySet(tokenId,
        permStateList);
    // isGeneral is true
    ASSERT_EQ(ERR_PARAM_INVALID, policySet1->QueryPermissionFlag("ohos.permission.TEST", flag));
}

/**
 * @tc.name: UpdatePermissionStatus001
 * @tc.desc: PermissionPolicySet::UpdatePermissionStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdatePermissionStatus001, TestSize.Level1)
{
    PermissionStateFull perm = {
        .permissionName = "ohos.permission.TEST",
        .isGeneral = false,
        .resDeviceID = {"dev-001", "dev-001"},
        .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };

    AccessTokenID tokenId = 789; // 789 is random input
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(perm);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::BuildPermissionPolicySet(tokenId,
        permStateList);

    // iter reach the end
    bool isGranted = false;
    uint32_t flag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    ASSERT_EQ(ERR_PARAM_INVALID, policySet->UpdatePermissionStatus("ohos.permission.TEST1",
        isGranted, flag));

    // isGeneral is false
    ASSERT_EQ(RET_SUCCESS, policySet->UpdatePermissionStatus("ohos.permission.TEST",
        isGranted, flag));
}

/**
 * @tc.name: ResetUserGrantPermissionStatus001
 * @tc.desc: PermissionPolicySet::ResetUserGrantPermissionStatus function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, ResetUserGrantPermissionStatus001, TestSize.Level1)
{
    PermissionStateFull perm = {
        .permissionName = "ohos.permission.TEST",
        .isGeneral = false,
        .resDeviceID = {"dev-001", "dev-001"},
        .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };

    AccessTokenID tokenId = 1011; // 1011 is random input
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(perm);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::BuildPermissionPolicySet(tokenId,
        permStateList);

    ASSERT_EQ(tokenId, policySet->tokenId_);

    // isGeneral is false
    policySet->ResetUserGrantPermissionStatus();
}

/**
 * @tc.name: PermStateFullToString001
 * @tc.desc: PermissionPolicySet::PermStateFullToString function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, PermStateFullToString001, TestSize.Level1)
{
    AccessTokenID tokenId = 123; // 123 is random input
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(g_permState);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::BuildPermissionPolicySet(tokenId,
        permStateList);

    ASSERT_EQ(tokenId, policySet->tokenId_);

    std::string info;
    // iter != end - 1
    policySet->PermStateFullToString(g_permState, info);
}

/**
 * @tc.name: MapRemoteDeviceTokenToLocal001
 * @tc.desc: AccessTokenRemoteTokenManager::MapRemoteDeviceTokenToLocal function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, MapRemoteDeviceTokenToLocal001, TestSize.Level1)
{
    std::map<std::string, AccessTokenRemoteDevice> remoteDeviceMap;
    remoteDeviceMap = AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_; // backup
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.clear();

    std::string deviceID;
    AccessTokenID remoteID = 0;

    // input invalid
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID));

    remoteID = 940572671; // 940572671 is max butt tokenId: 001 11 0 000000 11111111111111111111
    deviceID = "dev-001";

    // tokeType invalid
    ASSERT_EQ(static_cast<AccessTokenID>(0),
        AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID));

    remoteID = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111, no need to register
    std::map<AccessTokenID, AccessTokenID> MappingTokenIDPairMap;
    MappingTokenIDPairMap[537919487] = 456; // 456 is random input
    AccessTokenRemoteDevice device = {
        .DeviceID_ = "dev-001",
        .MappingTokenIDPairMap_ = MappingTokenIDPairMap
    };
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_["dev-001"] = device;

    // count(remoteID) > 0
    ASSERT_EQ(static_cast<AccessTokenID>(456),
        AccessTokenRemoteTokenManager::GetInstance().MapRemoteDeviceTokenToLocal(deviceID, remoteID));

    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_ = remoteDeviceMap; // recovery
}

/**
 * @tc.name: GetDeviceAllRemoteTokenID001
 * @tc.desc: AccessTokenRemoteTokenManager::GetDeviceAllRemoteTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetDeviceAllRemoteTokenID001, TestSize.Level1)
{
    std::string deviceID;
    std::vector<AccessTokenID> remoteIDs;

    // deviceID invalid
    ASSERT_EQ(ERR_PARAM_INVALID,
        AccessTokenRemoteTokenManager::GetInstance().GetDeviceAllRemoteTokenID(deviceID, remoteIDs));
}

/**
 * @tc.name: RemoveDeviceMappingTokenID001
 * @tc.desc: AccessTokenRemoteTokenManager::RemoveDeviceMappingTokenID function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveDeviceMappingTokenID001, TestSize.Level1)
{
    std::map<std::string, AccessTokenRemoteDevice> remoteDeviceMap;
    remoteDeviceMap = AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_; // backup
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.clear();

    std::string deviceID;
    AccessTokenID remoteID = 0;

    // input invalid
    ASSERT_NE(RET_SUCCESS,
        AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, remoteID));

    deviceID = "dev-001";
    remoteID = 123; // 123 is random input

    // count < 1
    ASSERT_NE(RET_SUCCESS,
        AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, remoteID));

    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_ = remoteDeviceMap; // recovery
}

/**
 * @tc.name: AddHapTokenObservation001
 * @tc.desc: TokenModifyNotifier::AddHapTokenObservation function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AddHapTokenObservation001, TestSize.Level1)
{
    std::set<AccessTokenID> observationSet = TokenModifyNotifier::GetInstance().observationSet_; // backup
    TokenModifyNotifier::GetInstance().observationSet_.clear();

    AccessTokenID tokenId = 123; // 123 is random input

    TokenModifyNotifier::GetInstance().observationSet_.insert(tokenId);
    ASSERT_EQ(true, TokenModifyNotifier::GetInstance().observationSet_.count(tokenId) > 0);

    // count > 0
    TokenModifyNotifier::GetInstance().AddHapTokenObservation(tokenId);
    TokenModifyNotifier::GetInstance().NotifyTokenModify(tokenId);

    TokenModifyNotifier::GetInstance().observationSet_ = observationSet; // recovery
}

/**
 * @tc.name: RestoreNativeTokenInfo001
 * @tc.desc: NativeTokenInfoInner::RestoreNativeTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RestoreNativeTokenInfo001, TestSize.Level1)
{
    std::shared_ptr<NativeTokenInfoInner> native = std::make_shared<NativeTokenInfoInner>();
    ASSERT_NE(nullptr, native);

    std::string info;
    native->ToString(info); // permPolicySet_ is null

    AccessTokenID tokenId = 0;
    std::string processName;
    int apl = static_cast<int>(ATokenAplEnum::APL_INVALID);
    int version = 10; // 10 is random input which only need not equal 1
    std::vector<std::string> dcap;
    std::vector<std::string> nativeAcls;
    std::vector<PermissionStateFull> permStateList;
    GenericValues inGenericValues;
    std::vector<GenericValues> permStateRes;

    // processName invalid
    TokenInfo tokenInfo = {
        .id = tokenId,
        .processName = processName,
        .apl = apl
    };
    ASSERT_NE(RET_SUCCESS, native->Init(tokenInfo, dcap, nativeAcls, permStateList));

    inGenericValues.Put(TokenFiledConst::FIELD_PROCESS_NAME, processName);
    // processName invalid
    ASSERT_NE(RET_SUCCESS, native->RestoreNativeTokenInfo(tokenId, inGenericValues, permStateRes));
    inGenericValues.Remove(TokenFiledConst::FIELD_PROCESS_NAME);

    tokenInfo.processName = "token_sync";
    // apl invalid
    ASSERT_NE(RET_SUCCESS, native->Init(tokenInfo, dcap, nativeAcls, permStateList));

    inGenericValues.Put(TokenFiledConst::FIELD_PROCESS_NAME, processName);
    inGenericValues.Put(TokenFiledConst::FIELD_APL, apl);
    // apl invalid
    ASSERT_NE(RET_SUCCESS, native->RestoreNativeTokenInfo(tokenId, inGenericValues, permStateRes));
    inGenericValues.Remove(TokenFiledConst::FIELD_APL);

    apl = static_cast<int>(ATokenAplEnum::APL_NORMAL);
    inGenericValues.Put(TokenFiledConst::FIELD_APL, apl);
    inGenericValues.Put(TokenFiledConst::FIELD_TOKEN_VERSION, version);
    // version invalid
    ASSERT_NE(RET_SUCCESS, native->RestoreNativeTokenInfo(tokenId, inGenericValues, permStateRes));
}

/**
 * @tc.name: Init001
 * @tc.desc: NativeTokenInfoInner::Init function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, Init001, TestSize.Level1)
{
    std::shared_ptr<NativeTokenInfoInner> native = std::make_shared<NativeTokenInfoInner>();
    ASSERT_NE(nullptr, native);

    AccessTokenID tokenId = 0;
    std::string processName = "tdd_0112";
    int apl = static_cast<int>(ATokenAplEnum::APL_NORMAL);
    std::vector<std::string> dcap;
    std::vector<std::string> nativeAcls;
    std::vector<PermissionStateFull> permStateList;

    // processName invalid
    TokenInfo tokenInfo = {
        .id = tokenId,
        .processName = processName,
        .apl = apl
    };
    ASSERT_EQ(RET_SUCCESS, native->Init(tokenInfo, dcap, nativeAcls, permStateList));
    native->GetNativeAcls();
    native->SetRemote(true);
    ASSERT_EQ(true, native->IsRemote());
}

/**
 * @tc.name: RestoreHapTokenInfo001
 * @tc.desc: HapTokenInfoInner::RestoreHapTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RestoreHapTokenInfo001, TestSize.Level1)
{
    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ASSERT_NE(nullptr, hap);

    AccessTokenID tokenId = 0;
    GenericValues tokenValue;
    std::vector<GenericValues> permStateRes;
    std::string bundleName;
    std::string appIDDesc;
    std::string deviceID;
    int aplNum = static_cast<int>(ATokenAplEnum::APL_INVALID);
    int version = 10; // 10 is random input which only need not equal 1
    HapPolicyParams policy;
    UpdateHapInfoParams hapInfo;
    hapInfo.apiVersion = DEFAULT_API_VERSION;
    hapInfo.isSystemApp = false;
    hap->Update(hapInfo, policy.permStateList, policy.apl); // permPolicySet_ is null

    std::string info;
    hap->ToString(info); // permPolicySet_ is null

    std::vector<GenericValues> hapInfoValues;
    std::vector<GenericValues> permStateValues;
    hap->StoreHapInfo(hapInfoValues);
    hap->StorePermissionPolicy(permStateValues); // permPolicySet_ is null


    tokenValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    // bundleName invalid
    ASSERT_EQ(ERR_PARAM_INVALID, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));
    tokenValue.Remove(TokenFiledConst::FIELD_BUNDLE_NAME);

    bundleName = "com.ohos.permissionmanger";
    tokenValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    tokenValue.Put(TokenFiledConst::FIELD_APP_ID, appIDDesc);
    // appID invalid
    ASSERT_EQ(ERR_PARAM_INVALID, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));
    tokenValue.Remove(TokenFiledConst::FIELD_APP_ID);

    appIDDesc = "what's this";
    tokenValue.Put(TokenFiledConst::FIELD_APP_ID, appIDDesc);
    tokenValue.Put(TokenFiledConst::FIELD_DEVICE_ID, deviceID);
    // deviceID invalid
    ASSERT_EQ(ERR_PARAM_INVALID, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));
    tokenValue.Remove(TokenFiledConst::FIELD_DEVICE_ID);

    deviceID = "dev-001";
    tokenValue.Put(TokenFiledConst::FIELD_DEVICE_ID, deviceID);
    tokenValue.Put(TokenFiledConst::FIELD_APL, aplNum);
    // apl invalid
    ASSERT_EQ(ERR_PARAM_INVALID, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));

    aplNum = static_cast<int>(ATokenAplEnum::APL_NORMAL);
    tokenValue.Put(TokenFiledConst::FIELD_APL, aplNum);
    tokenValue.Put(TokenFiledConst::FIELD_TOKEN_VERSION, version);
    // version invalid
    ASSERT_EQ(ERR_PARAM_INVALID, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));
}

/**
 * @tc.name: RegisterTokenId001
 * @tc.desc: AccessTokenIDManager::RegisterTokenId function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, RegisterTokenId001, TestSize.Level1)
{
    // 1477443583 is max abnormal butt tokenId which version is 2: 010 11 0 000000 11111111111111111111
    AccessTokenID tokenId = 1477443583;
    ATokenTypeEnum type = ATokenTypeEnum::TOKEN_HAP;

    // version != 1 + type dismatch
    ASSERT_NE(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, type));

    AccessTokenIDEx tokenIdEx = {0};
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(g_infoManagerTestInfoParms,
        g_infoManagerTestPolicyPrams1, tokenIdEx));

    // register repeat
    ASSERT_NE(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(
        tokenIdEx.tokenIdExStruct.tokenID, type));
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: DumpTokenInfo005
 * @tc.desc: AccessTokenInfoManager::DumpTokenInfo function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, DumpTokenInfo005, TestSize.Level1)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP));
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = tokenId;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo); // hap infoPtr is null
    ASSERT_EQ("", dumpInfo);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);

    tokenId = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_NATIVE));
    info.tokenId = tokenId;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo); // native infoPtr is null
    ASSERT_EQ("", dumpInfo);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);

    std::shared_ptr<HapTokenInfoInner> hap = nullptr;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[537919487] = hap;
    info.tokenId = static_cast<AccessTokenID>(0);
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo); // iter->second is null
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(537919487);

    std::shared_ptr<NativeTokenInfoInner> native = nullptr;
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[672137215] = native;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(info, dumpInfo); // iter->second is null
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_.erase(672137215);
}

/**
 * @tc.name: ClearAllSecCompGrantedPerm001
 * @tc.desc: ClearAllSecCompGrantedPerm function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, ClearAllSecCompGrantedPerm001, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    ASSERT_EQ(
        PERMISSION_DENIED, PermissionManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));
    PermissionManager::GetInstance().GrantPermission(tokenId, "ohos.permission.LOCATION", PERMISSION_COMPONENT_SET);
    ASSERT_EQ(
        PERMISSION_GRANTED, PermissionManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));

    std::string deviceId;
    atManagerService_->OnRemoveSystemAbility(SECURITY_COMPONENT_SERVICE_ID, deviceId);
    ASSERT_EQ(
        PERMISSION_DENIED, PermissionManager::GetInstance().VerifyAccessToken(tokenId, "ohos.permission.LOCATION"));

    // delete test token
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: ClearAllSecCompGrantedPerm002
 * @tc.desc: PermissionManager::ClearAllSecCompGrantedPerm function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, ClearAllSecCompGrantedPerm002, TestSize.Level1)
{
    AccessTokenID tokenId = 123; // 123 is random input
    std::vector<AccessTokenID> idList;
    idList.emplace_back(tokenId);
    PermissionManager::GetInstance().ClearAllSecCompGrantedPerm(idList); // permPolicySet is null
    auto tokenInfoPtr = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_EQ(tokenInfoPtr, nullptr);
}

/**
 * @tc.name: SetPermDialogCap001
 * @tc.desc: SetPermDialogCap with HapUniqueKey not exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, SetPermDialogCap001, TestSize.Level1)
{
    AccessTokenID tokenId = 123; // 123: invalid tokenid
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true));
}

/**
 * @tc.name: SetPermDialogCap002
 * @tc.desc: SetPermDialogCap with abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, SetPermDialogCap002, TestSize.Level1)
{
    AccessTokenIDEx tokenIdEx = {0};
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;

    // SetPermDialogCap successfull
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true));
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, false));
    ASSERT_EQ(false, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));

    std::shared_ptr<HapTokenInfoInner> back = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId];

    // tokeninfo of hapTokenInfoMap_ is nullptr, return true(forbid)
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true)); // info is null
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));

    // token is not found in hapTokenInfoMap_, return true(forbid)
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
    ASSERT_EQ(ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().SetPermDialogCap(tokenId, true)); // info is null
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(tokenId));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = back;
    
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: GetPermDialogCap001
 * @tc.desc: GetPermDialogCap with abnormal branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetPermDialogCap001, TestSize.Level1)
{
    // invalid token
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(INVALID_TOKENID));

    // nonexist token
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(123)); // 123: tokenid

    // tokeninfo is nullptr
    HapBaseInfo baseInfo = {
        .userID = g_infoManagerTestInfoParms.userID,
        .bundleName = g_infoManagerTestInfoParms.bundleName,
        .instIndex = g_infoManagerTestInfoParms.instIndex,
    };
    AccessTokenIDEx tokenIdEx = {0};
    int32_t ret = AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams1, tokenIdEx);
    ASSERT_EQ(RET_SUCCESS, ret);
    AccessTokenID tokenId = tokenIdEx.tokenIdExStruct.tokenID;
    std::shared_ptr<HapTokenInfoInner> back = AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId];
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_EQ(true, AccessTokenInfoManager::GetInstance().GetPermDialogCap(123)); // 123: tokenid

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = back;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: AllocHapToken001
 * @tc.desc: alloc hap create haptokeninfo failed.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AllocHapToken001, TestSize.Level1)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = -1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
        .isSystemApp = false,
    };
    HapPolicyParcel hapPolicyParcel;
    hapPolicyParcel.hapPolicyParameter.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicyParameter.domain = "test.domain";

    AccessTokenIDEx tokenIDEx = atManagerService_->AllocHapToken(hapinfoParcel, hapPolicyParcel);
    ASSERT_EQ(INVALID_TOKENID, tokenIDEx.tokenIDEx);
}

/**
 * @tc.name: OnStart001
 * @tc.desc: service is running.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, OnStart001, TestSize.Level1)
{
    ServiceRunningState state = atManagerService_->state_;
    atManagerService_->state_ = ServiceRunningState::STATE_RUNNING;
    atManagerService_->OnStart();
    ASSERT_EQ(ServiceRunningState::STATE_RUNNING, atManagerService_->state_);
    atManagerService_->state_ = state;
}

/**
 * @tc.name: Dlopen001
 * @tc.desc: Open a not exist lib & not exist func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, Dlopen001, TestSize.Level1)
{
    LibraryLoader loader1("libnotexist.z.so"); // is a not exist path
    EXPECT_EQ(nullptr, loader1.handle_);

    LibraryLoader loader2("libaccesstoken_manager_service.z.so"); // is a exist lib without create func
    EXPECT_EQ(nullptr, loader2.instance_);
    EXPECT_NE(nullptr, loader2.handle_);
}

/**
 * @tc.name: Dlopen002
 * @tc.desc: Open a exist lib & exist func
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, Dlopen002, TestSize.Level1)
{
    LibraryLoader loader(TOKEN_SYNC_LIBPATH);
    TokenSyncKitInterface* tokenSyncKit = loader.GetObject<TokenSyncKitInterface>();
    EXPECT_NE(nullptr, loader.handle_);
    EXPECT_NE(nullptr, tokenSyncKit);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
