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
#include "accesstoken_id_manager.h"
#include "accesstoken_log.h"
#include "access_token_error.h"
#include "atm_device_state_callback.h"
#ifdef SUPPORT_SANDBOX_APP
#define private public
#include "dlp_permission_set_manager.h"
#include "dlp_permission_set_parser.h"
#undef private
#endif
#define private public
#include "accesstoken_info_manager.h"
#include "dm_device_info.h"
#include "field_const.h"
#include "hap_token_info_inner.h"
#include "native_token_info_inner.h"
#include "permission_definition_cache.h"
#include "permission_manager.h"
#include "permission_policy_set.h"
#undef private
#include "permission_state_change_callback_stub.h"
#include "permission_validator.h"
#include "string_ex.h"
#include "token_sync_manager_client.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "AccessTokenInfoManagerTest"
};
static constexpr uint32_t MAX_CALLBACK_SIZE = 1024;
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

static HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};

static PermissionStateFull g_infoManagerTestStateA = {
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PERMISSION_GRANTED},
    .grantFlags = {1}
};
static PermissionStateFull g_infoManagerTestStateB = {
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PERMISSION_GRANTED},
    .grantFlags = {1}
};
static PermissionStateFull g_infoManagerTestStateC = {
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PERMISSION_GRANTED},
    .grantFlags = {1}
};
static PermissionStateFull g_infoManagerTestStateD = {
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PERMISSION_GRANTED},
    .grantFlags = {1}
};

static PermissionDef g_infoManagerPermDef1 = {
    .permissionName = "ohos.permission.MEDIA_LOCATION",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "MEDIA_LOCATION",
    .descriptionId = 1
};
static PermissionDef g_infoManagerPermDef2 = {
    .permissionName = "ohos.permission.MICROPHONE",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "MICROPHONE",
    .descriptionId = 1
};
static PermissionDef g_infoManagerPermDef3 = {
    .permissionName = "ohos.permission.READ_CALENDAR",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "READ_CALENDAR",
    .descriptionId = 1
};
static PermissionDef g_infoManagerPermDef4 = {
    .permissionName = "ohos.permission.READ_CALL_LOG",
    .bundleName = "accesstoken_test",
    .grantMode = USER_GRANT,
    .availableLevel = APL_NORMAL,
    .provisionEnable = false,
    .distributedSceneEnable = false,
    .label = "label",
    .labelId = 1,
    .description = "READ_CALL_LOG",
    .descriptionId = 1
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
}

void AccessTokenInfoManagerTest::TearDown()
{
    atManagerService_ = nullptr;
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
 * @tc.require: issueI5YR8M
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
 * @tc.require: issueI5YR8M
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
 * @tc.require: issueI5YR8M
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
 * @tc.require: issueI5YR8M
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
 * @tc.require: issueI5YR8M
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
 * @tc.require: issueI5YR8M
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
 * @tc.name: GetHapPermissionPolicySet001
 * @tc.desc: Verify the GetHapPermissionPolicySet abnormal and normal branch.
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
 * @tc.name: RemoveHapTokenInfo002
 * @tc.desc: AccessTokenInfoManager::RemoveHapTokenInfo function test count(id)
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveHapTokenInfo002, TestSize.Level1)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}

/**
 * @tc.name: RemoveHapTokenInfo003
 * @tc.desc: AccessTokenInfoManager::RemoveHapTokenInfo function test info is null
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveHapTokenInfo003, TestSize.Level1)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: RemoveHapTokenInfo004
 * @tc.desc: AccessTokenInfoManager::RemoveHapTokenInfo function test count(HapUniqueKey) == 0
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveHapTokenInfo004, TestSize.Level1)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->tokenInfoBasic_.userID = USER_ID;
    info->tokenInfoBasic_.bundleName = "com.ohos.testtesttest";
    info->tokenInfoBasic_.instIndex = INST_INDEX;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    ASSERT_EQ(0, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
}

/**
 * @tc.name: RemoveHapTokenInfo005
 * @tc.desc: AccessTokenInfoManager::RemoveHapTokenInfo function test hapTokenIdMap_[HapUniqueKey] != id
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveHapTokenInfo005, TestSize.Level1)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    AccessTokenID tokenId2 = 537919486; // 537919486: 001 00 0 000000 11111111111111111110
    AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP);
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->tokenInfoBasic_.userID = USER_ID;
    info->tokenInfoBasic_.bundleName = "com.ohos.testtesttest";
    info->tokenInfoBasic_.instIndex = INST_INDEX;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    std::string hapUniqueKey = "com.ohos.testtesttest&" + std::to_string(USER_ID) + "&" + std::to_string(INST_INDEX);
    AccessTokenInfoManager::GetInstance().hapTokenIdMap_[hapUniqueKey] = tokenId2;
    ASSERT_EQ(0, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
    AccessTokenInfoManager::GetInstance().hapTokenIdMap_.erase(hapUniqueKey);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
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

/**
 * @tc.name: UpdateHapToken003
 * @tc.desc: AccessTokenInfoManager::UpdateHapToken function test IsRemote_ true
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateHapToken003, TestSize.Level1)
{
    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    std::shared_ptr<HapTokenInfoInner> info = std::make_shared<HapTokenInfoInner>();
    info->isRemote_ = true;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = info;
    std::string appIDDesc = "who cares";
    int32_t apiVersion = DEFAULT_API_VERSION;
    HapPolicyParams policy;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().UpdateHapToken(tokenId, appIDDesc, apiVersion, policy));
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
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
 * @tc.name: GetHapTokenSync002
 * @tc.desc: AccessTokenInfoManager::GetHapTokenSync function test permSetPtr is null
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
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
    EXPECT_NE(0, static_cast<int>(tokenId));
    PermStateChangeScope inScopeInfo;
    PermStateChangeScope outScopeInfo;
    PermStateChangeScope emptyScopeInfo;

    // both empty
    inScopeInfo.permList = {};
    inScopeInfo.tokenIDs = {};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.tokenIDs = {123};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(true, outScopeInfo.tokenIDs.empty());

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.tokenIDs.clear();
    inScopeInfo.tokenIDs = {123, tokenId, tokenId};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(1, static_cast<int>(outScopeInfo.tokenIDs.size()));

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.tokenIDs.clear();
    inScopeInfo.permList = {"ohos.permission.test"};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(true, outScopeInfo.permList.empty());

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.permList.clear();
    inScopeInfo.permList = {"ohos.permission.test", "ohos.permission.CAMERA", "ohos.permission.CAMERA"};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(1, static_cast<int>(outScopeInfo.permList.size()));

    outScopeInfo = emptyScopeInfo;
    inScopeInfo.permList.clear();
    inScopeInfo.tokenIDs = {123, tokenId, tokenId};
    inScopeInfo.permList = {"ohos.permission.test", "ohos.permission.CAMERA", "ohos.permission.CAMERA"};
    EXPECT_EQ(RET_SUCCESS, PermissionManager::GetInstance().ScopeFilter(inScopeInfo, outScopeInfo));
    EXPECT_EQ(1, static_cast<int>(outScopeInfo.tokenIDs.size()));
    EXPECT_EQ(1, static_cast<int>(outScopeInfo.permList.size()));

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

    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, nullptr));

    inScopeInfo.permList = {"ohos.permission.CAMERA"};
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        PermissionManager::GetInstance().AddPermStateChangeCallback(inScopeInfo, nullptr));
    EXPECT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        PermissionManager::GetInstance().RemovePermStateChangeCallback(nullptr));
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
    EXPECT_NE(0, static_cast<int>(tokenId));
    std::string dumpInfo;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(tokenId, dumpInfo);
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

/**
 * @tc.name: RevokePermission001
 * @tc.desc: Test RevokePermission abnormal branch.
 * @tc.type: FUNC
 * @tc.require: issueI5SSXG
 */
HWTEST_F(AccessTokenInfoManagerTest, RevokePermission001, TestSize.Level1)
{
    int32_t ret;
    AccessTokenID tokenID = 0;
    ret = PermissionManager::GetInstance().RevokePermission(tokenID, "", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
    ret = PermissionManager::GetInstance().RevokePermission(tokenID, "ohos.perm", PERMISSION_USER_FIXED);
    ASSERT_EQ(AccessTokenError::ERR_PERMISSION_NOT_EXIT, ret);
    int32_t invalidFlag = -1;
    ret = PermissionManager::GetInstance().RevokePermission(tokenID, "ohos.permission.READ_CALENDAR", invalidFlag);
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, ret);
}

/**
 * @tc.name: AccessTokenInfoManager001
 * @tc.desc: AccessTokenInfoManager::~AccessTokenInfoManager+Init function test hasInited_ is false
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
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
 * @tc.require: issueI5YR8M
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
 * @tc.require: issueI5YR8M
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
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, AddHapTokenInfo002, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(USER_ID, "com.ohos.photos", INST_INDEX);
    std::shared_ptr<HapTokenInfoInner> info = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddHapTokenInfo(info));
}

/**
 * @tc.name: AddNativeTokenInfo001
 * @tc.desc: AccessTokenInfoManager::AddNativeTokenInfo function test info is null
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, AddNativeTokenInfo001, TestSize.Level1)
{
    std::shared_ptr<NativeTokenInfoInner> info = nullptr;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddNativeTokenInfo(info));
}

/**
 * @tc.name: AddNativeTokenInfo002
 * @tc.desc: AccessTokenInfoManager::AddNativeTokenInfo function test count(id) > 0
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, AddNativeTokenInfo002, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    std::shared_ptr<NativeTokenInfoInner> info = std::make_shared<NativeTokenInfoInner>();
    info->tokenInfoBasic_.tokenID = tokenId;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddNativeTokenInfo(info));
}

/**
 * @tc.name: RemoveNativeTokenInfo001
 * @tc.desc: AccessTokenInfoManager::RemoveNativeTokenInfo function test count(id) == 0
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveNativeTokenInfo001, TestSize.Level1)
{
    AccessTokenID tokenId = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId));
}

/**
 * @tc.name: RemoveNativeTokenInfo002
 * @tc.desc: AccessTokenInfoManager::RemoveNativeTokenInfo function test isRemote_ true
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveNativeTokenInfo002, TestSize.Level1)
{
    AccessTokenID tokenId = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    std::shared_ptr<NativeTokenInfoInner> info = std::make_shared<NativeTokenInfoInner>();
    info->isRemote_ = true;
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[tokenId] = info;
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId));
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: RemoveNativeTokenInfo003
 * @tc.desc: AccessTokenInfoManager::RemoveNativeTokenInfo function test count(processName) == 0
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, RemoveNativeTokenInfo003, TestSize.Level1)
{
    AccessTokenID tokenId = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_NATIVE);
    std::shared_ptr<NativeTokenInfoInner> info = std::make_shared<NativeTokenInfoInner>();
    info->isRemote_ = false;
    info->tokenInfoBasic_.processName = "testtesttest";
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[tokenId] = info;
    ASSERT_EQ(0, AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId));
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_.erase(tokenId);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);
}

/**
 * @tc.name: TryUpdateExistNativeToken001
 * @tc.desc: AccessTokenInfoManager::TryUpdateExistNativeToken function test infoPtr is null
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
 */
HWTEST_F(AccessTokenInfoManagerTest, TryUpdateExistNativeToken001, TestSize.Level1)
{
    std::shared_ptr<NativeTokenInfoInner> infoPtr = nullptr;
    ASSERT_EQ(false, AccessTokenInfoManager::GetInstance().TryUpdateExistNativeToken(infoPtr));
}

/**
 * @tc.name: ProcessNativeTokenInfos001
 * @tc.desc: AccessTokenInfoManager::ProcessNativeTokenInfos function test AddNativeTokenInfo fail
 * @tc.type: FUNC
 * @tc.require: issueI5YR8M
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
 * @tc.name: OnDeviceOnline001
 * @tc.desc: AtmDeviceStateCallbackTest::OnDeviceOnline function test
 * @tc.type: FUNC
 * @tc.require: IssueI60IB3
 */
HWTEST_F(AccessTokenInfoManagerTest, OnDeviceOnline001, TestSize.Level1)
{
    ASSERT_NE(nullptr, TokenSyncManagerClient::GetInstance().GetRemoteObject());

    DistributedHardware::DmDeviceInfo deviceInfo;
    std::shared_ptr<AtmDeviceStateCallback> callback = std::make_shared<AtmDeviceStateCallback>();
    callback->OnDeviceOnline(deviceInfo); // remote object is not nullptr
}

/**
 * @tc.name: VerifyAccessToken001
 * @tc.desc: VerifyAccessToken with permission is invalid
 * @tc.type: FUNC
 * @tc.require: IssueI60IB3
 */
HWTEST_F(AccessTokenInfoManagerTest, VerifyAccessToken001, TestSize.Level1)
{
    HapInfoParcel hapInfoParcel;
    HapPolicyParcel haoPolicyParcel;
    hapInfoParcel.hapInfoParameter = g_infoManagerTestInfoParms;
    haoPolicyParcel.hapPolicyParameter = g_infoManagerTestPolicyPrams;
    AccessTokenIDEx tokenIdEx = atManagerService_->AllocHapToken(hapInfoParcel, haoPolicyParcel);

    ASSERT_EQ(PERMISSION_DENIED, atManagerService_->VerifyAccessToken(tokenIdEx.tokenIdExStruct.tokenID, ""));
    // delete test token
    ASSERT_EQ(RET_SUCCESS, atManagerService_->DeleteToken(tokenIdEx.tokenIdExStruct.tokenID));
}

/**
 * @tc.name: Insert001
 * @tc.desc: PermissionDefinitionCache::Insert function test
 * @tc.type: FUNC
 * @tc.require: IssueI61OOX
 */
HWTEST_F(AccessTokenInfoManagerTest, Insert001, TestSize.Level1)
{
    PermissionDef info = {
        .permissionName = "ohos.permission.CAMERA",
        .bundleName = "com.ohos.camera",
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
 * @tc.require: IssueI61OOX
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
 * @tc.require: IssueI61OOX
 */
HWTEST_F(AccessTokenInfoManagerTest, RestorePermDefInfo001, TestSize.Level1)
{
    GenericValues value;
    value.Put(FIELD_AVAILABLE_LEVEL, ATokenAplEnum::APL_INVALID);

    std::vector<GenericValues> values;
    values.emplace_back(value);

    // ret not RET_SUCCESS
    ASSERT_EQ(RET_FAILED, PermissionDefinitionCache::GetInstance().RestorePermDefInfo(values));
}

/**
 * @tc.name: IsPermissionDefValid001
 * @tc.desc: PermissionValidator::IsPermissionDefValid function test
 * @tc.type: FUNC
 * @tc.require: IssueI61OOX
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
}

/**
 * @tc.name: IsPermissionStateValid001
 * @tc.desc: PermissionValidator::IsPermissionStateValid function test
 * @tc.type: FUNC
 * @tc.require: IssueI61OOX
 */
HWTEST_F(AccessTokenInfoManagerTest, IsPermissionStateValid001, TestSize.Level1)
{
    std::string permissionName;
    std::string deviceID = "dev-001";
    int grantState = PermissionState::PERMISSION_DENIED;
    int grantFlag = PermissionFlag::PERMISSION_DEFAULT_FLAG;

    std::vector<std::string> resDeviceID;
    std::vector<int> grantStates;
    std::vector<int> grantFlags;

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

    permState.resDeviceID.emplace_back("dev-002");
    // deviceID nums not eauql status nums or flag nums
    ASSERT_EQ(false, PermissionValidator::IsPermissionStateValid(permState));
}

/**
 * @tc.name: FilterInvalidPermissionDef001
 * @tc.desc: PermissionValidator::FilterInvalidPermissionDef function test
 * @tc.type: FUNC
 * @tc.require: IssueI61OOX
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
 * @tc.require: IssueI61OOX
 */
HWTEST_F(AccessTokenInfoManagerTest, DeduplicateResDevID001, TestSize.Level1)
{
    PermissionStateFull permState = {
        .permissionName = "ohos.permission.TEST",
        .isGeneral = false,
        .resDeviceID = {"dev-001", "dev-001"},
        .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
    };

    ASSERT_EQ(static_cast<uint32_t>(2), permState.resDeviceID.size());

    std::vector<PermissionStateFull> permList;
    permList.emplace_back(permState);
    std::vector<PermissionStateFull> result;

    PermissionValidator::FilterInvalidPermissionState(permList, result); // resDevId.count != 0
    ASSERT_EQ(static_cast<uint32_t>(1), result[0].resDeviceID.size());
}

/**
 * @tc.name: Update001
 * @tc.desc: PermissionPolicySet::Update function test
 * @tc.type: FUNC
 * @tc.require: IssueI61OOX
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
 * @tc.require: IssueI61OOX
 */
HWTEST_F(AccessTokenInfoManagerTest, RestorePermissionPolicy001, TestSize.Level1)
{
    GenericValues value1;
    value1.Put(FIELD_TOKEN_ID, 123); // 123 is random input
    value1.Put(FIELD_GRANT_IS_GENERAL, true);
    value1.Put(FIELD_PERMISSION_NAME, "ohos.permission.CAMERA");
    value1.Put(FIELD_DEVICE_ID, "dev-001");
    value1.Put(FIELD_GRANT_STATE, static_cast<PermissionState>(3));
    value1.Put(FIELD_GRANT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG);

    AccessTokenID tokenId = 123; // 123 is random input
    std::vector<GenericValues> permStateRes1;
    permStateRes1.emplace_back(value1);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::RestorePermissionPolicy(tokenId,
        permStateRes1); // ret != RET_SUCCESS

    ASSERT_EQ(tokenId, policySet->tokenId_);

    GenericValues value2;
    value2.Put(FIELD_TOKEN_ID, 123); // 123 is random input
    value2.Put(FIELD_GRANT_IS_GENERAL, true);
    value2.Put(FIELD_PERMISSION_NAME, "ohos.permission.CAMERA");
    value2.Put(FIELD_DEVICE_ID, "dev-002");
    value2.Put(FIELD_GRANT_STATE, PermissionState::PERMISSION_DENIED);
    value2.Put(FIELD_GRANT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG);
    GenericValues value3;
    value3.Put(FIELD_TOKEN_ID, 123); // 123 is random input
    value3.Put(FIELD_GRANT_IS_GENERAL, true);
    value3.Put(FIELD_PERMISSION_NAME, "ohos.permission.CAMERA");
    value3.Put(FIELD_DEVICE_ID, "dev-003");
    value3.Put(FIELD_GRANT_STATE, PermissionState::PERMISSION_DENIED);
    value3.Put(FIELD_GRANT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG);

    std::vector<GenericValues> permStateRes2;
    permStateRes2.emplace_back(value2);
    permStateRes2.emplace_back(value3);

    std::shared_ptr<PermissionPolicySet> policySet2 = PermissionPolicySet::RestorePermissionPolicy(tokenId,
        permStateRes2); // state.permissionName == iter->permissionName
    ASSERT_EQ(static_cast<uint32_t>(2), policySet2->permStateList_[0].resDeviceID.size());
}

/**
 * @tc.name: VerifyPermissStatus001
 * @tc.desc: PermissionPolicySet::VerifyPermissStatus function test
 * @tc.type: FUNC
 * @tc.require: IssueI61OOX
 */
HWTEST_F(AccessTokenInfoManagerTest, VerifyPermissStatus001, TestSize.Level1)
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
    ASSERT_EQ(PermissionState::PERMISSION_DENIED, policySet->VerifyPermissStatus("ohos.permission.TEST"));
}

/**
 * @tc.name: QueryPermissionFlag001
 * @tc.desc: PermissionPolicySet::QueryPermissionFlag function test
 * @tc.type: FUNC
 * @tc.require: IssueI61OOX
 */
HWTEST_F(AccessTokenInfoManagerTest, QueryPermissionFlag001, TestSize.Level1)
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

    // perm.permissionName != permissionName
    int flag = 0;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, policySet->QueryPermissionFlag("ohos.permission.TEST1", flag));
    // isGeneral is false
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, policySet->QueryPermissionFlag("ohos.permission.TEST", flag));
}

/**
 * @tc.name: UpdatePermissionStatus001
 * @tc.desc: PermissionPolicySet::UpdatePermissionStatus function test
 * @tc.type: FUNC
 * @tc.require: IssueI61OOX
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

    AccessTokenID tokenId = 123; // 123 is random input
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(perm);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::BuildPermissionPolicySet(tokenId,
        permStateList);

    // iter reach the end
    bool isGranted = false;
    uint32_t flag = PermissionFlag::PERMISSION_DEFAULT_FLAG;
    bool isUpdated = false;
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, policySet->UpdatePermissionStatus("ohos.permission.TEST1",
        isGranted, flag, isUpdated));

    // isGeneral is false
    ASSERT_EQ(RET_SUCCESS, policySet->UpdatePermissionStatus("ohos.permission.TEST",
        isGranted, flag, isUpdated));
}

/**
 * @tc.name: ResetUserGrantPermissionStatus001
 * @tc.desc: PermissionPolicySet::ResetUserGrantPermissionStatus function test
 * @tc.type: FUNC
 * @tc.require: IssueI61OOX
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

    AccessTokenID tokenId = 123; // 123 is random input
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
 * @tc.require: IssueI61OOX
 */
HWTEST_F(AccessTokenInfoManagerTest, PermStateFullToString001, TestSize.Level1)
{
    PermissionStateFull perm = {
        .permissionName = "ohos.permission.CAMERA",
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

    ASSERT_EQ(tokenId, policySet->tokenId_);

    int32_t tokenApl = static_cast<int32_t>(ATokenAplEnum::APL_SYSTEM_CORE);
    std::vector<std::string> nativeAcls;
    std::string info;
    // isGeneral is false
    policySet->PermStateToString(tokenApl, nativeAcls, info);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
