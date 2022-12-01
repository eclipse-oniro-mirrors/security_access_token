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
#include "accesstoken_remote_token_manager.h"
#include "dm_device_info.h"
#include "token_field_const.h"
#include "hap_token_info_inner.h"
#include "native_token_info_inner.h"
#include "permission_definition_cache.h"
#include "permission_manager.h"
#include "permission_policy_set.h"
#include "token_modify_notifier.h"
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
static PermissionStateFull g_permState1 = {
    .permissionName = "ohos.permission.TEST",
    .isGeneral = false,
    .resDeviceID = {"dev-001"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};
static PermissionStateFull g_permState2 = {
    .permissionName = "ohos.permission.CAMERA",
    .isGeneral = false,
    .resDeviceID = {"dev-001"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};
static PermissionStateFull g_permState3 = {
    .permissionName = "ohos.permission.CAMERA",
    .isGeneral = false,
    .resDeviceID = {"dev-001", "dev-001"},
    .grantStatus = {PermissionState::PERMISSION_DENIED, PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG, PermissionFlag::PERMISSION_DEFAULT_FLAG}
};
static PermissionStateFull g_permState4 = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .isGeneral = true,
    .resDeviceID = {"dev-001"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}
};
static PermissionStateFull g_permState5 = {
    .permissionName = "ohos.permission.APPROXIMATELY_LOCATION",
    .isGeneral = true,
    .resDeviceID = {"dev-001"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_FIXED}
};
static PermissionStateFull g_permState6 = {
    .permissionName = "ohos.permission.LOCATION",
    .isGeneral = true,
    .resDeviceID = {"dev-001"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
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
 * @tc.require:
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
 * @tc.require:
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
 * @tc.require:
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
    ASSERT_EQ(AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenIdEx.tokenIdExStruct.tokenID), RET_FAILED);

    AccessTokenID tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_HAP));
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId)); // count(id) == 0

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = nullptr;
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId)); // info is null
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
 * @tc.require:
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
 * @tc.require:
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
 * @tc.require:
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
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().UpdateRemoteHapTokenInfo(mapID, hapSync));

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
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().CreateRemoteHapTokenInfo(mapID, hapSync));

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

    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().SetRemoteNativeTokenInfo(deviceID,
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

    AccessTokenRemoteDevice device;
    device.DeviceID_ = deviceID;
    // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    device.MappingTokenIDPairMap_.insert(std::pair<AccessTokenID, AccessTokenID>(tokenID, 537919487));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_[deviceID] = device;

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(537919487, TOKEN_HAP));
    // hap mapID 537919487 is not exist
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID));
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_.erase(deviceID);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(537919487);

    // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    device.MappingTokenIDPairMap_[tokenID] = 672137215;
    AccessTokenRemoteTokenManager::GetInstance().remoteDeviceMap_[deviceID] = device;

    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(672137215, TOKEN_NATIVE));
    // native mapID 672137215 is not exist
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().DeleteRemoteToken(deviceID, tokenID));
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
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().DeleteRemoteDeviceTokens(remoteDeviceID));

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
    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(USER_ID, "com.ohos.photos", INST_INDEX);
    std::shared_ptr<HapTokenInfoInner> info = AccessTokenInfoManager::GetInstance().GetHapTokenInfoInner(tokenId);
    ASSERT_NE(0, AccessTokenInfoManager::GetInstance().AddHapTokenInfo(info));
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
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().AddNativeTokenInfo(info)); // info is null

    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    info = std::make_shared<NativeTokenInfoInner>();
    info->tokenInfoBasic_.tokenID = tokenId;
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().AddNativeTokenInfo(info)); // count(id) > 0

    // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    info->tokenInfoBasic_.tokenID = 672137215;
    info->tokenInfoBasic_.processName = "accesstoken_service";
    // 672137214 is max-1 native tokenId: 001 01 0 000000 11111111111111111110
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[672137214] = info;
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().AddNativeTokenInfo(info)); // count(processName) > 0

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
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId)); // count(id) == 0

    std::shared_ptr<NativeTokenInfoInner> info = std::make_shared<NativeTokenInfoInner>();
    info->isRemote_ = true;
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[tokenId] = info;
    ASSERT_EQ(RET_FAILED, AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId)); // remote is true
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
 * @tc.name: OnDeviceOnline001
 * @tc.desc: AtmDeviceStateCallbackTest::OnDeviceOnline function test
 * @tc.type: FUNC
 * @tc.require:
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
 * @tc.require:
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
 * @tc.require:
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
    ASSERT_EQ(RET_FAILED, PermissionDefinitionCache::GetInstance().RestorePermDefInfo(values));
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
 * @tc.name: VerifyPermissStatus001
 * @tc.desc: PermissionPolicySet::VerifyPermissStatus function test
 * @tc.type: FUNC
 * @tc.require:
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
 * @tc.require:
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
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, PermStateFullToString001, TestSize.Level1)
{
    AccessTokenID tokenId = 123; // 123 is random input
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(g_permState3);

    std::shared_ptr<PermissionPolicySet> policySet = PermissionPolicySet::BuildPermissionPolicySet(tokenId,
        permStateList);

    ASSERT_EQ(tokenId, policySet->tokenId_);

    std::string info;
    // iter != end - 1
    policySet->PermStateFullToString(g_permState3, info);
}

/**
 * @tc.name: VerifyNativeAccessToken001
 * @tc.desc: PermissionManager::VerifyNativeAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, VerifyNativeAccessToken001, TestSize.Level1)
{
    AccessTokenID tokenId = 123; // 123 is random input
    std::string permissionName = "ohos.permission.INVALID";

    PermissionManager::GetInstance().RemoveDefPermissions(tokenId); // tokenInfo is null

    // tokenInfoPtr is null
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        PermissionManager::GetInstance().VerifyNativeAccessToken(tokenId, permissionName));

    // backup
    std::map<std::string,
        PermissionDefData> permissionDefinitionMap = PermissionDefinitionCache::GetInstance().permissionDefinitionMap_;
    PermissionDefinitionCache::GetInstance().permissionDefinitionMap_.clear();

    // apl default normal, remote default false
    std::shared_ptr<NativeTokenInfoInner> native = std::make_shared<NativeTokenInfoInner>();
    ASSERT_NE(nullptr, native);
    ASSERT_EQ(ATokenAplEnum::APL_NORMAL, native->tokenInfoBasic_.apl);
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[tokenId] = native; // normal apl

    // permission definition set has not been installed + apl < APL_SYSTEM_BASIC
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        PermissionManager::GetInstance().VerifyNativeAccessToken(tokenId, permissionName));
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_.erase(tokenId);

    native->tokenInfoBasic_.apl = ATokenAplEnum::APL_SYSTEM_BASIC;
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[tokenId] = native; // basic apl
    // permission definition set has not been installed + apl >= APL_SYSTEM_BASIC
    ASSERT_EQ(PermissionState::PERMISSION_GRANTED,
        PermissionManager::GetInstance().VerifyNativeAccessToken(tokenId, permissionName));
    PermissionDefinitionCache::GetInstance().permissionDefinitionMap_ = permissionDefinitionMap; // recovery

    // not remote + no definition
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        PermissionManager::GetInstance().VerifyNativeAccessToken(tokenId, permissionName));

    permissionName = "ohos.permission.CAMERA";
    // permPolicySet is null
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        PermissionManager::GetInstance().VerifyNativeAccessToken(tokenId, permissionName));

    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: VerifyAccessToken002
 * @tc.desc: PermissionManager::VerifyAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, VerifyAccessToken002, TestSize.Level1)
{
    AccessTokenID tokenId = 0;
    std::string permissionName;

    // permissionName invalid
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        PermissionManager::GetInstance().VerifyAccessToken(tokenId, permissionName));

    tokenId = 940572671; // 940572671 is max butt tokenId: 001 11 0 000000 11111111111111111111
    permissionName = "ohos.permission.DISTRIBUTED_DATASYNC";
    
    // token type is TOKEN_TYPE_BUTT
    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        PermissionManager::GetInstance().VerifyAccessToken(tokenId, permissionName));
}

/**
 * @tc.name: GetDefPermission001
 * @tc.desc: PermissionManager::GetDefPermission function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetDefPermission001, TestSize.Level1)
{
    std::string permissionName;
    PermissionDef permissionDefResult;

    // permissionName invalid
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID,
        PermissionManager::GetInstance().GetDefPermission(permissionName, permissionDefResult));
}

/**
 * @tc.name: GetSelfPermissionState001
 * @tc.desc: PermissionManager::GetSelfPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetSelfPermissionState001, TestSize.Level1)
{
    std::vector<PermissionStateFull> permsList1;
    permsList1.emplace_back(g_permState1);
    PermissionListState permState1;
    permState1.permissionName = "ohos.permission.TEST";
    int32_t apiVersion = ACCURATE_LOCATION_API_VERSION;

    // permissionName no definition
    PermissionManager::GetInstance().GetSelfPermissionState(permsList1, permState1, apiVersion);
    ASSERT_EQ(PermissionOper::INVALID_OPER, permState1.state);

    std::vector<PermissionStateFull> permsList2;
    permsList2.emplace_back(g_permState2);
    PermissionListState permState2;
    permState2.permissionName = "ohos.permission.CAMERA";

    // flag not PERMISSION_DEFAULT_FLAG、PERMISSION_USER_SET or PERMISSION_USER_FIXED
    PermissionManager::GetInstance().GetSelfPermissionState(permsList2, permState2, apiVersion);
    ASSERT_EQ(PermissionOper::PASS_OPER, permState2.state);
}

/**
 * @tc.name: GetPermissionFlag001
 * @tc.desc: PermissionManager::GetPermissionFlag function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetPermissionFlag001, TestSize.Level1)
{
    AccessTokenID tokenID = 123; // 123 is random input
    std::string permissionName;
    int flag = 0;

    // permissionName invalid
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, PermissionManager::GetInstance().GetPermissionFlag(tokenID,
        permissionName, flag));

    permissionName = "ohos.permission.CAMERA";
    // permPolicySet is null
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, PermissionManager::GetInstance().GetPermissionFlag(tokenID,
        permissionName, flag));
}

/**
 * @tc.name: UpdateTokenPermissionState002
 * @tc.desc: PermissionManager::UpdateTokenPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, UpdateTokenPermissionState002, TestSize.Level1)
{
    AccessTokenID tokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(USER_ID,
        "com.ohos.camera", INST_INDEX);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);
    std::string permissionName = "ohos.permission.DUMP";
    bool isGranted = false;
    int flag = 0;

    // permission not in list
    ASSERT_EQ(AccessTokenError::ERR_PARAM_INVALID, PermissionManager::GetInstance().UpdateTokenPermissionState(tokenId,
        permissionName, isGranted, flag));
}

/**
 * @tc.name: GetApiVersionByTokenId001
 * @tc.desc: PermissionManager::GetApiVersionByTokenId function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetApiVersionByTokenId001, TestSize.Level1)
{
    AccessTokenID tokenId = 940572671; // 940572671 is max butt tokenId: 001 11 0 000000 11111111111111111111
    int32_t apiVersion = 0;

    // type TOKEN_TYPE_BUTT
    ASSERT_EQ(false, PermissionManager::GetInstance().GetApiVersionByTokenId(tokenId, apiVersion));

    tokenId = 537919487; // 537919487 is max hap tokenId: 001 00 0 000000 11111111111111111111
    // get token info err
    ASSERT_EQ(false, PermissionManager::GetInstance().GetApiVersionByTokenId(tokenId, apiVersion));
}

/**
 * @tc.name: IsPermissionVaild001
 * @tc.desc: PermissionManager::IsPermissionVaild function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, IsPermissionVaild001, TestSize.Level1)
{
    std::string permissionName;

    ASSERT_EQ(false, PermissionManager::GetInstance().IsPermissionVaild(permissionName)); // permissionName empty

    permissionName = "ohos.permission.TEST";
    // permissionName no definition
    ASSERT_EQ(false, PermissionManager::GetInstance().IsPermissionVaild(permissionName));
}

/**
 * @tc.name: GetPermissionStatusAndFlag001
 * @tc.desc: PermissionManager::GetPermissionStatusAndFlag function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, GetPermissionStatusAndFlag001, TestSize.Level1)
{
    std::string permissionName;
    std::vector<PermissionStateFull> permsList;
    permsList.emplace_back(g_permState2);
    int32_t status = 0;
    uint32_t flag = 0;

    // permissionName empty
    ASSERT_EQ(false, PermissionManager::GetInstance().GetPermissionStatusAndFlag(permissionName,
        permsList, status, flag));

    permissionName = "ohos.permission.LOCATION";
    // permissionName not in permsList
    ASSERT_EQ(false, PermissionManager::GetInstance().GetPermissionStatusAndFlag(permissionName,
        permsList, status, flag));
}

/**
 * @tc.name: AllLocationPermissionHandle001
 * @tc.desc: PermissionManager::AllLocationPermissionHandle function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, AllLocationPermissionHandle001, TestSize.Level1)
{
    PermissionListState permsState1 = {
        .permissionName = "ohos.permission.APPROXIMATELY_LOCATION"
    };
    PermissionListState permsState2 = {
        .permissionName = "ohos.permission.LOCATION"
    };

    PermissionListStateParcel parcel1;
    parcel1.permsState = permsState1;
    PermissionListStateParcel parcel2;
    parcel2.permsState = permsState2;

    std::vector<PermissionListStateParcel> reqPermList;
    reqPermList.emplace_back(parcel1);
    reqPermList.emplace_back(parcel2);
    std::vector<PermissionStateFull> permsList1;
    permsList1.emplace_back(g_permState4);
    permsList1.emplace_back(g_permState6);
    uint32_t vagueIndex = 0;
    uint32_t accurateIndex = 1;

    // vagueFlag == PERMISSION_DEFAULT_FLAG
    PermissionManager::GetInstance().AllLocationPermissionHandle(reqPermList, permsList1, vagueIndex, accurateIndex);
    ASSERT_EQ(static_cast<int>(PermissionOper::DYNAMIC_OPER), reqPermList[0].permsState.state);
    ASSERT_EQ(static_cast<int>(PermissionOper::DYNAMIC_OPER), reqPermList[1].permsState.state);

    std::vector<PermissionStateFull> permsList2;
    permsList2.emplace_back(g_permState5);
    permsList2.emplace_back(g_permState6);
    // vagueFlag == PERMISSION_DEFAULT_FLAG + accurateFlag == PERMISSION_SYSTEM_FIXED
    PermissionManager::GetInstance().AllLocationPermissionHandle(reqPermList, permsList2, vagueIndex, accurateIndex);
    ASSERT_EQ(static_cast<int>(PermissionOper::PASS_OPER), reqPermList[0].permsState.state);
    ASSERT_EQ(static_cast<int>(PermissionOper::INVALID_OPER), reqPermList[1].permsState.state);
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
    ASSERT_EQ(RET_FAILED,
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
    ASSERT_EQ(RET_FAILED,
        AccessTokenRemoteTokenManager::GetInstance().RemoveDeviceMappingTokenID(deviceID, remoteID));

    deviceID = "dev-001";
    remoteID = 123; // 123 is random input

    // count < 1
    ASSERT_EQ(RET_FAILED,
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
    ASSERT_EQ(RET_FAILED, native->Init(tokenId, processName, apl, dcap, nativeAcls, permStateList));

    inGenericValues.Put(TokenFiledConst::FIELD_PROCESS_NAME, processName);
    // processName invalid
    ASSERT_EQ(RET_FAILED, native->RestoreNativeTokenInfo(tokenId, inGenericValues, permStateRes));
    inGenericValues.Remove(TokenFiledConst::FIELD_PROCESS_NAME);

    processName = "token_sync";
    // apl invalid
    ASSERT_EQ(RET_FAILED, native->Init(tokenId, processName, apl, dcap, nativeAcls, permStateList));

    inGenericValues.Put(TokenFiledConst::FIELD_PROCESS_NAME, processName);
    inGenericValues.Put(TokenFiledConst::FIELD_APL, apl);
    // apl invalid
    ASSERT_EQ(RET_FAILED, native->RestoreNativeTokenInfo(tokenId, inGenericValues, permStateRes));
    inGenericValues.Remove(TokenFiledConst::FIELD_APL);

    apl = static_cast<int>(ATokenAplEnum::APL_NORMAL);
    inGenericValues.Put(TokenFiledConst::FIELD_APL, apl);
    inGenericValues.Put(TokenFiledConst::FIELD_TOKEN_VERSION, version);
    // version invalid
    ASSERT_EQ(RET_FAILED, native->RestoreNativeTokenInfo(tokenId, inGenericValues, permStateRes));
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
    int32_t apiVersion = DEFAULT_API_VERSION;
    int aplNum = static_cast<int>(ATokenAplEnum::APL_INVALID);
    int version = 10; // 10 is random input which only need not equal 1
    HapPolicyParams policy;
    hap->Update(appIDDesc, apiVersion, policy); // permPolicySet_ is null

    std::string info;
    hap->ToString(info); // permPolicySet_ is null

    std::vector<GenericValues> hapInfoValues;
    std::vector<GenericValues> permStateValues;
    hap->StoreHapInfo(hapInfoValues, permStateValues); // permPolicySet_ is null


    tokenValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    // bundleName invalid
    ASSERT_EQ(RET_FAILED, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));
    tokenValue.Remove(TokenFiledConst::FIELD_BUNDLE_NAME);

    bundleName = "com.ohos.permissionmanger";
    tokenValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    tokenValue.Put(TokenFiledConst::FIELD_APP_ID, appIDDesc);
    // appID invalid
    ASSERT_EQ(RET_FAILED, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));
    tokenValue.Remove(TokenFiledConst::FIELD_APP_ID);

    appIDDesc = "what's this";
    tokenValue.Put(TokenFiledConst::FIELD_APP_ID, appIDDesc);
    tokenValue.Put(TokenFiledConst::FIELD_DEVICE_ID, deviceID);
    // deviceID invalid
    ASSERT_EQ(RET_FAILED, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));
    tokenValue.Remove(TokenFiledConst::FIELD_DEVICE_ID);

    deviceID = "dev-001";
    tokenValue.Put(TokenFiledConst::FIELD_DEVICE_ID, deviceID);
    tokenValue.Put(TokenFiledConst::FIELD_APL, aplNum);
    // apl invalid
    ASSERT_EQ(RET_FAILED, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));

    aplNum = static_cast<int>(ATokenAplEnum::APL_NORMAL);
    tokenValue.Put(TokenFiledConst::FIELD_APL, aplNum);
    tokenValue.Put(TokenFiledConst::FIELD_TOKEN_VERSION, version);
    // version invalid
    ASSERT_EQ(RET_FAILED, hap->RestoreHapTokenInfo(tokenId, tokenValue, permStateRes));
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
    ASSERT_EQ(RET_FAILED, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, type));

    tokenId = AccessTokenInfoManager::GetInstance().GetHapTokenID(USER_ID, "com.ohos.permissionmanager", INST_INDEX);
    ASSERT_NE(static_cast<AccessTokenID>(0), tokenId);

    // register repeat
    ASSERT_EQ(RET_FAILED, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, type));
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

    AccessTokenInfoManager::GetInstance().DumpTokenInfo(tokenId, dumpInfo); // hap infoPtr is null
    ASSERT_EQ("", dumpInfo);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);

    tokenId = 672137215; // 672137215 is max native tokenId: 001 01 0 000000 11111111111111111111
    ASSERT_EQ(RET_SUCCESS, AccessTokenIDManager::GetInstance().RegisterTokenId(tokenId, TOKEN_NATIVE));
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(tokenId, dumpInfo); // native infoPtr is null
    ASSERT_EQ("", dumpInfo);
    AccessTokenIDManager::GetInstance().ReleaseTokenId(tokenId);

    std::shared_ptr<HapTokenInfoInner> hap = nullptr;
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[537919487] = hap;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(0, dumpInfo); // iter->second is null
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(537919487);

    std::shared_ptr<NativeTokenInfoInner> native = nullptr;
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_[672137215] = native;
    AccessTokenInfoManager::GetInstance().DumpTokenInfo(0, dumpInfo); // iter->second is null
    AccessTokenInfoManager::GetInstance().nativeTokenInfoMap_.erase(672137215);
}

/**
 * @tc.name: VerifyHapAccessToken001
 * @tc.desc: PermissionManager::VerifyHapAccessToken function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, VerifyHapAccessToken001, TestSize.Level1)
{
    AccessTokenID tokenId = 123; // 123 is random input
    std::string permissionName;

    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ASSERT_NE(nullptr, hap);
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = hap;

    ASSERT_EQ(PermissionState::PERMISSION_DENIED,
        PermissionManager::GetInstance().VerifyHapAccessToken(tokenId, permissionName)); // permPolicySet is null

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}

/**
 * @tc.name: ClearUserGrantedPermissionState001
 * @tc.desc: PermissionManager::ClearUserGrantedPermissionState function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenInfoManagerTest, ClearUserGrantedPermissionState001, TestSize.Level1)
{
    AccessTokenID tokenId = 123; // 123 is random input

    std::shared_ptr<HapTokenInfoInner> hap = std::make_shared<HapTokenInfoInner>();
    ASSERT_NE(nullptr, hap);
    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_[tokenId] = hap;

    PermissionManager::GetInstance().ClearUserGrantedPermissionState(tokenId); // permPolicySet is null

    AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(tokenId);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
