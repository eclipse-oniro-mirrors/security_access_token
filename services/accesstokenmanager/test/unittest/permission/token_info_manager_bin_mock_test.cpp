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

#include <cerrno>
#include <unistd.h>

#include <gtest/gtest.h>

#include "accesstoken_info_manager.h"

#include "access_token_error.h"
#include "fake_parent_hap_tokenid.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t SLEEP_TIME_SECONDS = 3;
static AccessTokenID g_selfTokenId = 0;

static PermissionDef g_binMockPermDef1 = {
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

static PermissionStatus g_binMockPermState1 = {
    .permissionName = "open the door",
    .grantStatus = 1,
    .grantFlag = 1
};

static HapInfoParams g_binMockInfo = {
    .userID = 1,
    .bundleName = "accesstoken_test_bin_mock",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest",
    .isSystemApp = false
};

static HapPolicy g_binMockPolicy = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_binMockPermDef1},
    .permStateList = {g_binMockPermState1}
};

AccessTokenID BuildBinTokenIdFromHapTokenId(AccessTokenID hapTokenId)
{
    AccessTokenIDInner innerId = *reinterpret_cast<AccessTokenIDInner*>(&hapTokenId);
    innerId.type_ext = 1;
    return *reinterpret_cast<AccessTokenID*>(&innerId);
}
}

class TokenInfoManagerBinMockTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_selfTokenId = GetSelfTokenID();
        uint32_t hapSize = 0;
        uint32_t nativeSize = 0;
        uint32_t pefDefSize = 0;
        uint32_t dlpSize = 0;
        std::map<int32_t, TokenIdInfo> tokenIdAplMap;
        AccessTokenInfoManager::GetInstance().Init(hapSize, nativeSize, pefDefSize, dlpSize, tokenIdAplMap);
        sleep(SLEEP_TIME_SECONDS);
    }

    static void TearDownTestCase()
    {
        sleep(SLEEP_TIME_SECONDS);
        SetSelfTokenID(g_selfTokenId);
    }

    void SetUp() override
    {
        ResetFakeParentHapTokenIdState();
    }

    void TearDown() override
    {
        ResetFakeParentHapTokenIdState();
    }
};

/**
 * @tc.name: GetHapTokenInfoWithBinToken001
 * @tc.desc: Verify GetHapTokenInfo returns ERR_IOCTL_UNSUPPORT when querying parent hap token is unsupported.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerBinMockTest, GetHapTokenInfoWithBinToken001, TestSize.Level0)
{
    auto& fakeState = GetFakeParentHapTokenIdState();
    fakeState.ret = ENOTSUP;
    AccessTokenID binTokenId = BuildBinTokenIdFromHapTokenId(123);

    HapTokenInfo info;
    EXPECT_EQ(AccessTokenError::ERR_IOCTL_UNSUPPORT,
        AccessTokenInfoManager::GetInstance().GetHapTokenInfo(binTokenId, info));
    EXPECT_EQ(1, fakeState.callCount);
    EXPECT_EQ(binTokenId, fakeState.lastBinTokenID);
}

/**
 * @tc.name: GetHapTokenInfoWithBinToken002
 * @tc.desc: Verify GetHapTokenInfo returns ERR_TOKENID_NOT_EXIST when parent hap token ID is invalid.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerBinMockTest, GetHapTokenInfoWithBinToken002, TestSize.Level0)
{
    auto& fakeState = GetFakeParentHapTokenIdState();
    fakeState.ret = ACCESS_TOKEN_OK;
    fakeState.parentHapTokenID = INVALID_TOKENID;
    AccessTokenID binTokenId = BuildBinTokenIdFromHapTokenId(124);

    HapTokenInfo info;
    EXPECT_EQ(AccessTokenError::ERR_TOKENID_NOT_EXIST,
        AccessTokenInfoManager::GetInstance().GetHapTokenInfo(binTokenId, info));
    EXPECT_EQ(1, fakeState.callCount);
    EXPECT_EQ(binTokenId, fakeState.lastBinTokenID);
}

/**
 * @tc.name: GetHapTokenInfoWithBinToken003
 * @tc.desc: Verify GetHapTokenInfo returns parent hap token info when bin token maps to a valid parent hap token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerBinMockTest, GetHapTokenInfoWithBinToken003, TestSize.Level0)
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        g_binMockInfo, g_binMockPolicy, tokenIdEx, undefValues));
    AccessTokenID parentHapTokenId = tokenIdEx.tokenIdExStruct.tokenID;

    auto& fakeState = GetFakeParentHapTokenIdState();
    fakeState.ret = ACCESS_TOKEN_OK;
    fakeState.parentHapTokenID = parentHapTokenId;
    AccessTokenID binTokenId = BuildBinTokenIdFromHapTokenId(parentHapTokenId);

    HapTokenInfo info;
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().GetHapTokenInfo(binTokenId, info));
    EXPECT_EQ(parentHapTokenId, info.tokenID);
    EXPECT_EQ(1, fakeState.callCount);
    EXPECT_EQ(binTokenId, fakeState.lastBinTokenID);

    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(parentHapTokenId));
}

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
