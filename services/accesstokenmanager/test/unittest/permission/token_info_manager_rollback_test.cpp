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

#include <gtest/gtest.h>
#include <gtest/hwext/gtest-tag.h>

#include "access_token_error.h"
#include "mock_access_token_db_operator.h"
#define private public
#include "accesstoken_info_manager.h"
#undef private
#include "permission_data_brief.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
#ifdef SPM_DATA_ENABLE
constexpr AccessTokenID TEST_TOKEN_ID = 0x20001000;
constexpr int32_t INVALID_UID = -1;
constexpr int32_t MIGRATED_UID = 20010001;
#endif
}

class TokenInfoManagerRollbackTest : public testing::Test {
public:
    void TearDown() override
    {
#ifdef SPM_DATA_ENABLE
        AccessTokenInfoManager::GetInstance().hapTokenInfoMap_.erase(TEST_TOKEN_ID);
        PermissionDataBrief::GetInstance().DeleteBriefPermDataByTokenId(TEST_TOKEN_ID);
        ResetMockDbState();
#endif
    }
};

#ifdef SPM_DATA_ENABLE
/**
 * @tc.name: RefreshTokenStatusRollback001
 * @tc.desc: RefreshTokenStatus rolls back in-memory uid and migrated flag when DB modify fails.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenInfoManagerRollbackTest, RefreshTokenStatusRollback001, TestSize.Level0)
{
    auto& manager = AccessTokenInfoManager::GetInstance();
    ResetMockDbState();

    HapInfoParams info = {
        .userID = 100,
        .bundleName = "com.example.refresh.rollback",
        .instIndex = 0,
        .dlpType = 0,
        .apiVersion = 12,
        .isSystemApp = true,
        .appIDDesc = "com.example.refresh.rollback",
    };
    auto tokenInfo = std::make_shared<HapTokenInfoInner>(TEST_TOKEN_ID, info, HapPolicy {});
    ASSERT_NE(nullptr, tokenInfo);
    tokenInfo->SetUid(INVALID_UID);
    tokenInfo->SetMigrated(false);
    manager.hapTokenInfoMap_[TEST_TOKEN_ID] = tokenInfo;

    GetMockDbState().modifyRet = ERR_DATABASE_OPERATE_FAILED;

    Identity identity = {
        .tokenId = TEST_TOKEN_ID,
        .uid = MIGRATED_UID,
    };
    EXPECT_EQ(ERR_DATABASE_OPERATE_FAILED, manager.RefreshTokenStatus(identity, ReservedType::NONE));
    EXPECT_EQ(1u, GetMockDbState().modifyCallCount);
    EXPECT_EQ(INVALID_UID, tokenInfo->GetUid());
    EXPECT_FALSE(tokenInfo->IsMigrated());
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
