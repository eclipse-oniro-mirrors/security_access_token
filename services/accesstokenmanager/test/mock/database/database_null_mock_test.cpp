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

#define private public
#include "access_token_db.h"
#undef private
#include "access_token_error.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {

class AccessTokenDatabaseNullMockTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void AccessTokenDatabaseNullMockTest::SetUpTestCase() {}

void AccessTokenDatabaseNullMockTest::TearDownTestCase() {}

void AccessTokenDatabaseNullMockTest::SetUp() {}

void AccessTokenDatabaseNullMockTest::TearDown() {}

/*
 * @tc.name: DeleteAndInsertValuesTest001
 * @tc.desc: test DeleteAndInsertValues with null db
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccessTokenDatabaseNullMockTest, DeleteAndInsertValuesTest001, TestSize.Level4)
{
    AccessTokenDb accessTokenDb;
    EXPECT_EQ(accessTokenDb.db_, nullptr);

    std::vector<DelInfo> delInfoVec;
    std::vector<AddInfo> addInfoVe;
    EXPECT_EQ(
        AccessTokenError::ERR_DATABASE_OPERATE_FAILED, accessTokenDb.DeleteAndInsertValues(delInfoVec, addInfoVe));

    accessTokenDb.RestoreDatabase(NativeRdb::E_SQLITE_CORRUPT);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
