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

#include "add_permission_used_record_test.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

void AddPermissionUsedRecordTest::SetUpTestCase()
{}

void AddPermissionUsedRecordTest::TearDownTestCase()
{
}

void AddPermissionUsedRecordTest::SetUp()
{
}

void AddPermissionUsedRecordTest::TearDown()
{
}

/**
 * @tc.name: AddPermissionUsedRecord_001
 * @tc.desc: cannot AddPermissionUsedRecord with invalid tokenID and permission.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD=====
 */
HWTEST_F(AddPermissionUsedRecordTest, AddPermissionUsedRecord_001, TestSize.Level1)
{
    int32_t successCount = 1;
    int32_t fasilCount = 0;
    std::string permission = "ohon.permission.READ_CONTACTS";
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_InfoParmsA.userID,
                                                          g_InfoParmsA.bundleName,
                                                          g_InfoParmsA.instIndex);
    int32_t ret = PrivacyKit::AddPermissionUsedRecord(0, permission, successCount, fasilCount);
    ASSERT_EQ(RET_FAILED, ret);

    ret = PrivacyKit::AddPermissionUsedRecord(tokenID, "", successCount, fasilCount);
    ASSERT_EQ(RET_FAILED, ret);
}
