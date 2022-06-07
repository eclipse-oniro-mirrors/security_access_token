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

#include "privacy_kit_test.h"

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "parameter.h"
#include "privacy_kit.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

const static int32_t RET_NO_ERROR = 0;
const static int32_t RET_ERROR = -1;

void PrivacyKitTest::SetUpTestCase()
{}

void PrivacyKitTest::TearDownTestCase()
{
}

void PrivacyKitTest::SetUp()
{
}

void PrivacyKitTest::TearDown()
{
}

/**
 * @tc.name: AddPermissionUsedRecord001
 * @tc.desc: cannot AddPermissionUsedRecord with illegal tokenId and permission.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, AddPermissionUsedRecord001, TestSize.Level1)
{
    int successCount = 1;
    int failCount = 0;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::AddPermissionUsedRecord(111, "ohos.permission.READ_CONTACTS", successCount, failCount));
}

/**
 * @tc.name: RemovePermissionUsedRecords001
 * @tc.desc: cannot RemovePermissionUsedRecords with illegal tokenId and deviceID.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, RemovePermissionUsedRecords001, TestSize.Level1)
{
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::RemovePermissionUsedRecords(111, "device"));
}

/**
 * @tc.name: GetPermissionUsedRecords001
 * @tc.desc: cannot GetPermissionUsedRecords with invalid query time.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecords001, TestSize.Level1)
{
    PermissionUsedRequest request;
    PermissionUsedResult result;
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, result));
}

/**
 * @tc.name: GetPermissionUsedRecordsAsync001
 * @tc.desc: cannot GetPermissionUsedRecordsAsync with invalid query time.
 * @tc.type: FUNC
 * @tc.require:Issue Number
 */
HWTEST_F(PrivacyKitTest, GetPermissionUsedRecordsAsync001, TestSize.Level1)
{
    PermissionUsedRequest request;
    OHOS::sptr<TestCallBack> callback(new TestCallBack());
    ASSERT_EQ(RET_NO_ERROR, PrivacyKit::GetPermissionUsedRecords(request, callback));
}