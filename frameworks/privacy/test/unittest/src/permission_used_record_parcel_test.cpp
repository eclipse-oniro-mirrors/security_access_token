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
 
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include "permission_used_record_parcel.h"
#include "parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
UsedRecordDetail g_accessRecord1 = {
    .status = 0,
    .timestamp = 0L,
    .accessDuration = 0L,
};

UsedRecordDetail g_accessRecord2 = {
    .status = 1,
    .timestamp = 1L,
    .accessDuration = 1L,
};

UsedRecordDetail g_rejectRecord1 = {
    .status = 2,
    .timestamp = 2L,
    .accessDuration = 2L,
};

UsedRecordDetail g_rejectRecord2 = {
    .status = 3,
    .timestamp = 3L,
    .accessDuration = 3L,
};
}
class PermissionUsedRecordParcelTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void PermissionUsedRecordParcelTest::SetUpTestCase(void) {}
void PermissionUsedRecordParcelTest::TearDownTestCase(void) {}
void PermissionUsedRecordParcelTest::SetUp(void) {}
void PermissionUsedRecordParcelTest::TearDown(void) {}

/**
 * @tc.name: PermissionUsedRecordParcel001
 * @tc.desc: Verify the PermissionUsedRecordParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RUCC
 */
HWTEST_F(PermissionUsedRecordParcelTest, PermissionUsedRecordParcel001, TestSize.Level1)
{
    PermissionUsedRecordParcel permissionUsedRecordParcel;

    permissionUsedRecordParcel.permissionRecord = {
        .permissionName = "ohos.permission.CAMERA",
        .accessCount = 2,
        .rejectCount = 2,
        .lastAccessTime = 0L,
        .lastRejectTime = 0L,
        .lastAccessDuration = 0L,
    };
    permissionUsedRecordParcel.permissionRecord.accessRecords.emplace_back(g_accessRecord1);
    permissionUsedRecordParcel.permissionRecord.accessRecords.emplace_back(g_accessRecord2);
    permissionUsedRecordParcel.permissionRecord.rejectRecords.emplace_back(g_rejectRecord1);
    permissionUsedRecordParcel.permissionRecord.rejectRecords.emplace_back(g_rejectRecord2);

    Parcel parcel;
    EXPECT_EQ(true, permissionUsedRecordParcel.Marshalling(parcel));

    std::shared_ptr<PermissionUsedRecordParcel> readedData(PermissionUsedRecordParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.permissionName, readedData->permissionRecord.permissionName);
    EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessCount, readedData->permissionRecord.accessCount);
    EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.rejectCount, readedData->permissionRecord.rejectCount);
    EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.lastAccessTime, readedData->permissionRecord.lastAccessTime);
    EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.lastRejectTime, readedData->permissionRecord.lastRejectTime);
    EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.lastAccessDuration,
        readedData->permissionRecord.lastAccessDuration);

    for(int32_t i = 0; i < permissionUsedRecordParcel.permissionRecord.accessRecords.size(); i++) {
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessRecords[i].status,
            readedData->permissionRecord.accessRecords[i].status);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessRecords[i].timestamp,
            readedData->permissionRecord.accessRecords[i].timestamp);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessRecords[i].accessDuration,
            readedData->permissionRecord.accessRecords[i].accessDuration);
    }

    for(int32_t i = 0; i < permissionUsedRecordParcel.permissionRecord.rejectRecords.size(); i++) {
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.rejectRecords[i].status,
            readedData->permissionRecord.rejectRecords[i].status);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.rejectRecords[i].timestamp,
            readedData->permissionRecord.rejectRecords[i].timestamp);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.rejectRecords[i].accessDuration,
            readedData->permissionRecord.rejectRecords[i].accessDuration);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
