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
 
#include "privacy_parcel_test.h"

#include <memory>
#include <string>

#include "bundle_used_record_parcel.h"
#include "parcel.h"
#include "perm_active_response_parcel.h"
#include "permission_used_record_parcel.h"
#include "permission_used_request_parcel.h"
#include "permission_used_result_parcel.h"
#include "used_record_detail_parcel.h"

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

PermissionUsedRecord g_permissionRecord1 = {
    .permissionName = "ohos.permission.CAMERA",
    .accessCount = 2,
    .rejectCount = 2,
    .lastAccessTime = 0L,
    .lastRejectTime = 0L,
    .lastAccessDuration = 0L,
};

PermissionUsedRecord g_permissionRecord2 = {
    .permissionName = "ohos.permission.LOCATION",
    .accessCount = 2,
    .rejectCount = 2,
    .lastAccessTime = 1L,
    .lastRejectTime = 1L,
    .lastAccessDuration = 1L,
};

BundleUsedRecord g_bundleUsedRecord1 = {
    .tokenId = 100,
    .isRemote = false,
    .deviceId = "you guess",
    .bundleName = "com.ohos.camera",
};

BundleUsedRecord g_bundleUsedRecord2 = {
    .tokenId = 101,
    .isRemote = false,
    .deviceId = "i want to know too",
    .bundleName = "com.ohos.permissionmanager",
};
}

void PrivacyParcelTest::SetUpTestCase()
{
}

void PrivacyParcelTest::TearDownTestCase()
{
}

void PrivacyParcelTest::SetUp()
{
}

void PrivacyParcelTest::TearDown()
{
}

/**
 * @tc.name: BundleUsedRecordParcel001
 * @tc.desc: Verify the CreateHapTokenInfo add one hap token function.
 * @tc.type: FUNC
 * @tc.require: issueI5RUCC
 */
HWTEST_F(PrivacyParcelTest, BundleUsedRecordParcel001, TestSize.Level1)
{
    BundleUsedRecordParcel bundleUsedRecordParcel;

    bundleUsedRecordParcel.bundleRecord = {
        .tokenId = 100,
        .isRemote = false,
        .deviceId = "you guess",
        .bundleName = "com.ohos.permissionmanager",
    };

    g_permissionRecord1.accessRecords.emplace_back(g_accessRecord1);
    g_permissionRecord1.accessRecords.emplace_back(g_accessRecord2);
    g_permissionRecord2.rejectRecords.emplace_back(g_rejectRecord1);
    g_permissionRecord2.rejectRecords.emplace_back(g_rejectRecord2);

    bundleUsedRecordParcel.bundleRecord.permissionRecords.emplace_back(g_permissionRecord1);
    bundleUsedRecordParcel.bundleRecord.permissionRecords.emplace_back(g_permissionRecord2);

    Parcel parcel;
    EXPECT_EQ(true, bundleUsedRecordParcel.Marshalling(parcel));

    std::shared_ptr<BundleUsedRecordParcel> readedData(BundleUsedRecordParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(bundleUsedRecordParcel.bundleRecord.tokenId, readedData->bundleRecord.tokenId);
    EXPECT_EQ(bundleUsedRecordParcel.bundleRecord.isRemote, readedData->bundleRecord.isRemote);
    EXPECT_EQ(bundleUsedRecordParcel.bundleRecord.deviceId, readedData->bundleRecord.deviceId);
    EXPECT_EQ(bundleUsedRecordParcel.bundleRecord.bundleName, readedData->bundleRecord.bundleName);
}

/**
 * @tc.name: ActiveChangeResponseParcel001
 * @tc.desc: Verify ActiveChangeResponseParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RRLJ
 */
HWTEST_F(PrivacyParcelTest, ActiveChangeResponseParcel001, TestSize.Level1)
{
    ActiveChangeResponseParcel activeChangeResponseParcel;

    activeChangeResponseParcel.changeResponse = {
        .tokenID = 100,
        .permissionName = "ohos.permission.CAMERA",
        .deviceId = "you guess",
        .type = PERM_INACTIVE,
    };

    Parcel parcel;
    EXPECT_EQ(true, activeChangeResponseParcel.Marshalling(parcel));

    std::shared_ptr<ActiveChangeResponseParcel> readedData(ActiveChangeResponseParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(activeChangeResponseParcel.changeResponse.tokenID, readedData->changeResponse.tokenID);
    EXPECT_EQ(activeChangeResponseParcel.changeResponse.permissionName, readedData->changeResponse.permissionName);
    EXPECT_EQ(activeChangeResponseParcel.changeResponse.deviceId, readedData->changeResponse.deviceId);
    EXPECT_EQ(activeChangeResponseParcel.changeResponse.type, readedData->changeResponse.type);
}

/**
 * @tc.name: PermissionUsedRecordParcel001
 * @tc.desc: Verify the PermissionUsedRecordParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RUCC
 */
HWTEST_F(PrivacyParcelTest, PermissionUsedRecordParcel001, TestSize.Level1)
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

    for(uint32_t i = 0; i < permissionUsedRecordParcel.permissionRecord.accessRecords.size(); i++) {
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessRecords[i].status,
            readedData->permissionRecord.accessRecords[i].status);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessRecords[i].timestamp,
            readedData->permissionRecord.accessRecords[i].timestamp);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessRecords[i].accessDuration,
            readedData->permissionRecord.accessRecords[i].accessDuration);
    }

    for(uint32_t i = 0; i < permissionUsedRecordParcel.permissionRecord.rejectRecords.size(); i++) {
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.rejectRecords[i].status,
            readedData->permissionRecord.rejectRecords[i].status);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.rejectRecords[i].timestamp,
            readedData->permissionRecord.rejectRecords[i].timestamp);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.rejectRecords[i].accessDuration,
            readedData->permissionRecord.rejectRecords[i].accessDuration);
    }
}

/**
 * @tc.name: PermissionUsedRequestParcel001
 * @tc.desc: Verify the PermissionUsedRequestParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RUP1
 */
HWTEST_F(PrivacyParcelTest, PermissionUsedRequestParcel001, TestSize.Level1)
{
    PermissionUsedRequestParcel permissionUsedRequestParcel;

    permissionUsedRequestParcel.request = {
        .tokenId = 100,
        .isRemote = false,
        .deviceId = "you guess",
        .bundleName = "com.ohos.permissionmanager",
        .beginTimeMillis = 0L,
        .endTimeMillis = 0L,
        .flag = FLAG_PERMISSION_USAGE_SUMMARY,
    };
    permissionUsedRequestParcel.request.permissionList.emplace_back("ohos.permission.CAMERA");
    permissionUsedRequestParcel.request.permissionList.emplace_back("ohos.permission.LOCATION");

    Parcel parcel;
    EXPECT_EQ(true, permissionUsedRequestParcel.Marshalling(parcel));

    std::shared_ptr<PermissionUsedRequestParcel> readedData(PermissionUsedRequestParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(permissionUsedRequestParcel.request.tokenId, readedData->request.tokenId);
    EXPECT_EQ(permissionUsedRequestParcel.request.isRemote, readedData->request.isRemote);
    EXPECT_EQ(permissionUsedRequestParcel.request.deviceId, readedData->request.deviceId);
    EXPECT_EQ(permissionUsedRequestParcel.request.bundleName, readedData->request.bundleName);
    EXPECT_EQ(permissionUsedRequestParcel.request.beginTimeMillis, readedData->request.beginTimeMillis);
    EXPECT_EQ(permissionUsedRequestParcel.request.endTimeMillis, readedData->request.endTimeMillis);
    EXPECT_EQ(permissionUsedRequestParcel.request.flag, readedData->request.flag);

    for(uint32_t i = 0; i < permissionUsedRequestParcel.request.permissionList.size(); i++) {
        EXPECT_EQ(permissionUsedRequestParcel.request.permissionList[i], readedData->request.permissionList[i]);
    }
}

/**
 * @tc.name: PermissionUsedResultParcel001
 * @tc.desc: Verify the PermissionUsedResultParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RWP4
 */
HWTEST_F(PrivacyParcelTest, PermissionUsedResultParcel001, TestSize.Level1)
{
    PermissionUsedResultParcel permissionUsedResultParcel;

    permissionUsedResultParcel.result = {
        .beginTimeMillis = 0L,
        .endTimeMillis = 0L,
    };

    g_bundleUsedRecord1.permissionRecords.emplace_back(g_permissionRecord1);
    g_bundleUsedRecord1.permissionRecords.emplace_back(g_permissionRecord2);
    g_bundleUsedRecord2.permissionRecords.emplace_back(g_permissionRecord1);
    g_bundleUsedRecord2.permissionRecords.emplace_back(g_permissionRecord2);

    permissionUsedResultParcel.result.bundleRecords.emplace_back(g_bundleUsedRecord1);
    permissionUsedResultParcel.result.bundleRecords.emplace_back(g_bundleUsedRecord2);

    Parcel parcel;
    EXPECT_EQ(true, permissionUsedResultParcel.Marshalling(parcel));

    std::shared_ptr<PermissionUsedResultParcel> readedData(PermissionUsedResultParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(permissionUsedResultParcel.result.beginTimeMillis, readedData->result.beginTimeMillis);
    EXPECT_EQ(permissionUsedResultParcel.result.endTimeMillis, readedData->result.endTimeMillis);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
