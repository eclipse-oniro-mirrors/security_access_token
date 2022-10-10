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

#include "bundle_used_record_parcel.h"
#include "parcel.h"
#include "parcel_utils.h"
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

class PrivacyParcelTest : public testing::Test  {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
};

void PrivacyParcelTest::SetUpTestCase() {}
void PrivacyParcelTest::TearDownTestCase() {}
void PrivacyParcelTest::SetUp() {}
void PrivacyParcelTest::TearDown() {}

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
        .deviceId = "device",
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
        .deviceId = "device",
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

    for (uint32_t i = 0; i < permissionUsedRecordParcel.permissionRecord.accessRecords.size(); i++) {
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessRecords[i].status,
            readedData->permissionRecord.accessRecords[i].status);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessRecords[i].timestamp,
            readedData->permissionRecord.accessRecords[i].timestamp);
        EXPECT_EQ(permissionUsedRecordParcel.permissionRecord.accessRecords[i].accessDuration,
            readedData->permissionRecord.accessRecords[i].accessDuration);
    }

    for (uint32_t i = 0; i < permissionUsedRecordParcel.permissionRecord.rejectRecords.size(); i++) {
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

    for (uint32_t i = 0; i < permissionUsedRequestParcel.request.permissionList.size(); i++) {
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

/**
 * @tc.name: UsedRecordDetailParcel001
 * @tc.desc: Verify the UsedRecordDetailParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RWP4
 */
HWTEST_F(PrivacyParcelTest, UsedRecordDetailParcel001, TestSize.Level1)
{
    UsedRecordDetailParcel usedRecordDetailParcel;

    usedRecordDetailParcel.detail = {
        .status = 0,
        .timestamp = 0L,
        .accessDuration = 0L,
    };

    Parcel parcel;
    EXPECT_EQ(true, usedRecordDetailParcel.Marshalling(parcel));

    std::shared_ptr<UsedRecordDetailParcel> readedData(UsedRecordDetailParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    EXPECT_EQ(usedRecordDetailParcel.detail.status, readedData->detail.status);
    EXPECT_EQ(usedRecordDetailParcel.detail.timestamp, readedData->detail.timestamp);
    EXPECT_EQ(usedRecordDetailParcel.detail.accessDuration, readedData->detail.accessDuration);
}

void BundleUsedRecordData(Parcel& out, uint32_t size)
{
    EXPECT_EQ(true, out.WriteUint32(100)); // 100: tokenid
    EXPECT_EQ(true, out.WriteBool(false));
    EXPECT_EQ(true, out.WriteString("device"));
    EXPECT_EQ(true, out.WriteString("bundleName"));

    EXPECT_EQ(true, out.WriteUint32(size));

    g_permissionRecord1.accessRecords.emplace_back(g_accessRecord1);

    for (uint32_t i = 0; i < size; i++) {
        PermissionUsedRecordParcel permRecordParcel;
        permRecordParcel.permissionRecord = g_permissionRecord1;
        out.WriteParcelable(&permRecordParcel);
    }
}
/**
 * @tc.name: BundleUsedRecordParcel002
 * @tc.desc: Test BundleUsedRecordParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(PrivacyParcelTest, BundleUsedRecordParcel002, TestSize.Level1)
{
    Parcel parcel;
    BundleUsedRecordData(parcel, MAX_RECORD_SIZE);
    std::shared_ptr<BundleUsedRecordParcel> readedData(BundleUsedRecordParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    Parcel parcel1;
    BundleUsedRecordData(parcel1, MAX_RECORD_SIZE + 1);
    std::shared_ptr<BundleUsedRecordParcel> readedData1(BundleUsedRecordParcel::Unmarshalling(parcel1));
    EXPECT_EQ(true, readedData1 == nullptr);
}

void DataMarshalling(Parcel& out, uint32_t accessSize, uint32_t rejectSize)
{
    UsedRecordDetail detailIns = {0, 0L, 0L};
    EXPECT_EQ(true, out.WriteString("permissionName"));
    EXPECT_EQ(true, out.WriteInt32(1));
    EXPECT_EQ(true, out.WriteInt32(1));
    EXPECT_EQ(true, out.WriteInt64(0L));
    EXPECT_EQ(true, out.WriteInt64(0L));
    EXPECT_EQ(true, out.WriteInt64(0L));

    EXPECT_EQ(true, out.WriteUint32(accessSize));
    for (uint32_t i = 0; i < accessSize; i++) {
        UsedRecordDetailParcel detailParcel;
        detailParcel.detail = detailIns;
        out.WriteParcelable(&detailParcel);
    }

    EXPECT_EQ(true, out.WriteUint32(rejectSize));
    for (uint32_t i = 0; i < rejectSize; i++) {
        UsedRecordDetailParcel detailParcel;
        detailParcel.detail = detailIns;
        out.WriteParcelable(&detailParcel);
    }
}

/**
 * @tc.name: PermissionUsedRecordParcel002
 * @tc.desc: Test PermissionUsedRecordParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(PrivacyParcelTest, PermissionUsedRecordParcel002, TestSize.Level1)
{
    Parcel parcel;
    DataMarshalling(parcel, MAX_ACCESS_RECORD_SIZE, MAX_ACCESS_RECORD_SIZE);
    std::shared_ptr<PermissionUsedRecordParcel> readedData(PermissionUsedRecordParcel::Unmarshalling(parcel));
    EXPECT_EQ(true, readedData != nullptr);

    Parcel parcel1;
    DataMarshalling(parcel1, MAX_ACCESS_RECORD_SIZE, MAX_ACCESS_RECORD_SIZE + 1);
    std::shared_ptr<PermissionUsedRecordParcel> readedData1(PermissionUsedRecordParcel::Unmarshalling(parcel1));
    EXPECT_EQ(true, readedData1 == nullptr);

    Parcel parcel2;
    DataMarshalling(parcel2, MAX_ACCESS_RECORD_SIZE + 1, MAX_ACCESS_RECORD_SIZE);
    std::shared_ptr<PermissionUsedRecordParcel> readedData2(PermissionUsedRecordParcel::Unmarshalling(parcel2));
    EXPECT_EQ(true, readedData2 == nullptr);
}

/**
 * @tc.name: PermissionUsedRequestParcel002
 * @tc.desc: Verify the PermissionUsedRequestParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RUP1
 */
HWTEST_F(PrivacyParcelTest, PermissionUsedRequestParcel002, TestSize.Level1)
{
    PermissionUsedRequestParcel permissionUsedRequestParcel;

    permissionUsedRequestParcel.request = {
        .tokenId = 100,
        .isRemote = false,
        .deviceId = "deviceId",
        .bundleName = "com.ohos.permissionmanager",
        .beginTimeMillis = 0L,
        .endTimeMillis = 0L,
        .flag = FLAG_PERMISSION_USAGE_SUMMARY,
    };
    for (uint32_t i = 0; i < MAX_PERMLIST_SIZE; i++) {
        permissionUsedRequestParcel.request.permissionList.emplace_back("ohos.permission.CAMERA");
    }

    Parcel parcel;
    EXPECT_EQ(true, permissionUsedRequestParcel.Marshalling(parcel));
    std::shared_ptr<PermissionUsedRequestParcel> readedData(PermissionUsedRequestParcel::Unmarshalling(parcel));
    EXPECT_NE(readedData, nullptr);

    permissionUsedRequestParcel.request.permissionList.emplace_back("ohos.permission.CAMERA");
    Parcel parcel1;
    EXPECT_EQ(true, permissionUsedRequestParcel.Marshalling(parcel1));
    std::shared_ptr<PermissionUsedRequestParcel> readedData1(PermissionUsedRequestParcel::Unmarshalling(parcel1));
    EXPECT_EQ(readedData1, nullptr);
}

/**
 * @tc.name: PermissionUsedResultParcel002
 * @tc.desc: Verify the PermissionUsedResultParcel Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: issueI5RWP4
 */
HWTEST_F(PrivacyParcelTest, PermissionUsedResultParcel002, TestSize.Level1)
{
    PermissionUsedResultParcel permissionUsedResultParcel;

    permissionUsedResultParcel.result = {
        .beginTimeMillis = 0L,
        .endTimeMillis = 0L,
    };

    g_bundleUsedRecord1.permissionRecords.emplace_back(g_permissionRecord1);
    g_bundleUsedRecord1.permissionRecords.emplace_back(g_permissionRecord2);

    for (uint32_t i = 0; i < 1024; i++) {
        permissionUsedResultParcel.result.bundleRecords.emplace_back(g_bundleUsedRecord1);
    }

    Parcel parcel;
    EXPECT_EQ(true, permissionUsedResultParcel.Marshalling(parcel));
    auto* resultParcel = new (std::nothrow) PermissionUsedResultParcel();
    ASSERT_NE(resultParcel, nullptr);
    EXPECT_EQ(true, parcel.ReadInt64(resultParcel->result.beginTimeMillis));
    EXPECT_EQ(true, parcel.ReadInt64(resultParcel->result.endTimeMillis));
    uint32_t bundResponseSize = 0;
    EXPECT_EQ(true, parcel.ReadUint32(bundResponseSize));
    EXPECT_EQ(true, bundResponseSize <= MAX_RECORD_SIZE);
    EXPECT_EQ(true, resultParcel != nullptr);
    delete resultParcel;
    permissionUsedResultParcel.result.bundleRecords.emplace_back(g_bundleUsedRecord1);

    Parcel parcel1;
    EXPECT_EQ(true, permissionUsedResultParcel.Marshalling(parcel1));
    auto* resultParcel2 = new (std::nothrow) PermissionUsedResultParcel();
    ASSERT_NE(resultParcel2, nullptr);
    EXPECT_EQ(true, parcel1.ReadInt64(resultParcel2->result.beginTimeMillis));
    EXPECT_EQ(true, parcel1.ReadInt64(resultParcel2->result.endTimeMillis));
    uint32_t bundResponseSize1 = 0;
    EXPECT_EQ(true, parcel1.ReadUint32(bundResponseSize1));
    GTEST_LOG_(INFO) << "bundResponseSize1 :" << bundResponseSize1;
    EXPECT_EQ(true, bundResponseSize1 > MAX_RECORD_SIZE);
    delete resultParcel2;

    Parcel parcel2;
    EXPECT_EQ(true, permissionUsedResultParcel.Marshalling(parcel2));
    std::shared_ptr<PermissionUsedResultParcel> readedData1(PermissionUsedResultParcel::Unmarshalling(parcel2));
    EXPECT_EQ(readedData1, nullptr);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
