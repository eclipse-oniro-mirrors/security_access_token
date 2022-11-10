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

#include "access_token.h"
#include "hap_info_parcel.h"
#include "hap_policy_parcel.h"
#include "hap_token_info_parcel.h"
#include "hap_token_info_for_sync_parcel.h"
#include "native_token_info_for_sync_parcel.h"
#include "native_token_info_parcel.h"
#include "parcel.h"
#include "parcel_utils.h"
#include "permission_state_change_scope_parcel.h"
#include "permission_state_change_info_parcel.h"
#include "permission_state_full.h"
#include "permission_state_full_parcel.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t DEFAULT_API_VERSION = 8;
static const std::string TEST_PERMISSION_NAME_ALPHA = "ohos.permission.ALPHA";
static const std::string TEST_PERMISSION_NAME_BETA = "ohos.permission.BETA";
static constexpr AccessTokenID TEST_TOKEN_ID = 10002;
static constexpr int32_t TEST_PERMSTATE_CHANGE_TYPE = 10001;

PermissionDef g_permDefAlpha = {
    .permissionName = TEST_PERMISSION_NAME_ALPHA,
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "annoying",
    .descriptionId = 1
};
PermissionDef g_permDefBeta = {
    .permissionName = TEST_PERMISSION_NAME_BETA,
    .bundleName = "accesstoken_test",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "so trouble",
    .descriptionId = 1
};

PermissionStateFull g_permStatAlpha = {
    .permissionName = TEST_PERMISSION_NAME_ALPHA,
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_DENIED},
    .grantFlags = {PermissionFlag::PERMISSION_USER_SET}
};
PermissionStateFull g_permStatBeta = {
    .permissionName = TEST_PERMISSION_NAME_BETA,
    .isGeneral = true,
    .resDeviceID = {"device"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}
};
}
class AccessTokenParcelTest : public testing::Test  {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AccessTokenParcelTest::SetUpTestCase(void) {}
void AccessTokenParcelTest::TearDownTestCase(void) {}
void AccessTokenParcelTest::SetUp(void) {}
void AccessTokenParcelTest::TearDown(void) {}

/**
 * @tc.name: HapInfoParcel001
 * @tc.desc: Test HapInfo Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, HapInfoParcel001, TestSize.Level1)
{
    HapInfoParcel hapinfoParcel;
    hapinfoParcel.hapInfoParameter = {
        .userID = 1,
        .bundleName = "accesstoken_test",
        .instIndex = 0,
        .appIDDesc = "testtesttesttest",
        .apiVersion = DEFAULT_API_VERSION,
    };

    Parcel parcel;
    EXPECT_EQ(true, hapinfoParcel.Marshalling(parcel));

    std::shared_ptr<HapInfoParcel> readedData(HapInfoParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);

    EXPECT_EQ(hapinfoParcel.hapInfoParameter.userID, readedData->hapInfoParameter.userID);
    EXPECT_EQ(true, hapinfoParcel.hapInfoParameter.bundleName == readedData->hapInfoParameter.bundleName);
    EXPECT_EQ(hapinfoParcel.hapInfoParameter.instIndex, readedData->hapInfoParameter.instIndex);
    EXPECT_EQ(true, hapinfoParcel.hapInfoParameter.appIDDesc == readedData->hapInfoParameter.appIDDesc);
    EXPECT_EQ(hapinfoParcel.hapInfoParameter.apiVersion, readedData->hapInfoParameter.apiVersion);
}

/**
 * @tc.name: HapPolicyParcel001
 * @tc.desc: Test HapPolicy Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, HapPolicyParcel001, TestSize.Level1)
{
    HapPolicyParcel hapPolicyParcel;

    hapPolicyParcel.hapPolicyParameter.apl = ATokenAplEnum::APL_NORMAL;
    hapPolicyParcel.hapPolicyParameter.domain = "test.domain";
    hapPolicyParcel.hapPolicyParameter.permList.emplace_back(g_permDefAlpha);
    hapPolicyParcel.hapPolicyParameter.permList.emplace_back(g_permDefBeta);
    hapPolicyParcel.hapPolicyParameter.permStateList.emplace_back(g_permStatAlpha);
    hapPolicyParcel.hapPolicyParameter.permStateList.emplace_back(g_permStatBeta);

    Parcel parcel;
    EXPECT_EQ(true, hapPolicyParcel.Marshalling(parcel));

    std::shared_ptr<HapPolicyParcel> readedData(HapPolicyParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);

    EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.apl, readedData->hapPolicyParameter.apl);
    EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.domain, readedData->hapPolicyParameter.domain);
    EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList.size(), readedData->hapPolicyParameter.permList.size());
    EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList.size(),
        readedData->hapPolicyParameter.permStateList.size());

    for (uint32_t i = 0; i < hapPolicyParcel.hapPolicyParameter.permList.size(); i++) {
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].permissionName,
            readedData->hapPolicyParameter.permList[i].permissionName);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].bundleName,
            readedData->hapPolicyParameter.permList[i].bundleName);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].grantMode,
            readedData->hapPolicyParameter.permList[i].grantMode);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].availableLevel,
            readedData->hapPolicyParameter.permList[i].availableLevel);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].label,
            readedData->hapPolicyParameter.permList[i].label);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].labelId,
            readedData->hapPolicyParameter.permList[i].labelId);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].description,
            readedData->hapPolicyParameter.permList[i].description);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permList[i].descriptionId,
            readedData->hapPolicyParameter.permList[i].descriptionId);
    }

    for (uint32_t i = 0; i < hapPolicyParcel.hapPolicyParameter.permStateList.size(); i++) {
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].permissionName,
            readedData->hapPolicyParameter.permStateList[i].permissionName);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].isGeneral,
            readedData->hapPolicyParameter.permStateList[i].isGeneral);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].resDeviceID,
            readedData->hapPolicyParameter.permStateList[i].resDeviceID);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].grantStatus,
            readedData->hapPolicyParameter.permStateList[i].grantStatus);
        EXPECT_EQ(hapPolicyParcel.hapPolicyParameter.permStateList[i].grantFlags,
            readedData->hapPolicyParameter.permStateList[i].grantFlags);
    }
}

/**
 * @tc.name: PermissionStateChangeInfoParcel001
 * @tc.desc: Test PermissionStateChangeInfo Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, PermissionStateChangeInfoParcel001, TestSize.Level1)
{
    PermissionStateChangeInfoParcel permissionStateParcel;
    permissionStateParcel.changeInfo.PermStateChangeType = TEST_PERMSTATE_CHANGE_TYPE;
    permissionStateParcel.changeInfo.tokenID = TEST_TOKEN_ID;
    permissionStateParcel.changeInfo.permissionName = TEST_PERMISSION_NAME_ALPHA;

    Parcel parcel;
    EXPECT_EQ(true, permissionStateParcel.Marshalling(parcel));

    std::shared_ptr<PermissionStateChangeInfoParcel> readedData(PermissionStateChangeInfoParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
    EXPECT_EQ(permissionStateParcel.changeInfo.PermStateChangeType, readedData->changeInfo.PermStateChangeType);
    EXPECT_EQ(permissionStateParcel.changeInfo.tokenID, readedData->changeInfo.tokenID);
    EXPECT_EQ(permissionStateParcel.changeInfo.permissionName, readedData->changeInfo.permissionName);
}

/**
 * @tc.name: PermStateChangeScopeParcel001
 * @tc.desc: Test PermStateChangeScope Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, PermStateChangeScopeParcel001, TestSize.Level1)
{
    PermStateChangeScopeParcel permStateChangeScopeParcel;
    permStateChangeScopeParcel.scope.tokenIDs.emplace_back(TEST_TOKEN_ID);
    permStateChangeScopeParcel.scope.permList.emplace_back(TEST_PERMISSION_NAME_ALPHA);

    Parcel parcel;
    EXPECT_EQ(true, permStateChangeScopeParcel.Marshalling(parcel));

    std::shared_ptr<PermStateChangeScopeParcel> readedData(PermStateChangeScopeParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
    
    EXPECT_EQ(true,  permStateChangeScopeParcel.scope.tokenIDs.size() == readedData->scope.tokenIDs.size());
    EXPECT_EQ(true,  permStateChangeScopeParcel.scope.permList.size() == readedData->scope.permList.size());

    for (uint32_t i = 0; i < readedData->scope.tokenIDs.size(); i++) {
        EXPECT_EQ(permStateChangeScopeParcel.scope.tokenIDs[i], readedData->scope.tokenIDs[i]);
    }
    for (uint32_t i = 0; i < readedData->scope.permList.size(); i++) {
        EXPECT_EQ(true, permStateChangeScopeParcel.scope.permList[i] == readedData->scope.permList[i]);
    }
}

/**
 * @tc.name: HapTokenInfoForSyncParcel001
 * @tc.desc: Test HapTokenInfoForSync Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, HapTokenInfoForSyncParcel001, TestSize.Level1)
{
    HapTokenInfoForSyncParcel hapTokenInfoSync;

    HapTokenInfo hapTokenInfo;
    hapTokenInfo.apl = ATokenAplEnum::APL_NORMAL;
    hapTokenInfo.ver = 0;
    hapTokenInfo.userID = 2;
    hapTokenInfo.bundleName = "bundle";
    hapTokenInfo.apiVersion = 8;
    hapTokenInfo.instIndex = 0;
    hapTokenInfo.dlpType = 0;
    hapTokenInfo.appID = "111";
    hapTokenInfo.deviceID = "0";
    hapTokenInfo.tokenID = 0x53100000;
    hapTokenInfo.tokenAttr = 0;
    hapTokenInfoSync.hapTokenInfoForSyncParams.baseInfo = hapTokenInfo;
    hapTokenInfoSync.hapTokenInfoForSyncParams.permStateList.emplace_back(g_permStatBeta);

    Parcel parcel;
    EXPECT_EQ(true, hapTokenInfoSync.Marshalling(parcel));
    std::shared_ptr<HapTokenInfoForSyncParcel> readedData(HapTokenInfoForSyncParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
}

/**
 * @tc.name: HapTokenInfoForSyncParcel002
 * @tc.desc: Test HapTokenInfoForSync Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, HapTokenInfoForSyncParcel002, TestSize.Level1)
{
    HapTokenInfoForSyncParcel hapTokenInfoSync;

    HapTokenInfo hapTokenInfo;
    hapTokenInfo.apl = ATokenAplEnum::APL_NORMAL;
    hapTokenInfo.ver = 0;
    hapTokenInfo.userID = 2;
    hapTokenInfo.bundleName = "bundle";
    hapTokenInfo.apiVersion = 8;
    hapTokenInfo.instIndex = 0;
    hapTokenInfo.dlpType = 0;
    hapTokenInfo.appID = "111";
    hapTokenInfo.deviceID = "0";
    hapTokenInfo.tokenID = 0x53100000;
    hapTokenInfo.tokenAttr = 0;

    Parcel out;
    HapTokenInfoParcel baseInfoParcel;
    baseInfoParcel.hapTokenInfoParams = hapTokenInfo;
    out.WriteParcelable(&baseInfoParcel);

    std::vector<PermissionStateFull> permStateList;
    for (uint32_t i = 0; i < MAX_PERMLIST_SIZE; i++) {
        permStateList.emplace_back(g_permStatBeta);
    }
    uint32_t permStateListSize = permStateList.size();
    out.WriteUint32(permStateListSize);
    for (uint32_t i = 0; i < permStateListSize; i++) {
        PermissionStateFullParcel permStateParcel;
        permStateParcel.permStatFull = permStateList[i];
        out.WriteParcelable(&permStateParcel);
    }

    std::shared_ptr<HapTokenInfoForSyncParcel> readedData(HapTokenInfoForSyncParcel::Unmarshalling(out));
    EXPECT_NE(nullptr, readedData);

    Parcel out1;
    out1.WriteParcelable(&baseInfoParcel);
    permStateList.emplace_back(g_permStatBeta);

    permStateListSize = permStateList.size();
    out1.WriteUint32(permStateListSize);
    for (uint32_t i = 0; i < permStateListSize; i++) {
        PermissionStateFullParcel permStateParcel;
        permStateParcel.permStatFull = permStateList[i];
        out1.WriteParcelable(&permStateParcel);
    }

    std::shared_ptr<HapTokenInfoForSyncParcel> readedData1(HapTokenInfoForSyncParcel::Unmarshalling(out1));
    EXPECT_EQ(true, readedData1 == nullptr);
}

/**
 * @tc.name: NativeTokenInfoForSyncParcel001
 * @tc.desc: Test HapTokenInfoForSync Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, NativeTokenInfoForSyncParcel001, TestSize.Level1)
{
    NativeTokenInfoForSyncParcel nativeTokenInfoSync;

    NativeTokenInfo baseInfo;
    baseInfo.apl = APL_NORMAL,
    baseInfo.ver = 1,
    baseInfo.processName = "native_token_test0",
    baseInfo.tokenID = 0x28100000, // 0x28100000 tokenid
    baseInfo.tokenAttr = 0,
    baseInfo.dcap =  {"AT_CAP", "ST_CAP"};
    baseInfo.nativeAcls = {"ohos.permission.LOCATION"};

    Parcel out;
    NativeTokenInfoParcel baseInfoParcel;
    baseInfoParcel.nativeTokenInfoParams = baseInfo;
    out.WriteParcelable(&baseInfoParcel);

    std::vector<PermissionStateFull> permStateList;
    for (uint32_t i = 0; i < MAX_PERMLIST_SIZE; i++) {
        permStateList.emplace_back(g_permStatBeta);
    }
    uint32_t permStateListSize = permStateList.size();
    out.WriteUint32(permStateListSize);
    for (uint32_t i = 0; i < permStateListSize; i++) {
        PermissionStateFullParcel permStateParcel;
        permStateParcel.permStatFull = permStateList[i];
        out.WriteParcelable(&permStateParcel);
    }

    std::shared_ptr<NativeTokenInfoForSyncParcel> readedData(NativeTokenInfoForSyncParcel::Unmarshalling(out));
    EXPECT_NE(nullptr, readedData);

    Parcel outInvalid;
    outInvalid.WriteParcelable(&baseInfoParcel);
    permStateList.emplace_back(g_permStatBeta);

    permStateListSize = permStateList.size();
    outInvalid.WriteUint32(permStateListSize);
    for (uint32_t i = 0; i < permStateListSize; i++) {
        PermissionStateFullParcel permStateParcel;
        permStateParcel.permStatFull = permStateList[i];
        outInvalid.WriteParcelable(&permStateParcel);
    }

    std::shared_ptr<NativeTokenInfoForSyncParcel> readedData1(NativeTokenInfoForSyncParcel::Unmarshalling(outInvalid));
    EXPECT_EQ(true, readedData1 == nullptr);
}

/**
 * @tc.name: NativeTokenInfoForSyncParcel002
 * @tc.desc: Test HapTokenInfoForSync Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, NativeTokenInfoForSyncParcel002, TestSize.Level1)
{
    NativeTokenInfoForSyncParcel nativeTokenInfoSync;

    NativeTokenInfo baseInfo;
    baseInfo.apl = APL_NORMAL,
    baseInfo.ver = 1,
    baseInfo.processName = "native_token_test0",
    baseInfo.tokenID = 0x28100000, // 0x28100000 tokenid
    baseInfo.tokenAttr = 0,
    baseInfo.dcap =  {"AT_CAP", "ST_CAP"};
    baseInfo.nativeAcls = {"ohos.permission.LOCATION"};

    nativeTokenInfoSync.nativeTokenInfoForSyncParams.baseInfo = baseInfo;
    nativeTokenInfoSync.nativeTokenInfoForSyncParams.permStateList.emplace_back(g_permStatBeta);

    Parcel parcel;
    EXPECT_EQ(true, nativeTokenInfoSync.Marshalling(parcel));
    std::shared_ptr<NativeTokenInfoForSyncParcel> readedData(NativeTokenInfoForSyncParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
}

static void PutData(Parcel& out, uint32_t deviceSize, uint32_t statusSize, uint32_t flagSize)
{
    out.WriteString("ohos.permission.LOCATION");
    out.WriteBool(true);
    out.WriteUint32(deviceSize);
    for (uint32_t i = 0; i < deviceSize; i++) {
        out.WriteString("deviceName");
    }
    out.WriteUint32(statusSize);
    for (uint32_t i = 0; i < statusSize; i++) {
        out.WriteInt32(0);
    }
    out.WriteUint32(flagSize);
    for (uint32_t i = 0; i < flagSize; i++) {
        out.WriteInt32(0);
    }
}

/**
 * @tc.name: PermissionStateFullParcel001
 * @tc.desc: Test permissionStateFullParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, PermissionStateFullParcel001, TestSize.Level1)
{
    Parcel out;
    PutData(out, MAX_DEVICE_ID_SIZE, MAX_DEVICE_ID_SIZE, MAX_DEVICE_ID_SIZE + 1);
    std::shared_ptr<PermissionStateFullParcel> readedData(PermissionStateFullParcel::Unmarshalling(out));
    EXPECT_EQ(nullptr, readedData);

    Parcel out1;
    PutData(out1, MAX_DEVICE_ID_SIZE, MAX_DEVICE_ID_SIZE + 1, MAX_DEVICE_ID_SIZE + 1);
    std::shared_ptr<PermissionStateFullParcel> readedData1(PermissionStateFullParcel::Unmarshalling(out1));
    EXPECT_EQ(readedData1, nullptr);

    Parcel out2;
    PutData(out2, MAX_DEVICE_ID_SIZE + 1, MAX_DEVICE_ID_SIZE + 1, MAX_DEVICE_ID_SIZE + 1);
    std::shared_ptr<PermissionStateFullParcel> readedData2(PermissionStateFullParcel::Unmarshalling(out2));
    EXPECT_EQ(readedData2, nullptr);

    Parcel out3;
    PutData(out3, MAX_DEVICE_ID_SIZE, MAX_DEVICE_ID_SIZE, MAX_DEVICE_ID_SIZE);
    std::shared_ptr<PermissionStateFullParcel> readedData3(PermissionStateFullParcel::Unmarshalling(out3));
    EXPECT_NE(readedData3, nullptr);
}

/**
 * @tc.name: PermissionStateFullParcel002
 * @tc.desc: Test permissionStateFullParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, PermissionStateFullParcel002, TestSize.Level1)
{
    PermissionStateFullParcel permissionStateFullParcel;
    permissionStateFullParcel.permStatFull.permissionName = "permissionName";
    permissionStateFullParcel.permStatFull.isGeneral = false;
    permissionStateFullParcel.permStatFull.resDeviceID = {"device"};
    permissionStateFullParcel.permStatFull.grantStatus = {1};
    permissionStateFullParcel.permStatFull.grantFlags = {0};
    Parcel parcel;
    EXPECT_EQ(true, permissionStateFullParcel.Marshalling(parcel));

    std::shared_ptr<PermissionStateFullParcel> readedData(PermissionStateFullParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
}


static void PutNativeTokenInfoData(Parcel& out, uint32_t dcapSize, uint32_t aclSize)
{
    EXPECT_EQ(true, out.WriteInt32(APL_NORMAL));
    EXPECT_EQ(true, out.WriteUint8(1));
    EXPECT_EQ(true, out.WriteString("native_token_test0"));
    EXPECT_EQ(true, out.WriteUint32(0x28100000)); // 0x28100000 tokenid
    EXPECT_EQ(true, out.WriteUint32(0));

    EXPECT_EQ(true, out.WriteUint32(dcapSize));
    for (uint32_t i = 0; i < dcapSize; i++) {
        EXPECT_EQ(true, out.WriteString("dcapItem"));
    }
    EXPECT_EQ(true, out.WriteUint32(aclSize));
    for (uint32_t i = 0; i < aclSize; i++) {
        EXPECT_EQ(true, out.WriteString("ohos.permission.LOCATION"));
    }
}

/**
 * @tc.name: NativeTokenInfoParcel001
 * @tc.desc: Test NativeTokenInfoParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, NativeTokenInfoParcel001, TestSize.Level1)
{
    Parcel out;
    PutNativeTokenInfoData(out, MAX_DCAP_SIZE, MAX_ACL_SIZE);
    std::shared_ptr<NativeTokenInfoParcel> readedData(NativeTokenInfoParcel::Unmarshalling(out));
    EXPECT_NE(nullptr, readedData);

    Parcel out1;
    PutNativeTokenInfoData(out1, MAX_DCAP_SIZE, MAX_ACL_SIZE + 1);
    std::shared_ptr<NativeTokenInfoParcel> readedData1(NativeTokenInfoParcel::Unmarshalling(out1));
    EXPECT_EQ(readedData1, nullptr);

    Parcel out2;
    PutNativeTokenInfoData(out2, MAX_DCAP_SIZE + 1, MAX_ACL_SIZE + 1);
    std::shared_ptr<NativeTokenInfoParcel> readedData2(NativeTokenInfoParcel::Unmarshalling(out2));
    EXPECT_EQ(readedData2, nullptr);
}

/**
 * @tc.name: NativeTokenInfoParcel002
 * @tc.desc: Test NativeTokenInfoParcel Marshalling/Unmarshalling.
 * @tc.type: FUNC
 * @tc.require: issueI5QKZF
 */
HWTEST_F(AccessTokenParcelTest, NativeTokenInfoParcel002, TestSize.Level1)
{
    NativeTokenInfoParcel nativeTokenInfoParcel;
    nativeTokenInfoParcel.nativeTokenInfoParams.apl = APL_NORMAL;
    nativeTokenInfoParcel.nativeTokenInfoParams.ver = 0;
    nativeTokenInfoParcel.nativeTokenInfoParams.processName = "processName";
    nativeTokenInfoParcel.nativeTokenInfoParams.dcap = {"AT_CAP"};
    nativeTokenInfoParcel.nativeTokenInfoParams.tokenID = 12; // 12 : tokenid
    nativeTokenInfoParcel.nativeTokenInfoParams.tokenAttr = 0;
    nativeTokenInfoParcel.nativeTokenInfoParams.nativeAcls = {};

    Parcel parcel;
    EXPECT_EQ(true, nativeTokenInfoParcel.Marshalling(parcel));
    std::shared_ptr<NativeTokenInfoParcel> readedData(NativeTokenInfoParcel::Unmarshalling(parcel));
    EXPECT_NE(nullptr, readedData);
}

/*
 * @tc.name: NativeTokenInfoParcel003
 * @tc.desc: NativeTokenInfoParcel::Marshalling function test dcap size > 32
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(AccessTokenParcelTest, NativeTokenInfoParcel003, TestSize.Level1)
{
    std::vector<std::string> vec(33, "AT_CAP");
    NativeTokenInfoParcel nativeTokenInfoParcel;
    nativeTokenInfoParcel.nativeTokenInfoParams.apl = APL_NORMAL;
    nativeTokenInfoParcel.nativeTokenInfoParams.ver = 0;
    nativeTokenInfoParcel.nativeTokenInfoParams.processName = "processName";
    nativeTokenInfoParcel.nativeTokenInfoParams.dcap = vec; // size is 33
    nativeTokenInfoParcel.nativeTokenInfoParams.tokenID = 12; // 12 : tokenid
    nativeTokenInfoParcel.nativeTokenInfoParams.tokenAttr = 0;
    nativeTokenInfoParcel.nativeTokenInfoParams.nativeAcls = {};

    Parcel parcel;
    EXPECT_NE(true, nativeTokenInfoParcel.Marshalling(parcel));
}

/*
 * @tc.name: NativeTokenInfoParcel004
 * @tc.desc: NativeTokenInfoParcel::Marshalling function test nativeAcls size > 64
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(AccessTokenParcelTest, NativeTokenInfoParcel004, TestSize.Level1)
{
    std::vector<std::string> vec(65, "AT_CAP");
    NativeTokenInfoParcel nativeTokenInfoParcel;
    nativeTokenInfoParcel.nativeTokenInfoParams.apl = APL_NORMAL;
    nativeTokenInfoParcel.nativeTokenInfoParams.ver = 0;
    nativeTokenInfoParcel.nativeTokenInfoParams.processName = "processName";
    nativeTokenInfoParcel.nativeTokenInfoParams.dcap = {"AT_CAP"};
    nativeTokenInfoParcel.nativeTokenInfoParams.tokenID = 12; // 12 : tokenid
    nativeTokenInfoParcel.nativeTokenInfoParams.tokenAttr = 0;
    nativeTokenInfoParcel.nativeTokenInfoParams.nativeAcls = vec; // size is 65

    Parcel parcel;
    EXPECT_NE(true, nativeTokenInfoParcel.Marshalling(parcel));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
