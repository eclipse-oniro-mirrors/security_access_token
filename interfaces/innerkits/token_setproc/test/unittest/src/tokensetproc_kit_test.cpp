/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "tokensetproc_kit_test.h"
#include <ctime>
#include <cstring>
#include "spm_setproc.h"
#include "token_setproc.h"
#include "perm_setproc_c.h"
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::Security;
using namespace OHOS::Security::AccessToken;

static const uint32_t ACCESS_TOKEN_UID = 3020;
static const uint32_t MAX_PROCESS_SIZE = 500; // same as kernel size
static const uint32_t MAX_PERM_NUM = 2048; // 64 * 32
static const uint32_t INVALID_OP_CODE = 65532;
static uint32_t g_tokeId = 5000;
static const std::vector<uint32_t> g_opCodeList = {0, 1, 2, 3, 4, 5, 63, 128};
static const std::vector<bool> g_statusList = {true, true, false, false, false, false, true, false};
static uint32_t g_selfUid;
static const int32_t CYCLE_TIMES = 1000;
static const int32_t TEST_UID = 1000;

void TokensetprocKitTest::SetUpTestCase()
{
    g_selfUid = getuid();
}

void TokensetprocKitTest::TearDownTestCase()
{}

void TokensetprocKitTest::SetUp()
{}

void TokensetprocKitTest::TearDown()
{
    OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId);
    setuid(g_selfUid);
}

/**
 * @tc.name: AddPermissionToKernel001
 * @tc.desc: cannot AddPermissionToKernel with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel001, TestSize.Level0)
{
    setuid(TEST_UID); // random uid
    ASSERT_EQ(EPERM, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    setuid(g_selfUid);
}

/**
 * @tc.name: AddPermissionToKernel002
 * @tc.desc: AddPermissionToKernel with differet size parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel002, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> opcodeList = {0, 1, 2};
    std::vector<bool> statusList = {0, 0};
    ASSERT_EQ(ACCESS_TOKEN_PARAM_INVALID, AddPermissionToKernel(g_tokeId, opcodeList, statusList));
    ASSERT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    setuid(g_selfUid);
}

/**
 * @tc.name: AddPermissionToKernel003
 * @tc.desc: AddPermissionToKernel with size is 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel003, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> opcodeList;
    std::vector<bool> statusList;
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opcodeList, statusList));
    ASSERT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    setuid(g_selfUid);
}

/**
 * @tc.name: AddPermissionToKernel004
 * @tc.desc: AddPermissionToKernel with having permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel004, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    ASSERT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    setuid(g_selfUid);
}

/**
 * @tc.name: AddPermissionToKernel005
 * @tc.desc: update less permission with same token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel005, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> opCodeList1 = {123, 124};
    std::vector<bool> statusList1 = {false, false}; // not granted
    std::vector<uint32_t> opCodeList2 = {123};
    std::vector<bool> statusList2 = {true}; // granted

    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList1, statusList1));
    bool isGranted = false;
    EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, opCodeList1[0], isGranted));
    EXPECT_EQ(false, isGranted);

    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList2, statusList2));

    EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, opCodeList2[0], isGranted));
    EXPECT_EQ(true, isGranted);
    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));

    setuid(g_selfUid);
}

/**
 * @tc.name: AddPermissionToKernel006
 * @tc.desc: update more permissiion with same token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel006, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> opCodeList1 = {123};
    std::vector<bool> statusList1 = {true}; // granted
    std::vector<uint32_t> opCodeList2 = {123, 124};
    std::vector<bool> statusList2 = {false, false}; // not granted

    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList1, statusList1));
    bool isGranted = false;
    EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, opCodeList1[0], isGranted));
    EXPECT_EQ(true, isGranted);

    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList2, statusList2));
    EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, opCodeList2[0], isGranted));
    EXPECT_EQ(false, isGranted);

    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));

    setuid(g_selfUid);
}

/**
 * @tc.name: AddPermissionToKernel007
 * @tc.desc: AddPermissionToKernel with different token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel007, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    uint32_t token1 = 111;
    uint32_t token2 = 222;
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(token1, g_opCodeList, g_statusList));
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(token2, g_opCodeList, g_statusList));
    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(token1));
    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(token2));
    setuid(g_selfUid);
}

/**
 * @tc.name: AddPermissionToKernel008
 * @tc.desc: AddPermissionToKernel with oversize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel008, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> tokenList;
    for (uint32_t i = 0; i < MAX_PROCESS_SIZE + 1; i++) {
        int32_t ret = AddPermissionToKernel(i, g_opCodeList, g_statusList);
        if (ret != ACCESS_TOKEN_OK) {
            EXPECT_EQ(ret, EDQUOT);
            break;
        } else {
            tokenList.emplace_back(i);
        }
    }

    for (uint32_t i = 0; i < tokenList.size(); i++) {
        OHOS::Security::AccessToken::RemovePermissionFromKernel(tokenList[i]);
    }
    setuid(g_selfUid);
}


/**
 * @tc.name: AddPermissionToKernel009
 * @tc.desc: AddPermissionToKernel with update permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel009, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));

    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::SetPermissionToKernel(g_tokeId, g_opCodeList[0], true));
    bool isGranted = false;
    EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    EXPECT_EQ(true, isGranted);

    std::vector<uint32_t> opCodeList;
    std::vector<bool> statusList;
    // update with less permission(size is 0)
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList, statusList));
    EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    EXPECT_EQ(false, isGranted);

    // update with more permission
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    EXPECT_EQ(g_statusList[0], isGranted);

    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    setuid(g_selfUid);
}

/**
 * @tc.name: RemovePermissionFromKernel001
 * @tc.desc: cannot RemovePermissionFromKernel with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, RemovePermissionFromKernel001, TestSize.Level0)
{
    setuid(TEST_UID); // random uid
    ASSERT_EQ(EPERM, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    setuid(g_selfUid);
}

/**
 * @tc.name: RemovePermissionFromKernel002
 * @tc.desc: RemovePermissionFromKernel with same token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, RemovePermissionFromKernel002, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    ASSERT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    setuid(g_selfUid);
}

/**
 * @tc.name: SetPermissionToKernel001
 * @tc.desc: cannot SetPermissionToKernel with no permission.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, SetPermissionToKernel001, TestSize.Level0)
{
    setuid(TEST_UID); // random uid
    ASSERT_EQ(EPERM, OHOS::Security::AccessToken::SetPermissionToKernel(g_tokeId, 1, true));
    setuid(g_selfUid);
}

/**
 * @tc.name: SetPermissionToKernel002
 * @tc.desc: cannot SetPermissionToKernel with noexst token.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, SetPermissionToKernel002, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ENODATA, OHOS::Security::AccessToken::SetPermissionToKernel(g_tokeId, g_opCodeList[0], true));
    bool isGranted = false;
    ASSERT_EQ(ENODATA, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    ASSERT_EQ(false, isGranted);
}

/**
 * @tc.name: SetPermissionToKernel003
 * @tc.desc: SetPermissionToKernel after remove token from kernel.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, SetPermissionToKernel003, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    ASSERT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    ASSERT_EQ(ENODATA, OHOS::Security::AccessToken::SetPermissionToKernel(g_tokeId,  g_opCodeList[0], true));
    bool isGranted = false;
    ASSERT_EQ(ENODATA, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
}


/**
 * @tc.name: GetPermissionFromKernel001
 * @tc.desc: Get permissin status after removing token perission.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, GetPermissionFromKernel001, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    uint32_t size = g_opCodeList.size();
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    for (uint32_t i = 0; i < size; i++) {
        bool isGranted = false;
        EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[i], isGranted));
        EXPECT_EQ(g_statusList[i], isGranted);
    }

    std::set<uint32_t> knownOpCodeSet(g_opCodeList.data(), g_opCodeList.data() + size);
    for (uint32_t i = 0; i < MAX_PERM_NUM; i++) {
        if (knownOpCodeSet.find(i) == knownOpCodeSet.end()) {
            bool isGranted = false;
            EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, i, isGranted));
            EXPECT_FALSE(isGranted);
        }
    }

    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    for (uint32_t i = 0; i < size; i++) {
        bool isGranted = false;
        EXPECT_EQ(ENODATA, GetPermissionFromKernel(g_tokeId, g_opCodeList[i], isGranted));
        EXPECT_EQ(false, isGranted);
    }
    setuid(g_selfUid);
}

/**
 * @tc.name: GetPermissionFromKernel002
 * @tc.desc: Get permissin status after set perission.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, GetPermissionFromKernel002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetPermissionFromKernel002 start";
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));

    // set permission status: false
    bool isGranted = false;
    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::SetPermissionToKernel(g_tokeId, g_opCodeList[0], false));
    EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    EXPECT_EQ(false, isGranted);

    // set permission status: true
    EXPECT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::SetPermissionToKernel(g_tokeId, g_opCodeList[0], true));
    EXPECT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    EXPECT_EQ(true, isGranted);

    ASSERT_EQ(ACCESS_TOKEN_OK, OHOS::Security::AccessToken::RemovePermissionFromKernel(g_tokeId));
    setuid(g_selfUid);
}

/**
 * @tc.name: Invalid parameter
 * @tc.desc: InvalidParam test.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, InvalidParam1, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));

    // set permission fail
    EXPECT_EQ(EINVAL, OHOS::Security::AccessToken::SetPermissionToKernel(g_tokeId, INVALID_OP_CODE, false));

    // get permission fail
    bool isGranted = false;
    ASSERT_EQ(EINVAL, GetPermissionFromKernel(g_tokeId, INVALID_OP_CODE, isGranted));
    EXPECT_EQ(false, isGranted);
}

static void *ThreadTestFunc01(void *args)
{
    int32_t token1 = g_tokeId;
    for (int32_t i = 0; i < CYCLE_TIMES; i++) {
        bool isGranted = false;
        AddPermissionToKernel(token1, g_opCodeList, g_statusList);
        OHOS::Security::AccessToken::SetPermissionToKernel(token1, g_opCodeList[0], false);
        GetPermissionFromKernel(token1, g_opCodeList[0], isGranted);
        OHOS::Security::AccessToken::RemovePermissionFromKernel(token1);
        token1++;
    }
    return nullptr;
}

static void *ThreadTestFunc02(void *args)
{
    int32_t token2 = g_tokeId + CYCLE_TIMES;
    uint32_t size = g_opCodeList.size();
    for (int32_t i = 0; i < CYCLE_TIMES; i++) {
        bool isGranted = false;
        AddPermissionToKernel(token2, g_opCodeList, g_statusList);
        OHOS::Security::AccessToken::SetPermissionToKernel(token2, g_opCodeList[size - 1], true);
        GetPermissionFromKernel(token2, g_opCodeList[size - 1], isGranted);
        OHOS::Security::AccessToken::RemovePermissionFromKernel(token2);
        token2++;
    }
    return nullptr;
}

/**
 * @tc.name: Mulitpulthread001
 * @tc.desc: Mulitpulthread test.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, Mulitpulthread001, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    int64_t beginTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    pthread_t tid[2];
    (void)pthread_create(&tid[0], nullptr, &ThreadTestFunc01, nullptr);
    (void)pthread_create(&tid[1], nullptr, &ThreadTestFunc01, nullptr);
    (void)pthread_join(tid[0], nullptr);
    (void)pthread_join(tid[1], nullptr);

    (void)pthread_create(&tid[0], nullptr, &ThreadTestFunc02, nullptr);
    (void)pthread_create(&tid[1], nullptr, &ThreadTestFunc02, nullptr);
    (void)pthread_join(tid[0], nullptr);
    (void)pthread_join(tid[1], nullptr);
    int64_t endTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    setuid(g_selfUid);
    ASSERT_TRUE(endTime - beginTime < 1000 * 100);
}

/**
 * @tc.name: APICostTimeTest001
 * @tc.desc: Test time of get permission api.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, APICostTimeTest001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "APICostTimeTest001 start";
    setuid(ACCESS_TOKEN_UID);
    int32_t token = 0;
    double costSum = 0.0;
    std::vector<uint32_t> tokenList;
    bool isGranted = false;
    while (1) {
        if (AddPermissionToKernel(token, g_opCodeList, g_statusList) != 0) {
            break;
        }
        tokenList.emplace_back(token);

        struct timespec ts1, ts2;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts1);
        GetPermissionFromKernel(token, g_opCodeList[0], isGranted);
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts2);

        double cost = (1000.0 * 1000.0 * ts2.tv_sec + 1e-3 * ts2.tv_nsec) -
            (1000.0 * 1000.0 * ts1.tv_sec + 1e-3 * ts1.tv_nsec);

        costSum += cost;
        token++;
    }
    if (!tokenList.empty()) {
        double avgCost = costSum / tokenList.size();
        GTEST_LOG_(INFO) << "get average time: " << avgCost << " us";
        EXPECT_TRUE(avgCost < 100.0); // 100.0: time limit
    }

    for (uint32_t i = 0; i < tokenList.size(); i++) {
        OHOS::Security::AccessToken::RemovePermissionFromKernel(tokenList[i]);
    }
    setuid(g_selfUid);
}

static void InitSpmEntry(SpmData *entry, uint32_t tokenid, const char *name)
{
    entry->uid = CYCLE_TIMES; // random uid for test, no need to be real
    entry->tokenid = tokenid;
    entry->tokenidAttr = 0;
    entry->index = 0;
    entry->apl = 0;
    entry->distributionType = 0;
    entry->idType = 0;
    entry->ownerid = 0;
    strncpy_s(entry->name.buf, entry->name.bufSize, name, entry->name.bufSize - 1);
    entry->name.buf[entry->name.bufSize - 1] = '\0';
}

/**
 * @tc.name: SpmDataNewFree001
 * @tc.desc: Test SpmDataNew with normal parameters and verify buffer allocation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmDataNewFree001, TestSize.Level0)
{
    SpmData *data = SpmDataNew(100, 50, 64);
    ASSERT_NE(data, nullptr);
    EXPECT_NE(data->perms.buf, nullptr);
    EXPECT_EQ(data->perms.bufSize, 100);
    EXPECT_NE(data->extendPerms.buf, nullptr);
    EXPECT_EQ(data->extendPerms.bufSize, 50);
    EXPECT_NE(data->name.buf, nullptr);
    EXPECT_EQ(data->name.bufSize, 64);
    SpmDataFree(data);
}

/**
 * @tc.name: SpmDataNewFree002
 * @tc.desc: Test SpmDataNew with zero parameters and SpmDataFree with nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmDataNewFree002, TestSize.Level0)
{
    SpmData *data = SpmDataNew(0, 0, 0);
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->perms.buf, nullptr);
    EXPECT_EQ(data->perms.bufSize, 0);
    EXPECT_EQ(data->extendPerms.buf, nullptr);
    EXPECT_EQ(data->extendPerms.bufSize, 0);
    EXPECT_EQ(data->name.buf, nullptr);
    EXPECT_EQ(data->name.bufSize, 0);
    SpmDataFree(data);
    SpmDataFree(nullptr);
}

/**
 * @tc.name: SpmDataNewFree003
 * @tc.desc: Test SpmDataNew with nameBufSize=0 and non-zero perms/extendPerms sizes.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmDataNewFree003, TestSize.Level0)
{
    // nameBufSize=0, permsBufSize and extendPermsBufSize are non-zero
    SpmData *data = SpmDataNew(100, 50, 0);
    ASSERT_NE(data, nullptr);
    EXPECT_NE(data->perms.buf, nullptr);
    EXPECT_EQ(data->perms.bufSize, 100);
    EXPECT_NE(data->extendPerms.buf, nullptr);
    EXPECT_EQ(data->extendPerms.bufSize, 50);
    EXPECT_EQ(data->name.buf, nullptr);
    EXPECT_EQ(data->name.bufSize, 0);
    SpmDataFree(data);
}

/**
 * @tc.name: SpmAddEntries001
 * @tc.desc: Test adding a single valid SPM entry to kernel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmAddEntries001, TestSize.Level0)
{
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    InitSpmEntry(entry, 6001, "test_app");

    uint8_t idx_err = 0;
    SpmData *arr[] = {entry};
    int ret = SpmAddEntries(arr, 1, &idx_err);
    SpmDataFree(entry);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    EXPECT_EQ(ret, 0);

    SpmRemoveEntry(6001);
}

/**
 * @tc.name: SpmAddEntries002
 * @tc.desc: Test SpmAddEntries with nullptr array parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmAddEntries002, TestSize.Level0)
{
    uint8_t idx_err = 0;
    int ret = SpmAddEntries(nullptr, 1, &idx_err);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: SpmAddEntries003
 * @tc.desc: Test SpmAddEntries with entry having nullptr name buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmAddEntries003, TestSize.Level0)
{
    SpmData entry;
    memset_s(&entry, sizeof(entry), 0, sizeof(entry));
    entry.name.buf = nullptr;
    entry.name.bufSize = 0;

    uint8_t idx_err = 0;
    SpmData *arr[] = {&entry};
    int ret = SpmAddEntries(arr, 1, &idx_err);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: SpmAddEntries004
 * @tc.desc: Test batch adding multiple SPM entries to kernel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmAddEntries004, TestSize.Level0)
{
    const int kCount = 15;
    SpmData *entries[kCount];
    for (int i = 0; i < kCount; i++) {
        entries[i] = SpmDataNew(1, 1, 64);
        ASSERT_NE(entries[i], nullptr);
        InitSpmEntry(entries[i], 7000 + i, "test_batch");
    }

    uint8_t idx_err = 0;
    int ret = SpmAddEntries(entries, kCount, &idx_err);
    for (int i = 0; i < kCount; i++) {
        SpmDataFree(entries[i]);
    }
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    EXPECT_EQ(ret, 0);

    for (int i = 0; i < kCount; i++) {
        SpmRemoveEntry(7000 + i);
    }
}

/**
 * @tc.name: SpmAddEntries005
 * @tc.desc: Test SpmAddEntries with nullptr idx_err parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmAddEntries005, TestSize.Level0)
{
    int ret = SpmAddEntries(nullptr, 1, nullptr);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: SpmAddEntries006
 * @tc.desc: Test SpmAddEntries with count=0 (empty array).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmAddEntries006, TestSize.Level0)
{
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    uint8_t idx_err = 0;
    SpmData *arr[] = {entry};
    int ret = SpmAddEntries(arr, 0, &idx_err);
    SpmDataFree(entry);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: SpmAddEntries007
 * @tc.desc: Test SpmAddEntries with valid array but nullptr idx_err should return EINVAL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmAddEntries007, TestSize.Level0)
{
    // idx_err=NULL with valid arr should return EINVAL
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    SpmData *arr[] = {entry};
    int ret = SpmAddEntries(arr, 1, nullptr);
    SpmDataFree(entry);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: SpmAddEntries008
 * @tc.desc: Test adding duplicate tokenid should return EEXIST.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmAddEntries008, TestSize.Level0)
{
    // Adding the same tokenid twice should return EEXIST
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    InitSpmEntry(entry, 6002, "test_dup");

    uint8_t idx_err = 0;
    SpmData *arr[] = {entry};
    int ret = SpmAddEntries(arr, 1, &idx_err);
    if (ret == ENOTSUP) {
        SpmDataFree(entry);
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    ASSERT_EQ(ret, 0);

    idx_err = 0;
    ret = SpmAddEntries(arr, 1, &idx_err);
    SpmDataFree(entry);
    EXPECT_EQ(ret, EEXIST);
    EXPECT_EQ(idx_err, 0);
    SpmRemoveEntry(6002);
}

/**
 * @tc.name: SpmSetEntries001
 * @tc.desc: Test updating an existing SPM entry with modified APL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmSetEntries001, TestSize.Level0)
{
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    InitSpmEntry(entry, 8001, "test_update");

    uint8_t idx_err = 0;
    SpmData *arr[] = {entry};
    int ret = SpmAddEntries(arr, 1, &idx_err);
    if (ret == ENOTSUP) {
        SpmDataFree(entry);
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }

    entry->apl = 1;
    ret = SpmSetEntries(arr, 1, &idx_err);
    SpmDataFree(entry);
    EXPECT_EQ(ret, 0);

    SpmRemoveEntry(8001);
}

/**
 * @tc.name: SpmSetEntries002
 * @tc.desc: Test SpmSetEntries with nullptr array parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmSetEntries002, TestSize.Level0)
{
    uint8_t idx_err = 0;
    int ret = SpmSetEntries(nullptr, 1, &idx_err);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: SpmSetEntries005
 * @tc.desc: Test SpmSetEntries with valid array but nullptr idx_err should return EINVAL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmSetEntries005, TestSize.Level0)
{
    // idx_err=NULL with valid arr should return EINVAL
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    SpmData *arr[] = {entry};
    int ret = SpmSetEntries(arr, 1, nullptr);
    SpmDataFree(entry);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: SpmSetEntries003
 * @tc.desc: Test batch updating multiple SPM entries with modified APL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmSetEntries003, TestSize.Level0)
{
    const int kCount = 15;
    SpmData *entries[kCount];
    for (int i = 0; i < kCount; i++) {
        entries[i] = SpmDataNew(1, 1, 64);
        ASSERT_NE(entries[i], nullptr);
        InitSpmEntry(entries[i], 12000 + i, "test_set_batch");
    }

    uint8_t idx_err = 0;
    int ret = SpmAddEntries(entries, kCount, &idx_err);
    if (ret == ENOTSUP) {
        for (int i = 0; i < kCount; i++) {
            SpmDataFree(entries[i]);
        }
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    ASSERT_EQ(ret, 0);

    for (int i = 0; i < kCount; i++) {
        entries[i]->apl = 1;
    }
    ret = SpmSetEntries(entries, kCount, &idx_err);
    for (int i = 0; i < kCount; i++) {
        SpmDataFree(entries[i]);
    }
    EXPECT_EQ(ret, 0);

    for (int i = 0; i < kCount; i++) {
        SpmRemoveEntry(12000 + i);
    }
}

/**
 * @tc.name: SpmSetEntries004
 * @tc.desc: Test SpmSetEntries with count=0 (empty array).
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmSetEntries004, TestSize.Level0)
{
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    uint8_t idx_err = 0;
    SpmData *arr[] = {entry};
    int ret = SpmSetEntries(arr, 0, &idx_err);
    SpmDataFree(entry);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: SpmGetEntry001
 * @tc.desc: Test querying an existing SPM entry from kernel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetEntry001, TestSize.Level0)
{
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    InitSpmEntry(entry, 9001, "test_query");

    uint8_t idx_err = 0;
    SpmData *arr[] = {entry};
    int ret = SpmAddEntries(arr, 1, &idx_err);
    if (ret == ENOTSUP) {
        SpmDataFree(entry);
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }

    SpmData *queryEntry = SpmDataNew(1, 1, 64);
    ASSERT_NE(queryEntry, nullptr);
    ret = SpmGetEntry(9001, queryEntry);
    SpmDataFree(entry);
    SpmDataFree(queryEntry);
    EXPECT_EQ(ret, 0);

    SpmRemoveEntry(9001);
}

/**
 * @tc.name: SpmGetEntry002
 * @tc.desc: Test SpmGetEntry with nullptr entry parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetEntry002, TestSize.Level0)
{
    int ret = SpmGetEntry(9001, nullptr);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: SpmGetEntry003
 * @tc.desc: Test SpmGetEntry with entry having nullptr name buffer.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetEntry003, TestSize.Level0)
{
    SpmData entry;
    memset_s(&entry, sizeof(entry), 0, sizeof(entry));
    entry.name.buf = nullptr;
    entry.name.bufSize = 0;

    int ret = SpmGetEntry(9001, &entry);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: SpmGetEntry004
 * @tc.desc: Test querying a non-existent SPM entry should return error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetEntry004, TestSize.Level0)
{
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    int ret = SpmGetEntry(9001, entry);
    SpmDataFree(entry);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    EXPECT_NE(ret, 0);
}

/**
 * @tc.name: SpmGetEntry005
 * @tc.desc: Test SpmGetEntry with buffer size too small to hold the name should return error.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetEntry005, TestSize.Level0)
{
    // bufSize too small to hold the name should return error from kernel
    SpmData *add_entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(add_entry, nullptr);
    InitSpmEntry(add_entry, 9002, "test_query_small");

    uint8_t idx_err = 0;
    SpmData *arr[] = {add_entry};
    int ret = SpmAddEntries(arr, 1, &idx_err);
    SpmDataFree(add_entry);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    ASSERT_EQ(ret, 0);

    // name "test_query_small" is 16 bytes; bufSize=1 is insufficient
    SpmData *get_entry = SpmDataNew(0, 0, 1);
    ASSERT_NE(get_entry, nullptr);
    ret = SpmGetEntry(9002, get_entry);
    SpmDataFree(get_entry);
    EXPECT_NE(ret, 0);

    SpmRemoveEntry(9002);
}

/**
 * @tc.name: SpmRemoveEntry001
 * @tc.desc: Test removing an existing SPM entry from kernel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmRemoveEntry001, TestSize.Level0)
{
    SpmData *entry = SpmDataNew(1, 1, 64);
    ASSERT_NE(entry, nullptr);
    InitSpmEntry(entry, 10001, "test_remove");

    uint8_t idx_err = 0;
    SpmData *arr[] = {entry};
    int ret = SpmAddEntries(arr, 1, &idx_err);
    SpmDataFree(entry);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }

    ret = SpmRemoveEntry(10001);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(TokensetprocKitTest, AddPermissionToKernelForC001, TestSize.Level0)
{
    uint32_t perms[MAX_PERM_BIT_MAP_SIZE] = {0};
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, ::AddPermissionToKernel(g_tokeId, nullptr, sizeof(perms)));
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, ::AddPermissionToKernel(g_tokeId, reinterpret_cast<const char *>(perms), 0));
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, ::AddPermissionToKernel(g_tokeId, reinterpret_cast<const char *>(perms), 1));
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID,
        ::AddPermissionToKernel(g_tokeId, reinterpret_cast<const char *>(perms), sizeof(perms) + sizeof(uint32_t)));
}

HWTEST_F(TokensetprocKitTest, AddPermissionToKernelForC002, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    uint32_t perms[MAX_PERM_BIT_MAP_SIZE] = {0};
    perms[0] = 0x5;
    ASSERT_EQ(ACCESS_TOKEN_OK,
        ::AddPermissionToKernel(g_tokeId, reinterpret_cast<const char *>(perms), sizeof(perms)));

    std::vector<uint32_t> opCodeList;
    int32_t ret = GetPermissionsFromKernel(g_tokeId, opCodeList);
    if (ret == ENOTSUP) {
        EXPECT_EQ(opCodeList.empty(), true);
    } else {
        EXPECT_EQ(std::vector<uint32_t>({0, 2}), opCodeList);
    }

    uint32_t queryPerms[MAX_PERM_BIT_MAP_SIZE] = {0};
    ret = ::GetPermissionsFromKernel(g_tokeId, queryPerms);
    if (ret == ENOTSUP) {
        EXPECT_EQ(queryPerms[0], 0);
    } else {
        EXPECT_EQ(perms[0], queryPerms[0]);
    }
    setuid(g_selfUid);
}

HWTEST_F(TokensetprocKitTest, GetPermissionsFromKernelForC001, TestSize.Level0)
{
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, ::GetPermissionsFromKernel(g_tokeId, nullptr));
}

HWTEST_F(TokensetprocKitTest, FilterKernelPermissions001, TestSize.Level0)
{
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, FilterKernelPermissions(nullptr, nullptr, nullptr));
    uint32_t perms[MAX_PERM_BIT_MAP_SIZE] = {0};
    uint32_t permSize = 1;
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, FilterKernelPermissions(perms, nullptr, &permSize));
}

HWTEST_F(TokensetprocKitTest, FilterKernelPermissions002, TestSize.Level0)
{
    uint32_t cameraCode = 0;
    uint32_t locationCode = 0;
    ASSERT_TRUE(::TransferPermissionToOpcode("ohos.permission.CAMERA", &cameraCode));
    ASSERT_TRUE(::TransferPermissionToOpcode("ohos.permission.LOCATION", &locationCode));

    uint32_t perms[MAX_PERM_BIT_MAP_SIZE] = {0};
    perms[cameraCode / UINT32_T_BITS] |= (static_cast<uint32_t>(1) << (cameraCode % UINT32_T_BITS));
    perms[locationCode / UINT32_T_BITS] |= (static_cast<uint32_t>(1) << (locationCode % UINT32_T_BITS));
    perms[MAX_PERM_BIT_MAP_SIZE - 1] = 0x80000000; // out-of-range code should be ignored

    uint16_t kernelPerms[2] = {0};
    uint32_t permSize = 2;
    int32_t ret = FilterKernelPermissions(perms, kernelPerms, &permSize);
    ASSERT_EQ(ret, 0);
    EXPECT_EQ(permSize, 0);
    EXPECT_EQ(0, kernelPerms[0]);
}

HWTEST_F(TokensetprocKitTest, FilterKernelPermissions003, TestSize.Level0)
{
    uint32_t cameraCode = 0;
    uint32_t pluginCode = 0;
    ASSERT_TRUE(::TransferPermissionToOpcode("ohos.permission.CAMERA", &cameraCode));
    ASSERT_TRUE(::TransferPermissionToOpcode("ohos.permission.kernel.SUPPORT_PLUGIN", &pluginCode));

    uint32_t perms[MAX_PERM_BIT_MAP_SIZE] = {0};
    perms[cameraCode / UINT32_T_BITS] |= (static_cast<uint32_t>(1) << (cameraCode % UINT32_T_BITS));
    perms[pluginCode / UINT32_T_BITS] |= (static_cast<uint32_t>(1) << (pluginCode % UINT32_T_BITS));

    uint16_t kernelPerms[1] = {0};
    uint32_t permSize = 1;
    int32_t ret = FilterKernelPermissions(perms, kernelPerms, &permSize);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(permSize, 1);
}

HWTEST_F(TokensetprocKitTest, TransferPermissionMapForC001, TestSize.Level0)
{
    uint32_t opCode = 0;
    EXPECT_FALSE(::TransferPermissionToOpcode(nullptr, &opCode));
    EXPECT_FALSE(::TransferPermissionToOpcode("ohos.permission.not_exist", &opCode));
    EXPECT_FALSE(::TransferPermissionToOpcode("ohos.permission.CAMERA", nullptr));

    ASSERT_TRUE(::TransferPermissionToOpcode("ohos.permission.CAMERA", &opCode));
    char permissionName[128] = {0};
    ASSERT_TRUE(::TransferOpCodeToPermission(opCode, permissionName, sizeof(permissionName)));
    EXPECT_STREQ("ohos.permission.CAMERA", permissionName);

    EXPECT_FALSE(::TransferOpCodeToPermission(opCode, nullptr, sizeof(permissionName)));
    EXPECT_FALSE(::TransferOpCodeToPermission(opCode, permissionName, 1));
    EXPECT_FALSE(::TransferOpCodeToPermission(UINT32_MAX, permissionName, sizeof(permissionName)));
}

HWTEST_F(TokensetprocKitTest, TransferSpmExternPerms001, TestSize.Level0)
{
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, TransferSpmExternPerms(nullptr, nullptr, nullptr));

    uint32_t listSize = 0;
    SpmBlob data = {
        .buf = nullptr,
        .bufSize = 4,
    };
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, TransferSpmExternPerms(&data, nullptr, &listSize));

    data.buf = const_cast<char *>("");
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, TransferSpmExternPerms(&data, nullptr, nullptr));
}

HWTEST_F(TokensetprocKitTest, TransferSpmExternPerms002, TestSize.Level0)
{
    char raw[] = {
        0x01, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        'a', 'b', 'c', '\0',
        0x02, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        'x', '\0',
    };
    SpmBlob data = {
        .buf = raw,
        .bufSize = sizeof(raw),
    };

    uint32_t listSize = 1;
    PermsWithValue valueList[1];
    EXPECT_EQ(ERANGE, TransferSpmExternPerms(&data, valueList, &listSize));

    PermsWithValue fullList[2];
    listSize = 2;
    EXPECT_EQ(ACCESS_TOKEN_OK, TransferSpmExternPerms(&data, fullList, &listSize));
    EXPECT_EQ(2u, listSize);
    EXPECT_EQ(2u, fullList[1].code);
    EXPECT_STREQ("x", fullList[1].value);
}

HWTEST_F(TokensetprocKitTest, TransferSpmExternPerms003, TestSize.Level0)
{
    char invalidValueSize[] = {
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    SpmBlob data = {
        .buf = invalidValueSize,
        .bufSize = sizeof(invalidValueSize),
    };
    uint32_t listSize = 1;
    PermsWithValue valueList[1];
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, TransferSpmExternPerms(&data, valueList, &listSize));

    char trailingBytes1[] = {
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        'x', '\0',
        'z',
    };
    data.buf = trailingBytes1;
    data.bufSize = sizeof(trailingBytes1);
    listSize = 1;
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, TransferSpmExternPerms(&data, valueList, &listSize));
    EXPECT_EQ(1u, listSize);

    char valueSizeInvalid[] = {
        0x01, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        'x', '\0',
        'z',
    };
    data.buf = valueSizeInvalid;
    data.bufSize = sizeof(valueSizeInvalid);
    listSize = 1;
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, TransferSpmExternPerms(&data, valueList, &listSize));

    char validRaw[] = {
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        'x', '\0',
    };
    data.buf = validRaw;
    data.bufSize = sizeof(validRaw);
    listSize = 0;
    EXPECT_EQ(ACCESS_TOKEN_PARAM_INVALID, TransferSpmExternPerms(&data, nullptr, &listSize));
}

HWTEST_F(TokensetprocKitTest, SpmIncUidRefCnt001, TestSize.Level0)
{
    int ret = SpmIncUidRefCnt(1000, 1);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    EXPECT_EQ(ret, 0);
    SpmDecUidRefCnt(1000, 1);
}

/**
 * @tc.name: SpmDecUidRefCnt001
 * @tc.desc: Test decrementing UID reference count after increment.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmDecUidRefCnt001, TestSize.Level0)
{
    int ret = SpmIncUidRefCnt(1001, 1);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    ret = SpmDecUidRefCnt(1001, 1);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: SpmGetUidRefCnt001
 * @tc.desc: Test getting UID reference count with valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetUidRefCnt001, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    uint64_t refcnt = 0;
    int ret = SpmGetUidRefCnt(1002, &refcnt);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    EXPECT_EQ(ret, 0);
    setuid(g_selfUid);
}

/**
 * @tc.name: SpmGetUidRefCnt002
 * @tc.desc: Test SpmGetUidRefCnt with nullptr refcnt parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetUidRefCnt002, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    int ret = SpmGetUidRefCnt(1002, nullptr);
    EXPECT_EQ(ret, EINVAL);
    setuid(g_selfUid);
}

/**
 * @tc.name: SpmIncTokenidRefCnt001
 * @tc.desc: Test incrementing token ID reference count.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmIncTokenidRefCnt001, TestSize.Level0)
{
    int ret = SpmIncTokenidRefCnt(11001, 1);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    EXPECT_EQ(ret, 0);
    SpmDecTokenidRefCnt(11001, 1);
}

/**
 * @tc.name: SpmDecTokenidRefCnt001
 * @tc.desc: Test decrementing token ID reference count after increment.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmDecTokenidRefCnt001, TestSize.Level0)
{
    int ret = SpmIncTokenidRefCnt(11002, 1);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    ret = SpmDecTokenidRefCnt(11002, 1);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: SpmGetTokenidRefCnt001
 * @tc.desc: Test getting token ID reference count with valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetTokenidRefCnt001, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    uint64_t refcnt = 0;
    int ret = SpmGetTokenidRefCnt(11003, &refcnt);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    EXPECT_EQ(ret, 0);
    setuid(g_selfUid);
}

/**
 * @tc.name: SpmGetTokenidRefCnt002
 * @tc.desc: Test SpmGetTokenidRefCnt with nullptr refcnt parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetTokenidRefCnt002, TestSize.Level0)
{
    setuid(ACCESS_TOKEN_UID);
    int ret = SpmGetTokenidRefCnt(11003, nullptr);
    EXPECT_EQ(ret, EINVAL);
    setuid(g_selfUid);
}

/**
 * @tc.name: SpmGetVersion001
 * @tc.desc: Test getting SPM version with valid parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetVersion001, TestSize.Level0)
{
    uint32_t version = 0;
    int ret = SpmGetVersion(&version);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    EXPECT_EQ(ret, 0);
    EXPECT_GE(version, 1);
}

/**
 * @tc.name: SpmGetVersion002
 * @tc.desc: Test SpmGetVersion with nullptr version parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmGetVersion002, TestSize.Level0)
{
    int ret = SpmGetVersion(nullptr);
    EXPECT_EQ(ret, EINVAL);
}

/**
 * @tc.name: SpmClearSpawnidRefCnt001
 * @tc.desc: Test clearing spawn ID reference count.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, SpmClearSpawnidRefCnt001, TestSize.Level0)
{
    int ret = SpmClearSpawnidRefCnt(1);
    if (ret == ENOTSUP) {
        GTEST_LOG_(INFO) << "Kernel doesn't support SPM CMD, skip test";
        return;
    }
    EXPECT_EQ(ret, 0);
}
