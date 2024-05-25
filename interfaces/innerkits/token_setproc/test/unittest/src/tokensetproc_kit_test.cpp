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
#include "token_setproc.h"

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
static uint32_t g_gelfUid;
static const int32_t CYCLE_TIMES = 1000;

void TokensetprocKitTest::SetUpTestCase()
{
    g_gelfUid = getuid();
}

void TokensetprocKitTest::TearDownTestCase()
{}

void TokensetprocKitTest::SetUp()
{}

void TokensetprocKitTest::TearDown()
{
    RemovePermissionFromKernel(g_tokeId);
    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel001
 * @tc.desc: cannot AddPermissionToKernel with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel001, TestSize.Level1)
{
    ASSERT_EQ(EPERM, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
}

/**
 * @tc.name: AddPermissionToKernel002
 * @tc.desc: AddPermissionToKernel with differet size parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel002, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> opcodeList = {0, 1, 2};
    std::vector<bool> statusList = {0, 0};
    ASSERT_EQ(ACCESS_TOKEN_PARAM_INVALID, AddPermissionToKernel(g_tokeId, opcodeList, statusList));
    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel003
 * @tc.desc: AddPermissionToKernel with size is 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel003, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> opcodeList;
    std::vector<bool> statusList;
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opcodeList, statusList));
    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel004
 * @tc.desc: AddPermissionToKernel with having permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel004, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel005
 * @tc.desc: update less permission with same token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel005, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> opCodeList1 = {123, 124};
    std::vector<bool> statusList1 = {false, false}; // not granted
    std::vector<uint32_t> opCodeList2 = {123};
    std::vector<bool> statusList2 = {true}; // granted

    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList1, statusList1));
    bool isGranted = false;
    ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, opCodeList1[0], isGranted));
    ASSERT_EQ(false, isGranted);

    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList2, statusList2));

    ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, opCodeList2[0], isGranted));
    ASSERT_EQ(true, isGranted);
    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));

    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel006
 * @tc.desc: update more permissiion with same token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel006, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> opCodeList1 = {123};
    std::vector<bool> statusList1 = {true}; // granted
    std::vector<uint32_t> opCodeList2 = {123, 124};
    std::vector<bool> statusList2 = {false, false}; // not granted

    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList1, statusList1));
    bool isGranted = false;
    ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, opCodeList1[0], isGranted));
    ASSERT_EQ(true, isGranted);

    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList2, statusList2));
    ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, opCodeList2[0], isGranted));
    ASSERT_EQ(false, isGranted);

    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));

    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel007
 * @tc.desc: AddPermissionToKernel with different token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel007, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    uint32_t token1 = 111;
    uint32_t token2 = 222;
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(token1, g_opCodeList, g_statusList));
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(token2, g_opCodeList, g_statusList));
    EXPECT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(token1));
    EXPECT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(token2));
    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel008
 * @tc.desc: AddPermissionToKernel with oversize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel008, TestSize.Level1)
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
        RemovePermissionFromKernel(tokenList[i]);
    }
    setuid(g_gelfUid);
}


/**
 * @tc.name: AddPermissionToKernel009
 * @tc.desc: AddPermissionToKernel with update permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel009, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));

    ASSERT_EQ(ACCESS_TOKEN_OK, SetPermissionToKernel(g_tokeId, g_opCodeList[0], true));
    bool isGranted = false;
    ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    ASSERT_EQ(true, isGranted);

    std::vector<uint32_t> opCodeList;
    std::vector<bool> statusList;
    // update with less permission(size is 0)
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, opCodeList, statusList));
    ASSERT_EQ(ENODATA, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    ASSERT_EQ(false, isGranted);

    // update with more permission
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    ASSERT_EQ(g_statusList[0], isGranted);

    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    setuid(g_gelfUid);
}

/**
 * @tc.name: RemovePermissionFromKernel001
 * @tc.desc: cannot RemovePermissionFromKernel with no permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, RemovePermissionFromKernel001, TestSize.Level1)
{
    ASSERT_EQ(EPERM, RemovePermissionFromKernel(g_tokeId));
}

/**
 * @tc.name: RemovePermissionFromKernel002
 * @tc.desc: RemovePermissionFromKernel with same token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, RemovePermissionFromKernel002, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    EXPECT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    setuid(g_gelfUid);
}

/**
 * @tc.name: SetPermissionToKernel001
 * @tc.desc: cannot SetPermissionToKernel with no permission.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, SetPermissionToKernel001, TestSize.Level1)
{
    ASSERT_EQ(EPERM, SetPermissionToKernel(g_tokeId, 1, true));
}

/**
 * @tc.name: SetPermissionToKernel002
 * @tc.desc: cannot SetPermissionToKernel with noexst token.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, SetPermissionToKernel002, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ENODATA, SetPermissionToKernel(g_tokeId, g_opCodeList[0], true));
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
HWTEST_F(TokensetprocKitTest, SetPermissionToKernel003, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    ASSERT_EQ(ENODATA, SetPermissionToKernel(g_tokeId,  g_opCodeList[0], true));
    bool isGranted = false;
    ASSERT_EQ(ENODATA, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
}


/**
 * @tc.name: GetPermissionFromKernel001
 * @tc.desc: Get permissin status after removing token perission.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, GetPermissionFromKernel001, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    uint32_t size = g_opCodeList.size();
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));
    for (uint32_t i = 0; i < size; i++) {
        bool isGranted = false;
        ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[i], isGranted));
        EXPECT_EQ(g_statusList[i], isGranted);
    }

    std::set<uint32_t> knownOpCodeSet(g_opCodeList.data(), g_opCodeList.data() + size);
    for (uint32_t i = 0; i < MAX_PERM_NUM; i++) {
        if (knownOpCodeSet.find(i) == knownOpCodeSet.end()) {
            bool isGranted = false;
            ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, i, isGranted));
            EXPECT_FALSE(isGranted);
        }
    }

    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    for (uint32_t i = 0; i < size; i++) {
        bool isGranted = false;
        ASSERT_EQ(ENODATA, GetPermissionFromKernel(g_tokeId, g_opCodeList[i], isGranted));
        EXPECT_EQ(false, isGranted);
    }
    setuid(g_gelfUid);
}

/**
 * @tc.name: GetPermissionFromKernel002
 * @tc.desc: Get permissin status after set perission.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, GetPermissionFromKernel002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetPermissionFromKernel002 start";
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));

    // set permission status: false
    bool isGranted = false;
    EXPECT_EQ(ACCESS_TOKEN_OK, SetPermissionToKernel(g_tokeId, g_opCodeList[0], false));
    ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    EXPECT_EQ(false, isGranted);

    // set permission status: true
    EXPECT_EQ(ACCESS_TOKEN_OK, SetPermissionToKernel(g_tokeId, g_opCodeList[0], true));
    ASSERT_EQ(ACCESS_TOKEN_OK, GetPermissionFromKernel(g_tokeId, g_opCodeList[0], isGranted));
    EXPECT_EQ(true, isGranted);

    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    setuid(g_gelfUid);
}

/**
 * @tc.name: Invalid parameter
 * @tc.desc: InvalidParam test.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, InvalidParam1, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList));

    // set permission fail
    EXPECT_EQ(EINVAL, SetPermissionToKernel(g_tokeId, INVALID_OP_CODE, false));

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
        SetPermissionToKernel(token1, g_opCodeList[0], false);
        GetPermissionFromKernel(token1, g_opCodeList[0], isGranted);
        RemovePermissionFromKernel(token1);
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
        SetPermissionToKernel(token2, g_opCodeList[size - 1], true);
        GetPermissionFromKernel(token2, g_opCodeList[size - 1], isGranted);
        RemovePermissionFromKernel(token2);
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
HWTEST_F(TokensetprocKitTest, Mulitpulthread001, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    pthread_t tid[2];
    (void)pthread_create(&tid[0], nullptr, &ThreadTestFunc01, nullptr);
    (void)pthread_create(&tid[1], nullptr, &ThreadTestFunc01, nullptr);
    (void)pthread_join(tid[0], nullptr);
    (void)pthread_join(tid[1], nullptr);

    (void)pthread_create(&tid[0], nullptr, &ThreadTestFunc02, nullptr);
    (void)pthread_create(&tid[1], nullptr, &ThreadTestFunc02, nullptr);
    (void)pthread_join(tid[0], nullptr);
    (void)pthread_join(tid[1], nullptr);

    setuid(g_gelfUid);
}

/**
 * @tc.name: APICostTimeTest001
 * @tc.desc: Test time of get permission api.
 * @tc.type: FUNC
 * @tc.require: issueI8HMUH
 */
HWTEST_F(TokensetprocKitTest, APICostTimeTest001, TestSize.Level1)
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
        RemovePermissionFromKernel(tokenList[i]);
    }
    setuid(g_gelfUid);
}
