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

static const uint32_t ACCESS_TOKEN_UID = 3020;
static const uint32_t MAX_PROCESS_SIZE = 500; // same as kernel size
static uint32_t g_tokeId = 5000;
static const uint32_t SIZE = 8;
static uint32_t g_opCodeList[SIZE] = {0, 1, 2, 3, 4, 5, 63, 64};
static int32_t g_statusList[SIZE] = {0, 0, 1, 1, 1, 1, 0, 0};
static uint32_t g_gelfUid;
static const int32_t CYCLE_TIMES = 1000;
static int32_t PERMISSION_GRANTED = 0;

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
    ASSERT_EQ(EPERM, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));
}

/**
 * @tc.name: AddPermissionToKernel002
 * @tc.desc: AddPermissionToKernel with invalid parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel002, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_PARAM_INVALID, AddPermissionToKernel(g_tokeId, nullptr, g_statusList, SIZE));
    ASSERT_EQ(ACCESS_TOKEN_PARAM_INVALID, AddPermissionToKernel(g_tokeId, g_opCodeList, nullptr, SIZE));
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
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, 0));
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
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));
    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel005
 * @tc.desc: AddPermissionToKernel with same token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel005, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));
    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel006
 * @tc.desc: AddPermissionToKernel with different token.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel006, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    uint32_t token1 = 111;
    uint32_t token2 = 222;
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(token1, g_opCodeList, g_statusList, SIZE));
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(token2, g_opCodeList, g_statusList, SIZE));
    EXPECT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(token1));
    EXPECT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(token2));
    setuid(g_gelfUid);
}

/**
 * @tc.name: AddPermissionToKernel007
 * @tc.desc: AddPermissionToKernel with oversize.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel007, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    std::vector<uint32_t> tokenList;
    for (uint32_t i = 0; i < MAX_PROCESS_SIZE + 1; i++) {
        int32_t ret = AddPermissionToKernel(i, g_opCodeList, g_statusList, SIZE);
        if (ret != ACCESS_TOKEN_OK) {
            EXPECT_EQ(ret, EOVERFLOW);
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
 * @tc.name: AddPermissionToKernel008
 * @tc.desc: AddPermissionToKernel with update permission.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokensetprocKitTest, AddPermissionToKernel008, TestSize.Level1)
{
    setuid(ACCESS_TOKEN_UID);
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));

    ASSERT_EQ(ACCESS_TOKEN_OK, SetPermissionToKernel(g_tokeId, g_opCodeList[0], true));
    ASSERT_EQ(true, GetPermissionFromKernel(g_tokeId, g_opCodeList[0]));

    // update with less permission(size is 0)
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, 0));
    ASSERT_EQ(false, GetPermissionFromKernel(g_tokeId, g_opCodeList[0]));

    // update with more permission
    EXPECT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));
    ASSERT_EQ(g_statusList[0] == PERMISSION_GRANTED, GetPermissionFromKernel(g_tokeId, g_opCodeList[0]));

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
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));
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
    ASSERT_EQ(false, GetPermissionFromKernel(g_tokeId, g_opCodeList[0]));
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
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));
    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    ASSERT_EQ(ENODATA, SetPermissionToKernel(g_tokeId,  g_opCodeList[0], true));
    ASSERT_EQ(false, GetPermissionFromKernel(g_tokeId, g_opCodeList[0]));
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
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));
    for (uint32_t i = 0; i < SIZE; i++) {
        EXPECT_EQ(g_statusList[i] == PERMISSION_GRANTED, GetPermissionFromKernel(g_tokeId, g_opCodeList[i]));
    }

    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    for (uint32_t i = 0; i < SIZE; i++) {
        EXPECT_EQ(false, GetPermissionFromKernel(g_tokeId, g_opCodeList[i]));
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
    ASSERT_EQ(ACCESS_TOKEN_OK, AddPermissionToKernel(g_tokeId, g_opCodeList, g_statusList, SIZE));

    // set permission status: false
    EXPECT_EQ(ACCESS_TOKEN_OK, SetPermissionToKernel(g_tokeId, g_opCodeList[0], false));
    EXPECT_EQ(false, GetPermissionFromKernel(g_tokeId, g_opCodeList[0]));

    // set permission status: true
    EXPECT_EQ(ACCESS_TOKEN_OK, SetPermissionToKernel(g_tokeId, g_opCodeList[0], true));
    EXPECT_EQ(true, GetPermissionFromKernel(g_tokeId, g_opCodeList[0]));

    ASSERT_EQ(ACCESS_TOKEN_OK, RemovePermissionFromKernel(g_tokeId));
    setuid(g_gelfUid);
}

static void *ThreadTestFunc01(void *args)
{
    int32_t token1 = g_tokeId;
    for (int32_t i = 0; i < CYCLE_TIMES; i++) {
        AddPermissionToKernel(token1, g_opCodeList, g_statusList, SIZE);
        SetPermissionToKernel(token1, g_opCodeList[0], false);
        GetPermissionFromKernel(token1, g_opCodeList[0]);
        RemovePermissionFromKernel(token1);
        token1++;
    }
    return nullptr;
}

static void *ThreadTestFunc02(void *args)
{
    int32_t token2 = g_tokeId + CYCLE_TIMES;
    for (int32_t i = 0; i < CYCLE_TIMES; i++) {
        AddPermissionToKernel(token2, g_opCodeList, g_statusList, SIZE);
        SetPermissionToKernel(token2, g_opCodeList[7], true); // 7: array index
        GetPermissionFromKernel(token2, g_opCodeList[7]); // 7: array index
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
    while (1) {
        if (AddPermissionToKernel(token, g_opCodeList, g_statusList, SIZE) != 0) {
            break;
        }
        tokenList.emplace_back(token);

        struct timespec ts1, ts2;
        clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts1);
        GetPermissionFromKernel(token, g_opCodeList[0]);
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
