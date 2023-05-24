/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "code_signature_analysis_kit_test.h"

#include <securec.h>
#include "code_signature_analysis_kit.h"


using namespace testing::ext;
using namespace OHOS::Security;

void CodeSignatureAnalysisKitTest::SetUpTestCase()
{
    ModelApi *test = GetModelApi();
    if (test != nullptr) {
        test->release();
    }
}

void CodeSignatureAnalysisKitTest::TearDownTestCase()
{}

void CodeSignatureAnalysisKitTest::SetUp()
{}

void CodeSignatureAnalysisKitTest::TearDown()
{}

static int32_t GetDataFromSqlMock(const char* sql, uint8_t *result, uint32_t resultLen)
{
    return 0;
}

static DbListener g_dbSubscribeMock;

static CodeSignatureReportedInfo g_reportInfo;

static int64_t g_timeStamp = 0;

typedef struct BundleInfo {
    const char *name;
    uint32_t tokenId;
} BundleInfo;

static BundleInfo g_bundleInfo[3] = {
    {"test0", 12345}, // 12345 random tokenId.
    {"test1", 123456}, // 123456 random tokenId.
    {"test2", 1234567} // 1234567 random tokenId.
};

static int32_t SubscribeDbMock(const int64_t *eventId, uint32_t eventIdLen, DbListener listener)
{
    g_dbSubscribeMock = listener;
    return 0;
}

static int32_t g_retListenerMockTime = 0;
/**
 * @tc.name: GetModelApi001
 * @tc.desc: GetModelApi test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, GetModelApi001, TestSize.Level1)
{
    ModelApi *test1 = GetModelApi();
    ASSERT_NE(test1, nullptr);
    ModelApi *test2 = GetModelApi();
    ASSERT_EQ(test1, test2);
}


/**
 * @tc.name: Init001
 * @tc.desc: init with invalid processName.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, Init001, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);
    ModelManagerApi *testApi = nullptr;
    int32_t res = test->init(testApi);
    ASSERT_EQ(res, INPUT_POINT_NULL);
}

/**
 * @tc.name: Init002
 * @tc.desc: init test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, Init002, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);

    ModelManagerApi testApi;
    testApi.execSql = GetDataFromSqlMock;
    testApi.subscribeDb = SubscribeDbMock;
    int32_t res = test->init(&testApi);
    ASSERT_EQ(res, OPER_SUCCESS);
    test->release();
}

/**
 * @tc.name: Init003
 * @tc.desc: init test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, Init003, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);

    ModelManagerApi testApi;
    testApi.execSql = GetDataFromSqlMock;
    testApi.subscribeDb = SubscribeDbMock;
    int32_t res = test->init(&testApi);
    ASSERT_EQ(res, OPER_SUCCESS);

    res = test->init(&testApi);
    ASSERT_EQ(res, INIT_OPER_REPEAT);

    test->release();
    res = test->init(&testApi);
    ASSERT_EQ(res, OPER_SUCCESS);
    test->release();
}

/**
 * @tc.name: GetResult001
 * @tc.desc: GetResult test with null input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, GetResult001, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);

    ModelManagerApi testApi;
    testApi.execSql = GetDataFromSqlMock;
    testApi.subscribeDb = SubscribeDbMock;
    int32_t res = test->init(&testApi);
    ASSERT_EQ(res, OPER_SUCCESS);

    uint32_t len = static_cast<uint32_t>(sizeof(NotifyRiskResultInfo));
    NotifyRiskResultInfo *result = new (std::nothrow) NotifyRiskResultInfo;
    ASSERT_NE(result, nullptr);

    res = test->getResult(nullptr, &len);
    EXPECT_EQ(res, INPUT_POINT_NULL);

    test->release();
    delete result;
}

/**
 * @tc.name: GetResult002
 * @tc.desc: GetResult test without init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, GetResult002, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);

    uint32_t len = static_cast<uint32_t>(sizeof(NotifyRiskResultInfo));
    NotifyRiskResultInfo *result = new (std::nothrow) NotifyRiskResultInfo;
    ASSERT_NE(result, nullptr);

    int32_t res = test->getResult(reinterpret_cast<uint8_t *>(result), &len);
    EXPECT_EQ(res, MODEL_INIT_NOT_COMPLETED);

    delete result;
}

static void ReportErrorEventMock(DataChangeTypeCode optType, const char* bundleName, uint32_t tokenId)
{
    g_reportInfo.bundleName[0] = '\0';
    int32_t res = strcpy_s(g_reportInfo.bundleName, MAX_BUNDLE_NAME_LENGTH, bundleName);
    ASSERT_EQ(res, 0);
    g_reportInfo.errorType = SIGNATURE_MISSING;
    g_reportInfo.timeStampMs = g_timeStamp++;
    g_reportInfo.tokenId = tokenId;
    g_dbSubscribeMock(optType,
        reinterpret_cast<uint8_t *>(&g_reportInfo), static_cast<uint32_t>(sizeof(CodeSignatureReportedInfo)));
}

/**
 * @tc.name: GetResult003
 * @tc.desc: GetResult test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, GetResult003, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);

    ModelManagerApi testApi;
    testApi.execSql = GetDataFromSqlMock;
    testApi.subscribeDb = SubscribeDbMock;
    int32_t res = test->init(&testApi);
    ASSERT_EQ(res, OPER_SUCCESS);

    uint32_t len = static_cast<uint32_t>(sizeof(NotifyRiskResultInfo));
    NotifyRiskResultInfo *result = new (std::nothrow) NotifyRiskResultInfo;
    ASSERT_NE(result, nullptr);

    for (int i = 0; i < MAX_CODE_SIGNATURE_ERROR_NUM; i++) {
        ReportErrorEventMock(EVENT_REPORTED, g_bundleInfo[0].name, g_bundleInfo[0].tokenId);
    }

    res = test->getResult(reinterpret_cast<uint8_t *>(result), &len);
    ASSERT_EQ(res, OPER_SUCCESS);
    ASSERT_EQ(len, 0);

    ReportErrorEventMock(EVENT_REPORTED, g_bundleInfo[0].name, g_bundleInfo[0].tokenId);

    // test the SHORT_OF_MEMORY error.
    len = 0;
    res = test->getResult(reinterpret_cast<uint8_t *>(result), &len);
    EXPECT_EQ(res, SHORT_OF_MEMORY);

    // test to get the right info.
    len = static_cast<uint32_t>(sizeof(NotifyRiskResultInfo));
    res = test->getResult(reinterpret_cast<uint8_t *>(result), &len);
    ASSERT_EQ(res, OPER_SUCCESS);
    ASSERT_EQ(len, sizeof(NotifyRiskResultInfo));
    EXPECT_EQ(APPLICATION_RISK_EVENT_ID, result->eventId);
    EXPECT_EQ(LOG_REPORT, result->policy);
    EXPECT_EQ(g_bundleInfo[0].tokenId, result->tokenId);

    // when the risk changed, the result is updated.
    ReportErrorEventMock(OUT_OF_STORAGE_LIFE, g_bundleInfo[0].name, g_bundleInfo[0].tokenId);
    len = static_cast<uint32_t>(sizeof(NotifyRiskResultInfo));
    res = test->getResult(reinterpret_cast<uint8_t *>(result), &len);
    EXPECT_EQ(res, OPER_SUCCESS);
    EXPECT_EQ(len, 0);

    test->release();
    delete result;
}

/**
 * @tc.name: GetResult004
 * @tc.desc: GetResult test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, GetResult004, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);

    ModelManagerApi testApi;
    testApi.execSql = GetDataFromSqlMock;
    testApi.subscribeDb = SubscribeDbMock;
    int32_t res = test->init(&testApi);
    ASSERT_EQ(res, OPER_SUCCESS);

    uint32_t len = static_cast<uint32_t>(sizeof(NotifyRiskResultInfo) * 3); // 3 means three info node.
    NotifyRiskResultInfo *result = new (std::nothrow) NotifyRiskResultInfo[3]; // 3 means three info node.
    ASSERT_NE(result, nullptr);

    for (int i = 0; i < MAX_CODE_SIGNATURE_ERROR_NUM + 1; i++) {
        ReportErrorEventMock(EVENT_REPORTED, g_bundleInfo[0].name, g_bundleInfo[0].tokenId);
    }
    uint32_t len1 = len;
    res = test->getResult(reinterpret_cast<uint8_t *>(result), &len1);
    ASSERT_EQ(res, OPER_SUCCESS);
    ASSERT_EQ(len1, sizeof(NotifyRiskResultInfo));
    EXPECT_EQ(g_bundleInfo[0].tokenId, result[0].tokenId);

    for (int i = 0; i < MAX_CODE_SIGNATURE_ERROR_NUM + 1; i++) {
        ReportErrorEventMock(EVENT_REPORTED, g_bundleInfo[1].name, g_bundleInfo[1].tokenId);
    }
    uint32_t len2 = len;
    res = test->getResult(reinterpret_cast<uint8_t *>(result), &len2);
    ASSERT_EQ(res, OPER_SUCCESS);
    ASSERT_EQ(len2, sizeof(NotifyRiskResultInfo) * 2); // 2 include g_bundleInfo[0] and [1]
    EXPECT_EQ(g_bundleInfo[0].tokenId, result[1].tokenId);
    EXPECT_EQ(g_bundleInfo[1].tokenId, result[0].tokenId);

    for (int i = 0; i < MAX_CODE_SIGNATURE_ERROR_NUM + 1; i++) {
        ReportErrorEventMock(EVENT_REPORTED, g_bundleInfo[2].name, g_bundleInfo[2].tokenId); // 2 means index
    }
    uint32_t len3 = len;
    res = test->getResult(reinterpret_cast<uint8_t *>(result), &len3);
    ASSERT_EQ(res, OPER_SUCCESS);
    ASSERT_EQ(len3, len);
    EXPECT_EQ(g_bundleInfo[0].tokenId, result[2].tokenId);
    EXPECT_EQ(g_bundleInfo[1].tokenId, result[1].tokenId);
    EXPECT_EQ(g_bundleInfo[2].tokenId, result[0].tokenId);

    g_timeStamp--;
    ReportErrorEventMock(OUT_OF_STORAGE_LIFE, g_bundleInfo[2].name, g_bundleInfo[2].tokenId);
    uint32_t len4 = len;
    res = test->getResult(reinterpret_cast<uint8_t *>(result), &len4);
    ASSERT_EQ(res, OPER_SUCCESS);
    ASSERT_EQ(len4, sizeof(NotifyRiskResultInfo) * 2); // 2 include g_bundleInfo[0] and [1]
    EXPECT_EQ(g_bundleInfo[0].tokenId, result[1].tokenId);
    EXPECT_EQ(g_bundleInfo[1].tokenId, result[0].tokenId);

    test->release();
    delete[] result;
}

static void RetListenerMock(uint8_t *result, uint32_t resultLen)
{
    g_retListenerMockTime++;
    ASSERT_EQ(resultLen, sizeof(NotifyRiskResultInfo));
    NotifyRiskResultInfo *res = reinterpret_cast<NotifyRiskResultInfo *>(result);
    ASSERT_EQ(APPLICATION_RISK_EVENT_ID, res->eventId);
    ASSERT_EQ(g_bundleInfo[1].tokenId, res->tokenId);

    if (g_retListenerMockTime == 1) {
        ASSERT_EQ(LOG_REPORT, res->policy);
    } else if (g_retListenerMockTime == 2) { // 2 the second time.
        ASSERT_EQ(NO_SECURITY_RISK, res->policy);
    }
    return;
}

/**
 * @tc.name: SubscribeResult001
 * @tc.desc: SubscribeResult test without init.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, SubscribeResult001, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);
    int32_t res = test->subscribeResult(RetListenerMock);
    ASSERT_EQ(res, MODEL_INIT_NOT_COMPLETED);
}

/**
 * @tc.name: SubscribeResult002
 * @tc.desc: SubscribeResult test with null input.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, SubscribeResult002, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);
    int32_t res = test->subscribeResult(nullptr);
    ASSERT_EQ(res, INPUT_POINT_NULL);
}

/**
 * @tc.name: SubscribeResult003
 * @tc.desc: SubscribeResult test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, SubscribeResult003, TestSize.Level1)
{
    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);

    ModelManagerApi testApi;
    testApi.execSql = GetDataFromSqlMock;
    testApi.subscribeDb = SubscribeDbMock;
    int32_t res = test->init(&testApi);
    EXPECT_EQ(res, OPER_SUCCESS);
    res = test->subscribeResult(RetListenerMock);
    EXPECT_EQ(res, OPER_SUCCESS);

    g_retListenerMockTime = 0;

    for (int i = 0; i < MAX_CODE_SIGNATURE_ERROR_NUM + 1; i++) {
        ReportErrorEventMock(EVENT_REPORTED, g_bundleInfo[1].name, g_bundleInfo[1].tokenId);
    }
    EXPECT_EQ(g_retListenerMockTime, 1);

    g_timeStamp--;
    ReportErrorEventMock(OUT_OF_STORAGE_LIFE, g_bundleInfo[1].name, g_bundleInfo[1].tokenId);

    EXPECT_EQ(g_retListenerMockTime, 2);
    test->release();
}

/**
 * @tc.name: DataProcess001
 * @tc.desc: DataProcess test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CodeSignatureAnalysisKitTest, DataProcess001, TestSize.Level1)
{
    ModelManagerApi testApi;
    testApi.execSql = GetDataFromSqlMock;
    testApi.subscribeDb = SubscribeDbMock;

    ModelApi *test = GetModelApi();
    ASSERT_NE(test, nullptr);
    int32_t res = test->init(&testApi);
    ASSERT_EQ(res, OPER_SUCCESS);

    uint32_t len = static_cast<uint32_t>(sizeof(NotifyRiskResultInfo));
    NotifyRiskResultInfo *result = new (std::nothrow) NotifyRiskResultInfo;
    ASSERT_NE(result, nullptr);

    g_dbSubscribeMock(EVENT_REPORTED, nullptr, 1);
    g_dbSubscribeMock(EVENT_REPORTED, reinterpret_cast<uint8_t *>(&g_reportInfo), 0);
    g_reportInfo.tokenId = 0;
    g_dbSubscribeMock(EVENT_REPORTED,
        reinterpret_cast<uint8_t *>(&g_reportInfo), static_cast<uint32_t>(sizeof(CodeSignatureReportedInfo)));

    g_reportInfo.tokenId = 1;
    g_reportInfo.errorType = CODE_SIGNATURE_ERROR_TYPE_BUFF;
    g_dbSubscribeMock(EVENT_REPORTED,
        reinterpret_cast<uint8_t *>(&g_reportInfo), static_cast<uint32_t>(sizeof(CodeSignatureReportedInfo)));

    g_reportInfo.tokenId = 1;
    g_reportInfo.errorType = ABC_FILE_TAMPERED;
    g_dbSubscribeMock(DATA_CHANGE_TYPE_BUFF,
        reinterpret_cast<uint8_t *>(&g_reportInfo), static_cast<uint32_t>(sizeof(CodeSignatureReportedInfo)));

    for (int i = 0; i < MAX_CODE_SIGNATURE_ERROR_NUM; i++) {
        ReportErrorEventMock(EVENT_REPORTED, g_bundleInfo[0].name, g_bundleInfo[0].tokenId);
    }

    res = test->getResult(reinterpret_cast<uint8_t *>(result), &len);
    EXPECT_EQ(res, OPER_SUCCESS);
    EXPECT_EQ(len, 0);

    delete result;
    test->release();
    test->release();
}