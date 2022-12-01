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

#include "nativetoken_oper_test.h"
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include "securec.h"
#include "nativetoken.h"
#include "nativetoken_json_oper.h"
#include "nativetoken_kit.h"

using namespace testing::ext;
using namespace OHOS::Security;

void TokenOperTest::SetUpTestCase()
{}

void TokenOperTest::TearDownTestCase()
{}

void TokenOperTest::SetUp()
{}

void TokenOperTest::TearDown()
{}

/**
 * @tc.name: FreeStrArray001
 * @tc.desc: FreeStrArray successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, FreeStrArray001, TestSize.Level1)
{
    const int32_t testSize = 2; // 2 means test size
    char **test = reinterpret_cast<char **>(malloc(sizeof(char *) * testSize));
    ASSERT_NE(test, nullptr);
    for (int32_t i = 0; i < testSize; i++) {
        test[i] = reinterpret_cast<char *>(malloc(sizeof(char)));
        ASSERT_NE(test[i], nullptr);
    }
    FreeStrArray(test, testSize - 1);
    EXPECT_EQ(test[0], nullptr);
    FreeStrArray(test, testSize - 1); // arr[i] == nullptr
    for (int32_t i = 0; i < testSize; i++) {
        free(test[i]);
    }
    free(test);
}

/**
 * @tc.name: GetProcessNameFromJson001
 * @tc.desc: GetProcessNameFromJson successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, GetProcessNameFromJson001, TestSize.Level1)
{
    NativeTokenList tokenNode;
    std::string stringJson1 = R"()"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]})";

    cJSON* jsonroot = cJSON_Parse(stringJson1.c_str());
    EXPECT_EQ(GetProcessNameFromJson(jsonroot, &tokenNode), 0);
    cJSON_Delete(jsonroot);

    stringJson1 = R"()"\
        R"({"processName":2,"APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]})";
    jsonroot = cJSON_Parse(stringJson1.c_str());
    EXPECT_NE(GetProcessNameFromJson(jsonroot, &tokenNode), 0);
    cJSON_Delete(jsonroot);

    stringJson1 = R"()"\
        R"({"processName":"partitionslot_hostApartitionslot_hostApartitionslot_hostApartitions)"\
        R"(lot_hostApartitionslot_hostApartitionslot_hostApartitionslot_hostApartitionslot_hostApartitonslt_hosApa)"\
        R"(lot_hostApartitionslot_hostApartitionslot_hostApartitionslot_hostApartitionslot_hostApartitonslo_hostpa)"\
        R"(lot_hostApartitionslot_hostApartitionslot_hostApartitionslot_hostApartitionslot_hostApartitonslo_hostpa)"\
        R"(lot_hostApartitionslot_hostApartitionslot_hostApartitionslot_hostApartitionslot_hostApartitonslt_htApa")"\
        R"(,"APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]})";

    jsonroot = cJSON_Parse(stringJson1.c_str());
    EXPECT_NE(GetProcessNameFromJson(jsonroot, &tokenNode), 0);
    cJSON_Delete(jsonroot);
}

/**
 * @tc.name: GetTokenIdFromJson001
 * @tc.desc: GetTokenIdFromJson successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, GetTokenIdFromJson001, TestSize.Level1)
{
    NativeTokenList tokenNode;
    const char *stringJson1 = "{\"processName\":\"partitionslot_host\","
        "\"APL\":2,\"version\":1,\"tokenId\":\"672003577\",\"tokenAttr\":0,\"dcaps\":[],"
        "\"permissions\":[],\"nativeAcls\":[]}";
    cJSON* jsonroot = cJSON_Parse(stringJson1);
    EXPECT_NE(GetTokenIdFromJson(jsonroot, &tokenNode), 0);
    cJSON_Delete(jsonroot);

    const char *stringJson2 = "{\"processName\":\"partitionslot_host\","
        "\"APL\":2,\"version\":1,\"tokenId\":0,\"tokenAttr\":0,\"dcaps\":[],"
        "\"permissions\":[],\"nativeAcls\":[]}";
    cJSON* jsonroot2 = cJSON_Parse(stringJson2);
    EXPECT_NE(GetTokenIdFromJson(jsonroot2, &tokenNode), 0);
    cJSON_Delete(jsonroot2);

    const char *stringJson3 = "{\"processName\":\"partitionslot_host\","
        "\"APL\":2,\"version\":1,\"tokenId\":536962970,\"tokenAttr\":0,\"dcaps\":[],"
        "\"permissions\":[],\"nativeAcls\":[]}";
    cJSON* jsonroot3 = cJSON_Parse(stringJson3);
    EXPECT_NE(GetTokenIdFromJson(jsonroot3, &tokenNode), 0);
    cJSON_Delete(jsonroot3);
}

/**
 * @tc.name: GetAplFromJson001
 * @tc.desc: GetAplFromJson successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, GetAplFromJson001, TestSize.Level1)
{
    NativeTokenList tokenNode;
    const char *stringJson1 = "{\"APL\":2}";
    cJSON* jsonroot = cJSON_Parse(stringJson1);
    EXPECT_EQ(GetAplFromJson(jsonroot, &tokenNode), 0);

    const char *stringJson2 = "{\"processName\":\"partitionslot_host\","
        "\"APL\":\"2\",\"version\":1,\"tokenId\":672003577,\"tokenAttr\":0,\"dcaps\":[],"
        "\"permissions\":[],\"nativeAcls\":[]}";
    jsonroot = cJSON_Parse(stringJson2);
    EXPECT_NE(GetAplFromJson(jsonroot, &tokenNode), 0);
    cJSON_Delete(jsonroot);

    const char *stringJson3 = "{\"processName\":\"partitionslot_host\","
        "\"APL\":-1,\"version\":1,\"tokenId\":672003577,\"tokenAttr\":0,\"dcaps\":[],"
        "\"permissions\":[],\"nativeAcls\":[]}";
    jsonroot = cJSON_Parse(stringJson3);
    EXPECT_NE(GetAplFromJson(jsonroot, &tokenNode), 0);
    cJSON_Delete(jsonroot);

    const char *stringJson4 = "{\"processName\":\"partitionslot_host\","
        "\"APL\":4,\"version\":1,\"tokenId\":672003577,\"tokenAttr\":0,\"dcaps\":[],"
        "\"permissions\":[],\"nativeAcls\":[]}";
    jsonroot = cJSON_Parse(stringJson4);
    EXPECT_NE(GetAplFromJson(jsonroot, &tokenNode), 0);
    cJSON_Delete(jsonroot);
}

/**
 * @tc.name: GetInfoArrFromJson001
 * @tc.desc: GetInfoArrFromJson successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, GetInfoArrFromJson001, TestSize.Level1)
{
    const int32_t testSize = 2;
    int32_t resSize;
    StrArrayAttr attr;
    attr.strKey = "dcaps";
    attr.maxStrNum = 1;
    attr.maxStrLen = 10;
    char *test[testSize];
    const char *stringJson1 = "{\"processName\":\"partitionslot_host\","
        "\"dcaps\":[\"DCAPS_AT\",\"DCAPS_AT\", \"DCAPS_AT\",\"DCAPS_AT\"],"
        "\"permissions\":[],\"nativeAcls\":[]}";
    cJSON* jsonroot = cJSON_Parse(stringJson1);
    EXPECT_NE(GetInfoArrFromJson(jsonroot, test, &resSize, &attr), 0);
    cJSON_Delete(jsonroot);

    stringJson1 = "{\"processName\":\"partitionslot_host\","
        "\"APL\":2,\"version\":1,\"tokenId\":672003577,\"tokenAttr\":0,\"dcaps\":[1],"
        "\"permissions\":[],\"nativeAcls\":[]}";
    jsonroot = cJSON_Parse(stringJson1);
    EXPECT_NE(GetInfoArrFromJson(jsonroot, test, &resSize, &attr), 0);
    cJSON_Delete(jsonroot);

    stringJson1 = "{\"processName\":\"partitionslot_host\","
        "\"APL\":2,\"version\":1,\"tokenId\":672003577,\"tokenAttr\":0,\"dcaps\":[\"DCAPSAAAAAAAA_AT\"],"
        "\"permissions\":[],\"nativeAcls\":[]}";
    jsonroot = cJSON_Parse(stringJson1);
    EXPECT_NE(GetInfoArrFromJson(jsonroot, test, &resSize, &attr), 0);
    cJSON_Delete(jsonroot);
}

/**
 * @tc.name: UpdateGoalItemFromRecord001
 * @tc.desc: UpdateGoalItemFromRecord abnormal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, UpdateGoalItemFromRecord001, TestSize.Level1)
{
    NativeTokenList tokenNode;

    // processName json is null
    const char *stringJson2 = "[{\"processName_\":\"partitionslot_host\","
        "\"APL\":2,\"version\":1,\"tokenId\":672003577,\"tokenAttr\":0,\"dcaps\":[],"
        "\"permissions\":[],\"nativeAcls\":[]}]";
    cJSON* jsonroot = cJSON_Parse(stringJson2);
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonroot), 0);
    cJSON_Delete(jsonroot);

    std::string stringJson1 = R"()"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]})";

    cJSON* jsonRoot = cJSON_Parse(stringJson1.c_str());
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    // processName json is not string
    const char *stringJson3 = "[{\"processName\": 1,"
        "\"APL\":1,\"version\":1,\"tokenId\":672003577,\"tokenAttr\":0,\"dcaps\":[],"
        "\"permissions\":[],\"nativeAcls\":[]}]";
    jsonroot = cJSON_Parse(stringJson3);
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonroot), 0);
    cJSON_Delete(jsonroot);

    const char *stringJson4 = "[]";
    jsonroot = cJSON_Parse(stringJson4);
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonroot), 0);
    cJSON_Delete(jsonroot);
}

