/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "cjson_utils.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
std::string g_testJsonStr = R"(
{
    "beginTime": 11,
    "endTime": 22,
    "bundleRecords": [
        {
            "tokenId": 123,
            "isRemote": false,
            "bundleName": "com.ohos.test1",
            "permissionRecords": [{
                "permissionName": "ohos.permission.READ_IMAGEVIDEO",
                "accessCount": 1,
                "secAccessCount": 1,
                "rejectCount": 1,
                "lastAccessTime": 11,
                "lastRejectTime": 22,
                "lastAccessDuration": 0,
                "accessRecords": [{
                        "status": 1,
                        "lockScreenStatus": 1,
                        "timestamp": 11,
                        "duration": 0,
                        "count": 2,
                        "usedType": 0
                    }
                ],
                "rejectRecords": []
            }]
        },
        {
            "tokenId": 234,
            "isRemote": true,
            "bundleName": "com.ohos.test",
            "permissionRecords": []
        }
    ]
}
)";
};

class CJsonUtilsTest : public testing::Test  {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
};

void CJsonUtilsTest::SetUpTestCase() {}
void CJsonUtilsTest::TearDownTestCase() {}
void CJsonUtilsTest::SetUp() {}
void CJsonUtilsTest::TearDown() {}

/*
 * @tc.name: CreateJsonFromString
 * @tc.desc: CreateJsonFromString
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, CreateJsonFromStringTest001, TestSize.Level3)
{
    std::string test1;
    EXPECT_EQ(nullptr, CreateJsonFromString(test1));

    std::string test2 = "{\"key\":\"value\"}";
    EXPECT_NE(nullptr, CreateJsonFromString(test2));
}

/*
 * @tc.name: PackJsonToString
 * @tc.desc: PackJsonToString
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, PackJsonToStringTest001, TestSize.Level3)
{
    std::string res = PackJsonToString(nullptr);
    EXPECT_TRUE(res.empty());

    std::string test = "{\"key\":\"value\"}";
    CJsonUnique json = CreateJsonFromString(test);
    EXPECT_NE(nullptr, json);

    res = PackJsonToString(json);
    EXPECT_FALSE(res.empty());

    FreeJsonString(nullptr);
}

/*
 * @tc.name: GetObjFromJson
 * @tc.desc: GetObjFromJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, GetObjFromJsonTest001, TestSize.Level3)
{
    std::string test;
    EXPECT_EQ(nullptr, GetObjFromJson(nullptr, test));

    test = "test1";
    CJsonUnique jsonInner = CreateJson();
    ASSERT_EQ(true, AddStringToJson(jsonInner, "test0", "0"));
    EXPECT_EQ(nullptr, GetObjFromJson(jsonInner, test));

    test = "test0";
    EXPECT_EQ(nullptr, GetObjFromJson(jsonInner, test));
}

/*
 * @tc.name: GetArrayFromJson
 * @tc.desc: GetArrayFromJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, GetArrayFromJsonTest001, TestSize.Level3)
{
    std::string test;
    EXPECT_EQ(nullptr, GetArrayFromJson(nullptr, test));

    test = "test1";
    CJsonUnique jsonInner = CreateJson();
    ASSERT_EQ(true, AddStringToJson(jsonInner, "test0", "0"));
    EXPECT_EQ(nullptr, GetArrayFromJson(jsonInner, test));

    test = "test0";
    EXPECT_EQ(nullptr, GetArrayFromJson(jsonInner, test));
}

/*
 * @tc.name: GetArrayFromJson
 * @tc.desc: GetArrayFromJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, GetArrayFromJsonTest002, TestSize.Level3)
{
    std::string test;
    std::vector<std::string> out;
    EXPECT_FALSE(GetArrayFromJson(nullptr, test, out));

    cJSON* arrayJson = cJSON_CreateArray();
    cJSON* arrayItem = cJSON_CreateString("test");
    cJSON_AddItemToArray(arrayJson, arrayItem);
    std::string key = "data";
    cJSON* array = cJSON_CreateObject();
    EXPECT_NE(NULL, array);
    cJSON_AddItemToObject(array, key.c_str(), arrayJson);
    EXPECT_TRUE(GetArrayFromJson(array, key, out));
    EXPECT_FALSE(GetArrayFromJson(arrayItem, key, out));
    cJSON_Delete(array);
}

/*
 * @tc.name: GetStringFromJson
 * @tc.desc: GetStringFromJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, GetStringFromJsonTest001, TestSize.Level3)
{
    std::string test;
    std::string res;
    CJsonUnique jsonInner = CreateJson();
    EXPECT_EQ(false, GetStringFromJson(jsonInner.get(), "", res));
    EXPECT_EQ(false, GetStringFromJson(nullptr, "test", res));

    ASSERT_EQ(true, AddStringToJson(jsonInner, "test0", "0"));
    EXPECT_EQ(false, GetStringFromJson(jsonInner.get(), test, res));

    test = "test1";
    EXPECT_EQ(false, GetStringFromJson(jsonInner.get(), test, res));

    CJsonUnique jsonArray = CreateJsonArray();
    ASSERT_EQ(true, AddObjToJson(jsonArray, "test1", jsonInner));
    EXPECT_EQ(false, GetStringFromJson(jsonArray.get(), test, res));
}

/*
 * @tc.name: GetIntFromJson
 * @tc.desc: GetIntFromJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, GetIntFromJsonTest001, TestSize.Level3)
{
    std::string test = "test1";
    int32_t res;
    CJsonUnique jsonInner = CreateJson();
    EXPECT_EQ(false, GetIntFromJson(jsonInner, "", res));
    EXPECT_EQ(false, GetIntFromJson(nullptr, test, res));

    ASSERT_EQ(true, AddStringToJson(jsonInner, "test0", "abc"));
    EXPECT_EQ(false, GetIntFromJson(jsonInner, test, res));

    test = "test0";
    EXPECT_EQ(false, GetIntFromJson(jsonInner, test, res));
}

/*
 * @tc.name: GetUnsignedIntFromJson
 * @tc.desc: GetUnsignedIntFromJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, GetUnsignedIntFromJsonTest001, TestSize.Level3)
{
    std::string test = "test1";
    uint32_t res;
    CJsonUnique jsonInner = CreateJson();
    EXPECT_EQ(false, GetUnsignedIntFromJson(jsonInner, "", res));
    EXPECT_EQ(false, GetUnsignedIntFromJson(nullptr, test, res));

    ASSERT_EQ(true, AddStringToJson(jsonInner, "test0", "abc"));
    EXPECT_EQ(false, GetUnsignedIntFromJson(jsonInner, test, res));

    test = "test0";
    EXPECT_EQ(false, GetUnsignedIntFromJson(jsonInner, test, res));
}

/*
 * @tc.name: GetBoolFromJson
 * @tc.desc: GetBoolFromJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, GetBoolFromJsonTest001, TestSize.Level3)
{
    std::string test = "test1";
    bool res;
    CJsonUnique jsonInner = CreateJson();
    EXPECT_EQ(false, GetBoolFromJson(jsonInner, "", res));
    EXPECT_EQ(false, GetBoolFromJson(nullptr, test, res));

    ASSERT_EQ(true, AddStringToJson(jsonInner, "test0", "0"));
    EXPECT_EQ(false, GetBoolFromJson(jsonInner, test, res));

    test = "test0";
    EXPECT_EQ(false, GetBoolFromJson(jsonInner, test, res));
}

/*
 * @tc.name: GetBoolFromJson
 * @tc.desc: GetBoolFromJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, GetBoolFromJsonTest002, TestSize.Level3)
{
    std::string test = "test1";
    bool res;
    CJsonUnique jsonInner = CreateJson();
    EXPECT_EQ(false, GetBoolFromJson(jsonInner, "", res));
    EXPECT_EQ(false, GetBoolFromJson(nullptr, "test1", res));

    ASSERT_EQ(true, AddBoolToJson(jsonInner, test, true));

    EXPECT_EQ(true, GetBoolFromJson(jsonInner, test, res));
    EXPECT_EQ(res, true);
}

/*
 * @tc.name: AddObjToJson
 * @tc.desc: AddObjToJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, AddObjToJsonTest001, TestSize.Level3)
{
    CJsonUnique jsonInner = CreateJson();
    std::string test = "test1";
    ASSERT_EQ(false, AddObjToJson(jsonInner.get(), "", nullptr));
    ASSERT_EQ(false, AddObjToJson(nullptr, "test", nullptr));

    ASSERT_EQ(true, AddStringToJson(jsonInner, "test0", "0"));
    ASSERT_EQ(true, AddStringToJson(jsonInner, "test1", "1"));

    CJsonUnique jsonArray = CreateJsonArray();
    ASSERT_EQ(true, AddObjToJson(jsonArray, "test1", jsonInner));
    ASSERT_EQ(true, AddObjToJson(jsonArray, "test1", jsonInner));
}

/*
 * @tc.name: AddObjToArray
 * @tc.desc: AddObjToArray
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, AddObjToArrayTest001, TestSize.Level3)
{
    ASSERT_EQ(false, AddObjToArray(nullptr, nullptr));

    CJsonUnique jsonInner = CreateJson();
    ASSERT_EQ(false, AddObjToArray(nullptr, jsonInner.get()));
}

/*
 * @tc.name: AddStringToJson
 * @tc.desc: AddStringToJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, AddStringToJsonTest001, TestSize.Level3)
{
    CJsonUnique jsonInner = CreateJson();
    ASSERT_EQ(false, AddStringToJson(jsonInner, "", ""));
    ASSERT_EQ(false, AddStringToJson(nullptr, "key_string", "test0"));

    ASSERT_EQ(true, AddStringToJson(jsonInner, "key_string", "test0"));
    // twice
    ASSERT_EQ(true, AddStringToJson(jsonInner, "key_string", "test0"));
}

/*
 * @tc.name: AddBoolToJson
 * @tc.desc: AddBoolToJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, AddBoolToJsonTest001, TestSize.Level3)
{
    CJsonUnique jsonInner = CreateJson();
    ASSERT_EQ(false, AddBoolToJson(jsonInner, "", true));
    ASSERT_EQ(false, AddBoolToJson(nullptr, "key_bool", true));

    ASSERT_EQ(true, AddBoolToJson(jsonInner, "key_bool", true));
    // twice
    ASSERT_EQ(true, AddBoolToJson(jsonInner, "key_bool", true));
}

/*
 * @tc.name: AddIntToJson
 * @tc.desc: AddIntToJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, AddIntToJsonTest001, TestSize.Level3)
{
    CJsonUnique jsonInner = CreateJson();
    ASSERT_EQ(false, AddIntToJson(jsonInner, "", 0));
    ASSERT_EQ(false, AddIntToJson(nullptr, "key_int32", 0));

    ASSERT_EQ(true, AddIntToJson(jsonInner, "key_int32", 0));
    // twice
    ASSERT_EQ(true, AddIntToJson(jsonInner, "key_int32", 0));
}

/*
 * @tc.name: AddUnsignedIntToJson
 * @tc.desc: AddUnsignedIntToJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, AddUnsignedIntToJsonTest001, TestSize.Level3)
{
    CJsonUnique jsonInner = CreateJson();
    ASSERT_EQ(false, AddUnsignedIntToJson(jsonInner, "", 0));
    ASSERT_EQ(false, AddUnsignedIntToJson(nullptr, "key_uint32", 0));

    ASSERT_EQ(true, AddUnsignedIntToJson(jsonInner, "key_uint32", 0));
    // twice
    ASSERT_EQ(true, AddUnsignedIntToJson(jsonInner, "key_uint32", 0));
}

/*
 * @tc.name: AddInt64ToJson
 * @tc.desc: AddInt64ToJson
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, AddInt64ToJsonTest001, TestSize.Level3)
{
    CJsonUnique jsonInner = CreateJson();
    ASSERT_EQ(false, AddInt64ToJson(jsonInner, "", 0));
    ASSERT_EQ(false, AddInt64ToJson(nullptr, "key_int64", 0));

    ASSERT_EQ(true, AddInt64ToJson(jsonInner, "key_int64", 0));
    // twice
    ASSERT_EQ(true, AddInt64ToJson(jsonInner, "key_int64", 0));
}

/*
 * @tc.name: JsonToStringFormatted
 * @tc.desc: JsonToStringFormatted with json is nullptr
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, JsonToStringFormattedTest001, TestSize.Level3)
{
    std::string str = JsonToStringFormatted(nullptr);
    EXPECT_TRUE(str.empty());

    CJsonUnique jsonInner = CreateJson();
    str = JsonToStringFormatted(jsonInner.get(), 501); // 501: level
    EXPECT_TRUE(str.empty());
}

/*
 * @tc.name: JsonToStringFormatted
 * @tc.desc: JsonToStringFormatted
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(CJsonUtilsTest, JsonToStringFormattedTest002, TestSize.Level3)
{
    CJsonUnique jsonInner = CreateJson();
    std::string str = JsonToStringFormatted(jsonInner.get());
    EXPECT_FALSE(str.empty());

    CJsonUnique json = CreateJsonFromString(g_testJsonStr);
    EXPECT_NE(nullptr, json.get());

    str = JsonToStringFormatted(json.get());
    EXPECT_FALSE(str.empty());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
