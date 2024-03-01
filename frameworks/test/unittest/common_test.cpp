/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include <fcntl.h>

#include "access_token_error.h"
#include "constant_common.h"
#define private public
#include "permission_map.h"
#undef private
#include "json_parser.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
const static uint32_t MAX_PERM_SIZE = 2048;
const static uint32_t MAX_CONFIG_FILE_SIZE = 5 * 1024;
const static std::string TEST_JSON_PATH = "/data/test.json";
const static std::string TEST_STR =
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA"
    "iVBORw0KGgoAAAANSUhEUgAAABUAAAAXCAIAAABrvZPKAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AA";
}
class CommonTest : public testing::Test  {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
};

void CommonTest::SetUpTestCase() {}
void CommonTest::TearDownTestCase() {}
void CommonTest::SetUp() {}
void CommonTest::TearDown() {}

/**
 * @tc.name: EncryptDevId001
 * @tc.desc: Test EncryptDevId001 function.
 * @tc.type: FUNC
 * @tc.require: issueI5RUCC
 */
HWTEST_F(CommonTest, EncryptDevId001, TestSize.Level1)
{
    std::string res;
    res = ConstantCommon::EncryptDevId("");
    EXPECT_EQ(res, "");

    res = ConstantCommon::EncryptDevId("12345");
    EXPECT_EQ(res, "1*******");

    res = ConstantCommon::EncryptDevId("123454321");
    EXPECT_EQ(res, "1234****4321");
}

/*
 * @tc.name: TransferOpcodeToPermission001
 * @tc.desc: TransferOpcodeToPermission function test
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(CommonTest, TransferOpcodeToPermission001, TestSize.Level1)
{
    std::string permissionName;
    EXPECT_TRUE(TransferOpcodeToPermission(0, permissionName));
    EXPECT_EQ(permissionName, "ohos.permission.ANSWER_CALL");
}

/*
 * @tc.name: TransferOpcodeToPermission002
 * @tc.desc: TransferOpcodeToPermission code oversize
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(CommonTest, TransferOpcodeToPermission002, TestSize.Level1)
{
    std::string permissionName;
    EXPECT_FALSE(TransferOpcodeToPermission(MAX_PERM_SIZE, permissionName));
    EXPECT_FALSE(TransferOpcodeToPermission(MAX_PERM_SIZE - 1, permissionName));
}

/*
 * @tc.name: GetUnsignedIntFromJson001
 * @tc.desc: GetUnsignedIntFromJson
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(CommonTest, GetUnsignedIntFromJson001, TestSize.Level1)
{
    const nlohmann::json json;
    u_int32_t out = 0;
    EXPECT_FALSE(JsonParser::GetUnsignedIntFromJson(json, "tokenId", out));
    EXPECT_EQ(0, out);
}

/*
 * @tc.name: ReadCfgFile001
 * @tc.desc: GetUnsignedIntFromJson json invalid
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(CommonTest, ReadCfgFile001, TestSize.Level1)
{
    int32_t fd = open(TEST_JSON_PATH.c_str(), O_RDWR | O_CREAT);
    EXPECT_NE(-1, fd);
    std::string rawData;
    EXPECT_EQ(ERR_PARAM_INVALID, JsonParser::ReadCfgFile(TEST_JSON_PATH, rawData));
    for (int i = 0; i < MAX_CONFIG_FILE_SIZE; i++) {
        size_t strLen = strlen(TEST_STR.c_str());
        write(fd, TEST_STR.c_str(), strLen);
    }
    EXPECT_EQ(ERR_OVERSIZE, JsonParser::ReadCfgFile(TEST_JSON_PATH, rawData));
    close(fd);
    sleep(5);

    remove(TEST_JSON_PATH.c_str());
}

/*
 * @tc.name: IsDirExsit001
 * @tc.desc: IsDirExsit input param error
 * @tc.type: FUNC
 * @tc.require: issueI6024A
 */
HWTEST_F(CommonTest, IsDirExsit001, TestSize.Level1)
{
    EXPECT_FALSE(JsonParser::IsDirExsit(""));
    int32_t fd = open(TEST_JSON_PATH.c_str(), O_RDWR | O_CREAT);
    EXPECT_NE(-1, fd);

    EXPECT_FALSE(JsonParser::IsDirExsit(TEST_JSON_PATH.c_str()));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
