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
#include <fcntl.h>
#include <memory>
#include <string>

#define private public
#include "json_parse_loader.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* TEST_FILE_PATH = "/data/test/abcdefg.txt";
}

class JsonParseLoaderTest : public testing::Test  {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp();
    void TearDown();
};

void JsonParseLoaderTest::SetUpTestCase() {}
void JsonParseLoaderTest::TearDownTestCase() {}
void JsonParseLoaderTest::SetUp() {}
void JsonParseLoaderTest::TearDown() {}

/*
 * @tc.name: IsDirExsit
 * @tc.desc: IsDirExsit
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, IsDirExsitTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    EXPECT_FALSE(loader.IsDirExsit(""));
    int32_t fd = open(TEST_FILE_PATH, O_RDWR | O_CREAT);
    EXPECT_NE(-1, fd);

    EXPECT_FALSE(loader.IsDirExsit(TEST_FILE_PATH));
}

#ifdef CUSTOMIZATION_CONFIG_POLICY_ENABLE
/*
 * @tc.name: GetConfigValueFromFile
 * @tc.desc: GetConfigValueFromFile
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, GetConfigValueFromFileTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    AccessTokenConfigValue config;
    EXPECT_FALSE(loader.GetConfigValueFromFile(ServiceType::ACCESSTOKEN_SERVICE, "", config));
}
#endif // CUSTOMIZATION_CONFIG_POLICY_ENABLE

/*
 * @tc.name: ParserNativeRawData
 * @tc.desc: ParserNativeRawData
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserNativeRawDataTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<NativeTokenInfoBase> tokenInfos;
    EXPECT_FALSE(loader.ParserNativeRawData("", tokenInfos));
}

/*
 * @tc.name: ParserDlpPermsRawData
 * @tc.desc: ParserDlpPermsRawData
 * @tc.type: FUNC
 * @tc.require: TDD coverage
 */
HWTEST_F(JsonParseLoaderTest, ParserDlpPermsRawDataTest001, TestSize.Level4)
{
    ConfigPolicLoader loader;
    std::vector<PermissionDlpMode> dlpPerms;
    EXPECT_FALSE(loader.ParserDlpPermsRawData("", dlpPerms));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
