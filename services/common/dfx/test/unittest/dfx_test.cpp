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
#include "data_usage_dfx.h"
#include <cstdio>
#include <fcntl.h>

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const char* INVALID_FILE = "/data/123456/xyz";
constexpr const char* INVALID_FILE2 = "/data/123456/xyz/";
constexpr const char* TEST_FILE_PATH = "/data/test/dfx_test_file.txt";
constexpr const char* TEST_TXT = "1234567890abcdefghij";
constexpr const char* DATABASE_DIR_PATH = "/data/service/el1/public/access_token/";
constexpr int32_t TEST_SIZE = 20;
constexpr int32_t INITIAL_DEPTH = 1;
constexpr int32_t OVERSIZE_DEPTH = 6;
} // namespace
class DfxTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DfxTest::SetUpTestCase() {}
void DfxTest::TearDownTestCase() {}
void DfxTest::SetUp() {}
void DfxTest::TearDown() {}

/**
 * @tc.name: GetUserDataRemainSizeTest001
 * @tc.desc: Test GetUserDataRemainSize function
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DfxTest, GetUserDataRemainSizeTest001, TestSize.Level1)
{
    // expect size > 0
    uint64_t size = GetUserDataRemainSize();
    EXPECT_GT(size, 0);
}

/**
 * @tc.name: GetFileSizeTest001
 * @tc.desc: Test GetFileSize function
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DfxTest, GetFileSizeTest001, TestSize.Level1)
{
    FILE* file = fopen(TEST_FILE_PATH, "w");
    size_t written = fwrite(TEST_TXT, sizeof(char), TEST_SIZE, file);
    EXPECT_EQ(written, TEST_SIZE);
    fclose(file);

    // test file size is 20
    uint64_t testFileSize = GetFileSize(TEST_FILE_PATH);
    EXPECT_EQ(testFileSize, TEST_SIZE);

    remove(TEST_FILE_PATH);

    // invalid file size is 0
    uint64_t invalidSize = GetFileSize(INVALID_FILE);
    EXPECT_EQ(invalidSize, 0);

    EXPECT_EQ(false, IsDirectory(INVALID_FILE));

    EXPECT_EQ("", GetFilePathByDir("", ""));
    EXPECT_EQ(INVALID_FILE2, GetFilePathByDir(INVALID_FILE, ""));
    EXPECT_EQ(INVALID_FILE2, GetFilePathByDir(INVALID_FILE2, ""));
}

/**
 * @tc.name: GetDirFileSizeTest001
 * @tc.desc: Test GetDirFileSize function
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(DfxTest, GetDirFileSizeTest001, TestSize.Level1)
{
    std::vector<std::string> filePath;
    std::vector<uint64_t> fileSize;
    GetDirFileSize(DATABASE_DIR_PATH, filePath, fileSize, INITIAL_DEPTH);
    EXPECT_GT(filePath.size(), 0);
    EXPECT_GT(fileSize.size(), 0);
    EXPECT_EQ(filePath.size(), fileSize.size());

    std::vector<std::string> invalidFilePath;
    std::vector<uint64_t> invalidFileSize;
    GetDirFileSize(INVALID_FILE, invalidFilePath, invalidFileSize, INITIAL_DEPTH);
    EXPECT_EQ(invalidFilePath.size(), 0);
    EXPECT_EQ(invalidFileSize.size(), 0);
    GetDirFileSize(INVALID_FILE, invalidFilePath, invalidFileSize, OVERSIZE_DEPTH);

    std::vector<std::string> files;
    GetAllDirFile(INVALID_FILE, files);
    EXPECT_EQ(files.size(), 0);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
