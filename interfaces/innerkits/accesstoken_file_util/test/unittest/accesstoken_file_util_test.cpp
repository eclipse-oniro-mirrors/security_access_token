/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <climits>
#include <cstring>
#include <cstdlib>
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-ext.h>
#include "securec.h"
#include "accesstoken_file_util.h"

using namespace testing::ext;

namespace {
constexpr int32_t FILE_MODE = 0600;
constexpr const char* TEST_ATOMIC_PATH = "/data/local/tmp/test_atomic.json";
constexpr const char* TEST_ATOMIC_NEW = "/data/local/tmp/test_atomic.json.new";

void GetTestBakPath(char* bakPath, size_t bakPathLen)
{
    GetBakFilePath(TEST_ATOMIC_PATH, bakPath, bakPathLen);
}
}

HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_HappyPath, TestSize.Level1)
{
    unlink(TEST_ATOMIC_PATH);
    unlink(TEST_ATOMIC_NEW);
    char bakPath[256] = {0};
    GetTestBakPath(bakPath, sizeof(bakPath));
    unlink(bakPath);

    const char* data = "hello world";
    int32_t ret = AtomicWriteFile(TEST_ATOMIC_PATH, data, strlen(data), FILE_MODE);
    EXPECT_EQ(ret, 0);

    int32_t fd = open(TEST_ATOMIC_PATH, O_RDONLY);
    ASSERT_GE(fd, 0);
    char buf[256] = {0};
    ssize_t bytesRead = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    ASSERT_GT(bytesRead, 0);
    EXPECT_STREQ(buf, "hello world");

    fd = open(bakPath, O_RDONLY);
    ASSERT_GE(fd, 0);
    char bakBuf[256] = {0};
    bytesRead = read(fd, bakBuf, sizeof(bakBuf) - 1);
    close(fd);
    ASSERT_GT(bytesRead, 0);
    EXPECT_STREQ(bakBuf, "hello world");

    struct stat st;
    EXPECT_NE(stat(TEST_ATOMIC_NEW, &st), 0);

    unlink(TEST_ATOMIC_PATH);
    unlink(bakPath);
}

HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_NewOrphanCleanup, TestSize.Level1)
{
    unlink(TEST_ATOMIC_PATH);
    unlink(TEST_ATOMIC_NEW);
    char bakPath[256] = {0};
    GetTestBakPath(bakPath, sizeof(bakPath));
    unlink(bakPath);

    int32_t fd = open(TEST_ATOMIC_NEW, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE);
    ASSERT_GE(fd, 0);
    write(fd, "old orphan data", 15);
    close(fd);

    const char* data = "new data";
    int32_t ret = AtomicWriteFile(TEST_ATOMIC_PATH, data, strlen(data), FILE_MODE);
    EXPECT_EQ(ret, 0);

    struct stat st;
    EXPECT_NE(stat(TEST_ATOMIC_NEW, &st), 0);

    fd = open(TEST_ATOMIC_PATH, O_RDONLY);
    ASSERT_GE(fd, 0);
    char buf[256] = {0};
    ssize_t bytesRead = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    ASSERT_GT(bytesRead, 0);
    EXPECT_STREQ(buf, "new data");

    unlink(TEST_ATOMIC_PATH);
    unlink(bakPath);
}

HWTEST(AccessTokenFileUtilTest, GetBakFilePath_HappyPath, TestSize.Level1)
{
    const char* filePath = "/data/service/el0/access_token/nativetoken.json";
    char bakPath[256] = {0};
    int32_t ret = GetBakFilePath(filePath, bakPath, sizeof(bakPath));
    EXPECT_EQ(ret, 0);
    EXPECT_STREQ(bakPath, "/data/service/el0/access_token/access_token_backup/nativetoken.json");
}

HWTEST(AccessTokenFileUtilTest, GetBakFilePath_PathTooLong, TestSize.Level1)
{
    char bakPath[40] = {0};
    // 11-char filename: "/a/b/0123456789a" (16 chars)
    // -> "/a/b/access_token_backup/0123456789a" (36 chars) + NUL = 37
    // bakPathLen=36 -> 37 bytes > 36, triggers truncation
    char longPath[32] = "/a/b/0123456789a"; // 16 chars
    int32_t ret = GetBakFilePath(longPath, bakPath, 36);
    EXPECT_NE(ret, 0);
}

HWTEST(AccessTokenFileUtilTest, GetBakFilePath_NullFilePath, TestSize.Level1)
{
    char bakPath[256] = {0};
    EXPECT_NE(GetBakFilePath(nullptr, bakPath, sizeof(bakPath)), 0);
}

HWTEST(AccessTokenFileUtilTest, GetBakFilePath_NullBakPath, TestSize.Level1)
{
    EXPECT_NE(GetBakFilePath("/tmp/test.json", nullptr, 256), 0);
}

HWTEST(AccessTokenFileUtilTest, GetBakFilePath_ZeroLen, TestSize.Level1)
{
    char bakPath[256] = {0};
    EXPECT_NE(GetBakFilePath("/tmp/test.json", bakPath, 0), 0);
}

HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_NullFilePath, TestSize.Level1)
{
    EXPECT_NE(AtomicWriteFile(nullptr, "data", 4, FILE_MODE), 0);
}

HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_NullData, TestSize.Level1)
{
    EXPECT_NE(AtomicWriteFile(TEST_ATOMIC_PATH, nullptr, 4, FILE_MODE), 0);
}

HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_WriteToNonExistentDir, TestSize.Level1)
{
    unlink(TEST_ATOMIC_PATH);
    char bakPath[256] = {0};
    GetTestBakPath(bakPath, sizeof(bakPath));
    unlink(bakPath);
    unlink(TEST_ATOMIC_NEW);
    const char* badPath = "/nonexistent_dir/test_atomic.json";
    int32_t ret = AtomicWriteFile(badPath, "data", 4, FILE_MODE);
    EXPECT_NE(ret, 0);
}

HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_RootPath, TestSize.Level1)
{
    // path "/test.json" -> lastSlash == filePath -> GetParentDir returns -1
    // hasParentStat=false -> no chown, no FsyncDir
    // But writing to "/" requires root, may fail on open
    // This covers the GetParentDir root path branch
    const char* rootPath = "/test_root_atomic.json";
    unlink(rootPath);
    char bakPath[256] = {0};
    GetBakFilePath(rootPath, bakPath, sizeof(bakPath));
    unlink(bakPath);
    unlink("/test_root_atomic.json.new");
    AtomicWriteFile(rootPath, "data", 4, FILE_MODE);
    unlink(rootPath);
    unlink(bakPath);
    unlink("/test_root_atomic.json.new");
}

HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_LongFilePath, TestSize.Level1)
{
    char longPath[PATH_MAX];
    for (int i = 0; i < PATH_MAX - 1; i++) {
        longPath[i] = 'a';
    }
    longPath[PATH_MAX - 1] = '\0';
    int32_t ret = AtomicWriteFile(longPath, "data", 4, FILE_MODE);
    EXPECT_NE(ret, 0);
}

HWTEST(AccessTokenFileUtilTest, GetBakFilePath_NoSlash, TestSize.Level1)
{
    char bakPath[256] = {0};
    int32_t ret = GetBakFilePath("nofile.json", bakPath, sizeof(bakPath));
    EXPECT_NE(ret, 0);
}

HWTEST(AccessTokenFileUtilTest, GetBakFilePath_RootPath, TestSize.Level1)
{
    char bakPath[256] = {0};
    int32_t ret = GetBakFilePath("/file.json", bakPath, sizeof(bakPath));
    EXPECT_NE(ret, 0);
}

HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_NoSlash, TestSize.Level1)
{
    char* origCwd = getcwd(nullptr, 0);
    ASSERT_NE(origCwd, nullptr);
    ASSERT_EQ(chdir("/data/local/tmp"), 0);

    const char* noSlash = "test_noslash.json";
    unlink(noSlash);
    char newPath[64] = {0};
    (void)snprintf_s(newPath, sizeof(newPath), sizeof(newPath) - 1, "%s.new", noSlash);
    unlink(newPath);

    int32_t ret = AtomicWriteFile(noSlash, "data", 4, FILE_MODE);
    EXPECT_EQ(ret, 0);

    unlink(noSlash);
    unlink(newPath);
    chdir(origCwd);
    free(origCwd);
}

HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_StaleNewIsDir, TestSize.Level1)
{
    unlink(TEST_ATOMIC_PATH);
    char bakPath[256] = {0};
    GetTestBakPath(bakPath, sizeof(bakPath));
    unlink(bakPath);
    rmdir(TEST_ATOMIC_NEW);
    int32_t ret = mkdir(TEST_ATOMIC_NEW, S_IRWXU | S_IRGRP | S_IXGRP);
    ASSERT_EQ(ret, 0);

    ret = AtomicWriteFile(TEST_ATOMIC_PATH, "data", 4, FILE_MODE);
    EXPECT_NE(ret, 0);

    rmdir(TEST_ATOMIC_NEW);
    unlink(TEST_ATOMIC_PATH);
    unlink(bakPath);
}

/**
 * @tc.name: AtomicWriteFile_MainPreservedOnFailure
 * @tc.desc: When WriteAndSync fails (open .new as dir), main file is unchanged.
 * @tc.type: FUNC
 * @tc.require: AC-1.2
 */
HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_MainPreservedOnFailure, TestSize.Level1)
{
    unlink(TEST_ATOMIC_PATH);
    unlink(TEST_ATOMIC_NEW);
    char bakPath[256] = {0};
    GetTestBakPath(bakPath, sizeof(bakPath));
    unlink(bakPath);

    int32_t fd = open(TEST_ATOMIC_PATH, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(write(fd, "original_content", 17), 17);
    close(fd);

    ASSERT_EQ(mkdir(TEST_ATOMIC_NEW, S_IRWXU), 0);

    int32_t ret = AtomicWriteFile(TEST_ATOMIC_PATH, "new_data", 8, FILE_MODE);
    EXPECT_NE(ret, 0);

    fd = open(TEST_ATOMIC_PATH, O_RDONLY);
    ASSERT_GE(fd, 0);
    char buf[256] = {0};
    ssize_t bytesRead = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    ASSERT_GT(bytesRead, 0);
    EXPECT_STREQ(buf, "original_content");

    rmdir(TEST_ATOMIC_NEW);
    unlink(TEST_ATOMIC_PATH);
    unlink(bakPath);
}

/**
 * @tc.name: AtomicWriteFile_ChownInheritsParentUidGid
 * @tc.desc: After AtomicWriteFile, main and backup uid/gid match parent dir.
 * @tc.type: FUNC
 * @tc.require: AC-1.5
 */
HWTEST(AccessTokenFileUtilTest, AtomicWriteFile_ChownInheritsParentUidGid, TestSize.Level1)
{
    unlink(TEST_ATOMIC_PATH);
    unlink(TEST_ATOMIC_NEW);
    char bakPath[256] = {0};
    GetTestBakPath(bakPath, sizeof(bakPath));
    unlink(bakPath);

    struct stat dirStat = {};
    ASSERT_EQ(stat("/data/local/tmp", &dirStat), 0);

    int32_t ret = AtomicWriteFile(TEST_ATOMIC_PATH, "data", 4, FILE_MODE);
    EXPECT_EQ(ret, 0);

    struct stat fileStat = {};
    ASSERT_EQ(stat(TEST_ATOMIC_PATH, &fileStat), 0);
    EXPECT_EQ(fileStat.st_uid, dirStat.st_uid);
    EXPECT_EQ(fileStat.st_gid, dirStat.st_gid);

    struct stat bakStat = {};
    ASSERT_EQ(stat(bakPath, &bakStat), 0);
    EXPECT_EQ(bakStat.st_uid, dirStat.st_uid);
    EXPECT_EQ(bakStat.st_gid, dirStat.st_gid);

    EXPECT_NE(stat(TEST_ATOMIC_NEW, &fileStat), 0);

    unlink(TEST_ATOMIC_PATH);
    unlink(bakPath);
}
