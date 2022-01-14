/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "accesstokenlib_kit_test.h"
#include <pthread.h>
#include "accesstoken_lib.h"
#include "accesstokenlib_kit.h"

using namespace testing::ext;
using namespace OHOS::Security;

extern NativeTokenQueue *g_tokenQueueHead;
extern NativeTokenList *g_tokenListHead;
extern char *GetFileBuff(const char *cfg);
namespace {
static NativeTokenQueue g_readRes;
static string g_jsonStr = "["
    "{\"processName\":\"asdf\", \"tokenId\":15},"
    "{\"processName\":\"GetAccessTokenId008\", \"tokenId\":16},"
    "{\"processName\":\"GetAccessTokenId009\", \"tokenId\":17}"
    "]";
}
void TokenLibKitTest::SetUpTestCase()
{}

void TokenLibKitTest::TearDownTestCase()
{}

void TokenLibKitTest::SetUp()
{
    AtlibInit();
    ResetFile();
    g_readRes.next = nullptr;
}

void TokenLibKitTest::TearDown()
{
    while (g_tokenQueueHead->next != nullptr) {
        NativeTokenQueue *tmp = g_tokenQueueHead->next;
        g_tokenQueueHead->next = tmp->next;
        free(tmp);
        tmp = nullptr;
    }
    while (g_tokenListHead->next != nullptr) {
        NativeTokenList *tmp = g_tokenListHead->next;
        g_tokenListHead->next = tmp->next;
        free(tmp);
        tmp = nullptr;
    }
    while (g_readRes.next != nullptr) {
        NativeTokenQueue *tmp = g_readRes.next;
        g_readRes.next = tmp->next;
        free(tmp);
        tmp = nullptr;
    }
}

void TokenLibKitTest::ResetFile(void)
{
    int32_t fd = open(TOKEN_ID_CFG_PATH, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:open failed.", __func__);
        return;
    }
    int32_t strLen = strlen(g_jsonStr.c_str());
    int32_t writtenLen = write(fd, (void *)g_jsonStr.c_str(), strLen);
    close(fd);
    if (writtenLen != strLen) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:write failed, writtenLen is %d.", __func__, writtenLen);
    }
}

void TokenLibKitTest::PthreadCloseTrigger(void)
{
    struct sockaddr_un addr;
    int32_t fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:socket failed.", __func__);
        return;
    }
    (void)memset_s(&addr, sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    if (strncpy_s(addr.sun_path, sizeof(addr.sun_path), SOCKET_FILE, sizeof(addr.sun_path) - 1) != EOK) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:strncpy_s failed.", __func__);
        close(fd);
        return;
    }
    int result = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (result != 0) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:connect failed.", __func__);
        close(fd);
        return;
    }
    int32_t writtenSize = write(fd, "over", 4);
    if (writtenSize != 4) {
        ACCESSTOKEN_LOG_ERROR("[ATLIB-%s]:SendString write failed.", __func__);
    }
    close(fd);
    return;
}


int Start(const char *processName)
{
    const char *processname = processName;
    const char **dcaps = (const char **)malloc(sizeof(char *) * 2);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int dcapNum = 2;
    uint64_t tokenId;
    tokenId = GetAccessTokenId(processname, dcaps, dcapNum, "system_core");
    return tokenId;
}

HWTEST_F(TokenLibKitTest, GetAccessTokenId001, TestSize.Level1)
{
    const char **dcaps = (const char **)malloc(sizeof(char *) * 2);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int dcapNum = 2;
    uint64_t tokenId;
    tokenId = GetAccessTokenId("", dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);
    tokenId = GetAccessTokenId(nullptr, dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);
    const std::string invalidProcName (257, 'x');
    tokenId = GetAccessTokenId(invalidProcName.c_str(), dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);
}

HWTEST_F(TokenLibKitTest, GetAccessTokenId002, TestSize.Level1)
{
    const char **dcaps = (const char **)malloc(sizeof(char *) * 2);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int dcapNum = -1;
    uint64_t tokenId;
    tokenId = GetAccessTokenId("GetAccessTokenId002", dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);

    dcapNum = 1025;
    tokenId = GetAccessTokenId("GetAccessTokenId002", dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);
}

HWTEST_F(TokenLibKitTest, GetAccessTokenId003, TestSize.Level1)
{
    const char **dcaps = (const char **)malloc(sizeof(char *) * 2);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int dcapNum = 2;
    uint64_t tokenId;
    tokenId = GetAccessTokenId("GetAccessTokenId003", nullptr, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);

    const std::string invalidDcaps (1025, 'x');
    dcaps[0] = invalidDcaps.c_str();
    tokenId = GetAccessTokenId("GetAccessTokenId003", dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);
}

HWTEST_F(TokenLibKitTest, GetAccessTokenId004, TestSize.Level1)
{
    const char **dcaps = (const char **)malloc(sizeof(char *) * 2);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int dcapNum = 2;
    uint64_t tokenId;
    tokenId = GetAccessTokenId("GetAccessTokenId003", dcaps, dcapNum, nullptr);
    ASSERT_EQ(tokenId, 0);

    tokenId = GetAccessTokenId("GetAccessTokenId003", dcaps, dcapNum, "system_invalid");
    ASSERT_EQ(tokenId, 0);
}

HWTEST_F(TokenLibKitTest, GetAccessTokenId005, TestSize.Level1)
{
    uint64_t tokenId01 = Start("GetAccessTokenId005");
    ASSERT_NE(tokenId01, 0);
    uint64_t tokenId02 = Start("GetAccessTokenId005");
    ASSERT_NE(tokenId02, 0);

    ASSERT_EQ(tokenId01, tokenId02);
}

HWTEST_F(TokenLibKitTest, GetAccessTokenId007, TestSize.Level1)
{
    uint64_t tokenID;
    NativeAtIdEx *tokenIdEx = (NativeAtIdEx *)(&tokenID);
    tokenID = Start("GetAccessTokenId007");

    int ret = strcmp("GetAccessTokenId007", g_tokenListHead->next->processName);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(tokenIdEx->tokenId, g_tokenListHead->next->tokenId);

    ret = strcmp("GetAccessTokenId007", g_tokenQueueHead->next->processName);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(tokenIdEx->tokenId, g_tokenQueueHead->next->tokenId);

    char *fileBuff = GetFileBuff(TOKEN_ID_CFG_PATH);
    string s = "GetAccessTokenId007";
    char *pos = strstr(fileBuff, s.c_str());
    ASSERT_EQ(pos, nullptr);
}

HWTEST_F(TokenLibKitTest, GetAccessTokenId008, TestSize.Level1)
{
    uint64_t tokenID;
    NativeAtIdEx *tokenIdEx = (NativeAtIdEx *)(&tokenID);
    tokenID = Start("GetAccessTokenId008");

    string s = "GetAccessTokenId008";
    int ret = strcmp(s.c_str(), g_tokenQueueHead->next->processName);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(tokenIdEx->tokenId, g_tokenQueueHead->next->tokenId);
}

HWTEST_F(TokenLibKitTest, GetAccessTokenId009, TestSize.Level1)
{
    char *fileBuffBefore = GetFileBuff(TOKEN_ID_CFG_PATH);
    char *posMatch = strstr(fileBuffBefore, "GetAccessTokenId009");
    ASSERT_NE(posMatch, nullptr);
    free(fileBuffBefore);

    uint64_t tokenIdFoundation = Start("foundation");
    ASSERT_NE(tokenIdFoundation, 0);
    sleep(DELAY_ONE_SECONDS);
    uint64_t tokenID009 = Start("GetAccessTokenId009");
    ASSERT_NE(tokenID009, 0);

    tokenID009 = Start("GetAccessTokenId009_01");
    ASSERT_NE(tokenID009, 0);

    tokenID009 = Start("GetAccessTokenId009_02");
    ASSERT_NE(tokenID009, 0);

    sleep(DELAY_ONE_SECONDS);
    char *fileBuff = GetFileBuff(TOKEN_ID_CFG_PATH);
    char *pos = strstr(fileBuff, "GetAccessTokenId009");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "GetAccessTokenId009_01");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "GetAccessTokenId009_02");
    ASSERT_NE(pos, nullptr);
    free(fileBuff);
    PthreadCloseTrigger();
}

HWTEST_F(TokenLibKitTest, GetAccessTokenId010, TestSize.Level1)
{
    char *fileBuffBefore = GetFileBuff(TOKEN_ID_CFG_PATH);
    char *posMatch = strstr(fileBuffBefore, "GetAccessTokenId010");
    ASSERT_EQ(posMatch, nullptr);
    free(fileBuffBefore);

    uint64_t tokenIdFoundation = Start("foundation");
    ASSERT_NE(tokenIdFoundation, 0);
    sleep(DELAY_ONE_SECONDS);
    uint64_t tokenID010 = Start("GetAccessTokenId010");
    ASSERT_NE(tokenID010, 0);

    sleep(DELAY_ONE_SECONDS);
    char *fileBuff = GetFileBuff(TOKEN_ID_CFG_PATH);
    char *pos = strstr(fileBuff, "GetAccessTokenId010");
    ASSERT_NE(pos, nullptr);
    free(fileBuff);

    PthreadCloseTrigger();
}

 HWTEST_F(TokenLibKitTest, GetAccessTokenId011, TestSize.Level1)
{
    Start("process1");
    Start("process2");
    Start("process3");
    Start("process4");
    Start("process5");
    sleep(5);

    Start("foundation");
    Start("process6");
    Start("process7");
    Start("process8");
    Start("process9");
    Start("process10");
    sleep(5);
    Start("process15");
    Start("process16");
    sleep(5);
    Start("process17");
    sleep(5);
    Start("process18");
    sleep(5);
    Start("process19");
    sleep(5);
    char *fileBuff = GetFileBuff(TOKEN_ID_CFG_PATH);
    char *pos = strstr(fileBuff, "process1");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "process2");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "process3");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "process4");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "process5");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "process6");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "process7");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "process8");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "process9");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "foundation");
    ASSERT_NE(pos, nullptr);
    free(fileBuff);
    PthreadCloseTrigger();
}

 HWTEST_F(TokenLibKitTest, GetAccessTokenId012, TestSize.Level1)
{
    sleep(5);
    Start("process1");
    Start("process2");
    Start("process3");
    Start("process4");
    Start("process5");
    sleep(5);
    Start("foundation");
    Start("process6");
    sleep(5);
    Start("process11");
    Start("process12");
    Start("process13");
    Start("process15");
    Start("process16");
    Start("process17");
    sleep(1);
    PthreadCloseTrigger();
}
