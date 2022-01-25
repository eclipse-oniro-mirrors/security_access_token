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

#include "nativetoken_kit_test.h"
#include <pthread.h>
#include "nativetoken.h"
#include "nativetoken_kit.h"

using namespace testing::ext;
using namespace OHOS::Security;

extern NativeTokenList *g_tokenListHead;
extern int32_t g_isNativeTokenInited;
extern int32_t GetFileBuff(const char *cfg, char **retBuff);

void TokenLibKitTest::SetUpTestCase()
{}

void TokenLibKitTest::TearDownTestCase()
{}

void TokenLibKitTest::SetUp()
{
    g_isNativeTokenInited = 0;
    (void)remove(TOKEN_ID_CFG_FILE_PATH);
}

void TokenLibKitTest::TearDown()
{
    while (g_tokenListHead->next != nullptr) {
        NativeTokenList *tmp = g_tokenListHead->next;
        g_tokenListHead->next = tmp->next;
        free(tmp);
        tmp = nullptr;
    }
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
    free(dcaps);
    return tokenId;
}

/**
 * @tc.name: GetAccessTokenId001
 * @tc.desc: cannot getAccessTokenId with invalid processName.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
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

    /* 257 is invalid processName length */
    const std::string invalidProcName (257, 'x');
    tokenId = GetAccessTokenId(invalidProcName.c_str(), dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);

    /* 255 is valid processName length */
    const std::string validProcName01 (255, 'x');
    tokenId = GetAccessTokenId(validProcName01.c_str(), dcaps, dcapNum, "system_core");
    ASSERT_NE(tokenId, 0);

    /* 256 is valid processName length */
    const std::string validProcName02 (256, 'x');
    tokenId = GetAccessTokenId(validProcName02.c_str(), dcaps, dcapNum, "system_core");
    ASSERT_NE(tokenId, 0);
    free(dcaps);
}

/**
 * @tc.name: GetAccessTokenId002
 * @tc.desc: cannot getAccessTokenId with invalid dcapNum.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId002, TestSize.Level1)
{
    const char **dcaps = (const char **)malloc(sizeof(char *) * 32);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int dcapNum = -1;
    uint64_t tokenId;
    tokenId = GetAccessTokenId("GetAccessTokenId002", dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);

    /* 33 is invalid dcapNum */
    dcapNum = 33;
    tokenId = GetAccessTokenId("GetAccessTokenId002_00", dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);

    for (int32_t i = 0; i < 32; i++) {
        dcaps[i] = "AT_CAP";
    }
    /* 32 is valid dcapNum */
    dcapNum = 32;
    tokenId = GetAccessTokenId("GetAccessTokenId002_01", dcaps, dcapNum, "system_core");
    ASSERT_NE(tokenId, 0);

    /* 31 is valid dcapNum */
    dcapNum = 31;
    tokenId = GetAccessTokenId("GetAccessTokenId002_02", dcaps, dcapNum, "system_core");
    ASSERT_NE(tokenId, 0);
    
    free(dcaps);
}

/**
 * @tc.name: GetAccessTokenId003
 * @tc.desc: cannot getAccessTokenId with invalid dcaps.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId003, TestSize.Level1)
{
    const char **dcaps = (const char **)malloc(sizeof(char *) * 2);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int dcapNum = 2;
    uint64_t tokenId;
    tokenId = GetAccessTokenId("GetAccessTokenId003", nullptr, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);

    dcapNum = 0;
    tokenId = GetAccessTokenId("GetAccessTokenId003_01", nullptr, dcapNum, "system_core");
    ASSERT_NE(tokenId, 0);

    dcapNum = 2;
    /* 1025 is invalid dcap length */
    const std::string invalidDcap (1025, 'x');
    dcaps[0] = invalidDcap.c_str();
    tokenId = GetAccessTokenId("GetAccessTokenId003_02", dcaps, dcapNum, "system_core");
    ASSERT_EQ(tokenId, 0);

    /* 1024 is valid dcap length */
    const std::string validDcap01 (1024, 'x');
    dcaps[0] = validDcap01.c_str();
    tokenId = GetAccessTokenId("GetAccessTokenId003_03", dcaps, dcapNum, "system_core");
    ASSERT_NE(tokenId, 0);

    /* 1023 is valid dcap length */
    const std::string validDcap02 (1023, 'x');
    dcaps[0] = validDcap02.c_str();
    tokenId = GetAccessTokenId("GetAccessTokenId003_04", dcaps, dcapNum, "system_core");
    ASSERT_NE(tokenId, 0);

    free(dcaps);
}

/**
 * @tc.name: GetAccessTokenId004
 * @tc.desc: cannot getAccessTokenId with invalid APL.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
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

    free(dcaps);
}

/**
 * @tc.name: GetAccessTokenId005
 * @tc.desc: Get AccessTokenId successfully.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId005, TestSize.Level1)
{
    uint64_t tokenId01 = Start("GetAccessTokenId005");
    ASSERT_NE(tokenId01, 0);
    uint64_t tokenId02 = Start("GetAccessTokenId005");
    ASSERT_NE(tokenId02, 0);

    ASSERT_EQ(tokenId01, tokenId02);
}

/**
 * @tc.name: GetAccessTokenId006
 * @tc.desc: Get AccessTokenId with new processName and check g_tokenListHead.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId006, TestSize.Level1)
{
    uint64_t tokenID;
    NativeAtIdEx *tokenIdEx = (NativeAtIdEx *)(&tokenID);
    tokenID = Start("GetAccessTokenId006");

    int ret = strcmp("GetAccessTokenId006", g_tokenListHead->next->processName);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(tokenIdEx->tokenId, g_tokenListHead->next->tokenId);

    char *fileBuff = nullptr;
    ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    ASSERT_EQ(ret, ATRET_SUCCESS);
    string s = "GetAccessTokenId006";
    char *pos = strstr(fileBuff, s.c_str());
    ASSERT_NE(pos, nullptr);
}

/**
 * @tc.name: GetAccessTokenId007
 * @tc.desc: Get a batch of AccessTokenId.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId007, TestSize.Level1)
{
    char processName[200][MAX_PROCESS_NAME_LEN];
    /* enable 200 process before fondation is prepared */
    for (int32_t i = 0; i < 200; i++) {
        processName[i][0] = '\0';
        int ret = sprintf_s(processName[i], MAX_PROCESS_NAME_LEN, "processName_%d", i);
        ASSERT_NE(ret, 0);
        uint64_t tokenId = Start(processName[i]);
        ASSERT_NE(tokenId, 0);
    }
    char *fileBuff = nullptr;
    int ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    ASSERT_EQ(ret, 0);
    for (int32_t i = 0; i < 200; i++) {
        char *pos = strstr(fileBuff, processName[i]);
        ASSERT_NE(pos, nullptr);
    }
    free(fileBuff);
}

/**
 * @tc.name: GetAccessTokenId008
 * @tc.desc: Get AccessTokenId and check the config file.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId008, TestSize.Level1)
{
    char *fileBuff = nullptr;
    int ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    ASSERT_EQ(ret, 0);
    if (fileBuff != nullptr) {
        char *pos = strstr(fileBuff, "process1");
        ASSERT_EQ(pos, nullptr);
        pos = strstr(fileBuff, "process2");
        ASSERT_EQ(pos, nullptr);
        pos = strstr(fileBuff, "process3");
        ASSERT_EQ(pos, nullptr);
        pos = strstr(fileBuff, "process4");
        ASSERT_EQ(pos, nullptr);
        pos = strstr(fileBuff, "process5");
        ASSERT_EQ(pos, nullptr);
        pos = strstr(fileBuff, "process6");
        ASSERT_EQ(pos, nullptr);
        pos = strstr(fileBuff, "process7");
        ASSERT_EQ(pos, nullptr);
        pos = strstr(fileBuff, "process8");
        ASSERT_EQ(pos, nullptr);
        pos = strstr(fileBuff, "process9");
        ASSERT_EQ(pos, nullptr);
        pos = strstr(fileBuff, "foundation");
        ASSERT_EQ(pos, nullptr);
        free(fileBuff);
    }

    Start("process1");
    Start("process2");
    Start("process3");
    Start("process4");
    Start("process5");
    Start("foundation");
    Start("process6");
    Start("process7");
    Start("process8");
    Start("process9");
    Start("process10");
    Start("process15");
    Start("process16");
    Start("process17");
    Start("process18");
    Start("process19");

    ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    ASSERT_EQ(ret, 0);
    GTEST_LOG_(INFO) << "fileBuff" << fileBuff;
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
}
