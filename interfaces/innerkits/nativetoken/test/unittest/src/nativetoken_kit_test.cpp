/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include "securec.h"
#include "nativetoken.h"
#include "nativetoken_json_oper.h"
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

static void WriteContentToFile(const cJSON *root)
{
    char *jsonString = nullptr;
    jsonString = cJSON_PrintUnformatted(root);
    if (jsonString == nullptr) {
        return;
    }

    do {
        int32_t fd = open(TOKEN_ID_CFG_FILE_PATH, O_RDWR | O_CREAT | O_TRUNC,
                          S_IRUSR | S_IWUSR | S_IRGRP);
        if (fd < 0) {
            break;
        }
        size_t strLen = strlen(jsonString);
        ssize_t writtenLen = write(fd, static_cast<void *>(jsonString), strLen);
        close(fd);
        if (writtenLen < 0 || static_cast<size_t>(writtenLen) != strLen) {
            break;
        }
    } while (0);

    cJSON_free(jsonString);
    return;
}

static void DeleteGoalItemFromRecord(const char *processName, cJSON *record)
{
    cJSON *rec = nullptr;
    int32_t index = -1;
    bool isFound = false;
    cJSON_ArrayForEach(rec, record) {
        index++;
        cJSON *innerProcessName = cJSON_GetObjectItemCaseSensitive(rec, PROCESS_KEY_NAME);
        if ((cJSON_IsString(innerProcessName)) && (innerProcessName->valuestring != nullptr)) {
            if (strcmp(innerProcessName->valuestring, processName) == 0) {
                isFound = true;
                break;
            }
        }
    }
    if (isFound) {
        cJSON_DeleteItemFromArray(record, index);
    }
}

static int32_t DeleteNodeInFile(const char *processName)
{
    cJSON *record = nullptr;
    char *fileBuff = nullptr;

    if (GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff) != ATRET_SUCCESS) {
        return ATRET_FAILED;
    }

    if (fileBuff == nullptr) {
        record = cJSON_CreateArray();
    } else {
        record = cJSON_Parse(fileBuff);
        free(fileBuff);
        fileBuff = nullptr;
    }

    if (record == nullptr) {
        return ATRET_FAILED;
    }

    DeleteGoalItemFromRecord(processName, record);
    WriteContentToFile(record);
    cJSON_Delete(record);

    return ATRET_SUCCESS;
}

static int32_t DeleteAccessTokenId(const char *processName)
{
    int32_t result = 0;

    if ((g_isNativeTokenInited == 0) && (AtlibInit() != ATRET_SUCCESS)) {
        return INVALID_TOKEN_ID;
    }
    NativeTokenList *tokenNode = g_tokenListHead;
    while (tokenNode->next != nullptr) {
        if (strcmp(tokenNode->next->processName, processName) == 0) {
            result = DeleteNodeInFile(processName);
            NativeTokenList *tokenNodeA = tokenNode->next;
            tokenNode->next = tokenNode->next->next;
            free(tokenNodeA);
            break;
        }
        tokenNode = tokenNode->next;
    }
    return result;
}

int32_t Start(const char *processName)
{
    const char **dcaps = new (std::nothrow) const char *[2];
    if (dcaps == nullptr) {
        return 0;
    }
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    uint64_t tokenId;
    const char **perms = new (std::nothrow) const char *[2];
    if (perms == nullptr) {
        return 0;
    }
    perms[0] = "ohos.permission.test1";
    perms[1] = "ohos.permission.test2";
    const char **acls = new (std::nothrow) const char *[1];
    if (acls == nullptr) {
        return 0;
    }
    acls[0] = "ohos.permission.test1";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 2,
        .permsNum = 2,
        .aclsNum = 1,
        .dcaps = dcaps,
        .perms = perms,
        .acls = acls,
        .processName = processName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    delete[] dcaps;
    delete[] perms;
    delete[] acls;
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
    const char **dcaps = new (std::nothrow) const char *[2];
    ASSERT_NE(dcaps, nullptr);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int32_t dcapNum = 2;
    uint64_t tokenId;
    const char **perms = new (std::nothrow) const char *[2];
    ASSERT_NE(perms, nullptr);
    perms[0] = "ohos.permission.test1";
    perms[1] = "ohos.permission.test2";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = dcapNum,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = dcaps,
        .perms = perms,
        .acls = nullptr,
        .aplStr = "system_core",
    };
    infoInstance.processName = "";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);
    infoInstance.processName = nullptr;
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    /* 257 is invalid processName length */
    const std::string invalidProcName (257, 'x');
    infoInstance.processName = invalidProcName.c_str();
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    /* 255 is valid processName length */
    const std::string validProcName01 (255, 'x');
    infoInstance.processName = validProcName01.c_str();
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    /* 256 is valid processName length */
    const std::string validProcName02 (256, 'x');
    infoInstance.processName = validProcName02.c_str();
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);
    delete[] dcaps;
    delete[] perms;
}

/**
 * @tc.name: GetAccessTokenId002
 * @tc.desc: cannot getAccessTokenId with invalid dcapNum.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId002, TestSize.Level1)
{
    const char **dcaps = new (std::nothrow) const char *[32];
    ASSERT_NE(dcaps, nullptr);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int32_t dcapNum = -1;
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = dcaps,
        .perms = nullptr,
        .aplStr = "system_core",
    };
    infoInstance.dcapsNum = dcapNum;
    infoInstance.processName = "GetAccessTokenId002";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    /* 33 is invalid dcapNum */
    dcapNum = 33;
    infoInstance.dcapsNum = dcapNum;
    infoInstance.processName = "GetAccessTokenId002_00";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    for (int32_t i = 0; i < 32; i++) {
        dcaps[i] = "AT_CAP";
    }
    /* 32 is valid dcapNum */
    dcapNum = 32;
    infoInstance.dcapsNum = dcapNum;
    infoInstance.processName = "GetAccessTokenId002_01";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    /* 31 is valid dcapNum */
    dcapNum = 31;
    infoInstance.dcapsNum = dcapNum;
    infoInstance.processName = "GetAccessTokenId002_02";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    delete[] dcaps;
}

/**
 * @tc.name: GetAccessTokenId003
 * @tc.desc: cannot getAccessTokenId with invalid dcaps.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId003, TestSize.Level1)
{
    const char **dcaps = new (std::nothrow) const char *[2];
    ASSERT_NE(dcaps, nullptr);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int32_t dcapNum = 2;
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = dcaps,
        .perms = nullptr,
        .aplStr = "system_core",
    };
    infoInstance.dcapsNum = dcapNum;
    infoInstance.dcaps = nullptr;
    infoInstance.processName = "GetAccessTokenId003";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    dcapNum = 0;
    infoInstance.dcapsNum = dcapNum;
    infoInstance.dcaps = nullptr;
    infoInstance.processName = "GetAccessTokenId003_01";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    dcapNum = 2;
    /* 1025 is invalid dcap length */
    const std::string invalidDcap (1025, 'x');
    dcaps[0] = invalidDcap.c_str();
    infoInstance.dcapsNum = dcapNum;
    infoInstance.dcaps = dcaps;
    infoInstance.processName = "GetAccessTokenId003_02";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    /* 1024 is valid dcap length */
    const std::string validDcap01 (1024, 'x');
    dcaps[0] = validDcap01.c_str();
    infoInstance.dcapsNum = dcapNum;
    infoInstance.dcaps = dcaps;
    infoInstance.processName = "GetAccessTokenId003_03";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    /* 1023 is valid dcap length */
    const std::string validDcap02 (1023, 'x');
    dcaps[0] = validDcap02.c_str();
    infoInstance.dcapsNum = dcapNum;
    infoInstance.dcaps = dcaps;
    infoInstance.processName = "GetAccessTokenId003_04";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    delete[] dcaps;
}

/**
 * @tc.name: GetAccessTokenId004
 * @tc.desc: cannot getAccessTokenId with invalid APL.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId004, TestSize.Level1)
{
    const char **dcaps = new (std::nothrow) const char *[2];
    ASSERT_NE(dcaps, nullptr);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    int32_t dcapNum = 2;
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = dcapNum,
        .permsNum = 0,
        .aclsNum = 0,
        .dcaps = dcaps,
        .perms = nullptr,
        .processName = "GetAccessTokenId003",
    };

    infoInstance.aplStr = nullptr,
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    infoInstance.aplStr = "system_invalid",
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    delete[] dcaps;
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
    ASSERT_EQ(DeleteAccessTokenId("GetAccessTokenId005"), 0);
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
    tokenID = Start("GetAccessTokenId006");
    ASSERT_NE(tokenID, 0);

    char *fileBuff = nullptr;
    int32_t ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    ASSERT_EQ(ret, ATRET_SUCCESS);
    string s = "GetAccessTokenId006";
    char *pos = strstr(fileBuff, s.c_str());
    ASSERT_NE(pos, nullptr);
    ASSERT_EQ(DeleteAccessTokenId("GetAccessTokenId006"), 0);
}

/**
 * @tc.name: GetAccessTokenId007
 * @tc.desc: cannot getAccessTokenId with invalid dcapNum.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId007, TestSize.Level1)
{
    const char **perms = new (std::nothrow) const char *[MAX_PERM_NUM];
    ASSERT_NE(perms, nullptr);
    perms[0] = "ohos.permission.test1";
    perms[1] = "ohos.permission.test2";
    int32_t permsNum = -1;
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .aplStr = "system_core",
    };

    infoInstance.permsNum = permsNum;
    infoInstance.processName = "GetAccessTokenId007";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    permsNum = MAX_PERM_NUM + 1;
    infoInstance.permsNum = permsNum;
    infoInstance.processName = "GetAccessTokenId007_00";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    for (int32_t i = 0; i < MAX_PERM_NUM; i++) {
        perms[i] = "ohos.permission.test";
    }

    permsNum = MAX_PERM_NUM;
    infoInstance.permsNum = permsNum;
    infoInstance.processName = "GetAccessTokenId007_01";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId("GetAccessTokenId007_01"), 0);

    permsNum = MAX_PERM_NUM - 1;
    infoInstance.permsNum = permsNum;
    infoInstance.processName = "GetAccessTokenId007_02";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId("GetAccessTokenId007_02"), 0);

    delete[] perms;
}

/**
 * @tc.name: GetAccessTokenId008
 * @tc.desc: Get AccessTokenId with new processName.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId008, TestSize.Level1)
{
    const char **dcaps = new (std::nothrow) const char *[2];
    ASSERT_NE(dcaps, nullptr);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    uint64_t tokenId;
    const char **acls = new (std::nothrow) const char *[2];
    ASSERT_NE(acls, nullptr);
    acls[0] = "ohos.permission.test1";
    acls[1] = "ohos.permission.test2";
    const char **perms = new (std::nothrow) const char *[2];
    ASSERT_NE(perms, nullptr);
    perms[0] = "ohos.permission.test1";
    perms[1] = "ohos.permission.test2";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 2,
        .permsNum = 2,
        .aclsNum = 2,
        .dcaps = dcaps,
        .perms = perms,
        .acls = acls,
        .processName = "GetAccessTokenId008",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId("GetAccessTokenId008"), 0);

    delete[] perms;
    delete[] dcaps;
    delete[] acls;
}

/**
 * @tc.name: GetAccessTokenId009
 * @tc.desc: cannot getAccessTokenId with invalid perms.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId009, TestSize.Level1)
{
    const char **perms = new (std::nothrow) const char *[2];
    ASSERT_NE(perms, nullptr);
    perms[0] = "AT_CAP";
    perms[1] = "ST_CAP";
    int32_t permsNum = 2;
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .dcaps = nullptr,
        .aplStr = "system_core",
    };

    infoInstance.permsNum = permsNum;
    infoInstance.perms = nullptr;
    infoInstance.processName = "GetAccessTokenId009";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    permsNum = 0;
    infoInstance.permsNum = permsNum;
    infoInstance.perms = nullptr;
    infoInstance.processName = "GetAccessTokenId009_01";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId("GetAccessTokenId009_01"), 0);

    permsNum = 2;
    /* 1025 is invalid dcap length */
    const std::string invalidDcap (MAX_PERM_LEN + 1, 'x');
    perms[0] = invalidDcap.c_str();
    infoInstance.permsNum = permsNum;
    infoInstance.perms = perms;
    infoInstance.processName = "GetAccessTokenId009_02";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    const std::string validDcap01 (MAX_PERM_LEN, 'x');
    perms[0] = validDcap01.c_str();
    infoInstance.permsNum = permsNum;
    infoInstance.perms = perms;
    infoInstance.processName = "GetAccessTokenId009_03";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId("GetAccessTokenId009_03"), 0);

    const std::string validDcap02 (MAX_PERM_LEN - 1, 'x');
    perms[0] = validDcap02.c_str();
    infoInstance.permsNum = permsNum;
    infoInstance.perms = perms;
    infoInstance.processName = "GetAccessTokenId009_04";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId("GetAccessTokenId009_04"), 0);

    delete[] perms;
}

/**
 * @tc.name: GetAccessTokenId010
 * @tc.desc: Get a batch of AccessTokenId.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId010, TestSize.Level1)
{
    char processName[200][MAX_PROCESS_NAME_LEN];
    /* enable 200 process before fondation is prepared */
    for (int32_t i = 0; i < 200; i++) {
        processName[i][0] = '\0';
        int32_t ret = sprintf_s(processName[i], MAX_PROCESS_NAME_LEN, "processName_%d", i);
        ASSERT_NE(ret, 0);
        uint64_t tokenId = Start(processName[i]);
        ASSERT_NE(tokenId, 0);
    }
    char *fileBuff = nullptr;
    int32_t ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    ASSERT_EQ(ret, 0);
    for (int32_t i = 0; i < 200; i++) {
        char *pos = strstr(fileBuff, processName[i]);
        ASSERT_NE(pos, nullptr);
    }
    free(fileBuff);
    for (int32_t i = 0; i < 200; i++) {
        ASSERT_EQ(DeleteAccessTokenId(processName[i]), 0);
    }
}

/**
 * @tc.name: GetAccessTokenId011
 * @tc.desc: Get AccessTokenId and check the config file.
 * @tc.type: FUNC
 * @tc.require:AR000GK6TD
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId011, TestSize.Level1)
{
    Start("process1");
    Start("process2");

    char *fileBuff = nullptr;
    int32_t ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    ASSERT_EQ(ret, 0);
    char *pos = strstr(fileBuff, "process1");
    ASSERT_NE(pos, nullptr);
    pos = strstr(fileBuff, "process2");
    ASSERT_NE(pos, nullptr);
    free(fileBuff);

    DeleteAccessTokenId("process1");
    DeleteAccessTokenId("process2");
    fileBuff = nullptr;
    ret = GetFileBuff(TOKEN_ID_CFG_FILE_PATH, &fileBuff);
    ASSERT_EQ(ret, 0);
    pos = strstr(fileBuff, "process1");
    ASSERT_EQ(pos, nullptr);
    pos = strstr(fileBuff, "process2");
    ASSERT_EQ(pos, nullptr);
    free(fileBuff);
}

/**
 * @tc.name: GetAccessTokenId012
 * @tc.desc: Get AccessTokenId with valid acls.
 * @tc.type: FUNC
 * @tc.require:AR000H09K6
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId012, TestSize.Level1)
{
    const char **dcaps = new (std::nothrow) const char *[2];
    ASSERT_NE(dcaps, nullptr);
    dcaps[0] = "AT_CAP";
    dcaps[1] = "ST_CAP";
    uint64_t tokenId;
    const char **acls = new (std::nothrow) const char *[2];
    ASSERT_NE(acls, nullptr);
    acls[0] = "ohos.permission.test1";
    acls[1] = "ohos.permission.test2";

    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 2,
        .permsNum = 0,
        .aclsNum = 2,
        .dcaps = dcaps,
        .perms = nullptr,
        .acls = acls,
        .processName = "GetAccessTokenId008",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    infoInstance.acls = nullptr;
    infoInstance.aclsNum = 0;

    delete[] dcaps;
    delete[] acls;
}

/**
 * @tc.name: GetAccessTokenId013
 * @tc.desc: cannot getAccessTokenId with invalid acls.
 * @tc.type: FUNC
 * @tc.require:AR000H09K6
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId013, TestSize.Level1)
{
    const char **acls = new (std::nothrow) const char *[2];
    ASSERT_NE(acls, nullptr);
    acls[0] = "AT_CAP";
    acls[1] = "ST_CAP";
    int32_t aclsNum = 2;
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .dcaps = nullptr,
        .perms = acls,
        .aplStr = "system_core",
    };

    infoInstance.aclsNum = aclsNum;
    infoInstance.acls = nullptr;
    infoInstance.processName = "GetAccessTokenId013";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    aclsNum = 0;
    infoInstance.aclsNum = aclsNum;
    infoInstance.acls = nullptr;
    infoInstance.processName = "GetAccessTokenId013_01";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    aclsNum = 1;
    const std::string invalidAcl (MAX_PERM_LEN + 1, 'x');
    acls[0] = invalidAcl.c_str();
    infoInstance.aclsNum = aclsNum;
    infoInstance.acls = acls;
    infoInstance.processName = "GetAccessTokenId013_02";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    const std::string validcAcl01 (MAX_PERM_LEN, 'x');
    acls[0] = validcAcl01.c_str();
    infoInstance.aclsNum = aclsNum;
    infoInstance.acls = acls;
    infoInstance.processName = "GetAccessTokenId013_03";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    const std::string validcAcl02 (MAX_PERM_LEN - 1, 'x');
    acls[0] = validcAcl02.c_str();
    infoInstance.aclsNum = aclsNum;
    infoInstance.acls = acls;
    infoInstance.processName = "GetAccessTokenId013_04";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    delete[] acls;
}

/**
 * @tc.name: GetAccessTokenId014
 * @tc.desc: getAccessTokenId success with perms and acls.
 * @tc.type: FUNC
 * @tc.require:AR000H09K7
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId014, TestSize.Level0)
{
    uint64_t tokenId;
    const char **acls = new (std::nothrow) const char *[1];
    ASSERT_NE(acls, nullptr);
    acls[0] = "ohos.permission.PERMISSION_USED_STATS";
    const char **perms = new (std::nothrow) const char *[3];
    ASSERT_NE(perms, nullptr);
    perms[0] = "ohos.permission.PERMISSION_USED_STATS"; // system_core
    perms[1] = "ohos.permission.PLACE_CALL"; // system_basic
    perms[2] = "ohos.permission.unknown"; // invalid
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 3,
        .dcaps = nullptr,
        .perms = perms,
        .aplStr = "system_basic",
    };

    infoInstance.acls = nullptr;
    infoInstance.aclsNum = 0;
    infoInstance.processName = "GetAccessTokenId014_01";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    infoInstance.acls = acls;
    infoInstance.aclsNum = 1;
    infoInstance.processName = "GetAccessTokenId014_02";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    delete[] perms;
    delete[] acls;
}

/**
 * @tc.name: GetAccessTokenId015
 * @tc.desc: cannot getAccessTokenId with invalid aclsNum.
 * @tc.type: FUNC
 * @tc.require:AR000H09K6
 */
HWTEST_F(TokenLibKitTest, GetAccessTokenId015, TestSize.Level1)
{
    const char **perms = new (std::nothrow) const char *[MAX_PERM_NUM + 1];
    ASSERT_NE(perms, nullptr);
    perms[0] = "ohos.permission.test1";
    perms[1] = "ohos.permission.test2";
    int32_t permsNum = 2;
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = perms,
        .aplStr = "system_core",
    };

    infoInstance.permsNum = permsNum;
    infoInstance.aclsNum = -1;
    infoInstance.processName = "GetAccessTokenId015";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    for (int32_t i = 0; i < MAX_PERM_NUM + 1; i++) {
        perms[i] = "ohos.permission.test";
    }

    infoInstance.permsNum = MAX_PERM_NUM;
    infoInstance.aclsNum = MAX_PERM_NUM + 1;
    infoInstance.processName = "GetAccessTokenId015_00";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    permsNum = MAX_PERM_NUM;
    infoInstance.permsNum = permsNum;
    infoInstance.aclsNum = permsNum;
    infoInstance.processName = "GetAccessTokenId015_01";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    permsNum = MAX_PERM_NUM - 1;
    infoInstance.permsNum = permsNum;
    infoInstance.aclsNum = permsNum;
    infoInstance.processName = "GetAccessTokenId015_02";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, 0);
    ASSERT_EQ(DeleteAccessTokenId(infoInstance.processName), 0);

    permsNum = MAX_PERM_NUM - 1;
    infoInstance.permsNum = permsNum;
    infoInstance.aclsNum = permsNum + 1;
    infoInstance.processName = "GetAccessTokenId015_03";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(tokenId, 0);

    delete[] perms;
}
