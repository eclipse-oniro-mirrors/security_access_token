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
#include <fstream>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include "securec.h"
#include "nativetoken.h"
#include "nativetoken_json_oper.h"
#include "nativetoken_kit.h"
#include "cJSON.h"

using namespace testing::ext;
using namespace OHOS::Security;

void TokenOperTest::SetUpTestCase()
{
    GetHandle();
}

void TokenOperTest::TearDownTestCase()
{}

void TokenOperTest::SetUp()
{}

void TokenOperTest::TearDown()
{}
static const int32_t VALID_TIME = 100;
static const int32_t DEFAULT_TIME = -1;
static const char *TOKEN_ID_CFG_FILE_COPY_PATH = "/data/service/el0/access_token/nativetoken_copy.json";
extern int g_getArrayItemTime;
extern int g_getObjectItem;
extern int g_strcpyTime;
extern NativeTokenList *g_tokenListHead;

static void SetTimes(void)
{
    g_getArrayItemTime = VALID_TIME;
    g_getObjectItem = VALID_TIME;
    g_isStringTime = VALID_TIME;
    g_replaceItemInObjectTime = VALID_TIME;
    g_createNumberTime = VALID_TIME;
    g_createArrayTime = VALID_TIME;
    g_createStringTime = VALID_TIME;
    g_addItemToArray = VALID_TIME;
    g_addItemToObject = VALID_TIME;
    g_createObject = VALID_TIME;
    g_parse = VALID_TIME;
    g_getArraySize = VALID_TIME;
    g_printUnformatted = VALID_TIME;
    g_strcpyTime = VALID_TIME;
}

static bool IsFileEmpty(const std::string& fileName)
{
    FILE *file = fopen(fileName.c_str(), "r");
    if (file == nullptr) {
        std::cout << "fopen failed " << fileName << std::endl;
        return false;
    }
    (void)fseek(file, 0, SEEK_END);
    bool flag = false;
    if (ftell(file) == 0) {
        flag = true;
    }
    (void)fclose(file);
    return flag;
}

static int32_t ClearFile(const char* fileName)
{
    int32_t fd = open(fileName, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0) {
        return -1;
    }

    close(fd);
    return 0;
}

static void CopyNativeTokenJson(const std::string& sourceFileName, const std::string& destFileName)
{
    // if dest file exists, clear it;
    if (access(destFileName.c_str(), F_OK) == 0) {
        if (ClearFile(destFileName.c_str()) != 0) {
            std::cout << "dest file exists, failed to remove dest file" << std::endl;
            return;
        }
    }

    std::ifstream sourceFile(sourceFileName, std::ios::binary);
    std::ofstream destFile(destFileName, std::ios::binary);
    if (!sourceFile.is_open()) {
        std::cout << "open source file " << sourceFileName << "failed" << std::endl;
        return;
    }

    destFile << sourceFile.rdbuf();

    sourceFile.close();
    destFile.close();
}

/**
 * @tc.name: UpdateGoalItemFromRecord001
 * @tc.desc: UpdateGoalItemFromRecord abnormal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, UpdateGoalItemFromRecord001, TestSize.Level0)
{
    SetTimes();
    NativeTokenList tokenNode;
    std::string stringJson1 = R"()"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]})";

    cJSON* jsonRoot = cJSON_Parse(stringJson1.c_str());
    g_getArrayItemTime = DEFAULT_TIME;
    g_getObjectItem = DEFAULT_TIME;

    // cJSON_GetArrayItem failed
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    // processNameJson == NULL
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    cJSON_Delete(jsonRoot);
}

/**
 * @tc.name: UpdateItemcontent001
 * @tc.desc: UpdateItemcontent abnormal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, UpdateItemcontent001, TestSize.Level0)
{
    SetTimes();
    g_createNumberTime = DEFAULT_TIME;
    g_replaceItemInObjectTime = DEFAULT_TIME;
    NativeTokenList tokenNode;
    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");

    std::string stringJson1 = R"([)"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]}])";

    cJSON* jsonRoot = cJSON_Parse(stringJson1.c_str());

    // cJSON_CreateNumber failed 248 line
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    // cJSON_ReplaceItemInObject failed 251 line
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    cJSON_Delete(jsonRoot);
}

/**
 * @tc.name: UpdateItemcontent002
 * @tc.desc: UpdateItemcontent abnormal in UpdateStrArrayType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, UpdateItemcontent002, TestSize.Level0)
{
    SetTimes();
    NativeTokenList tokenNode;
    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");
    tokenNode.apl = 1;
    tokenNode.dcapsNum = 1;
    tokenNode.aclsNum = 0;
    tokenNode.permsNum = 0;
    tokenNode.dcaps = static_cast<char **>(malloc(tokenNode.dcapsNum * sizeof(char *)));
    EXPECT_NE(tokenNode.dcaps, nullptr);
    tokenNode.perms = static_cast<char **>(malloc(tokenNode.permsNum * sizeof(char *)));
    EXPECT_NE(tokenNode.perms, nullptr);
    tokenNode.acls = static_cast<char **>(malloc(tokenNode.aclsNum * sizeof(char *)));
    EXPECT_NE(tokenNode.acls, nullptr);

    std::string stringJson1 = R"([)"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]}])";

    cJSON* jsonRoot = cJSON_Parse(stringJson1.c_str());

    g_createArrayTime = DEFAULT_TIME;
    // cJSON_CreateArray failed 209 line
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    // cJSON_CreateString failed 215 line
    g_createStringTime = DEFAULT_TIME;
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);
    cJSON_Delete(jsonRoot);
}

/**
 * @tc.name: UpdateItemcontent003
 * @tc.desc: UpdateItemcontent abnormal in UpdateStrArrayType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, UpdateItemcontent003, TestSize.Level0)
{
    SetTimes();
    NativeTokenList tokenNode;
    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");
    int32_t newDcapsNum = 2;
    tokenNode.apl = 1;
    tokenNode.dcapsNum = 1;
    tokenNode.dcaps = static_cast<char **>(malloc(sizeof(char *) * newDcapsNum));
    EXPECT_NE(tokenNode.dcaps, nullptr);
    for (int32_t i = 0; i < newDcapsNum; ++i) {
        tokenNode.dcaps[i] = static_cast<char *>(malloc(sizeof(char) * MAX_DCAP_LEN));
        EXPECT_NE(tokenNode.dcaps[i], nullptr);
    }
    (void)strcpy_s(tokenNode.dcaps[0], MAX_DCAP_LEN, "x");
    tokenNode.aclsNum = 0;
    tokenNode.permsNum = 0;

    std::string stringJson1 = R"([)"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]}])";

    cJSON* jsonRoot = cJSON_Parse(stringJson1.c_str());

    // cJSON_AddItemToArray failed 221
    g_addItemToArray = DEFAULT_TIME;
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    // cJSON_GetObjectItem failed 228
    g_getObjectItem = 8; // 8 times
    EXPECT_EQ(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    // cJSON_AddItemToObject failed
    g_getObjectItem = 8; // 8 times
    g_addItemToObject = DEFAULT_TIME;
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    // cJSON_AddItemToObject failed 229 line
    g_replaceItemInObjectTime = 8; // 8 times
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    cJSON_Delete(jsonRoot);
    FreeStrArray(&tokenNode.dcaps, newDcapsNum - 1);
}

/**
 * @tc.name: UpdateItemcontent003
 * @tc.desc: UpdateItemcontent abnormal in UpdateStrArrayType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, UpdateItemcontent004, TestSize.Level0)
{
    SetTimes();
    NativeTokenList tokenNode;
    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");
    int32_t newDcapsNum = 2;
    tokenNode.apl = 1;
    tokenNode.dcapsNum = 1;
    tokenNode.dcaps = static_cast<char **>(malloc(sizeof(char *) * newDcapsNum));
    EXPECT_NE(tokenNode.dcaps, nullptr);
    for (int32_t i = 0; i < newDcapsNum; ++i) {
        tokenNode.dcaps[i] = static_cast<char *>(malloc(sizeof(char) * MAX_DCAP_LEN));
        EXPECT_NE(tokenNode.dcaps[i], nullptr);
    }
    (void)strcpy_s(tokenNode.dcaps[0], MAX_DCAP_LEN, "x");
    tokenNode.aclsNum = 0;
    tokenNode.permsNum = 0;

    std::string stringJson1 = R"([)"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]}])";

    cJSON* json = cJSON_Parse(stringJson1.c_str());
    EXPECT_EQ(UpdateGoalItemFromRecord(&tokenNode, json), 0);

    // perms update failed
    tokenNode.permsNum = 1;
    tokenNode.perms = static_cast<char **>(malloc(sizeof(char *) * tokenNode.permsNum));
    EXPECT_NE(tokenNode.perms, nullptr);
    tokenNode.perms[0] = nullptr;
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, json), 0);

    // acls update failed
    tokenNode.perms[0] = static_cast<char *>(malloc(sizeof(char) * MAX_PERM_LEN));
    (void)strcpy_s(tokenNode.perms[0], MAX_PERM_LEN, "x");
    tokenNode.aclsNum = 1;
    tokenNode.acls = static_cast<char **>(malloc(sizeof(char *) * tokenNode.aclsNum));
    EXPECT_NE(tokenNode.acls, nullptr);
    tokenNode.acls[0] = nullptr;
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, json), 0);

    tokenNode.acls[0] = static_cast<char *>(malloc(sizeof(char) * MAX_PERM_LEN));
    EXPECT_NE(tokenNode.acls[0], nullptr);
    (void)strcpy_s(tokenNode.acls[0], MAX_PERM_LEN, "x");
    EXPECT_EQ(UpdateGoalItemFromRecord(&tokenNode, json), 0);

    cJSON_Delete(json);
    FreeStrArray(&tokenNode.dcaps, newDcapsNum - 1);
    FreeStrArray(&tokenNode.perms, tokenNode.permsNum - 1);
    FreeStrArray(&tokenNode.acls, tokenNode.aclsNum - 1);
}

/**
 * @tc.name: CreateNativeTokenJsonObject001
 * @tc.desc: CreateNativeTokenJsonObject ABNORMAL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, CreateNativeTokenJsonObject001, TestSize.Level0)
{
    SetTimes();
    NativeTokenList tokenNode;

    // cJSON_CreateObject failed 194 line
    g_createObject = DEFAULT_TIME;
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_CreateString failed 143 line
    g_createStringTime = DEFAULT_TIME;
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");
    tokenNode.apl = 1;
    tokenNode.dcapsNum = 1;
    tokenNode.dcaps = static_cast<char **>(malloc(sizeof(char *) * tokenNode.dcapsNum));
    EXPECT_NE(tokenNode.dcaps, nullptr);
    tokenNode.dcaps[0] = static_cast<char *>(malloc(sizeof(char) * MAX_DCAP_LEN));
    EXPECT_NE(tokenNode.dcaps[0], nullptr);
    (void)strcpy_s(tokenNode.dcaps[0], MAX_DCAP_LEN, "x");
    tokenNode.aclsNum = 0;
    tokenNode.permsNum = 0;

    // cJSON_AddItemToObject failed 144 line
    g_addItemToObject = DEFAULT_TIME;
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_CreateNumber failed 150
    g_createNumberTime = DEFAULT_TIME;
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_AddItemToObject failed 151
    g_addItemToObject = 8; // 8 times
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_CreateNumber failed 157
    g_createNumberTime = 8; // 8 times
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_AddItemToObject failed 158
    g_addItemToObject = 17; // 17 times
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_CreateNumber failed 164
    g_createNumberTime = 17; // 17 times
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_AddItemToObject failed 165
    g_addItemToObject = 26; // 26 times
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_CreateNumber failed 171
    g_createNumberTime = 26; // 26 times
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_AddItemToObject failed 172
    g_addItemToObject = 35; // 35 times
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    FreeStrArray(&tokenNode.dcaps, tokenNode.dcapsNum - 1);
}

/**
 * @tc.name: CreateNativeTokenJsonObject002
 * @tc.desc: CreateNativeTokenJsonObject abnormal for AddStrArrayInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, CreateNativeTokenJsonObject002, TestSize.Level0)
{
    SetTimes();
    NativeTokenList tokenNode;

    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");
    tokenNode.apl = 1;
    tokenNode.dcapsNum = 1;
    tokenNode.dcaps = static_cast<char **>(malloc(sizeof(char *) * tokenNode.dcapsNum));
    EXPECT_NE(tokenNode.dcaps, nullptr);
    tokenNode.dcaps[0] = static_cast<char *>(malloc(sizeof(char) * MAX_DCAP_LEN));
    EXPECT_NE(tokenNode.dcaps[0], nullptr);
    (void)strcpy_s(tokenNode.dcaps[0], MAX_DCAP_LEN, "y");
    tokenNode.aclsNum = 0;
    tokenNode.permsNum = 0;

    // AddStrArrayInfo cJSON_CreateArray failed 119
    g_createArrayTime = DEFAULT_TIME;
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // AddStrArrayInfo cJSON_CreateString failed 125
    g_createStringTime = 8; // 8 times
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // AddStrArrayInfo cJSON_AddItemToArray failed 126
    g_addItemToArray = DEFAULT_TIME;
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);

    // cJSON_AddItemToObject failed 172
    g_addItemToObject = 44; // 44 times
    EXPECT_EQ(CreateNativeTokenJsonObject(&tokenNode), nullptr);
    FreeStrArray(&tokenNode.dcaps, tokenNode.dcapsNum - 1);
}

/**
 * @tc.name: GetNativeTokenFromJson001
 * @tc.desc: GetNativeTokenFromJson successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, GetNativeTokenFromJson001, TestSize.Level0)
{
    SetTimes();
    EXPECT_EQ(IsFileEmpty(TOKEN_ID_CFG_FILE_PATH), false);

    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_PATH, TOKEN_ID_CFG_FILE_COPY_PATH);
    g_parse = DEFAULT_TIME;
    AtlibInit();
    EXPECT_EQ(IsFileEmpty(TOKEN_ID_CFG_FILE_PATH), true);
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_COPY_PATH, TOKEN_ID_CFG_FILE_PATH);

    g_getArrayItemTime = DEFAULT_TIME;
    AtlibInit();
    EXPECT_EQ(IsFileEmpty(TOKEN_ID_CFG_FILE_PATH), true);
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_COPY_PATH, TOKEN_ID_CFG_FILE_PATH);

    g_getArraySize = DEFAULT_TIME;
    AtlibInit();
    EXPECT_EQ(IsFileEmpty(TOKEN_ID_CFG_FILE_PATH), true);
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_COPY_PATH, TOKEN_ID_CFG_FILE_PATH);

    g_getArraySize = 8; // 8 times
    AtlibInit();
    EXPECT_EQ(IsFileEmpty(TOKEN_ID_CFG_FILE_PATH), true);
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_COPY_PATH, TOKEN_ID_CFG_FILE_PATH);

    g_getArraySize = 17; // 17 times
    AtlibInit();
    EXPECT_EQ(IsFileEmpty(TOKEN_ID_CFG_FILE_PATH), true);
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_COPY_PATH, TOKEN_ID_CFG_FILE_PATH);

    std::remove(TOKEN_ID_CFG_FILE_COPY_PATH);
}

static int32_t Start(const char *processName, bool isChange = false)
{
    const char **dcapList = new (std::nothrow) const char *[2];
    if (dcapList == nullptr) {
        return 0;
    }
    dcapList[0] = "AT_CAP";
    dcapList[1] = "ST_CAP";
    uint64_t tokenId;
    const char **permList = new (std::nothrow) const char *[2];
    if (permList == nullptr) {
        return 0;
    }
    permList[0] = "ohos.permission.test1";
    permList[1] = "ohos.permission.test2";
    if (isChange) {
        permList[1] = "ohos.permission.test3";
    }
    const char **acls = new (std::nothrow) const char *[1];
    if (acls == nullptr) {
        return 0;
    }
    acls[0] = "ohos.permission.test1";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 2,
        .permsNum = 2,
        .aclsNum = 1,
        .dcaps = dcapList,
        .perms = permList,
        .acls = acls,
        .processName = processName,
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    delete[] dcapList;
    delete[] permList;
    delete[] acls;
    return tokenId;
}

/**
 * @tc.name: GetInfoArrFromJson001
 * @tc.desc: GetInfoArrFromJson successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, GetInfoArrFromJson001, TestSize.Level0)
{
    SetTimes();
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_PATH, TOKEN_ID_CFG_FILE_COPY_PATH);

    NativeTokenInfoParams tokenInfo;
    g_parse = DEFAULT_TIME;
    EXPECT_EQ(GetAccessTokenId(&tokenInfo), 0);
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_COPY_PATH, TOKEN_ID_CFG_FILE_PATH);
    g_parse = VALID_TIME;
    AtlibInit();
    EXPECT_EQ(IsFileEmpty(TOKEN_ID_CFG_FILE_PATH), false);

    // UpdateInfoInCfgFile failed for SaveTokenIdToCfg
    // tokenNode->dcapsNum != dcapNumIn branch
    g_parse = 9; // 9 times
    EXPECT_EQ(Start("foundation"), 0);
    EXPECT_EQ(IsFileEmpty(TOKEN_ID_CFG_FILE_PATH), false);

    g_printUnformatted = DEFAULT_TIME;
    EXPECT_NE(Start("process1"), 0);

    // CreateNativeTokenJsonObject failed 385 line
    EXPECT_NE(Start("processUnique"), 0);

    EXPECT_NE(Start("processUnique1"), 0);
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_COPY_PATH, TOKEN_ID_CFG_FILE_PATH);
    std::remove(TOKEN_ID_CFG_FILE_COPY_PATH);
}

/**
 * @tc.name: RemoveNodeFromList001
 * @tc.desc: remove foundation node of token list.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, RemoveNodeFromList001, TestSize.Level0)
{
    SetTimes();
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_PATH, TOKEN_ID_CFG_FILE_COPY_PATH);
    AtlibInit();
    EXPECT_NE(g_tokenListHead, nullptr);
    g_strcpyTime = 0;
    EXPECT_EQ(Start("foundation"), 0);

    // check the node whether exsits in the list
    NativeTokenList *node = g_tokenListHead->next;
    while (node != nullptr) {
        if (strcmp(node->processName, "foundation") == 0) {
            break;
        }
        node = node->next;
    }
    EXPECT_EQ(node, nullptr);

    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_COPY_PATH, TOKEN_ID_CFG_FILE_PATH);
    std::remove(TOKEN_ID_CFG_FILE_COPY_PATH);
}

/**
 * @tc.name: RemoveNodeFromList002
 * @tc.desc: rmeove the second node of token list.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, RemoveNodeFromList002, TestSize.Level0)
{
    SetTimes();
    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_PATH, TOKEN_ID_CFG_FILE_COPY_PATH);
    AtlibInit();
    EXPECT_NE(g_tokenListHead, nullptr);
    // add the node
    EXPECT_NE(Start("process3"), 0);
    g_strcpyTime = 0;

    // remove the node
    EXPECT_EQ(Start("process3", true), 0);

    // check the node whether exsits in the list
    NativeTokenList *node = g_tokenListHead->next;
    while (node != nullptr) {
        if (strcmp(node->processName, "process3") == 0) {
            break;
        }
        node = node->next;
    }
    EXPECT_EQ(node, nullptr);

    CopyNativeTokenJson(TOKEN_ID_CFG_FILE_COPY_PATH, TOKEN_ID_CFG_FILE_PATH);
    std::remove(TOKEN_ID_CFG_FILE_COPY_PATH);
}
