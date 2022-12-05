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
#include "cJSON.h"

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
static const int32_t VALID_TIME = 100;
static const int32_t DEFAULT_TIME = -1;
extern int g_getArrayItemTime;
extern int g_getObjectItem;
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
}

/**
 * @tc.name: UpdateGoalItemFromRecord001
 * @tc.desc: UpdateGoalItemFromRecord abnormal.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, UpdateGoalItemFromRecord001, TestSize.Level1)
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
HWTEST_F(TokenOperTest, UpdateItemcontent001, TestSize.Level1)
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
HWTEST_F(TokenOperTest, UpdateItemcontent002, TestSize.Level1)
{
    SetTimes();
    NativeTokenList tokenNode;
    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");
    tokenNode.apl = 1;
    tokenNode.dcapsNum = 1;
    tokenNode.aclsNum = 0;
    tokenNode.permsNum = 0;

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
HWTEST_F(TokenOperTest, UpdateItemcontent003, TestSize.Level1)
{
    SetTimes();
    NativeTokenList tokenNode;
    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");
    tokenNode.apl = 1;
    tokenNode.dcapsNum = 1;
    tokenNode.dcaps[0] = static_cast<char *>(malloc(sizeof(char) * MAX_DCAP_LEN));
    EXPECT_NE(tokenNode.dcaps[0], nullptr);
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
    free(tokenNode.dcaps[0]);
}

/**
 * @tc.name: UpdateItemcontent003
 * @tc.desc: UpdateItemcontent abnormal in UpdateStrArrayType.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, UpdateItemcontent004, TestSize.Level1)
{
    SetTimes();
    NativeTokenList tokenNode;
    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");
    tokenNode.apl = 1;
    tokenNode.dcapsNum = 1;
    tokenNode.dcaps[0] = static_cast<char *>(malloc(sizeof(char) * MAX_DCAP_LEN));
    EXPECT_NE(tokenNode.dcaps[0], nullptr);
    (void)strcpy_s(tokenNode.dcaps[0], MAX_DCAP_LEN, "x");
    tokenNode.aclsNum = 0;
    tokenNode.permsNum = 0;

    std::string stringJson1 = R"([)"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]}])";

    cJSON* jsonRoot = cJSON_Parse(stringJson1.c_str());
    EXPECT_EQ(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    // perms update failed
    tokenNode.permsNum = 1;
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    // perms update failed
    tokenNode.aclsNum = 1;
    tokenNode.perms[0] = static_cast<char *>(malloc(sizeof(char) * MAX_PERM_LEN));
    EXPECT_NE(tokenNode.perms[0], nullptr);
    (void)strcpy_s(tokenNode.perms[0], MAX_PERM_LEN, "x");
    EXPECT_NE(UpdateGoalItemFromRecord(&tokenNode, jsonRoot), 0);

    cJSON_Delete(jsonRoot);
    free(tokenNode.dcaps[0]);
    free(tokenNode.perms[0]);
}

/**
 * @tc.name: CreateNativeTokenJsonObject001
 * @tc.desc: CreateNativeTokenJsonObject ABNORMAL.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, CreateNativeTokenJsonObject001, TestSize.Level1)
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

    free(tokenNode.dcaps[0]);
}

/**
 * @tc.name: CreateNativeTokenJsonObject002
 * @tc.desc: CreateNativeTokenJsonObject abnormal for AddStrArrayInfo.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, CreateNativeTokenJsonObject002, TestSize.Level1)
{
    SetTimes();
    NativeTokenList tokenNode;

    (void)strcpy_s(tokenNode.processName, MAX_PROCESS_NAME_LEN + 1, "process5");
    tokenNode.apl = 1;
    tokenNode.dcapsNum = 1;
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
    free(tokenNode.dcaps[0]);
}

/**
 * @tc.name: GetNativeTokenFromJson001
 * @tc.desc: GetNativeTokenFromJson successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, GetNativeTokenFromJson001, TestSize.Level1)
{
    SetTimes();

    g_parse = DEFAULT_TIME;
    AtlibInit();
    EXPECT_EQ(g_tokenListHead, nullptr);

    g_getArrayItemTime = DEFAULT_TIME;
    AtlibInit();
    EXPECT_EQ(g_tokenListHead, nullptr);

    g_getArraySize = DEFAULT_TIME;
    AtlibInit();
    EXPECT_EQ(g_tokenListHead, nullptr);

    g_getArraySize = 8; // 8 times
    AtlibInit();
    EXPECT_EQ(g_tokenListHead, nullptr);

    g_getArraySize = 17; // 17 times
    AtlibInit();
    EXPECT_EQ(g_tokenListHead, nullptr);
}

static int32_t Start(const char *processName)
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
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    delete[] dcaps;
    delete[] perms;
    delete[] acls;
    return tokenId;
}

/**
 * @tc.name: GetInfoArrFromJson001
 * @tc.desc: GetInfoArrFromJson successfully.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TokenOperTest, GetInfoArrFromJson001, TestSize.Level1)
{
    SetTimes();

    NativeTokenInfoParams tokenInfo;
    g_parse = DEFAULT_TIME;
    EXPECT_EQ(GetAccessTokenId(&tokenInfo), 0);

    // UpdateInfoInCfgFile failed for SaveTokenIdToCfg
    // tokenNode->dcapsNum != dcapNumIn branch
    g_parse = 8; // 8 times
    EXPECT_EQ(Start("foundation"), 0);

    g_printUnformatted = DEFAULT_TIME;
    EXPECT_NE(Start("process1"), 0);

    // CreateNativeTokenJsonObject failed 385 line
    EXPECT_NE(Start("processUnique"), 0);

    EXPECT_NE(Start("processUnique1"), 0);
}
