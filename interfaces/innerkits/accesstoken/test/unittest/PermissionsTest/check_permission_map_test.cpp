/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "check_permission_map_test.h"
#include "gtest/gtest.h"
#include <fcntl.h>
#include <cstdint>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>

#include "access_token.h"
#include "cJSON.h"

#include "permission_def.h"
#include "permission_map.h"

using namespace testing::ext;
typedef cJSON CJson;
typedef std::unique_ptr<CJson, std::function<void(CJson *ptr)>> CJsonUnique;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string DEFINE_PERMISSION_FILE = "/system/etc/access_token/permission_definitions.json";
static const std::string SYSTEM_GRANT_DEFINE_PERMISSION = "systemGrantPermissions";
static const std::string USER_GRANT_DEFINE_PERMISSION = "userGrantPermissions";
static const std::string PERMISSION_GRANT_MODE_SYSTEM_GRANT = "system_grant";
constexpr int32_t MAX_NATIVE_CONFIG_FILE_SIZE = 5 * 1024 * 1024; // 5M
constexpr size_t BUFFER_SIZE = 1024;
constexpr uint32_t ACCESS_TOKEN_UID = 3020;
}

void CheckPermissionMapTest::SetUpTestCase()
{
}

void CheckPermissionMapTest::TearDownTestCase()
{
}

void CheckPermissionMapTest::SetUp()
{
}

void CheckPermissionMapTest::TearDown()
{
}

static int32_t GetPermissionGrantMode(const std::string &mode)
{
    if (mode == PERMISSION_GRANT_MODE_SYSTEM_GRANT) {
        return AccessToken::GrantMode::SYSTEM_GRANT;
    }
    return AccessToken::GrantMode::USER_GRANT;
}

static bool ReadCfgFile(const std::string& file, std::string& rawData)
{
    int32_t selfUid = getuid();
    setuid(ACCESS_TOKEN_UID);
    char filePath[PATH_MAX] = {0};
    if (realpath(file.c_str(), filePath) == NULL) {
        setuid(selfUid);
        return false;
    }
    int32_t fd = open(filePath, O_RDONLY);
    if (fd < 0) {
        setuid(selfUid);
        return false;
    }
    struct stat statBuffer;

    if (fstat(fd, &statBuffer) != 0) {
        close(fd);
        setuid(selfUid);
        return false;
    }

    if (statBuffer.st_size == 0) {
        close(fd);
        setuid(selfUid);
        return false;
    }
    if (statBuffer.st_size > MAX_NATIVE_CONFIG_FILE_SIZE) {
        close(fd);
        setuid(selfUid);
        return false;
    }
    rawData.reserve(statBuffer.st_size);

    char buff[BUFFER_SIZE] = { 0 };
    ssize_t readLen = 0;
    while ((readLen = read(fd, buff, BUFFER_SIZE)) > 0) {
        rawData.append(buff, readLen);
    }
    close(fd);
    setuid(selfUid);
    return true;
}

void FreeJson(CJson* jsonObj)
{
    cJSON_Delete(jsonObj);
    jsonObj = nullptr;
}

CJsonUnique CreateJsonFromString(const std::string& jsonStr)
{
    if (jsonStr.empty()) {
        CJsonUnique aPtr(cJSON_CreateObject(), FreeJson);
        return aPtr;
    }
    CJsonUnique aPtr(cJSON_Parse(jsonStr.c_str()), FreeJson);
    return aPtr;
}

static CJson* GetArrayFromJson(const CJson* jsonObj, const std::string& key)
{
    if (key.empty()) {
        return nullptr;
    }

    CJson* objValue = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (objValue != nullptr && cJSON_IsArray(objValue)) {
        return objValue;
    }
    return nullptr;
}

bool GetStringFromJson(const CJson *jsonObj, const std::string& key, std::string& out)
{
    if (jsonObj == nullptr || key.empty()) {
        return false;
    }

    cJSON *jsonObjTmp = cJSON_GetObjectItemCaseSensitive(jsonObj, key.c_str());
    if (jsonObjTmp != nullptr && cJSON_IsString(jsonObjTmp)) {
        out = cJSON_GetStringValue(jsonObjTmp);
        return true;
    }
    return false;
}

static bool GetPermissionDefList(const CJsonUnique &json, const std::string& permsRawData,
    const std::string& type, std::vector<PermissionDef>& permDefList)
{
    cJSON *permDefObj = GetArrayFromJson(json.get(), type);
    if (permDefObj == nullptr) {
        return false;
    }
    CJson *j = nullptr;
    cJSON_ArrayForEach(j, permDefObj) {
        PermissionDef result;
        GetStringFromJson(j, "name", result.permissionName);
        std::string grantModeStr = "";
        GetStringFromJson(j, "grantMode", grantModeStr);
        result.grantMode = GetPermissionGrantMode(grantModeStr);
        permDefList.emplace_back(result);
    }
    return true;
}

static bool ParserPermsRawData(const std::string& permsRawData,
    std::vector<PermissionDef>& permDefList)
{
    CJsonUnique jsonRes = CreateJsonFromString(permsRawData);
    if (jsonRes == nullptr) {
        return false;
    }

    bool ret = GetPermissionDefList(jsonRes, permsRawData, SYSTEM_GRANT_DEFINE_PERMISSION, permDefList);
    if (!ret) {
        return false;
    }

    return GetPermissionDefList(jsonRes, permsRawData, USER_GRANT_DEFINE_PERMISSION, permDefList);
}

/**
 * @tc.name: CheckPermissionMapFuncTest001
 * @tc.desc: Check if permissions in permission_definitions.json are consistent with g_permMap in permission_map.cpp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionMapTest, CheckPermissionMapFuncTest001, TestSize.Level1)
{
    std::string permsRawData;
    EXPECT_TRUE(ReadCfgFile(DEFINE_PERMISSION_FILE, permsRawData));

    std::vector<PermissionDef> permDefList;
    EXPECT_TRUE(ParserPermsRawData(permsRawData, permDefList));

    uint32_t opCode;
    for (const auto& perm : permDefList) {
        // Check if permissions exist
        bool isExsit = TransferPermissionToOpcode(perm.permissionName, opCode);
        if (!isExsit) {
            GTEST_LOG_(INFO) << "permission name is " << perm.permissionName;
        }
        EXPECT_TRUE(isExsit);
        // Check true-user_grant/false-system_grant
        if (perm.grantMode == AccessToken::GrantMode::USER_GRANT) {
            EXPECT_TRUE(IsUserGrantPermission(perm.permissionName));
        } else if (perm.grantMode == AccessToken::GrantMode::SYSTEM_GRANT) {
            EXPECT_FALSE(IsUserGrantPermission(perm.permissionName));
        }
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS