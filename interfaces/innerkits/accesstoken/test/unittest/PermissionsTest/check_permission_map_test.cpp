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
#include <thread>
#include "access_token.h"
#include "access_token_error.h"
#include "accesstoken_log.h"
#include "tokenid_kit.h"
#include "token_setproc.h"
#include "json_parser.h"
#include "permission_def.h"
#include "nlohmann/json.hpp"
#include "data_validator.h"
#include "permission_map.h"

using namespace testing::ext;
namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE,
    SECURITY_DOMAIN_ACCESSTOKEN, "CheckPermissionMapTest"};
static const std::string DEFINE_PERMISSION_FILE = "/system/etc/access_token/permission_definitions.json";
static const std::string SYSTEM_GRANT_DEFINE_PERMISSION = "systemGrantPermissions";
static const std::string USER_GRANT_DEFINE_PERMISSION = "userGrantPermissions";
static const std::string PERMISSION_GRANT_MODE_SYSTEM_GRANT = "system_grant";
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

static int32_t GetPermissionDefList(const nlohmann::json& json, const std::string& permsRawData,
    const std::string& type, std::vector<PermissionDef>& permDefList)
{
    if ((json.find(type) == json.end()) || (!json.at(type).is_array())) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Json is not array.");
        return ERR_PARAM_INVALID;
    }

    PermissionDef result;
    nlohmann::json JsonData = json.at(type).get<nlohmann::json>();
    for (auto it = JsonData.begin(); it != JsonData.end(); it++) {
        result.permissionName = it->at("name").get<std::string>();
        result.grantMode = GetPermissionGrantMode(it->at("grantMode").get<std::string>());
        permDefList.emplace_back(result);
    }
    return RET_SUCCESS;
}

static int32_t ParserPermsRawData(const std::string& permsRawData,
    std::vector<PermissionDef>& permDefList)
{
    nlohmann::json jsonRes = nlohmann::json::parse(permsRawData, nullptr, false);
    if (jsonRes.is_discarded()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "JsonRes is invalid.");
        return ERR_PARAM_INVALID;
    }

    int32_t ret = GetPermissionDefList(jsonRes, permsRawData, SYSTEM_GRANT_DEFINE_PERMISSION, permDefList);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get system_grant permission def list failed.");
        return ret;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Get system_grant permission size=%{public}zu.", permDefList.size());
    ret = GetPermissionDefList(jsonRes, permsRawData, USER_GRANT_DEFINE_PERMISSION, permDefList);
    if (ret != RET_SUCCESS) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Get user_grant permission def list failed.");
        return ret;
    }
    ACCESSTOKEN_LOG_INFO(LABEL, "Get permission size=%{public}zu.", permDefList.size());
    return RET_SUCCESS;
}

/**
 * @tc.name: CheckPermissionMapFuncTest001
 * @tc.desc: Check if permissions in permission_definitions.json are consistent with g_permMap in permission_map.cpp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(CheckPermissionMapTest, CheckPermissionMapFuncTest001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "CheckPermissionMapFuncTest001");

    std::string permsRawData;
    int32_t ret = JsonParser::ReadCfgFile(DEFINE_PERMISSION_FILE, permsRawData);
    EXPECT_EQ(RET_SUCCESS, ret);

    std::vector<PermissionDef> permDefList;
    ret = ParserPermsRawData(permsRawData, permDefList);
    EXPECT_EQ(RET_SUCCESS, ret);

    uint32_t opCode;
    for (const auto& perm : permDefList) {
        // Check if permissions exist
        EXPECT_TRUE(TransferPermissionToOpcode(perm.permissionName, opCode));
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