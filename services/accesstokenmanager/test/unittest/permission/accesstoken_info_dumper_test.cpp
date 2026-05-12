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

#include <gtest/gtest.h>

#include "access_token.h"
#include "access_token_error.h"
#define private public
#include "accesstoken_info_dumper.h"
#undef private
#include "accesstoken_info_manager.h"
#include "permission_map.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
PermissionStatus BuildStatus(const std::string& permissionName)
{
    PermissionStatus status;
    status.permissionName = permissionName;
    status.grantStatus = PERMISSION_DENIED;
    status.grantFlag = PERMISSION_DEFAULT_FLAG;
    return status;
}

HapInfoParams BuildInfoParams()
{
    return {
        .userID = 1,
        .bundleName = "accesstoken_dumper_test",
        .instIndex = 0,
        .appIDDesc = "accesstoken_dumper_test",
        .isSystemApp = false
    };
}

HapPolicy BuildPolicy()
{
    return {
        .apl = APL_NORMAL,
        .domain = "test.domain",
        .permList = {},
        .permStateList = {BuildStatus("ohos.permission.CAMERA"), BuildStatus("ohos.permission.MICROPHONE")}
    };
}

AccessTokenID CreateTestHapToken()
{
    AccessTokenIDEx tokenIdEx = {0};
    std::vector<GenericValues> undefValues;
    EXPECT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().CreateHapTokenInfo(
        BuildInfoParams(), BuildPolicy(), tokenIdEx, undefValues));
    return tokenIdEx.tokenIdExStruct.tokenID;
}

void RemoveTestHapToken(AccessTokenID tokenId)
{
    ASSERT_EQ(RET_SUCCESS, AccessTokenInfoManager::GetInstance().RemoveHapTokenInfo(tokenId));
}
} // namespace

class AccessTokenInfoDumperTest : public testing::Test {};

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo001, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = static_cast<AccessTokenID>(0);
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    dumpInfo.clear();
    info.tokenId = static_cast<AccessTokenID>(123);
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ("Error: TokenID does not exist.\n", dumpInfo);
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo002, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = tokenId;
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    RemoveTestHapToken(tokenId);
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo003, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo004, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("hdcd");
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo005, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = "hdcd";
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo006, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.bundleName = BuildInfoParams().bundleName;
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ(false, dumpInfo.empty());

    RemoveTestHapToken(tokenId);
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo007, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.bundleName = "bundle.not.exist";
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ("Error: BundleName 'bundle.not.exist' does not exist.\n", dumpInfo);
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo008, TestSize.Level0)
{
    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = "process.not.exist";
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_EQ("Error: ProcessName 'process.not.exist' does not exist.\n", dumpInfo);
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo009, TestSize.Level0)
{
    EXPECT_EQ("Error: TokenID does not exist.\n", AccessTokenInfoDumper::NativeTokenToString(INVALID_TOKENID));
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo010, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.tokenId = 0;
    AccessTokenInfoDumper::DumpTokenInfo(info, dumpInfo);
    EXPECT_NE(std::string::npos, dumpInfo.find(BuildInfoParams().bundleName));
    EXPECT_NE(std::string::npos, dumpInfo.find("accesstoken_service"));

    RemoveTestHapToken(tokenId);
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo011, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string dumpInfo;
    AccessTokenInfoDumper::DumpAllHapTokenName(dumpInfo);

    const std::string expectedLine = std::to_string(tokenId) + ": " + BuildInfoParams().bundleName;
    EXPECT_NE(std::string::npos, dumpInfo.find(expectedLine));

    RemoveTestHapToken(tokenId);
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo012, TestSize.Level0)
{
    const AccessTokenID nativeTokenId = AccessTokenInfoManager::GetInstance().GetNativeTokenId("accesstoken_service");
    ASSERT_NE(INVALID_TOKENID, nativeTokenId);

    std::string dumpInfo;
    AccessTokenInfoDumper::DumpAllNativeTokenName(dumpInfo);

    const std::string expectedLine = std::to_string(nativeTokenId) + ": accesstoken_service";
    EXPECT_NE(std::string::npos, dumpInfo.find(expectedLine));
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo013, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string dumpInfo;
    AccessTokenInfoDumper::DumpHapTokenInfoByTokenId(tokenId, dumpInfo);

    EXPECT_NE(std::string::npos, dumpInfo.find(BuildInfoParams().bundleName));
    EXPECT_NE(std::string::npos, dumpInfo.find(std::to_string(tokenId)));

    RemoveTestHapToken(tokenId);
}

HWTEST_F(AccessTokenInfoDumperTest, DumpTokenInfo014, TestSize.Level0)
{
    AccessTokenID tokenId = CreateTestHapToken();
    ASSERT_NE(INVALID_TOKENID, tokenId);

    std::string dumpInfo;
    AccessTokenInfoDumper::DumpHapTokenInfoByBundleName(BuildInfoParams().bundleName, dumpInfo);

    EXPECT_NE(std::string::npos, dumpInfo.find(BuildInfoParams().bundleName));
    EXPECT_NE(std::string::npos, dumpInfo.find(std::to_string(tokenId)));

    RemoveTestHapToken(tokenId);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
