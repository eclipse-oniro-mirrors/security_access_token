/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "native_token_receptor_test.h"

#include <fcntl.h>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "accesstoken_info_manager.h"
#include "accesstoken_kit.h"
#include "access_token_db.h"
#include "access_token_error.h"
#include "permission_manager.h"
#include "permission_status.h"
#include "token_field_const.h"
#include "nativetoken_kit.h"
#define private public
#include "native_token_receptor.h"
#undef private
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

void NativeTokenReceptorTest::SetUpTestCase()
{
    // delete all test 0x28100000 - 0x28100007
    for (unsigned int i = 0x28100000; i <= 0x28100007; i++) {
        AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(i);
    }
}

void NativeTokenReceptorTest::TearDownTestCase()
{
    sleep(3); // delay 3 minutes
}

void NativeTokenReceptorTest::SetUp()
{}

void NativeTokenReceptorTest::TearDown()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test down!");
}

/**
 * @tc.name: ParserNativeRawData001
 * @tc.desc: Verify processing right native token json.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ParserNativeRawData001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test ParserNativeRawData001!");
    std::string testStr = R"([)"\
        R"({"processName":"process6","APL":3,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]},)"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"], "permissions":[], "nativeAcls":[]}])";

    NativeTokenReceptor& receptor = NativeTokenReceptor::GetInstance();
    std::vector<NativeTokenInfoBase> tokenInfos;
    receptor.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(2), tokenInfos.size());

    ASSERT_EQ("process6", tokenInfos[0].processName);
    ASSERT_EQ(static_cast<AccessTokenID>(685266937), tokenInfos[0].tokenID);

    ASSERT_EQ("process5", tokenInfos[1].processName);
    ASSERT_EQ(static_cast<AccessTokenID>(678065606), tokenInfos[1].tokenID);
}

/**
 * @tc.name: ParserNativeRawData002
 * @tc.desc: Verify processing wrong native token json.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ParserNativeRawData002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test ParserNativeRawData002!");
    std::string testStr = R"([{"processName":""}])";
    std::vector<NativeTokenInfoBase> tokenInfos;

    NativeTokenReceptor& receptor = NativeTokenReceptor::GetInstance();

    receptor.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr1 = R"([{"processName":"", }])";
    receptor.ParserNativeRawData(testStr1, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr2 = R"([{"processName":"process6"}, {}])";
    receptor.ParserNativeRawData(testStr2, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr3 = R"([{"processName":""}, {"":"", ""}])";
    receptor.ParserNativeRawData(testStr3, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr4 = R"([{"processName":"process6", "tokenId":685266937, "APL":3, "version":new}])";
    receptor.ParserNativeRawData(testStr4, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr5 = R"([{"processName":"process6", "tokenId":685266937, "APL":7, "version":1}])";
    receptor.ParserNativeRawData(testStr5, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr6 =
        R"({"NativeToken":[{"processName":"process6", "tokenId":685266937, "APL":7, "version":1}]})";
    receptor.ParserNativeRawData(testStr6, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr7 = R"({"NativeToken":[{"processName":"process6", "tokenId":685266937, "APL":7, "version":1}])";
    receptor.ParserNativeRawData(testStr7, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr8 = R"(["NativeToken":])";
    receptor.ParserNativeRawData(testStr8, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());

    std::string testStr9 = R"([)";
    receptor.ParserNativeRawData(testStr9, tokenInfos);
    ASSERT_EQ(static_cast<uint32_t>(0), tokenInfos.size());
}

/**
 * @tc.name: ParserNativeRawData002
 * @tc.desc: Verify from json right case.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ParserNativeRawData002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test ParserNativeRawData002!");
    std::string testStr = R"([)"\
        R"({"processName":"process6","APL":APL_SYSTEM_CORE,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"],)"\
        R"("permissions":["ohos.permission.PLACE_CALL"],)"\
        R"("nativeAcls":["ohos.permission.PLACE_CALL"]})"\
        R"(])";
    CJsonUnique j = CreateJsonFromString(testStr);
    NativeTokenInfoBase native;
    NativeTokenReceptor::GetInstance().GetNativeTokenInfoFromJson(j.get(), native);
    ASSERT_EQ(native.tokenID, 685266937);
}

/**
 * @tc.name: GetnNativeTokenInfoFromJson002
 * @tc.desc: Verify from json wrong case.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, GetnNativeTokenInfoFromJson002, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test GetnNativeTokenInfoFromJson002!");
    // version wrong
    std::string testStr = R"([)"\
        R"({"processName":"process6","APL":APL_SYSTEM_CORE,"version":2,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    CJsonUnique j = CreateJsonFromString(testStr);
    NativeTokenInfoBase native;
    NativeTokenReceptor::GetInstance().GetNativeTokenInfoFromJson(j.get(), native);
    ASSERT_EQ(native.tokenID, 0);

    // APL wrong
    testStr = R"([)"\
        R"({"processName":"process6","APL":-1,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    j = CreateJsonFromString(testStr);
    NativeTokenReceptor::GetInstance().GetNativeTokenInfoFromJson(j.get(), native);
    ASSERT_EQ(native.tokenID, 0);

    // tokenId wrong
    testStr = R"([)"\
        R"({"processName":"","APL":APL_SYSTEM_BASIC,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    j = CreateJsonFromString(testStr);
    NativeTokenReceptor::GetInstance().GetNativeTokenInfoFromJson(j.get(), native);
    ASSERT_EQ(native.tokenID, 0);

    // process name empty
    testStr = R"([)"\
        R"({"processName":name,"APL":APL_SYSTEM_BASIC,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    j = CreateJsonFromString(testStr);
    NativeTokenReceptor::GetInstance().GetNativeTokenInfoFromJson(j.get(), native);
    ASSERT_EQ(native.tokenID, 0);

    // process name too long
    testStr = R"([)"\
        R"({"processName":name,"APL":APL_SYSTEM_BASIC,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    j = CreateJsonFromString(testStr);
    NativeTokenReceptor::GetInstance().GetNativeTokenInfoFromJson(j.get(), native);
    ASSERT_EQ(native.tokenID, 0);

    // lose process name
    testStr = R"([)"\
        R"({"APL":APL_SYSTEM_BASIC,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]})"\
        R"(])";
    j = CreateJsonFromString(testStr);
    NativeTokenReceptor::GetInstance().GetNativeTokenInfoFromJson(j.get(), native);
    ASSERT_EQ(native.tokenID, 0);
}

/**
 * @tc.name: init001
 * @tc.desc: test get native cfg
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, init001, TestSize.Level1)
{
    LOGI(ATM_DOMAIN, ATM_TAG, "test init001!");

    const char *dcaps[1];
    dcaps[0] = "AT_CAP_01";
    int dcapNum = 1;
    const char *perms[2];
    perms[0] = "ohos.permission.test1";
    perms[1] = "ohos.permission.test2";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = dcapNum,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = dcaps,
        .perms = perms,
        .acls = nullptr,
        .processName = "native_token_test7",
        .aplStr = "system_core",
    };
    uint64_t tokenId = ::GetAccessTokenId(&infoInstance);
    ASSERT_NE(tokenId, INVALID_TOKENID);

    uint32_t nativeSize = 0;
    AccessTokenInfoManager::GetInstance().InitNativeTokenInfos(nativeSize);
    NativeTokenInfoBase findInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(tokenId, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.processName, infoInstance.processName);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(tokenId);
    ASSERT_EQ(ret, RET_SUCCESS);
}