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
#include "data_storage.h"
#include "field_const.h"
#define private public
#include "native_token_receptor.h"
#undef private
#include "securec.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "NativeTokenReceptorTest"};
}

void NativeTokenReceptorTest::SetUpTestCase()
{
    // delete all test 0x28100000 - 0x28100007
    for (unsigned int i = 0x28100000; i <= 0x28100007; i++) {
        AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(i);
    }
}

void NativeTokenReceptorTest::TearDownTestCase()
{}

void NativeTokenReceptorTest::SetUp()
{}

void NativeTokenReceptorTest::TearDown()
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test down!");
}

/**
 * @tc.name: Init001
 * @tc.desc: Verify socket init result.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, Init001, TestSize.Level1)
{
    NativeTokenReceptor::GetInstance().socketPath_ = "/data/system/token_unix_socket.test.socket";
    NativeTokenReceptor::GetInstance().Init();
    NativeTokenReceptor::GetInstance().receptorThread_->detach();
    ASSERT_LT(NativeTokenReceptor::GetInstance().listenSocket_, 0);
    sleep(3);
    char buffer[128] = {0};
    int ret = GetParameter(SYSTEM_PROP_NATIVE_RECEPTOR.c_str(), "false", buffer, 127);
    GTEST_LOG_(INFO) << "ret " << ret << " buffer " << buffer;
    ASSERT_EQ(ret, strlen("true"));
    ASSERT_EQ(strcmp(buffer, "true"), 0);
}

/**
 * @tc.name: ParserNativeRawData001
 * @tc.desc: Verify processing right native token json.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ParserNativeRawData001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ParserNativeRawData001!");
    std::string testStr = R"({"NativeTokenInfo":[)"\
        R"({"processName":"process6","APL":3,"version":1,"tokenId":685266937,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]},)"\
        R"({"processName":"process5","APL":3,"version":1,"tokenId":678065606,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]}]})";

    NativeTokenReceptor& receptor = NativeTokenReceptor::GetInstance();
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;
    receptor.ParserNativeRawData(testStr, tokenInfos);
    int size = tokenInfos.size();
    ASSERT_EQ(2, size);
    ASSERT_NE(nullptr, tokenInfos[0]);
    ASSERT_NE(nullptr, tokenInfos[1]);

    ASSERT_EQ("process6", tokenInfos[0]->GetProcessName());
    ASSERT_EQ(685266937, tokenInfos[0]->GetTokenID());
    ASSERT_EQ(2, tokenInfos[0]->GetDcap().size());
    ASSERT_EQ("AT_CAP", (tokenInfos[0]->GetDcap())[0]);
    ASSERT_EQ("ST_CAP", (tokenInfos[0]->GetDcap())[1]);

    ASSERT_EQ("process5", tokenInfos[1]->GetProcessName());
    ASSERT_EQ(678065606, tokenInfos[1]->GetTokenID());
    ASSERT_EQ(2, tokenInfos[1]->GetDcap().size());
    ASSERT_EQ("AT_CAP", (tokenInfos[1]->GetDcap())[0]);
    ASSERT_EQ("ST_CAP", (tokenInfos[1]->GetDcap())[1]);
}

/**
 * @tc.name: ParserNativeRawData002
 * @tc.desc: Verify processing wrong native token json.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ParserNativeRawData002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ParserNativeRawData002!");
    std::string testStr = R"({"NativeTokenInfo":[{"processName":""}]})";
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;

    NativeTokenReceptor& receptor = NativeTokenReceptor::GetInstance();

    receptor.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(0, tokenInfos.size());

    testStr = R"({"NativeTokenInfo":[{"processName":"", }]})";
    receptor.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(0, tokenInfos.size());

    testStr = R"({"NativeTokenInfo":[{"processName":"process6"}, {}]})";
    receptor.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(0, tokenInfos.size());

    testStr = R"({"NativeTokenInfo":[{"processName":""}, {"":"", ""}]})";
    receptor.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(0, tokenInfos.size());

    testStr = R"({"NativeTokenInfo":[{"processName":"process6", "tokenId":685266937, "APL":3, "version":new}]})";
    receptor.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(0, tokenInfos.size());

    testStr = R"({"NativeTokenInfo":[{"processName":"process6", "tokenId":685266937, "APL":7, "version":1}]})";
    receptor.ParserNativeRawData(testStr, tokenInfos);
    ASSERT_EQ(0, tokenInfos.size());
}

namespace OHOS {
namespace Security {
namespace AccessToken {
    extern void from_json(const nlohmann::json& j, std::shared_ptr<NativeTokenInfoInner>& p);
}
}
}

/**
 * @tc.name: from_json001
 * @tc.desc: Verify from json right case.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, from_json001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test from_json001!");
    nlohmann::json j = nlohmann::json{
        {"processName", "process6"},
        {"APL", APL_SYSTEM_CORE},
        {"version", 1},
        {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    std::shared_ptr<NativeTokenInfoInner> p;
    from_json(j, p);
    ASSERT_NE((p == nullptr), true);
}

/**
 * @tc.name: from_json002
 * @tc.desc: Verify from json wrong case.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, from_json002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test from_json002!");
    // version wrong
    nlohmann::json j = nlohmann::json{
        {"processName", "process6"}, {"APL", APL_SYSTEM_CORE},
        {"version", 2}, {"tokenId", 685266937},
        {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    std::shared_ptr<NativeTokenInfoInner> p;
    from_json(j, p);
    ASSERT_EQ((p == nullptr), true);

    // APL wrong
    j = nlohmann::json{
        {"processName", "process6"},
        {"APL", -1}, {"version", 1},
        {"tokenId", 685266937}, {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    from_json(j, p);
    ASSERT_EQ((p == nullptr), true);

    // tokenId wrong
    j = nlohmann::json{
        {"processName", "process6"},
        {"APL", APL_SYSTEM_BASIC}, {"version", 1},
        {"tokenId", 0}, {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    from_json(j, p);
    ASSERT_EQ((p == nullptr), true);

    // process name empty
    j = nlohmann::json{
        {"processName", ""},
        {"APL", APL_SYSTEM_BASIC}, {"version", 1},
        {"tokenId", 685266937}, {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    from_json(j, p);
    ASSERT_EQ((p == nullptr), true);

    // process name too long
    std::string name(512, 'c');
    j = nlohmann::json{
        {"processName", name},
        {"APL", APL_SYSTEM_BASIC}, {"version", 1},
        {"tokenId", 685266937}, {"tokenAttr", 0},
        {"dcaps", {"AT_CAP", "ST_CAP"}}};
    from_json(j, p);
    ASSERT_EQ((p == nullptr), true);

    // lose process name
    j = nlohmann::json{
        {"APL", APL_SYSTEM_BASIC},
        {"version", 1}, {"tokenId", 685266937},
        {"tokenAttr", 0}, {"dcaps", {"AT_CAP", "ST_CAP"}}};
    from_json(j, p);
    ASSERT_EQ((p == nullptr), true);
}

/**
 * @tc.name: ProcessNativeTokenInfos001
 * @tc.desc: test add one native token
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ProcessNativeTokenInfos001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ProcessNativeTokenInfos001!");
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;

    // test process one
    NativeTokenInfo info = {
        .apl = APL_NORMAL,
        .ver = 1,
        .processName = "native_token_test0",
        .tokenID = 0x28100000,
        .tokenAttr = 0,
        .dcap =  {"AT_CAP", "ST_CAP"}
    };
    std::shared_ptr<NativeTokenInfoInner> nativeToken = std::make_shared<NativeTokenInfoInner>(info);
    tokenInfos.emplace_back(nativeToken);
    AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);
    NativeTokenInfo findInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(info.tokenID, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, info.apl);
    ASSERT_EQ(findInfo.ver, info.ver);
    ASSERT_EQ(findInfo.processName, info.processName);
    ASSERT_EQ(findInfo.tokenID, info.tokenID);
    ASSERT_EQ(findInfo.tokenAttr, info.tokenAttr);
    ASSERT_EQ(findInfo.dcap, info.dcap);

    // wait fresh tokens to sql.
    sleep(3);

    // get sql data
    std::vector<GenericValues> nativeTokenResults;
    DataStorage::GetRealDataStorage().Find(DataStorage::ACCESSTOKEN_NATIVE_INFO, nativeTokenResults);
    for (GenericValues nativeTokenValue : nativeTokenResults) {
        AccessTokenID tokenId = (AccessTokenID)nativeTokenValue.GetInt(FIELD_TOKEN_ID);
        if (tokenId != info.tokenID) {
            continue;
        }
        GTEST_LOG_(INFO) <<"apl " << nativeTokenValue.GetInt(FIELD_APL);
        std::shared_ptr<NativeTokenInfoInner> native = std::make_shared<NativeTokenInfoInner>();
        ASSERT_NE(native, nullptr);
        ret = native->RestoreNativeTokenInfo(tokenId, nativeTokenValue);
        ASSERT_EQ(ret, RET_SUCCESS);
        ASSERT_EQ(native->GetTokenID(), info.tokenID);
        ASSERT_EQ(native->GetProcessName(), info.processName);
        ASSERT_EQ(native->GetDcap(), info.dcap);
    }

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(info.tokenID);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: ProcessNativeTokenInfos002
 * @tc.desc: test add two native tokens.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ProcessNativeTokenInfos002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ProcessNativeTokenInfos002!");
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;

    NativeTokenInfo info1 = {
        .apl = APL_NORMAL,
        .ver = 1,
        .processName = "native_token_test1",
        .tokenID = 0x28100001,
        .tokenAttr = 0,
        .dcap =  {"AT_CAP", "ST_CAP"}
    };

    NativeTokenInfo info2 = {
        .apl = APL_NORMAL,
        .ver = 1,
        .processName = "native_token_test2",
        .tokenID = 0x28100002,
        .tokenAttr = 0,
        .dcap =  {"AT_CAP", "ST_CAP"}
    };

    std::shared_ptr<NativeTokenInfoInner> nativeToken1 = std::make_shared<NativeTokenInfoInner>(info1);
    tokenInfos.emplace_back(nativeToken1);

    std::shared_ptr<NativeTokenInfoInner> nativeToken2 = std::make_shared<NativeTokenInfoInner>(info2);
    tokenInfos.emplace_back(nativeToken2);

    AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);
    NativeTokenInfo findInfo;

    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(info1.tokenID, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, info1.apl);
    ASSERT_EQ(findInfo.ver, info1.ver);
    ASSERT_EQ(findInfo.processName, info1.processName);
    ASSERT_EQ(findInfo.tokenID, info1.tokenID);
    ASSERT_EQ(findInfo.tokenAttr, info1.tokenAttr);
    ASSERT_EQ(findInfo.dcap, info1.dcap);

    ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(info2.tokenID, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, info2.apl);
    ASSERT_EQ(findInfo.ver, info2.ver);
    ASSERT_EQ(findInfo.processName, info2.processName);
    ASSERT_EQ(findInfo.tokenID, info2.tokenID);
    ASSERT_EQ(findInfo.tokenAttr, info2.tokenAttr);
    ASSERT_EQ(findInfo.dcap, info2.dcap);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(info1.tokenID);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(info2.tokenID);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: ProcessNativeTokenInfos003
 * @tc.desc: test add nullptr tokenInfo.
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ProcessNativeTokenInfos003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ProcessNativeTokenInfos003!");
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;

    std::shared_ptr<NativeTokenInfoInner> nativeToken1 = std::make_shared<NativeTokenInfoInner>();
    tokenInfos.emplace_back(nativeToken1);
    AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);
    ASSERT_EQ(RET_SUCCESS, RET_SUCCESS);
}

/**
 * @tc.name: ProcessNativeTokenInfos004
 * @tc.desc: test add repeat id, but process doesnt
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ProcessNativeTokenInfos004, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ProcessNativeTokenInfos004!");
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;

    NativeTokenInfo info3 = {
        .apl = APL_NORMAL,
        .ver = 1,
        .processName = "native_token_test3",
        .tokenID = 0x28100003,
        .tokenAttr = 0,
        .dcap =  {"AT_CAP", "ST_CAP"}
    };

    NativeTokenInfo info4 = {
        .apl = APL_NORMAL,
        .ver = 1,
        .processName = "native_token_test4",
        .tokenID = 0x28100003,
        .tokenAttr = 0,
        .dcap =  {"AT_CAP", "ST_CAP"}
    };

    std::shared_ptr<NativeTokenInfoInner> nativeToken3 = std::make_shared<NativeTokenInfoInner>(info3);
    tokenInfos.emplace_back(nativeToken3);

    std::shared_ptr<NativeTokenInfoInner> nativeToken4 = std::make_shared<NativeTokenInfoInner>(info4);
    tokenInfos.emplace_back(nativeToken4);

    AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);

    NativeTokenInfo findInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(info3.tokenID, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, info3.apl);
    ASSERT_EQ(findInfo.ver, info3.ver);
    ASSERT_EQ(findInfo.processName, info3.processName);
    ASSERT_EQ(findInfo.tokenID, info3.tokenID);
    ASSERT_EQ(findInfo.tokenAttr, info3.tokenAttr);
    ASSERT_EQ(findInfo.dcap, info3.dcap);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(info3.tokenID);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: ProcessNativeTokenInfos005
 * @tc.desc: test add repeat process, but id doesnt
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ProcessNativeTokenInfos005, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ProcessNativeTokenInfos005!");
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;

    NativeTokenInfo info5 = {
        .apl = APL_NORMAL,
        .ver = 1,
        .processName = "native_token_test5",
        .tokenID = 0x28100005,
        .tokenAttr = 0,
        .dcap =  {"AT_CAP", "ST_CAP"}
    };

    NativeTokenInfo info6 = {
        .apl = APL_NORMAL,
        .ver = 1,
        .processName = "native_token_test5",
        .tokenID = 0x28100006,
        .tokenAttr = 0,
        .dcap =  {"AT_CAP", "ST_CAP"}
    };

    std::shared_ptr<NativeTokenInfoInner> nativeToken5 = std::make_shared<NativeTokenInfoInner>(info5);
    tokenInfos.emplace_back(nativeToken5);

    std::shared_ptr<NativeTokenInfoInner> nativeToken6 = std::make_shared<NativeTokenInfoInner>(info6);
    tokenInfos.emplace_back(nativeToken6);

    AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);

    NativeTokenInfo findInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(info5.tokenID, findInfo);
    ASSERT_EQ(ret, RET_FAILED);

    ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(info6.tokenID, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, info6.apl);
    ASSERT_EQ(findInfo.ver, info6.ver);
    ASSERT_EQ(findInfo.processName, info6.processName);
    ASSERT_EQ(findInfo.tokenID, info6.tokenID);
    ASSERT_EQ(findInfo.tokenAttr, info6.tokenAttr);
    ASSERT_EQ(findInfo.dcap, info6.dcap);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(info6.tokenID);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: ProcessNativeTokenInfos006
 * @tc.desc: test add repeat process and id
 * @tc.type: FUNC
 * @tc.require: Issue Number
 */
HWTEST_F(NativeTokenReceptorTest, ProcessNativeTokenInfos006, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ProcessNativeTokenInfos006!");
    std::vector<std::shared_ptr<NativeTokenInfoInner>> tokenInfos;

    NativeTokenInfo info7 = {
        .apl = APL_NORMAL,
        .ver = 1,
        .processName = "native_token_test7",
        .tokenID = 0x28100007,
        .tokenAttr = 0,
        .dcap =  {"AT_CAP", "ST_CAP"}
    };

    NativeTokenInfo info8 = {
        .apl = APL_SYSTEM_BASIC,
        .ver = 1,
        .processName = "native_token_test7",
        .tokenID = 0x28100007,
        .tokenAttr = 0,
        .dcap =  {"AT_CAP"}
    };

    std::shared_ptr<NativeTokenInfoInner> nativeToken7 = std::make_shared<NativeTokenInfoInner>(info7);
    tokenInfos.emplace_back(nativeToken7);

    std::shared_ptr<NativeTokenInfoInner> nativeToken8 = std::make_shared<NativeTokenInfoInner>(info8);
    tokenInfos.emplace_back(nativeToken8);

    AccessTokenInfoManager::GetInstance().ProcessNativeTokenInfos(tokenInfos);

    NativeTokenInfo findInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(info7.tokenID, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, info8.apl);
    ASSERT_EQ(findInfo.ver, info8.ver);
    ASSERT_EQ(findInfo.processName, info8.processName);
    ASSERT_EQ(findInfo.tokenID, info8.tokenID);
    ASSERT_EQ(findInfo.tokenAttr, info8.tokenAttr);
    ASSERT_EQ(findInfo.dcap, info8.dcap);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(info8.tokenID);
    ASSERT_EQ(ret, RET_SUCCESS);
}

static int initClientSocket()
{
    struct sockaddr_un addr;
    int fd = -1;

    /* set socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    (void)memset_s(&addr, sizeof(struct sockaddr_un), 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    if (strncpy_s(addr.sun_path, sizeof(addr.sun_path),
        "/data/system/token_unix_socket.test.socket", sizeof(addr.sun_path) - 1) != EOK) {
        close(fd);
        return -1;
    }
    int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

void LibatConcurrencyTask(const char* syncMesg)
{
    int fd = initClientSocket();
    if (fd <= 0) {
        GTEST_LOG_(INFO) << "initClientSocket failed";
        return;
    }
    int writtenSize;
    int len = strlen(syncMesg);

    writtenSize = write(fd, syncMesg, len);
    ASSERT_EQ(writtenSize, len);
    if (writtenSize != len) {
        GTEST_LOG_(INFO) << "send mesg failed";
    }
    close(fd);
}

/**
 * @tc.name: ClientConnect001
 * @tc.desc: client connect and send a nativetoken, and close
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeTokenReceptorTest, ClientConnect001, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ClientConnect001!");
    // 672137216 = 0x28100000
    std::string testStr = R"({"NativeTokenInfo":[)"\
        R"({"processName":"process6","APL":3,"version":1,"tokenId":672137216,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]}]})";

    LibatConcurrencyTask(testStr.c_str());
    sleep(5);

    NativeTokenInfo findInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(672137216, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, 3);
    ASSERT_EQ(findInfo.ver, 1);
    ASSERT_EQ(findInfo.processName, "process6");
    ASSERT_EQ(findInfo.tokenID, 672137216);
    ASSERT_EQ(findInfo.tokenAttr, 0);
    std::vector<std::string> dcap = {"AT_CAP", "ST_CAP"};
    ASSERT_EQ(findInfo.dcap, dcap);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(672137216);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: ClientConnect002
 * @tc.desc: client connect and send two nativetokens at same time by two threads
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeTokenReceptorTest, ClientConnect002, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ClientConnect002!");
    std::string testStr1 = R"({"NativeTokenInfo":[)"\
        R"({"processName":"process6","APL":3,"version":1,"tokenId":672137216,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]}]})";

    std::string testStr2 = R"({"NativeTokenInfo":[)"\
        R"({"processName":"process7","APL":3,"version":1,"tokenId":672137217,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]}]})";

    std::thread threadClient1(LibatConcurrencyTask, testStr1.c_str());

    std::thread threadClient2(LibatConcurrencyTask, testStr2.c_str());
    threadClient1.join();
    threadClient2.join();

    sleep(5);

    NativeTokenInfo findInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(672137216, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, 3);
    ASSERT_EQ(findInfo.ver, 1);
    ASSERT_EQ(findInfo.processName, "process6");
    ASSERT_EQ(findInfo.tokenID, 672137216);
    ASSERT_EQ(findInfo.tokenAttr, 0);
    std::vector<std::string> dcap = {"AT_CAP", "ST_CAP"};
    ASSERT_EQ(findInfo.dcap, dcap);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(672137216);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(672137217, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, 3);
    ASSERT_EQ(findInfo.ver, 1);
    ASSERT_EQ(findInfo.processName, "process7");
    ASSERT_EQ(findInfo.tokenID, 672137217);
    ASSERT_EQ(findInfo.tokenAttr, 0);
    ASSERT_EQ(findInfo.dcap, dcap);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(672137217);
    ASSERT_EQ(ret, RET_SUCCESS);
}

/**
 * @tc.name: ClientConnect003
 * @tc.desc: client connect and send two nativetokens at one time
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(NativeTokenReceptorTest, ClientConnect003, TestSize.Level1)
{
    ACCESSTOKEN_LOG_INFO(LABEL, "test ClientConnect003!");
    std::string testStr = R"({"NativeTokenInfo":[)"\
        R"({"processName":"process6","APL":3,"version":1,"tokenId":672137216,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]},)"\
        R"({"processName":"process7","APL":3,"version":1,"tokenId":672137217,"tokenAttr":0,)"\
        R"("dcaps":["AT_CAP","ST_CAP"]}]})";

    LibatConcurrencyTask(testStr.c_str());

    sleep(5);

    NativeTokenInfo findInfo;
    int ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(672137216, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, 3);
    ASSERT_EQ(findInfo.ver, 1);
    ASSERT_EQ(findInfo.processName, "process6");
    ASSERT_EQ(findInfo.tokenID, 672137216);
    ASSERT_EQ(findInfo.tokenAttr, 0);
    std::vector<std::string> dcap = {"AT_CAP", "ST_CAP"};
    ASSERT_EQ(findInfo.dcap, dcap);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(672137216);
    ASSERT_EQ(ret, RET_SUCCESS);

    ret = AccessTokenInfoManager::GetInstance().GetNativeTokenInfo(672137217, findInfo);
    ASSERT_EQ(ret, RET_SUCCESS);
    ASSERT_EQ(findInfo.apl, 3);
    ASSERT_EQ(findInfo.ver, 1);
    ASSERT_EQ(findInfo.processName, "process7");
    ASSERT_EQ(findInfo.tokenID, 672137217);
    ASSERT_EQ(findInfo.tokenAttr, 0);
    ASSERT_EQ(findInfo.dcap, dcap);

    ret = AccessTokenInfoManager::GetInstance().RemoveNativeTokenInfo(672137217);
    ASSERT_EQ(ret, RET_SUCCESS);
}
