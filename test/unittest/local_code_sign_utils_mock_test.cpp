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

#include <cstdlib>
#include <gtest/gtest.h>
#include <string>
#include <parameters.h>

#include "cert_utils.h"
#include "directory_ex.h"
#include "fsverity_utils_helper.h"
#include "local_sign_key.h"
#include "log.h"
#include "pkcs7_generator.h"
#include "hks_api.h"
#include "byte_buffer.h"
#include "cert_path.h"


using namespace OHOS::Security::CodeSign;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace Security {
namespace CodeSign {
static const std::string AN_BASE_PATH = "/data/local/ark-cache/tmp/";
static const std::string DEMO_AN_PATH2 = AN_BASE_PATH + "demo2.an";
static const std::string DEFAULT_HASH_ALGORITHM = "sha256";

class LocalCodeSignUtilsMockTest : public testing::Test {
public:
    LocalCodeSignUtilsMockTest() {};
    virtual ~LocalCodeSignUtilsMockTest() {};
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: LocalCodeSignUtilsMockTest_0001
 * @tc.desc: Sign local code successfully, owner ID is empty, and set g_count.
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsMockTest, LocalCodeSignUtilsMockTest_0001, TestSize.Level0)
{
    ByteBuffer digest;
    std::string realPath;
    std::string ownerID = "";
    bool bRet = OHOS::PathToRealPath(DEMO_AN_PATH2, realPath);
    EXPECT_EQ(bRet, true);
    bRet = FsverityUtilsHelper::GetInstance().GenerateFormattedDigest(realPath.c_str(), digest);
    EXPECT_EQ(bRet, true);

    ByteBuffer signature;
    g_count = ATTESTKEY;
    int ret = PKCS7Generator::GenerateSignature(ownerID, LocalSignKey::GetInstance(), DEFAULT_HASH_ALGORITHM.c_str(),
        digest, signature);
    EXPECT_EQ(ret, CS_ERR_HUKS_OBTAIN_CERT);

    g_count = INIT;
    ret = PKCS7Generator::GenerateSignature(ownerID, LocalSignKey::GetInstance(), DEFAULT_HASH_ALGORITHM.c_str(),
        digest, signature);
    EXPECT_EQ(ret, CS_ERR_HUKS_SIGN);

    g_count = UPDATE;
    ret = PKCS7Generator::GenerateSignature(ownerID, LocalSignKey::GetInstance(), DEFAULT_HASH_ALGORITHM.c_str(),
        digest, signature);
    EXPECT_EQ(ret, CS_ERR_HUKS_SIGN);

    g_count = FINISH;
    ret = PKCS7Generator::GenerateSignature(ownerID, LocalSignKey::GetInstance(), DEFAULT_HASH_ALGORITHM.c_str(),
        digest, signature);
    EXPECT_EQ(ret, CS_ERR_HUKS_SIGN);
}

/**
 * @tc.name: LocalCodeSignUtilsMockTest_0002
 * @tc.desc: Generate formatted digest failed with wrong path
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsMockTest, LocalCodeSignUtilsMockTest_0002, TestSize.Level0)
{
    std::unique_ptr<ByteBuffer> challenge = GetRandomChallenge();
    LocalSignKey &key = LocalSignKey::GetInstance();
    key.SetChallenge(*challenge);
    bool bRet = key.InitKey();
    EXPECT_EQ(bRet, true);

    g_count = ERROR;
    bRet = key.InitKey();
    EXPECT_EQ(bRet, false);

    g_count = KEYEXIST;
    bRet = key.InitKey();
    EXPECT_EQ(bRet, false);

    int32_t iRet = key.GetFormattedCertChain(*challenge);
    EXPECT_EQ(iRet, 0);
}

/**
 * @tc.name: LocalCodeSignUtilsMockTest_0003
 * @tc.desc: LocalSignKey GetSignCert test
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsMockTest, LocalCodeSignUtilsMockTest_0003, TestSize.Level0)
{
    LocalSignKey &key = LocalSignKey::GetInstance();
    EXPECT_NE(key.GetSignCert(), nullptr);
}

/**
 * @tc.name: LocalCodeSignUtilsMockTest_0004
 * @tc.desc: cert_utils FreeCertChain certChain is nullptr or certChain->certs is nullptr
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsMockTest, LocalCodeSignUtilsMockTest_0004, TestSize.Level0)
{
    struct HksCertChain *certChain = nullptr;
    uint32_t pos = 0;
    (void)OHOS::Security::CodeSign::FreeCertChain(&certChain, pos);

    certChain = static_cast<struct HksCertChain *>(malloc(sizeof(struct HksCertChain)));
    EXPECT_NE(certChain, nullptr);
    certChain->certs = nullptr;
    (void)OHOS::Security::CodeSign::FreeCertChain(&certChain, pos);
}

/**
 * @tc.name: LocalCodeSignUtilsMockTest_0005
 * @tc.desc: cert_utils CheckChallengeSize func test
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsMockTest, LocalCodeSignUtilsMockTest_0005, TestSize.Level0)
{
    uint32_t size = 0;
    bool bRet = OHOS::Security::CodeSign::CheckChallengeSize(size);
    EXPECT_EQ(bRet, true);

    size = 33;
    bRet = OHOS::Security::CodeSign::CheckChallengeSize(size);
    EXPECT_EQ(bRet, false);
}

/**
 * @tc.name: LocalCodeSignUtilsMockTest_0006
 * @tc.desc: cert_utils FormattedCertChain func test
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsMockTest, LocalCodeSignUtilsMockTest_0006, TestSize.Level0)
{
    const HksCertChain *certChain = LocalSignKey::GetInstance().GetCertChain();
    std::unique_ptr<ByteBuffer> buffer = GetRandomChallenge();
    bool bRet = OHOS::Security::CodeSign::FormattedCertChain(certChain, *buffer);
    EXPECT_EQ(bRet, true);
}

/**
 * @tc.name: LocalCodeSignUtilsMockTest_0007
 * @tc.desc: cert_utils GetCertChainFormBuffer func test
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsMockTest, LocalCodeSignUtilsMockTest_0007, TestSize.Level0)
{
    ByteBuffer certChainBuffer;
    ByteBuffer signCert;
    ByteBuffer issuer;
    std::vector<ByteBuffer> chain;
    bool bRet = OHOS::Security::CodeSign::GetCertChainFormBuffer(certChainBuffer, signCert, issuer, chain);
    EXPECT_EQ(bRet, false);
}

/**
 * @tc.name: LocalCodeSignUtilsMockTest_0009
 * @tc.desc: cert_path IsDeveloperModeOn and GetCertChainFormBuffer func test
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsMockTest, LocalCodeSignUtilsMockTest_0009, TestSize.Level0)
{
    (void)FsverityUtilsHelper::GetInstance().ErrorMsgLogCallback(nullptr);

    if (OHOS::system::GetBoolParameter("const.security.developermode.state", false)) {
        EXPECT_EQ(IsDeveloperModeOn(), true);
    } else {
        EXPECT_EQ(IsDeveloperModeOn(), false);
    }
}

/**
 * @tc.name: LocalCodeSignUtilsMockTest_0010
 * @tc.desc: cert_path CodeSignGetUdid func test
 * @tc.type: Func
 * @tc.require: issueI8FCGF
 */
HWTEST_F(LocalCodeSignUtilsMockTest, LocalCodeSignUtilsMockTest_0010, TestSize.Level0)
{
    EXPECT_EQ(CodeSignGetUdid(nullptr), -1);
}
} // namespace CodeSign
} // namespace Security
} // namespace OHOS
