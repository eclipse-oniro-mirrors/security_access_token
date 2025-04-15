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

#include <gtest/gtest.h>
#define private public
#include "proxy_death_handler.h"
#include "privacy_manager_proxy_death_param.h"
#include "proxy_death_callback_stub.h"
#undef private
#include "constant.h"
#include "permission_record_set.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {

class PrivacyManagerProxyDeathTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PrivacyManagerProxyDeathTest::SetUpTestCase()
{
}

void PrivacyManagerProxyDeathTest::TearDownTestCase()
{
}

void PrivacyManagerProxyDeathTest::SetUp()
{
}

void PrivacyManagerProxyDeathTest::TearDown()
{
}

/**
 * @tc.name: PrivacyManagerProxyDeathTest001
 * @tc.desc: AddProxyStub test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerProxyDeathTest, PrivacyManagerProxyDeathTest001, TestSize.Level1)
{
    auto handler = std::make_shared<ProxyDeathHandler>();
    auto anonyStub = new (std::nothrow) ProxyDeathCallBackStub();
    int32_t callerPid = 456; // 456 is random input
    std::shared_ptr<ProxyDeathParam> param = std::make_shared<PrivacyManagerProxyDeathParam>(callerPid);
    handler->AddProxyStub(anonyStub->AsObject(), param);
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 1);
    handler->AddProxyStub(anonyStub->AsObject(), param);
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 1); // has inserted

    auto anonyStub2 = new (std::nothrow) ProxyDeathCallBackStub();
    std::shared_ptr<ProxyDeathParam> param2 = std::make_shared<PrivacyManagerProxyDeathParam>(callerPid);
    handler->AddProxyStub(anonyStub2->AsObject(), param2);
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 2);
}

/**
 * @tc.name: PrivacyManagerProxyDeathTest001
 * @tc.desc: ReleaseProxyByParam test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerProxyDeathTest, PrivacyManagerProxyDeathTest002, TestSize.Level1)
{
    auto handler = std::make_shared<ProxyDeathHandler>();
    auto anonyStub = new (std::nothrow) ProxyDeathCallBackStub();
    int32_t callerPid = 456; // 456 is random input
    std::shared_ptr<ProxyDeathParam> param = std::make_shared<PrivacyManagerProxyDeathParam>(callerPid);
    handler->AddProxyStub(anonyStub->AsObject(), param);
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 1);

    auto anonyStub2 = new (std::nothrow) ProxyDeathCallBackStub();
    std::shared_ptr<ProxyDeathParam> param2 = std::make_shared<PrivacyManagerProxyDeathParam>(callerPid);
    handler->AddProxyStub(anonyStub2->AsObject(), param2);
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 2);

    handler->ReleaseProxyByParam(param);
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 0);
}

class TestProxyDeathParam : public ProxyDeathParam {
public:
    void ProcessParam() override
    {
        status = true;
    }
    bool IsEqual(ProxyDeathParam *) override
    {
        return status;
    }
    bool status = false;
};

/**
 * @tc.name: PrivacyManagerProxyDeathTest003
 * @tc.desc: HandleRemoteDied test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerProxyDeathTest, PrivacyManagerProxyDeathTest003, TestSize.Level1)
{
    auto handler = std::make_shared<ProxyDeathHandler>();
    auto anonyStub = new (std::nothrow) ProxyDeathCallBackStub();
    std::shared_ptr<ProxyDeathParam> param = std::make_shared<TestProxyDeathParam>();
    handler->AddProxyStub(anonyStub->AsObject(), param);
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 1);

    handler->HandleRemoteDied(anonyStub->AsObject());
    EXPECT_TRUE(param->IsEqual(nullptr));
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 0);
}

/**
 * @tc.name: PrivacyManagerProxyDeathTest004
 * @tc.desc: HandleRemoteDied test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PrivacyManagerProxyDeathTest, PrivacyManagerProxyDeathTest004, TestSize.Level1)
{
    auto handler = std::make_shared<ProxyDeathHandler>();
    auto anonyStub = new (std::nothrow) ProxyDeathCallBackStub();
    std::shared_ptr<ProxyDeathParam> param = std::make_shared<TestProxyDeathParam>();
    handler->AddProxyStub(anonyStub->AsObject(), param);
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 1);

    auto anonyStub2 = new (std::nothrow) ProxyDeathCallBackStub();
    std::shared_ptr<ProxyDeathParam> param2 = std::make_shared<TestProxyDeathParam>();

    handler->HandleRemoteDied(anonyStub2->AsObject());
    EXPECT_FALSE(param->IsEqual(nullptr));
    EXPECT_EQ(handler->proxyStubAndRecipientMap_.size(), 1);
}
}
}
}