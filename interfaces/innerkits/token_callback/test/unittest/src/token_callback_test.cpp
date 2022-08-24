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

#include "token_callback_test.h"
#include "string_ex.h"
#include "token_callback_stub.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;

const static int32_t RET_NO_ERROR = 0;

void TokenCallbackTest::SetUpTestCase()
{
}

void TokenCallbackTest::TearDownTestCase()
{
}

void TokenCallbackTest::SetUp()
{
}

void TokenCallbackTest::TearDown()
{
}

class TestCallBack : public TokenCallbackStub {
public:
    TestCallBack() = default;
    virtual ~TestCallBack() = default;

    void GrantResultsCallback(
        const std::vector<std::string> &permissions, const std::vector<int> &grantResults)
    {
        GTEST_LOG_(INFO) << "GrantResultsCallback,  permissions.size:" << permissions.size() <<
            ", grantResults.size :" << grantResults.size();
    }
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: OnRemoteRequest empty.
 * @tc.type: FUNC
 * @tc.require: issueI5NU8U
 */
HWTEST_F(TokenCallbackTest, OnRemoteRequest001, TestSize.Level1)
{
    std::vector<std::string> permissions;
    std::vector<int32_t> grantResults;
    uint32_t listSize = permissions.size();
    uint32_t resultSize = grantResults.size();

    TestCallBack callback;
    MessageParcel data;
    ASSERT_EQ(true, data.WriteInterfaceToken(ITokenCallback::GetDescriptor()));

    ASSERT_EQ(true, data.WriteUint32(listSize));
    for (uint32_t i = 0; i < listSize; i++) {
        ASSERT_EQ(true, data.WriteString16(Str8ToStr16(permissions[i])));
    }

    ASSERT_EQ(true, data.WriteUint32(resultSize));
    for (uint32_t i = 0; i < resultSize; i++) {
        ASSERT_EQ(true, data.WriteInt32(grantResults[i]));
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(RET_NO_ERROR,
        callback.OnRemoteRequest(static_cast<uint32_t>(ITokenCallback::GRANT_RESULT_CALLBACK), data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: OnRemoteRequest not empty.
 * @tc.type: FUNC
 * @tc.require: issueI5NU8U
 */
HWTEST_F(TokenCallbackTest, OnRemoteRequest002, TestSize.Level1)
{
    std::vector<std::string> permissions;
    std::vector<int32_t> grantResults;
    permissions.emplace_back("ohos.permission.CAMERA");
    grantResults.emplace_back(0);
    uint32_t listSize = permissions.size();
    uint32_t resultSize = grantResults.size();

    TestCallBack callback;
    MessageParcel data;
    ASSERT_EQ(true, data.WriteInterfaceToken(ITokenCallback::GetDescriptor()));

    ASSERT_EQ(true, data.WriteUint32(listSize));
    for (uint32_t i = 0; i < listSize; i++) {
        ASSERT_EQ(true, data.WriteString16(Str8ToStr16(permissions[i])));
    }

    ASSERT_EQ(true, data.WriteUint32(resultSize));
    for (uint32_t i = 0; i < resultSize; i++) {
        ASSERT_EQ(true, data.WriteInt32(grantResults[i]));
    }

    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    ASSERT_EQ(RET_NO_ERROR,
        callback.OnRemoteRequest(static_cast<uint32_t>(ITokenCallback::GRANT_RESULT_CALLBACK), data, reply, option));
}
