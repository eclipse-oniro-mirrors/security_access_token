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

#include <cstdint>
#include <gtest/gtest.h>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#define private public
#include "accesstoken_info_manager.h"
#include "permission_definition_cache.h"
#include "form_manager_access_client.h"
#undef private
#include "accesstoken_callback_stubs.h"
#include "callback_death_recipients.h"
#include "running_form_info.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string FORM_VISIBLE_NAME = "#1";
}
class PermissionRecordManagerCoverageTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void PermissionRecordManagerCoverageTest::SetUpTestCase() {}

void PermissionRecordManagerCoverageTest::TearDownTestCase() {}

void PermissionRecordManagerCoverageTest::SetUp() {}

void PermissionRecordManagerCoverageTest::TearDown() {}

/*
 * @tc.name: RegisterAddObserverTest001
 * @tc.desc: regist form observer
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerCoverageTest, RegisterAddObserverTest001, TestSize.Level1)
{
    AccessTokenID selfTokenId = GetSelfTokenID();
    AccessTokenID nativeToken = AccessTokenKit::GetNativeTokenId("privacy_service");
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(nativeToken));
    sptr<FormStateObserverStub> formStateObserver = new (std::nothrow) FormStateObserverStub();
    ASSERT_NE(formStateObserver, nullptr);
    ASSERT_EQ(RET_SUCCESS,
        FormManagerAccessClient::GetInstance().RegisterAddObserver(FORM_VISIBLE_NAME, formStateObserver));
    ASSERT_EQ(RET_FAILED,
        FormManagerAccessClient::GetInstance().RegisterAddObserver(FORM_VISIBLE_NAME, nullptr));

    ASSERT_EQ(RET_FAILED,
        FormManagerAccessClient::GetInstance().RegisterRemoveObserver(FORM_VISIBLE_NAME, nullptr));
    ASSERT_EQ(RET_SUCCESS,
        FormManagerAccessClient::GetInstance().RegisterRemoveObserver(FORM_VISIBLE_NAME, formStateObserver));
    EXPECT_EQ(RET_SUCCESS, SetSelfTokenID(selfTokenId));
}

/*
 * @tc.name: FormMgrDiedHandle001
 * @tc.desc: test form manager remote die
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(PermissionRecordManagerCoverageTest, FormMgrDiedHandle001, TestSize.Level1)
{
    FormManagerAccessClient::GetInstance().OnRemoteDiedHandle();
    ASSERT_EQ(nullptr, FormManagerAccessClient::GetInstance().proxy_);
    ASSERT_EQ(nullptr, FormManagerAccessClient::GetInstance().serviceDeathObserver_);
}

class PermissionRecordManagerCoverTestCb1 : public FormStateObserverStub {
public:
    PermissionRecordManagerCoverTestCb1()
    {}

    ~PermissionRecordManagerCoverTestCb1()
    {}

    virtual int32_t NotifyWhetherFormsVisible(const FormVisibilityType visibleType,
        const std::string &bundleName, std::vector<FormInstance> &formInstances) override
    {
        return 0;
    }
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: FormStateObserverStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordManagerCoverageTest, OnRemoteRequest001, TestSize.Level1)
{
    PermissionRecordManagerCoverTestCb1 callback;

    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    OHOS::MessageParcel data1;
    ASSERT_EQ(true, data1.WriteInterfaceToken(IJsFormStateObserver::GetDescriptor()));
    EXPECT_EQ(RET_SUCCESS, callback.OnRemoteRequest(static_cast<uint32_t>(
        IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE), data1, reply, option));

    MessageParcel data2;
    data2.WriteInterfaceToken(IJsFormStateObserver::GetDescriptor());
    ASSERT_EQ(true, data2.WriteString(FORM_VISIBLE_NAME));
    std::vector<FormInstance> formInstances;
    FormInstance formInstance;
    formInstances.emplace_back(formInstance);
    ASSERT_EQ(true, data2.WriteInt32(formInstances.size()));
    for (auto &parcelable: formInstances) {
        ASSERT_EQ(true, data2.WriteParcelable(&parcelable));
    }
    EXPECT_EQ(RET_SUCCESS, callback.OnRemoteRequest(static_cast<uint32_t>(
        IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE), data2, reply, option));

    uint32_t code = -1;
    EXPECT_NE(RET_SUCCESS, callback.OnRemoteRequest(code, data2, reply, option));
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
