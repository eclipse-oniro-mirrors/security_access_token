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

#include "access_token.h"
#include "accesstoken_kit.h"
#include "app_manager_access_client.h"
#include "app_manager_access_proxy.h"
#include "app_state_data.h"
#define private public
#include "audio_manager_privacy_client.h"
#include "camera_manager_privacy_client.h"
#undef private
#include "audio_manager_privacy_proxy.h"
#include "camera_manager_privacy_proxy.h"
#include "token_setproc.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class SensitiveManagerCoverageTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
void SensitiveManagerCoverageTest::SetUpTestCase()
{
}

void SensitiveManagerCoverageTest::TearDownTestCase()
{
}

void SensitiveManagerCoverageTest::SetUp()
{
}

void SensitiveManagerCoverageTest::TearDown()
{
}

class SensitiveManagerCoverageTestCb1 : public ApplicationStateObserverStub {
public:
    SensitiveManagerCoverageTestCb1() = default;
    virtual ~SensitiveManagerCoverageTestCb1() = default;

    void OnAppStateChanged(const AppStateData &appStateData)
    {
        GTEST_LOG_(INFO) << "OnAppStateChanged, state is "
            << appStateData.state;
    }
};

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: ApplicationStateObserverStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveManagerCoverageTest, OnRemoteRequest001, TestSize.Level1)
{
    AppStateData appData;
    SensitiveManagerCoverageTestCb1 callback;

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IApplicationStateObserver::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&appData));
    uint32_t code = -1;
    ASSERT_NE(0, callback.OnRemoteRequest(code, data, reply, option)); // code default
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: ApplicationStateObserverStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveManagerCoverageTest, OnRemoteRequest002, TestSize.Level1)
{
    AppStateData appData;
    SensitiveManagerCoverageTestCb1 callback;

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    appData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    ASSERT_EQ(true, data.WriteInterfaceToken(IApplicationStateObserver::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&appData));
    // code not default + state = 3
    ASSERT_EQ(0, callback.OnRemoteRequest(static_cast<uint32_t>(
        IApplicationStateObserver::Message::TRANSACT_ON_APP_STATE_CHANGED), data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: ApplicationStateObserverStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveManagerCoverageTest, OnRemoteRequest003, TestSize.Level1)
{
    AppStateData appData;
    SensitiveManagerCoverageTestCb1 callback;

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    appData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    ASSERT_EQ(true, data.WriteInterfaceToken(IApplicationStateObserver::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&appData));
    // code not default + state = 5
    ASSERT_EQ(0, callback.OnRemoteRequest(static_cast<uint32_t>(
        IApplicationStateObserver::Message::TRANSACT_ON_APP_STATE_CHANGED), data, reply, option));
}

/*
 * @tc.name: AudioRemoteDiedHandle001
 * @tc.desc: test audio remote die
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(SensitiveManagerCoverageTest, AudioRemoteDiedHandle001, TestSize.Level1)
{
    AudioManagerPrivacyClient::GetInstance().OnRemoteDiedHandle();
    EXPECT_EQ(AudioManagerPrivacyClient::GetInstance().proxy_, nullptr);
}

/*
 * @tc.name: CameraRemoteDiedHandle001
 * @tc.desc: test camera remote die
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(SensitiveManagerCoverageTest, CameraRemoteDiedHandle001, TestSize.Level1)
{
    CameraManagerPrivacyClient::GetInstance().OnRemoteDiedHandle();
    EXPECT_EQ(CameraManagerPrivacyClient::GetInstance().proxy_, nullptr);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
