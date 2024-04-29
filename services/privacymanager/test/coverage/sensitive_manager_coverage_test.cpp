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

#include "accesstoken_kit.h"
#include "app_manager_access_client.h"
#include "app_manager_access_proxy.h"
#include "app_state_data.h"
#define private public
#include "audio_manager_privacy_client.h"
#undef private
#include "audio_manager_privacy_proxy.h"
#define private public
#include "camera_manager_privacy_client.h"
#undef private
#include "camera_manager_privacy_proxy.h"
#include "camera_service_callback_stub.h"
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

class TestCallBack2 : public ApplicationStateObserverStub {
public:
    TestCallBack2() = default;
    virtual ~TestCallBack2() = default;

    void OnForegroundApplicationChanged(const AppStateData &appStateData)
    {
        GTEST_LOG_(INFO) << "OnForegroundApplicationChanged, state is "
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
    TestCallBack2 callback;

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(IApplicationStateObserver::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&appData));
    uint32_t code = 10;
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
    TestCallBack2 callback;

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    appData.state = static_cast<int32_t>(ApplicationState::APP_STATE_FOREGROUND);
    ASSERT_EQ(true, data.WriteInterfaceToken(IApplicationStateObserver::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&appData));
    // code not default + state = 3
    ASSERT_EQ(0, callback.OnRemoteRequest(static_cast<uint32_t>(
        IApplicationStateObserver::Message::TRANSACT_ON_FOREGROUND_APPLICATION_CHANGED), data, reply, option));
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
    TestCallBack2 callback;

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    appData.state = static_cast<int32_t>(ApplicationState::APP_STATE_BACKGROUND);
    ASSERT_EQ(true, data.WriteInterfaceToken(IApplicationStateObserver::GetDescriptor()));
    ASSERT_EQ(true, data.WriteParcelable(&appData));
    // code not default + state = 5
    ASSERT_EQ(0, callback.OnRemoteRequest(static_cast<uint32_t>(
        IApplicationStateObserver::Message::TRANSACT_ON_FOREGROUND_APPLICATION_CHANGED), data, reply, option));
}

class TestCallBack3 : public CameraServiceCallbackStub {
public:
    TestCallBack3() = default;
    virtual ~TestCallBack3() = default;

    int32_t OnCameraMute(bool muteMode)
    {
        GTEST_LOG_(INFO) << "OnCameraMute, muteMode is " << muteMode;
        return 0;
    }
};

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: CameraServiceCallbackStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveManagerCoverageTest, OnRemoteRequest004, TestSize.Level1)
{
    bool muteMode = false;
    TestCallBack3 callback;

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(ICameraMuteServiceCallback::GetDescriptor()));
    ASSERT_EQ(true, data.WriteBool(muteMode));
    uint32_t code = 10;
    ASSERT_NE(0, callback.OnRemoteRequest(code, data, reply, option)); // msgCode default
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: CameraServiceCallbackStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveManagerCoverageTest, OnRemoteRequest005, TestSize.Level1)
{
    bool muteMode = false;
    TestCallBack3 callback;

    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(ICameraMuteServiceCallback::GetDescriptor()));
    ASSERT_EQ(true, data.WriteBool(muteMode));
    // msgId = 0
    ASSERT_EQ(0, callback.OnRemoteRequest(static_cast<uint32_t>(
        PrivacyCameraMuteServiceInterfaceCode::CAMERA_CALLBACK_MUTE_MODE), data, reply, option));
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
