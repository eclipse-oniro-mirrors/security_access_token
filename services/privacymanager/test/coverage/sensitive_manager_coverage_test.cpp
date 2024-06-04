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
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "background_task_manager_access_client.h"
#include "continuous_task_callback_info.h"
#endif
#include "camera_manager_privacy_client.h"
#undef private
#include "audio_manager_privacy_proxy.h"
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "background_task_manager_access_proxy.h"
#endif
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

class SensitiveManagerCoverageTestCb1 : public ApplicationStateObserverStub {
public:
    SensitiveManagerCoverageTestCb1() = default;
    virtual ~SensitiveManagerCoverageTestCb1() = default;

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
    SensitiveManagerCoverageTestCb1 callback;

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
    SensitiveManagerCoverageTestCb1 callback;

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
    SensitiveManagerCoverageTestCb1 callback;

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

class SensitiveManagerCoverageTestCb2 : public CameraServiceCallbackStub {
public:
    SensitiveManagerCoverageTestCb2() = default;
    virtual ~SensitiveManagerCoverageTestCb2() = default;

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
    SensitiveManagerCoverageTestCb2 callback;

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
    SensitiveManagerCoverageTestCb2 callback;

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
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
/*
 * @tc.name: SubscribeBackgroundTaskTest001
 * @tc.desc: regist back ground task
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(SensitiveManagerCoverageTest, SubscribeBackgroundTaskTest001, TestSize.Level1)
{
    system("setenforce 0");
    sptr<BackgroundTaskSubscriberStub> bgTaskCallback = new (std::nothrow) BackgroundTaskSubscriberStub();
    ASSERT_NE(bgTaskCallback, nullptr);
    ASSERT_EQ(RET_SUCCESS, BackgourndTaskManagerAccessClient::GetInstance().SubscribeBackgroundTask(bgTaskCallback));
    ASSERT_EQ(RET_FAILED, BackgourndTaskManagerAccessClient::GetInstance().SubscribeBackgroundTask(nullptr));

    ASSERT_EQ(RET_FAILED, BackgourndTaskManagerAccessClient::GetInstance().UnsubscribeBackgroundTask(nullptr));
    ASSERT_EQ(RET_SUCCESS, BackgourndTaskManagerAccessClient::GetInstance().UnsubscribeBackgroundTask(bgTaskCallback));
    system("setenforce 1");
}

/*
 * @tc.name: BackgourndTaskManagerDiedHandle001
 * @tc.desc: test back ground task manager remote die
 * @tc.type: FUNC
 * @tc.require: issueI5RWXF
 */
HWTEST_F(SensitiveManagerCoverageTest, BackgourndTaskManagerDiedHandle001, TestSize.Level1)
{
    BackgourndTaskManagerAccessClient::GetInstance().OnRemoteDiedHandle();
    ASSERT_EQ(nullptr, BackgourndTaskManagerAccessClient::GetInstance().proxy_);
    ASSERT_EQ(nullptr, BackgourndTaskManagerAccessClient::GetInstance().serviceDeathObserver_);
}

class SensitiveManagerCoverageTestCb3 : public BackgroundTaskSubscriberStub {
public:
    SensitiveManagerCoverageTestCb3() = default;
    virtual ~SensitiveManagerCoverageTestCb3() = default;

    void OnContinuousTaskStart(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
    {
        GTEST_LOG_(INFO) << "OnContinuousTaskStart tokenID is " << continuousTaskCallbackInfo->GetFullTokenId();
    }

    void OnContinuousTaskStop(const std::shared_ptr<ContinuousTaskCallbackInfo> &continuousTaskCallbackInfo)
    {
        GTEST_LOG_(INFO) << "OnContinuousTaskStart  tokenID is " << continuousTaskCallbackInfo->GetFullTokenId();
    }
};

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: CameraServiceCallbackStub::OnRemoteRequest function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SensitiveManagerCoverageTest, OnRemoteRequest006, TestSize.Level1)
{
    SensitiveManagerCoverageTestCb3 callback;

    MessageParcel reply;
    MessageOption option;
    std::shared_ptr<ContinuousTaskCallbackInfo> info = std::make_shared<ContinuousTaskCallbackInfo>();
    MessageParcel data1;
    data1.WriteInterfaceToken(IBackgroundTaskSubscriber::GetDescriptor());
    EXPECT_EQ(RET_SUCCESS, callback.OnRemoteRequest(
        static_cast<uint32_t>(IBackgroundTaskSubscriber::Message::ON_CONTINUOUS_TASK_START), data1, reply, option));
    MessageParcel data2;
    data2.WriteInterfaceToken(IBackgroundTaskSubscriber::GetDescriptor());
    data2.WriteParcelable(info.get());
    EXPECT_EQ(RET_SUCCESS, callback.OnRemoteRequest(
        static_cast<uint32_t>(IBackgroundTaskSubscriber::Message::ON_CONTINUOUS_TASK_START), data2, reply, option));

    MessageParcel data3;
    data3.WriteInterfaceToken(IBackgroundTaskSubscriber::GetDescriptor());
    EXPECT_EQ(RET_SUCCESS, callback.OnRemoteRequest(
        static_cast<uint32_t>(IBackgroundTaskSubscriber::Message::ON_CONTINUOUS_TASK_STOP), data3, reply, option));
    MessageParcel data4;
    data4.WriteInterfaceToken(IBackgroundTaskSubscriber::GetDescriptor());
    data4.WriteParcelable(info.get());
    EXPECT_EQ(RET_SUCCESS, callback.OnRemoteRequest(
        static_cast<uint32_t>(IBackgroundTaskSubscriber::Message::ON_CONTINUOUS_TASK_STOP), data4, reply, option));

    MessageParcel data5;
    data5.WriteInterfaceToken(IBackgroundTaskSubscriber::GetDescriptor());
    data5.WriteParcelable(info.get());
    uint32_t code = -1;
    EXPECT_NE(RET_SUCCESS, callback.OnRemoteRequest(code, data5, reply, option));
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
