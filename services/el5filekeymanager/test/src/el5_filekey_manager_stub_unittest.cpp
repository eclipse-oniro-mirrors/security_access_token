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

#include "el5_filekey_manager_stub_unittest.h"
#include "singleton.h"

#include "accesstoken_kit.h"
#include "el5_filekey_callback_stub.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;

void El5FilekeyManagerStubTest::SetUpTestCase()
{
}

void El5FilekeyManagerStubTest::TearDownTestCase()
{
}

void El5FilekeyManagerStubTest::SetUp()
{
    el5FilekeyManagerStub_ = DelayedSingleton<El5FilekeyManagerService>::GetInstance();
}

void El5FilekeyManagerStubTest::TearDown()
{
}

/**
 * @tc.name: OnRemoteRequest001
 * @tc.desc: EFMInterfaceCode::GENERATE_APP_KEY.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerStubTest, OnRemoteRequest001, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor()));

    ASSERT_EQ(el5FilekeyManagerStub_->OnRemoteRequest(
        static_cast<uint32_t>(EFMInterfaceCode::GENERATE_APP_KEY), data, reply, option), OHOS::NO_ERROR);
}

/**
 * @tc.name: OnRemoteRequest002
 * @tc.desc: EFMInterfaceCode::DELETE_APP_KEY.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerStubTest, OnRemoteRequest002, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor()));

    ASSERT_EQ(el5FilekeyManagerStub_->OnRemoteRequest(
        static_cast<uint32_t>(EFMInterfaceCode::DELETE_APP_KEY), data, reply, option), OHOS::NO_ERROR);
}

/**
 * @tc.name: OnRemoteRequest003
 * @tc.desc: EFMInterfaceCode::ACQUIRE_ACCESS.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerStubTest, OnRemoteRequest003, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor()));

    ASSERT_EQ(el5FilekeyManagerStub_->OnRemoteRequest(
        static_cast<uint32_t>(EFMInterfaceCode::ACQUIRE_ACCESS), data, reply, option), OHOS::NO_ERROR);
}

/**
 * @tc.name: OnRemoteRequest004
 * @tc.desc: EFMInterfaceCode::RELEASE_ACCESS.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerStubTest, OnRemoteRequest004, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor()));

    ASSERT_EQ(el5FilekeyManagerStub_->OnRemoteRequest(
        static_cast<uint32_t>(EFMInterfaceCode::RELEASE_ACCESS), data, reply, option), OHOS::NO_ERROR);
}

/**
 * @tc.name: OnRemoteRequest005
 * @tc.desc: EFMInterfaceCode::GET_USER_APP_KEY.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerStubTest, OnRemoteRequest005, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor()));

    ASSERT_EQ(el5FilekeyManagerStub_->OnRemoteRequest(
        static_cast<uint32_t>(EFMInterfaceCode::GET_USER_APP_KEY), data, reply, option), OHOS::NO_ERROR);
}

/**
 * @tc.name: OnRemoteRequest006
 * @tc.desc: EFMInterfaceCode::CHANGE_USER_APP_KEYS_LOAD_INFO.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerStubTest, OnRemoteRequest006, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor()));

    ASSERT_EQ(el5FilekeyManagerStub_->OnRemoteRequest(
        static_cast<uint32_t>(EFMInterfaceCode::CHANGE_USER_APP_KEYS_LOAD_INFO), data, reply, option), OHOS::NO_ERROR);
}

/**
 * @tc.name: OnRemoteRequest007
 * @tc.desc: EFMInterfaceCode::SET_FILE_PATH_POLICY.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerStubTest, OnRemoteRequest007, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor()));

    ASSERT_EQ(el5FilekeyManagerStub_->OnRemoteRequest(
        static_cast<uint32_t>(EFMInterfaceCode::SET_FILE_PATH_POLICY), data, reply, option), OHOS::NO_ERROR);
}

/**
 * @tc.name: OnRemoteRequest008
 * @tc.desc: EFMInterfaceCode::REGISTER_CALLBACK.
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerStubTest, OnRemoteRequest008, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    ASSERT_EQ(true, data.WriteInterfaceToken(El5FilekeyManagerInterface::GetDescriptor()));

    ASSERT_EQ(el5FilekeyManagerStub_->OnRemoteRequest(
        static_cast<uint32_t>(EFMInterfaceCode::REGISTER_CALLBACK), data, reply, option), OHOS::NO_ERROR);
}

/**
 * @tc.name: OnRemoteRequest009
 * @tc.desc: data.ReadInterfaceToken() != El5FilekeyManagerInterface::GetDescriptor().
 * @tc.type: FUNC
 * @tc.require: issueI9JGMV
 */
HWTEST_F(El5FilekeyManagerStubTest, OnRemoteRequest009, TestSize.Level1)
{
    OHOS::MessageParcel data;
    OHOS::MessageParcel reply;
    OHOS::MessageOption option(OHOS::MessageOption::TF_SYNC);

    std::string des = "I don't know";
    data.WriteInterfaceToken(OHOS::Str8ToStr16(des));

    ASSERT_EQ(el5FilekeyManagerStub_->OnRemoteRequest(
        static_cast<uint32_t>(EFMInterfaceCode::GENERATE_APP_KEY), data, reply, option), EFM_ERR_IPC_TOKEN_INVALID);
}