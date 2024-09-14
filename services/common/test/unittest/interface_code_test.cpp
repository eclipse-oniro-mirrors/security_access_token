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
#ifdef ABILITY_RUNTIME_ENABLE
#include "ams_mgr_interface.h"
#include "app_manager_access_proxy.h"
#include "app_mgr_ipc_interface_code.h"

#include "ability_manager_ipc_interface_code.h"
#include "iapplication_state_observer.h"
#endif

#ifdef CAMERA_FRAMEWORK_ENABLE
#include "camera_service_ipc_interface_code.h"
#endif

#include "privacy_camera_service_ipc_interface_code.h"
#include "service_ipc_interface_code.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
class IpcCodeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void IpcCodeTest::SetUpTestCase()
{
}

void IpcCodeTest::TearDownTestCase()
{
}

void IpcCodeTest::SetUp()
{
}

void IpcCodeTest::TearDown()
{
}

#ifdef ABILITY_RUNTIME_ENABLE
/*
 * @tc.name: AppManagerCodeTest001
 * @tc.desc: test appMgr ipc code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IpcCodeTest, AppManagerCodeTest001, TestSize.Level1)
{
    ASSERT_EQ(static_cast<uint32_t>(AppExecFwk::AppMgrInterfaceCode::REGISTER_APPLICATION_STATE_OBSERVER),
        static_cast<uint32_t>(AccessToken::IAppMgr::Message::REGISTER_APPLICATION_STATE_OBSERVER)); // 12
    ASSERT_EQ(static_cast<uint32_t>(AppExecFwk::AppMgrInterfaceCode::UNREGISTER_APPLICATION_STATE_OBSERVER),
        static_cast<uint32_t>(AccessToken::IAppMgr::Message::UNREGISTER_APPLICATION_STATE_OBSERVER)); // 13
    ASSERT_EQ(static_cast<uint32_t>(AppExecFwk::AppMgrInterfaceCode::GET_FOREGROUND_APPLICATIONS),
        static_cast<uint32_t>(AccessToken::IAppMgr::Message::GET_FOREGROUND_APPLICATIONS)); // 14
}

/*
 * @tc.name: AmsManagerCodeTest001
 * @tc.desc: test amsMgr ipc code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IpcCodeTest, AmsManagerCodeTest001, TestSize.Level1)
{
    ASSERT_EQ(static_cast<uint32_t>(AppExecFwk::IAmsMgr::Message::FORCE_KILL_APPLICATION_BY_ACCESS_TOKEN_ID),
        static_cast<uint32_t>(AccessToken::IAmsMgr::Message::FORCE_KILL_APPLICATION_BY_ACCESS_TOKEN_ID));
}

/*
 * @tc.name: AmsManagerCodeTest001
 * @tc.desc: test ability manager ipc code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IpcCodeTest, AbilityManagerCodeTest001, TestSize.Level1)
{
    ASSERT_EQ(static_cast<uint32_t>(
        AppExecFwk::IApplicationStateObserver::Message::TRANSACT_ON_FOREGROUND_APPLICATION_CHANGED),
        static_cast<uint32_t>(
            AccessToken::AccessAppServiceInterfaceCode::TRANSACT_ON_FOREGROUND_APPLICATION_CHANGED));
    ASSERT_EQ(static_cast<uint32_t>(AAFwk::AbilityManagerInterfaceCode::START_ABILITY_ADD_CALLER),
        static_cast<uint32_t>(AccessToken::AccessAbilityServiceInterfaceCode::START_ABILITY_ADD_CALLER));
}
#endif

#ifdef CAMERA_FRAMEWORK_ENABLE
/*
 * @tc.name: CameraManagerCodeTest001
 * @tc.desc: test camera framework ipc code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IpcCodeTest, CameraManagerCodeTest001, TestSize.Level1)
{
    ASSERT_EQ(static_cast<uint32_t>(CameraStandard::CameraServiceInterfaceCode::CAMERA_SERVICE_IS_CAMERA_MUTED),
        static_cast<uint32_t>(AccessToken::PrivacyCameraServiceInterfaceCode::CAMERA_SERVICE_IS_CAMERA_MUTED));
    ASSERT_EQ(static_cast<uint32_t>(CameraStandard::CameraServiceInterfaceCode::CAMERA_SERVICE_MUTE_CAMERA_PERSIST),
        static_cast<uint32_t>(AccessToken::PrivacyCameraServiceInterfaceCode::CAMERA_SERVICE_MUTE_CAMERA_PERSIST));
}
#endif

#ifdef AUDIO_FRAMEWORK_ENABLE
/*
 * @tc.name: AudioManagerCodeTest001
 * @tc.desc: test audio framework ipc code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IpcCodeTest, AudioManagerCodeTest001, TestSize.Level1)
{
}
#endif
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
