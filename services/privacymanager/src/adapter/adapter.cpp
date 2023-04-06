/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "adapter.h"

using namespace OHOS;
using namespace OHOS::Security;
using namespace OHOS::Security::AccessToken;

int32_t StartAbility(const AAFwk::Want &want, void* callerToken)
{
    auto caller = *reinterpret_cast<sptr<IRemoteObject>*>(&callerToken);
    return AbilityManagerPrivacyClient::GetInstance().StartAbility(want, caller);
}

int32_t SetMuteCallback(void* callback)
{
    auto cameraServiceCallbackStub = *reinterpret_cast<sptr<CameraServiceCallbackStub>*>(&callback);
    return CameraManagerPrivacyClient::GetInstance().SetMuteCallback(cameraServiceCallbackStub);
}

int32_t MuteCamera(bool muteMode)
{
    return CameraManagerPrivacyClient::GetInstance().MuteCamera(muteMode);
}

bool IsCameraMuted()
{
    return CameraManagerPrivacyClient::GetInstance().IsCameraMuted();
}

void* GetCameraServiceCallbackStub()
{
    return new(std::nothrow) CameraServiceCallbackStub();
}

void DelCameraServiceCallbackStub(void* cameraServiceCallbackStub)
{
    delete reinterpret_cast<CameraServiceCallbackStub*>(cameraServiceCallbackStub);
}

int32_t RegisterApplicationStateObserver(void* observer)
{
    auto applicationStateObserverStub = *reinterpret_cast<sptr<ApplicationStateObserverStub>*>(&observer);
    return AppManagerPrivacyClient::GetInstance().RegisterApplicationStateObserver(applicationStateObserverStub);
}

int32_t UnregisterApplicationStateObserver(void* observer)
{
    auto applicationStateObserverStub = *reinterpret_cast<sptr<ApplicationStateObserverStub>*>(&observer);
    return AppManagerPrivacyClient::GetInstance().UnregisterApplicationStateObserver(applicationStateObserverStub);
}

int32_t GetForegroundApplications(std::vector<AppStateData>& list)
{
    return AppManagerPrivacyClient::GetInstance().GetForegroundApplications(list);
}

void* GetApplicationStateObserverStub()
{
    return new(std::nothrow) ApplicationStateObserverStub();
}

void DelApplicationStateObserverStub(void* applicationStateObserverStub)
{
    delete reinterpret_cast<ApplicationStateObserverStub*>(applicationStateObserverStub);
}

int32_t SetMicStateChangeCallback(void* callback)
{
    auto audioRoutingManagerListenerStub = *reinterpret_cast<sptr<AudioRoutingManagerListenerStub>*>(&callback);
    return AudioManagerPrivacyClient::GetInstance().SetMicStateChangeCallback(audioRoutingManagerListenerStub);
}

int32_t SetMicrophoneMute(bool isMute)
{
    return AudioManagerPrivacyClient::GetInstance().SetMicrophoneMute(isMute);
}

bool IsMicrophoneMute()
{
    return AudioManagerPrivacyClient::GetInstance().IsMicrophoneMute();
}

void* GetAudioRoutingManagerListenerStub()
{
    return new(std::nothrow) AudioRoutingManagerListenerStub();
}

void DelAudioRoutingManagerListenerStub(void* audioRoutingManagerListenerStub)
{
    delete reinterpret_cast<AudioRoutingManagerListenerStub*>(audioRoutingManagerListenerStub);
}

bool RegisterWindowManagerAgent(WindowManagerAgentType type, void* windowManagerAgent)
{
    auto windowManagerPrivacyAgent = *reinterpret_cast<sptr<WindowManagerPrivacyAgent>*>(&windowManagerAgent);
    return WindowManagerPrivacyClient::GetInstance().RegisterWindowManagerAgent(type, windowManagerPrivacyAgent);
}

bool UnregisterWindowManagerAgent(WindowManagerAgentType type, void* windowManagerAgent)
{
    auto windowManagerPrivacyAgent = *reinterpret_cast<sptr<WindowManagerPrivacyAgent>*>(&windowManagerAgent);
    return WindowManagerPrivacyClient::GetInstance().UnregisterWindowManagerAgent(type, windowManagerPrivacyAgent);
}

void* GetWindowManagerPrivacyAgent()
{
    return new(std::nothrow) WindowManagerPrivacyAgent();
}

void DelGetWindowManagerPrivacyAgent(void* windowManagerAgent)
{
    delete reinterpret_cast<WindowManagerPrivacyAgent*>(windowManagerAgent);
}
