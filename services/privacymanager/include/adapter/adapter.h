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

#ifndef ADAPTER_H
#define ADAPTER_H
#include "ability_manager_privacy_client.h"
#include "app_manager_privacy_client.h"
#include "app_status_change_callback.h"
#include "audio_global_switch_change_stub.h"
#include "audio_manager_privacy_client.h"
#include "camera_manager_privacy_client.h"
#include "camera_service_callback_stub.h"
#include "want.h"
#include "window_manager_privacy_agent.h"
#include "window_manager_privacy_client.h"

#ifdef __cplusplus
extern "C" {
#endif
int32_t StartAbility(const OHOS::AAFwk::Want& want, void* callerToken);

int32_t SetMuteCallback(void* callback);
int32_t MuteCamera(bool muteMode);
bool IsCameraMuted(void);
void* GetCameraServiceCallbackStub(void);
void DelCameraServiceCallbackStub(void* cameraServiceCallbackStub);

int32_t RegisterApplicationStateObserver(void* observer);
int32_t UnregisterApplicationStateObserver(void* observer);
int32_t GetForegroundApplications(std::vector<OHOS::Security::AccessToken::AppStateData>& list);
void* GetApplicationStateObserverStub(void);
void DelApplicationStateObserverStub(void* applicationStateObserverStub);

int32_t SetMicStateChangeCallback(void* callback);
int32_t SetMicrophoneMute(bool isMute);
bool IsMicrophoneMute(void);
void* GetAudioRoutingManagerListenerStub(void);
void DelAudioRoutingManagerListenerStub(void* audioRoutingManagerListenerStub);

bool RegisterWindowManagerAgent(OHOS::Security::AccessToken::WindowManagerAgentType type, void* windowManagerAgent);
bool UnregisterWindowManagerAgent(OHOS::Security::AccessToken::WindowManagerAgentType type, void* windowManagerAgent);
void* GetWindowManagerPrivacyAgent(void);
void DelGetWindowManagerPrivacyAgent(void* windowManagerAgent);
#ifdef __cplusplus
}
#endif

#endif // ADAPTER_H
