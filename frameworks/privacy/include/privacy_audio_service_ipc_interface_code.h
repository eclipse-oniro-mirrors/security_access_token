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

#ifndef PRIVACY_AUDIO_SERVICE_IPC_INTERFACE_CODE_H
#define PRIVACY_AUDIO_SERVICE_IPC_INTERFACE_CODE_H

namespace OHOS {
namespace Security {
namespace AccessToken {
enum PrivacyAudioPolicyInterfaceCode {
#ifdef FEATURE_DTMF_TONE
    SET_MICROPHONE_MUTE_PERSISTENT = 120,
    GET_MICROPHONE_MUTE_PERSISTENT = 121,
#else
    SET_MICROPHONE_MUTE_PERSISTENT = 118,
    GET_MICROPHONE_MUTE_PERSISTENT = 119,
#endif
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // PRIVACY_AUDIO_SERVICE_IPC_INTERFACE_CODE_H
