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

#ifndef APPLICATION_STATUS_CHANGE_CALLBACK_H
#define APPLICATION_STATUS_CHANGE_CALLBACK_H

#include <vector>
#include "application_state_observer_stub.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
typedef void (*OnAppStatusChangeCallback)(uint32_t tokenId, int32_t status);
class ApplicationStatusChangeCallback : public AppExecFwk::ApplicationStateObserverStub {
public:
    void OnForegroundApplicationChanged(const AppExecFwk::AppStateData& appStateData) override;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // APPLICATION_STATUS_CHANGE_CALLBACK_H
