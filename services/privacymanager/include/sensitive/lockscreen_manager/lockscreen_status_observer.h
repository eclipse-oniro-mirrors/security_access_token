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

#ifndef ACCESS_TOKEN_LOCKSCREEN_STATUS_OBSERVER_H
#define ACCESS_TOKEN_LOCKSCREEN_STATUS_OBSERVER_H

#include "active_change_response_info.h"
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class LockscreenObserver : public OHOS::EventFwk::CommonEventSubscriber {
public:
    LockscreenObserver(const OHOS::EventFwk::CommonEventSubscribeInfo& info) : CommonEventSubscriber(info)
    {}

    ~LockscreenObserver() override = default;

    static void RegisterEvent();

    static void UnRegisterEvent();

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData& event) override;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_LOCKSCREEN_STATUS_PBSERVER_H