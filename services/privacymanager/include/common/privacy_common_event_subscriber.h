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

#ifndef ACCESS_TOKEN_COMMON_EVENT_SUBSCRIBER_H
#define ACCESS_TOKEN_COMMON_EVENT_SUBSCRIBER_H

#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

#ifdef COMMON_EVENT_SERVICE_ENABLE
class PrivacyCommonEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
public:
    PrivacyCommonEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo& info) : CommonEventSubscriber(info)
    {}

    ~PrivacyCommonEventSubscriber() override = default;

    static void RegisterEvent();

    static void UnRegisterEvent();

    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData& event) override;
};
#endif //COMMON_EVENT_SERVICE_ENABLE
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_COMMON_EVENT_SUBSCRIBER_H