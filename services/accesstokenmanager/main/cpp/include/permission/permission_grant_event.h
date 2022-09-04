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

#ifndef PERMISSION_GRANT_EVENT_H
#define PERMISSION_GRANT_EVENT_H

#include <mutex>
#include <string>
#include <vector>

#include "access_token.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
struct GrantEvent {
    AccessTokenID tokenID;
    std::string permissionName;
    uint64_t timeStamp;
};

class PermissionGrantEvent final {
public:
    PermissionGrantEvent() = default;
    virtual ~PermissionGrantEvent() = default;

    void AddEvent(AccessTokenID tokenID, const std::string& permissionName, uint64_t& timestamp);
    void NotifyPermGrantStoreResult(bool result, uint64_t timestamp);

private:
    std::mutex lock_;
    std::vector<GrantEvent> permGrantEventList_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_GRANT_EVENT_H
