
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
#include "permission_grant_event.h"
#include <ctime>
#include <unistd.h>
#include "accesstoken_dfx_define.h"
#include "accesstoken_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr int MS_PER_S = 1000;
static constexpr int NS_PER_MS = 1000000;

static uint64_t GetRealTimeStamp()
{
    struct timespec curTime;
    if (clock_gettime(CLOCK_MONOTONIC, &curTime) != 0) {
        return 0;
    }

    return curTime.tv_sec * MS_PER_S + curTime.tv_nsec / NS_PER_MS;
}

void PermissionGrantEvent::AddEvent(AccessTokenID tokenID, const std::string& permissionName, uint64_t& timestamp)
{
    std::unique_lock<std::mutex> lck(lock_);
    struct GrantEvent event = {
        .tokenID = tokenID,
        .permissionName = permissionName,
        .timeStamp = GetRealTimeStamp()
    };

    timestamp = event.timeStamp;
    permGrantEventList_.emplace_back(event);
}

void PermissionGrantEvent::NotifyPermGrantStoreResult(bool isStoreSucc, uint64_t timestamp)
{
    std::unique_lock<std::mutex> lck(lock_);
    for (auto iter = permGrantEventList_.begin(); iter != permGrantEventList_.end();) {
        if (timestamp >= iter->timeStamp) {
            if (!isStoreSucc) {
                HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
                    HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", PERMISSION_STORE_ERROR,
                    "CALLER_TOKENID", iter->tokenID, "PERMISSION_NAME", iter->permissionName);
            }
            iter = permGrantEventList_.erase(iter);
        } else {
            iter++;
        }
    }
    return;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
