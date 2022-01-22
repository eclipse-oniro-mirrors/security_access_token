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

#ifndef SOFT_BUS_MANAGER_H
#define SOFT_BUS_MANAGER_H

#include <functional>
#include <inttypes.h>
#include <memory>
#include <set>
#include <string>
#include <thread>

#include "accesstoken_log.h"
#include "rwlock.h"
#include "session.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class SoftBusManager final {
public:
    virtual ~SoftBusManager();
    static SoftBusManager &GetInstance();
    void Initialize();
    void Destroy();

    static int OnSessionOpend(int sessionId, int result);
    static void OnSessionClosed(int sessionId);
    static void OnBytesReceived(int sessionId, const void *data, unsigned int dataLen);
    static void OnMessageReceived(int sessionId, const void *data, unsigned int dataLen);
    static void isSessionRespond(int sessionId);

    void InsertSessionRespondStatus(int sessionId);
    bool IsSessionRespond(int sessionId);
    int32_t SendRequest();
    bool IsSessionWaitingOpen(int sessionId);
    bool IsSessionOpen(int sessionId);
    void ModifySessionStatus(int sessionId);
    void SetSessionWaitingOpen(int sessionId);

public:
    static const std::string SESSION_NAME;

private:
    SoftBusManager();

    static const std::string ACCESS_TOKEN_PACKAGE_NAME;

    // soft bus session server opened flag
    bool isSoftBusServiceBindSuccess_;
    std::atomic_bool inited_;

    // init mutex
    std::mutex mutex_;

    OHOS::Utils::RWLock sessIdLock_;
    std::set<int32_t> sessOpenSet_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif  // SOFT_BUS_MANAGER_H
