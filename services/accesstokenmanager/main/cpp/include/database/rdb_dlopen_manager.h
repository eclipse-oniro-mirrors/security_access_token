/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef ACCESS_TOKEN_RDB_DLOPEN_MANAGER_H
#define ACCESS_TOKEN_RDB_DLOPEN_MANAGER_H

#include <mutex>
#include <vector>

#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif
#include "access_token_db_loader.h"
#include "atm_data_type.h"
#include "generic_values.h"
#include "refbase.h"
#include "singleton.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static constexpr const char* RDB_ADAPTER_LIBPATH = "libaccesstoken_db_loader.z.so";

class RdbDlopenManager final : public DelayedSingleton<RdbDlopenManager> {
public:
    RdbDlopenManager();
    ~RdbDlopenManager() = default;

    int32_t Modify(const AtmDataType type, const GenericValues& modifyValue,
        const GenericValues& conditionValue);
    int32_t Find(AtmDataType type, const GenericValues& conditionValue, std::vector<GenericValues>& results);
    int32_t DeleteAndInsertValues(const std::vector<DelInfo>& delInfoVec,
        const std::vector<AddInfo>& addInfoVec);

private:
    DISALLOW_COPY_AND_MOVE(RdbDlopenManager);

#ifdef EVENTHANDLER_ENABLE
    void InitEventHandler();
    std::shared_ptr<AccessEventHandler> GetEventHandler();

    std::mutex eventHandlerLock_;
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner_ = nullptr;
    std::shared_ptr<AccessEventHandler> eventHandler_ = nullptr;
#endif

    AccessTokenDbLoaderInterface* GetDbInstance();
    void Init();
    void Create(void* handle);
    void Destroy(void* handle);
    bool CleanUp();
    void DelayDlcloseHandle(int64_t delayTime);

    std::mutex handleMutex_;
    void* handle_ = nullptr;
    AccessTokenDbLoaderInterface* instance_ = nullptr;
    std::atomic_int32_t taskNum_ = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_RDB_DLOPEN_MANAGER_H
