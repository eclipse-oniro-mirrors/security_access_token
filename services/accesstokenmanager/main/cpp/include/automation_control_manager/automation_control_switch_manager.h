/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef AUTOMATION_CONTROL_SWITCH_MANAGER_H
#define AUTOMATION_CONTROL_SWITCH_MANAGER_H

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "access_token.h"
#include "atm_data_type.h"
#include "generic_values.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class AutomationControlSwitchManager final {
public:
    static AutomationControlSwitchManager& GetInstance();

    int32_t SetAutomationControlStatus(uint32_t controllerTokenId,
        const std::vector<uint32_t>& targetTokenIds,
        const std::vector<int32_t>& statusList,
        std::vector<int32_t>& results);
    int32_t GetAutomationControlTargets(uint32_t controllerTokenId,
        std::vector<uint32_t>& targetTokenIds, std::vector<int32_t>& statusList,
        std::vector<std::string>& bundleNames);
    int32_t GetAutomationControlControllers(uint32_t targetTokenId,
        std::vector<uint32_t>& controllerTokenIds, std::vector<std::string>& bundleNames);
    void ClearByTokenId(uint32_t tokenId);
    int32_t CheckAccess(uint32_t controllerTokenId,
        const std::vector<uint32_t>& targetList,
        std::vector<int32_t>& decisionResults);

private:
    struct SetBatchData {
        std::vector<DelInfo> delInfoVec;
        std::vector<AddInfo> addInfoVec;
        std::vector<std::pair<AccessTokenID, int32_t>> validList;
    };

    AutomationControlSwitchManager() = default;
    ~AutomationControlSwitchManager() = default;
    DISALLOW_COPY_AND_MOVE(AutomationControlSwitchManager);

    bool IsHapTokenIdExist(AccessTokenID tokenId) const;
    std::string ResolveBundleName(AccessTokenID tokenId) const;
    void BuildSetBatch(uint32_t controllerTokenId,
        const std::vector<uint32_t>& targetTokenIds,
        const std::vector<int32_t>& statusList,
        std::vector<int32_t>& results,
        SetBatchData& batch);
    int32_t LoadControllerFromDb(AccessTokenID controllerId);

    std::mutex switchCacheMutex_;
    std::unordered_map<AccessTokenID, std::unordered_map<AccessTokenID, int32_t>> switchCache_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // AUTOMATION_CONTROL_SWITCH_MANAGER_H
