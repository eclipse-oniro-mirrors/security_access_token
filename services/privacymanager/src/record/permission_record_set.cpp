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

#include "permission_record_set.h"
#include "accesstoken_common_log.h"
#include "constant.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

void PermissionRecordSet::RemoveByKey(std::set<ContinusPermissionRecord>& recordList,
    const ContinusPermissionRecord& record, const IsEqualFunc& isEqualFunc,
    std::vector<ContinusPermissionRecord>& retList)
{
    for (auto it = recordList.begin(); it != recordList.end();) {
        if (((*it).*isEqualFunc)(record)) {
            retList.emplace_back(*it);
            it = recordList.erase(it);
        } else {
            ++it;
        }
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "After removing record List size = %{public}zu, removed size = %{public}zu",
        recordList.size(), retList.size());
}

void PermissionRecordSet::GetInActiveUniqueRecord(const std::set<ContinusPermissionRecord>& recordList,
    const std::vector<ContinusPermissionRecord>& removedList, std::vector<ContinusPermissionRecord>& retList)
{
    // get unique record with tokenid and opcode
    uint64_t lastUniqueKey = 0;
    for (const auto &record: removedList) {
        uint64_t curUniqueKey = record.GetTokenIdAndPermCode();
        if (lastUniqueKey != curUniqueKey) {
            retList.emplace_back(record);
            lastUniqueKey = curUniqueKey;
        }
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "Unique list size = %{public}zu", retList.size());

    // filter active records with same tokenid and opcode in set
    auto iterRemoved = retList.begin();
    auto iterRemain = recordList.begin();
    uint64_t removeKey;
    uint64_t remainKey;
    while (iterRemoved != retList.end() && iterRemain != recordList.end()) {
        removeKey = iterRemoved->GetTokenIdAndPermCode();
        remainKey = iterRemain->GetTokenIdAndPermCode();
        if (removeKey < remainKey) {
            ++iterRemoved;
            continue;
        } else if (removeKey == remainKey) {
            if (iterRemain->status != PERM_INACTIVE) {
                iterRemoved = retList.erase(iterRemoved);
                continue;
            }
        }
        ++iterRemain;
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "Get inactive list size = %{public}zu", retList.size());
}

void PermissionRecordSet::GetUnusedCameraRecords(const std::set<ContinusPermissionRecord>& recordList,
    const std::vector<ContinusPermissionRecord>& removedList, std::vector<ContinusPermissionRecord>& retList)
{
    if (removedList.empty()) {
        return;
    }
    // filtering irrelevant records
    uint64_t lastUniqueKey = 0;
    for (auto iter = removedList.begin(); iter != removedList.end(); ++iter) {
        if (iter->opCode != Constant::OP_CAMERA) {
            continue;
        }
        uint64_t curUniqueKey = iter->GetTokenIdAndPid();
        if (lastUniqueKey == curUniqueKey) {
            continue;
        }
        lastUniqueKey = curUniqueKey;
        retList.emplace_back(*iter);
    }
    LOGD(PRI_DOMAIN, PRI_TAG, "Unique list size = %{public}zu", retList.size());

    // filter records with same tokenid, opcode and pid in set
    auto iterRemoved = retList.begin();
    auto iterRemain = recordList.begin();
    uint64_t removeKey;
    uint64_t remainKey;
    while (iterRemoved != retList.end() && iterRemain != recordList.end()) {
        removeKey = iterRemoved->GetTokenIdAndPermCode();
        remainKey = iterRemain->GetTokenIdAndPermCode();
        if (removeKey < remainKey) {
            ++iterRemoved;
            continue;
        } else if (removeKey == remainKey) {
            if (iterRemoved->IsEqualPid(*iterRemain)) {
                iterRemoved = retList.erase(iterRemoved);
                continue;
            } else if (iterRemoved->pid < iterRemain->pid) {
                ++iterRemoved;
            } else {
                ++iterRemain;
            }
        } else {
            ++iterRemain;
        }
    }
    LOGI(PRI_DOMAIN, PRI_TAG, "Get unused camera list size = %{public}zu", retList.size());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS