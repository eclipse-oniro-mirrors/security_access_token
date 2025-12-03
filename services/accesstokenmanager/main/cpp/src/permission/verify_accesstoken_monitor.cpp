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

#include "verify_accesstoken_monitor.h"

#include <numeric>
#include <thread>

#include "access_token.h"
#include "accesstoken_common_log.h"
#include "accesstoken_id_manager.h"
#include "time_util.h"
#ifdef SECURITY_GUARD_ENABLE
#include "sg_collect_client.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr const int32_t VERIFY_THRESHOLD = 50;
constexpr const int32_t REPORT_THRESHOLD = 5;
#ifndef VERIFY_ACCESS_MONITER_TEST
constexpr const int64_t REPORT_TIME_WINDOW = 60 * 60 * 1000; // 60min
constexpr const int64_t MONITOR_TIME_WINDOW = 60 * 1000; // 60s
constexpr const int64_t DENIED_TIME_WINDOW = 30 * 60 * 1000; // 30min
#else
constexpr const int64_t REPORT_TIME_WINDOW = 5 * 1000; // 5s
constexpr const int64_t MONITOR_TIME_WINDOW = 2 * 1000; // 2s
constexpr const int64_t DENIED_TIME_WINDOW = 3 * 1000; // 3s
#endif
constexpr const int32_t MAX_RECORD_HAP_NUM_MAX = 512;
constexpr const int32_t MAX_RECORD_TOKENID_NUM_MAX = 80;
#ifdef SECURITY_GUARD_ENABLE
constexpr const int32_t MAX_REPORT_TOKENID_NUM_MAX = 40;
constexpr const int64_t ACCESS_TOKEN_EVENT_ID = 0xB000001;
#endif
}

VerifyAccessTokenMonitor::~VerifyAccessTokenMonitor()
{
    std::unique_lock<std::shared_mutex> listGuard(lock_);
    monitoredHapTokenMap_.clear();
}

bool VerifyAccessTokenMonitor::IsOverThresholdByRecords(
    const std::deque<VerifyAccessTokenRecord>& records, int64_t currentTimeStamp)
{
    size_t recordSize = records.size();
    if (recordSize < VERIFY_THRESHOLD) {
        return false;
    }
    const VerifyAccessTokenRecord& record = records[recordSize - VERIFY_THRESHOLD];
    if (currentTimeStamp - record.timestamp > MONITOR_TIME_WINDOW) {
        return false;
    }
    return true;
}

bool VerifyAccessTokenMonitor::IsInPunishingTime(AccessTokenID callerTokenId)
{
    bool isUpdate = false;
    {
        std::shared_lock<std::shared_mutex> readLock(lock_);
        auto it = monitoredHapTokenMap_.find(callerTokenId);
        if (it == monitoredHapTokenMap_.end()) {
            return false;
        }
        if (it->second.isOverThreshold) {
            int64_t currentTimeStamp = TimeUtil::GetCurrentTimestamp();
            if (currentTimeStamp - it->second.lastOverThresholdTime <= DENIED_TIME_WINDOW) {
                return true;
            }
            isUpdate = true;
        }
    }

    std::unique_lock<std::shared_mutex> writeLock(lock_);
    if (isUpdate) {
        isUpdate = false;
        auto it = monitoredHapTokenMap_.find(callerTokenId);
        if (it == monitoredHapTokenMap_.end()) {
            return false;
        }
        it->second.isOverThreshold = false;
    }
    return false;
}

void VerifyAccessTokenMonitor::RecordExceptionalBehavior(
    const HapTokenInfo& callerHapTokenInfo,
    AccessTokenID targetTokenID, const std::string& permissionName)
{
    std::unique_lock<std::shared_mutex> listGuard(lock_);

    int64_t currentTimeStamp = TimeUtil::GetCurrentTimestamp();
    auto it = monitoredHapTokenMap_.find(callerHapTokenInfo.tokenID);
    if (it == monitoredHapTokenMap_.end()) {
        // add hap into monitor list
        HapTokenMonitoredInfo info;
        info.bundleName = callerHapTokenInfo.bundleName;
        info.tokenAttr = callerHapTokenInfo.tokenAttr;
        VerifyAccessTokenRecord record = {targetTokenID, permissionName, currentTimeStamp};
        info.verifyTokenRecords.push_back(record);
        info.reportNum = 1;
        monitoredHapTokenMap_[callerHapTokenInfo.tokenID] = info;
        if (monitoredHapTokenMap_.size() >= MAX_RECORD_HAP_NUM_MAX) {
            ReportSecurityInfoAsync(currentTimeStamp, listGuard);
        }
        return;
    }

    // add record when caller tokenId exist in monitor list
    VerifyAccessTokenRecord record = {targetTokenID, permissionName, currentTimeStamp};
    if (it->second.verifyTokenRecords.size() >= MAX_RECORD_TOKENID_NUM_MAX) {
        VerifyAccessTokenRecord toRemoveRecord = it->second.verifyTokenRecords.front();
        it->second.verifyTokenRecords.pop_front();
        if (toRemoveRecord.timestamp >= lastReportTime_) {
            it->second.reportNum--;
        }
    }
    it->second.verifyTokenRecords.push_back(record);
    it->second.reportNum++;
    if (IsOverThresholdByRecords(it->second.verifyTokenRecords, currentTimeStamp)) {
        it->second.isOverThreshold = true;
        it->second.lastOverThresholdTime = currentTimeStamp;
    }
    if (!isNeedReport_ && it->second.reportNum >= REPORT_THRESHOLD) {
        isNeedReport_ = true;
    }
}

#ifdef SECURITY_GUARD_ENABLE
CJsonUnique VerifyAccessTokenMonitor::ToReportHapInfoJson(AccessTokenID callerTokenID,
    const HapTokenMonitoredInfo& info, int64_t currentTimeStamp)
{
    CJsonUnique extraInfoJson = CreateJson();
    CJsonUnique permsJson = CreateJsonArray();
    CJsonUnique tokenIdsJson = CreateJsonArray();
    if (extraInfoJson == nullptr || permsJson == nullptr || tokenIdsJson == nullptr) {
        return nullptr;
    }
    (void)AddUnsignedIntToJson(extraInfoJson, "invalid_times", static_cast<uint32_t>(info.verifyTokenRecords.size()));
    int32_t count = 0;
    for (auto item = info.verifyTokenRecords.rbegin(); item != info.verifyTokenRecords.rend(); ++item) {
        if (item->timestamp < lastReportTime_ || count >= MAX_REPORT_TOKENID_NUM_MAX) {
            break;
        }
        (void)AddStringToArray(permsJson, item->permissionName);
        (void)AddUnsignedIntToArray(tokenIdsJson, static_cast<uint32_t>(item->tokenID));
        count++;
    }
    (void)AddObjToJson(extraInfoJson, "permission_list", permsJson);
    (void)AddObjToJson(extraInfoJson, "tokenid_list", tokenIdsJson);

    CJsonUnique hapTokenReportJson = CreateJson();
    if (hapTokenReportJson == nullptr) {
        return nullptr;
    }
    (void)AddIntToJson(hapTokenReportJson, "version", 0);
    (void)AddStringToJson(hapTokenReportJson, "bundle_name", info.bundleName);
    (void)AddUnsignedIntToJson(hapTokenReportJson, "tokenid", static_cast<uint32_t>(callerTokenID));
    (void)AddUnsignedIntToJson(hapTokenReportJson, "tokenid_attr", info.tokenAttr);
    (void)AddStringToJson(hapTokenReportJson, "event_type", "0");
    (void)AddStringToJson(hapTokenReportJson, "event_msg", "Abnormal access token usage detected.");
    (void)AddObjToJson(hapTokenReportJson, "extra_info", extraInfoJson);
    return hapTokenReportJson;
}

void VerifyAccessTokenMonitor::ReportSecurityInfo(
    std::map<AccessTokenID, HapTokenMonitoredInfo>::iterator& it, int64_t currentTimeStamp)
{
    if (it->second.reportNum < REPORT_THRESHOLD) {
        return;
    }
    CJsonUnique hapTokenReportJson = ToReportHapInfoJson(it->first, it->second, currentTimeStamp);
    if (hapTokenReportJson == nullptr) {
        return;
    }
    std::string jsonStr = PackJsonToString(hapTokenReportJson);
    if (jsonStr.empty()) {
        LOGI(ATM_DOMAIN, ATM_TAG, "Failed to pack json to string for reporting.");
        return;
    }
    LOGI(ATM_DOMAIN, ATM_TAG, "Report security info: %{public}s", jsonStr.c_str());
    int64_t eventId = ACCESS_TOKEN_EVENT_ID;
    std::shared_ptr<SecurityGuard::EventInfo> eventInfo =
        std::make_shared<SecurityGuard::EventInfo>(eventId, "1.0", jsonStr);
    (void)SecurityGuard::NativeDataCollectKit::ReportSecurityInfo(eventInfo);
}
#endif

void VerifyAccessTokenMonitor::ClearReportedRecords(
    std::map<AccessTokenID, HapTokenMonitoredInfo>::iterator& it, int64_t currentTimeStamp)
{
    while (!it->second.verifyTokenRecords.empty() &&
           currentTimeStamp - MONITOR_TIME_WINDOW > it->second.verifyTokenRecords.front().timestamp) {
        it->second.verifyTokenRecords.pop_front();
    }
}

void VerifyAccessTokenMonitor::ReportSecurityInfoAsync(
    int64_t currentTimeStamp, std::unique_lock<std::shared_mutex>& listGuard)
{
    std::thread([weak = weak_from_this(), currentTimeStamp, guard = std::move(listGuard)]() mutable {
        auto self = weak.lock();
        if (self == nullptr) {
            LOGI(ATM_DOMAIN, ATM_TAG, "self is nullptr.");
            return;
        }
        auto it = self->monitoredHapTokenMap_.begin();
        while (it != self->monitoredHapTokenMap_.end()) {
#ifdef SECURITY_GUARD_ENABLE
            self->ReportSecurityInfo(it, currentTimeStamp);
#endif
            it->second.reportNum = 0;
            self->ClearReportedRecords(it, currentTimeStamp);
            if (it->second.verifyTokenRecords.empty()) {
                it = self->monitoredHapTokenMap_.erase(it);
            } else {
                ++it;
            }
        }
        while (self->monitoredHapTokenMap_.size() >= MAX_RECORD_HAP_NUM_MAX) {
            (void)self->monitoredHapTokenMap_.erase(self->monitoredHapTokenMap_.begin());
        }

        self->lastReportTime_ = currentTimeStamp;
        self->isNeedReport_ = false;
    }).detach();
}

void VerifyAccessTokenMonitor::ReportExceptionalAccessTokenUsage()
{
    int64_t currentTimeStamp = TimeUtil::GetCurrentTimestamp();
    {
        std::shared_lock<std::shared_mutex> readLock(lock_);
        if (!isNeedReport_ || currentTimeStamp - lastReportTime_ < REPORT_TIME_WINDOW ||
            monitoredHapTokenMap_.empty()) {
            return;
        }
    }
    std::unique_lock<std::shared_mutex> writeLock(lock_);
    if (!isNeedReport_ || currentTimeStamp - lastReportTime_ < REPORT_TIME_WINDOW ||
        monitoredHapTokenMap_.empty()) {
        return;
    }
    ReportSecurityInfoAsync(currentTimeStamp, writeLock);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
