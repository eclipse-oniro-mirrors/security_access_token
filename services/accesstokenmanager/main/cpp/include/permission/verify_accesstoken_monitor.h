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

#ifndef VERIFY_ACCESSTOKEN_MONITOR
#define VERIFY_ACCESSTOKEN_MONITOR

#include <deque>
#include <memory>
#include <shared_mutex>
#include <vector>

#include "cjson_utils.h"
#include "hap_token_info.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

struct VerifyAccessTokenRecord {
    AccessTokenID tokenID = INVALID_TOKENID;
    std::string permissionName;
    int64_t timestamp = 0;
};

class HapTokenMonitoredInfo final {
public:
    std::string bundleName;
    uint32_t tokenAttr = 0;
    bool isOverThreshold = false;
    int64_t lastOverThresholdTime = 0;
    int32_t reportNum = 0;
    std::deque<VerifyAccessTokenRecord> verifyTokenRecords;
};

class VerifyAccessTokenMonitor final: public std::enable_shared_from_this<VerifyAccessTokenMonitor> {
public:
    VerifyAccessTokenMonitor() {};
    ~VerifyAccessTokenMonitor();
    void RecordExceptionalBehavior(const HapTokenInfo& callerHapTokenInfo,
        AccessTokenID targetTokenID, const std::string& permissionName);
    void ReportExceptionalAccessTokenUsage();
    bool IsInPunishingTime(AccessTokenID callerTokenId);

private:
    DISALLOW_COPY_AND_MOVE(VerifyAccessTokenMonitor);
    bool IsOverThresholdByRecords(const std::deque<VerifyAccessTokenRecord>& records, int64_t currentTimeStamp);
    void ReportSecurityInfoAsync(int64_t currentTimeStamp, std::unique_lock<std::shared_mutex>& listGuard);
    void ClearReportedRecords(std::map<AccessTokenID, HapTokenMonitoredInfo>::iterator& it, int64_t currentTimeStamp);
#ifdef SECURITY_GUARD_ENABLE
    CJsonUnique ToReportHapInfoJson(AccessTokenID callerTokenID,
        const HapTokenMonitoredInfo& info, int64_t currentTimeStamp);
    void ReportSecurityInfo(std::map<AccessTokenID, HapTokenMonitoredInfo>::iterator& it, int64_t currentTimeStamp);
#endif
    std::map<AccessTokenID, HapTokenMonitoredInfo> monitoredHapTokenMap_;
    std::atomic<int64_t> lastReportTime_ = 0;
    bool isNeedReport_ = false;
    std::shared_mutex lock_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // VERIFY_ACCESSTOKEN_MONITOR
