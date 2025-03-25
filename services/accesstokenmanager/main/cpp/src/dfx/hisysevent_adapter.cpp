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

#include "hisysevent_adapter.h"
#include "accesstoken_common_log.h"
#include "hisysevent.h"
#include "time_util.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static const std::string ACCESSTOKEN_PROCESS_NAME = "accesstoken_service";
static constexpr char ADD_DOMAIN[] = "PERFORMANCE";
}

void ReportSysEventPerformance()
{
    // accesstoken_service add CPU_SCENE_ENTRY system event in OnStart, avoid CPU statistics
    long id = 1 << 0; // first scene
    int64_t time = AccessToken::TimeUtil::GetCurrentTimestamp();

    int32_t ret = HiSysEventWrite(ADD_DOMAIN, "CPU_SCENE_ENTRY", HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "PACKAGE_NAME", ACCESSTOKEN_PROCESS_NAME, "SCENE_ID", std::to_string(id).c_str(), "HAPPEN_TIME", time);
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to report performance, ret %{public}d.", ret);
    }
}

void ReportSysEventServiceStart(int32_t pid, uint32_t hapSize, uint32_t nativeSize, uint32_t permDefSize)
{
    int32_t ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ACCESSTOKEN_SERVICE_START",
        HiviewDFX::HiSysEvent::EventType::STATISTIC,
        "PID", pid, "HAP_SIZE", hapSize, "NATIVE_SIZE", nativeSize, "PERM_DEFINITION_SIZE", permDefSize);
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", ret);
    }
}

void ReportSysEventServiceStartError(SceneCode scene, const std::string& errMsg, int32_t errCode)
{
    int32_t ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ACCESSTOKEN_SERVICE_START_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT, "SCENE_CODE", scene, "ERROR_CODE", errCode, "ERROR_MSG", errMsg);
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", ret);
    }
}

void ReportSysCommonEventError(int32_t ipcCode, int32_t errCode)
{
    if (GetThreadErrorMsgLen() == 0) {
        return;
    }
    int32_t ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "ACCESSTOKEN_SERVICE_START_ERROR",
        HiviewDFX::HiSysEvent::EventType::FAULT, "SCENE_CODE", ipcCode, "ERROR_CODE", errCode,
        "ERROR_MSG", GetThreadErrorMsg());
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", ret);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS