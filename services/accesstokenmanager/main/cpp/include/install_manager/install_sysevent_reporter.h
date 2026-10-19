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

#ifndef INSTALL_SYSEVENT_REPORTER_H
#define INSTALL_SYSEVENT_REPORTER_H

#include <vector>

#include "access_token.h"
#include "hap_token_info.h"
#include "hisysevent_adapter.h"
#include "install_session_cache.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

class InstallSysEventReporter final {
public:
    static void ReportSessionFinish(const InstallCache& cache, int64_t duration,
        int32_t sceneCode, int32_t errorCode);
    static void ReportSessionError(const InstallCache& cache,
        int32_t sceneCode, int32_t errorCode, AccessTokenID tokenId);
    // Timeout cleanup runs on the thread of an unrelated request: thread-local LOGC
    // residue does not belong to the timed-out session, so no FAULT is attached.
    static void ReportSessionTimeout(const InstallCache& cache, int64_t duration);

private:
    static void ReportAddHap(const InstallCache& cache, int32_t sceneCode,
        int32_t errorCode, const HapDfxInfo& dfxInfoRaw, bool needReportFault);
    static void ReportUpdateHap(AccessTokenID tokenID, const BundlePolicy& bundlePolicy, int32_t sceneCode,
        int32_t errorCode, const HapDfxInfo& dfxInfoRaw, bool needReportFault);
    static void DumpPolicyEventInfo(const HapPolicy& policy, HapDfxInfo& dfxInfo);
    static void DumpPreAuthInfo(const std::vector<PreAuthorizationInfo>& preAuthorizationInfo, HapDfxInfo& dfxInfo);
    static HapDfxInfo BuildDefaultDfxInfo(const HapDfxInfo& dfxInfoRaw);
};

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // INSTALL_SYSEVENT_REPORTER_H
