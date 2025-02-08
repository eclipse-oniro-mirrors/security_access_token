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

#ifndef ACCESSTOKEN_HISYSEVENT_ADAPTER_H
#define ACCESSTOKEN_HISYSEVENT_ADAPTER_H

#include <string>

namespace OHOS {
namespace Security {
namespace AccessToken {
enum SceneCode {
    SA_PUBLISH_FAILED,
    EVENTRUNNER_CREATE_ERROR,
    INIT_HAP_TOKENINFO_ERROR,
    INIT_NATIVE_TOKENINFO_ERROR,
    INIT_PERM_DEF_JSON_ERROR,
    TOKENID_NOT_EQUAL,
};
enum UpdatePermStatusErrorCode {
    GRANT_TEMP_PERMISSION_FAILED = 0,
    DLP_CHECK_FAILED = 1,
    UPDATE_PERMISSION_STATUS_FAILED = 2,
};
void ReportSysEventPerformance();
void ReportSysEventServiceStart(int32_t pid, uint32_t hapSize, uint32_t nativeSize, uint32_t permDefSize);
void ReportSysEventServiceStartError(SceneCode scene, const std::string& errMsg, int32_t errCode);
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_HISYSEVENT_ADAPTER_H
