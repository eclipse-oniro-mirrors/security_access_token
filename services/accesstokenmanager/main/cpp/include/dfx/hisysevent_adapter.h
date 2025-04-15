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
#include "access_token.h"

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
enum CommonSceneCode {
    AT_COMMOM_START = 0,
    AT_COMMON_FINISH = 1,
};
enum AddHapSceneCode {
    INSTALL_START = 0,
    TOKEN_ID_CHANGE,
    INIT,
    MAP,
    INSTALL_FINISH,
};
struct AccessTokenDfxInfo {
    AddHapSceneCode sceneCode;
    AccessTokenID tokenId;
    AccessTokenID oriTokenId;
    AccessTokenIDEx tokenIdEx;
    int32_t userId;
    std::string bundleName;
    int32_t instIndex;
    HapDlpType dlpType;
    bool isRestore;
    std::string permInfo;
    std::string aclInfo;
    std::string preauthInfo;
    std::string extendInfo;
    uint64_t duration;
    int32_t errorCode;
    int32_t pid;
    uint32_t hapSize;
    uint32_t nativeSize;
    uint32_t permDefSize;
    uint32_t dlpSize;
    uint32_t parseConfigFlag;
};
void ReportSysEventPerformance();
void ReportSysEventServiceStart(const AccessTokenDfxInfo& info);
void ReportSysEventServiceStartError(SceneCode scene, const std::string& errMsg, int32_t errCode);
void ReportSysCommonEventError(int32_t ipcCode, int32_t errCode);
void ReportSysEventAddHap(const AccessTokenDfxInfo& info);

} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_HISYSEVENT_ADAPTER_H
