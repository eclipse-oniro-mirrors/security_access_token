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

#ifndef ACCESSTOKEN_DLP_PERMISSION_SET_MANAGER_H
#define ACCESSTOKEN_DLP_PERMISSION_SET_MANAGER_H

#include <map>
#include <vector>

#include "nocopyable.h"
#include "permission_dlp_mode.h"
#include "permission_state_full.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class DlpPermissionSetManager final {
public:
    static DlpPermissionSetManager& GetInstance();
    virtual ~DlpPermissionSetManager();

    int32_t UpdatePermStateWithDlpInfo(int32_t dlpType, std::vector<PermissionStateFull>& permStateList);
    bool IsPermStateNeedUpdate(int32_t dlpType, int32_t dlpMode);
    void ProcessDlpPermInfos(const std::vector<PermissionDlpMode>& info);
    int32_t GetPermDlpMode(const std::string& permissionName);

private:
    DlpPermissionSetManager();
    DISALLOW_COPY_AND_MOVE(DlpPermissionSetManager);
    void ProcessDlpPermsInfos(std::vector<PermissionDlpMode>& dlpPerms);

    /**
     * key: the permission name.
     * value: the mode of permission.
     */
    std::map<std::string, int32_t> dlpPermissionModeMap_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESSTOKEN_DLP_PERMISSION_SET_MANAGER_H
