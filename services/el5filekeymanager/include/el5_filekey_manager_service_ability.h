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

#ifndef EL5_FILEKEY_MANAGER_SERVICE_ABILITY_H
#define EL5_FILEKEY_MANAGER_SERVICE_ABILITY_H

#include "el5_filekey_manager_log.h"
#include "el5_filekey_manager_service.h"
#include "system_ability.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class El5FilekeyManagerServiceAbility final : public SystemAbility {
public:
    /**
     * @brief The constructor of the el5 filekey manager service ability.
     * @param systemAbilityId Indicates the system ability id.
     * @param runOnCreate Run the system ability on created.
     */
    El5FilekeyManagerServiceAbility(int32_t systemAbilityId, bool runOnCreate);

    /**
     * @brief The destructor.
     */
    virtual ~El5FilekeyManagerServiceAbility() final;

private:
    void OnStart(const SystemAbilityOnDemandReason &startReason) final;
    void OnStop() final;
    int32_t OnIdle(const SystemAbilityOnDemandReason &idleReason) final;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;

    DISALLOW_COPY_AND_MOVE(El5FilekeyManagerServiceAbility);
    DECLARE_SYSTEM_ABILITY(El5FilekeyManagerServiceAbility);

private:
    std::shared_ptr<El5FilekeyManagerService> service_;
};
}  // namespace AccessToken
}  // namespace Security
}  // namespace OHOS
#endif // EL5_FILEKEY_MANAGER_SERVICE_ABILITY_H
