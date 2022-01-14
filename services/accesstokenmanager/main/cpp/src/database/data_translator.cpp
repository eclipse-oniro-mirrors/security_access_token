/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "data_translator.h"

#include <memory>

#include "accesstoken_log.h"
#include "data_validator.h"
#include "field_const.h"
#include "permission_validator.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "DataTranslator"};
}

int DataTranslator::TranslationIntoGenericValues(const PermissionDef& inPermissionDef, GenericValues& outGenericValues)
{
    outGenericValues.Put(FIELD_PERMISSION_NAME, inPermissionDef.permissionName);
    outGenericValues.Put(FIELD_BUNDLE_NAME, inPermissionDef.bundleName);
    outGenericValues.Put(FIELD_GRANT_MODE, inPermissionDef.grantMode);
    outGenericValues.Put(FIELD_AVAILABLE_LEVEL, inPermissionDef.availableLevel);
    outGenericValues.Put(FIELD_PROVISION_ENABLE, inPermissionDef.provisionEnable ? 1 : 0);
    outGenericValues.Put(FIELD_DISTRIBUTED_SCENE_ENABLE, inPermissionDef.distributedSceneEnable ? 1 : 0);
    outGenericValues.Put(FIELD_LABEL, inPermissionDef.label);
    outGenericValues.Put(FIELD_LABEL_ID, inPermissionDef.labelId);
    outGenericValues.Put(FIELD_DESCRIPTION, inPermissionDef.description);
    outGenericValues.Put(FIELD_DESCRIPTION_ID, inPermissionDef.descriptionId);
    return RET_SUCCESS;
}

int DataTranslator::TranslationIntoPermissionDef(const GenericValues& inGenericValues, PermissionDef& outPermissionDef)
{
    outPermissionDef.permissionName = inGenericValues.GetString(FIELD_PERMISSION_NAME);
    outPermissionDef.bundleName = inGenericValues.GetString(FIELD_BUNDLE_NAME);
    outPermissionDef.grantMode = inGenericValues.GetInt(FIELD_GRANT_MODE);
    int aplNum = inGenericValues.GetInt(FIELD_AVAILABLE_LEVEL);
    if (!DataValidator::IsAplNumValid(aplNum)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "%{public}s:Apl is wrong.", __func__);
        return RET_FAILED;
    }
    outPermissionDef.availableLevel = (ATokenAplEnum)aplNum;
    outPermissionDef.provisionEnable = (inGenericValues.GetInt(FIELD_PROVISION_ENABLE) == 1);
    outPermissionDef.distributedSceneEnable = (inGenericValues.GetInt(FIELD_DISTRIBUTED_SCENE_ENABLE) == 1);
    outPermissionDef.label = inGenericValues.GetString(FIELD_LABEL);
    outPermissionDef.labelId = inGenericValues.GetInt(FIELD_LABEL_ID);
    outPermissionDef.description = inGenericValues.GetString(FIELD_DESCRIPTION);
    outPermissionDef.descriptionId = inGenericValues.GetInt(FIELD_DESCRIPTION_ID);
    return RET_SUCCESS;
}

int DataTranslator::TranslationIntoGenericValues(const PermissionStateFull& inPermissionState,
    const unsigned int grantIndex, GenericValues& outGenericValues)
{
    if (grantIndex >= inPermissionState.resDeviceID.size() || grantIndex >= inPermissionState.grantStatus.size()
        || grantIndex >= inPermissionState.grantFlags.size()) {
        ACCESSTOKEN_LOG_WARN(LABEL, "%{public}s: perm status grant size is wrong", __func__);
        return RET_FAILED;
    }
    outGenericValues.Put(FIELD_PERMISSION_NAME, inPermissionState.permissionName);
    outGenericValues.Put(FIELD_DEVICE_ID, inPermissionState.resDeviceID[grantIndex]);
    outGenericValues.Put(FIELD_GRANT_IS_GENERAL, inPermissionState.isGeneral ? 1 : 0);
    outGenericValues.Put(FIELD_GRANT_STATE, inPermissionState.grantStatus[grantIndex]);
    outGenericValues.Put(FIELD_GRANT_FLAG, inPermissionState.grantFlags[grantIndex]);
    return RET_SUCCESS;
}

int DataTranslator::TranslationIntoPermissionStateFull(const GenericValues& inGenericValues,
    PermissionStateFull& outPermissionState)
{
    outPermissionState.isGeneral = ((inGenericValues.GetInt(FIELD_GRANT_IS_GENERAL) == 1) ? true : false);
    outPermissionState.permissionName = inGenericValues.GetString(FIELD_PERMISSION_NAME);
    if (!DataValidator::IsPermissionNameValid(outPermissionState.permissionName)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "%{public}s: permission name is wrong", __func__);
        return RET_FAILED;
    }

    std::string devID = inGenericValues.GetString(FIELD_DEVICE_ID);
    if (!DataValidator::IsDeviceIdValid(devID)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "%{public}s: devID is wrong", __func__);
        return RET_FAILED;
    }
    outPermissionState.resDeviceID.push_back(devID);

    int grantStatus = (PermissionState)inGenericValues.GetInt(FIELD_GRANT_STATE);
    if (!PermissionValidator::IsGrantStatusValid(grantStatus)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "%{public}s: grantStatus is wrong", __func__);
        return RET_FAILED;
    }
    outPermissionState.grantStatus.push_back(grantStatus);

    int grantFlag = (PermissionState)inGenericValues.GetInt(FIELD_GRANT_FLAG);
    if (!PermissionValidator::IsPermissionFlagValid(grantFlag)) {
        ACCESSTOKEN_LOG_WARN(LABEL, "%{public}s: grantFlag is wrong", __func__);
        return RET_FAILED;
    }
    outPermissionState.grantFlags.push_back(grantFlag);
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
