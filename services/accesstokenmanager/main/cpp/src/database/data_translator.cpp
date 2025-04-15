/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "accesstoken_dfx_define.h"
#include "accesstoken_common_log.h"
#include "access_token_error.h"
#include "data_validator.h"
#include "permission_validator.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

int DataTranslator::TranslationIntoGenericValues(const PermissionDef& inPermissionDef, GenericValues& outGenericValues)
{
    outGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, inPermissionDef.permissionName);
    outGenericValues.Put(TokenFiledConst::FIELD_BUNDLE_NAME, inPermissionDef.bundleName);
    outGenericValues.Put(TokenFiledConst::FIELD_GRANT_MODE, inPermissionDef.grantMode);
    outGenericValues.Put(TokenFiledConst::FIELD_AVAILABLE_LEVEL, inPermissionDef.availableLevel);
    outGenericValues.Put(TokenFiledConst::FIELD_PROVISION_ENABLE, inPermissionDef.provisionEnable ? 1 : 0);
    outGenericValues.Put(TokenFiledConst::FIELD_DISTRIBUTED_SCENE_ENABLE,
        inPermissionDef.distributedSceneEnable ? 1 : 0);
    outGenericValues.Put(TokenFiledConst::FIELD_LABEL, inPermissionDef.label);
    outGenericValues.Put(TokenFiledConst::FIELD_LABEL_ID, inPermissionDef.labelId);
    outGenericValues.Put(TokenFiledConst::FIELD_DESCRIPTION, inPermissionDef.description);
    outGenericValues.Put(TokenFiledConst::FIELD_DESCRIPTION_ID, inPermissionDef.descriptionId);
    outGenericValues.Put(TokenFiledConst::FIELD_AVAILABLE_TYPE, inPermissionDef.availableType);
    outGenericValues.Put(TokenFiledConst::FIELD_KERNEL_EFFECT, inPermissionDef.isKernelEffect ? 1 : 0);
    outGenericValues.Put(TokenFiledConst::FIELD_HAS_VALUE, inPermissionDef.hasValue ? 1 : 0);
    return RET_SUCCESS;
}

int DataTranslator::TranslationIntoPermissionDef(const GenericValues& inGenericValues, PermissionDef& outPermissionDef)
{
    outPermissionDef.permissionName = inGenericValues.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
    outPermissionDef.bundleName = inGenericValues.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
    outPermissionDef.grantMode = inGenericValues.GetInt(TokenFiledConst::FIELD_GRANT_MODE);
    int aplNum = inGenericValues.GetInt(TokenFiledConst::FIELD_AVAILABLE_LEVEL);
    if (!DataValidator::IsAplNumValid(aplNum)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Apl is wrong.");
        return ERR_PARAM_INVALID;
    }
    outPermissionDef.availableLevel = static_cast<ATokenAplEnum>(aplNum);
    outPermissionDef.provisionEnable = (inGenericValues.GetInt(TokenFiledConst::FIELD_PROVISION_ENABLE) == 1);
    outPermissionDef.distributedSceneEnable =
        (inGenericValues.GetInt(TokenFiledConst::FIELD_DISTRIBUTED_SCENE_ENABLE) == 1);
    outPermissionDef.label = inGenericValues.GetString(TokenFiledConst::FIELD_LABEL);
    outPermissionDef.labelId = inGenericValues.GetInt(TokenFiledConst::FIELD_LABEL_ID);
    outPermissionDef.description = inGenericValues.GetString(TokenFiledConst::FIELD_DESCRIPTION);
    outPermissionDef.descriptionId = inGenericValues.GetInt(TokenFiledConst::FIELD_DESCRIPTION_ID);
    int availableType = inGenericValues.GetInt(TokenFiledConst::FIELD_AVAILABLE_TYPE);
    outPermissionDef.availableType = static_cast<ATokenAvailableTypeEnum>(availableType);
    outPermissionDef.isKernelEffect = (inGenericValues.GetInt(TokenFiledConst::FIELD_KERNEL_EFFECT) == 1);
    outPermissionDef.hasValue = (inGenericValues.GetInt(TokenFiledConst::FIELD_HAS_VALUE) == 1);
    return RET_SUCCESS;
}

int DataTranslator::TranslationIntoGenericValues(const PermissionStatus& inPermissionState,
    GenericValues& outGenericValues)
{
    outGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, inPermissionState.permissionName);
    outGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, "");
    outGenericValues.Put(TokenFiledConst::FIELD_GRANT_STATE, inPermissionState.grantStatus);
    int32_t grantFlag = static_cast<int32_t>(inPermissionState.grantFlag);
    outGenericValues.Put(TokenFiledConst::FIELD_GRANT_FLAG, grantFlag);
    return RET_SUCCESS;
}

int DataTranslator::TranslationIntoPermissionStatus(const GenericValues& inGenericValues,
    PermissionStatus& outPermissionState)
{
    outPermissionState.permissionName = inGenericValues.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
    if (!DataValidator::IsPermissionNameValid(outPermissionState.permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission name is wrong");
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "permission name error");
        return ERR_PARAM_INVALID;
    }

    int grantFlag = (PermissionFlag)inGenericValues.GetInt(TokenFiledConst::FIELD_GRANT_FLAG);
    if (!PermissionValidator::IsPermissionFlagValid(grantFlag)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GrantFlag is wrong");
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "permission grant flag error");
        return ERR_PARAM_INVALID;
    }
    outPermissionState.grantFlag = static_cast<uint32_t>(grantFlag);

    int grantStatus = (PermissionState)inGenericValues.GetInt(TokenFiledConst::FIELD_GRANT_STATE);
    if (!PermissionValidator::IsGrantStatusValid(grantStatus)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "GrantStatus is wrong");
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "permission grant status error");
        return ERR_PARAM_INVALID;
    }
    if (static_cast<uint32_t>(grantFlag) & PERMISSION_ALLOW_THIS_TIME) {
        grantStatus = PERMISSION_DENIED;
    }
    outPermissionState.grantStatus = grantStatus;

    return RET_SUCCESS;
}

int32_t DataTranslator::TranslationIntoExtendedPermission(
    const GenericValues& inGenericValues, PermissionWithValue& perm)
{
    perm.permissionName =  inGenericValues.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
    if (!DataValidator::IsPermissionNameValid(perm.permissionName)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Permission name is wrong");
        HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "permission name error");
        return ERR_PARAM_INVALID;
    }
    perm.value = inGenericValues.GetString(TokenFiledConst::FIELD_VALUE);

    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
