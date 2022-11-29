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
#include "accesstoken_log.h"
#include "data_validator.h"
#include "permission_validator.h"
#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "DataTranslator"};
}

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
    return RET_SUCCESS;
}

int DataTranslator::TranslationIntoPermissionDef(const GenericValues& inGenericValues, PermissionDef& outPermissionDef)
{
    outPermissionDef.permissionName = inGenericValues.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
    outPermissionDef.bundleName = inGenericValues.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
    outPermissionDef.grantMode = inGenericValues.GetInt(TokenFiledConst::FIELD_GRANT_MODE);
    int aplNum = inGenericValues.GetInt(TokenFiledConst::FIELD_AVAILABLE_LEVEL);
    if (!DataValidator::IsAplNumValid(aplNum)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "Apl is wrong.");
        return RET_FAILED;
    }
    outPermissionDef.availableLevel = static_cast<ATokenAplEnum>(aplNum);
    outPermissionDef.provisionEnable = (inGenericValues.GetInt(TokenFiledConst::FIELD_PROVISION_ENABLE) == 1);
    outPermissionDef.distributedSceneEnable =
        (inGenericValues.GetInt(TokenFiledConst::FIELD_DISTRIBUTED_SCENE_ENABLE) == 1);
    outPermissionDef.label = inGenericValues.GetString(TokenFiledConst::FIELD_LABEL);
    outPermissionDef.labelId = inGenericValues.GetInt(TokenFiledConst::FIELD_LABEL_ID);
    outPermissionDef.description = inGenericValues.GetString(TokenFiledConst::FIELD_DESCRIPTION);
    outPermissionDef.descriptionId = inGenericValues.GetInt(TokenFiledConst::FIELD_DESCRIPTION_ID);
    return RET_SUCCESS;
}

int DataTranslator::TranslationIntoGenericValues(const PermissionStateFull& inPermissionState,
    const unsigned int grantIndex, GenericValues& outGenericValues)
{
    if (grantIndex >= inPermissionState.resDeviceID.size() || grantIndex >= inPermissionState.grantStatus.size() ||
        grantIndex >= inPermissionState.grantFlags.size()) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "perm status grant size is wrong");
        return RET_FAILED;
    }
    outGenericValues.Put(TokenFiledConst::FIELD_PERMISSION_NAME, inPermissionState.permissionName);
    outGenericValues.Put(TokenFiledConst::FIELD_DEVICE_ID, inPermissionState.resDeviceID[grantIndex]);
    outGenericValues.Put(TokenFiledConst::FIELD_GRANT_IS_GENERAL, inPermissionState.isGeneral ? 1 : 0);
    outGenericValues.Put(TokenFiledConst::FIELD_GRANT_STATE, inPermissionState.grantStatus[grantIndex]);
    outGenericValues.Put(TokenFiledConst::FIELD_GRANT_FLAG, inPermissionState.grantFlags[grantIndex]);
    return RET_SUCCESS;
}

int DataTranslator::TranslationIntoPermissionStateFull(const GenericValues& inGenericValues,
    PermissionStateFull& outPermissionState)
{
    outPermissionState.isGeneral =
        ((inGenericValues.GetInt(TokenFiledConst::FIELD_GRANT_IS_GENERAL) == 1) ? true : false);
    outPermissionState.permissionName = inGenericValues.GetString(TokenFiledConst::FIELD_PERMISSION_NAME);
    if (!DataValidator::IsPermissionNameValid(outPermissionState.permissionName)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "permission name is wrong");
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "permission name error");
        return RET_FAILED;
    }

    std::string devID = inGenericValues.GetString(TokenFiledConst::FIELD_DEVICE_ID);
    if (!DataValidator::IsDeviceIdValid(devID)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "devID is wrong");
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "permission deviceId error");
        return RET_FAILED;
    }
    outPermissionState.resDeviceID.push_back(devID);

    int grantStatus = (PermissionState)inGenericValues.GetInt(TokenFiledConst::FIELD_GRANT_STATE);
    if (!PermissionValidator::IsGrantStatusValid(grantStatus)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "grantStatus is wrong");
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "permission grant status error");
        return RET_FAILED;
    }
    outPermissionState.grantStatus.push_back(grantStatus);

    int grantFlag = (PermissionState)inGenericValues.GetInt(TokenFiledConst::FIELD_GRANT_FLAG);
    if (!PermissionValidator::IsPermissionFlagValid(grantFlag)) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "grantFlag is wrong");
        HiviewDFX::HiSysEvent::Write(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN, "PERMISSION_CHECK",
            HiviewDFX::HiSysEvent::EventType::FAULT, "CODE", LOAD_DATABASE_ERROR,
            "ERROR_REASON", "permission grant flag error");
        return RET_FAILED;
    }
    outPermissionState.grantFlags.push_back(grantFlag);
    return RET_SUCCESS;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
