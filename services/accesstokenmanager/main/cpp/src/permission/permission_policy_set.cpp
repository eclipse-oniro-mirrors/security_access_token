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

#include "permission_policy_set.h"

#include "accesstoken_log.h"
#include "data_storage.h"
#include "data_translator.h"
#include "field_const.h"
#include "permission_validator.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_ACCESSTOKEN, "PermissionPolicySet"};
}

std::shared_ptr<PermissionPolicySet> PermissionPolicySet::BuildPermissionPolicySet(
    AccessTokenID tokenId, const std::vector<PermissionDef>& permList,
    const std::vector<PermissionStateFull>& permStateList)
{
    std::shared_ptr<PermissionPolicySet> policySet = std::make_shared<PermissionPolicySet>();
    if (policySet != nullptr) {
        PermissionValidator::FilterInvalidPermisionDef(permList, policySet->permList_);
        PermissionValidator::FilterInvalidPermisionState(permStateList, policySet->permStateList_);
        policySet->tokenId_ = tokenId;
    }
    return policySet;
}

void PermissionPolicySet::UpdatePermDef(PermissionDef& permOld, const PermissionDef& permNew)
{
    permOld.bundleName = permNew.bundleName;
    permOld.grantMode = permNew.grantMode;
    permOld.availableScope = permNew.availableScope;
    permOld.label = permNew.label;
    permOld.labelId = permNew.labelId;
    permOld.description = permNew.description;
    permOld.descriptionId = permNew.descriptionId;
}

void PermissionPolicySet::UpdatePermStateFull(PermissionStateFull& permOld, const PermissionStateFull& permNew)
{
    if (permOld.isGeneral != permNew.isGeneral) {
        permOld.resDeviceID.clear();
        permOld.grantStatus.clear();
        permOld.grantFlags.clear();
        permOld.isGeneral = permNew.isGeneral;
    }
}

void PermissionPolicySet::Update(const std::vector<PermissionDef>& permList,
    const std::vector<PermissionStateFull>& permStateList)
{
    for (const PermissionDef& permNew : permList) {
        for (PermissionDef& permOld : permList_) {
            if (permNew.permissionName == permOld.permissionName) {
                UpdatePermDef(permOld, permNew);
                break;
            }
        }
        permList_.emplace_back(permNew);
    }

    for (const PermissionStateFull& permStateNew : permStateList) {
        for (PermissionStateFull& permStateOld : permStateList_) {
            if (permStateNew.permissionName == permStateOld.permissionName) {
                UpdatePermStateFull(permStateOld, permStateNew);
                break;
            }
        }
        permStateList_.emplace_back(permStateNew);
    }
}

std::shared_ptr<PermissionPolicySet> PermissionPolicySet::RestorePermissionPolicy(AccessTokenID tokenId,
    const std::vector<GenericValues>& permDefRes, const std::vector<GenericValues>& permStateRes)
{
    std::shared_ptr<PermissionPolicySet> policySet = std::make_shared<PermissionPolicySet>();
    if (policySet == nullptr) {
        ACCESSTOKEN_LOG_ERROR(LABEL, "%{public}s: tokenId 0x%{public}x new failed.", __func__, tokenId);
        return nullptr;
    }
    policySet->tokenId_ = tokenId;

    for (GenericValues defValue : permDefRes) {
        if ((AccessTokenID)defValue.GetInt(FIELD_TOKEN_ID) == tokenId) {
            PermissionDef def;
            DataTranslator::TranslationIntoPermissionDef(defValue, def);
            policySet->permList_.emplace_back(def);
        }
    }

    for (GenericValues stateValue : permStateRes) {
        if ((AccessTokenID)stateValue.GetInt(FIELD_TOKEN_ID) == tokenId) {
            PermissionStateFull state;
            DataTranslator::TranslationIntoPermissionStateFull(stateValue, state);
            MergePermissionStateFull(policySet->permStateList_, state);
        }
    }
    return policySet;
}

void PermissionPolicySet::MergePermissionStateFull(std::vector<PermissionStateFull>& permStateList,
    const PermissionStateFull& state)
{
    for (auto iter = permStateList.begin(); iter != permStateList.end(); iter++) {
        if (state.permissionName == iter->permissionName) {
            iter->resDeviceID.emplace_back(state.resDeviceID[0]);
            iter->grantStatus.emplace_back(state.grantStatus[0]);
            iter->grantFlags.emplace_back(state.grantFlags[0]);
            return;
        }
    }
    permStateList.emplace_back(state);
}

void PermissionPolicySet::StorePermissionDef(std::vector<GenericValues>& valueList) const
{
    for (auto permissionDef : permList_) {
        GenericValues genericValues;
        genericValues.Put(FIELD_TOKEN_ID, tokenId_);
        DataTranslator::TranslationIntoGenericValues(permissionDef, genericValues);
        valueList.emplace_back(genericValues);
    }
}

void PermissionPolicySet::StorePermissionState(std::vector<GenericValues>& valueList) const
{
    for (auto permissionState : permStateList_) {
        if (permissionState.isGeneral) {
            GenericValues genericValues;
            genericValues.Put(FIELD_TOKEN_ID, tokenId_);
            DataTranslator::TranslationIntoGenericValues(permissionState, 0, genericValues);
            valueList.emplace_back(genericValues);
            continue;
        }

        unsigned int stateSize = permissionState.resDeviceID.size();
        for (unsigned int i = 0; i < stateSize; i++) {
            GenericValues genericValues;
            genericValues.Put(FIELD_TOKEN_ID, tokenId_);
            DataTranslator::TranslationIntoGenericValues(permissionState, i, genericValues);
            valueList.emplace_back(genericValues);
        }
    }
}

void PermissionPolicySet::StorePermissionPolicySet(std::vector<GenericValues>& permDefValueList,
    std::vector<GenericValues>& permStateValueList) const
{
    StorePermissionDef(permDefValueList);
    StorePermissionState(permStateValueList);
}

void PermissionPolicySet::PermDefToString(const PermissionDef& def, std::string& info) const
{
    info.append(R"({"permissionName": ")" + def.permissionName + R"(")");
    info.append(R"(, "bundleName": ")" + def.bundleName + R"(")");
    info.append(R"(, "grantMode": )" + std::to_string(def.grantMode));
    info.append(R"(, "availableScope": )" + std::to_string(def.availableScope));
    info.append(R"(, "label": ")" + def.label + R"(")");
    info.append(R"(, "labelId": )" + std::to_string(def.labelId));
    info.append(R"(, "description": ")" + def.description + R"(")");
    info.append(R"(, "descriptionId": )" + std::to_string(def.descriptionId));
    info.append(R"(})");
}

void PermissionPolicySet::PermStateFullToString(const PermissionStateFull& state, std::string& info) const
{
    info.append(R"({"permissionName": ")" + state.permissionName + R"(")");
    info.append(R"(, "isGeneral": )" + std::to_string(state.isGeneral));

    info.append(R"(, "resDeviceIDList": [ )");
    for (auto iter = state.resDeviceID.begin(); iter != state.resDeviceID.end(); iter++) {
        info.append(R"({"resDeviceID": ")" + *iter + R"("})");
        if (iter != (state.resDeviceID.end() - 1)) {
            info.append(",");
        }
    }

    info.append(R"(], "grantStatusList": [)");
    for (auto iter = state.grantStatus.begin(); iter != state.grantStatus.end(); iter++) {
        info.append(R"({"grantStatus": )" + std::to_string(*iter) + "}");
        if (iter != (state.grantStatus.end() - 1)) {
            info.append(",");
        }
    }

    info.append(R"(], "grantFlagsList": [)");
    for (auto iter = state.grantFlags.begin(); iter != state.grantFlags.end(); iter++) {
        info.append(R"({"grantFlag": )" + std::to_string(*iter) + "}");
        if (iter != (state.grantFlags.end() - 1)) {
            info.append(",");
        }
    }

    info.append(R"(]})");
}

void PermissionPolicySet::ToString(std::string& info) const
{
    info.append(R"(, "permDefList": [)");
    for (auto iter = permList_.begin(); iter != permList_.end(); iter++) {
        PermDefToString(*iter, info);
        if (iter != (permList_.end() - 1)) {
            info.append(",");
        }
    }
    info.append("]");

    info.append(R"(, "permStateList": [)");
    for (auto iter = permStateList_.begin(); iter != permStateList_.end(); iter++) {
        PermStateFullToString(*iter, info);
        if (iter != (permStateList_.end() - 1)) {
            info.append(",");
        }
    }
    info.append("]");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
