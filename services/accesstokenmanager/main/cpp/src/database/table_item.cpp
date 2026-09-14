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

#include "table_item.h"

#include <map>

#include "token_field_const.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
void ModuleInfoItem::BuildAddValue(std::vector<GenericValues>& addValues) const
{
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_MODULE_NAME, moduleName);
    addValue.Put(TokenFiledConst::FIELD_PATH, path);
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_TYPE, bundleType);
    addValue.PutBlob(TokenFiledConst::FIELD_PERSIST_DATA, persistData);
    addValues.emplace_back(addValue);
}

void BundleInfoItems::BuildAddValue(std::vector<GenericValues>& addValues) const
{
    for (const auto& moduleInfo : moduleInfoItems) {
        std::vector<GenericValues> moduleValues;
        moduleInfo.BuildAddValue(moduleValues);
        for (auto& addValue : moduleValues) {
            addValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
            addValue.Put(TokenFiledConst::FIELD_IS_PREINSTALLED, static_cast<int32_t>(isPreInstalled));
            addValues.emplace_back(addValue);
        }
    }
}

void BundleInfoItems::BuildDeleteValues(GenericValues& deleteValue) const
{
    deleteValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
}

void BundleInfoItems::BuildUpdateValues(GenericValues& deleteValue, std::vector<GenericValues>& addValues) const
{
    BuildDeleteValues(deleteValue);
    BuildAddValue(addValues);
}

void BundleInfoItems::BuildFindValues(GenericValues& findValue) const
{
    findValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
}

void BundleInfoItems::LoadFromDB(const std::vector<GenericValues>& values, std::vector<BundleInfoItems>& items)
{
    items.clear();
    std::map<std::string, size_t> bundleIndexMap;
    for (const auto& value : values) {
        std::string bundleName = value.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        auto iter = bundleIndexMap.find(bundleName);
        if (iter == bundleIndexMap.end()) {
            BundleInfoItems item;
            item.bundleName = bundleName;
            item.isPreInstalled = static_cast<bool>(value.GetInt(TokenFiledConst::FIELD_IS_PREINSTALLED));
            items.emplace_back(item);
            iter = bundleIndexMap.emplace(bundleName, items.size() - 1).first;
        }

        ModuleInfoItem moduleInfo;
        moduleInfo.moduleName = value.GetString(TokenFiledConst::FIELD_MODULE_NAME);
        moduleInfo.path = value.GetString(TokenFiledConst::FIELD_PATH);
        moduleInfo.bundleType =
            value.GetInt(TokenFiledConst::FIELD_BUNDLE_TYPE);
        moduleInfo.persistData = value.GetBlob(TokenFiledConst::FIELD_PERSIST_DATA);
        items[iter->second].moduleInfoItems.emplace_back(moduleInfo);
    }
}

void BundleInfoItems::GenerateAddList(const std::vector<GenericValues>& values, std::vector<AddInfo>& addInfoVec)
{
    AddInfo addInfo;
    addInfo.addType = type_;
    addInfo.addValues = values;
    addInfoVec.emplace_back(addInfo);
}

void BundleInfoItems::GenerateDelList(const std::vector<GenericValues>& values, DelInfo& delInfo)
{
    delInfo.delType = type_;
    if (!values.empty()) {
        delInfo.delValue = values.front();
    }
}

void HapTokenInfoItem::BuildAddValue(std::vector<GenericValues>& addValues) const
{
    GenericValues addValue;
    addValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
    addValue.Put(TokenFiledConst::FIELD_USER_ID, static_cast<int32_t>(userId));
    addValue.Put(TokenFiledConst::FIELD_BUNDLE_NAME, bundleName);
    addValue.Put(TokenFiledConst::FIELD_INST_INDEX, static_cast<int32_t>(instIndex));
    addValue.Put(TokenFiledConst::FIELD_DLP_TYPE, static_cast<int32_t>(dlpType));
    addValue.Put(TokenFiledConst::FIELD_APP_ID, appId);
    addValue.Put(TokenFiledConst::FIELD_DEVICE_ID, deviceId);
    addValue.Put(TokenFiledConst::FIELD_APL, static_cast<int32_t>(apl));
    addValue.Put(TokenFiledConst::FIELD_TOKEN_VERSION, static_cast<int32_t>(version));
    addValue.Put(TokenFiledConst::FIELD_TOKEN_ATTR, static_cast<int32_t>(tokenAttr));
    addValue.Put(TokenFiledConst::FIELD_API_VERSION, apiVersion);
    addValue.Put(TokenFiledConst::FIELD_FORBID_PERM_DIALOG, static_cast<int32_t>(permDialogCapState));
#ifdef SPM_DATA_ENABLE
    addValue.Put(TokenFiledConst::FIELD_UID, uid);
    addValue.Put(TokenFiledConst::FIELD_MIGRATED, static_cast<int32_t>(migrated));
    addValue.Put(TokenFiledConst::FIELD_RESERVED, static_cast<int32_t>(reserved));
#endif
    addValues.emplace_back(addValue);
}

void HapTokenInfoItem::BuildDeleteValues(GenericValues& deleteValue) const
{
    deleteValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
}

void HapTokenInfoItem::BuildUpdateValues(GenericValues& deleteValue, std::vector<GenericValues>& addValues) const
{
    BuildDeleteValues(deleteValue);
    BuildAddValue(addValues);
}

void HapTokenInfoItem::BuildFindValues(GenericValues& findValue) const
{
    findValue.Put(TokenFiledConst::FIELD_TOKEN_ID, static_cast<int32_t>(tokenId));
}

void HapTokenInfoItem::LoadFromDB(const std::vector<GenericValues>& values, std::vector<HapTokenInfoItem>& items)
{
    items.clear();
    for (const auto& value : values) {
        HapTokenInfoItem item;
        item.tokenId = static_cast<AccessTokenID>(value.GetInt(TokenFiledConst::FIELD_TOKEN_ID));
        item.userId = static_cast<uint32_t>(value.GetInt(TokenFiledConst::FIELD_USER_ID));
        item.bundleName = value.GetString(TokenFiledConst::FIELD_BUNDLE_NAME);
        item.instIndex = static_cast<uint32_t>(value.GetInt(TokenFiledConst::FIELD_INST_INDEX));
        item.dlpType = static_cast<HapDlpType>(value.GetInt(TokenFiledConst::FIELD_DLP_TYPE));
        item.appId = value.GetString(TokenFiledConst::FIELD_APP_ID);
        item.deviceId = value.GetString(TokenFiledConst::FIELD_DEVICE_ID);
        item.apl = static_cast<ATokenAplEnum>(value.GetInt(TokenFiledConst::FIELD_APL));
        item.version = static_cast<uint32_t>(value.GetInt(TokenFiledConst::FIELD_TOKEN_VERSION));
        item.tokenAttr = static_cast<uint32_t>(value.GetInt(TokenFiledConst::FIELD_TOKEN_ATTR));
        item.apiVersion = value.GetInt(TokenFiledConst::FIELD_API_VERSION);
        item.permDialogCapState = value.GetInt(TokenFiledConst::FIELD_FORBID_PERM_DIALOG) != 0;
#ifdef SPM_DATA_ENABLE
        item.uid = value.GetInt(TokenFiledConst::FIELD_UID);
        item.migrated = value.GetInt(TokenFiledConst::FIELD_MIGRATED) != 0;
        item.reserved = static_cast<ReservedType>(value.GetInt(TokenFiledConst::FIELD_RESERVED));
#endif
        items.emplace_back(item);
    }
}

void HapTokenInfoItem::GenerateAddList(const std::vector<GenericValues>& values, std::vector<AddInfo>& addInfoVec)
{
    AddInfo addInfo;
    addInfo.addType = type_;
    addInfo.addValues = values;
    addInfoVec.emplace_back(addInfo);
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
