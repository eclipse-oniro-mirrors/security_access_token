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

#include "to_string.h"

#include "constant_common.h"
#include "permission_map.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
static void DetailUsedRecordToJson(const std::vector<UsedRecordDetail>& detailRecord, CJsonUnique& detailsJson)
{
    for (const auto& detail : detailRecord) {
        CJsonUnique recordJson = CreateJson();
        (void)AddIntToJson(recordJson, "status", detail.status);
        (void)AddIntToJson(recordJson, "lockScreenStatus", detail.lockScreenStatus);
        (void)AddInt64ToJson(recordJson, "timestamp", detail.timestamp);
        (void)AddInt64ToJson(recordJson, "duration", detail.accessDuration);
        (void)AddIntToJson(recordJson, "count", detail.count);
        (void)AddIntToJson(recordJson, "usedType", detail.type);

        (void)AddObjToArray(detailsJson, recordJson);
    }
}

std::string ToString::PermissionUsedResultToString(const PermissionUsedResult& result)
{
    CJsonUnique responseJsion = CreateJson();
    (void)AddInt64ToJson(responseJsion, "beginTime", result.beginTimeMillis);
    (void)AddInt64ToJson(responseJsion, "endTime", result.endTimeMillis);
    
    CJsonUnique bundleRecordsJson = CreateJsonArray();
    for (const auto& bundleRecord : result.bundleRecords) {
        CJsonUnique bundleRecordJson = CreateJson();
        (void)AddUnsignedIntToJson(bundleRecordJson, "tokenId", bundleRecord.tokenId);
        (void)AddBoolToJson(bundleRecordJson, "isRemote", bundleRecord.isRemote);
        (void)AddStringToJson(bundleRecordJson, "bundleName", bundleRecord.bundleName);

        CJsonUnique permRecordListJson = CreateJsonArray();
        for (const auto& permRecord : bundleRecord.permissionRecords) {
            CJsonUnique permRecordJson = CreateJson();
            (void)AddStringToJson(permRecordJson, "permissionName", permRecord.permissionName);
            (void)AddIntToJson(permRecordJson, "accessCount", permRecord.accessCount);
            (void)AddIntToJson(permRecordJson, "secAccessCount", permRecord.secAccessCount);
            (void)AddIntToJson(permRecordJson, "rejectCount", permRecord.rejectCount);
            (void)AddInt64ToJson(permRecordJson, "lastAccessTime", permRecord.lastAccessTime);
            (void)AddInt64ToJson(permRecordJson, "lastRejectTime", permRecord.lastRejectTime);
            (void)AddInt64ToJson(permRecordJson, "lastAccessDuration", permRecord.lastAccessDuration);

            CJsonUnique accessDetailsJson = CreateJsonArray();
            DetailUsedRecordToJson(permRecord.accessRecords, accessDetailsJson);
            (void)AddObjToJson(permRecordJson, "accessRecords", accessDetailsJson);

            CJsonUnique rejectDetailsJson = CreateJsonArray();
            DetailUsedRecordToJson(permRecord.rejectRecords, rejectDetailsJson);
            (void)AddObjToJson(permRecordJson, "rejectRecords", rejectDetailsJson);

            (void)AddObjToArray(permRecordListJson, permRecordJson);
        }
        (void)AddObjToJson(bundleRecordJson, "permissionRecords", permRecordListJson);
        (void)AddObjToArray(bundleRecordsJson, bundleRecordJson);
    }
    (void)AddObjToJson(responseJsion, "bundleRecords", bundleRecordsJson);
    return JsonToStringFormatted(responseJsion.get());
}

std::string ToString::PermissionUsedTypeInfoToString(const std::vector<PermissionUsedTypeInfo>& typeInfos)
{
    CJsonUnique useTypeInfoJson = CreateJsonArray();
    for (const auto& usedType : typeInfos) {
        CJsonUnique tmpJson = CreateJson();
        (void)AddUnsignedIntToJson(tmpJson, "tokenId", usedType.tokenId);
        (void)AddStringToJson(tmpJson, "permissionName", usedType.permissionName);
        (void)AddIntToJson(tmpJson, "type", usedType.type);
        (void)AddObjToArray(useTypeInfoJson, tmpJson);
    }
    return JsonToStringFormatted(useTypeInfoJson.get());
}

static std::string FormatApl(ATokenAplEnum availableLevel)
{
    std::string apl = "";
    switch (availableLevel) {
        case ATokenAplEnum::APL_NORMAL:
            apl = "NORMAL";
            break;
        case ATokenAplEnum::APL_SYSTEM_BASIC:
            apl = "SYSTEM_BASIC";
            break;
        case ATokenAplEnum::APL_SYSTEM_CORE:
            apl = "SYSTEM_CORE";
            break;
        default:
            apl = "invalid apl";
            break;
    }
    return apl;
}

static std::string FormatAvailableType(ATokenAvailableTypeEnum availableType)
{
    std::string type = "";
    switch (availableType) {
        case ATokenAvailableTypeEnum::NORMAL:
            type = "NORMAL";
            break;
        case ATokenAvailableTypeEnum::SYSTEM:
            type = "SYSTEM";
            break;
        case ATokenAvailableTypeEnum::MDM:
            type = "MDM";
            break;
        case ATokenAvailableTypeEnum::SYSTEM_AND_MDM:
            type = "MDM";
            break;
        case ATokenAvailableTypeEnum::SERVICE:
            type = "SERVICE";
            break;
        case ATokenAvailableTypeEnum::ENTERPRISE_NORMAL:
            type = "ENTERPRISE_NORMAL";
            break;
        default:
            type = "invalid type";
            break;
    }
    return type;
}

static void PermDefToJson(const PermissionBriefDef& briefDef, CJsonUnique& permDefJson)
{
    std::string grantMode;
    if (briefDef.grantMode == GrantMode::USER_GRANT) {
        grantMode = "USER_GRANT";
    } else if (briefDef.grantMode == GrantMode::SYSTEM_GRANT) {
        grantMode = "SYSTEM_GRANT";
    } else if (briefDef.grantMode == GrantMode::MANUAL_SETTINGS) {
        grantMode = "MANUAL_SETTINGS";
    } else {
        grantMode = "UNDEFINED";
    }
    (void)AddStringToJson(permDefJson, "permissionName", briefDef.permissionName);
    (void)AddStringToJson(permDefJson, "grantMode", grantMode);
    (void)AddStringToJson(permDefJson, "availableLevel", FormatApl(briefDef.availableLevel));
    (void)AddStringToJson(permDefJson, "availableType", FormatAvailableType(briefDef.availableType));
    (void)AddBoolToJson(permDefJson, "provisionEnable", briefDef.provisionEnable);
    (void)AddBoolToJson(permDefJson, "distributedSceneEnable", briefDef.distributedSceneEnable);
    (void)AddBoolToJson(permDefJson, "isKernelEffect", briefDef.isKernelEffect);
    (void)AddBoolToJson(permDefJson, "hasValue", briefDef.hasValue);
}

std::string ToString::DumpPermDefinition(const std::string& permissionName)
{
    CJsonUnique permDefJson = nullptr;
    if (permissionName.empty()) {
        size_t count = GetDefPermissionsSize();
        permDefJson = CreateJsonArray();
        for (size_t i = 0; i < count; ++i) {
            PermissionBriefDef briefDef;
            GetPermissionBriefDef(i, briefDef);
            CJsonUnique sinPrmDefJson = CreateJson();
            PermDefToJson(briefDef, sinPrmDefJson);

            (void)AddObjToArray(permDefJson, sinPrmDefJson);
        }
    } else {
        uint32_t code = 0;
        if (TransferPermissionToOpcode(permissionName, code)) {
            PermissionBriefDef briefDef;
            GetPermissionBriefDef(code, briefDef);
            permDefJson = CreateJson();
            PermDefToJson(briefDef, permDefJson);
        }
    }
    return JsonToStringFormatted(permDefJson.get());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS