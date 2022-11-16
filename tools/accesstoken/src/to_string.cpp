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

namespace OHOS {
namespace Security {
namespace AccessToken {
void ToString::DetailUsedRecordToString(
    bool isAccessDetail, const std::vector<UsedRecordDetail>& detailRecord, std::string& infos)
{
    if (isAccessDetail) {
        infos.append(R"(          "accessRecords": [)");
    } else {
        infos.append(R"(          "rejectRecords": [)");
    }
    infos.append("\n");
    for (const auto& detail : detailRecord) {
        infos.append("              {");
        infos.append("\n");
        infos.append(R"(                  "status": ")" + std::to_string(detail.status) + R"(")" + ",\n");
        infos.append(R"(                  "timestamp": ")" + std::to_string(detail.timestamp) + R"(")" + ",\n");
        infos.append(R"(                  "duration": )" + std::to_string(detail.accessDuration) + ",\n");
        infos.append("              },");
        infos.append("\n");
    }

    infos.append("          ]");
    infos.append("\n");
}

void ToString::PermissionUsedRecordToString(
    const std::vector<PermissionUsedRecord>& permissionRecords, std::string& infos)
{
    infos.append(R"(  "permissionRecords": [)");
    infos.append("\n");

    for (const auto& perm : permissionRecords) {
        infos.append("      {");
        infos.append("\n");
        infos.append(R"(          "permissionName": ")" + perm.permissionName + R"(")" + ",\n");
        infos.append(R"(          "accessCount": ")" + std::to_string(perm.accessCount) + R"(")" + ",\n");
        infos.append(R"(          "rejectCount": )" + std::to_string(perm.rejectCount) + ",\n");
        infos.append(R"(          "lastAccessTime": )" + std::to_string(perm.lastAccessTime) + ",\n");
        infos.append(R"(          "lastRejectTime": )" + std::to_string(perm.lastRejectTime) + ",\n");
        infos.append(R"(          "lastAccessDuration": )" + std::to_string(perm.lastAccessDuration) + ",\n");
        ToString::DetailUsedRecordToString(true, perm.accessRecords, infos);
        ToString::DetailUsedRecordToString(false, perm.rejectRecords, infos);
        infos.append("      },");
        infos.append("\n");
    }

    infos.append("  ]");
    infos.append("\n");
}

void ToString::BundleUsedRecordToString(const BundleUsedRecord& bundleRecord, std::string& infos)
{
    infos.append("{");
    infos.append("\n");
    infos.append(R"(  "tokenId": )" + std::to_string(bundleRecord.tokenId) + ",\n");
    infos.append(R"(  "isRemote": )" + std::to_string(bundleRecord.isRemote) + ",\n");
    infos.append(R"(  "bundleName": )" + bundleRecord.bundleName + ",\n");
    infos.append(R"(  "deviceId": )" + bundleRecord.deviceId + ",\n");

    ToString::PermissionUsedRecordToString(bundleRecord.permissionRecords, infos);

    infos.append("}");
    infos.append("\n");
}

void ToString::PermissionUsedResultToString(const PermissionUsedResult& result, std::string& infos)
{
    if (result.bundleRecords.empty()) {
        return;
    }
    infos.append(R"("beginTime": )" + std::to_string(result.beginTimeMillis) + ",\n");
    infos.append(R"("endTime": )" + std::to_string(result.endTimeMillis) + ",\n");

    for (const auto& res : result.bundleRecords) {
        ToString::BundleUsedRecordToString(res, infos);
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS