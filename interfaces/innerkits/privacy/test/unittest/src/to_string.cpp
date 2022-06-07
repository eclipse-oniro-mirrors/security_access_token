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
void ToString::PermissionUsedRecordToString(const PermissionUsedRecord& permissionRecord, std::string& infos)
{
    infos.append(R"(  "permissionRecords": [)");
    infos.append("\n");

    infos.append(R"(      "permissionName": ")" + permissionRecord.permissionName + R"(")" + ",\n");
    infos.append(R"(      "accessCount": ")" + std::to_string(permissionRecord.accessCount) + R"(")" + ",\n");
    infos.append(R"(      "rejectCount": )" + std::to_string(permissionRecord.rejectCount) + ",\n");
    infos.append(R"(      "lastAccessTime": )" + std::to_string(permissionRecord.lastAccessTime) + ",\n");
    infos.append(R"(      "lastRejectTime": )" + std::to_string(permissionRecord.lastRejectTime) + ",\n");
    infos.append(R"(      "lastAccessDuration": )" + std::to_string(permissionRecord.lastAccessDuration) + ",\n");
    infos.append("  ],\n");
}

void ToString::BundleUsedRecordToString(const BundleUsedRecord& bundleRecord, std::string& infos)
{
    infos.append(R"({)");
    infos.append("\n");
    infos.append(R"(  "bundleName": )" + bundleRecord.bundleName + ",\n");
    infos.append(R"(  "deviceId": )" + bundleRecord.deviceId + ",\n");

    for (auto perm : bundleRecord.permissionRecords) {
        ToString::PermissionUsedRecordToString(perm, infos);
    }

    infos.append("}");
}

void ToString::PermissionUsedResultToString(const PermissionUsedResult& result, std::string& infos)
{
    infos.append(R"("beginTimeMillis": )" + std::to_string(result.beginTimeMillis) + ",\n");
    infos.append(R"("endTimeMillis": )" + std::to_string(result.endTimeMillis) + ",\n");

    for (auto res : result.bundleRecords) {
        ToString::BundleUsedRecordToString(res, infos);
    }
    infos.append("\n");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS