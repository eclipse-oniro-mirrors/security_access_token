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

#ifndef TO_STRING_H
#define TO_STRING_H

#include <string>
#include "permission_used_request.h"
#include "permission_used_result.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class ToString {
public:
    static void DetailUsedRecordToString(
        bool isAccessDetail, const std::vector<UsedRecordDetail>& detailRecord, std::string& infos);
    static void PermissionUsedRecordToString(
        const std::vector<PermissionUsedRecord>& permissionRecords, std::string& infos);
    static void BundleUsedRecordToString(const BundleUsedRecord& bundleRecord, std::string& infos);
    static void PermissionUsedResultToString(const PermissionUsedResult& result, std::string& infos);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // TO_STRING_H
