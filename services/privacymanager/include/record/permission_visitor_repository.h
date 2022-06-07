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

#ifndef PERMISSION_VISITOR_REPOSITORY_H
#define PERMISSION_VISITOR_REPOSITORY_H

#include <vector>
#include "generic_values.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class PermissionVisitorRepository final {
public:
    virtual ~PermissionVisitorRepository();
    PermissionVisitorRepository();

    static PermissionVisitorRepository& GetInstance();

    bool AddVisitorValues(const GenericValues& visitorValues);
    bool FindVisitorValues(const GenericValues& andConditionValues,
        const GenericValues& orConditionValues, std::vector<GenericValues>& visitorValues);
    bool RemoveVisitorValues(const GenericValues& conditionValues);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // PERMISSION_VISITOR_REPOSITORY_H
