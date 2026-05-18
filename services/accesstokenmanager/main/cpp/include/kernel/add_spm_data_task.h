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

#ifndef ADD_SPM_DATA_TASK_H
#define ADD_SPM_DATA_TASK_H

#include <functional>
#include <vector>

#include "permission_kernel_utils.h"
#include "spm_data_kernel_common.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class HapTokenInfoInner;
class SpmDataTaskItem;
class AddSpmDataTask final {
public:
    explicit AddSpmDataTask(const std::vector<SpmDataParam>& params);
    ~AddSpmDataTask();

    int32_t Add(uint32_t& errIndex);
    int32_t Rollback();

private:
    std::vector<SpmDataTaskItem> items_;
    bool isBuildSuccess_ = true;
    bool updateWithPerm_ = false;
    size_t spmDataSuccessCount_ = 0;
    size_t permDataSuccessCount_ = 0;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // ADD_SPM_DATA_TASK_H
