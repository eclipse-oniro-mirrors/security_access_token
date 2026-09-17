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
class AddSpmDataTask final {
public:
    /**
     * Note: all objects referenced by params (hapInfo, noCachedInfo, permBriefDataList,
     * extendPermList and oldPermBriefDataList) must stay alive from task construction
     * until Add()/Rollback() completes, because the task keeps references or pointers
     * to them for later kernel sync and rollback.
     */
    explicit AddSpmDataTask(const std::vector<SpmDataParam>& params);
    ~AddSpmDataTask();

    AddSpmDataTask(const AddSpmDataTask&) = delete;
    AddSpmDataTask& operator=(const AddSpmDataTask&) = delete;
    AddSpmDataTask(AddSpmDataTask&&) = delete;
    AddSpmDataTask& operator=(AddSpmDataTask&&) = delete;

    /**
     * Add spm data entries and permission data to kernel in batch.
     *
     * @param errIndex Output. Index of the first failed entry on failure.
     * @return RET_SUCCESS on success, error code otherwise.
     */
    int32_t Add(uint32_t& errIndex);

    /**
     * Rollback previously added spm entries and permission data.
     *
     * @return RET_SUCCESS on success, error code otherwise.
     */
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
