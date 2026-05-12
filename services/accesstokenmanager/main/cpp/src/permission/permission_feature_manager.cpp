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

#include "permission_feature_manager.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
PermissionFeatureManager::PermissionFeatureManager() = default;

PermissionFeatureManager& PermissionFeatureManager::GetInstance()
{
    static PermissionFeatureManager instance;
    return instance;
}

void PermissionFeatureManager::SetFeatures(const std::unordered_set<std::string>& features)
{
    std::lock_guard<std::mutex> lock(initMutex_);
    features_ = features;
}

bool PermissionFeatureManager::IsSupportFeature(const PermissionStatus& status)
{
    if (status.feature.empty()) {
        return true;
    }
    std::lock_guard<std::mutex> lock(initMutex_);
    return features_.find(status.feature) != features_.end();
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
