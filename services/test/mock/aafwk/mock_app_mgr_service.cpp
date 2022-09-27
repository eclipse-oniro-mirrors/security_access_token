/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "mock_app_mgr_service.h"
#include <gtest/gtest.h>

namespace OHOS {
namespace AppExecFwk {
int32_t MockAppMgrService::GetForegroundApplications(std::vector<AppStateData> &list)
{
    AppStateData data;
    data.bundleName = "ohos.test.access_token";
    data.pid = 0;
    data.accessTokenId = 0;
    data.state = 1;
    list.emplace_back(data);
    return 0;
}

int32_t MockAppMgrService::RegisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer,
    const std::vector<std::string>& bundleNameList)
{
    if (observer == nullptr || observer == observer_) {
        return -1;
    }
    GTEST_LOG_(INFO) << "register: " << observer;
    observer_ = observer;
    return 0;
}

int32_t MockAppMgrService::UnregisterApplicationStateObserver(const sptr<IApplicationStateObserver>& observer)
{
    if (observer == nullptr || observer != observer_) {
        return -1;
    }
    GTEST_LOG_(INFO) << "unregister: " << observer;
    observer_ = nullptr;
    return 0;
}

void MockAppMgrService::SwitchForeOrBackGround(uint32_t tokenId, int32_t flag)
{
    if (observer_ == nullptr) {
        return;
    }
    AppStateData data;
    data.bundleName = "ohos.test.access_token";
    data.pid = 0;
    data.accessTokenId = tokenId;
    data.state = flag;
    observer_->OnForegroundApplicationChanged(data);
}
}
}