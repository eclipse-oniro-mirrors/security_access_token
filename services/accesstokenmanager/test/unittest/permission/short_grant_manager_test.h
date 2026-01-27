/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#ifndef SHORT_GRANT_MANAGER_TEST_H
#define SHORT_GRANT_MANAGER_TEST_H

#include <gtest/gtest.h>
#define private public
#include "short_grant_manager.h"
#include "accesstoken_manager_service.h"
#include "permission_manager.h"
#undef private
#ifdef EVENTHANDLER_ENABLE
#include "access_event_handler.h"
#endif

namespace OHOS {
namespace Security {
namespace AccessToken {
class ShortGrantManagerTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

    sptr<AccessTokenManagerService> accessTokenService_ = nullptr;
    sptr<ShortPermAppStateObserver> appStateObserver_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SHORT_GRANT_MANAGER_TEST_H
