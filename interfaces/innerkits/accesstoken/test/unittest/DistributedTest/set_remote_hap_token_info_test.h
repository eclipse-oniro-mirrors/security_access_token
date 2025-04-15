/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef GET_REMOTE_HAP_TOKEN_INFO_TEST_H
#define GET_REMOTE_HAP_TOKEN_INFO_TEST_H

#include <gtest/gtest.h>

#include "access_token.h"
#ifdef TOKEN_SYNC_ENABLE
#include "device_manager.h"
#endif
#include "permission_def.h"
#include "permission_state_full.h"

namespace OHOS {
namespace Security {
namespace AccessToken {

#ifdef TOKEN_SYNC_ENABLE
class TestDmInitCallback final : public OHOS::DistributedHardware::DmInitCallback {
    void OnRemoteDied() override
    {}
};
#endif
class SetRemoteHapTokenInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::string udid_;
    std::string networkId_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // GET_REMOTE_HAP_TOKEN_INFO_TEST_H