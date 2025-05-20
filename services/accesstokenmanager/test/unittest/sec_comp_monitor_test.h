/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SEC_COMP_MONITOR_TEST_H
#define SEC_COMP_MONITOR_TEST_H

#include <gtest/gtest.h>

#define private public
#include "sec_comp_monitor.h"
#undef private

namespace OHOS {
namespace Security {
namespace AccessToken {
class SecCompMonitorTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

    std::shared_ptr<SecCompUsageObserver> appStateObserver_ = nullptr;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // SEC_COMP_MONITOR_TEST_H
