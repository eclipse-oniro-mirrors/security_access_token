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

#include "sec_comp_monitor_test.h"

using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
constexpr int32_t APP_STATE_CACHED = 100;
}

void SecCompMonitorTest::SetUpTestCase()
{
}

void SecCompMonitorTest::TearDownTestCase()
{
    sleep(3); // delay 3 minutes
}

void SecCompMonitorTest::SetUp()
{
    if (appStateObserver_ != nullptr) {
        return;
    }
    appStateObserver_ = std::make_shared<SecCompUsageObserver>();
}

void SecCompMonitorTest::TearDown()
{
    appStateObserver_ = nullptr;
}

/**
 * @tc.name: ProcessFromForegroundList001
 * @tc.desc: Monitor foreground list for process after process state changed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecCompMonitorTest, ProcessFromForegroundList001, TestSize.Level0)
{
    EXPECT_EQ(true, SecCompMonitor::GetInstance().IsToastShownNeeded(10));
    EXPECT_EQ(false, SecCompMonitor::GetInstance().IsToastShownNeeded(10));
    ASSERT_NE(nullptr, appStateObserver_);
    EXPECT_EQ(1, SecCompMonitor::GetInstance().appsInForeground_.size());
    ProcessData processData;
    processData.state = AppProcessState::APP_STATE_BACKGROUND;
    processData.pid = 10;
    // change to background
    appStateObserver_->OnProcessStateChanged(processData);
    EXPECT_EQ(0, SecCompMonitor::GetInstance().appsInForeground_.size());

    EXPECT_EQ(true, SecCompMonitor::GetInstance().IsToastShownNeeded(10));
    EXPECT_EQ(1, SecCompMonitor::GetInstance().appsInForeground_.size());
    // change to die
    appStateObserver_->OnProcessDied(processData);
    EXPECT_EQ(0, SecCompMonitor::GetInstance().appsInForeground_.size());

    EXPECT_EQ(true, SecCompMonitor::GetInstance().IsToastShownNeeded(10));
    EXPECT_EQ(1, SecCompMonitor::GetInstance().appsInForeground_.size());
    AppStateData appStateData;
    appStateData.state = APP_STATE_CACHED;
    appStateData.pid = 10;
    // change to background
    appStateObserver_->OnAppCacheStateChanged(appStateData);
    EXPECT_EQ(0, SecCompMonitor::GetInstance().appsInForeground_.size());
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
