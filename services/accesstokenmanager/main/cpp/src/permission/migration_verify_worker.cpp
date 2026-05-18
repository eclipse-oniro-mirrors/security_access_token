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

#include "migration_verify_worker.h"

#include "accesstoken_common_log.h"
#include "migration_verify_helper.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
MigrationVerifyWorker& MigrationVerifyWorker::GetInstance()
{
    static MigrationVerifyWorker instance;
    return instance;
}

MigrationVerifyWorker::~MigrationVerifyWorker()
{
    Shutdown();
}

void MigrationVerifyWorker::Submit(const MigratedInfoIdl& migratedInfo,
    const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        taskQueue_.emplace(Task { migratedInfo, cachedInfos });
    }
    cv_.notify_one();
    EnsureThreadRunning();
}

void MigrationVerifyWorker::Shutdown()
{
    shuttingDown_ = true;
    cv_.notify_all();
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    // Reset flag so the singleton can be reused (test-only path).
    shuttingDown_ = false;
}

void MigrationVerifyWorker::EnsureThreadRunning()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_ || shuttingDown_) {
        return;
    }
    if (workerThread_.joinable()) {
        workerThread_.join();
    }
    running_ = true;
    workerThread_ = std::thread(&MigrationVerifyWorker::WorkerLoop, this);
}

void MigrationVerifyWorker::WorkerLoop()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "Verification worker thread started.");
    while (!shuttingDown_) {
        Task task;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (!cv_.wait_for(lock, IDLE_TIMEOUT, [this] {
                return shuttingDown_ || !taskQueue_.empty();
            })) {
                LOGI(ATM_DOMAIN, ATM_TAG, "Verification worker thread idle timeout, exiting.");
                break;
            }
            if (shuttingDown_ && taskQueue_.empty()) {
                break;
            }
            task = std::move(taskQueue_.front());
            taskQueue_.pop();
        }
        (void)MigrationVerifyHelper::VerifyMigratedBundle(task.migratedInfo, task.cachedInfos);
    }
    running_ = false;
    LOGI(ATM_DOMAIN, ATM_TAG, "Verification worker thread stopped.");
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
