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

#ifndef MIGRATION_VERIFY_WORKER_H
#define MIGRATION_VERIFY_WORKER_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include "hap_token_info_inner.h"
#include "idl_common.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class MigrationVerifyWorker final {
public:
    static MigrationVerifyWorker& GetInstance();

    void Submit(const MigratedInfoIdl& migratedInfo,
        const std::vector<std::shared_ptr<HapTokenInfoInner>>& cachedInfos);

private:
    // Shutdown is not protected, test only. Caller must ensure no concurrent Submit after shutdown starts.
    void Shutdown();
    struct Task final {
        MigratedInfoIdl migratedInfo;
        std::vector<std::shared_ptr<HapTokenInfoInner>> cachedInfos;
    };

    MigrationVerifyWorker() = default;
    ~MigrationVerifyWorker();

    void WorkerLoop();
    void EnsureThreadRunning();

    std::chrono::seconds IDLE_TIMEOUT = std::chrono::seconds(30);

    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<Task> taskQueue_;
    std::thread workerThread_;
    std::atomic<bool> running_ = false;
    std::atomic<bool> shuttingDown_ = false;

    DISALLOW_COPY_AND_MOVE(MigrationVerifyWorker);
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS

#endif // MIGRATION_VERIFY_WORKER_H
