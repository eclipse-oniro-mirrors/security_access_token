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

#include "access_token_db_loader.h"

#include "accesstoken_common_log.h"
#include "access_token_db.h"
#include "rdb_helper.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t DESTROY_REPEAT_TIMES = 10;
static constexpr int32_t DESTROY_WAIT_TIME_MILLISECONDS = 100; // 0.1s
}

AccessTokenDbLoader::AccessTokenDbLoader()
{
    LOGI(ATM_DOMAIN, ATM_TAG, "AccessTokenDbLoader");
}

AccessTokenDbLoader::~AccessTokenDbLoader()
{
    AccessTokenDb::DestroyInstance();
    LOGI(ATM_DOMAIN, ATM_TAG, "~AccessTokenDbLoader");
}

void AccessTokenDbLoader::InitRdbHelper()
{
    (void)NativeRdb::RdbHelper::Init();
}

int32_t AccessTokenDbLoader::Modify(const AtmDataType type, const GenericValues& modifyValue,
    const GenericValues& conditionValue)
{
    return AccessTokenDb::GetInstance()->Modify(type, modifyValue, conditionValue);
}

int32_t AccessTokenDbLoader::Find(AtmDataType type, const GenericValues& conditionValue,
    std::vector<GenericValues>& results)
{
    return AccessTokenDb::GetInstance()->Find(type, conditionValue, results);
}

int32_t AccessTokenDbLoader::DeleteAndInsertValues(const std::vector<DelInfo>& delInfoVec,
    const std::vector<AddInfo>& addInfoVec)
{
    return AccessTokenDb::GetInstance()->DeleteAndInsertValues(delInfoVec, addInfoVec);
}

bool AccessTokenDbLoader::DestroyRdbHelper()
{
    AccessTokenDb::DestroyInstance();

    LOGI(ATM_DOMAIN, ATM_TAG, "Clean up rdb resource.");

    // rdb release ipc resource may delay in watch, repeat ten times and wait 0.1s after each attempt
    auto sleepTime = std::chrono::milliseconds(DESTROY_WAIT_TIME_MILLISECONDS);
    bool isDestroy = false;
    for (int32_t i = 0; i < DESTROY_REPEAT_TIMES; ++i) {
        isDestroy = NativeRdb::RdbHelper::Destroy();
        if (isDestroy) {
            LOGI(ATM_DOMAIN, ATM_TAG, "Rdb resource clean up success!");
            break;
        } else {
            std::this_thread::sleep_for(sleepTime);
        }
    }

    return isDestroy;
}

extern "C" {
void* Create()
{
    return reinterpret_cast<void*>(new AccessTokenDbLoader);
}

void Destroy(void* loaderPtr)
{
    AccessTokenDbLoaderInterface* loader = reinterpret_cast<AccessTokenDbLoaderInterface*>(loaderPtr);
    if (loader != nullptr) {
        delete loader;
        loader = nullptr;
    }
    loaderPtr = nullptr;
}
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
