/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "random_mbedtls.h"
#include "access_token.h"

using OHOS::Security::AccessToken::RandomMbedtls;
using OHOS::Security::AccessToken::RET_SUCCESS;

namespace OHOS {
namespace Security {
namespace AccessToken {
extern "C" unsigned int GetRandomUint32()
{
    unsigned int rand;
    int ret = RandomMbedtls::GetInstance().GenerateRandomArray((unsigned char *)&rand, sizeof(rand));
    if (ret != RET_SUCCESS) {
        return 0;
    }
    return rand;
}

int RandomMbedtls::GenerateRandomArray(unsigned char *randStr, unsigned int len)
{
    if (randStr == nullptr || len == 0) {
        return RET_FAILED;
    }
    int ret;

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->randomLock_);
    if (!initFlag_) {
        mbedtls_ctr_drbg_init(&ctrDrbg_);
        mbedtls_entropy_init(&entropy_);
        ret = mbedtls_ctr_drbg_seed(&ctrDrbg_, mbedtls_entropy_func, &entropy_, nullptr, 0);
        if (ret != 0) {
            return RET_FAILED;
        }
        initFlag_ = true;
    }

    ret = mbedtls_ctr_drbg_random(&ctrDrbg_, randStr, len);
    if (ret != 0) {
        return RET_FAILED;
    }
    return RET_SUCCESS;
}

RandomMbedtls& RandomMbedtls::GetInstance()
{
    static RandomMbedtls instance;
    return instance;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
