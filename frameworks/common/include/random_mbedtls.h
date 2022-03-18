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

#ifndef ACCESS_TOKEN_RANDOM_MBEDTLS
#define ACCESS_TOKEN_RANDOM_MBEDTLS

#include "rwlock.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
class RandomMbedtls {
public:
    static RandomMbedtls& GetInstance();
    int GenerateRandomArray(unsigned char *randStr, unsigned int len);
    ~RandomMbedtls() {}
    static unsigned int GetRandomUint32();

private:
    RandomMbedtls() : initFlag_(false) {}
    mbedtls_entropy_context entropy_;
    mbedtls_ctr_drbg_context ctrDrbg_;
    OHOS::Utils::RWLock randomLock_;
    bool initFlag_;
};
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
#endif // ACCESS_TOKEN_RANDOM_MBEDTLS
