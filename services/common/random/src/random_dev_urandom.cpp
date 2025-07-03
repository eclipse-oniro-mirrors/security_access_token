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

#include "random.h"

#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
#include "accesstoken_common_log.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
extern "C" uint32_t GetRandomUint32FromUrandom(void)
{
    uint64_t accessTokenFdTag = 0xD005A01;
    uint32_t random;
    int32_t fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to open urandom, errno=%{public}d.", errno);
        return 0;
    }
    fdsan_exchange_owner_tag(fd, 0, accessTokenFdTag);
    ssize_t len = read(fd, &random, sizeof(random));
    (void)fdsan_close_with_tag(fd, accessTokenFdTag);

    if (len != sizeof(random)) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to read from urandom, errno=%{public}d.", errno);
        return 0;
    }
    return random;
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS
