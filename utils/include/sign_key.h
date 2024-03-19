/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef CODE_SIGN_SIGN_KEY_H
#define CODE_SIGN_SIGN_KEY_H

#include <vector>

#include "byte_buffer.h"

namespace OHOS {
namespace Security {
namespace CodeSign {
class SignKey {
public:
    virtual const ByteBuffer *GetSignCert() = 0;
    std::vector<ByteBuffer> GetCarriedCerts()
    {
        std::vector<ByteBuffer> certs;
        return certs;
    }
    virtual bool Sign(const ByteBuffer &data, ByteBuffer &ret) = 0;
};
}
}
}
#endif