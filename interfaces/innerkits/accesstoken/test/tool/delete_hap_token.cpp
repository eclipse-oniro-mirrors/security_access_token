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
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include "test_common.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

int32_t main(int argc, char *argv[])
{
    if (argc < 3) { // 3: size
        std::cout << "Help: ./DeleteHapToken bundleName isReservedToken\n" << std::endl;
        return 0;
    }
    std::string bundleName = argv[1]; // 1: index
    bool isReservedToken = (std::string(argv[2]) == "true"); // 2: index
    DeleteHapTokenID(bundleName, isReservedToken);
    return 0;
}
