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
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include "test_common.h"

using namespace std;
using namespace OHOS::Security::AccessToken;

int32_t main(int argc, char *argv[])
{
    if (argc < 2) { // 2: size
        std::cout << "Help: ./CreateHapToken bundleName [optional]permission1 permission2 ...\n" << std::endl;
        return 0;
    }
    std::string bundleName = argv[1]; // 1: index
    std::vector<std::string> reqPerm;
    for (int32_t i = 2; i < argc; ++i) { // 2: start index
        reqPerm.emplace_back(argv[i]);
    }
    (void)GetHapTokenId(bundleName, reqPerm);
    return 0;
}
