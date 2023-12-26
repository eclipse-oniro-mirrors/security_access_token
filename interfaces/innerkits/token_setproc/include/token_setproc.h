/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef TOKEN_SETPROC_H
#define TOKEN_SETPROC_H
#include<stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
#define ACCESS_TOKEN_OK 0
#define ACCESS_TOKEN_PARAM_INVALID (-1)
#define ACCESS_TOKEN_OPEN_ERROR (-2)

uint64_t GetSelfTokenID();

int SetSelfTokenID(uint64_t tokenID);

uint64_t GetFirstCallerTokenID();

int SetFirstCallerTokenID(uint64_t tokenID);

int32_t AddPermissionToKernel(uint32_t tokenID, const uint32_t* opCodeList, const int32_t* statusList, uint32_t size);
int32_t RemovePermissionFromKernel(uint32_t tokenID);
int32_t SetPermissionToKernel(uint32_t tokenID, int32_t opCode, bool status);
bool GetPermissionFromKernel(uint32_t tokenID, int32_t opCode);

#ifdef __cplusplus
}
#endif

#endif
