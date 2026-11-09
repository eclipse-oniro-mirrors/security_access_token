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

#include <gtest/gtest.h>
#include <cstring>
#include "malloc_wrapper.h"
#include "strcpy_wrapper.h"
#include "nativetoken_kit.h"
#include "nativetoken.h"
#include "nativetoken_json_oper.h"
#include "nativetoken_malloc_test.h"
#include "perm_setproc_c.h"
#include "spm_setproc.h"
#include "accesstoken_file_util.h"
#include "accesstoken_thread_msg.h"

using namespace testing::ext;

static constexpr const char *KERN_PERM_VALID = "ohos.permission.kernel.LOAD_CERTSIGN_LIBRARY";

class NativeTokenMallocTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        g_tokenListHead = (NativeTokenList *)malloc(sizeof(NativeTokenList));
        g_tokenListHead->next = NULL;
        g_isNativeTokenInited = 1;
        ClearThreadErrorMsg();
    }
    static void TearDownTestCase()
    {
        free(g_tokenListHead);
        g_tokenListHead = NULL;
        g_isNativeTokenInited = 0;
    }
    void SetUp()
    {
        ResetMallocMock();
        ResetStrcpyMock();
    }
    void TearDown()
    {
        ResetMallocMock();
        ResetStrcpyMock();
    }
};

static PermNameWithValue *CreateKernPermEntry(const char *name, int32_t type, int32_t valueNum)
{
    PermNameWithValue *entry = new PermNameWithValue;
    entry->type = type;
    entry->valueNum = valueNum;
    entry->permissionName = strdup(name);
    return entry;
}

static void FreeKernPermEntry(PermNameWithValue *entry)
{
    if (entry != nullptr) {
        free(entry->permissionName);
        delete entry;
    }
}

static NativeTokenInfoParams MakeTokenInfo(const char *processName, PermNameWithValue *kernEntry)
{
    NativeTokenInfoParams info = {};
    info.permsNum = 0;
    info.aclsNum = 0;
    info.dcaps = nullptr;
    info.perms = nullptr;
    info.acls = nullptr;
    info.aplStr = "system_core";
    info.processName = processName;
    if (kernEntry != nullptr) {
        info.kernPerms.permsNum = 1;
        info.kernPerms.perms = kernEntry;
    }
    return info;
}

/**
 * @tc.name: KernPermMalloc001
 * @tc.desc: DedupFilterKernPerms malloc fails, return INVALID_TOKEN_ID
 * @tc.type: FUNC
 */
HWTEST_F(NativeTokenMallocTest, KernPermMalloc001, TestSize.Level1)
{
    PermNameWithValue *kernEntry = CreateKernPermEntry(KERN_PERM_VALID, 1, 1);
    NativeTokenInfoParams info = MakeTokenInfo("MallocTest001", kernEntry);
    SetMallocFailCount(1);
    uint64_t tokenId = GetAccessTokenId(&info);
    EXPECT_EQ(tokenId, INVALID_TOKEN_ID);
    FreeKernPermEntry(kernEntry);
}

/**
 * @tc.name: KernPermMalloc002
 * @tc.desc: malloc fails at each call (1~6), return INVALID_TOKEN_ID
 * @tc.type: FUNC
 */
HWTEST_F(NativeTokenMallocTest, KernPermMalloc002, TestSize.Level1)
{
    PermNameWithValue *kernEntry = CreateKernPermEntry(KERN_PERM_VALID, 1, 1);
    for (int i = 1; i <= 6; i++) {
        std::string name = "MallocTest002_" + std::to_string(i);
        NativeTokenInfoParams info = MakeTokenInfo(name.c_str(), kernEntry);
        SetMallocFailCount(i);
        uint64_t tokenId = GetAccessTokenId(&info);
        EXPECT_EQ(tokenId, INVALID_TOKEN_ID);
        EXPECT_GE(GetMallocCount(), i);
        ResetMallocMock();
    }
    FreeKernPermEntry(kernEntry);
}

/**
 * @tc.name: KernPermStrcpy001
 * @tc.desc: strcpy_s fails in CopyKernPermEntry, return INVALID_TOKEN_ID
 * @tc.type: FUNC
 */
HWTEST_F(NativeTokenMallocTest, KernPermStrcpy001, TestSize.Level1)
{
    PermNameWithValue *kernEntry = CreateKernPermEntry(KERN_PERM_VALID, 1, 1);
    std::string name = "StrcpyTest001";
    NativeTokenInfoParams info = MakeTokenInfo(name.c_str(), kernEntry);
    SetStrcpyFailCount(2);
    uint64_t tokenId = GetAccessTokenId(&info);
    EXPECT_EQ(tokenId, INVALID_TOKEN_ID);
    EXPECT_GE(GetStrcpyCount(), 2);
    FreeKernPermEntry(kernEntry);
}

/**
 * @tc.name: KernPermStrcpy002
 * @tc.desc: strcpy_s fails in CreatePermsWithKernPerms kernPerm loop, return INVALID_TOKEN_ID
 * @tc.type: FUNC
 */
HWTEST_F(NativeTokenMallocTest, KernPermStrcpy002, TestSize.Level1)
{
    PermNameWithValue *kernEntry = CreateKernPermEntry(KERN_PERM_VALID, 1, 1);
    std::string name = "StrcpyTest002";
    NativeTokenInfoParams info = MakeTokenInfo(name.c_str(), kernEntry);
    SetStrcpyFailCount(3);
    uint64_t tokenId = GetAccessTokenId(&info);
    EXPECT_EQ(tokenId, INVALID_TOKEN_ID);
    EXPECT_GE(GetStrcpyCount(), 3);
    FreeKernPermEntry(kernEntry);
}
