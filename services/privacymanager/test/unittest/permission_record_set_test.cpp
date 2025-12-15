/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "constant.h"
#include "permission_record_set.h"

using namespace testing::ext;

namespace OHOS {
namespace Security {
namespace AccessToken {
namespace {
static constexpr int32_t HAP_TOKEN_ID[] = {101, 102};
static constexpr int32_t HAP_PID[] = {201, 202};
static constexpr int32_t INACTIVE = ActiveChangeType::PERM_INACTIVE;
static constexpr int32_t ACTIVE = ActiveChangeType::PERM_ACTIVE_IN_BACKGROUND;
static constexpr int32_t CALLER_PID[] = {301, 302};
static constexpr int32_t OPCODE[] = {Constant::OP_MICROPHONE, Constant::OP_CAMERA};
static constexpr int32_t RECORD_ITEM_SIZE = 5;
static constexpr int32_t SECOND_PARAM = 2;
static constexpr int32_t THIRD_PARAM = 3;
static constexpr int32_t FORTH_PARAM = 4;
}

static ContinuousPermissionRecord MakeRecord(const int32_t recordArray[RECORD_ITEM_SIZE])
{
    ContinuousPermissionRecord record;
    record.tokenId = recordArray[0];
    record.opCode = recordArray[1];
    record.status = recordArray[SECOND_PARAM];
    record.pid = recordArray[THIRD_PARAM];
    record.callerPid = recordArray[FORTH_PARAM];
    return record;
}

static void MakeRecordSet(const int32_t recordArray[][RECORD_ITEM_SIZE], int32_t setSize,
    std::set<ContinuousPermissionRecord>& recordSet)
{
    for (size_t i = 0; i < setSize; i++) {
        ContinuousPermissionRecord record = MakeRecord(recordArray[i]);
        recordSet.emplace(record);
    }
}

static void MakeRecordList(const int32_t recordArray[][RECORD_ITEM_SIZE], int32_t setSize,
    std::vector<ContinuousPermissionRecord>& recordList)
{
    for (size_t i = 0; i < setSize; i++) {
        ContinuousPermissionRecord record = MakeRecord(recordArray[i]);
        recordList.emplace_back(record);
    }
}

static void RemoveRecord(std::set<ContinuousPermissionRecord>& recordList,
    const ContinuousPermissionRecord& record, std::vector<ContinuousPermissionRecord>& retList)
{
    return PermissionRecordSet::RemoveByKey(recordList, record, &ContinuousPermissionRecord::IsEqualRecord, retList);
}

static void RemoveTokenId(std::set<ContinuousPermissionRecord>& recordList,
    const ContinuousPermissionRecord& record, std::vector<ContinuousPermissionRecord>& retList)
{
    return PermissionRecordSet::RemoveByKey(recordList, record, &ContinuousPermissionRecord::IsEqualTokenId, retList);
}

static void RemoveTokenIdAndPid(std::set<ContinuousPermissionRecord>& recordList,
    const ContinuousPermissionRecord& record, std::vector<ContinuousPermissionRecord>& retList)
{
    return PermissionRecordSet::RemoveByKey(recordList, record,
        &ContinuousPermissionRecord::IsEqualTokenIdAndPid, retList);
}

static void RemovePermCode(std::set<ContinuousPermissionRecord>& recordList,
    const ContinuousPermissionRecord& record, std::vector<ContinuousPermissionRecord>& retList)
{
    return PermissionRecordSet::RemoveByKey(recordList, record, &ContinuousPermissionRecord::IsEqualPermCode, retList);
}

static void RemoveCallerPid(std::set<ContinuousPermissionRecord>& recordList,
    const ContinuousPermissionRecord& record, std::vector<ContinuousPermissionRecord>& retList)
{
    return PermissionRecordSet::RemoveByKey(recordList, record, &ContinuousPermissionRecord::IsEqualCallerPid, retList);
}

class PermissionRecordSetTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void PermissionRecordSetTest::SetUpTestCase()
{
}

void PermissionRecordSetTest::TearDownTestCase()
{
}

void PermissionRecordSetTest::SetUp()
{
}

void PermissionRecordSetTest::TearDown()
{
}

/**
 * @tc.name: PermissionRecordSetTest0001
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0001, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 1);
}

/**
 * @tc.name: PermissionRecordSetTest0002
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0002, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],  INACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 1);
}

/**
 * @tc.name: PermissionRecordSetTest0003
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0003, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[1] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
}

/**
 * @tc.name: PermissionRecordSetTest0004
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0004, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
}

/**
 * @tc.name: PermissionRecordSetTest0005
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0005, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
}

/**
 * @tc.name: PermissionRecordSetTest0006
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0006, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
}

/**
 * @tc.name: PermissionRecordSetTest0007
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0007, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
}

/**
 * @tc.name: PermissionRecordSetTest0008
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0008, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] }, // 0-3
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] }, // 1-5
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] }, // 2-2
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[1] }, // 3-4
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] }, // 4-0
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] }, // 5-1
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 6);
    auto it = recordSet.begin();
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[4])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[5])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[2])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[0])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[3])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[1])));
    ++it;
    EXPECT_EQ(it, recordSet.end());
}


/**
 * @tc.name: PermissionRecordSetTest0009
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0009, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] }, // 0-0
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[1] }, // 1-1
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] }, // 2-2
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] }, // 3-3
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] }, // 4-4
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 5);
    auto it = recordSet.begin();
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[0])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[1])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[2])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[3])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[4])));
    ++it;
    EXPECT_EQ(it, recordSet.end());
}

/**
 * @tc.name: PermissionRecordSetTest0010
 * @tc.desc: PermissionRecordSetTest set test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, PermissionRecordSetTest0010, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] }, // 0-4
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] }, // 1-3
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] }, // 2-2
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[1] }, // 3-1
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] }, // 4-0
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 5);
    auto it = recordSet.begin();
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[4])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[3])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[2])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[1])));
    ++it;
    EXPECT_TRUE(it->IsEqualRecord(MakeRecord(recordList[0])));
    ++it;
    EXPECT_EQ(it, recordSet.end());
}

/**
 * @tc.name: RemoveRecord0001
 * @tc.desc: RemoveRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveRecord0001, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveRecord(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemoveRecord0002
 * @tc.desc: RemoveRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveRecord0002, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    INACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveRecord(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: RemoveRecord0003
 * @tc.desc: RemoveRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveRecord0003, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveRecord(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 2);
    EXPECT_EQ(retList.size(), 0);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: RemoveRecord0005
 * @tc.desc: RemoveRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveRecord0005, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    INACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveRecord(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemoveTokenId0001
 * @tc.desc: RemoveTokenId test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveTokenId0001, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[1],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveTokenId(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemoveTokenId0002
 * @tc.desc: RemoveTokenId test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveTokenId0002, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[1],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveTokenId(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 0);
    EXPECT_EQ(retList.size(), 2);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemoveTokenId0003
 * @tc.desc: RemoveRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveTokenId0003, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[1],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveTokenId(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 2);
    EXPECT_EQ(retList.size(), 0);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: RemoveTokenIdAndPid0001
 * @tc.desc: RemoveTokenIdAndPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveTokenIdAndPid0001, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[1],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveTokenIdAndPid(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 0);
    EXPECT_EQ(retList.size(), 2);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 2);
}

/**
 * @tc.name: RemoveTokenIdAndPid0002
 * @tc.desc: RemoveTokenIdAndPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveTokenIdAndPid0002, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[1],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveTokenIdAndPid(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemoveTokenIdAndPid0003
 * @tc.desc: RemoveTokenIdAndPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveTokenIdAndPid0003, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[1],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveTokenIdAndPid(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 2);
    EXPECT_EQ(retList.size(), 0);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: RemoveTokenIdAndPid0004
 * @tc.desc: RemoveTokenIdAndPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveTokenIdAndPid0004, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[1],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveTokenIdAndPid(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: RemoveTokenIdAndPid0005
 * @tc.desc: RemoveTokenIdAndPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveTokenIdAndPid0005, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   -1, CALLER_PID[1] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[1],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveTokenIdAndPid(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: RemovePermCode0001
 * @tc.desc: RemovePermCode test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemovePermCode0001, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemovePermCode(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 0);
    EXPECT_EQ(retList.size(), 2);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemovePermCode0002
 * @tc.desc: RemovePermCode test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemovePermCode0002, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemovePermCode(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemovePermCode0003
 * @tc.desc: RemovePermCode test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemovePermCode0003, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemovePermCode(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 2);
    EXPECT_EQ(retList.size(), 0);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: RemovePermCode0004
 * @tc.desc: RemovePermCode test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemovePermCode0004, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    INACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,     HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemovePermCode(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemoveCallerPid0001
 * @tc.desc: RemoveCallerPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveCallerPid0001, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveCallerPid(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 0);
    EXPECT_EQ(retList.size(), 2);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemoveCallerPid0002
 * @tc.desc: RemoveCallerPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveCallerPid0002, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveCallerPid(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 0);
    EXPECT_EQ(retList.size(), 2);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 2);
}

/**
 * @tc.name: RemoveCallerPid0003
 * @tc.desc: RemoveCallerPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveCallerPid0003, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[1] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveCallerPid(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 1);
    EXPECT_EQ(retList.size(), 1);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: RemoveCallerPid0004
 * @tc.desc: RemoveCallerPid test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, RemoveCallerPid0004, TestSize.Level0)
{
    int32_t recordList[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[1] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[1] },
    };
    int32_t setSize = sizeof(recordList) / sizeof(recordList[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordList, setSize, recordSet);
    EXPECT_EQ(recordSet.size(), 2);
    ContinuousPermissionRecord record = {
        .tokenId = HAP_TOKEN_ID[0],
        .opCode = OPCODE[0],
        .status = ACTIVE,
        .pid = HAP_PID[0],
        .callerPid = CALLER_PID[0],
    };
    std::vector<ContinuousPermissionRecord> retList;
    RemoveCallerPid(recordSet, record, retList);
    EXPECT_EQ(recordSet.size(), 2);
    EXPECT_EQ(retList.size(), 0);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, retList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: GetUnusedCameraRecords0001
 * @tc.desc: GetUnusedCameraRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetUnusedCameraRecords0001, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetUnusedCameraRecords(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: GetUnusedCameraRecords0002
 * @tc.desc: GetUnusedCameraRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetUnusedCameraRecords0002, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetUnusedCameraRecords(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetUnusedCameraRecords0003
 * @tc.desc: GetUnusedCameraRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetUnusedCameraRecords0003, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetUnusedCameraRecords(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetUnusedCameraRecords0004
 * @tc.desc: GetUnusedCameraRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetUnusedCameraRecords0004, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
        { HAP_TOKEN_ID[1],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetUnusedCameraRecords(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetUnusedCameraRecords0005
 * @tc.desc: GetUnusedCameraRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetUnusedCameraRecords0005, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetUnusedCameraRecords(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetUnusedCameraRecords0006
 * @tc.desc: GetUnusedCameraRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetUnusedCameraRecords0006, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[1] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetUnusedCameraRecords(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetUnusedCameraRecords0007
 * @tc.desc: GetUnusedCameraRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetUnusedCameraRecords0007, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[1] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetUnusedCameraRecords(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: GetUnusedCameraRecords0008
 * @tc.desc: GetUnusedCameraRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetUnusedCameraRecords0008, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[1] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetUnusedCameraRecords(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetUnusedCameraRecords0009
 * @tc.desc: GetUnusedCameraRecords test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetUnusedCameraRecords0009, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   -1, CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[1] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetUnusedCameraRecords(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: GetInActiveUniqueRecord0001
 * @tc.desc: GetInActiveUniqueRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetInActiveUniqueRecord0001, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    INACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[1],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[1] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
        { HAP_TOKEN_ID[1],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetInActiveUniqueRecord0002
 * @tc.desc: GetInActiveUniqueRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetInActiveUniqueRecord0002, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetInActiveUniqueRecord0003
 * @tc.desc: GetInActiveUniqueRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetInActiveUniqueRecord0003, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[1],   OPCODE[0],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetInActiveUniqueRecord0004
 * @tc.desc: GetInActiveUniqueRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetInActiveUniqueRecord0004, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],   INACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 1);
}

/**
 * @tc.name: GetInActiveUniqueRecord0005
 * @tc.desc: GetInActiveUniqueRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetInActiveUniqueRecord0005, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],   ACTIVE,   HAP_PID[1], CALLER_PID[0] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}

/**
 * @tc.name: GetInActiveUniqueRecord0006
 * @tc.desc: GetInActiveUniqueRecord test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(PermissionRecordSetTest, GetInActiveUniqueRecord0006, TestSize.Level0)
{
    int32_t recordArray1[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],   INACTIVE,   HAP_PID[1], CALLER_PID[0] },
        { HAP_TOKEN_ID[0],   OPCODE[1],   ACTIVE,   HAP_PID[1], CALLER_PID[1] },
    };
    int32_t recordArray2[][RECORD_ITEM_SIZE] = {
        { HAP_TOKEN_ID[0],   OPCODE[1],    ACTIVE,   HAP_PID[0], CALLER_PID[0] },
    };
    int32_t size1 = sizeof(recordArray1) / sizeof(recordArray1[0]);
    int32_t size2 = sizeof(recordArray2) / sizeof(recordArray1[0]);
    std::set<ContinuousPermissionRecord> recordSet;
    MakeRecordSet(recordArray1, size1, recordSet);
    std::vector<ContinuousPermissionRecord> recordList;
    MakeRecordList(recordArray2, size2, recordList);
    std::vector<ContinuousPermissionRecord> inactiveList;
    PermissionRecordSet::GetInActiveUniqueRecord(recordSet, recordList, inactiveList);
    EXPECT_EQ(inactiveList.size(), 0);
}
}
}
}