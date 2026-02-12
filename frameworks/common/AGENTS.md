# Frameworks Common

This directory contains common utilities, constants, and DFX (Design for X) components shared across the AccessToken module.

## Overview

```
frameworks/common/
├── include/
│   ├── accesstoken_common_log.h    # Logging utilities (LOGC, LOGE, etc.)
│   ├── accesstoken_thread_msg.h    # Thread-local error message storage
│   ├── hisysevent_adapter.h        # HiSysEvent reporting interface
│   ├── hisysevent_common.h         # Scene code and error code definitions
│   ├── data_validator.h            # Input validation utilities
│   ├── permission_map.h            # Permission definitions and mapping
│   └── ...
└── src/
    ├── accesstoken_common_log.cpp  # Log and error message implementation
    ├── hisysevent_adapter.cpp      # HiSysEvent reporting implementation
    ├── data_validator.cpp          # Validation implementation
    └── ...
```

## LOGC Critical Error Logging

### Purpose

`LOGC` is used for **critical errors** that need to be:
1. Logged to HiLog for immediate visibility
2. Reported via HiSysEvent for fault tracking and analysis

### Usage

```cpp
#include "accesstoken_common_log.h"

// LOGC automatically:
// 1. Logs the error via HiLog (LOG_ERROR level)
// 2. Stores the error message in thread-local storage
// 3. The stored message can be retrieved by HiSysEvent reporting
LOGC(ATM_DOMAIN, ATM_TAG, "Invalid value length(%{public}d).", length);
```

### LOGC vs Other Log Macros

| Macro | Level | HiSysEvent | Use Case |
|-------|-------|------------|----------|
| `LOGC` | ERROR | Yes (ACCESSTOKEN_EXCEPTION) | Critical validation failures |
| `LOGE` | ERROR | No | General errors |
| `LOGW` | WARN | No | Warnings |
| `LOGI` | INFO | No | Information |
| `LOGD` | DEBUG | No | Debug |

### LOGC Implementation

```cpp
// accesstoken_common_log.h
#define LOGC(domain, tag, fmt, ...)            \
do { \
    ((void)HILOG_IMPL(LOG_CORE, LOG_ERROR, domain, tag, \
    "[%{public}s]" fmt, __FUNCTION__, ##__VA_ARGS__)); \
    AddEventMessage(domain, tag, \
        "%" LOG_PUBLIC "s[%" LOG_PUBLIC "u]: " fmt, __func__, __LINE__, ##__VA_ARGS__); \
} while (0)
```

### Usage Principles

**Core Principle**: Only use `LOGC` for errors that cause the function call to fail and return early. Do NOT use `LOGC` for non-blocking errors or high-frequency data reporting.

**Rules**:
1. **Only for fatal errors**: Use `LOGC` only when the error prevents the function from completing successfully
2. **No mass data reporting**: Do NOT use `LOGC` for non-blocking errors or collecting statistics
3. **Violation handling**: If these principles are violated, you must:
   - Proactively report the violation through proper channels
   - Clear the cached error message (`ClearThreadErrorMsg()`)

**Rationale**: `LOGC` triggers HiSysEvent FAULT reporting which is designed for fault tracking, not for monitoring or statistics. Misuse can overwhelm the fault tracking system and mask real critical issues.

### When to Use LOGC

Use `LOGC` for **data validation failures** that indicate input corruption or critical errors:

```cpp
bool DataValidator::IsBundleNameValid(const std::string& bundleName)
{
    bool ret = (!bundleName.empty() && (bundleName.length() <= MAX_LENGTH));
    if (!ret) {
        LOGC(ATM_DOMAIN, ATM_TAG, "bunldename %{public}s is invalid.", bundleName.c_str());
    }
    return ret;
}
```

**Use LOGC for**:
- Invalid input parameters that should never occur
- Data corruption detected
- Critical validation failures
- Any error that needs fault tracking

**Do NOT use LOGC for**:
- Expected error conditions (e.g., file not found when optional)
- Normal operation failures (use `LOGE`)
- Debug/trace information (use `LOGD`/`LOGI`)

## Thread-Local Error Message

### Purpose

Thread-local storage (`g_errMsg`) captures the error message chain for HiSysEvent reporting.

### API

```cpp
// Get length of stored error message
uint32_t GetThreadErrorMsgLen(void);

// Get the stored error message
const char* GetThreadErrorMsg(void);

// Clear the stored error message
void ClearThreadErrorMsg(void);

// Add an error message (called by LOGC)
void AddEventMessage(uint32_t domain, const char* tag, const char* format, ...);
```

### Message Chain

The error message can be built up across the call stack:

```cpp
// Function A calls LOGC
// A() -> LOGC(...) -> "Error message A"

// Function B calls LOGC
// B() -> A() -> LOGC(...) -> "Error message B <A[123]"

// Result: "Error message B <A[123]" stored in thread-local storage
```

## HiSysEvent Reporting

### Purpose

HiSysEvent is used for fault tracking, performance monitoring, and statistics.

### Event Types

| Event Name | Type | Domain | Purpose |
|------------|------|--------|---------|
| `ACCESSTOKEN_EXCEPTION` | FAULT | ACCESS_TOKEN | Critical errors from LOGC |
| `DATABASE_EXCEPTION` | FAULT | ACCESS_TOKEN | Database operation failures |
| `ACCESSTOKEN_SERVICE_START` | STATISTIC | ACCESS_TOKEN | Service startup statistics |
| `ACCESSTOKEN_SERVICE_START_ERROR` | FAULT | ACCESS_TOKEN | Service startup failures |
| `ADD_HAP` | STATISTIC | ACCESS_TOKEN | HAP token creation |
| `UPDATE_HAP` | STATISTIC | ACCESS_TOKEN | HAP token update |
| `DEL_HAP` | STATISTIC | ACCESS_TOKEN | HAP token deletion |

### ACCESSTOKEN_EXCEPTION Event

Triggered automatically by `LOGC` via `ReportSysCommonEventError()`:

```cpp
// hisysevent_adapter.cpp
void ReportSysCommonEventError(int32_t ipcCode, int32_t errCode)
{
    if (GetThreadErrorMsgLen() == 0) {
        return;
    }
    int32_t ret = HiSysEventWrite(HiviewDFX::HiSysEvent::Domain::ACCESS_TOKEN,
        "ACCESSTOKEN_EXCEPTION",
        HiviewDFX::HiSysEvent::EventType::FAULT,
        "SCENE_CODE", ipcCode,
        "ERROR_CODE", errCode,
        "ERROR_MSG", GetThreadErrorMsg());
    if (ret != 0) {
        LOGE(ATM_DOMAIN, ATM_TAG, "Failed to write hisysevent write, ret %{public}d.", ret);
    }
    ClearThreadErrorMsg();
}
```

### Scene Codes

Defined in `hisysevent_common.h`:

```cpp
typedef enum AccessTokenExceptionSceneCode {
    // 0~0xFFF reserved for ipc code of access token manager
    // 0x1000~0x1FFF reserved for native token
    NATIVE_TOKEN_INIT = 0x1000,
    CHECK_PROCESS_INFO,
    ADD_NODE,
    UPDATE_NODE
} AccessTokenExceptionSceneCode;
```

### Reporting Events

```cpp
#include "hisysevent_adapter.h"

// Report database exception
ReportSysEventDbException(AT_DB_INSERT_RESTORE, errCode, "token_table");

// Report ADD_HAP event
HapDfxInfo info;
// ... populate info ...
ReportSysEventAddHap(errorCode, info, needReportFault);
```

### Event Parameters

**ACCESSTOKEN_EXCEPTION**:
- `SCENE_CODE`: Scene identifier (where the error occurred)
- `ERROR_CODE`: Error code (what went wrong)
- `ERROR_MSG`: Error message from thread-local storage

**DATABASE_EXCEPTION**:
- `SCENE_CODE`: Database operation (INSERT/DELETE/UPDATE/QUERY/COMMIT)
- `ERROR_CODE`: Database error code
- `TABLE_NAME`: Affected table name

## Domain and Tag Definitions

```cpp
// AccessTokenManager
#define ATM_DOMAIN 0xD005A01
#define ATM_TAG "ATM"

// PrivacyManager
#define PRI_DOMAIN 0xD005A02
#define PRI_TAG "PRIVACY"
```

## Best Practices

1. **Use LOGC sparingly**: Only for critical validation failures
2. **Clear error messages**: After reporting via HiSysEvent, messages are automatically cleared
3. **Scene codes**: Add new scene codes to `hisysevent_common.h` when adding new fault points
4. **Error codes**: Define specific error codes for better fault analysis
5. **Thread safety**: Error messages are thread-local, safe for multi-threaded use

## Example: Adding New Fault Tracking

```cpp
// 1. Define scene code in hisysevent_common.h
typedef enum AccessTokenExceptionSceneCode {
    // ... existing codes ...
    FEATURE_CONFIG_PARSE_FAILED = 0x2000,  // New code
} AccessTokenExceptionSceneCode;

// 2. Use LOGC in code
bool ConfigPolicLoader::LoadPermissionFeatureConfig()
{
    if (parseFailed) {
        LOGC(ATM_DOMAIN, ATM_TAG, "Parse feature config failed: %{public}s", filePath.c_str());
        return false;
    }
    return true;
}

// 3. Report error (if not on IPC path)
if (GetThreadErrorMsgLen() > 0) {
    ReportSysCommonEventError(FEATURE_CONFIG_PARSE_FAILED, ERR_PARSE_FAILED);
}
```
