# PrivacyManager Service

## Overview

PrivacyManager Service is the permission usage management service for OpenHarmony. It manages permission usage records and active status, tracking when applications are actively using sensitive permissions.

**Key Responsibility**: Manages permission **usage records** and **active status** (when an app is actively USING a permission). This is distinct from AccessTokenManager which manages permission grant state (whether an app HAS a permission: granted/denied).

## Architecture

```
services/privacymanager/
├── include/
│   ├── service/                    # Main service implementation
│   │   └── privacy_manager_service.h
│   ├── record/                     # Permission usage record management
│   │   ├── permission_record_manager.h
│   │   ├── permission_record.h
│   │   ├── permission_record_set.h
│   │   └── on_permission_used_record_callback_proxy.h
│   ├── database/                   # Database operations
│   │   ├── permission_used_record_db.h
│   │   ├── data_translator.h
│   │   └── privacy_field_const.h
│   ├── active/                     # Active status callback management
│   │   ├── active_status_callback_manager.h
│   │   ├── perm_active_status_change_callback_proxy.h
│   │   └── state_change_callback_proxy.h
│   ├── disable_policy/             # Disable policy callback management
│   │   ├── disable_policy_cbk_manager.h
│   │   ├── perm_disable_policy_cbk_proxy.h
│   │   └── perm_disable_policy_cbk_death_recipient.h
│   ├── sensitive/                  # Sensitive resource managers
│   │   ├── camera_manager/camera_manager_adapter.h
│   │   └── audio_manager/audio_manager_adapter.h
│   └── common/                     # Common utilities
│       ├── constant.h
│       ├── access_token_helper.h
│       └── privacy_common_event_subscriber.h
└── src/                            # Implementation files
└── test/                           # Unit tests
    ├── unittest/
    ├── mock/
    └── coverage/
```

## Core Components

### 1. PrivacyManagerService

**Location**: `include/service/privacy_manager_service.h`

The main system ability that provides IPC interfaces for permission usage management.

**Responsibilities**:
- Handle IPC requests from client applications
- Permission verification for calling processes (privileged, AccessToken, system app)
- Coordinate with PermissionRecordManager for record operations
- Manage proxy death handlers
- Dump service information for debugging

**Key Interfaces**:

| Interface | Description |
|-----------|-------------|
| `AddPermissionUsedRecord` | Add permission usage record (synchronous) |
| `AddPermissionUsedRecordAsync` | Add permission usage record (asynchronous) |
| `StartUsingPermission` | Mark permission as actively being used |
| `StopUsingPermission` | Mark permission as no longer being used |
| `RemovePermissionUsedRecords` | Remove all usage records for a token |
| `GetPermissionUsedRecords` | Get permission usage records (synchronous) |
| `GetPermissionUsedRecordsAsync` | Get permission usage records (asynchronous) |
| `RegisterPermActiveStatusCallback` | Register callback for active status changes |
| `UnRegisterPermActiveStatusCallback` | Unregister active status callback |
| `IsAllowedUsingPermission` | Check if permission usage is allowed |
| `SetPermissionUsedRecordToggleStatus` | Enable/disable permission usage records |
| `GetPermissionUsedRecordToggleStatus` | Get permission usage record toggle status |
| `SetMutePolicy` | Set mute policy for sensitive resources |
| `SetDisablePolicy` | Set disable policy for permissions |
| `RegisterPermDisablePolicyCallback` | Register disable policy callback |
| `UnRegisterPermDisablePolicyCallback` | Unregister disable policy callback |

### 2. PermissionRecordManager

**Location**: `include/record/permission_record_manager.h`

Manages permission usage records and coordinates database operations.

**Responsibilities**:
- Maintain `startRecordList_` for tracking active permission usage
- Add, remove, and query permission usage records
- Database synchronization for permission records
- Active status management and callbacks
- Mute policy management for camera and microphone
- Disable policy management
- Application state observation (app died, stopped, state changed)
- Lock screen status tracking

**Key Methods**:
- `AddPermissionUsedRecord`: Add permission usage record
- `StartUsingPermission`: Mark permission as in use
- `StopUsingPermission`: Mark permission as no longer in use
- `GetPermissionUsedRecords`: Query usage records
- `RegisterPermActiveStatusCallback`: Register for active status changes
- `SetMutePolicy`: Set mute policy (EDM/Privacy/Temporary)
- `SetDisablePolicy`: Set permission disable policy
- `NotifyAppStateChange`: Handle application state changes

### 3. PermissionRecord

**Location**: `include/record/permission_record.h`

Data structures for permission usage records.

**Responsibilities**:
- Provide data structures for permission usage records
- Support serialization/deserialization with GenericValues
- Define comparison operators for record set operations
- Manage both persistent records (PermissionRecord) and active tracking (ContinuousPermissionRecord)

**PermissionRecord**: Persistent record structure
```cpp
struct PermissionRecord {
    uint32_t tokenId;           // Token ID
    int32_t opCode;             // Permission operation code
    int32_t status;             // Usage status
    int64_t timestamp;          // Access timestamp
    int64_t accessDuration;     // Access duration
    PermissionUsedType type;     // Usage type (NORMAL_TYPE/GLOBAL_TYPE)
    int32_t accessCount;        // Access count
    int32_t rejectCount;        // Reject count
    int32_t lockScreenStatus;    // Lock screen status when accessed
};
```

**ContinuousPermissionRecord**: Active usage tracking structure
```cpp
struct ContinuousPermissionRecord {
    uint32_t tokenId;           // Token ID
    int32_t opCode;             // Permission operation code
    int32_t status;             // Active status
    int32_t pid;                // Process ID
    int32_t callerPid;          // Caller process ID
    PermissionUsedType usedType; // Usage type
    uint32_t callertokenId;      // Caller token ID
};
```

### 4. PermissionUsedRecordDb

**Location**: `include/database/permission_used_record_db.h`

Database wrapper for persistent permission usage record storage using SQLite.

**Responsibilities**:
- Manage database connection and lifecycle
- Create and update database schema
- Execute CRUD operations for all table types
- Handle prepared SQL statements for performance
- Support transaction operations for data consistency
- Manage database version and migrations

**Database Tables**:
- `permission_record_table`: Store permission usage records
- `permission_used_type_table`: Store permission used type information
- `permission_used_record_toggle_status_table`: Store per-user toggle status
- `permission_disable_policy_table`: Store permission disable policies

**Key Methods**:
- `Add`: Add records to database
- `Remove`: Remove records by conditions
- `FindByConditions`: Query records with conditions and pagination
- `DeleteExpireRecords`: Delete expired records
- `DeleteExcessiveRecords`: Delete excessive records when limit reached
- `DeleteHistoryRecordsInTables`: Delete records for specific tokens
- `Update`: Update records in database

**Database Location**: `/data/service/el1/public/access_token/permission_used_record.db`

### 5. ActiveStatusCallbackManager

**Location**: `include/active/active_status_callback_manager.h`

Manages callbacks for permission active status changes.

**Responsibilities**:
- Register/unregister active status callbacks
- Execute callbacks when active status changes
- Filter callbacks by permission list
- Handle callback death recipients

**Key Methods**:
- `AddCallback`: Register callback with permission list filter
- `RemoveCallback`: Unregister callback
- `ExecuteCallbackAsync`: Execute callback asynchronously
- `ActiveStatusChange`: Process active status change and notify callbacks

**CallbackData Structure**:
```cpp
struct CallbackData {
    AccessTokenID registerTokenId;
    std::vector<std::string> permList;      // Filtered permission list
    sptr<IRemoteObject> callbackObject_;
};
```

### 6. DisablePolicyCbkManager

**Location**: `include/disable_policy/disable_policy_cbk_manager.h`

Manages callbacks for permission disable policy changes.

**Responsibilities**:
- Register/unregister disable policy callbacks
- Execute callbacks when disable policy changes
- Filter callbacks by permission list

**Key Methods**:
- `AddCallback`: Register callback with permission list filter
- `RemoveCallback`: Unregister callback
- `ExecuteCallbackAsync`: Execute callback asynchronously

## Key Workflows

### 1. Add Permission Used Record

```
Client Application
    ↓
PrivacyManagerService::AddPermissionUsedRecord
    ↓
PermissionRecordManager::AddPermissionUsedRecord
    ↓
CheckPermissionUsedRecordToggleStatus (is enabled?)
    ↓
PermissionRecordManager::AddPermissionUsedRecordInner
    ↓
Create PermissionRecord
    ↓
MergeOrInsertRecord (merge with cached record or insert new)
    ↓
Memory Cache: permUsedRecList_
    ↓ [periodically or on demand]
UpdatePermissionUsedRecordToDb
    ↓
Database: permission_record_table
```

### 2. Start Using Permission (Active Status)

```
Client Application
    ↓
PrivacyManagerService::StartUsingPermission
    ↓
PermissionRecordManager::StartUsingPermission
    ↓
IsAllowedUsingPermission (check if allowed)
    ↓
Check: IsMuted? / IsDisabled? / LockScreenStatus?
    ↓ [if allowed]
AddRecordToStartList
    ↓
Memory Cache: startRecordList_
    ↓
ActiveStatusCallbackManager::ActiveStatusChange
    ↓
Notify all registered callbacks
```

### 3. Stop Using Permission

```
Client Application
    ↓
PrivacyManagerService::StopUsingPermission
    ↓
PermissionRecordManager::StopUsingPermission
    ↓
RemoveRecordFromStartList
    ↓
Memory Cache: Remove from startRecordList_
    ↓
ActiveStatusCallbackManager::ActiveStatusChange
    ↓
Notify all registered callbacks
```

### 4. Get Permission Used Records

```
Client Application
    ↓
PrivacyManagerService::GetPermissionUsedRecords
    ↓
PermissionRecordManager::GetPermissionUsedRecords
    ↓
GetRecordsFromLocalDB (query database)
    ↓
PermissionUsedRecordDb::FindByConditions
    ↓
DataTranslator::TranslationGenericValuesIntoPermissionUsedRecord
    ↓
FillPermissionUsedRecords (merge records by permission)
    ↓
Return PermissionUsedResult
```

## Configuration Files

### Privacy Configuration

PrivacyManager supports runtime configuration through the config policy framework. Configuration is loaded from the system config via `libaccesstoken_json_parse` library.

**Default Values**:
- `recordSizeMaximum_`: **500,000** records (`DEFAULT_PERMISSION_USED_RECORD_SIZE_MAXIMUM`)
- `recordAgingTime_`: **7 days** (`DEFAULT_PERMISSION_USED_RECORD_AGING_TIME`)

**Configurable Parameters**:
| Parameter | Description | Default |
|-----------|-------------|---------|
| `sizeMaxImum` | Maximum number of permission records to store | 500,000 |
| `agingTime` | Number of days before records expire and are deleted | 7 days |
| `globalDialogBundleName` | Bundle name for global privacy dialog | (platform-specific) |
| `globalDialogAbilityName` | Ability name for global privacy dialog | (platform-specific) |

**Configuration Loading**:
1. Service reads config via `GetConfigValue()` from config policy
2. If config is unavailable or values are 0/empty, defaults are used via `SetDefaultConfigValue()`
3. Config values are logged at service startup for verification

**Record Management Behavior**:
- When total records exceed `sizeMaxImum`, oldest records are deleted
- Records older than `agingTime` days are automatically deleted
- Cleanup is executed periodically via `DeletePermissionRecord()` and `DeleteExcessiveRecords()`

### Service Profile
- **Location**: `sa_profile/`
- **Purpose**: System ability profile configuration

## Important Notes

### Adding New user_grant Permissions

**CRITICAL**: When adding a new user_grant permission to the system, you must update the permission-to-opCode mapping in `Constant` class.

**Required Steps**:

1. **Add OpCode Enum Value** in `include/common/constant.h`:
   ```cpp
   enum OpCode {
       // ... existing codes ...
       OP_NEW_PERMISSION = XX,  // Add new enum value
   };
   ```

2. **Add Mapping in PERMISSION_OPCODE_MAP** in `src/common/constant.cpp`:
   ```cpp
   const std::map<std::string, int32_t> Constant::PERMISSION_OPCODE_MAP = {
       // ... existing mappings ...
       {"ohos.permission.NEW_PERMISSION", OP_NEW_PERMISSION},  // Add new mapping
   };
   ```

**Why This Is Required**:
- PermissionRecordManager uses `PERMISSION_OPCODE_MAP` to convert permission names to opCodes for storage
- The mapping is used in `AddPermissionUsedRecord`, `StartUsingPermission`, and other record operations
- Without the mapping, permission usage records cannot be created for the new permission
- Both the enum value and the map entry must be added for the permission to work correctly

**Verification**:
- After adding a new permission, test both usage record creation and querying
- Check service startup logs to ensure the mapping is loaded correctly

### Performance Critical Paths

1. **AddPermissionUsedRecord**: Called frequently when apps use permissions
   - Use in-memory cache (`permUsedRecList_`) to batch database writes
   - Periodically flush to database to avoid blocking callers
   - Use async interface when possible

2. **StartUsingPermission**: Called when apps begin using sensitive permissions
   - Must quickly check mute status, disable policy, lock screen status
   - Avoid blocking operations that could delay app functionality

3. **IsAllowedUsingPermission**: Called frequently to verify if permission usage is allowed
   - Check in-memory cache first (mute status, disable policy)
   - Minimize database queries

### Database Consistency

- Memory cache (`permUsedRecList_`) must stay synchronized with persistent storage
- Use `needUpdateToDb` flag in `PermissionRecordCache` to track dirty records
- Periodically flush cached records to database
- Implement proper rollback on operation failures

### Record Management Policies

1. **Toggle Status**: Per-user control for enabling/disabling permission usage records
   - When disabled: `permUsedRecToggleStatusMap_[userID] = false`
   - Records are not added when toggle is off

2. **Aging Policy**: Automatically delete records older than configured days
   - Configured by `recordAgingTime_`
   - Executed periodically via `DeletePermissionRecord`

3. **Size Limit**: Delete excessive records when limit reached
   - Configured by `recordSizeMaximum_`
   - Executed via `DeleteExcessiveRecords`

### SA (System Ability) Initialization

- Must complete quickly
- No blocking I/O during startup
- Cannot fail - ensure all dependencies are ready
- Initialize mute status, disable policy from database

### Camera Float Window

When camera is used by background apps, show float window to notify user:
- Managed by `IsCameraWindowShow()` and `RegisterWindowCallback()`
- Only enabled when `access_token_camera_float_window_enable` is true

### Mute Policy Types

| Type | Description | Priority |
|------|-------------|-----------|
| EDM Mute Policy | Enterprise device management mute policy | Highest |
| Privacy Mute Policy | User privacy settings mute policy | Medium |
| Temporary Mute Policy | Temporary mute (e.g., during call) | Lowest |

When multiple policies conflict, the most restrictive (muted) takes effect.

## Related Modules

| Module | Responsibility |
|--------|----------------|
| **AccessTokenManager** | Permission grant state (HAS permission?) |
| **PrivacyManager** | Permission usage records/status (USING permission?) |

## References

- [AGENTS.md](../../AGENTS.md) - Project overview and coding guide
- [services/accesstokenmanager/AGENTS.md](../accesstokenmanager/AGENTS.md) - AccessTokenManager documentation
- [privacy_kit.h](../../../interfaces/innerkits/privacy/include/privacy_kit.h) - Inner API interfaces
