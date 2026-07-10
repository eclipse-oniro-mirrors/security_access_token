# AccessTokenManager Service

## Overview

AccessTokenManager (ATM) Service is the core permission management service for OpenHarmony. It manages access tokens which are unique identifiers for applications, controlling what permissions apps have to access sensitive data and APIs.

**Key Responsibility**: Manages permission **grant state** (whether an app HAS a permission: granted/denied) and grant mode (system_grant/user_grant). This is distinct from PrivacyManager which manages permission usage records and active status (when an app is actively USING a permission).

## Architecture

```
services/accesstokenmanager/
├── main/cpp/
│   ├── include/
│   │   ├── service/              # Main service implementation
│   │   │   └── accesstoken_manager_service.h
│   │   ├── permission/           # Permission management
│   │   │   ├── permission_manager.h
│   │   │   ├── accesstoken_info_manager.h
│   │   │   ├── hap_token_info_inner.h
│   │   │   ├── permission_data_brief.h
│   │   │   ├── short_grant_manager.h
│   │   │   ├── dlp_permission_set_manager.h
│   │   │   ├── install_session_manager.h
│   │   │   └── permission_constraint_check.h
│   │   ├── database/             # Database operations
│   │   │   ├── access_token_db.h
│   │   │   ├── access_token_db_operator.h
│   │   │   ├── access_token_db_loader.h
│   │   │   └── data_translator.h
│   │   ├── callback/             # Callback management
│   │   │   ├── callback_manager.h
│   │   │   └── accesstoken_callback_proxys.h
│   │   └── form_manager/         # Form manager integration
│   └── src/                      # Implementation files
└── test/                         # Unit tests
    ├── unittest/
    ├── mock/
    └── coverage/
```

## Where To Look

Use this table before editing service code in this directory.

| Task type | First paths to inspect | What else to read |
| --- | --- | --- |
| Four-phase install or update flow | `InstallSessionManager`, `AccessTokenManagerService`, `PermissionManager`, `AccessTokenInfoManager` | Trace all four phases together before changing one phase in isolation. |
| Permission verification hot path | `PermissionDataBrief`, `PermissionManager`, `VerifyAccessToken` call path | Check kernel, DB, and cache interactions before editing. |
| TokenID or UID allocation | `AccessTokenIDManager`, `AccessTokenInfoManager`, related migration or reserved-token logic | Check set membership invariants, cache ownership, and persistence updates together. |
| permission-state persistence | `database/`, `DataTranslator`, `PermissionManager`, `AccessTokenInfoManager` | Keep kernel -> DB -> cache update order and rollback rules intact. |
| permission definition | `frameworks/common/*/permission_map.*`, `frameworks/common/*.py`, `PermissionManager` | trace definition source, generated constants, runtime lookup. |
| IPC, IDL, or Parcel contract | `main/cpp/include/service`, `idl`, framework Parcel classes, client/proxy/stub call paths | Trace client -> proxy/stub -> service -> callback path before changing contract fields or semantics. |
| Migration or reserved token behavior | `AccessTokenMigrationManager`, `InstallSessionManager`, `AccessTokenIDManager` | Check startup recovery, reserved/untrusted transitions, and persisted state together. |

## When To Read More

Apply these routing rules before editing:

- For high-risk changes involving API, IDL, IPC, install flow, persistence, token lifecycle, or permission semantics, state the task category, documents read, and key constraints you found before editing.
- If the task changes any install or update phase, inspect the full four-phase flow before editing one phase alone.
- If the task changes `VerifyAccessToken`, `PermissionDataBrief`, or permission grant/revoke behavior, inspect kernel, DB, and cache order before editing.
- If the task changes TokenID/UID allocation or migration behavior, inspect reserved, untrusted, and active-state transitions before editing.
- If the task changes permission definitions, permission-name/opCode mapping, `permission_definitions.json`, or `permission_map.*`, read `frameworks/common/AGENTS.md` and the permission-definition sections first.
- If the task description or code mentions `reserved`, `untrusted`, `SPM`, `permission_map.h`, `PermissionDataBrief`, `ACL`, or `EDM`, load the corresponding cache, permission-definition, and validation sections first.

## Core Components

### 1. AccessTokenManagerService

**Location**: `main/cpp/include/service/accesstoken_manager_service.h`

The main system ability that provides IPC interfaces for permission management.

**Key Interfaces**:

| Interface | Description |
|-----------|-------------|
| `CheckHapSignInfo` | Verify HAP signature and create install session (Phase 1 of install/update) |
| `CheckHapPermissionInfo` | Check permission list (ACL/EDM) and initialize permission states (Phase 2) |
| `PrepareHapIdentity` | Create TokenID and allocate UID (Phase 3 of install, GID handled by BMS) |
| `UpdateHapPolicy` | Update policy for existing tokens (Phase 3 of update) |
| `FinishInstall` | Write to database, notify SPM, and cleanup session (Phase 4) |
| `DeleteToken` | Delete a token from the system |
| `VerifyAccessToken` | Verify if a token has a specific permission |
| `GrantPermission` | Grant a permission to a token |
| `RevokePermission` | Revoke a permission from a token |
| `GetHapTokenInfo` | Get HAP token information |
| `GetNativeTokenInfo` | Get native token information |
| `RegisterPermStateChangeCallback` | Register callback for permission state changes |

**Deprecated Interfaces**:

| Interface | Status | Replacement | Migration Notes |
|-----------|--------|-------------|-----------------|
| `InitHapToken` | **Deprecated** | `CheckHapSignInfo` + `CheckHapPermissionInfo` + `PrepareHapIdentity` + `FinishInstall` | Migrate to four-phase install flow for better atomicity and rollback support |
| `AllocLocalTokenID` | **Deprecated** | `PrepareHapIdentity` (Phase 3 of install flow) | UID allocation is now handled within the phased install process |
| `UpdateHapToken` | **Deprecated** | `CheckHapSignInfo` + `CheckHapPermissionInfo` + `UpdateHapPolicy` + `FinishInstall` | Migrate to four-phase update flow; use `UpdateHapPolicy` for policy updates in update scenarios |
| `DeleteToken` | **Deprecated** | N/A | Token deletion is now handled internally during app uninstallation by BMS |

**Migration Guide**:

The old one-stop interfaces (`InitHapToken`, `UpdateHapToken`) have been replaced with a phased approach to provide:
- **Better atomicity**: Each phase can fail independently with proper rollback
- **Permission pre-check**: Validate permissions (ACL/EDM) before allocating TokenID/UID
- **Reserved token support**: Preserve token identity and permission data across updates
- **Clear separation of concerns**: Signature check, permission check, identity allocation, and persistence are separate phases

**Old Install Flow** (Deprecated):
```
BMS → InitHapToken → (all operations in one call) → Token created
```

**New Install Flow** (Current):
```
BMS → CheckHapSignInfo (Phase 1)
   → CheckHapPermissionInfo (Phase 2)
   → PrepareHapIdentity (Phase 3)
   → FinishInstall (Phase 4)
```

### 2. AccessTokenInfoManager

**Location**: `main/cpp/include/permission/accesstoken_info_manager.h`

Manages in-memory cache of token information and coordinates database operations.

**Responsibilities**:
- Maintain `hapTokenInfoMap_` and `nativeTokenInfoMap_` for fast access
- Token ID allocation and management
- Database synchronization (memory-data consistency)
- Remote token management (distributed scenarios)

**Key Methods**:
- `CreateHapTokenInfo`: Create new HAP token entry
- `GetHapTokenInfoInner`: Retrieve token info from cache or database
- `RemoveHapTokenInfo`: Remove token from cache and database

### 3. PermissionManager

**Location**: `main/cpp/include/permission/permission_manager.h`

Handles permission grant/revoke operations and permission state verification.

**Responsibilities**:
- Permission grant/revoke logic
- Permission verification (`VerifyHapAccessToken`)
- User_grant permission handling with dialog flow
- Permission request toggle status management
- Location permission special handling

**Key Methods**:
- `GrantPermission`: Grant permission with specified flag
- `RevokePermission`: Revoke permission
- `VerifyHapAccessToken`: Check if token has permission
- `InitPermissionList`: Initialize permissions during token creation
- `InitPermState`: Initialize permission state with ACL/EDM/pre-auth/debug handling

### 4. InstallSessionManager

**Location**: `main/cpp/include/permission/install_session_manager.h`

Manages the install session lifecycle for app installation and update. Introduced to replace the one-stop `InitHapToken`/`UpdateHapToken` interfaces with a phased approach.

**Responsibilities**:
- Session lifecycle management (create, update, cleanup, timeout)
- Permission checking (ACL/EDM) before token allocation
- UID allocation (GID is handled by BMS, ATM does not perceive it)
- Token ID allocation with reserved token support
- Permission initialization and merging
- Database write coordination with SPM notification

**Key Methods**:
- `CheckHapSignInfo`: Verify signature, create session, return sessionId
- `CheckHapPermissionInfo`: Check permissions, initialize states, handle TYPE_INSTALL/REPLACE/MERGE
- `PrepareHapIdentity`: Allocate TokenID and UID, handle reserved tokens
- `UpdateHapPolicy`: Update policy for existing tokens in update scenarios
- `FinishInstall`: Write to database, notify SPM, cleanup session
- `GetTokenIdAndUid`: Allocate UID with multi-user support (GID is handled by BMS)
- `RollbackAll`: Rollback all session data on failure

**Session Mechanism**:
- Each install/update operation gets a unique `sessionId`
- Session data cached in memory during the phased process
- Automatic cleanup on timeout or caller death
- Ensures atomicity and proper rollback on failures

**Reserved Token Types**:
```cpp
enum class ReservedType {
    NONE = 0,                  // No reservation
    RESERVED_IDENTITY = 1,     // Reserve token identity (tokenId)
    RESERVED_DATA = 2          // Reserve both identity and permission data
};
```

### 5. PermissionDataBrief

**Location**: `main/cpp/include/permission/permission_data_brief.h`

Lightweight in-memory storage for permission states, optimized for fast permission verification.

**Data Structure**:
```cpp
typedef struct {
    int8_t status;      // Permission grant status
    uint8_t type;       // KERNEL_EFFECT_FLAG | HAS_VALUE_FLAG
    uint16_t permCode;  // Permission code
    uint32_t flag;      // Permission grant flag
} BriefPermData;
```

**Responsibilities**:
- Cache permission states for fast `VerifyAccessToken` access
- Synchronize with database on state changes
- Manage kernel permission lists
- Support Security Component (SecComp) granted permissions

### 6. HapTokenInfoInner

**Location**: `main/cpp/include/permission/hap_token_info_inner.h`

Internal representation of HAP token information.

**Key Fields**:
- `tokenInfoBasic_`: Basic token information (HapTokenInfo)
- `isRemote_`: Whether token is from remote device
- `isPermDialogForbidden_`: Whether permission dialog is disabled
- `permUpdateTimestamp_`: Last permission update timestamp

### 7. AccessTokenDb

**Location**: `main/cpp/include/database/access_token_db.h`

Database wrapper for persistent token storage using RDB (Relational Database). Uses singleton pattern with thread-safe operations via `std::shared_mutex`.

**Responsibilities**:
- Persistent storage for token and permission data
- Database corruption detection and restoration
- Transaction support for atomic multi-table operations
- Thread-safe read/write operations

**Key Methods**:
- `Modify`: Update records in database with condition matching
- `Find`: Query records from database
- `DeleteAndInsertValues`: Batch delete and insert operations within a transaction
- `GetRdb`: Get underlying RDB store instance

**Database Tables**:

| Table Name | Purpose | Primary Key |
|------------|---------|-------------|
| `hap_token_info_table` | HAP token basic information | `token_id` |
| `native_token_info_table` | Native token basic information | `token_id` |
| `permission_state_table` | Permission grant states | `(token_id, permission_name, device_id)` |
| `permission_definition_table` | Permission definitions | `(token_id, permission_name)` |
| `permission_request_toggle_status_table` | Permission request toggle status | - |
| `permission_extend_value_table` | Extended permission values (ACL extensions) | - |
| `hap_undefine_info_table` | HAP undefined permission info | - |
| `system_config_table` | System configuration | - |
| `user_policy_table` | User policy settings | - |

**Key Table Structures**:

**hap_token_info_table**:
```sql
CREATE TABLE hap_token_info_table (
    token_id INTEGER PRIMARY KEY,
    user_id INTEGER,
    bundle_name TEXT,
    inst_index INTEGER,
    dlp_type INTEGER,
    app_id TEXT,
    device_id TEXT,
    apl INTEGER,
    token_version INTEGER,
    token_attr INTEGER,
    api_version INTEGER,
    forbid_perm_dialog INTEGER,
    uid INTEGER NOT NULL DEFAULT -1,      -- SPM_DATA_ENABLE
    migrated INTEGER NOT NULL DEFAULT 0,  -- SPM_DATA_ENABLE
    reserved INTEGER NOT NULL DEFAULT 0   -- SPM_DATA_ENABLE
);
```

**permission_state_table**:
```sql
CREATE TABLE permission_state_table (
    token_id INTEGER,
    permission_name TEXT,
    device_id TEXT,
    grant_is_general INTEGER,
    grant_state INTEGER,
    grant_flag INTEGER,
    timestamp INTEGER DEFAULT 0,
    PRIMARY KEY(token_id, permission_name, device_id)
);
```

**permission_definition_table**:
```sql
CREATE TABLE permission_definition_table (
    token_id INTEGER,
    permission_name TEXT,
    available_level INTEGER,
    available_type INTEGER,
    is_set_cruliae INTEGER,
    kernel_effect INTEGER,
    has_value INTEGER,
    label TEXT,
    description TEXT,
    label_resource TEXT,
    description_resource TEXT,
    PRIMARY KEY(token_id, permission_name)
);
```

### 8. AccessTokenDbOperator

**Location**: `main/cpp/include/database/access_token_db_operator.h`

Static utility class providing database operations interface. Delegates to AccessTokenDb for actual execution.

**Key Methods**:
- `Modify`: Update single or multiple records
- `Find`: Query records by condition or column values
- `DeleteAndInsertValues`: Batch delete and insert in transaction

### 9. DataTranslator

**Location**: `main/cpp/include/database/data_translator.h`

Converts between domain objects (PermissionDef, PermissionStatus) and database GenericValues.

**Key Methods**:
- `TranslationIntoGenericValues(PermissionDef, GenericValues)`: Convert PermissionDef to DB format
- `TranslationIntoPermissionDef(GenericValues, PermissionDef)`: Convert DB format to PermissionDef
- `TranslationIntoGenericValues(PermissionStatus, GenericValues)`: Convert PermissionStatus to DB format
- `TranslationIntoPermissionStatus(GenericValues, PermissionStatus)`: Convert DB format to PermissionStatus
- `TranslationIntoExtendedPermission`: Convert extended permission data

### 10. PermissionConstraintCheck

**Location**: `main/cpp/include/permission/permission_constraint_check.h`

Handles permission constraint validation including ACL and EDM/Enterprise permission checks.

**Responsibilities**:
- ACL permission satisfaction check
- MDM/ENTERPRISE permission availability check
- Permission available range validation

**Key Methods**:
- `IsAclSatisfied`: Check if ACL requirements are met
- `IsPermAvailableRangeSatisfied`: Check if permission is available for app type

**ACL Check Rules**:
| Condition | Need ACL | ACL Check Method | Reject Condition |
|-----------|----------|------------------|------------------|
| APL ≥ availableLevel | No | N/A | N/A |
| APL < availableLevel | Yes | hasValue?aclExtendedMap:aclRequestedList | ACL not exist or provisionEnable=false |

**Permission Available Range Rules**:
| availableType | Allowed App Types |
|--------------|------------------|
| NORMAL | All apps |
| SYSTEM | System apps only |
| MDM | ENTERPRISE_MDM or debug version |
| ENTERPRISE_NORMAL | ENTERPRISE_MDM, ENTERPRISE_NORMAL, system apps, debug version |

## Key Workflows

### 1. App Installation (Four-Phase Flow)

**Phase 1: CheckHapSignInfo**
```
AppInstaller (BMS)
    ↓
AccessTokenManagerService::CheckHapSignInfo
    ↓
InstallSessionManager::CheckHapSignInfo
    ↓
Verify signature and create InstallSession
    ↓
Return sessionId and signature info
```

**Phase 2: CheckHapPermissionInfo**
```
AppInstaller (BMS)
    ↓
AccessTokenManagerService::CheckHapPermissionInfo
    ↓
InstallSessionManager::CheckHapPermissionInfo
    ↓
PermissionManager::InitPermissionList
    ↓
Check permission list (ACL/EDM)
    ↓
Initialize permission states
    ↓
Store in session cache
    ↓
Return permission check result
```

**Phase 3: PrepareHapIdentity**
```
AppInstaller (BMS)
    ↓
AccessTokenManagerService::PrepareHapIdentity
    ↓
InstallSessionManager::PrepareHapIdentity
    ↓
AccessTokenIDManager::GetTokenIdAndUid (allocate UID)
    ↓
Handle reserved token logic
    ↓
Return tokenId and uid
```

**Phase 4: FinishInstall**
```
AppInstaller (BMS)
    ↓
AccessTokenManagerService::FinishInstall
    ↓
InstallSessionManager::FinishInstall
    ↓
AccessTokenInfoManager::CreateHapTokenInfo
    ↓
new HapTokenInfoInner
    ↓
PermissionDataBrief::AddPermToBriefPermission
    ↓
Memory Cache: hapTokenInfoMap_
    ↓
AccessTokenInfoManager::AddHapTokenInfoToDb
    ↓
Database: Write to token_table and permission_state_table
    ↓
ExecuteSpmKernelTasks (notify SPM)
    ↓
Cleanup InstallSession
```

### 2. App Update (Four-Phase Flow)

**Phase 1: CheckHapSignInfo**
```
AppInstaller (BMS)
    ↓
AccessTokenManagerService::CheckHapSignInfo
    ↓
Verify signature and create InstallSession
    ↓
Return sessionId
```

**Phase 2: CheckHapPermissionInfo (TYPE_MERGE Scenario)**
```
AppInstaller (BMS)
    ↓
AccessTokenManagerService::CheckHapPermissionInfo
    ↓
InstallSessionManager::CheckHapPermissionInfo
    ↓
RebuildHapPolicy (merge old permissions from database)
    ↓
NoNeedPermissionInheritance check (debug/release switch)
    ↓
MergePermission (merge permission states using UpdatePermStatus)
    ↓
Store in session cache
    ↓
Return permission check result
```

**Phase 3: UpdateHapPolicy**
```
AppInstaller (BMS)
    ↓
AccessTokenManagerService::UpdateHapPolicy
    ↓
InstallSessionManager::UpdateHapPolicy
    ↓
Support multiple tokens (tokenIDToBundlePolicy)
    ↓
Update policy cache only (no DB write yet)
```

**Phase 4: FinishInstall**
```
AppInstaller (BMS)
    ↓
AccessTokenManagerService::FinishInstall
    ↓
Unified database write
    ↓
ExecuteSpmKernelTasks
    ↓
Cleanup InstallSession
```

### 3. Permission Verification (VerifyAccessToken)

```
Client Process
    ↓
Kernel Cache (fast path, ioctl)
    ↓ [if not in kernel cache]
AccessTokenManagerService::VerifyAccessToken
    ↓
PermissionDataBrief::VerifyPermissionStatus (low path, ipc)
    ↓
Return result (PERMISSION_GRANTED / PERMISSION_DENIED)
```

### 4. Permission Grant (GrantPermission)

```
PermissionManagerService
    ↓
AccessTokenManagerService::GrantPermission
    ↓
PermissionManager::GrantPermission
    ↓
HapTokenInfoInner::UpdatePermissionStatus
    ↓
PermissionDataBrief::UpdatePermissionStatus
    ↓
Memory Cache: Update requestedPermData_
    ↓
Database: Update permission_state_table
    ↓
CallbackManager: Notify registered callbacks
```

## Configuration Files

### Service Configuration
- **Path**: `/etc/access_token/accesstoken_config.json`
- **Purpose**: Configure ability names, dialog settings, timeouts
- **Conditional**: Only loaded when `CUSTOMIZATION_CONFIG_POLICY_ENABLE` is defined

## Important Notes

### Permission Definition Access Pattern

**Design Principle**: Always retrieve permission definitions from `permission_map.h` instead of querying the database `permission_definition_table`.

**Key Rules**:

1. **Runtime Access**: Use `GetPermissionBriefDef()` from `permission_map.h` for permission definition lookups
   - Higher performance (compile-time definitions)
   - Avoids database query overhead
   - More reliable than database data

2. **Data Persistence**: Use `permission_name` (string) for database storage, NOT `perm_code` (integer)
   - **Reason**: The mapping between permissions and opCodes is **unstable across versions**
   - A permission may have different opCodes before and after a system upgrade
   - Using `permission_name` ensures data compatibility across version upgrades

**Data Flow Example**:

```
Saving data:
  permissionName -> GetPermissionBriefDef() -> validate permission
  permissionName -> store in database

Loading data (Init):
  Read permissionName from database
  permissionName -> TransferPermissionToOpcode() -> permCode
  permCode -> memory data structure
```

**API Reference**:

| Function | Purpose | Location |
|----------|---------|----------|
| `GetPermissionBriefDef(name, def, code)` | Get permission definition and code | `permission_map.h` |
| `TransferPermissionToOpcode(name, code)` | Convert permission name to code | `permission_map.h` |
| `TransferOpcodeToPermission(code)` | Convert code to permission name | `permission_map.h` |

**Anti-Patterns** (DO NOT):

```cpp
// WRONG: Do not query permission_definition_table for definition
GenericValues condition;
condition.Put(TokenFiledConst::FIELD_PERMISSION_NAME, permName);
AccessTokenDb::GetInstance().Find(ACCESSTOKEN_PERMISSION_DEF, condition, results);

// CORRECT: Use permission_map.h
PermissionBriefDef briefDef;
uint32_t code;
if (!GetPermissionBriefDef(permName, briefDef, code)) {
    // handle error
}
```

**Database Storage Pattern**:

When designing new database tables that reference permissions:

```cpp
// CORRECT: Store permission_name
CREATE TABLE permission_extend_value_table (
    token_id INTEGER NOT NULL,
    permission_name TEXT NOT NULL,  -- Use string
    value TEXT NOT NULL
    PRIMARY KEY(token_id, permission_name)
);

// WRONG: Do not store perm_code
CREATE TABLE permission_extend_value_table (
    token_id INTEGER NOT NULL,
    perm_code INTEGER NOT NULL,  -- Avoid: unstable across versions
    value TEXT NOT NULL
    PRIMARY KEY(token_id, permission_name)
);
```

### Permission Definition Query Usage Constraints

**Critical Constraints**:

1. **Permission Existence vs Device Availability**
   - Successfully retrieving a permission definition does **NOT** guarantee the permission exists on the current device
   - Permission definitions are compile-time constants from `permission_map.h`
   - Device-specific permission availability must be verified separately

2. **Client-Side Visibility Limitation**
   - Client applications **cannot** directly determine permission visibility
   - The `isEnable` field in `PermissionDef` is **not initialized** to actual values on client side
   - Client queries must rely on server-side validation

3. **Server-Side Validation Requirement**
   - Server must use the `isEnable` field to determine if a permission definition truly exists and is usable
   - Only server-side permission definitions have properly initialized `isEnable` values
   - Permission availability checks must be performed on server side

**Usage Pattern**:
```
Client Side:
  Get permission definition from permission_map.h
  ↓ Cannot determine if permission is actually available on device

Server Side:
  Get permission definition with isEnable field
  ↓ Check isEnable == true
  ↓ Only then grant or verify the permission
```

### Application Info and Permission Caching

**Cache Architecture**:

AccessTokenInfoManager maintains multiple cache maps with different lifecycle and visibility characteristics:

1. **hapTokenInfoMap_ (Active Application Cache)**
   - **Purpose**: Stores active/running application token information
   - **Lifecycle**: Must be **resident in memory** at all times
   - **Visibility**: Externally queryable, visible to kernel
   - **Usage**: Fast path for permission verification on active apps

2. **inactiveTokenInfoMap_ (Inactive Application Cache)**
   - **Purpose**: Stores inactive application token information
   - **Contents**:
     - Applications with `reserved` status (uninstalled but data preserved)
     - Applications in `untrusted` status (not yet verified)
   - **Lifecycle**: **Dynamically loaded on demand**, released when no longer needed
   - **Visibility**: **Externally NOT queryable**, no kernel data
   - **Usage**: Loaded when needed for specific operations, released afterwards

3. **bundleInfoMap_ (Bundle-Level Cache)**
   - **Purpose**: Aggregates application information by bundle name
   - **Scope**: Includes all HAPs belonging to the same bundle
   - **Lifecycle**: Cached when bundle has any active state
   - **Contents**: Token list, bundle-level metadata

**Token ID Management Constraints**:

All allocated TokenIDs must belong to **exactly one** of the following sets:

| Set | Purpose | Visibility |
|-----|---------|------------|
| `tokenIdSet_` | Normal/active tokens | Externally queryable, kernel-visible |
| `reservedTokenIdSet_` | Reserved tokens (uninstalled apps) | Not queryable, no kernel data |
| `untrustedTokenIdSet_` | Untrusted tokens (pending verification) | Not queryable, no kernel data |

**Critical Rules**:
- **No Overlap**: A TokenID cannot exist in multiple sets simultaneously
- **Completeness**: Every allocated TokenID must belong to exactly one set
- **Transitions**: TokenIDs move between sets based on application lifecycle

**UID Management Constraints**:

- All allocated UIDs must have their corresponding bundleId added to `bundleIdSet_`
- **UID Uniqueness**: Different applications **cannot** share the same UID
- **Bundle Mapping**: Each UID maps to exactly one bundleId

**Cache Operations**:

```
App Install (Active):
  Allocate TokenID → Add to tokenIdSet_
  Allocate UID → Add to bundleIdSet_
  Create HapTokenInfoInner → Add to hapTokenInfoMap_
  Create BundleInfoInner → Add to bundleInfoMap_

App Uninstall (Reserved):
  Move TokenID from tokenIdSet_ to reservedTokenIdSet_
  Move from hapTokenInfoMap_ to inactiveTokenInfoMap_
  Keep in bundleInfoMap_ (bundle still exists)

Untrusted App:
  Add to untrustedTokenIdSet_
  Add to inactiveTokenInfoMap_
  Not visible externally, no kernel data

Untrusted → Trusted Upgrade:
  Move from untrustedTokenIdSet_ to tokenIdSet_
  Move from inactiveTokenInfoMap_ to hapTokenInfoMap_
  Now visible externally, kernel data populated
```

### New Application Processing Constraints

**1. Untrusted to Trusted Application Upgrade**

- **Supported**: Untrusted applications CAN be upgraded/replaced with trusted (verified) applications
- **Flow**:
  ```
  Untrusted HAP install → untrustedTokenIdSet_
  ↓
  Trusted HAP upgrade → tokenIdSet_
  ↓
  TokenID migration preserves existing permission states (if applicable)
  ```

**2. Inactive Application Visibility**

- **External Query**: Inactive application tokens are **NOT externally queryable**
- **Kernel Data**: No kernel permission data exists for inactive applications
- **Affected States**:
  - `reserved` status (uninstalled but preserved)
  - `untrusted` status (pending verification)

**3. Data Consistency Guarantee**

All permission state modifications must follow this strict order:

```
1. Operate on Kernel (SPM)
   ↓
2. Operate on Database
   ↓
3. Operate on Cache
```

**Rationale**:
- **Kernel First**: Ensures immediate enforcement, prevents security gaps
- **Database Second**: Persistent record, survives restarts
- **Cache Last**: In-memory optimization, can be rebuilt from DB

**Example (Permission Grant)**:
```
1. GrantPermission called
   ↓
2. Update kernel permission list (ExecuteSpmKernelTasks)
   ↓
3. Write to permission_state_table (Database Modify)
   ↓
4. Update PermissionDataBrief cache (Memory Update)
```

**Rollback Handling**:
- If step 2 (Database) fails: Rollback kernel changes
- If step 3 (Cache) fails: Kernel and DB already committed, cache can be rebuilt
- Transaction boundaries must ensure atomicity

### Performance Critical Paths

1. **VerifyAccessToken**: Called frequently during permission verification
   - Must minimize database queries
   - Use in-memory cache (`PermissionDataBrief`)
   - Avoid blocking operations

### Permission Initialization and Inheritance

**Permission Initialization (Install Scenario)**

Located at: `main/cpp/src/permission/permission_manager.cpp:1068`

Rules:
| Scenario | Rule | grantFlag | grantStatus |
|----------|------|-----------|-------------|
| SYSTEM_GRANT permission | Auto-grant | PERMISSION_SYSTEM_FIXED | PERMISSION_GRANTED |
| No pre-auth, non-debug | Deny | PERMISSION_DEFAULT_FLAG | PERMISSION_DENIED |
| Pre-auth不可取消 | Pre-grant | PERMISSION_SYSTEM_FIXED | PERMISSION_GRANTED |
| Pre-auth可取消 | Pre-grant | PERMISSION_PRE_AUTHORIZED_CANCELABLE | PERMISSION_GRANTED |
| Debug mode | Auto-grant | PERMISSION_USER_FIXED | PERMISSION_GRANTED |

**Permission Inheritance (Update Scenario)**

Located at: `main/cpp/src/permission/permission_data_brief.cpp:284`

The `UpdatePermStatus` function implements permission state inheritance during updates:

**Inheritance Rules**:
| Old Permission State | Old Flag | New Flag | Result |
|---------------------|----------|-----------|--------|
| Not granted | DEFAULT_FLAG | Any | Use new state |
| Not granted | SYSTEM_FIXED | SYSTEM_FIXED | Use new state |
| Not granted | PRE_AUTHORIZED_CANCELABLE | Any | Use new state |
| Any state | FIXED_BY_ADMIN_POLICY | SYSTEM_FIXED | Use new state |
| Any state | ADMIN_POLICIES_CANCEL | PRE_AUTHORIZED_CANCELABLE | Use new state |
| Any state | Other | Other | **Inherit old state** |

**NoNeedPermissionInheritance Control**:

Located at: `main/cpp/src/permission/install_session_manager.cpp:127`

Debug version upgrades to release version, or release version upgrades to debug version: skip permission inheritance (except for admin-policy fixed permissions).

### Database Consistency

- Memory cache must stay synchronized with persistent storage
- Use transactions for atomic multi-step operations
- Implement proper rollback on operation failures

## Minimum Validation By Change Type

- For service logic, install flow, permission-state, database, IDL, IPC, or Parcel changes, follow the common validation rules in `../../AGENTS.md`.
- TokenID/UID allocation, migration, or reserved-token changes: report how cache-set invariants and persistence behavior were validated.
- `VerifyAccessToken`, or SA startup flow changes: explain why the change does not add blocking work, extra DB queries, or heavy-path cost.
- If startup flow was changed, report which exception or failure path could cause abnormal service startup.

## Done Definition

- The affected service targets build, or the final response clearly states what could not be built.
- The final response states whether permission semantics, install-flow semantics, token lifecycle behavior, or persistence behavior changed.
- If runtime kernel, migration, or install-session scenarios could not be executed, the final response states the unverified scenario and remaining risk.

### SA (System Ability) Initialization

- Must complete quickly
- No blocking I/O during startup
- Cannot fail - ensure all dependencies are ready

## Related Modules

| Module | Responsibility |
|--------|----------------|
| **AccessTokenManager** | Permission grant state (HAS permission?) |
| **PrivacyManager** | Permission usage records/status (USING permission?) |
| **TokenSyncManager** | Distributed permission synchronization |
| **SPM (Signed Permission Monitor)** | Kernel permission enforcement (after FinishInstall) |

## References

- [AGENTS.md](../../AGENTS.md) - Project overview and coding guide
- [frameworks/common/AGENTS.md](../../frameworks/common/AGENTS.md) - Common permission map, validators, and shared guidance
- [access_token.h](../../../interfaces/innerkits/accesstoken/include/access_token.h) - Core data structures and permission flag definitions
- [permission_def.h](../../../interfaces/innerkits/accesstoken/include/permission_def.h) - Permission definitions
- [hap_token_info.h](../../../interfaces/innerkits/accesstoken/include/hap_token_info.h) - HAP token structures (HapPolicy, BundlePolicy, PermissionStatus)
- [install_session_manager.h](main/cpp/include/permission/install_session_manager.h) - Install session management
