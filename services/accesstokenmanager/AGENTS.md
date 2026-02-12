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
│   │   │   └── dlp_permission_set_manager.h
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

## Core Components

### 1. AccessTokenManagerService

**Location**: `main/cpp/include/service/accesstoken_manager_service.h`

The main system ability that provides IPC interfaces for permission management.

**Key Interfaces**:

| Interface | Description |
|-----------|-------------|
| `InitHapToken` | Initialize HAP token (called during app installation) |
| `UpdateHapToken` | Update existing HAP token information |
| `DeleteToken` | Delete a token from the system |
| `VerifyAccessToken` | Verify if a token has a specific permission |
| `GrantPermission` | Grant a permission to a token |
| `RevokePermission` | Revoke a permission from a token |
| `GetHapTokenInfo` | Get HAP token information |
| `GetNativeTokenInfo` | Get native token information |
| `RegisterPermStateChangeCallback` | Register callback for permission state changes |

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

### 4. PermissionDataBrief

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

### 5. HapTokenInfoInner

**Location**: `main/cpp/include/permission/hap_token_info_inner.h`

Internal representation of HAP token information.

**Key Fields**:
- `tokenInfoBasic_`: Basic token information (HapTokenInfo)
- `isRemote_`: Whether token is from remote device
- `isPermDialogForbidden_`: Whether permission dialog is disabled
- `permUpdateTimestamp_`: Last permission update timestamp

### 6. AccessTokenDb

**Location**: `main/cpp/include/database/access_token_db.h`

Database wrapper for persistent token storage using RDB (Relational Database).

**Database Tables**:
- `token_table`: Store basic token information
- `permission_state_table`: Store permission grant states
- `permission_def_table`: Store permission definitions
- `extended_perm_table`: Store extended permission values

## Key Workflows

### 1. App Installation (InitHapToken)

```
AppInstaller
    ↓
AccessTokenManagerService::InitHapToken
    ↓
PermissionManager::InitPermissionList
    ↓
AccessTokenInfoManager::CreateHapTokenInfo
    ↓
new HapTokenInfoInner
    ↓
PermissionDataBrief::AddPermToBriefPermission
    ↓
Memory Cache: requestedPermData_
    ↓
AccessTokenInfoManager::AddHapTokenInfoToDb
    ↓
Database: hap_token_info_table
    ↓
AccessTokenInfoManager::AddHapTokenInfo
    ↓
Memory Cache: hapTokenInfoMap_
```

### 2. Permission Verification (VerifyAccessToken)

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

### 3. Permission Grant (GrantPermission)

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

### Performance Critical Paths

1. **VerifyAccessToken**: Called frequently during permission verification
   - Must minimize database queries
   - Use in-memory cache (`PermissionDataBrief`)
   - Avoid blocking operations

### Database Consistency

- Memory cache must stay synchronized with persistent storage
- Use transactions for atomic multi-step operations
- Implement proper rollback on operation failures

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

## References

- [AGENTS.md](../../AGENTS.md) - Project overview and coding guide
- [access_token.h](../../../interfaces/innerkits/accesstoken/include/access_token.h) - Core data structures
- [permission_def.h](../../../interfaces/innerkits/accesstoken/include/permission_def.h) - Permission definitions
