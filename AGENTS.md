# AGENTS.md

## Project Overview

This is the **AccessTokenManager (ATM)** module for OpenHarmony. It provides unified permission management based on access tokens, controlling what permissions apps have to access sensitive data and APIs.

## Basic Information
| Property | Value |
|----------|-------|
| Repository Name | security_access_token |
| Subsystem | security |
| Primary Language | C++ |
| Last Updated | 2026-01-31 |

## Architecture

### Document Directory Structure
```
/base/security/access_token
├── interfaces                  # Inner interfaces (C++ SDK for system components)
│   ├── innerkits               # Internal interfaces.
│   │   ├── accesstoken         # Access token management interfaces
│   │   ├── nativetoken         # Native process token interfaces
│   │   ├── privacy             # Privacy management interfaces
│   │   ├── token_callback      # Token callback interfaces
│   │   ├── token_setproc       # internal interfaces for exchanging token IDs.
│   │   └── tokensync           # Token sync interfaces
│   └── kits                    # Outer interfaces (APIs for applications)
│       ├── capi                # C API interfaces
│       └── js                  # JS API interfaces.
├── frameworks                  # Code of basic functionalities.
│   ├── accesstoken             # Access token IPC data serialization (Parcel class definitions and implementations)
│   ├── common                  # Common components (validators, logging, utilities, permission mapping)
│   ├── privacy                 # Privacy management IPC data serialization
│   ├── tokensync               # Token sync IPC interface definitions
│   ├── json_adapter            # JSON parsing utilities (based on cJSON)
│   ├── js                      # JavaScript NAPI binding implementations
│   ├── ets                     # ArkTS (ETS/ANI) binding implementations
│   ├── inner_api               # Internal APIs (cross-module call interfaces)
│   └── test                    # Framework layer unit tests
└── services                    # Services
    ├── accesstokenmanager      # ATM service code.
    ├── el5filekeymanager       # el5 filekey service code.
    ├── privacymanager          # Privacy manager service code.
    └── tokensyncmanager        # Code of the access token synchronization service. 

```

## Core Capabilities
### Access Token Manager
- **Location**: `frameworks/accesstoken`, `frameworks/ets/ani/accesstoken`, `frameworks/js/napi/accesstoken`, `interfaces/innerkits/accesstoken`, `services/accesstokenmanager`
- **Purpose**:
  - **Manage Permission Grant State**: Manage permission grant/revoke state (granted/denied) and grant flag. This is about whether an app HAS a permission, not whether it is USING it.
  - Provide unified permission management enabling application and system service processes to request and verify permission.
  - Provide the capability to subscribe to permission grant status change events for specific processes.
  - Provide capabilities for granting and revoking permissions by user and system mechanism.
- **Details**: @services/accesstokenmanager/AGENTS.md

### Privacy Manager
- **Location**: `frameworks/privacy`, `frameworks/ets/ani/privacy`, `frameworks/js/napi/privacy`, `interfaces/innerkits/privacy`, `services/privacymanager`
- **Purpose**:
  - **Manage Permission Usage Records/Status**: Manage permission usage records and active status (when an app is actively using a permission).
  - Support validation whether a process or application is allowed to use permissions.
  - Provide the capability to add and persist permission usage records.
  - Provide the switch of permissions records. When the switch is turned off permission records of the user will be deleted.
  - Manage the usage status of sensitive permissions and provides the capability to subscribe to active status change notifications.

### Token Sync Manager
- **Location**: `frameworks/tokensync`, `interfaces/innerkits/tokensync`, `services/tokensyncmanager`
- **Purpose**: 
  - Synchronize distributed permissions among trusted devices and update when the permission status changes.
  - Support permission verification to check whether the peer in the RPC call has the distributed permission.
- **Details**: @services/tokensyncmanager/AGENTS.md

### El5 File Key Manager
- **Location**: `frameworks/ets/ani/el5filekeymanager`, `frameworks/js/napi/el5filekeymanager`, `interfaces/inner_api/el5filekeymanager`, `services/el5filekeymanager`
- **Purpose**: 
  - Provides key management services for lock screen file encryption, supporting application and data group key generation and deletion, data access control.

## Core Concepts

### AccessTokenID
A unique identifier for applications, used for permission verification and application identification. Each application instance has a unique AccessTokenID that differs across users and application clones.

### APL (Ability Privilege Level)
Classifies applications into privilege levels that determine the permission scope they can request:
- `APL_NORMAL` - Normal applications
- `APL_SYSTEM_BASIC` - System basic applications
- `APL_SYSTEM_CORE` - System core applications (highest level)

Details for core concepts: [Application Permission Management Overview](../../../docs/en/application-dev/security/AccessToken/app-permission-mgmt-overview.md)


## Build System

This codebase uses **GN (Generate Ninja)** as the build system, which is standard for OpenHarmony.

### Feature Flags

The module supports various feature flags defined in [access_token.gni](access_token.gni) that control optional functionality:

#### User-Configurable Flags
- Support Camera Float Window: access_token_camera_float_window_enable

#### Dependency-Based Feature Flags
These flags are automatically enabled/disabled based on `global_parts_info` dependencies:
- ability_runtime: ability_runtime_enable
- Dfx: hicollie_enable
- Multimedia: audio_framework_enable, camera_framework_enable
- Security: security_guard_enable, token_sync_enable, dlp_permission_enable
- Platform-specific: light_device_enable

**Note**: Dependency-based flags default to `false` unless the corresponding part is included in the build configuration.

### Building Module

```bash
# Build access_token components from OpenHarmony root
./build.sh --product-name <product> --build-target access_token

# Build unit tests
./build.sh --product-name <product> --build-target base/security/access_token:accesstoken_build_module_test

# Build fuzz tests
./build.sh --product-name <product> --build-target base/security/access_token:accesstoken_build_fuzz_test --gn-args use_cfi=false use_thin_lto=false

# Common product names: rk3568, ohos-sdk
# Example for rk3568
./build.sh --product-name rk3568 --build-target access_token

# part compile for access_token components from OpenHarmony root
# -i indicates compiling function code
hb build access_token -i

# -t indicates compiling test cases
hb build access_token -t --gn-args use_cfi=false use_thin_lto=false
```

### Outputs Location
```bash
# output of function code for build all 
./out/rk3568/security/access_token

# unit test
./out/rk3568/tests/unittest/access_token

# fuzztest
./out/rk3568/tests/fuzztest/access_token

# output of part compile
./out/standard/src_test/security/access_token

# unit test of part compile
./out/standard/src_test/tests/unittest/access_token

# fuzz test of part compile
./out/standard/src_test/tests/fuzztest/access_token
```

### Running Tests
```bash
# it runs in test framework
# run unit test
run -t UT -tp access_token

# run fuzz test
run -t FUZZ -tp access_token
```

## Coding Guide
[Coding Style Guide](../../../docs/en/contribute/OpenHarmony-c-coding-style-guide.md)

[Secure Coding Guide](../../../docs/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md)

## API Reference
[Public API for Access Token Manager ](../../../docs/en/application-dev/reference/apis-ability-kit/js-apis-abilityAccessCtrl.md)

[System API for Access Token Manager ](../../../docs/en/application-dev/reference/apis-ability-kit/js-apis-abilityAccessCtrl-sys.md)

[System API for Privacy Manager ](../../../docs/en/application-dev/reference/apis-ability-kit/js-apis-privacyManager-sys.md)

[API for El5 Filekey Manager](../../../docs/en/application-dev/reference/apis-ability-kit/js-apis-screenLockFileManager.md)

## Common Issue
### SA Initialization
- **Avoid time-consuming operations**: System ability startup must complete quickly; do not perform blocking I/O, network requests, or complex computations during initialization
- **No failures allowed**: Startup operations must not fail; ensure all dependencies and resources are properly prepared before initialization.

### Performance Requirements
- **VerifyAccessToken API**: This interface has strict performance requirements as it is called frequently during permission verification; avoid heavy database queries or complex logic in the hot path.
- **AddPermissionUsedRecord API**: This interface is called when applications use sensitive permissions; optimize database writes to avoid blocking callers, consider batch or asynchronous operations for record persistence.
- **StartUsingPermission API**: This interface is invoked when applications begin using permissions; avoid blocking operations that could delay application startup or feature access.

### Database Operations
- **Memory-data consistency**: When performing database operations, ensure in-memory data structures stay synchronized with persistent storage.
- **Transaction rollback**: On operation failures, implement proper rollback mechanisms to restore data to a consistent state; use database transactions for atomic multi-step operations.

## History Record
| version | date | modify content | writer |
|------|------|---------|--------|
| v1.0 | 2026-01-31 | primary version | xiacong |
| v1.1 | 2026-02-05 | clarify distinction between Permission Grant State (AccessTokenManager) and Permission Usage Status (PrivacyManager) | hehehe-li |
