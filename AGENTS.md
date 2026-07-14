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
- **Details**: @services/privacymanager/AGENTS.md

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

## Where To Look

Use this table before editing. If a directory has its own `AGENTS.md`, read that file before changing code under that scope.

| Task type | First paths to inspect | Required deeper guidance |
| --- | --- | --- |
| Public C++ SDK or system API change | `interfaces/innerkits`, `interfaces/kits`, `frameworks/accesstoken`, `services/accesstokenmanager/idl` | Read the matching API reference and the subsystem `AGENTS.md` for the service you are changing. |
| Permission grant state or token lifecycle logic | `services/accesstokenmanager`, `frameworks/accesstoken`, `interfaces/innerkits/accesstoken` | Read `services/accesstokenmanager/AGENTS.md` before editing service logic or IPC contracts. |
| Privacy usage record or active status logic | `services/privacymanager`, `frameworks/privacy`, `interfaces/innerkits/privacy` | Read `services/privacymanager/AGENTS.md` before editing persistence, callbacks, or IPC. |
| Token sync or distributed permission behavior | `services/tokensyncmanager`, `frameworks/tokensync`, `interfaces/innerkits/tokensync` | Read `services/tokensyncmanager/AGENTS.md` before editing protocol, device sync, or distributed verification. |
| El5 file key service or screen-lock file encryption logic | `services/el5filekeymanager`, `interfaces/inner_api/el5filekeymanager`, `frameworks/js/napi/el5filekeymanager`, `frameworks/ets/ani/el5filekeymanager` | Read `services/el5filekeymanager/AGENTS.md` before editing service lifecycle, memory management, or IPC behavior. |
| IPC/Parcel/IDL serialization | `frameworks/accesstoken`, `frameworks/privacy`, `services/*/idl`, `interfaces/innerkits/*/include` | Inspect generated or mirrored types, transaction codes, and service/client call paths before editing fields or order. |
| Database or persistence change | `services/accesstokenmanager/main/cpp/src/database`, `services/common/database`, service managers that read or write DB | Read the owning service `AGENTS.md` and trace in-memory cache update paths before changing schema or stored values. |
| JS/ETS/NAPI binding change | `frameworks/js`, `frameworks/ets`, `interfaces/kits/js` | Read the matching API reference first, then verify native and JS/ETS behavior stay aligned. |
| Common validators, permission mapping, utilities | `frameworks/common`, `services/common` | Check all service and SDK call sites before changing shared helpers. |

## Core Concepts

### AccessTokenID
A unique identifier for applications, used for permission verification and application identification. Each application instance has a unique AccessTokenID that differs across users and application clones.

### APL (Ability Privilege Level)
Classifies applications into privilege levels that determine the permission scope they can request:
- `APL_NORMAL` - Normal applications
- `APL_SYSTEM_BASIC` - System basic applications
- `APL_SYSTEM_CORE` - System core applications (highest level)

Details for core concepts: [Application Permission Management Overview](../../../docs/en/application-dev/security/AccessToken/app-permission-mgmt-overview.md)

## When To Read More

Apply these routing rules before editing:

- For high-risk changes involving API, IDL, IPC, persistence, permission semantics, or distributed behavior, state the task category, documents read, and key constraints you found before editing.
- If the task changes `services/accesstokenmanager`, read `services/accesstokenmanager/AGENTS.md` first.
- If the task changes `services/privacymanager`, read `services/privacymanager/AGENTS.md` first.
- If the task changes `services/tokensyncmanager`, read `services/tokensyncmanager/AGENTS.md` first.
- If the task changes `frameworks/js`, `frameworks/ets`, or `interfaces/kits/js`, read the relevant API reference first because external behavior must stay compatible.
- If the task changes `services/*/idl`, `frameworks/*` Parcel classes, or IPC transaction handlers, trace the full client -> proxy/stub -> service path before editing.
- If the task changes database reads, writes, or cache refresh logic, inspect both persistence code and in-memory ownership code before editing.
- If the task description or code mentions `AccessTokenID`, `APL`, `grant state`, `grant flag`, `token sync`, `distributed permission`, `permission active status`, or `usage record`, read the core concept doc and the owning subsystem guidance before editing.
- If the task touches `VerifyAccessToken`, `AddPermissionUsedRecord`, or `StartUsingPermission`, treat it as a performance-sensitive path and inspect existing hot-path behavior before changing logic.


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
[OpenHarmony C Coding Style Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-coding-style-guide.md)

[OpenHarmony C++ Coding Style Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-cpp-coding-style-guide.md)

[OpenHarmony C/C++ Secure Coding Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-c-cpp-secure-coding-guide.md)

[OpenHarmony Security Design Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-security-design-guide.md)

[OpenHarmony Security Test Guide](https://gitcode.com/openharmony/docs/blob/master/en/contribute/OpenHarmony-security-test-guide.md)

### Additional Coding Rules
- Do not mix signed and unsigned types. Keep integer types consistent in declarations, comparisons, arithmetic, and loop/index logic to avoid implicit conversions and unexpected behavior.
- Do not introduce circular dependencies. Keep dependencies acyclic across modules, directories, and files, and avoid mutual inclusion or call chains that create circular references between files within the same directory.
- Keep source line width within 120 characters. If a line exceeds that limit, refactor it to comply.
- Keep functions within 50 lines where practical. If logic would exceed that size, split it into smaller helpers while preserving readability and behavior.

## API Reference
[Public API for Access Token Manager ](../../../docs/en/application-dev/reference/apis-ability-kit/js-apis-abilityAccessCtrl.md)

[System API for Access Token Manager ](../../../docs/en/application-dev/reference/apis-ability-kit/js-apis-abilityAccessCtrl-sys.md)

[System API for Privacy Manager ](../../../docs/en/application-dev/reference/apis-ability-kit/js-apis-privacyManager-sys.md)

[API for El5 Filekey Manager](../../../docs/en/application-dev/reference/apis-ability-kit/js-apis-screenLockFileManager.md)

## Constraints And Boundaries

### Do Not Change Without Explicit Review
- Do not change public API signatures, argument meaning, return codes, callback contracts, or lifecycle semantics in `interfaces/kits`, `interfaces/innerkits`, `frameworks/js`, or `frameworks/ets` without compatibility review.
- Do not change permission grant semantics, permission usage semantics, `APL` meaning, token type meaning, or verification result interpretation without subsystem-level confirmation.
- Do not change IPC transaction codes, Parcel field order, IDL field meaning, or serialized data layout without checking all client, stub, proxy, and service call sites for compatibility.
- Do not change database schema, persisted key names, stored value formats, or cross-version migration behavior without tracing rollback and startup recovery logic.
- Do not bypass permission checks, trust checks, authentication checks, device trust assumptions, or cross-user isolation rules for convenience.
- Do not edit generated outputs as the source of truth when the change should be made in the corresponding `.idl`, template, or handwritten source file.

### Ask Before High-Risk Changes
- Ask before changing `VerifyAccessToken`, `AddPermissionUsedRecord`, `StartUsingPermission`, or other hot paths in a way that may add blocking I/O, new DB access, or heavy iteration.
- Ask before introducing new third-party dependencies, changing feature flags, or changing whether a capability is gated by a build flag.

### Concurrency And Reentrancy Boundaries
- Do not invoke synchronous callbacks, IPC requests, or cross-module notifications while holding locks if they may re-enter the current module.
- Limit lock scope to local state updates, capture notification data before unlocking, and perform external callbacks only after the lock is released.

### Project-Specific Invariants
- Keep permission grant state logic in AccessTokenManager distinct from permission usage status logic in PrivacyManager.
- Keep in-memory cache and database state synchronized; when persistence fails, preserve or restore a consistent state instead of partially updating one side.
- Keep dependency direction acyclic across `interfaces`, `frameworks`, and `services`; avoid adding service-only knowledge into public SDK layers.
- Preserve DFX behavior when changing fault paths, logs, or observability points; do not silently remove useful diagnostics from high-risk flows.

### Common Agent Failure Modes
- Do not change only `.idl` or Parcel definitions without checking the matching proxy, stub, service, client, tests, and any manually converted containers.
- Do not change only database persistence logic without checking cache initialization, refresh, rollback, and startup recovery paths.
- Do not change SDK or JS/ETS API exposure without checking the corresponding native implementation and reference documentation stay aligned.
- Do not optimize hot paths by skipping validation, permission checks, or state synchronization that the existing design depends on.

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
- **No destructive intermediate state during updates**: For token, permission, record, or database update flows, prefer in-place update or atomic replacement over delete-and-recreate patterns. If a rebuild is required, keep the original valid state recoverable until the new state is fully committed, and ensure rollback restores the complete pre-update state.

## Minimum Validation By Change Type

- Compile the affected business code and test targets by following the commands in the `Build System` section.
- Run the corresponding unit tests for the changed scope.
- Run the corresponding fuzz tests for the changed scope when fuzz targets exist.
- Hot-path changes: in addition to building, explain why the change does not add blocking work or extra heavy-path cost.

## Done Definition

- The changed code builds for the affected target set, or the final response clearly states what could not be built.
- The changed code preserves API, IPC, persistence, and permission semantics unless the task explicitly requires changing them.
- The final response reports the commands run, the result, any skipped validation, and the remaining risks or compatibility concerns.

## If Validation Cannot Run

- State exactly which command could not be run.
- State why it could not be run, such as missing environment, excessive runtime, or unrelated build breakage.
- State the best partial validation that was completed and the remaining risk.

## History Record
| version | date | modify content | writer |
|------|------|---------|--------|
| v1.0 | 2026-01-31 | primary version | xiacong |
| v1.1 | 2026-02-05 | clarify distinction between Permission Grant State (AccessTokenManager) and Permission Usage Status (PrivacyManager) | hehehe-li |
| v1.2 | 2026-07-10 | add task routing, high-risk boundaries, and validation loop guidance for coding agents | xiacong, AI |
| v1.3 | 2026-07-14 | add repository-wide lock callback safety and update-state consistency constraints | linshuqing, AI |
