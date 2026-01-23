# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is the **AccessTokenManager (ATM)** module for OpenHarmony. It provides unified permission management based on access tokens, controlling what permissions apps have to access sensitive data and APIs.

## Core Capabilities
### Access token manager
- Provides unified permission access control, enabling application processes and system service processes to query and verify permissions.
- Provides the capability to subscribe to permission status change events for specific processes.
- Supports per-user configuration of permission management policies.

### privacy manager
- Provides comprehensive lifecycle management of permission usage records, including adding, deleting,
   querying, and toggle control.
- Supports dynamic management of permission usage states, including starting/stopping permission
  usage and legitimacy verification.
- Offers permission policy configuration and status change subscription capabilities, supporting mute
  policy, background access policy, disable policy, and related callback registration.

### token sync manager
- Provides cross-device token synchronization capabilities in distributed scenarios, supporting query, update, and deletion operations for remote HAP token information.

### el5 file key manager
- Provides key management services for lock screen file encryption, supporting application and data group key generation and deletion, data access control, policy configuration, and callback registration.

## Architecture

### Poject Structure
```
/base/security/access_token
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
|   
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
└── services                    # Services
    ├── accesstokenmanager      # ATM service code.
    ├── privacymanager          # Privacy manager service code.
    └── tokensyncmanager        # Code of the access token synchronization service. 

```

## Core concept
### AccessToken
**Definition**: A unique identifier for applications, used for permission verification and application identification.

**Related Terms**:
- `AccessTokenID` (32-bit) - token identifier
- `FullTokenID` (64-bit) - full token identifier (token attribution + TokenID)

**Structure**:
- `tokenUniqueID` (20 bits) - Unique token number
- `type` (2 bits) - Token type (HAP/NATIVE/SHELL)
- `version` (3 bits) - Token format version
- `dlpFlag`, `cloneFlag`, `renderFlag` - Special state flags

### APL (Ability Privilege Level)
**Definition**: Ability privilege level classification that determines the permission scope an application can request.

**Levels**:
- `APL_NORMAL` - Normal applications
- `APL_SYSTEM_BASIC` - System basic applications
- `APL_SYSTEM_CORE` - System core applications (highest level)

**Impact**: Higher APL allows access to more sensitive permissions.

## Develop mode
AccessTokenManager 模块采用**分层架构**设计，从应用层 JS API 到服务端实现，完整调用链路如下：

```
┌─────────────────────────────────────────────────────────────┐
│                    Appliaction layer (ArkTS)                │
│                     import xxxx from ...                    │
└───────────────────────┬─────────────────────────────────────┘
                        │ NAPI/ANI binding
┌───────────────────────▼─────────────────────────────────────┐
│              Bridge layer                                   │
│              interfaces/kits/js/napi                        |
|              interfaces/kits/ets/ani                        │
└───────────────────────┬─────────────────────────────────────┘
                        │ call across language
┌───────────────────────▼─────────────────────────────────────┐
│                Innerkits (C++ SDK)                          │
│                interfaces/innerkits                         │
└───────────────────────┬─────────────────────────────────────┘
                        │ IPC (Binder/HIPC)
┌───────────────────────▼─────────────────────────────────────┐
│                 Service layer                               │
│                 services/                                   │
└─────────────────────────────────────────────────────────────┘
                        
```

## Build System

This codebase uses **GN (Generate Ninja)** as the build system, which is standard for OpenHarmony.

### Building the Module

```bash
# Build all access_token components from OpenHarmony root
./build.sh --product-name <product> --build-variant root --build-target access_token

# Common product names: rk3568, ohos-sdk
# Example for rk3568
./build.sh --product-name rk3568 --build-variant root --build-target access_token
```






