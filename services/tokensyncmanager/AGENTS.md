# TokenSyncManager Service

## Overview

TokenSyncManager Service is the distributed permission synchronization service for OpenHarmony. It synchronizes access tokens and permission states among trusted devices in a distributed network, enabling cross-device permission verification and management.

**Key Responsibility**: Synchronize permission grant states across distributed devices. When permission states change on one device (grant/revoke or app update), TokenSyncManager propagates these changes to trusted devices to ensure consistent permission enforcement across the distributed system.

## Architecture

```
services/tokensyncmanager/
├── include/
│   ├── service/                   # Main service implementation
│   │   ├── token_sync_manager_service.h    # System ability entry point
│   │   └── token_sync_manager_stub.h       # IPC interface implementation
│   ├── remote/                    # Remote communication layer
│   │   ├── remote_command_manager.h        # Command routing and buffering
│   │   ├── remote_command_executor.h       # Per-device command execution
│   │   ├── remote_command_factory.h        # Command instantiation
│   │   ├── soft_bus_manager.h              # SoftBus service binding
│   │   ├── soft_bus_channel.h              # Communication channel
│   │   ├── soft_bus_socket_listener.h      # Socket event handling
│   │   ├── soft_bus_device_connection_listener.h  # Device connection events
│   │   └── rpc_channel.h                  # RPC channel abstraction
│   ├── command/                   # Remote command implementations
│   │   ├── base_remote_command.h          # Base class for all commands
│   │   ├── sync_remote_hap_token_command.h   # Sync HAP token command
│   │   ├── update_remote_hap_token_command.h  # Update HAP token command
│   │   └── delete_remote_token_command.h      # Delete token command
│   ├── protocol/                  # Communication protocol
│   │   └── remote_protocol.h              # Protocol data structures
│   ├── device/                    # Device management
│   │   ├── device_info.h                 # Device info data structure
│   │   ├── device_info_manager.h         # Device info cache
│   │   └── device_info_repository.h      # Device info storage
│   └── common/                    # Common utilities
│       └── constant.h                   # Constants and error codes
└── src/                         # Implementation files
└── test/                        # Unit tests
    ├── unittest/
    ├── mock/
    └── coverage/
```

## Where To Look

Use this table before editing service code in this directory.

| Task type | First paths to inspect | What else to read |
| --- | --- | --- |
| Protocol field or version change | `include/protocol`, `include/command`, `include/remote`, serialization helpers in command implementations | Trace requestor `Prepare()`, responder `Execute()`, and requestor `Finish()` together. |
| Remote command behavior change | `include/command`, `src/command`, `include/remote/remote_command_factory.h` | Check command creation, serialization, execution, and response handling as one chain. |
| Device online/offline or channel lifecycle | `include/remote/soft_bus_manager.h`, `include/remote/soft_bus_channel.h`, `include/device`, `RemoteCommandManager` | Inspect buffering, reconnection, and cleanup flow before editing. |
| Device ID conversion or identity handling | `include/device`, `include/remote/soft_bus_manager.h` | Keep `networkId`, `UUID`, and `UDID` conversion rules aligned. |
| IPC or service entry behavior | `include/service`, service stub files, remote access-token call sites | Trace local service call -> remote command -> remote service behavior before changing the contract. |

## When To Read More

Apply these routing rules before editing:

- For high-risk changes involving protocol fields, versioning, distributed semantics, or device identity handling, state the task category, documents read, and key constraints you found before editing.
- If the task changes `RemoteProtocol`, JSON payload structure, or command serialization helpers, inspect compatibility rules and all `Prepare/Execute/Finish` stages before editing.
- If the task changes `SoftBus`, channel lifecycle, or device online/offline handling, inspect buffering and retry behavior before editing.
- If the task description or code mentions `requestVersion`, `responseVersion`, `UUID`, `UDID`, `networkId`, `SoftBus`, or `RemoteProtocol`, load the protocol and device-management sections first.

## Core Components

### 1. TokenSyncManagerService

**Location**: `include/service/token_sync_manager_service.h`

The main system ability that provides IPC interfaces for distributed token synchronization. Extends `SystemAbility` and `TokenSyncManagerStub`.

**Key Interfaces**:

| Interface | Description |
|-----------|-------------|
| `OnStart` | Service initialization, start event runners |
| `OnStop` | Service cleanup |
| `GetRemoteHapTokenInfo` | Get HAP token info from remote device |
| `DeleteRemoteHapTokenInfo` | Delete remote HAP token info |
| `UpdateRemoteHapTokenInfo` | Update remote HAP token info |

**Event Handlers**:
- `sendHandler_`: Handles outgoing commands to remote devices
- `recvHandler_`: Handles incoming commands from remote devices

### 2. RemoteCommandManager

**Location**: `include/remote/remote_command_manager.h`

Central manager for remote command execution and buffering. Maintains a map of `RemoteCommandExecutor` instances, one per target device.

**Responsibilities**:
- Create and manage per-device `RemoteCommandExecutor` instances
- Buffer commands when devices are offline
- Execute commands immediately when devices are online
- Handle device online/offline events

**Key Methods**:
- `AddCommand`: Add command to buffer for a specific device
- `ExecuteCommand`: Execute command immediately
- `ProcessDeviceCommandImmediately`: Process all buffered commands for a device
- `NotifyDeviceOnline`: Initialize channel when device comes online
- `NotifyDeviceOffline`: Clean up resources when device goes offline

### 3. RemoteCommandExecutor

**Location**: `include/remote/remote_command_executor.h`

Per-device command executor with command buffering and channel management.

**Responsibilities**:
- Maintain command buffer (`std::deque<BaseRemoteCommand>`)
- Create and manage RPC channel to target device
- Execute commands sequentially
- Handle remote response processing

**Key Methods**:
- `AddCommand`: Add command to buffer
- `ProcessBufferedCommands`: Execute all buffered commands
- `ProcessBufferedCommandsWithThread`: Async execution with thread
- `ExecuteRemoteCommand`: Execute single command (local or remote)

**Execution Flow**:
```
Requestor Side: Prepare() -> Send via Channel -> Finish()
Responder Side: Receive -> Execute() -> Send Response
```

### 4. BaseRemoteCommand

**Location**: `include/command/base_remote_command.h`

Abstract base class for all remote commands. Implements the Command pattern for distributed operations.

**Command Lifecycle**:

| Phase | Location | Description |
|-------|-----------|-------------|
| `Prepare()` | Requestor | Prepare command payload before sending |
| `Execute()` | Responder | Execute the command on remote device |
| `Finish()` | Requestor | Process response after remote execution |

**Key Methods**:
- `ToJsonPayload`: Serialize command to JSON
- `FromRemoteProtocolJson`: Deserialize from JSON
- `ToHapTokenInfosJson` / `FromHapTokenInfoJson`: Token info serialization
- `ToPermStateJson` / `FromPermStateJson`: Permission state serialization

**Concrete Commands**:
- `SyncRemoteHapTokenCommand`: Request full token info from remote device
- `UpdateRemoteHapTokenCommand`: Push token update to remote device
- `DeleteRemoteTokenCommand`: Delete token on remote device

### 5. RemoteCommandFactory

**Location**: `include/remote/remote_command_factory.h`

Factory for creating command instances from JSON payloads.

**Responsibilities**:
- Parse command name from JSON
- Instantiate appropriate command class
- Handle unknown command types

### 6. SoftBusManager

**Location**: `include/remote/soft_bus_manager.h`

Manages SoftBus service binding and device connections. SoftBus is OpenHarmony's distributed communication bus.

**Responsibilities**:
- Initialize and bind to SoftBus service
- Manage socket connections to peer devices
- Handle device online/offline events
- Convert between different device ID types (networkId, UUID, UDID)

**Key Methods**:
- `Initialize`: Bind SoftBus service and initialize
- `BindService`: Open session with peer device
- `CloseSocket`: Close socket connection
- `GetUniversallyUniqueIdByNodeId`: Convert networkId to UUID
- `GetUniqueDeviceIdByNodeId`: Convert networkId to UDID

**Device ID Types**:
- **networkId**: Dynamic ID assigned by SoftBus for active connection
- **UUID (UniversallyUniqueId)**: Persistent unique device identifier
- **UDID (UniqueDeviceId)**: Unique device ID for device management

### 7. RpcChannel / SoftBusChannel

**Location**: `include/remote/rpc_channel.h`, `include/remote/soft_bus_channel.h`

Abstraction for RPC communication with remote devices.

**Responsibilities**:
- Send commands to remote device
- Receive responses from remote device
- Manage socket lifecycle
- Handle connection errors

### 8. DeviceInfoManager

**Location**: `include/device/device_info_manager.h`

Manages cached device information for online and local devices.

**Responsibilities**:
- Cache device info (networkId, UUID, UDID, name, type)
- Add/remove device info
- Convert between device ID types
- Check device existence

**Key Methods**:
- `AddDeviceInfo`: Add device to cache
- `GetDeviceInfo`: Get cached device info
- `ConvertToUniversallyUniqueId`: Convert nodeId to UUID
- `ConvertToUniqueDeviceId`: Convert nodeId to UDID

### 9. RemoteProtocol

**Location**: `include/protocol/remote_protocol.h`

Protocol data structure for remote command communication.

**Fields**:
```cpp
struct RemoteProtocol {
    std::string commandName;      // Command class name
    std::string uniqueId;         // Unique command ID
    int32_t requestVersion;       // Protocol version
    std::string srcDeviceId;     // Source device ID
    std::string srcDeviceLevel;  // Source device APL level
    std::string dstDeviceId;     // Target device ID
    std::string dstDeviceLevel;  // Target device APL level
    int32_t statusCode;          // Status code
    std::string message;         // Status message
    int32_t responseVersion;     // Response protocol version
    std::string responseDeviceId; // Response device ID
};
```

## Key Workflows

### 1. Token Synchronization (Update Remote Token)

```
AccessTokenManager (local device)
    ↓
TokenSyncManagerService::UpdateRemoteHapTokenInfo
    ↓
RemoteCommandManager::AddCommand (creates UpdateRemoteHapTokenCommand)
    ↓
RemoteCommandExecutor::ProcessBufferedCommands
    ↓
UpdateRemoteHapTokenCommand::Prepare
    ↓
SoftBusChannel::SendRequest
    ↓ [via SoftBus]
Remote Device: SoftBusSocketListener::OnBytesReceived
    ↓
RemoteCommandFactory::CreateCommand
    ↓
UpdateRemoteHapTokenCommand::Execute (calls AccessTokenManager)
    ↓
Send Response
    ↓ [via SoftBus]
Local Device: ClientProcessResult
    ↓
UpdateRemoteHapTokenCommand::Finish
```

### 2. Device Online Flow

```
DeviceManager callback
    ↓
SoftBusManager::OnDeviceOnline
    ↓
DeviceInfoManager::AddDeviceInfo
    ↓
RemoteCommandManager::NotifyDeviceOnline
    ↓
RemoteCommandExecutor created (or re-used)
    ↓
SoftBusChannel::OpenSession
    ↓
ProcessBufferedCommands (sync pending commands)
```

### 3. Device Offline Flow

```
DeviceManager callback
    ↓
SoftBusManager::OnDeviceOffline
    ↓
DeviceInfoManager::RemoveRemoteDeviceInfo
    ↓
RemoteCommandManager::NotifyDeviceOffline
    ↓
RemoteCommandExecutor cleanup
    ↓
SoftBusChannel::CloseSession
```

### Performance Considerations

1. **Command Buffering**: Commands are buffered when device is offline to avoid blocking
2. **Sequential Execution**: Commands for a device are executed sequentially to preserve order
3. **Async Processing**: Use `ProcessBufferedCommandsWithThread` for non-blocking execution
4. **Channel Reuse**: RPC channel is reused for multiple commands to the same device

### Error Handling

1. **SoftBus Errors**: Handled by `SoftBusManager`, retry logic implemented
2. **Command Failures**: Individual command failures don't stop buffer processing
3. **Device Offline**: Commands remain buffered until device comes back online
4. **Timeout Handling**: Commands have implicit timeout via SoftBus

### Thread Safety

- `RemoteCommandManager`: Uses `std::mutex` to protect `executors_` map
- `RemoteCommandExecutor`: Uses `std::recursive_mutex` for command buffer
- `SoftBusManager`: Uses `std::mutex` for client socket map

### RPC Communication Format Compatibility

**CRITICAL**: When modifying RPC communication format, MUST ensure backward and forward compatibility between devices running different versions.

#### Version Management

The `RemoteProtocol` structure includes version fields for compatibility:

```cpp
struct RemoteProtocol {
    int32_t requestVersion;       // Request protocol version
    int32_t responseVersion;      // Response protocol version
    // ... other fields
};
```

Current version is defined in `constant.h`:
```cpp
const static int32_t DISTRIBUTED_ACCESS_TOKEN_SERVICE_VERSION = 2;
```

#### Compatibility Scenarios

| Scenario | Description | Handling Strategy |
|----------|-------------|-------------------|
| **Old → New** | Old device sends to new device | New device MUST handle old version format |
| **New → Old** | New device sends to old device | New device MUST send old-compatible format |
| **Old → Old** | Both devices on old version | Original format preserved |
| **New → New** | Both devices on new version | New format used |

#### Compatibility Design Principles

1. **Additive Changes Only**: New fields MUST be optional
   - New device MUST check if field exists before using
   - Old device ignores unknown fields

2. **Never Remove Fields**: Deprecated fields MUST be preserved for compatibility
   - Mark as deprecated but keep in structure
   - May add replacement field alongside

## Constraints And Boundaries

### Do Not Change Without Explicit Review

- Do not change protocol field meaning, version negotiation meaning, or command payload structure without compatibility review.
- Do not remove protocol fields that may still be required by older devices; keep deprecated fields readable until compatibility retirement is explicitly planned.
- Do not change device identity conversion rules between `networkId`, `UUID`, and `UDID` without tracing all call sites that depend on those identities.
- Do not change command ordering, buffering, or online/offline retry assumptions without checking sequential execution guarantees.

### Ask Before High-Risk Changes

- Ask before changing distributed permission semantics, remote error handling policy, or retry behavior.
- Ask before changing SoftBus binding lifecycle, socket ownership, or thread model in ways that may affect reconnect behavior.
- Ask before changing remote-to-local trust assumptions or which device identifiers are persisted or exposed.

### Common Agent Failure Modes

- Do not change only JSON serialization without checking deserialization and command factory creation logic.
- Do not change only the local requestor path without checking the remote responder path and response processing path.
- Do not change only protocol version constants without defining how mixed-version peers behave.

## Minimum Validation By Change Type

- Remote command, device lifecycle, or protocol changes: follow the common validation rules in `../../AGENTS.md`.
- Protocol field or version changes: in the final response explicitly cover `Old -> New`, `New -> Old`, optional-field-absent, and deprecated-field-preserved scenarios.
- SoftBus or buffering changes: report which online/offline, reconnect, or buffered-command paths were validated by build, tests, or reasoning.
- IPC or remote command contract changes: confirm both command-side and service-side targets still compile and link.

## Done Definition

- The affected service targets build, or the final response clearly states what could not be built.
- The final response states whether protocol compatibility, version behavior, or device identity handling changed.
- If mixed-version or runtime device scenarios could not be executed, the final response states the unverified scenario and remaining compatibility risk.

## Related Modules

| Module | Responsibility |
|--------|----------------|
| **AccessTokenManager** | Local permission grant state management |
| **PrivacyManager** | Local permission usage records/status |
| **TokenSyncManager** | Distributed permission synchronization |
