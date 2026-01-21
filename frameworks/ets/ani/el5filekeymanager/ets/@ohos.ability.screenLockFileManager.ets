/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
export namespace screenLockFileManager {
  loadLibrary("el5filekeymanager_ani.z");

  export enum DataType {
    MEDIA_DATA = 0x00000001,
    ALL_DATA = -0x00000001
  }

  export enum AccessStatus {
    ACCESS_DENIED = -1,
    ACCESS_GRANTED = 0
  }

  export enum ReleaseStatus {
    RELEASE_DENIED = -1,
    RELEASE_GRANTED = 0
  }

  export enum KeyStatus {
    KEY_NOT_EXIST = -2,
    KEY_RELEASED = -1,
    KEY_EXIST = 0
  }

  native function acquireAccessSync(): int;
  native function acquireAccessExecute(dataType: int): int;
  native function releaseAccessSync(): int;
  native function releaseAccessExecute(dataType: int): int;
  native function queryAppKeyStateSync(): int;
  native function queryAppKeyStateExecute(dataType: int): int;

  export function acquireAccess(): AccessStatus {
    let result: int = acquireAccessSync();
    return AccessStatus.fromValue(result);
  }
  export function acquireAccess(dataType: DataType): AccessStatus {
    let result: int = acquireAccessExecute(dataType);
    return AccessStatus.fromValue(result);
  }

  export function releaseAccess(): ReleaseStatus {
    let result: int = releaseAccessSync();
    return ReleaseStatus.fromValue(result);
  }
  export function releaseAccess(dataType: DataType): ReleaseStatus {
    let result: int = releaseAccessExecute(dataType);
    return ReleaseStatus.fromValue(result);
  }

  export function queryAppKeyState(): KeyStatus {
    let result: int = queryAppKeyStateSync();
    return KeyStatus.fromValue(result);
  }
  export function queryAppKeyState(dataType: DataType): KeyStatus {
    let result: int = queryAppKeyStateExecute(dataType);
    return KeyStatus.fromValue(result);
  }
}
