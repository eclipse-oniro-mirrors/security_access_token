/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

import { Permissions } from 'permissions';
import { PermissionRequestResult } from 'PermissionRequestResult';

export { Permissions, PermissionRequestResult };

class BusinessError<T = void> {
    code: number;
    data: T;
}

type AsyncCallback<T, E = void> = (err: BusinessError<E>, data: T) => void;

class Result<T, E>{
    result:T;
    error:E;
    constructor(result: T , error: E) {
        this.result = result;
        this.error = error;
    }
}

export namespace abilityAccessCtrl {

    loadLibrary("ani_ability_access_ctrl.z");

    export enum GrantStatus {

        PERMISSION_DENIED = -1,

        PERMISSION_GRANTED = 0
    }

    export enum PermissionRequestToggleStatus {

        CLOSED = 0,

        OPEN = 1,
    }

    export enum PermissionStatus {

        DENIED = -1,

        GRANTED = 0,

        NOT_DETERMINED = 1,

        INVALID = 2,

        RESTRICTED = 3
    }

    interface PermissionStateChangeInfo {

        change: PermissionStateChangeType;

        tokenID: number;

        permissionName: Permissions;
    }

    export enum PermissionStateChangeType {

        PERMISSION_REVOKED_OPER = 0,

        PERMISSION_GRANTED_OPER = 1
    }

    export enum SwitchType {

        CAMERA = 0,

        MICROPHONE = 1,

        LOCATION = 2,
    }

    export native function createAtManager(): AtManager;

    interface AtManager {

    }

    class AtManagerInner implements AtManager {

    }
}
