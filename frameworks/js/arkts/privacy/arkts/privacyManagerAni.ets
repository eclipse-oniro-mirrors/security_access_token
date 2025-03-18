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

class BusinessError<T = void> {
    code: number;
    data: T;
 }

 export { Permissions }
 
 type AsyncCallback<T, E = void> = (err: BusinessError<E>, data: T) => void;
 
 class Result<T, E>{
     result:T;
     error:E;
     constructor(result: T , error: E) {
         this.result = result;
         this.error = error;
     }
 }
 export namespace privacyManager {

    loadLibrary("ani_privacy_manager.z");

    export enum PermissionUsedType {

        NORMAL_TYPE = 0,

        PICKER_TYPE = 1,

        SECURITY_COMPONENT_TYPE = 2
    }

    export class AddPermissionUsedRecordOptions {
        usedType: PermissionUsedType;
    }

    export class PrivacyManagerInner {

        native addPermissionUsedRecordSync(tokenID: int, permissionName: Permissions, successCount: int, failCount: int,
            options: AddPermissionUsedRecordOptions): int;

    }

    interface UsedRecordDetail {

        status: number;

        lockScreenStatus?: number;

        timestamp: number;

        count?: number;

        accessDuration: number;

        usedType?: PermissionUsedType;
    }

    interface PermissionUsedTypeInfo {

        tokenId: number;

        permissionName: Permissions;

        usedType: PermissionUsedType;
    }


    export function addPermissionUsedRecord(tokenID: int, permissionName: string, successCount: int, failCount: int,
        options?: AddPermissionUsedRecordOptions): Promise<int> {

        let optionsLocal: AddPermissionUsedRecordOptions = {
            usedType: PermissionUsedType.NORMAL_TYPE
        };
        let optionsTmp = options ? options : optionsLocal
        let p = new Promise<int>((resolve: (v: int) => void, reject: (error: Object) => void) => {
            let p1 = taskpool.execute((): int => { return new PrivacyManagerInner().addPermissionUsedRecordSync(tokenID,
                permissionName, successCount, failCount, optionsTmp) });

            p1.then((e: NullishType) => {
                console.log("P1 then e = " + e + ".");
                let r: Int = e as Int;
                resolve(r.intValue());
            }, (err: Object): void => {
                console.log("Promise exception.");
            });
        }
        );
        return p;
    }
}
