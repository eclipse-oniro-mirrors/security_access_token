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

import { AsyncCallback, Callback ,BusinessError} from '@ohos.base'; 
import { Permissions } from 'permissions';

export { Permissions }

export default namespace privacyManager {

    loadLibrary("privacy_ani.z");

    enum PermissionUsedType {

        NORMAL_TYPE = 0,

        PICKER_TYPE = 1,

        SECURITY_COMPONENT_TYPE = 2
    }

    interface AddPermissionUsedRecordOptions {
        usedType?: PermissionUsedType;
    }

    class AddPermissionUsedRecordOptionsInner implements AddPermissionUsedRecordOptions {
        usedType: PermissionUsedType|undefined;
    }

    class PrivacyManagerInner {

        native addPermissionUsedRecordSync(tokenID: int, permissionName: Permissions, successCount: int, failCount: int,
            options: AddPermissionUsedRecordOptionsInner): int;

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

    function addPermissionUsedRecord(tokenID: int, permissionName: Permissions, successCount: int,
        failCount: int, options?: AddPermissionUsedRecordOptions): Promise<int> {

        let usedTypeTemp : PermissionUsedType|undefined = options ? options.usedType : PermissionUsedType.NORMAL_TYPE

        let optionsLocal: AddPermissionUsedRecordOptionsInner = {
            usedType: usedTypeTemp
        };
        let p = new Promise<int>((resolve: (v: int) => void, reject: (error: Object) => void) => {
            let p1 = taskpool.execute((): int => { return new PrivacyManagerInner().addPermissionUsedRecordSync(tokenID,
                permissionName, successCount, failCount, optionsLocal) });

            p1.then((e: NullishType) => {
                let r: Int = e as Int;
                resolve(r.intValue());
            }, (err: Object): void => {
            });
        }
        );
        return p;
    }
}