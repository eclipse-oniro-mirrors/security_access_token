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

import { AsyncCallback, Callback, BusinessError} from '@ohos.base'; 
import { Permissions } from 'permissions';

function PARAM_ERROR_MSG(param: string, type: string): string {
    return `Parameter Error. The type of "${param}" must be ${type}.`;
}

export { Permissions }

export default namespace privacyManager {
    loadLibrary("privacy_ani.z");

    enum PermissionUsedType {
        NORMAL_TYPE = 0,
        PICKER_TYPE = 1,
        SECURITY_COMPONENT_TYPE = 2
    };

    enum STSErrorCode {
        STS_OK = 0,
        STS_ERROR_PERMISSION_DENIED = 201,
        STS_ERROR_NOT_SYSTEM_APP = 202,
        STS_ERROR_PARAM_ILLEGAL = 401,
        STS_ERROR_SYSTEM_CAPABILITY_NOT_SUPPORT = 801,
    };

    interface AddPermissionUsedRecordOptions {
        usedType?: PermissionUsedType;
    }

    class AddPermissionUsedRecordOptionsInner implements AddPermissionUsedRecordOptions {
        usedType: PermissionUsedType|undefined;
    }

    class PrivacyManagerInner {
        native addPermissionUsedRecordSync(tokenID: int, permissionName: Permissions, successCount: int, failCount: int,
            options: AddPermissionUsedRecordOptionsInner): void;
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
        failCount: int, options?: AddPermissionUsedRecordOptions): Promise<void> {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }

        let usedTypeTemp : PermissionUsedType|undefined = options ? options.usedType : PermissionUsedType.NORMAL_TYPE;
        let optionsLocal: AddPermissionUsedRecordOptionsInner = { usedType: usedTypeTemp };
        let p = new Promise<void>((resolve: (v: undefined) => void, reject: (error: BusinessError) => void): void => {
            let p1 = taskpool.execute((): void => {
                return new PrivacyManagerInner().addPermissionUsedRecordSync(
                    tokenID, permissionName, successCount, failCount, optionsLocal)
            });
            p1.then(() => {
                resolve(undefined);
            }).catch((err: BusinessError): void => {
                reject(err);
            });
        });
        return p;
    }

    function addPermissionUsedRecord(tokenID: int, permissionName: Permissions, successCount: int,
        failCount: int, callback: AsyncCallback<void>): void {
        if (typeof permissionName !== "string") {
            let err = new BusinessError<string>();
            err.code = STSErrorCode.STS_ERROR_PARAM_ILLEGAL;
            err.data = PARAM_ERROR_MSG("permissionName", "Permissions");
            throw err;
        }
        let optionsLocal: AddPermissionUsedRecordOptionsInner = { usedType: PermissionUsedType.NORMAL_TYPE };
        let p2 = taskpool.execute((): void => {
            return new PrivacyManagerInner().addPermissionUsedRecordSync(tokenID, permissionName,
                successCount, failCount, optionsLocal)});
        p2.then(() => {
            let err = new BusinessError<void>();
            callback(err, undefined);
        },(err: BusinessError): void=> {
            callback(err, undefined);
        })
    }
}