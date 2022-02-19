/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

export const BundleFlag = {
  GET_BUNDLE_DEFAULT : 0x00000000,
  GET_BUNDLE_WITH_ABILITIES : 0x00000001,
  GET_ABILITY_INFO_WITH_PERMISSION : 0x00000002,
  GET_ABILITY_INFO_WITH_APPLICATION : 0x00000004,
  GET_APPLICATION_INFO_WITH_PERMISSION : 0x00000008,
  GET_BUNDLE_WITH_REQUESTED_PERMISSION : 0x00000010,
  GET_ALL_APPLICATION_INFO : 0xFFFF0000,
  /**
      * @since 8
      */
  GET_ABILITY_INFO_WITH_METADATA : 0x00000020,
  /**
      * @since 8
      */
  GET_APPLICATION_INFO_WITH_METADATA : 0x00000040,
  /**
      * @since 8
      */
  GET_ABILITY_INFO_SYSTEMAPP_ONLY : 0x00000080
}

export const USER_ID: number = 100