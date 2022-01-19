/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

import { privacyDialog } from "../common/components/dialog.ets"
import { dialogData } from "../common/model/dialogDataList.ets"

@Entry
@Component
struct dialogPlusPage {
  @State count: number = 0
  privacyDialogController: CustomDialogController = new CustomDialogController({
    builder: privacyDialog({ cancel: this.privacyCancel, confirm: this.privacyAccept, count:this.count }),
    cancel: this.privacyExist,
    autoCancel: true,
    alignment: DialogAlignment.Bottom,
    offset: { dx: 0 , dy: -12 },
    customStyle: true
  })
  privacyAccept() {
      this.count < dialogData.length ? this.count += 1 : this.count = 0
      console.info('accept ' + this.count)

  }
  privacyCancel() {
    if (this.count < dialogData.length) {
      this.count += 1
    } else {
      this.count = 0
    }
    console.info('cancel' + this.count)

  }
  privacyExist() {
    console.info("exist")
  }
  aboutToAppear() {
    this.privacyDialogController.open()
  }
  build() {
  }
}
