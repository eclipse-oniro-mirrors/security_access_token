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

import Constants from '../utils/constant.ets';

@CustomDialog
export struct authorizeDialog {
  controller: CustomDialogController;
  cancel: () => void;
  confirm: () => void;

  build() {
    Column() {
      Row() {
        Flex({ justifyContent: FlexAlign.Center }) {
          Text($r("app.string.Authorization_failed")).fontSize(Constants.DIALOG_TEXT_FONT_SIZE)
            .margin({
              top: Constants.DIALOG_TEXT_MARGIN_TOP
            })
        }
      }
    }
    .backgroundColor($r('app.color.default_background_color'))
    .borderRadius(Constants.DIALOG_BORDER_RADIUS)
    .height(Constants.DIALOG_HEIGHT)
    .width(Constants.DIALOG_WIDTH)
  }
}
