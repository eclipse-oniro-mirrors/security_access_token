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

@Component
export struct textInput {
  @Prop placeholder: string
  build() {
    Column() {
      Flex({ alignContent: FlexAlign.Start }) {
        TextInput({ placeholder: this.placeholder })
          .padding({ left: 36 })
          .type(InputType.Normal)
          .border({ radius: 20 })
          .placeholderColor($r('app.color.secondary_font_color'))
          .placeholderFont({ size: '16vp', weight: FontWeight.Normal, family: "sans-serif", style: FontStyle.Normal })
          .caretColor($r('app.color.secondary_font_color'))
          .backgroundColor($r('app.color.default_background_color'))
          .height(40)
          .width(324)
          .onChange((value: string) => {

          })
          .onSubmit((enterKey) => {

          })
          .onEditChanged((isEditing) => {

          })
        Column() {
          Image($r('app.media.search'))
            .objectFit(ImageFit.Contain)
            .width(16)
            .height(16)
            .margin({ left: -312, top: 12 })
        }
      }
    }
  }
}