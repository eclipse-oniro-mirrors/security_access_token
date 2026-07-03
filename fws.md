这条 using namespace 不在全局作用域 ，而是位于 OHOS::CJSystemapi 命名空间内部。它只会把 OHOS::Security::AccessToken 中的名字引入到 OHOS::CJSystemapi 这个命名空间， 不会污染全局命名空间 ；


告警位置 at_manager_impl.cpp:851-853 ：

```
delete *item;
*item = nullptr;
g_permStateChangeRegisters.erase(item);
```
g_permStateChangeRegisters 的类型是 std::vector<RegisterPermStateChangeInfo*> ，即 裸指针 vector 。告警建议用 unique_ptr 管理，但这里 不适合 改，原因：

1. RegisterPermStateChangeInfo* 是指向 PermStateChangeContext 派生类的多态指针 （见头文件 at_manager_impl.h:142 typedef PermStateChangeContext RegisterPermStateChangeInfo; ），它带有虚析构函数。 std::vector<unique_ptr<T>> 虽能管理多态对象，但会改变 vector 的元素类型，影响所有使用 g_permStateChangeRegisters 的地方（构造、插入、比较 callbackRef / threadId 等大量代码都要改）。
2. 这些指针在注册时 new ，在注销/异常路径里 delete ，是典型的"跨多个生命周期分支手动管理"场景，改成 unique_ptr 会引入大量重构，且 vector 的 erase 配合 unique_ptr 的移动语义反而容易在遍历中出错。
3. 当前这段代码本身是正确的 ：先 delete 指向的对象，置空指针，再 erase 迭代器，是删除 vector 中裸指针元素的标准写法。