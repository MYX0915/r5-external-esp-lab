# GitHub 引用：角色选择脚本

[固定提交下的脚本第 1–170 行](https://github.com/outl4wz/apex-squirrelscripts-linux/blob/ad16ad8bc3aa885a876dd7597577d176defdb45e/sh_character_select_new.gnut#L1-L170)｜提交 `ad16ad8bc3aa885a876dd7597577d176defdb45e`

| GitHub 行号 | 原文件内容的中文整理 |
| --- | --- |
| 1–16 | 全局脚本标记、条件编译区、角色选择调试开关，以及背景烟雾、背景几何和灯光模型资源。 |
| 17–35 | 角色选择进度、锁定状态、当前焦点等网络变量名，以及角色重选菜单开关的远程调用名称。 |
| 36–56 | 角色选择 UI 的初始化、运行、关闭、静音更新等函数声明；角色皮肤选择和锁定回调；角色选择按钮数量；客户端打开菜单的声明。 |
| 57–95 | 小队或 MVP 卡片展示、角色解锁与锁定反馈、菜单焦点与筛选、镜头和视图恢复等客户端声明。 |
| 96–128 | 角色选择画面用的镜头、模型和灯光实体名；景深、菜单显示参数；角色选择菜单状态枚举。 |
| 129–170 | 角色选择菜单初始化、是否启用角色重选、俱乐部小队接口及名称常量；区间末尾进入开发用的角色选择镜头声明。 |

原文标识符短摘：`DEBUG_CHARACTER_SELECT`、`UI_InitCharacterSelectNewMenu`、`NUM_CHARACTER_SELECT_BUTTONS`、`eNewCharacterSelectMenuState`。

## 与 DeepWiki 的对应关系

DeepWiki 在战利品图标和血条一节引用[第 10–56 行](https://github.com/outl4wz/apex-squirrelscripts-linux/blob/ad16ad8bc3aa885a876dd7597577d176defdb45e/sh_character_select_new.gnut#L10-L56)，在用途、发光和雷达各节引用[第 1–170 行](https://github.com/outl4wz/apex-squirrelscripts-linux/blob/ad16ad8bc3aa885a876dd7597577d176defdb45e/sh_character_select_new.gnut#L1-L170)。逐段对照后，这些行主要是角色选择界面相关的资源、常量和声明，**没有直接展示 ESP、描边或雷达渲染的实现**。因此不能把 DeepWiki 的实现描述当作这些引文已经证实的事实。

本文件只整理网页引用的源码区间，不是整份可运行脚本的副本。
