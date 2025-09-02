# SIM APDU Parser

一个功能强大的SIM卡APDU（Application Protocol Data Unit）解析工具，支持Proactive命令和eSIM协议的图形化分析。

## 功能特性

### 🔍 多格式支持
- **MTK原始日志**：解析MTK平台的APDU_tx/APDU_rx日志格式
- **APDU文本**：支持每行一条APDU的纯文本格式

### 📊 协议解析
- **Proactive命令**：完整的UICC=>TERMINAL和TERMINAL=>UICC通信解析
- **eSIM协议**：支持LPA=>ESIM和ESIM=>LPA的eUICC通信
- **普通SIM**：基础SIM卡APDU命令解析

### 🎨 图形界面
- **双面板设计**：左侧事件列表，右侧详细解析树
- **颜色编码**：不同方向的消息使用不同颜色区分
- **实时搜索**：支持标题和详情内容的全文搜索
- **高级搜索**：Ctrl+F快捷键，支持正则表达式和导航

### 📋 数据导出
- **复制功能**：支持复制单行、RAW数据、详情树等
- **右键菜单**：便捷的上下文操作
- **快捷键支持**：Ctrl+C复制，Ctrl+F搜索等

## 安装要求

- Python 3.7+
- tkinter（通常随Python安装）

## 快速开始

### 1. 运行程序
```bash
python main.py
```

### 2. 加载数据
- 点击"加载 MTK 原始日志"选择MTK格式的日志文件
- 或点击"加载 APDU 文本（每行）"选择纯文本APDU文件

### 3. 查看解析结果
- 左侧列表显示所有解析的APDU事件
- 点击任意事件，右侧显示详细的解析树
- 底部显示原始十六进制数据

## 使用指南

### 数据筛选
使用"筛选类别"下拉菜单可以：
- 显示/隐藏 Proactive APDU
- 显示/隐藏 eSIM APDU  
- 显示/隐藏 普通 SIM APDU

### 搜索功能
- **简单搜索**：在搜索框中输入关键词
- **高级搜索**：按 `Ctrl+F` 打开搜索对话框
  - 支持正则表达式
  - 自动搜索详情内容
  - 上一个/下一个导航
  - 键盘快捷键：Enter（下一个）、Shift+Enter（上一个）、Escape（关闭）

### 复制数据
- **右键菜单**：在列表或详情区域右键
- **快捷键**：Ctrl+C 复制选中内容
- **复制选项**：
  - 复制当前行
  - 复制RAW数据
  - 复制详情树（全部或子树）

## 支持的协议

### Proactive命令
- **D0命令**：UICC=>TERMINAL的主动命令
- **TERMINAL RESPONSE**：终端响应
- **ENVELOPE**：终端发送的封装命令
- **TERMINAL PROFILE**：终端能力配置
- **FETCH**：获取命令

### eSIM协议
- **BF22**：GetEuiccInfo2 - eUICC信息查询
- **BF2D**：ProfileInfoList - 配置文件列表
- **BF37**：ProfileInstallationResult - 配置文件安装结果
- **其他BF系列**：完整的eSIM命令集支持

## 文件结构

```
SIM_APDU_Parser/
├── main.py                 # 主程序入口
├── app/
│   └── adapter.py         # GUI适配器
├── classify/
│   └── rules.py           # 消息分类规则
├── core/
│   ├── models.py          # 数据模型
│   ├── utils.py           # 工具函数
│   ├── tlv.py            # TLV解析
│   └── registry.py        # 解析器注册
├── data_io/
│   ├── loaders.py         # 文件加载器
│   └── extractors/        # 数据提取器
│       ├── mtk.py         # MTK格式提取
│       └── generic.py     # 通用格式提取
├── parsers/
│   ├── base.py            # 基础解析器
│   ├── proactive/         # Proactive命令解析
│   └── esim/             # eSIM协议解析
└── render/
    ├── gui_adapter.py     # GUI数据适配
    └── tree_builder.py    # 树形结构构建
```

## 技术特点

### 解析引擎
- **模块化设计**：可扩展的解析器架构
- **TLV支持**：完整的BER-TLV解析
- **智能分类**：基于APDU头部的自动消息分类
- **错误处理**：优雅的解析错误处理

### 性能优化
- **缓存机制**：详情内容解析结果缓存
- **懒加载**：按需解析详情内容
- **内存管理**：高效的数据结构设计

## 快捷键

| 快捷键 | 功能 |
|--------|------|
| `Ctrl+F` | 打开搜索对话框 |
| `Ctrl+C` | 复制选中内容 |
| `Enter` | 搜索下一个结果 |
| `Shift+Enter` | 搜索上一个结果 |
| `Escape` | 关闭搜索对话框 |

## 示例数据格式

### MTK日志格式
```
APDU_tx 0: 00 A4 04 00 07 A0 00 00 00 87 10 02
APDU_rx 0: 6F 1A 84 07 A0 00 00 00 87 10 02 A5 0F 73 0D 06 07 2F 00 2F E2 04 81 01 01 90 00
```

### 纯文本APDU格式
```
00A4040007A0000000871002
6F1A8407A0000000871002A50F730D06072F002FE2048101019000
```

## 开发说明

### 添加新的解析器
1. 在相应的协议目录下创建解析器文件
2. 使用 `@register` 装饰器注册解析器
3. 实现 `build` 方法返回 `ParseNode`

### 扩展消息分类
在 `classify/rules.py` 中的 `classify_message` 函数中添加新的分类规则。

## 许可证

本项目采用MIT许可证。

## 贡献

欢迎提交Issue和Pull Request来改进这个工具。

## 更新日志

### v1.0.0
- 基础APDU解析功能
- MTK和纯文本格式支持
- 图形界面实现
- Proactive和eSIM协议支持
- 搜索和复制功能
- 快捷键支持
