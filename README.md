# RUIJIE · 飞牛 fnOS 锐捷路由器管理

独立于 MERCURY 的锐捷（Ruijie EWeb）路由器管理 FPK 应用。安装后出现在飞牛应用中心，
打开即进入路由器状态页；地址与账号在页面内填写并保存在 NAS 本机。

## 功能

- 设备概况：型号、主机名、固件 / 硬件版本、厂商、运行时长
- 内存占用、WAN 地址、工作模式、设备时间
- 在线终端列表（ARP）：IP、MAC、接口
- 连接设置：地址、用户名、密码；支持「测试连接」与「保存并连接」

## 协议要点

锐捷 EWeb 的登录流程（与固件 Lua 源码一致）：

1. `GET /cgi-bin/luci/` 取登录页，解析 `GibberishAES.enc(passwordEl.value, "<32位hex>")` 得到本次 AES 口令。
2. 密码用 GibberishAES（AES-256-CBC + OpenSSL `Salted__`）加密，字段名为 `pwd`。
3. `POST /cgi-bin/luci/api/auth`，body `{method:"login",params:{username,time,encry,pwd}}`。
4. 业务请求：`POST /cgi-bin/luci/api/<module>?auth=<sid>`。
5. 两个请求都带 `Content-Accept: md5("Web@Rj$2020!" + Content-Length)`。

登录成功后会缓存 sid；失败次数过多设备会临时锁定，程序会自动复用会话。

## 目录结构

```
backend/main.go             后端：配置、锐捷客户端、API、静态托管
www/index.html              单页前端
package/                    FPK 外壳（manifest、cmd 钩子、权限）
ui/                         fnOS 桌面入口与 index.cgi
build.sh                    一键打包
```

## 打包

```bash
./build.sh                              # 使用 manifest 版本号
VERSION=V1.0.1-261026 ./build.sh        # 临时改版本号
```

产物：`dist/RUIJIE-V1.0.0-261026.fpk`

## 安全

- 不在仓库中保存任何真实路由器地址、账号或密码。
- 用户填写的配置保存在 NAS 的 `/var/apps/ruijie/var/config.json`（权限 0600），不会上传。
- 卸载应用时随应用目录一并删除。
