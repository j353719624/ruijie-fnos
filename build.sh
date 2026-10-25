#!/bin/bash
# 一条命令把仓库打成 RUIJIE.fpk（在 Linux / fnOS 上执行）
#   ./build.sh
#   VERSION=V1.0.1-261101 ./build.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$ROOT/dist}"
STAGE="$OUT/stage"
APP="$STAGE/app"

echo "==> 清理输出目录"
rm -rf "$STAGE"
mkdir -p "$APP/server" "$APP/config" "$APP/ui" "$STAGE/wizard"

echo "==> 编译后端 (linux/amd64)"
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  cp "$ROOT/backend/prebuilt/ruijie_service" "$APP/server/ruijie_service"
else
  command -v go >/dev/null 2>&1 || { echo "找不到 go，请先安装 Go 或用 SKIP_BUILD=1"; exit 1; }
  ( cd "$ROOT/backend" && \
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GO111MODULE=off \
    go build -trimpath -ldflags "-s -w" \
      -o "$APP/server/ruijie_service" main.go )
fi
chmod 755 "$APP/server/ruijie_service"

echo "==> 拷贝桌面入口与前端"
cp -r "$ROOT/ui/." "$APP/ui/"
chmod 755 "$APP/ui/index.cgi"
cp -r "$ROOT/www" "$APP/server/www"

echo "==> 拷贝权限与共享目录配置"
cp "$ROOT/package/app-config/privilege" "$APP/config/privilege"
cp "$ROOT/package/app-config/resource" "$APP/config/resource"

echo "==> 组装包外壳"
cp -r "$ROOT/package/cmd" "$STAGE/cmd"
cp -r "$ROOT/package/config" "$STAGE/config"
cp "$ROOT/package/ICON.PNG" "$STAGE/ICON.PNG"
cp "$ROOT/package/ICON_256.PNG" "$STAGE/ICON_256.PNG"
cp "$ROOT/package/manifest.template" "$STAGE/manifest"

if [ -n "${VERSION:-}" ]; then
  sed -i "s/^version .*/version               = $VERSION/" "$STAGE/manifest"
fi
VER="$(awk '/^version/ {print $3}' "$STAGE/manifest")"

echo "==> 打包 app.tgz"
( cd "$APP" && tar czf "$STAGE/app.tgz" . )
SUM="$(md5sum "$STAGE/app.tgz" | cut -d' ' -f1)"
sed -i "s/^checksum .*/checksum              = $SUM/" "$STAGE/manifest"

echo "==> 生成 FPK"
( cd "$STAGE" && tar czf "$OUT/RUIJIE-$VER.fpk" \
    app.tgz cmd config ICON.PNG ICON_256.PNG manifest wizard )
cp "$OUT/RUIJIE-$VER.fpk" "$OUT/RUIJIE.fpk"

echo
echo "完成: $OUT/RUIJIE-$VER.fpk"
grep -E '^(appname|display_name|version|gatewayPrefix|checksum)' "$STAGE/manifest"
ls -lh "$OUT/RUIJIE-$VER.fpk"
