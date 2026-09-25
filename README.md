# cloakbrowser-pro-releases

CloakBrowser Pro 二进制的发布仓库（仅此用途）：每小时检查上游
`CloakHQ/CloakBrowser` 的 releases，发现新版本后用 `CLOAKBROWSER_LICENSE_KEY`
（Actions secret，不落库）下载、校验（Ed25519 清单签名 + SHA-256）并作为本仓库
Release 资产发布。

- `.github/workflows/sync.yml` —— 检查 + 下载发布（唯一自动化）
- `scripts/sync_releases.py` —— 下载/校验/发布实现
- `state/downloaded.json` —— 已镜像与基线记录（仅哈希，无密钥）

首次配置：`gh secret set CLOAKBROWSER_LICENSE_KEY -R x6nux/cloakbrowser-pro-releases`
