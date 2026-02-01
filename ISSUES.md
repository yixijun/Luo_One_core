# 洛一后端 - 问题与优化建议

## ✅ 已修复

### 1. CORS 配置过于宽松
**文件**: `internal/api/router.go`
**修复**: 现在根据 `CORSOrigins` 配置动态设置，当为 `*` 时禁用 `AllowCredentials`。

### 2. 删除账户时文件路径硬编码
**文件**: `internal/services/account_service.go`
**修复**: 添加 `EmailsDirGetter` 接口，通过 `getEmailsBaseDir()` 获取正确路径。

### 3. 密码加密密钥来源不安全
**文件**: `internal/config/config.go`
**修复**: 添加独立的 `EncryptionKey` 配置，通过 `GetEncryptionKey()` 获取（支持向后兼容）。

### 4. 缺少数据库索引
**文件**: `internal/database/models/email.go`
**修复**: 添加 `(account_id, date)` 复合索引、`from_addr` 索引、`is_read` 索引。

### 5. 健康检查增强
**文件**: `internal/api/router.go`
**修复**: 健康检查现在包含数据库连接状态。

## 🟡 中等问题（待处理）

### 5. 同步调度器没有优雅关闭
**文件**: `internal/services/sync_scheduler.go`
**问题**: `syncScheduler.Start()` 启动后没有在程序退出时调用 `Stop()`。
**建议**: 在 main.go 中添加信号处理，优雅关闭调度器。

### 6. OAuth Token 刷新竞态条件
**文件**: `internal/services/token_scheduler.go`
**问题**: 多个请求可能同时触发 Token 刷新，导致重复刷新。
**建议**: 添加互斥锁或使用 singleflight 模式。

### 7. 邮件同步缺少重试机制
**文件**: `internal/services/email_service.go`
**问题**: IMAP 连接失败时直接返回错误，没有重试逻辑。
**建议**: 添加指数退避重试机制。

## 🟢 优化建议（待处理）

### 8. 日志级别配置
**现状**: 日志级别通过配置文件设置，但很多地方直接使用 `log.Printf`。
**建议**: 统一使用 `LogService`，支持结构化日志。

### 9. 数据库连接池配置
**文件**: `internal/database/db.go`
**建议**: 添加连接池配置：
```go
sqlDB.SetMaxIdleConns(10)
sqlDB.SetMaxOpenConns(100)
sqlDB.SetConnMaxLifetime(time.Hour)
```

### 10. API 响应格式统一
**现状**: 部分 API 返回 `{ success: true, data: ... }`，部分直接返回数据。
**建议**: 统一所有 API 响应格式。

### 11. 邮件附件大小限制
**问题**: 没有限制附件大小，可能导致内存溢出。
**建议**: 添加附件大小限制配置。

## 📋 待办事项

- [x] 修复 CORS 配置
- [x] 修复删除账户时的文件路径问题
- [x] 添加独立的加密密钥配置
- [x] 添加数据库索引
- [x] 增强健康检查
- [ ] 实现优雅关闭
- [ ] 添加 Token 刷新锁
- [ ] 添加邮件同步重试机制
- [ ] 统一日志系统
- [ ] 配置数据库连接池
- [ ] 统一 API 响应格式
- [ ] 添加附件大小限制
