# 洛一后端 - 问题与优化建议

## 🔴 严重问题

### 1. CORS 配置过于宽松
**文件**: `internal/api/router.go`
```go
AllowOrigins: []string{"*"},
AllowCredentials: true,
```
**问题**: `AllowOrigins: *` 与 `AllowCredentials: true` 同时使用存在安全风险，浏览器会拒绝此配置。
**建议**: 生产环境应指定具体的允许域名。

### 2. 删除账户时文件路径硬编码
**文件**: `internal/services/account_service.go`
```go
baseDir := "data/users"
```
**问题**: 删除账户时使用硬编码路径，不会使用配置的 `EmailsDir`。
**建议**: 注入 `userManager` 或 `config` 来获取正确的路径。

### 3. 密码加密密钥来源不安全
**文件**: `internal/api/router.go`
```go
encryptionKey := []byte(cfg.JWTSecret)
```
**问题**: 使用 JWT Secret 作为 AES 加密密钥，如果 JWT Secret 泄露，所有邮箱密码都会暴露。
**建议**: 使用独立的加密密钥，并通过环境变量配置。

## 🟡 中等问题

### 4. 缺少数据库索引
**文件**: `internal/database/models/email.go`
**问题**: 
- `Email.Body` 和 `Email.HTMLBody` 没有全文索引，搜索效率低
- 缺少 `(account_id, date)` 复合索引，按时间排序查询慢
**建议**: 添加必要的索引或考虑使用全文搜索引擎。

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

## 🟢 优化建议

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

### 12. 健康检查增强
**文件**: `internal/api/router.go`
**建议**: 健康检查应包含数据库连接状态：
```go
router.GET("/health", func(c *gin.Context) {
    if err := db.Exec("SELECT 1").Error; err != nil {
        c.JSON(503, gin.H{"status": "unhealthy", "db": "disconnected"})
        return
    }
    c.JSON(200, gin.H{"status": "ok", "db": "connected"})
})
```

## 📋 待办事项

- [ ] 修复 CORS 配置
- [ ] 修复删除账户时的文件路径问题
- [ ] 添加独立的加密密钥配置
- [ ] 添加数据库索引
- [ ] 实现优雅关闭
- [ ] 添加 Token 刷新锁
- [ ] 添加邮件同步重试机制
- [ ] 统一日志系统
- [ ] 配置数据库连接池
- [ ] 统一 API 响应格式
- [ ] 添加附件大小限制
- [ ] 增强健康检查
