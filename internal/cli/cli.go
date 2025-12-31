package cli

import (
	"fmt"
	"os"

	"github.com/luo-one/core/internal/api/middleware"
	"github.com/luo-one/core/internal/config"
	"github.com/luo-one/core/internal/services"
	"github.com/luo-one/core/internal/user"
	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

var (
	db            *gorm.DB
	cfg           *config.Config
	apiKeyManager *middleware.APIKeyManager
	userService   *services.UserService
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "luo_one_core",
	Short: "洛一邮箱管理系统后端服务",
	Long: `洛一 (Luo One) 是一个前后端分离的多邮箱管理系统后端服务。

该命令行工具提供以下功能：
  - 密钥管理：查看和重置 API 密钥
  - 用户管理：创建用户、列出用户、重置用户密码

使用示例：
  luo_one_core key show          # 显示当前 API 密钥
  luo_one_core key reset         # 重置 API 密钥
  luo_one_core user create       # 创建新用户
  luo_one_core user list         # 列出所有用户
  luo_one_core user reset-pwd    # 重置用户密码`,
}

// Execute runs the CLI with the provided database and config
func Execute(database *gorm.DB, config *config.Config) {
	db = database
	cfg = config

	// Initialize API key manager
	var err error
	apiKeyManager, err = middleware.NewAPIKeyManager(cfg.DataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: 无法初始化 API 密钥管理器: %v\n", err)
		os.Exit(1)
	}

	// Initialize user manager and service
	userManager := user.NewManager(cfg.DataDir)
	userService = services.NewUserService(db, userManager)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(keyCmd)
	rootCmd.AddCommand(userCmd)
}
