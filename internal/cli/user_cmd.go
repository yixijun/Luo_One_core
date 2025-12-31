package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// userCmd represents the user command group
var userCmd = &cobra.Command{
	Use:   "user",
	Short: "用户管理",
	Long:  `管理系统用户，包括创建用户、列出用户和重置用户密码。`,
}

// userCreateCmd creates a new user
var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "创建新用户",
	Long:  `交互式创建新用户，需要输入用户名、密码和昵称。`,
	Run: func(cmd *cobra.Command, args []string) {
		if userService == nil {
			fmt.Fprintln(os.Stderr, "错误: 用户服务未初始化")
			os.Exit(1)
		}

		reader := bufio.NewReader(os.Stdin)

		// Get username
		fmt.Print("请输入用户名: ")
		username, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 读取输入失败: %v\n", err)
			os.Exit(1)
		}
		username = strings.TrimSpace(username)
		if username == "" {
			fmt.Fprintln(os.Stderr, "错误: 用户名不能为空")
			os.Exit(1)
		}

		// Get password (hidden input)
		fmt.Print("请输入密码 (至少6位): ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n错误: 读取密码失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()
		password := string(passwordBytes)
		if len(password) < 6 {
			fmt.Fprintln(os.Stderr, "错误: 密码长度至少为6位")
			os.Exit(1)
		}

		// Confirm password
		fmt.Print("请再次输入密码: ")
		confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n错误: 读取密码失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()
		if password != string(confirmBytes) {
			fmt.Fprintln(os.Stderr, "错误: 两次输入的密码不一致")
			os.Exit(1)
		}

		// Get nickname (optional)
		fmt.Print("请输入昵称 (可选，直接回车跳过): ")
		nickname, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 读取输入失败: %v\n", err)
			os.Exit(1)
		}
		nickname = strings.TrimSpace(nickname)
		if nickname == "" {
			nickname = username
		}

		// Create user
		newUser, err := userService.CreateUser(username, password, nickname)
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 创建用户失败: %v\n", err)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println("用户创建成功！")
		fmt.Printf("  ID: %d\n", newUser.ID)
		fmt.Printf("  用户名: %s\n", newUser.Username)
		fmt.Printf("  昵称: %s\n", newUser.Nickname)
	},
}

// userListCmd lists all users
var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "列出所有用户",
	Long:  `显示系统中所有用户的信息。`,
	Run: func(cmd *cobra.Command, args []string) {
		if userService == nil {
			fmt.Fprintln(os.Stderr, "错误: 用户服务未初始化")
			os.Exit(1)
		}

		users, err := userService.ListUsers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 获取用户列表失败: %v\n", err)
			os.Exit(1)
		}

		if len(users) == 0 {
			fmt.Println("系统中暂无用户。")
			return
		}

		fmt.Println("用户列表:")
		fmt.Println("----------------------------------------")
		fmt.Printf("%-6s %-20s %-20s %s\n", "ID", "用户名", "昵称", "创建时间")
		fmt.Println("----------------------------------------")
		for _, u := range users {
			createdAt := u.CreatedAt.Format("2006-01-02 15:04:05")
			fmt.Printf("%-6d %-20s %-20s %s\n", u.ID, u.Username, u.Nickname, createdAt)
		}
		fmt.Println("----------------------------------------")
		fmt.Printf("共 %d 个用户\n", len(users))
	},
}

// userResetPwdCmd resets a user's password
var userResetPwdCmd = &cobra.Command{
	Use:   "reset-pwd",
	Short: "重置用户密码",
	Long:  `交互式重置指定用户的密码。此操作需要确认。`,
	Run: func(cmd *cobra.Command, args []string) {
		if userService == nil {
			fmt.Fprintln(os.Stderr, "错误: 用户服务未初始化")
			os.Exit(1)
		}

		reader := bufio.NewReader(os.Stdin)

		// List users first
		users, err := userService.ListUsers()
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 获取用户列表失败: %v\n", err)
			os.Exit(1)
		}

		if len(users) == 0 {
			fmt.Println("系统中暂无用户。")
			return
		}

		fmt.Println("可用用户:")
		for _, u := range users {
			fmt.Printf("  [%d] %s (%s)\n", u.ID, u.Username, u.Nickname)
		}
		fmt.Println()

		// Get user ID
		fmt.Print("请输入要重置密码的用户 ID: ")
		idStr, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 读取输入失败: %v\n", err)
			os.Exit(1)
		}
		idStr = strings.TrimSpace(idStr)
		userID, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			fmt.Fprintln(os.Stderr, "错误: 无效的用户 ID")
			os.Exit(1)
		}

		// Verify user exists
		targetUser, err := userService.GetUserByID(uint(userID))
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 用户不存在: %v\n", err)
			os.Exit(1)
		}

		// Confirm operation
		fmt.Printf("\n警告: 即将重置用户 '%s' (ID: %d) 的密码。\n", targetUser.Username, targetUser.ID)
		fmt.Print("确定要继续吗？(yes/no): ")
		confirm, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 读取输入失败: %v\n", err)
			os.Exit(1)
		}
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm != "yes" && confirm != "y" {
			fmt.Println("操作已取消。")
			return
		}

		// Get new password
		fmt.Print("请输入新密码 (至少6位): ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n错误: 读取密码失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()
		newPassword := string(passwordBytes)
		if len(newPassword) < 6 {
			fmt.Fprintln(os.Stderr, "错误: 密码长度至少为6位")
			os.Exit(1)
		}

		// Confirm password
		fmt.Print("请再次输入新密码: ")
		confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n错误: 读取密码失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()
		if newPassword != string(confirmBytes) {
			fmt.Fprintln(os.Stderr, "错误: 两次输入的密码不一致")
			os.Exit(1)
		}

		// Reset password
		if err := userService.ResetPassword(uint(userID), newPassword); err != nil {
			fmt.Fprintf(os.Stderr, "错误: 重置密码失败: %v\n", err)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Printf("用户 '%s' 的密码已重置成功！\n", targetUser.Username)
	},
}

func init() {
	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userResetPwdCmd)
}
