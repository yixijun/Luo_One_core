package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// keyCmd represents the key command group
var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "API 密钥管理",
	Long:  `管理 API 密钥，包括查看当前密钥和重置密钥。`,
}

// keyShowCmd shows the current API key
var keyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "显示当前 API 密钥",
	Long:  `显示当前系统使用的 API 密钥。`,
	Run: func(cmd *cobra.Command, args []string) {
		if apiKeyManager == nil {
			fmt.Fprintln(os.Stderr, "错误: API 密钥管理器未初始化")
			os.Exit(1)
		}

		currentKey := apiKeyManager.GetCurrentKey()
		if currentKey == "" {
			fmt.Fprintln(os.Stderr, "错误: 无法获取 API 密钥")
			os.Exit(1)
		}

		fmt.Println("当前 API 密钥:")
		fmt.Println(currentKey)
	},
}

// keyResetCmd resets the API key
var keyResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "重置 API 密钥",
	Long:  `生成新的 API 密钥，旧密钥将失效。此操作需要确认。`,
	Run: func(cmd *cobra.Command, args []string) {
		if apiKeyManager == nil {
			fmt.Fprintln(os.Stderr, "错误: API 密钥管理器未初始化")
			os.Exit(1)
		}

		// Show current key
		oldKey := apiKeyManager.GetCurrentKey()
		fmt.Println("当前 API 密钥:")
		fmt.Println(oldKey)
		fmt.Println()

		// Ask for confirmation
		fmt.Print("警告: 重置密钥后，所有使用旧密钥的客户端将无法访问系统。\n")
		fmt.Print("确定要重置 API 密钥吗？(yes/no): ")

		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 读取输入失败: %v\n", err)
			os.Exit(1)
		}

		input = strings.TrimSpace(strings.ToLower(input))
		if input != "yes" && input != "y" {
			fmt.Println("操作已取消。")
			return
		}

		// Reset the key
		newKey, err := apiKeyManager.ResetKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "错误: 重置密钥失败: %v\n", err)
			os.Exit(1)
		}

		fmt.Println()
		fmt.Println("API 密钥已重置成功！")
		fmt.Println("新的 API 密钥:")
		fmt.Println(newKey)
	},
}

func init() {
	keyCmd.AddCommand(keyShowCmd)
	keyCmd.AddCommand(keyResetCmd)
}
