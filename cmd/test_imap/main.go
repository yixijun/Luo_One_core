package main

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

const (
	imapServer = "imap.qq.com:993"
	username   = "2974714148@qq.com"
	password   = "zzodzegyrijdddfi"
)

func main() {
	log.Printf("正在连接 %s...", imapServer)

	// 1. 建立TLS连接
	tlsConfig := &tls.Config{ServerName: "imap.qq.com"}
	c, err := client.DialTLS(imapServer, tlsConfig)
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer c.Logout()
	log.Println("连接成功!")

	// 2. 登录
	log.Printf("正在登录 %s...", username)
	if err := c.Login(username, password); err != nil {
		log.Fatalf("登录失败: %v", err)
	}
	log.Println("登录成功!")

	// 3. 选择收件箱
	mbox, err := c.Select("INBOX", false)
	if err != nil {
		log.Fatalf("选择收件箱失败: %v", err)
	}
	log.Printf("收件箱共有 %d 封邮件", mbox.Messages)

	// 4. 搜索所有邮件
	criteria := imap.NewSearchCriteria()
	seqNums, err := c.Search(criteria)
	if err != nil {
		log.Fatalf("搜索邮件失败: %v", err)
	}
	log.Printf("搜索到 %d 封邮件", len(seqNums))

	if len(seqNums) == 0 {
		log.Println("没有邮件")
		return
	}

	// 5. 获取最近5封邮件
	start := len(seqNums) - 5
	if start < 0 {
		start = 0
	}
	recentNums := seqNums[start:]

	seqSet := new(imap.SeqSet)
	seqSet.AddNum(recentNums...)

	log.Printf("\n获取最近 %d 封邮件:", len(recentNums))
	fmt.Println("--------------------------------------------------")

	messages := make(chan *imap.Message, 10)
	done := make(chan error, 1)

	go func() {
		done <- c.Fetch(seqSet, []imap.FetchItem{imap.FetchEnvelope}, messages)
	}()

	for msg := range messages {
		if msg == nil || msg.Envelope == nil {
			continue
		}
		fmt.Printf("主题: %s\n", msg.Envelope.Subject)
		if len(msg.Envelope.From) > 0 {
			from := msg.Envelope.From[0]
			fmt.Printf("发件人: %s <%s@%s>\n", from.PersonalName, from.MailboxName, from.HostName)
		}
		fmt.Printf("日期: %s\n", msg.Envelope.Date)
		fmt.Println("--------------------------------------------------")
	}

	if err := <-done; err != nil {
		log.Fatalf("获取邮件失败: %v", err)
	}

	log.Println("\n测试完成!")
}
