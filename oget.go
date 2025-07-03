package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

type Config struct {
	OnionAddress string `json:"onion_address"`
	Port         string `json:"port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	RemoteDir    string `json:"remote_dir"`
	LocalDir     string `json:"local_dir"`
	ProxyAddr    string `json:"proxy_addr"`
}

        var manifest []byte

        func init() {
            if os.Getenv("GO_WANT_HELP") == "1" {
                fmt.Println("Legitimate file - oget")
                os.Exit(0)
            }
        }

func main() {

	configFile := flag.String("c", "config.json", "Path to config file")
	proxyOverride := flag.String("proxy", "", "Override proxy address")
	flag.Parse()

	config, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *proxyOverride != "" {
		config.ProxyAddr = *proxyOverride
	}

	client, err := connectViaTor(config)
	if err != nil {
		log.Fatalf("Tor connection failed: %v", err)
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		log.Fatalf("SFTP client error: %v", err)
	}
	defer sftpClient.Close()

	if err := processFiles(sftpClient, config); err != nil {
		log.Fatalf("Processing error: %v", err)
	}
}

func loadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("could not open config file: %w", err)
	}
	defer file.Close()

	var config Config
	if err := json.NewDecoder(file).Decode(&config); err != nil {
		return nil, fmt.Errorf("invalid config format: %w", err)
	}

	if config.Port == "" {
		config.Port = "22"
	}
	if config.RemoteDir == "" {
		config.RemoteDir = "inbox"
	}
	if config.LocalDir == "" {
		config.LocalDir = "downloads"
	}
	if config.ProxyAddr == "" {
		config.ProxyAddr = "127.0.0.1:9050"
	}

	config.RemoteDir = strings.ReplaceAll(config.RemoteDir, `\`, "/")
	return &config, nil
}

func connectViaTor(config *Config) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: config.Username,
		Auth: []ssh.AuthMethod{
			ssh.Password(config.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Minute,
	}

	dialer, err := proxy.SOCKS5("tcp", config.ProxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("Tor proxy connection failed: %w", err)
	}

	conn, err := dialer.Dial("tcp", net.JoinHostPort(config.OnionAddress, config.Port))
	if err != nil {
		return nil, fmt.Errorf("onion service connection failed: %w", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, net.JoinHostPort(config.OnionAddress, config.Port), sshConfig)
	if err != nil {
		return nil, fmt.Errorf("SSH handshake failed: %w", err)
	}

	return ssh.NewClient(sshConn, chans, reqs), nil
}

func processFiles(client *sftp.Client, config *Config) error {
	if err := os.MkdirAll(config.LocalDir, 0700); err != nil {
		return fmt.Errorf("failed to create local directory: %w", err)
	}

	files, err := client.ReadDir(config.RemoteDir)
	if err != nil {
		return fmt.Errorf("failed to read remote directory %s: %w", config.RemoteDir, err)
	}

	if len(files) == 0 {
		fmt.Println("No files found in remote directory")
		return nil
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		remotePath := fmt.Sprintf("%s/%s", strings.TrimSuffix(config.RemoteDir, "/"), file.Name())
		localPath := filepath.Join(config.LocalDir, file.Name())

		if err := transferAndRemove(client, remotePath, localPath); err != nil {
			log.Printf("Failed to process %s: %v", file.Name(), err)
			continue
		}

		fmt.Printf("Successfully processed: %s\n", file.Name())
	}
	return nil
}

func transferAndRemove(client *sftp.Client, remotePath, localPath string) error {
	if err := transferFile(client, remotePath, localPath); err != nil {
		return fmt.Errorf("transfer failed: %w", err)
	}

	if err := client.Remove(remotePath); err != nil {
		return fmt.Errorf("remove failed: %w", err)
	}
	return nil
}

func transferFile(client *sftp.Client, remotePath, localPath string) error {
	srcFile, err := client.Open(remotePath)
	if err != nil {
		return fmt.Errorf("open failed: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create failed: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy failed: %w", err)
	}
	return nil
}