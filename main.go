package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	cdn20180510 "github.com/alibabacloud-go/cdn-20180510/v6/client"
	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	util "github.com/alibabacloud-go/tea-utils/v2/service"
	"github.com/alibabacloud-go/tea/tea"
	credential "github.com/aliyun/credentials-go/credentials"
	"github.com/urfave/cli/v2"
)

const (
	tempDir     = "./cdn_logs_temp"
	resultsFile = "ip_search_results.txt"
	maxWorkers  = 8
	userAgent   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

// 全局配置
var config struct {
	domainName string
	startTime  string
	endTime    string
	searchIP   string
}

func main() {
	app := &cli.App{
		Name:  "cdn-log-analyzer",
		Usage: "查询、下载和分析阿里云CDN日志",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "domain",
				Aliases:  []string{"d"},
				Value:    "替换成你自己的域名！！！！！",
				Usage:    "CDN域名",
				Required: false,
			},
			&cli.StringFlag{
				Name:     "start",
				Aliases:  []string{"s"},
				Usage:    "开始时间 (格式: 2006-01-02T15:04:05Z)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "end",
				Aliases:  []string{"e"},
				Usage:    "结束时间 (格式: 2006-01-02T15:04:05Z)",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "ip",
				Aliases:  []string{"i"},
				Usage:    "要搜索的IP地址",
				Required: true,
			},
		},
		Action: run,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func run(c *cli.Context) error {
	// 解析配置
	config.domainName = c.String("domain")
	config.startTime = c.String("start")
	config.endTime = c.String("end")
	config.searchIP = c.String("ip")

	fmt.Printf("开始CDN日志分析任务\n")
	fmt.Printf("域名: %s\n", config.domainName)
	fmt.Printf("时间范围: %s 至 %s\n", config.startTime, config.endTime)
	fmt.Printf("搜索IP: %s\n", config.searchIP)

	// 创建临时目录
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("创建临时目录失败: %w", err)
	}
	// 创建日志保存目录
	if err := os.MkdirAll("onlice-log", 0755); err != nil {
		return fmt.Errorf("创建日志保存目录失败: %w", err)
	}
	defer os.RemoveAll(tempDir)

	// 获取日志下载链接并写入文件
	if err := fetchAndSaveCDNLogURLs(); err != nil {
		return fmt.Errorf("获取日志链接失败: %w", err)
	}

	// 从文件读取日志链接
	logURLs, err := readLogURLsFromFile("log-url.log")
	if err != nil {
		return fmt.Errorf("读取日志链接失败: %w", err)
	}

	fmt.Printf("获取到 %d 个日志文件链接\n", len(logURLs))

	// 下载日志文件
	downloadedFiles, err := downloadLogs(logURLs)
	if err != nil {
		return fmt.Errorf("下载日志失败: %w", err)
	}

	fmt.Printf("成功下载 %d/%d 个日志文件\n", len(downloadedFiles), len(logURLs))

	// 搜索IP
	results, err := searchLogsForIP(downloadedFiles)
	if err != nil {
		return fmt.Errorf("搜索日志失败: %w", err)
	}

	// 保存结果
	if err := saveResults(results); err != nil {
		return fmt.Errorf("保存结果失败: %w", err)
	}

	fmt.Printf("\n分析完成! 结果已保存到 %s\n", resultsFile)
	return nil
}

// 获取CDN日志下载链接并写入log-url.log文件
func fetchAndSaveCDNLogURLs() error {
	client, err := createClient()
	if err != nil {
		return err
	}

	req := &cdn20180510.DescribeCdnDomainLogsRequest{
		DomainName: tea.String(config.domainName),
		StartTime:  tea.String(config.startTime),
		EndTime:    tea.String(config.endTime),
	}

	resp, err := client.DescribeCdnDomainLogsWithOptions(req, &util.RuntimeOptions{})
	if err != nil {
		return fmt.Errorf("API调用失败: %w", err)
	}

	var urls []string
	for _, log := range resp.Body.DomainLogDetails.DomainLogDetail {
		for _, detail := range log.LogInfos.LogInfoDetail {
			if detail.LogPath != nil {
				urls = append(urls, tea.StringValue(detail.LogPath))
			}
		}
	}

	// 写入到 log-url.log 文件
	f, err := os.Create("log-url.log")
	if err != nil {
		return fmt.Errorf("保存日志链接失败: %w", err)
	}
	defer f.Close()
	for _, url := range urls {
		f.WriteString(url + "\n")
	}

	return nil
}

// 读取log-url.log文件中的日志链接
func readLogURLsFromFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	var fixed []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "http") {
			line = "https://" + line
		}
		fixed = append(fixed, line)
	}

	return fixed, nil
}

// 创建阿里云客户端
func createClient() (*cdn20180510.Client, error) {
	cred, err := credential.NewCredential(nil)
	if err != nil {
		return nil, err
	}

	config := &openapi.Config{
		Credential: cred,
		Endpoint:   tea.String("cdn.aliyuncs.com"),
	}

	return cdn20180510.NewClient(config)
}

// 下载日志文件
func downloadLogs(urls []string) ([]string, error) {
	var wg sync.WaitGroup
	workers := make(chan struct{}, maxWorkers)
	results := make(chan string, len(urls))
	errChan := make(chan error, len(urls))

	for _, url := range urls {
		wg.Add(1)
		workers <- struct{}{}

		go func(url string) {
			defer wg.Done()
			defer func() { <-workers }()

			filename := filepath.Join("onlice-log", filepath.Base(url))
			if strings.Contains(filename, "?") {
				filename = strings.Split(filename, "?")[0]
			}

			// 如果文件已存在则跳过
			if _, err := os.Stat(filename); err == nil {
				results <- filename
				time.Sleep(1 * time.Second)
				return
			}

			if err := downloadFile(url, filename); err != nil {
				errChan <- fmt.Errorf("下载失败 %s: %w", url, err)
				time.Sleep(1 * time.Second)
				return
			}

			results <- filename
			time.Sleep(1 * time.Second)
		}(url)
	}

	wg.Wait()
	close(results)
	close(errChan)

	// 处理错误
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	// 收集结果
	var downloaded []string
	for file := range results {
		downloaded = append(downloaded, file)
	}

	if len(errs) > 0 {
		return downloaded, fmt.Errorf("部分文件下载失败: %v", errs)
	}

	return downloaded, nil
}

// 下载单个文件
func downloadFile(url, filename string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)

	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP错误: %s", resp.Status)
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	return err
}

// 在日志中搜索IP
func searchLogsForIP(files []string) (map[string][]string, error) {
	var wg sync.WaitGroup
	workers := make(chan struct{}, maxWorkers)
	results := make(chan struct {
		file  string
		lines []string
	}, len(files))
	errChan := make(chan error, len(files))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, file := range files {
		wg.Add(1)
		workers <- struct{}{}

		go func(file string) {
			defer wg.Done()
			defer func() { <-workers }()

			lines, err := searchInFile(ctx, file)
			if err != nil {
				errChan <- fmt.Errorf("搜索 %s 失败: %w", file, err)
				return
			}

			results <- struct {
				file  string
				lines []string
			}{file: file, lines: lines}
		}(file)
	}

	wg.Wait()
	close(results)
	close(errChan)

	// 处理错误
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	// 收集结果
	allResults := make(map[string][]string)
	for res := range results {
		if len(res.lines) > 0 {
			allResults[res.file] = res.lines
		}
	}

	if len(errs) > 0 {
		return allResults, fmt.Errorf("部分文件搜索失败: %v", errs)
	}

	return allResults, nil
}

// 在单个文件中搜索IP
func searchInFile(ctx context.Context, filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var reader io.Reader = file
	var matches []string

	// 处理gzip压缩文件
	if strings.HasSuffix(filename, ".gz") {
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 1MB初始，最大10MB

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			line := scanner.Text()
			if strings.Contains(line, config.searchIP) {
				matches = append(matches, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return matches, nil
}

// 保存结果
func saveResults(results map[string][]string) error {
	file, err := os.Create(resultsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// 写入头部
	header := fmt.Sprintf("# CDN日志IP分析报告\n"+
		"# 域名: %s\n"+
		"# 时间范围: %s 至 %s\n"+
		"# 搜索IP: %s\n"+
		"# 生成时间: %s\n"+
		"# 匹配文件数: %d\n"+
		"# 总匹配行数: %d\n"+
		"========================================\n\n",
		config.domainName, config.startTime, config.endTime, config.searchIP,
		time.Now().Format(time.RFC3339),
		len(results), totalMatches(results))

	if _, err := writer.WriteString(header); err != nil {
		return err
	}

	// 写入结果
	for file, lines := range results {
		section := fmt.Sprintf("## 文件: %s\n匹配行数: %d\n", filepath.Base(file), len(lines))
		if _, err := writer.WriteString(section); err != nil {
			return err
		}

		for _, line := range lines {
			if _, err := writer.WriteString(line + "\n"); err != nil {
				return err
			}
		}
		writer.WriteString("\n")
	}

	// 写入尾部
	footer := fmt.Sprintf("========================================\n"+
		"# 分析完成时间: %s\n",
		time.Now().Format(time.RFC3339))

	_, err = writer.WriteString(footer)
	return err
}

// 计算总匹配行数
func totalMatches(results map[string][]string) int {
	total := 0
	for _, lines := range results {
		total += len(lines)
	}
	return total
}
