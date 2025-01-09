package apnic

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	apnicFile = "./data/delegated-apnic-extended-latest.txt"
	eTagFile  = "./data/delegated-apnic-extended-latest.txt.etag"
)

type ApnicInfo struct {
	IpSet   string
	Country string
}

func Init() {
	apnicInit()
}

func apnicInit() {
	go func() {
		req, err := http.NewRequest("GET", "http://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-extended-latest", nil)
		if err != nil {
			panic(err)
		}

		eTag, _ := os.ReadFile(eTagFile)
		eTagVal := strings.TrimSpace(string(eTag))
		if eTagVal != "" {
			req.Header.Set("If-None-Match", eTagVal)
		}

		client := http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			panic(err)
		}
		res, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNotModified {
			newETag := resp.Header.Get("ETag")
			err = os.WriteFile(eTagFile, []byte(newETag), 0644)
			if err != nil {
				panic(err)
			}

			err = os.WriteFile(apnicFile, res, 0644)
			if err != nil {
				panic(err)
			}
		}

		time.Sleep(time.Hour * 24)
	}()
}

func parse(record string) (ApnicInfo, error) {
	info := ApnicInfo{}
	fields := strings.Split(record, "|")
	if len(fields) < 7 || fields[2] != "ipv4" {
		return info, fmt.Errorf("not ipv4 record")
	}

	ipStart := fields[3]
	count, err := strconv.Atoi(fields[4])
	if err != nil {
		return info, fmt.Errorf("invalid count: %v", err)
	}

	mask := 32 - int(math.Log2(float64(count)))
	info.IpSet = fmt.Sprintf("%s/%d", ipStart, mask)
	info.Country = fields[1]
	return info, nil
}

func in(ip, cidr string) (bool, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, fmt.Errorf("invalid cidr: %v", err)
	}

	ipInfo := net.ParseIP(ip)
	if ipInfo == nil {
		return false, fmt.Errorf("invalid ip: %v", ip)
	}

	return ipNet.Contains(ipInfo), nil
}

func match(record, ip string, wg *sync.WaitGroup, info *ApnicInfo, found chan<- bool) {
	defer wg.Done()

	result, err := parse(record)
	if err != nil {
		return
	}

	if result.IpSet != "" {
		in, err := in(ip, result.IpSet)
		if err != nil {
			fmt.Printf("error checking ip in cidr: %v", err)
		} else if in {
			fmt.Printf("[NOTE] ip: %s is inside cidr: %s\n", ip, result)
			found <- true
			info.IpSet = result.IpSet
			info.Country = result.Country
		}
	}
}

func Check(ip string) (bool, ApnicInfo, error) {
	file, err := os.Open(apnicFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	var wg sync.WaitGroup
	found := make(chan bool, 1)
	sem := make(chan struct{}, 10)
	info := ApnicInfo{}
	matches := false

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "ipv4") {
			sem <- struct{}{}
			wg.Add(1)
			go func(record string) {
				defer func() { <-sem }()
				match(record, ip, &wg, &info, found)
			}(line)

			select {
			case <-found:
				matches = true
				break
			default:
			}
		}
	}

	go func() {
		wg.Wait()
	}()

	if err := scanner.Err(); err != nil {
		return false, info, err
	}

	return matches, info, nil
}
