//MIT License
//
//Copyright (c) 2021 zngw
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/zngw/frptables/config"
)

// 解析日志
func parse(text string) (ip, name string, port int, err error) {
	// 从frp日志中获取tcp连接信息
	// 2025-01-09 20:22:26.325 [I] [proxy/proxy.go:204] [6b20f9e3d1cd33fc] [ssh-office] get a user connection [122.226.147.98:49812]
	if !strings.Contains(text, "get a user connection") {
		err = fmt.Errorf("not tcp link")
		return
	}

	// 正则表达式获取转发名和请求ID
	compileRegex := regexp.MustCompile(`\s*\[I\] \[.*\] \[.*\] \[(.*?)\] get a user connection \[(.*?)\]`)
	matchArr := compileRegex.FindStringSubmatch(text)

	if len(matchArr) <= 2 {
		err = fmt.Errorf("not tcp link")
		return
	}

	// 转发名
	name = matchArr[1]
	addr := matchArr[2]
	addrArray := strings.Split(addr, ":")
	if len(addrArray) != 2 {
		err = fmt.Errorf("%s", addr+" addr error")
		return
	}

	// 请求IP
	ip = addrArray[0]

	if v, ok := config.Cfg.NamePort[name]; ok {
		port = v
	} else {
		port = -1
	}

	return
}
