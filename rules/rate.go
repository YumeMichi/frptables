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
	"github.com/zngw/frptables/config"
	"sync"
	"time"
)

// 用线程安装的map保存ip记录
var ips = sync.Map{}

type history struct {
	Ip   string
	Port int
	List []int64
}

func (h *history) Init(ip string, port int) {
	h.Ip = ip
	h.Port = port
	h.Add()
}

func (h *history) Add() {
	h.List = append(h.List, time.Now().Unix())
}

func (h *history) Count(interval int64) (count int) {
	count = 0
	now := time.Now().Unix()
	for _, v := range h.List {
		if now < v+interval {
			count++
		}
	}
	return
}

func rateInit() {
	// 异步清理
	go func() {
		for {
			delTime := time.Now().Unix() - config.Cfg.RateMaxTime
			var del []string
			ips.Range(func(k, v interface{}) bool {
				h := v.(*history)
				for i := 0; i < len(h.List); {
					if h.List[i] < delTime {
						h.List = append(h.List[:i], h.List[i+1:]...)
					} else {
						i++
					}
				}

				if len(h.List) == 0 {
					del = append(del, k.(string))
				}

				return true
			})

			for _, k := range del {
				ips.Delete(k)
			}

			time.Sleep(time.Second * time.Duration(config.Cfg.RateMaxTime))
		}
	}()
}

func getIpHistory(ip string, port int) (h *history) {
	key := fmt.Sprintf("%s:%d", ip, port)
	tmp, ok := ips.Load(key)
	if !ok {
		h = new(history)
		h.Init(ip, port)
		ips.Store(key, h)
		return
	}

	h = tmp.(*history)
	h.Add()
	return
}

func delIpHistory(ip string, port int) {
	key := fmt.Sprintf("%s:%d", ip, port)
	ips.Delete(key)
}
