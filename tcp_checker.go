package proxyfinder

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/tevino/tcp-shaker"
)

// commonTcpPorts is port list
// that is usually found in public
// proxy.
var commonTcpPorts = []string{
	"8080",
	"80",
	"3128",
	"8081",
	"808",
	"8000",
	"8090",
	"33630",
	"1975",
	"53040",
	"7532",
	"1081",
	"1981",
	"53281",
	"55443",
	"1337",
	"9091",
	"7890",
	"443",
	"40657",
	"8088",
	"10000",
	"8889",
	"3129",
	"8118",
	"7001",
	"9300",
	"45977",
}

const maxTcpPort = 65535
const (
	userAgentHeader = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
	acceptHeader    = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
)

type Proxy struct {
	Ip          string `json:"ip"`
	Port        string `json:"port"`
	Type        string `json:"type"` // tcp, udp, socks4, socks5
	Anonymity   string `json:"anonymity"`
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	Https       bool   `json:"https"`
	Google      bool   `json:"google"`
	Cloudflare  bool   `json:"cloudflare"`
}

// FindTcpProxy find a working TCP proxy.
// Please note that the proxy that has been found
// might not be working all the time (99% up-time)
// because who knows the quality of the server.
// It is recommended to test the proxy from time to
// time to make sure if the proxy is still working
// or not
func FindTcpProxy() (Proxy, error) {
	for {
		// generate random IP
		ip := randIp()
		var port string

		// DELETE
		fmt.Printf("scan open port for IP %s\n", ip)

		// scan for any open ports
		for _, port = range commonTcpPorts {
			valid, err := validateTcpProxy(ip, port)
			if err != nil {
				return Proxy{}, err
			}

			if !valid {
				continue
			} else {
				// check for google.com bypass
				googleBypass, err := checkGoogleBypass(ip, port)
				if err != nil {
					return Proxy{}, err
				}

				// check for cloudflare.com bypass
				cloudflareBypass, err := checkCloudflareBypass(ip, port)
				if err != nil {
					return Proxy{}, err
				}

				// TODO
				// - anonymity check
				// - geolocation check

				fmt.Printf("Proxy %s:%s is valid!\n", ip, port)
				return Proxy{
					Ip:         ip,
					Port:       port,
					Type:       "tcp",
					Google:     googleBypass,
					Cloudflare: cloudflareBypass,
				}, nil
			}
		}

		for i := 1; i < maxTcpPort+1; i++ {
			port = strconv.Itoa(i)
			valid, err := validateTcpProxy(ip, port)
			if err != nil {
				return Proxy{}, err
			}

			if !valid {
				continue
			} else {
				// check for google.com bypass
				googleBypass, err := checkGoogleBypass(ip, port)
				if err != nil {
					return Proxy{}, err
				}

				// check for cloudflare.com bypass
				cloudflareBypass, err := checkCloudflareBypass(ip, port)
				if err != nil {
					return Proxy{}, err
				}

				// TODO
				// - anonymity check
				// - geolocation check

				fmt.Printf("Proxy %s:%s is valid!\n", ip, port)
				return Proxy{
					Ip:         ip,
					Port:       port,
					Type:       "tcp",
					Google:     googleBypass,
					Cloudflare: cloudflareBypass,
				}, nil
			}
		}
	}
}

func validateTcpProxy(ip, port string) (bool, error) {
	if !checkTcp(ip, port) {
		return false, nil
	}

	// DELETE
	fmt.Printf("validate %s:%s\n", ip, port)

	// check if proxy can be used to request
	// httpbin.org/get.
	// If not then proxy is not valid at all
	valid, err := checkTcpProxHttpBin(ip, port)
	if err != nil {
		return false, err
	}

	if !valid {
		// DELETE
		fmt.Printf("%s:%s is not valid\n", ip, port)

		return false, nil
	} else {
		fmt.Printf("%s:%s is valid!\n", ip, port)
	}

	return true, nil
}

// scanTcpPort scan open port for an IP.
// This function will scan from a known list first,
// if non open then it will find open port to the range
// of 1 to 65535 while skipping common ports.
// If port is still not found, then this IP is invalid
// and this function will return empty string
func scanTcpPort(ip string) string {
	// iterate over common known ports
	for _, p := range commonTcpPorts {
		if checkTcp(ip, p) {
			return p
		}
	}

	// iterate over the TCP port range
	for i := 1; i < maxTcpPort+1; i++ {
		port := strconv.Itoa(i)
		if tcpPortIsCommon(port) {
			continue
		}

		if checkTcp(ip, port) {
			return port
		}
	}

	return ""
}

func tcpPortIsCommon(port string) bool {
	for _, p := range commonTcpPorts {
		if port == p {
			return true
		}
	}

	return false
}

// checkTcp perform SYN TCP check for ip and port pair
func checkTcp(ip, port string) bool {
	c := tcp.NewChecker()

	ctx, stopChecker := context.WithCancel(context.Background())
	defer stopChecker()
	go func() {
		c.CheckingLoop(ctx)
	}()

	<-c.WaitReady()

	timeout := time.Second * 5
	ipPort := fmt.Sprintf("%s:%s", ip, port)

	err := c.CheckAddr(ipPort, timeout)
	if err != nil {
		return false
	}

	return true
}

// checkGoogleBypass check whether the proxy
// can be used to bypass google.com
func checkGoogleBypass(ip, port string) (bool, error) {
	proxyUrl, err := url.Parse(fmt.Sprintf("http://%s:%s", ip, port))
	if err != nil {
		return false, err
	}

	timeout := time.Second * 5
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyUrl),
		DialContext: (&net.Dialer{
			Timeout:   time.Second * time.Duration(timeout),
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	}

	client := http.Client{
		Timeout:   time.Second * time.Duration(timeout),
		Transport: tr,
	}

	req, err := http.NewRequest("GET", "https://google.com", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("User-Agent", userAgentHeader)
	req.Header.Add("Accept", acceptHeader)

	res, err := client.Do(req)
	if err != nil {
		return false, nil
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return false, nil
	}

	return true, nil
}

// checkGoogleBypass check whether the proxy
// can be used to bypass cloudflare.com
func checkCloudflareBypass(ip, port string) (bool, error) {
	proxyUrl, err := url.Parse(fmt.Sprintf("http://%s:%s", ip, port))
	if err != nil {
		return false, err
	}

	timeout := time.Second * 5
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyUrl),
		DialContext: (&net.Dialer{
			Timeout:   time.Second * time.Duration(timeout),
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	}

	client := http.Client{
		Timeout:   time.Second * time.Duration(timeout),
		Transport: tr,
	}

	req, err := http.NewRequest("GET", "https://cloudflare.com/", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("User-Agent", userAgentHeader)
	req.Header.Add("Accept", acceptHeader)

	res, err := client.Do(req)
	if err != nil {
		return false, nil
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return false, nil
	}

	return true, nil
}

func checkTcpProxHttpBin(ip, port string) (bool, error) {
	proxyUrl, err := url.Parse(fmt.Sprintf("http://%s:%s", ip, port))
	if err != nil {
		return false, err
	}

	timeout := time.Second * 5
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyUrl),
		DialContext: (&net.Dialer{
			Timeout:   time.Second * time.Duration(timeout),
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	}

	client := http.Client{
		Timeout:   time.Second * time.Duration(timeout),
		Transport: tr,
	}

	req, err := http.NewRequest("GET", "https://httpbin.org/get", nil)
	if err != nil {
		return false, err
	}

	req.Header.Add("User-Agent", userAgentHeader)
	req.Header.Add("Accept", acceptHeader)

	res, err := client.Do(req)
	if err != nil {
		return false, nil
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		return false, nil
	}

	return true, nil
}
