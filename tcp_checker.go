package proxyfinder

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/sggms/go-pingparse/pinger"
	"github.com/sggms/go-pingparse/pinger/parser"
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
	"8089",
	"59175",
	"8083",
	"999",
	"10001",
	"4015",
	"10012",
	"10005",
	"10009",
	"10002",
	"6969",
	"9090",
	"49920",
	"8111",
	"1976",
	"3333",
	"9000",
	"52151",
	"9812",
	"9741",
	"6666",
	"24000",
	"12345",
	"4555",
	"8989",
	"5555",
	"57322",
	"8888",
	"23456",
	"41258",
	"54651",
	"9898",
	"46752",
	"5002",
	"35081",
	"9229",
	"38080",
	"31409",
	"49717",
}

const maxTcpPort = 65535
const (
	userAgentHeader = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36"
	acceptHeader    = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
)

const (
	ModeFast     = "fast"
	ModeRangeAll = "all"
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
// or not.
func FindTcpProxy(mode string) (Proxy, error) {
	for {
		// generate random IP
		ip := randIp()

		// check if IP is private
		pIp := net.ParseIP(ip)

		if pIp == nil {
			continue
		}

		if pIp.IsPrivate() {
			continue
		}

		// ping to confirm if server is accessible by public
		pingOut, err := pingIp(ip)
		if err != nil {
			log.Println("ping fatal error:", err.Error())
			return Proxy{}, err
		}

		if pingOut.Stats.PacketLossPercent > 0 {
			continue
		}

		log.Printf("ip %s is alive, scanning port...\n", ip)

		// scan for any open ports
		for _, port := range commonTcpPorts {
			prox, err := validateTcpProxy(ip, port)
			if err != nil {
				return Proxy{}, err
			}

			if prox == nil {
				log.Printf("proxy %s:%s is not valid, continue scanning port...\n", ip, port)
				continue
			} else {
				log.Printf("proxy %s:%s is saved\n", ip, port)
				return *prox, nil
			}
		}

		if mode == ModeRangeAll {
			for i := 1; i < maxTcpPort+1; i++ {
				port := strconv.Itoa(i)
				prox, err := validateTcpProxy(ip, port)
				if err != nil {
					return Proxy{}, err
				}

				if prox == nil {
					log.Printf("proxy %s:%s is not valid, continue scanning port...\n", ip, port)
					continue
				} else {
					log.Printf("proxy %s:%s is saved\n", ip, port)
					return *prox, nil
				}
			}
		}

		log.Printf("ip %s can not be used as proxy, scanning IPs...\n", ip)
	}
}

func validateTcpProxy(ip, port string) (*Proxy, error) {
	if !checkTcp(ip, port) {
		return nil, nil
	}

	log.Printf("ip port %s:%s is open, validating...\n", ip, port)

	// check if proxy can be used to request
	// httpbin.org/get.
	// If not then proxy is not valid at all
	valid, err := checkTcpProxHttpBin2(ip, port)
	if err != nil {
		log.Printf("httpbin.org req error: %s\n", err.Error())
		return nil, err
	}

	if !valid {
		return nil, nil
	}

	log.Printf("proxy %s:%s is valid!\n", ip, port)

	log.Printf("checking google bypass for proxy %s:%s...\n", ip, port)
	// check for google.com bypass
	googleBypass, err := checkGoogleBypass(ip, port)
	if err != nil {
		return nil, err
	}

	log.Printf("checking cloudflare bypass for proxy %s:%s...\n", ip, port)
	// check for cloudflare.com bypass
	cloudflareBypass, err := checkCloudflareBypass(ip, port)
	if err != nil {
		return nil, err
	}

	// TODO
	// - anonymity check
	// - geolocation check

	return &Proxy{
		Ip:         ip,
		Port:       port,
		Type:       "tcp",
		Google:     googleBypass,
		Cloudflare: cloudflareBypass,
	}, nil
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
			Timeout:   timeout,
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	}

	client := http.Client{
		Timeout:   timeout,
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
			Timeout:   timeout,
			KeepAlive: time.Second,
			DualStack: true,
		}).DialContext,
	}

	client := http.Client{
		Timeout:   timeout,
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
	cl := http.DefaultClient
	proxUrl, err := url.Parse(fmt.Sprintf("http://%s:%s", ip, port))
	if err != nil {
		return false, err
	}

	cl.Transport = &http.Transport{
		Proxy: http.ProxyURL(proxUrl),
	}
	cl.Timeout = time.Second * 5

	// you can test the proxy against any website, I just pick this randomly
	req, _ := http.NewRequest(http.MethodGet, "https://httpbin.org/get", nil)
	resp, err := cl.Do(req)
	if err != nil {
		log.Println("httpbin check error: ", err.Error())
		return false, nil
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// body, _ := ioutil.ReadAll(resp.Body)
		// if err != nil {
		// 	return false, err
		// }

		log.Printf("httpbin check error: HTTP %d\n", resp.StatusCode)

		return false, nil
	}

	return true, nil
}

func checkTcpProxHttpBin2(ip, port string) (bool, error) {
	proxyUrl, err := url.Parse(fmt.Sprintf("http://%s:%s", ip, port))
	if err != nil {
		return false, err
	}

	timeout := time.Second * 10
	tr := &http.Transport{
		Proxy: http.ProxyURL(proxyUrl),
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: time.Second,
		}).DialContext,
	}

	client := http.Client{
		Timeout:   timeout,
		Transport: tr,
	}

	req, err := http.NewRequest("GET", "https://httpbin.org/get", nil)
	if err != nil {
		fmt.Println(err.Error())
		return false, err
	}

	req.Header.Add("User-Agent", userAgentHeader)
	req.Header.Add("Accept", acceptHeader)

	res, err := client.Do(req)
	if err != nil {
		log.Println(err.Error())
		return false, nil
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		log.Println("non 200")
		return false, nil
	}

	return true, nil
}

func pingIp(ip string) (*parser.PingOutput, error) {
	out, err := pinger.Ping(ip, time.Second*2, time.Second*5, 4)
	if err != nil {
		switch err {

		case parser.ErrHeaderMismatch:
			return nil, err

		case parser.ErrUnrecognizedLine:
			return nil, err

		case parser.ErrMalformedStatsHeader:
			return nil, err

		case parser.ErrMalformedStatsLine1:
			return nil, err

		case parser.ErrMalformedStatsLine2:
			return nil, err

		default:
			return &parser.PingOutput{
				Stats: parser.PingStatistics{
					PacketLossPercent: 100,
				},
			}, nil
		}
	}

	return out, nil
}
