package proxyfinder

import (
	"errors"
	"fmt"
	"os"
	"sync"
)

func FindProxies(count int, mode string) ([]Proxy, error) {
	f, err := os.Create("proxies.txt")
	if err != nil {
		return nil, err
	}

	defer f.Close()

	var proxies []Proxy
	mx := new(sync.Mutex)
	wg := new(sync.WaitGroup)
	var resErr error

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup, mx *sync.Mutex) {
			defer wg.Done()

			prox, err := FindTcpProxy(mode)
			if err != nil {
				mx.Lock()
				if resErr == nil {
					resErr = err
				} else {
					resErr = errors.New(resErr.Error() + ";" + err.Error())
				}

				mx.Unlock()

				return
			}

			mx.Lock()
			proxies = append(proxies, prox)
			f.WriteString(fmt.Sprintf("http://%s:%s#%s#google=%v#cloudflare=%v\n", prox.Ip, prox.Port, prox.CountryCode, prox.Google, prox.Cloudflare))
			mx.Unlock()
		}(wg, mx)
	}

	wg.Wait()

	return proxies, resErr
}
