package proxyfinder

import (
	"errors"
	"sync"
)

func FindProxies(count int) ([]Proxy, error) {
	var proxies []Proxy
	mx := new(sync.Mutex)
	wg := new(sync.WaitGroup)
	var resErr error

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup, mx *sync.Mutex) {
			defer wg.Done()

			prox, err := FindTcpProxy()
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
			mx.Unlock()
		}(wg, mx)
	}

	wg.Wait()

	return proxies, resErr
}
