package main

import (
	"flag"
	"fmt"

	proxyfinder "github.com/tamboto2000/proxy-finder"
)

func main() {
	proxCount := flag.Int("c", 1, "how many proxy need to be find")
	flag.Parse()

	_, err := proxyfinder.FindProxies(*proxCount)
	if err != nil {
		fmt.Println("error:", err.Error())
		return
	}
}
