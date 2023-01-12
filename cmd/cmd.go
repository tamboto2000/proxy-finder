package main

import (
	"flag"
	"fmt"

	proxyfinder "github.com/tamboto2000/proxy-finder"
)

func main() {
	proxCount := flag.Int("c", 1, "how many proxy need to be find")
	mode := flag.String("m", "fast", "port scan mode, \"fast\" for only scan from common known ports, \"all\" for scan all possible TCP ports")
	flag.Parse()

	_, err := proxyfinder.FindProxies(*proxCount, *mode)
	if err != nil {
		fmt.Println("error:", err.Error())
		return
	}
}
