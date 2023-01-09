package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	proxyfinder "github.com/tamboto2000/proxy-finder"
)

func main() {
	proxCount := flag.Int("c", 1, "how many proxy need to be find")
	flag.Parse()

	proxies, err := proxyfinder.FindProxies(*proxCount)
	if err != nil {
		fmt.Println("error:", err.Error())
		return
	}

	jsonB, err := json.Marshal(proxies)
	if err != nil {
		fmt.Println("error:", err.Error())
		return
	}

	f, err := os.Create("proxies.json")
	defer f.Close()

	if err != nil {
		log.Fatal(err.Error())
	}

	f.Write(jsonB)
}
