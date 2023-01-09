package proxyfinder

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// randIp generate random IPv4
func randIp() string {
	buf := make([]byte, 4)
	rand.Seed(time.Now().UnixNano())
	ip := rand.Uint32()

	binary.LittleEndian.PutUint32(buf, ip)
	return fmt.Sprintf("%s", net.IP(buf))
}
