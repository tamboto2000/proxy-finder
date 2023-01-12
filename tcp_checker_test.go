package proxyfinder

import (
	"reflect"
	"testing"
)

func Test_validateTcpProxy(t *testing.T) {
	type args struct {
		ip   string
		port string
	}
	tests := []struct {
		name    string
		args    args
		want    *Proxy
		wantErr bool
	}{
		{
			name: "Validate proxy (valid)",
			args: args{
				ip:   "42.63.10.170",
				port: "9002",
			},
			want: &Proxy{
				Ip:   "8080",
				Port: "3128",
				Type: "tcp",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateTcpProxy(tt.args.ip, tt.args.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateTcpProxy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("validateTcpProxy() = %v, want %v", got, tt.want)
			}
		})
	}
}
