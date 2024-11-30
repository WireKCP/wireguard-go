//go:build !linux

package device

import (
	"github.com/wirekcp/wireguard-go/conn"
	"github.com/wirekcp/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(bind conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
