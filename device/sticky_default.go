//go:build !linux

package device

import (
	"github.com/wirekcp/wireguard-go/conn"
	"github.com/wirekcp/wireguard-go/rwcancel"
)

func (device *Device) startRouteListener(_ conn.Bind) (*rwcancel.RWCancel, error) {
	return nil, nil
}
