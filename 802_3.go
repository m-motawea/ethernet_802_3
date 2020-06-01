package ethernet_802_3

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/m-motawea/llc"
	"github.com/m-motawea/snap"
)

type Length uint16

// type FCS uint32

type Frame struct {
	Destination net.HardwareAddr
	Source      net.HardwareAddr
	Length      Length // <= 0x05DC or 1500 decimal
	LLC         llc.LLCPDU
	SNAP        snap.SNAP // exist only if DSAP / SSAP = 0xAAAA. (llc.LSAPSNAPExtension)
	Data        []byte    // 46 - 1500
	// FCS         FCS
}

func (f *Frame) Len() int {
	len := len(f.Data)
	if f.LLC.SSAP == llc.LSAPSNAPExtension && f.LLC.DSAP == llc.LSAPSNAPExtension {
		len += 5
	}
	f.Length = Length(len)
	return len
}

func (f *Frame) TotalLength() int {
	/*
		6 byte Destination
		6 byte Source
		2 byte Length
		3 byte LLC
		(5 byte SNAP)
		len(f.Data)
		4 byte checksum
	*/
	dataLen := f.Len()
	return dataLen + 17
}

func (f *Frame) MarshalBinary() ([]byte, error) {
	b := make([]byte, f.TotalLength())
	if f.Length > Length(1500) {
		return b, errors.New("invalid frame length for 802.3")
	}
	copy(b[0:6], f.Destination)
	copy(b[6:12], f.Source)
	binary.BigEndian.PutUint16(b[12:14], uint16(f.Length))
	llcBytes, err := f.LLC.MarshalBinary()
	if err != nil {
		return b, err
	}
	copy(b[14:17], llcBytes)

	index := 17
	if f.LLC.SSAP == llc.LSAPSNAPExtension && f.LLC.DSAP == llc.LSAPSNAPExtension {
		// add SNAP
		snapBytes, err := f.SNAP.MarshalBinary()
		if err != nil {
			return b, err
		}
		copy(b[17:23], snapBytes)
		index += 5
	}
	if len(f.Data) > 0 {
		copy(b[index:], f.Data)
	}
	// fcs := crc32.ChecksumIEEE(b[0 : len(b)-4])
	// binary.BigEndian.PutUint32(b[len(b)-4:], fcs)
	return b, nil
}

func (f *Frame) UnmarshalBinary(b []byte) error {
	if len(b) < 17 {
		return errors.New("invalid size for 802.3 frame")
	}
	f.Destination = net.HardwareAddr(b[:6])
	f.Source = net.HardwareAddr(b[6:12])
	frameLen := binary.BigEndian.Uint16(b[12:14])
	if frameLen > 1500 {
		return errors.New("invalid length value found in frame.")
	}
	f.Length = Length(frameLen)
	err := f.LLC.UnmarshalBinary(b[14:17])
	if err != nil {
		return err
	}

	index := 17
	if f.LLC.SSAP == llc.LSAPSNAPExtension && f.LLC.DSAP == llc.LSAPSNAPExtension {
		if len(b) < 26 {
			return errors.New("invalid size for 802.3 frame with SNAP extension")
		}
		err := f.SNAP.UnmarshalBinary(b[index : index+5])
		if err != nil {
			return err
		}
		index += 5
	}
	// fcs := binary.BigEndian.Uint32(b[len(b)-4:])
	// f.FCS = FCS(fcs)
	f.Data = make([]byte, int(f.Length))
	copy(f.Data, b[index:index+int(f.Length)])

	return nil
}
