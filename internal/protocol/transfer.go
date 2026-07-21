package protocol

import "fmt"

// TransferPayloadPrefixBytes 是每个 file/app 数据帧前固定的 64 字节 TransferPayload 头长度。
const TransferPayloadPrefixBytes = 64

// CompressionType 是 file/app 传输的压缩算法枚举；本服务只支持 CompressionNone，其余一律拒绝。
type CompressionType uint8

const (
	CompressionNone CompressionType = iota
	CompressionLZ4
	CompressionLZ77
	CompressionLZMA
	CompressionBrotli
)

// TransferConfig 是 file/app 传输握手（CMD_FILE_CHECK / CMD_APP_CHECK）携带的元数据。
// 关键字段：FileSize（总大小）、Path（设备目标路径）、OptionalName（文件/包名）、
// FunctionName（app 用 "install"）、Options（安装选项）、Compression（须为 None）。
type TransferConfig struct {
	FileSize      uint64
	ATime         uint64
	MTime         uint64
	Options       string
	Path          string
	OptionalName  string
	UpdateIfNew   bool
	Compression   CompressionType
	HoldTimestamp bool
	FunctionName  string
	ClientCWD     string
	Reserve1      string
	Reserve2      string
}

// TransferPayload 是每个数据帧头部字段：Index 为文件偏移，CompressedSize/UncompressedSize 为本片大小（未压缩时相等）。
type TransferPayload struct {
	Index            uint64
	Compression      CompressionType
	CompressedSize   uint32
	UncompressedSize uint32
}

// EncodeTransferConfig 把 TransferConfig 序列化为 file/app CHECK 帧负载（protobuf 风格字段）。
func EncodeTransferConfig(config TransferConfig) []byte {
	var result []byte
	result = appendVarintField(result, 1, config.FileSize)
	result = appendVarintField(result, 2, config.ATime)
	result = appendVarintField(result, 3, config.MTime)
	result = appendStringField(result, 4, config.Options)
	result = appendStringField(result, 5, config.Path)
	result = appendStringField(result, 6, config.OptionalName)
	result = appendBoolField(result, 7, config.UpdateIfNew)
	result = appendVarintField(result, 8, uint64(config.Compression))
	result = appendBoolField(result, 9, config.HoldTimestamp)
	result = appendStringField(result, 10, config.FunctionName)
	result = appendStringField(result, 11, config.ClientCWD)
	result = appendStringField(result, 12, config.Reserve1)
	return appendStringField(result, 13, config.Reserve2)
}

// DecodeTransferConfig 从 file/app CHECK 帧负载解析 TransferConfig；未知字段按 wire 类型跳过。
func DecodeTransferConfig(payload []byte) (TransferConfig, error) {
	cursor := newCursor(payload)
	var config TransferConfig
	for cursor.remaining() {
		field, wire, stop, err := nextTransferField(cursor)
		if err != nil {
			return TransferConfig{}, err
		}
		if stop {
			break
		}
		switch field {
		case 1:
			config.FileSize, err = cursor.varintValue(wire)
		case 2:
			config.ATime, err = cursor.varintValue(wire)
		case 3:
			config.MTime, err = cursor.varintValue(wire)
		case 4:
			config.Options, err = cursor.stringValue(wire)
		case 5:
			config.Path, err = cursor.stringValue(wire)
		case 6:
			config.OptionalName, err = cursor.stringValue(wire)
		case 7:
			config.UpdateIfNew, err = readBool(cursor, wire)
		case 8:
			config.Compression, err = readCompressionType(cursor, wire)
		case 9:
			config.HoldTimestamp, err = readBool(cursor, wire)
		case 10:
			config.FunctionName, err = cursor.stringValue(wire)
		case 11:
			config.ClientCWD, err = cursor.stringValue(wire)
		case 12:
			config.Reserve1, err = cursor.stringValue(wire)
		case 13:
			config.Reserve2, err = cursor.stringValue(wire)
		default:
			err = cursor.skip(wire)
		}
		if err != nil {
			return TransferConfig{}, fmt.Errorf("decode HDC transfer config field %d: %w", field, err)
		}
	}
	return config, nil
}

// EncodeTransferPayload 序列化数据帧头（index 偏移、压缩类型、分片大小），作为 CMD_*_DATA 帧前缀。
func EncodeTransferPayload(payload TransferPayload) []byte {
	var result []byte
	result = appendVarintField(result, 1, payload.Index)
	result = appendVarintField(result, 2, uint64(payload.Compression))
	result = appendVarintField(result, 3, uint64(payload.CompressedSize))
	return appendVarintField(result, 4, uint64(payload.UncompressedSize))
}

// DecodeTransferPayload 解析数据帧头字段；未知字段按 wire 类型跳过。
func DecodeTransferPayload(payload []byte) (TransferPayload, error) {
	cursor := newCursor(payload)
	var transferPayload TransferPayload
	for cursor.remaining() {
		field, wire, stop, err := nextTransferField(cursor)
		if err != nil {
			return TransferPayload{}, err
		}
		if stop {
			break
		}
		switch field {
		case 1:
			transferPayload.Index, err = cursor.varintValue(wire)
		case 2:
			transferPayload.Compression, err = readCompressionType(cursor, wire)
		case 3:
			transferPayload.CompressedSize, err = readUint32(cursor, wire)
		case 4:
			transferPayload.UncompressedSize, err = readUint32(cursor, wire)
		default:
			err = cursor.skip(wire)
		}
		if err != nil {
			return TransferPayload{}, fmt.Errorf("decode HDC transfer payload field %d: %w", field, err)
		}
	}
	return transferPayload, nil
}

// EncodeTransferData 组装一个数据帧负载：64 字节 TransferPayload 头 + 原始数据；要求 data 长度与 header.CompressedSize 一致。
func EncodeTransferData(header TransferPayload, data []byte) ([]byte, error) {
	if uint64(len(data)) != uint64(header.CompressedSize) {
		return nil, fmt.Errorf("HDC transfer data size is %d, want %d", len(data), header.CompressedSize)
	}
	serialized := EncodeTransferPayload(header)
	if len(serialized)+1 > TransferPayloadPrefixBytes {
		return nil, fmt.Errorf("HDC transfer payload header is too large: %d", len(serialized))
	}
	result := make([]byte, TransferPayloadPrefixBytes+len(data))
	copy(result, serialized)
	copy(result[TransferPayloadPrefixBytes:], data)
	return result, nil
}

// DecodeTransferData 从数据帧负载中解出 TransferPayload 头与数据片，并校验大小边界（防越界与超限放大）。
func DecodeTransferData(payload []byte, maxUncompressedBytes uint32) (TransferPayload, []byte, error) {
	if len(payload) < TransferPayloadPrefixBytes {
		return TransferPayload{}, nil, fmt.Errorf("HDC transfer data is shorter than the %d-byte prefix", TransferPayloadPrefixBytes)
	}
	header, err := DecodeTransferPayload(payload[:TransferPayloadPrefixBytes])
	if err != nil {
		return TransferPayload{}, nil, err
	}
	available := len(payload) - TransferPayloadPrefixBytes
	if uint64(header.CompressedSize) > uint64(available) {
		return TransferPayload{}, nil, fmt.Errorf("HDC transfer compressed size %d exceeds available data %d", header.CompressedSize, available)
	}
	if header.UncompressedSize > maxUncompressedBytes {
		return TransferPayload{}, nil, fmt.Errorf("HDC transfer uncompressed size %d exceeds limit %d", header.UncompressedSize, maxUncompressedBytes)
	}
	data := payload[TransferPayloadPrefixBytes : TransferPayloadPrefixBytes+int(header.CompressedSize)]
	return header, append([]byte(nil), data...), nil
}

func nextTransferField(cursor *cursor) (field, wire int, stop bool, err error) {
	key, err := cursor.varint()
	if err != nil {
		return 0, 0, false, err
	}
	if key == 0 {
		return 0, 0, true, nil
	}
	return int(key >> 3), int(key & 7), false, nil
}

func appendBoolField(target []byte, field int, value bool) []byte {
	if value {
		return appendVarintField(target, field, 1)
	}
	return appendVarintField(target, field, 0)
}

func readBool(cursor *cursor, wire int) (bool, error) {
	value, err := cursor.varintValue(wire)
	return value != 0, err
}

func readCompressionType(cursor *cursor, wire int) (CompressionType, error) {
	value, err := cursor.varintValue(wire)
	if err != nil {
		return 0, err
	}
	if value > uint64(^uint8(0)) {
		return 0, fmt.Errorf("compression type is out of range: %d", value)
	}
	return CompressionType(value), nil
}

func readUint32(cursor *cursor, wire int) (uint32, error) {
	value, err := cursor.varintValue(wire)
	if err != nil {
		return 0, err
	}
	if value > uint64(^uint32(0)) {
		return 0, fmt.Errorf("value is out of uint32 range: %d", value)
	}
	return uint32(value), nil
}
