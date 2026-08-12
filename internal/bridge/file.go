// Package bridge 实现各 HDC 协议族的 daemon 侧桥接：shell、unity、file、app、forward。
// 把用户侧协议帧翻译为对主 HDC target channel 的命令与数据流，并管理临时存储与会话生命周期。
package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

const (
	fileFinishAll         = byte(0)
	fileFinishCurrentFile = byte(1)
	// fileOutputLimit 是主 HDC 命令输出的采集上限，仅用于识别失败标记。
	fileOutputLimit = 4 * 1024
)

const (
	failInvalidFileRequest    = "[Fail] File transfer request is invalid."
	failUnsupportedFileOption = "[Fail] File transfer option is not supported."
	failUnsupportedCompress   = "[Fail] Compressed file transfer is not supported."
	failUnsupportedDirectory  = "[Fail] Directory transfer is not supported."
	failFileTransfer          = "[Fail] File transfer failed."
	failFileTransferTimeout   = "[Fail] File transfer timed out."
	failFileDownload          = "[Fail] File receive is not implemented."
	failFileNoResult          = "[Fail] File transfer did not return a result."
)

// TargetChannel 抽象一条到设备的主 HDC 命令通道（由 hdc.TargetChannel 实现），
// 用接口而非具体类型以便各 bridge 单测注入 fake channel。
type TargetChannel interface {
	ReadPayload() ([]byte, error)
	WritePayload([]byte) error
	Close() error
}

// OpenTargetFunc 打开一条执行指定命令的 target channel；gateway 注入的闭包内部会解析在线 connectKey。
type OpenTargetFunc func(context.Context, string) (TargetChannel, error)

// FrameWriter 把已编码的响应帧写回用户 client 连接（由 daemonConnection.write 提供，内部串行化）。
type FrameWriter func([]byte) error

// FileBridge 处理 file 族：send（用户→设备，本服务为 slave 写临时文件再经主 HDC 上传）与
// recv（设备→用户，本服务为 master 经主 HDC 下载临时文件再回放）。仅支持未压缩单文件。
type FileBridge struct {
	ctx          context.Context
	codec        *protocol.Codec
	tempStore    *TempStore
	maxFileBytes int64
	timeout      time.Duration
	openTarget   OpenTargetFunc
	write        FrameWriter

	mu        sync.Mutex
	uploads   map[uint32]*fileUpload
	downloads map[uint32]*fileDownload
	closed    bool
	closeWg   sync.WaitGroup
}

// NewFileBridge 构造 file 族桥接；openTarget 打开主 HDC target channel，write 回写用户连接，
// 受单文件大小与临时空间总量双重配额约束。
func NewFileBridge(
	ctx context.Context,
	codec *protocol.Codec,
	tempStore *TempStore,
	maxFileBytes int64,
	timeout time.Duration,
	openTarget OpenTargetFunc,
	write FrameWriter,
) *FileBridge {
	return &FileBridge{
		ctx: ctx, codec: codec, tempStore: tempStore, maxFileBytes: maxFileBytes,
		timeout: timeout, openTarget: openTarget, write: write,
		uploads:   make(map[uint32]*fileUpload),
		downloads: make(map[uint32]*fileDownload),
	}
}

// Handle 分派 file 族帧：send 的 CHECK/DATA/FINISH 与 recv 的 INIT/BEGIN/FINISH，其余不支持项 fail-closed。
func (b *FileBridge) Handle(frame protocol.Frame) error {
	switch frame.CommandFlag {
	case protocol.CommandFileCheck:
		return b.handleCheck(frame)
	case protocol.CommandFileData:
		return b.handleData(frame)
	case protocol.CommandFileFinish:
		// recv：本服务为 master，收到用户(slave) 的 FINISH(1)；send：收到用户 FINISH(0)。
		if download := b.getDownload(frame.ChannelID); download != nil {
			return b.handleRecvFinish(frame, download)
		}
		return b.handleFinish(frame)
	case protocol.CommandFileInit:
		return b.handleRecvInit(frame)
	case protocol.CommandFileBegin:
		// 仅 recv 场景本服务(master) 会收到用户(slave) 的 BEGIN；send 场景由本服务发出 BEGIN。
		return b.handleRecvBegin(frame)
	case protocol.CommandLegacyFileRecvInit:
		return b.reject(frame.ChannelID, failFileDownload)
	case protocol.CommandFileMode, protocol.CommandDirMode:
		return b.rejectAndClose(frame.ChannelID, failUnsupportedFileOption)
	default:
		return b.rejectAndClose(frame.ChannelID, "[Fail] Command is not supported.")
	}
}

// CloseChannel 关闭指定 channel 上的上传/下载会话（收到 ChannelClose 时调用）。
func (b *FileBridge) CloseChannel(channelID uint32) {
	if upload := b.removeUpload(channelID, nil); upload != nil {
		upload.close()
	}
	if download := b.removeDownload(channelID, nil); download != nil {
		download.close()
	}
}

// Close 关闭文件桥：终止所有进行中的上传/下载，释放临时文件并等待其 goroutine 退出。
func (b *FileBridge) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	uploads := make([]*fileUpload, 0, len(b.uploads))
	for channelID, upload := range b.uploads {
		uploads = append(uploads, upload)
		delete(b.uploads, channelID)
	}
	downloads := make([]*fileDownload, 0, len(b.downloads))
	for channelID, download := range b.downloads {
		downloads = append(downloads, download)
		delete(b.downloads, channelID)
	}
	b.mu.Unlock()
	for _, upload := range uploads {
		upload.close()
	}
	for _, download := range downloads {
		download.close()
	}
	b.closeWg.Wait()
}

func (b *FileBridge) handleCheck(frame protocol.Frame) error {
	config, err := protocol.DecodeTransferConfig(frame.Payload)
	if err != nil {
		return b.rejectAndClose(frame.ChannelID, failInvalidFileRequest)
	}
	fileSize, message := b.validateConfig(config)
	if message != "" {
		return b.rejectAndClose(frame.ChannelID, message)
	}
	allocation, err := b.tempStore.allocate(fileSize)
	if err != nil {
		return b.rejectAndClose(frame.ChannelID, failFileTransfer)
	}
	upload := &fileUpload{
		channelID:    frame.ChannelID,
		targetPath:   config.Path,
		optionalName: strings.TrimSpace(config.OptionalName),
		expectedSize: fileSize,
		allocation:   allocation,
	}
	b.mu.Lock()
	if b.closed || b.uploads[frame.ChannelID] != nil {
		b.mu.Unlock()
		upload.close()
		return b.rejectAndClose(frame.ChannelID, failInvalidFileRequest)
	}
	b.uploads[frame.ChannelID] = upload
	b.mu.Unlock()

	if err := b.write(b.codec.EncodeFrame(frame.ChannelID, protocol.CommandFileBegin, nil)); err != nil {
		if removed := b.removeUpload(frame.ChannelID, upload); removed != nil {
			removed.close()
		}
		return err
	}
	return nil
}

func (b *FileBridge) handleData(frame protocol.Frame) error {
	upload := b.getUpload(frame.ChannelID)
	if upload == nil {
		return b.rejectAndClose(frame.ChannelID, failInvalidFileRequest)
	}
	header, data, err := protocol.DecodeTransferData(frame.Payload, uint32(min(b.maxFileBytes, int64(^uint32(0)))))
	if err != nil {
		return b.failUpload(frame.ChannelID, upload, failInvalidFileRequest)
	}
	if header.Compression != protocol.CompressionNone {
		return b.failUpload(frame.ChannelID, upload, failUnsupportedCompress)
	}
	if header.CompressedSize != header.UncompressedSize {
		return b.failUpload(frame.ChannelID, upload, failInvalidFileRequest)
	}
	complete, err := upload.writeChunk(header.Index, data)
	if err != nil {
		return b.failUpload(frame.ChannelID, upload, failInvalidFileRequest)
	}
	if complete {
		return b.write(b.codec.EncodeFrame(frame.ChannelID, protocol.CommandFileFinish, []byte{fileFinishCurrentFile}))
	}
	return nil
}

func (b *FileBridge) handleFinish(frame protocol.Frame) error {
	upload := b.getUpload(frame.ChannelID)
	if upload == nil || len(frame.Payload) != 1 || frame.Payload[0] != fileFinishAll {
		return b.failUpload(frame.ChannelID, upload, failInvalidFileRequest)
	}
	if err := upload.prepareTargetTransfer(); err != nil {
		return b.failUpload(frame.ChannelID, upload, failInvalidFileRequest)
	}
	b.closeWg.Add(1)
	go func() {
		defer b.closeWg.Done()
		b.runTargetUpload(upload)
	}()
	return nil
}

func (b *FileBridge) runTargetUpload(upload *fileUpload) {
	ctx, cancel := context.WithTimeout(b.ctx, b.timeout)
	defer cancel()

	if b.openTarget == nil {
		b.finishUpload(upload, failFileTransfer, false)
		return
	}
	target, err := b.openTarget(ctx, buildFileSendCommand(upload.allocation.currentPath(), upload.targetPath))
	if err != nil {
		b.finishUpload(upload, failFileTransfer, false)
		return
	}
	if !upload.attachTarget(target) {
		_ = target.Close()
		return
	}
	defer closeOnContext(ctx, upload.close)()

	outputSeen := false
	for {
		payload, readErr := target.ReadPayload()
		if len(payload) > 0 {
			outputSeen = true
			if err := b.write(b.codec.EncodeEchoRaw(upload.channelID, payload)); err != nil {
				b.finishUpload(upload, "", false)
				return
			}
		}
		if readErr != nil {
			switch {
			case errors.Is(ctx.Err(), context.DeadlineExceeded):
				b.finishUpload(upload, failFileTransferTimeout, false)
			case errors.Is(readErr, io.EOF), errors.Is(readErr, net.ErrClosed):
				b.finishUpload(upload, failFileNoResult, outputSeen)
			default:
				b.finishUpload(upload, failFileTransfer, false)
			}
			return
		}
	}
}

func (b *FileBridge) finishUpload(upload *fileUpload, message string, success bool) {
	if removed := b.removeUpload(upload.channelID, upload); removed == nil {
		return
	}
	upload.close()
	if !success && message != "" {
		_ = b.write(b.codec.EncodeEchoRaw(upload.channelID, []byte(message+"\n")))
	}
	_ = b.write(b.codec.EncodeChannelClose(upload.channelID))
}

// handleRecvInit 处理 file recv 发起帧（CMD_FILE_INIT）。本服务扮演 file master：
// 先经主 HDC 把设备文件下载到临时文件，再作为 sender 回放给用户 client。
func (b *FileBridge) handleRecvInit(frame protocol.Frame) error {
	devicePath, optionalName, userPath, message := parseRecvCommand(frame.Payload)
	if message != "" {
		return b.reject(frame.ChannelID, message)
	}
	allocation, err := b.tempStore.prepareDownload(b.maxFileBytes)
	if err != nil {
		return b.reject(frame.ChannelID, failFileTransfer)
	}
	download := &fileDownload{
		channelID: frame.ChannelID, devicePath: devicePath,
		optionalName: optionalName, userPath: userPath, allocation: allocation,
	}
	b.mu.Lock()
	if b.closed || b.downloads[frame.ChannelID] != nil || b.uploads[frame.ChannelID] != nil {
		b.mu.Unlock()
		allocation.close()
		return b.reject(frame.ChannelID, failInvalidFileRequest)
	}
	b.downloads[frame.ChannelID] = download
	b.closeWg.Add(1)
	b.mu.Unlock()

	go func() {
		defer b.closeWg.Done()
		b.runTargetDownload(download)
	}()
	return nil
}

// runTargetDownload 经主 HDC `file recv` 把设备文件下载到临时文件，成功后向用户发送 CMD_FILE_CHECK。
func (b *FileBridge) runTargetDownload(download *fileDownload) {
	ctx, cancel := context.WithTimeout(b.ctx, b.timeout)
	defer cancel()
	if b.openTarget == nil {
		b.failDownload(download, failFileTransfer)
		return
	}
	temporaryPath := download.allocation.currentPath()
	target, err := b.openTarget(ctx, buildFileRecvCommand(download.devicePath, temporaryPath))
	if err != nil {
		b.failDownload(download, failFileTransfer)
		return
	}
	if !download.attachTarget(target) {
		_ = target.Close()
		return
	}
	defer closeOnContext(ctx, download.close)()
	// 主 HDC 直接把设备文件写到临时路径，写入量不受本进程控制；
	// 只在写完后查大小的话，一个超大设备文件会先把本机磁盘写满再被拒绝。
	stopSizeGuard := watchTempFileSize(ctx, temporaryPath, b.maxFileBytes, download.close)
	defer stopSizeGuard()

	var output strings.Builder
	for {
		payload, readErr := target.ReadPayload()
		if len(payload) > 0 && output.Len() < fileOutputLimit {
			output.Write(payload)
		}
		if readErr != nil {
			break
		}
	}
	_ = target.Close()
	stopSizeGuard()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		b.failDownload(download, failFileTransferTimeout)
		return
	}
	if strings.Contains(strings.ToLower(output.String()), "[fail]") {
		b.failDownload(download, failFileTransfer)
		return
	}
	info, statErr := os.Stat(temporaryPath)
	if statErr != nil {
		b.failDownload(download, failFileNoResult)
		return
	}
	size := info.Size()
	if size > b.maxFileBytes {
		b.failDownload(download, failFileTransfer)
		return
	}
	download.setSize(size)

	config := protocol.TransferConfig{
		FileSize: uint64(size), Path: download.userPath,
		OptionalName: download.optionalName, Compression: protocol.CompressionNone,
	}
	if err := b.write(b.codec.EncodeFrame(download.channelID, protocol.CommandFileCheck, protocol.EncodeTransferConfig(config))); err != nil {
		b.failDownload(download, "")
	}
}

// handleRecvBegin 收到用户(slave) 的 CMD_FILE_BEGIN 后，开始分片回放临时文件。
//
// 回放放到独立 goroutine 执行：单个文件最大可达 MAX_FILE_BYTES，若在连接的读协程上同步跑完，
// 这条连接在整个传输期间都无法再处理任何帧——ChannelClose、keepalive、其它 channel 的命令全部阻塞，
// 用户连取消传输都做不到。其余 bridge 的数据通路同样是独立 goroutine。
func (b *FileBridge) handleRecvBegin(frame protocol.Frame) error {
	download := b.getDownload(frame.ChannelID)
	if download == nil {
		return b.reject(frame.ChannelID, failInvalidFileRequest)
	}
	if !download.beginSending() {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closeWg.Add(1)
	b.mu.Unlock()
	go func() {
		defer b.closeWg.Done()
		b.sendDownloadData(download)
	}()
	return nil
}

func (b *FileBridge) sendDownloadData(download *fileDownload) {
	file, err := os.Open(download.allocation.currentPath())
	if err != nil {
		b.failDownload(download, failFileTransfer)
		return
	}
	defer file.Close()

	const chunkSize = 60 * 1024 // 保守分片值，低于旧版 HDC_BUF_MAX_BYTES(61440)，对新版 INT_MAX 上限亦安全
	buffer := make([]byte, chunkSize)
	var index uint64
	for {
		// 客户端关闭 channel 或连接拆除时立刻停手，不必把剩余文件写完。
		if download.isClosed() {
			return
		}
		count, readErr := file.Read(buffer)
		if count > 0 {
			header := protocol.TransferPayload{
				Index: index, Compression: protocol.CompressionNone,
				CompressedSize: uint32(count), UncompressedSize: uint32(count),
			}
			dataPayload, encErr := protocol.EncodeTransferData(header, buffer[:count])
			if encErr != nil {
				b.failDownload(download, failFileTransfer)
				return
			}
			if err := b.write(b.codec.EncodeFrame(download.channelID, protocol.CommandFileData, dataPayload)); err != nil {
				b.failDownload(download, "")
				return
			}
			index += uint64(count)
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			b.failDownload(download, failFileTransfer)
			return
		}
	}
	// 数据发送完毕；等待用户(slave) 写满后回 CMD_FILE_FINISH(1)。
}

// handleRecvFinish 收到用户(slave) 的 FINISH(1)，回 FINISH(0) 并结束会话（master 侧握手）。
func (b *FileBridge) handleRecvFinish(frame protocol.Frame, download *fileDownload) error {
	if len(frame.Payload) == 1 && frame.Payload[0] == fileFinishCurrentFile {
		_ = b.write(b.codec.EncodeFrame(download.channelID, protocol.CommandFileFinish, []byte{fileFinishAll}))
	}
	b.endDownload(download, "")
	return nil
}

func (b *FileBridge) failDownload(download *fileDownload, message string) {
	b.endDownload(download, message)
}

func (b *FileBridge) endDownload(download *fileDownload, message string) {
	if removed := b.removeDownload(download.channelID, download); removed == nil {
		return
	}
	download.close()
	if message != "" {
		_ = b.write(b.codec.EncodeEchoRaw(download.channelID, []byte(message+"\n")))
	}
	_ = b.write(b.codec.EncodeChannelClose(download.channelID))
}

func (b *FileBridge) getDownload(channelID uint32) *fileDownload {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.downloads[channelID]
}

func (b *FileBridge) removeDownload(channelID uint32, expected *fileDownload) *fileDownload {
	b.mu.Lock()
	defer b.mu.Unlock()
	download := b.downloads[channelID]
	if download == nil || expected != nil && download != expected {
		return nil
	}
	delete(b.downloads, channelID)
	return download
}

func (b *FileBridge) validateConfig(config protocol.TransferConfig) (int64, string) {
	if config.FileSize > uint64(^uint64(0)>>1) || strings.TrimSpace(config.Path) == "" || hasUnsafeText(config.Path) {
		return 0, failInvalidFileRequest
	}
	if int64(config.FileSize) > b.maxFileBytes {
		return 0, failFileTransfer
	}
	if config.Compression != protocol.CompressionNone {
		return 0, failUnsupportedCompress
	}
	if config.UpdateIfNew || config.HoldTimestamp || strings.TrimSpace(config.Options) != "" ||
		strings.TrimSpace(config.FunctionName) != "" || strings.TrimSpace(config.Reserve1) != "" ||
		strings.TrimSpace(config.Reserve2) != "" {
		return 0, failUnsupportedFileOption
	}
	if strings.ContainsAny(config.OptionalName, `/\\`) {
		return 0, failUnsupportedDirectory
	}
	return int64(config.FileSize), ""
}

func (b *FileBridge) reject(channelID uint32, message string) error {
	return b.write(b.codec.EncodeEchoAndClose(channelID, message))
}

func (b *FileBridge) rejectAndClose(channelID uint32, message string) error {
	if upload := b.removeUpload(channelID, nil); upload != nil {
		upload.close()
	}
	return b.reject(channelID, message)
}

func (b *FileBridge) failUpload(channelID uint32, upload *fileUpload, message string) error {
	if upload != nil {
		if removed := b.removeUpload(channelID, upload); removed != nil {
			removed.close()
		}
	}
	return b.reject(channelID, message)
}

func (b *FileBridge) getUpload(channelID uint32) *fileUpload {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.uploads[channelID]
}

func (b *FileBridge) removeUpload(channelID uint32, expected *fileUpload) *fileUpload {
	b.mu.Lock()
	defer b.mu.Unlock()
	upload := b.uploads[channelID]
	if upload == nil || expected != nil && upload != expected {
		return nil
	}
	delete(b.uploads, channelID)
	return upload
}

type fileUpload struct {
	channelID    uint32
	targetPath   string
	optionalName string
	expectedSize int64
	allocation   *tempAllocation

	mu              sync.Mutex
	receivedSize    int64
	transferStarted bool
	target          TargetChannel
	closed          bool
	closeOnce       sync.Once
}

func (u *fileUpload) writeChunk(index uint64, data []byte) (bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || u.transferStarted || index != uint64(u.receivedSize) {
		return false, fmt.Errorf("invalid file transfer offset")
	}
	if int64(len(data)) > u.expectedSize-u.receivedSize {
		return false, fmt.Errorf("file transfer exceeds declared size")
	}
	written, err := u.allocation.write(data)
	if err != nil {
		return false, err
	}
	if written != len(data) {
		return false, io.ErrShortWrite
	}
	u.receivedSize += int64(written)
	return u.receivedSize == u.expectedSize, nil
}

func (u *fileUpload) prepareTargetTransfer() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || u.transferStarted || u.receivedSize != u.expectedSize {
		return fmt.Errorf("file transfer is incomplete")
	}
	if err := u.allocation.seal(); err != nil {
		return err
	}
	// 目标路径是目录时，设备侧按源文件名落盘；临时文件默认名是 "payload"，
	// 不改回客户端声明的文件名就会在设备上写出一个名为 payload 的文件。
	if u.optionalName != "" {
		if err := u.allocation.renameToName(u.optionalName); err != nil {
			return err
		}
	}
	u.transferStarted = true
	return nil
}

func (u *fileUpload) attachTarget(target TargetChannel) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return false
	}
	u.target = target
	return true
}

func (u *fileUpload) close() {
	u.closeOnce.Do(func() {
		u.mu.Lock()
		u.closed = true
		target := u.target
		u.target = nil
		u.mu.Unlock()
		if target != nil {
			_ = target.Close()
		}
		u.allocation.close()
	})
}

// fileDownload 表示一次 recv 会话：本服务作为 file master/sender，把主 HDC 下载到临时文件的内容回放给用户。
type fileDownload struct {
	channelID    uint32
	devicePath   string
	optionalName string
	userPath     string
	allocation   *tempAllocation

	mu        sync.Mutex
	fileSize  int64
	target    TargetChannel
	sending   bool
	closed    bool
	closeOnce sync.Once
}

func (d *fileDownload) attachTarget(target TargetChannel) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	d.target = target
	return true
}

func (d *fileDownload) setSize(size int64) {
	d.mu.Lock()
	d.fileSize = size
	d.mu.Unlock()
	// 把 prepareDownload 时按上限预占的配额调整为实际占用。
	d.allocation.settle(size)
}

// isClosed 供回放循环在分片之间检查会话是否已被拆除，避免关闭后仍继续写剩余文件。
func (d *fileDownload) isClosed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.closed
}

func (d *fileDownload) beginSending() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.sending {
		return false
	}
	d.sending = true
	return true
}

func (d *fileDownload) close() {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		target := d.target
		d.target = nil
		d.mu.Unlock()
		if target != nil {
			_ = target.Close()
		}
		d.allocation.close()
	})
}

// parseRecvCommand 解析 recv 发起负载。
// 负载已剥离 "recv " 关键字，且客户端会追加 `remote -cwd "<cwd>"` 等选项（选项在前、路径在后），
// 形如 `-cwd "<cwd>" <设备路径> <用户本地路径>`，故路径恒为最后两个 token。本服务为 master，读取设备路径。
func parseRecvCommand(payload []byte) (devicePath, optionalName, userPath, message string) {
	text := string(payload)
	if hasUnsafeText(text) {
		return "", "", "", failInvalidFileRequest
	}
	tokens := splitCommandTokens(text)
	if len(tokens) < 2 {
		return "", "", "", failInvalidFileRequest
	}
	devicePath = tokens[len(tokens)-2]
	userPath = tokens[len(tokens)-1]
	if devicePath == "" || userPath == "" || strings.HasPrefix(devicePath, "-") || strings.HasPrefix(userPath, "-") {
		return "", "", "", failInvalidFileRequest
	}
	optionalName = baseName(devicePath)
	if optionalName == "" || strings.ContainsAny(optionalName, `/\`) {
		return "", "", "", failInvalidFileRequest
	}
	return devicePath, optionalName, userPath, ""
}

// splitCommandTokens 按空白分词，双引号分组（引号内空白保留、引号本身剔除，不做转义）。
// 用于从 recv 命令串中提取路径，兼容 Windows 带反斜杠的引号路径（如 -cwd "D:\work\"）。
func splitCommandTokens(text string) []string {
	var tokens []string
	var current strings.Builder
	inQuote := false
	flush := func() {
		if current.Len() > 0 {
			tokens = append(tokens, current.String())
			current.Reset()
		}
	}
	for _, r := range text {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return tokens
}

func baseName(path string) string {
	trimmed := strings.TrimRight(path, `/\`)
	if index := strings.LastIndexAny(trimmed, `/\`); index >= 0 {
		return trimmed[index+1:]
	}
	return trimmed
}

func buildFileRecvCommand(devicePath, localPath string) string {
	return "file recv " + quoteCommandArg(devicePath) + " " + quoteCommandArg(localPath)
}

func buildFileSendCommand(localPath, targetPath string) string {
	return "file send " + quoteCommandArg(localPath) + " " + quoteCommandArg(targetPath)
}
