package gateway

import (
	"time"

	"github.com/yabi-zzh/hdc-remote-kit/internal/hostauth"
	"github.com/yabi-zzh/hdc-remote-kit/internal/model"
	"github.com/yabi-zzh/hdc-remote-kit/internal/protocol"
)

type authPhase uint8

const (
	authPhaseStart authPhase = iota
	authPhaseWaitPubkey
	authPhaseWaitSignature
	authPhaseDone
)

const unauthorizedNotice = "[E000002]:The device unauthorized.\r\n" +
	"This server's public key is not set.\r\n" +
	"Please check for a confirmation dialog on your device.\r\n" +
	"Otherwise try 'hdc kill' if that seems wrong."

const unauthorizedDenied = "[E000003]:The device unauthorized.\r\n" +
	"The user denied the access for the device.\r\n" +
	"Please execute 'hdc kill' and redo your command,\r\n" +
	"then check for a confirmation dialog on your device."

// handleHandshake 走官方多轮公钥握手：NONE → PUBLICKEY → SIGNATURE → OK。
// handshakeAccepted 只在验签成功后置位；confirm 模式下待确认期间远程为 Unauthorized。
func (c *daemonConnection) handleHandshake(frame protocol.Frame) error {
	handshake, err := c.codec.DecodeSessionHandshake(frame.Payload)
	if err != nil || handshake.Banner != "OHOS HDC" {
		c.audit(frame, model.AuditRejected, "invalid handshake")
		c.authRejectReason = "invalid handshake"
		return &daemonProtocolViolation{message: "Invalid HDC daemon handshake."}
	}
	switch handshake.AuthType {
	case protocol.HandshakeAuthNone:
		return c.handleAuthNone(frame, handshake)
	case protocol.HandshakeAuthPublicKey:
		return c.handleAuthPublicKey(frame, handshake)
	case protocol.HandshakeAuthSignature:
		return c.handleAuthSignature(frame, handshake)
	default:
		c.audit(frame, model.AuditRejected, "invalid handshake")
		c.authRejectReason = "invalid handshake"
		return &daemonProtocolViolation{message: "Invalid HDC daemon handshake."}
	}
}

func (c *daemonConnection) handleAuthNone(frame protocol.Frame, handshake protocol.SessionHandshake) error {
	if c.authPhase != authPhaseStart {
		c.audit(frame, model.AuditRejected, "handshake already started")
		c.authRejectReason = "handshake already started"
		return &daemonProtocolViolation{message: "HDC daemon handshake is already in progress."}
	}
	if protocol.ClientVersionTooOld(handshake.Version) {
		c.audit(frame, model.AuditRejected, "client version too old")
		c.authRejectReason = "client version too old"
		c.setCloseReason("version_too_old")
		c.rejectOldClient(handshake.Version)
		if err := c.write(c.codec.EncodeHandshakeUnauthorized(frame.ChannelID, handshake.Version, c.deviceName(),
			"[E000001]:The sdk hdc.exe version is too low, please upgrade to the latest version.")); err != nil {
			return err
		}
		return errHostAuthRejected
	}
	if c.hosts == nil {
		c.audit(frame, model.AuditRejected, "host auth unavailable")
		c.authRejectReason = "host auth unavailable"
		return &daemonProtocolViolation{message: "HDC host authentication is unavailable."}
	}
	token, err := hostauth.NewChallengeToken()
	if err != nil {
		return err
	}
	c.authType = hostauth.ParseClientAuthType(handshake.Buffer)
	c.authToken = token
	c.handshakeVersion = handshake.Version
	c.authPhase = authPhaseWaitPubkey
	c.audit(frame, model.AuditAllowed, "")
	return c.write(c.codec.EncodeHandshakePublicKey(frame.ChannelID, handshake.Version, c.authType == hostauth.AuthRSA3072SHA512))
}

func (c *daemonConnection) handleAuthPublicKey(frame protocol.Frame, handshake protocol.SessionHandshake) error {
	if c.authPhase != authPhaseWaitPubkey {
		c.audit(frame, model.AuditRejected, "unexpected public key")
		c.authRejectReason = "unexpected public key"
		return &daemonProtocolViolation{message: "Invalid HDC daemon handshake."}
	}
	identity, err := hostauth.ParseHostIdentity(handshake.Buffer)
	if err != nil {
		c.audit(frame, model.AuditRejected, "invalid host public key")
		c.authRejectReason = "invalid host public key"
		return &daemonProtocolViolation{message: "Invalid HDC host public key."}
	}
	c.authIdentity = identity
	if c.hostAuthOff || c.hosts.Trusted(identity.Fingerprint) {
		reason := "known host"
		if c.hostAuthOff && !c.hosts.Trusted(identity.Fingerprint) {
			reason = "host auth off"
		}
		c.audit(frame, model.AuditAllowed, reason)
		return c.sendSignatureChallenge(frame.ChannelID)
	}
	// 官方 hdc 收到公钥后必须立刻拿到 AUTH_OK，否则 tconn 马上 Connect failed。
	// AUTH_OK + DAEMON_UNAUTH：对端打印 Connect OK，list targets 为 Unauthorized，会话继续等本机放行。
	// 待确认期间清掉握手读超时；此连接仍占用 MaxConnections。
	if err := c.write(c.codec.EncodeHandshakeUnauthorized(frame.ChannelID, c.handshakeVersion, c.deviceName(), unauthorizedNotice)); err != nil {
		return err
	}
	_ = c.conn.SetReadDeadline(time.Time{})
	decision, err := c.hosts.Submit(c.ctx, hostauth.PendingRequest{
		DeviceID:    c.binding.DeviceID,
		Serial:      model.DeviceSerial(c.binding.DeviceID),
		Hostname:    identity.Hostname,
		Fingerprint: identity.Fingerprint,
		SourceIP:    c.sourceIP,
		LeaseID:     c.leaseID,
	})
	if c.handshakeTimeout > 0 {
		_ = c.conn.SetReadDeadline(time.Now().Add(c.handshakeTimeout))
	}
	if err != nil {
		c.audit(frame, model.AuditRejected, "auth submit failed")
		c.authRejectReason = "auth submit failed"
		return err
	}
	if decision != hostauth.DecisionAllowOnce && decision != hostauth.DecisionAllowForever {
		c.audit(frame, model.AuditRejected, string(decision))
		c.authRejectReason = string(decision)
		if decision == hostauth.DecisionExpired {
			c.setCloseReason("timeout")
		} else {
			c.setCloseReason("deny")
		}
		notice := unauthorizedDenied
		if decision == hostauth.DecisionExpired {
			notice = unauthorizedNotice
		}
		if err := c.write(c.codec.EncodeHandshakeUnauthorized(frame.ChannelID, c.handshakeVersion, c.deviceName(), notice)); err != nil {
			return err
		}
		return errHostAuthRejected
	}
	c.audit(frame, model.AuditAllowed, string(decision))
	return c.sendSignatureChallenge(frame.ChannelID)
}

func (c *daemonConnection) sendSignatureChallenge(channelID uint32) error {
	c.authPhase = authPhaseWaitSignature
	return c.write(c.codec.EncodeHandshakeSignatureChallenge(channelID, c.handshakeVersion, c.authToken))
}

func (c *daemonConnection) handleAuthSignature(frame protocol.Frame, handshake protocol.SessionHandshake) error {
	if c.authPhase != authPhaseWaitSignature || c.authToken == "" || c.authIdentity.PublicKey == "" {
		c.audit(frame, model.AuditRejected, "unexpected signature")
		c.authRejectReason = "unexpected signature"
		return &daemonProtocolViolation{message: "Invalid HDC daemon handshake."}
	}
	if err := hostauth.VerifyChallenge(c.authIdentity.PublicKey, c.authToken, handshake.Buffer, c.authType); err != nil {
		c.audit(frame, model.AuditRejected, "signature failed")
		c.authRejectReason = "signature failed"
		c.setCloseReason("deny")
		return c.write(c.codec.EncodeEchoAndClose(frame.ChannelID, "[E000010]:Auth failed, cannt login the device."))
	}
	c.authPhase = authPhaseDone
	c.handshakeAccepted = true
	c.audit(frame, model.AuditAllowed, "auth ok")
	if c.logger != nil {
		c.logger.Info("HDC daemon handshake accepted",
			"serial", model.DeviceSerial(c.binding.DeviceID),
			"host", c.authIdentity.Hostname,
			"fingerprint", hostauth.ShortFingerprint(c.authIdentity.Fingerprint),
			"remote", c.sourceIP)
	}
	if c.onAuthed != nil {
		c.onAuthed()
	}
	response := c.codec.EncodeHandshakeOK(frame, handshake, c.deviceName())
	response = append(response, c.codec.EncodeChannelClose(frame.ChannelID)...)
	return c.write(response)
}

func (c *daemonConnection) rejectOldClient(version string) {
	if c.logger != nil {
		c.logger.Info("auth rejected",
			"reason", "client version too old",
			"serial", model.DeviceSerial(c.binding.DeviceID),
			"source", c.sourceIP,
			"version", version,
			"required", protocol.HandshakeMinAuthVersion)
	}
	if c.hosts == nil {
		return
	}
	c.hosts.Notify(hostauth.Notice{
		Kind:     hostauth.NoticeClientVersionTooOld,
		Serial:   model.DeviceSerial(c.binding.DeviceID),
		SourceIP: c.sourceIP,
		Version:  version,
		Required: protocol.HandshakeMinAuthVersion,
		Message:  "本机不能放行。通知对端升级到 " + protocol.HandshakeMinAuthVersion + " 及以上后重连。",
	})
}

func (c *daemonConnection) deviceName() string {
	if serial := model.DeviceSerial(c.binding.DeviceID); serial != "" {
		return serial
	}
	if c.binding.DeviceID != "" {
		return c.binding.DeviceID
	}
	return "hdc-remote"
}
