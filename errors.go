package mailiosmtphelpers

import "errors"

var (
	ErrInvalidMessageID             = errors.New("invalid message id")
	ErrInvalidMessage               = errors.New("invalid message")
	ErrInvalidAttachment            = errors.New("invalid attachment")
	ErrInvalidAttachmentContent     = errors.New("invalid attachment content")
	ErrInvalidAttachmentContentType = errors.New("invalid attachment content type")
	ErrInvalidAttachmentFilename    = errors.New("invalid attachment filename")
	ErrInvalidAttachmentSize        = errors.New("invalid attachment size")
	ErrInvalidAttachmentType        = errors.New("invalid attachment type")
	ErrInvalidHostname              = errors.New("invalid hostname")
	ErrInvalidRFC2822MessageID      = errors.New("invalid rfc2822 message id")
	ErrInvalidRecipientHeaders      = errors.New("invalid recipient headers")
	ErrInvalidFromHeader            = errors.New("invalid from header")
	ErrInvalidReplyToHeader         = errors.New("invalid reply to header")
	ErrFailedParsingMime            = errors.New("failed parsing mime")
)
