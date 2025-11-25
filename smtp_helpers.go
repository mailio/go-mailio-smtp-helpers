package mailiosmtphelpers

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jhillyerd/enmime/v2"
	abi "github.com/mailio/go-mailio-smtp-abi"
	"github.com/microcosm-cc/bluemonday"
	"golang.org/x/net/html/charset"
)

var headerDecoder = &mime.WordDecoder{
	CharsetReader: charset.NewReaderLabel,
}

// DecodeRFC2047Header decodes an RFC 2047 encoded header (e.g. "=?iso-2022-jp?...?=")
// into UTF-8. If it fails or is not encoded, it returns the original string.
func decodeHeader(h string) string {
	if h == "" {
		return h
	}
	decoded, err := headerDecoder.DecodeHeader(h)
	if err != nil {
		return h
	}
	return decoded
}

// parseAddressListHeader takes a slice of header values (e.g. headers["To"])
// decodes each with RFC 2047, joins them, and parses into []*mail.Address.
func parseAddressListHeader(values []string) ([]*mail.Address, error) {
	if len(values) == 0 {
		return nil, nil
	}
	var result []*mail.Address

	for _, raw := range values {
		decoded := decodeHeader(raw) // your RFC2047 + charset-aware decoder
		// 1) Try normal, standards-compliant parse first
		if addrs, err := mail.ParseAddressList(decoded); err == nil {
			result = append(result, addrs...)
			continue
		}
		// 2) Fallback: split on comma and try each part
		parts := strings.Split(decoded, ",")
		for _, part := range parts {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			// 2a) Try parsing as a single address
			if addr, err := mail.ParseAddress(p); err == nil {
				result = append(result, addr)
				continue
			}
			// 2b) Handle broken patterns like "test@mail.io <test@mail.io>"
			if lt := strings.Index(p, "<"); lt != -1 {
				if gt := strings.Index(p[lt:], ">"); gt != -1 {
					addrStr := strings.TrimSpace(p[lt+1 : lt+gt])
					if addrStr != "" {
						result = append(result, &mail.Address{Address: addrStr})
						continue
					}
				}
			}
			// 2c) Last-resort: if it looks like an email, accept it as bare address
			if strings.Contains(p, "@") {
				result = append(result, &mail.Address{Address: p})
			}
		}
	}
	return result, nil
}

// parseSingleAddressHeader parses a single address header (like "From" or "Reply-To")
// which may contain RFC 2047 encoded display names.
func parseSingleAddressHeader(value string) (*mail.Address, error) {
	if value == "" {
		return nil, nil
	}
	decoded := decodeHeader(value)
	addr, err := mail.ParseAddress(decoded)
	if err != nil {
		return nil, ErrInvalidFromHeader
	}
	return addr, nil
}

func normalizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}

	// Attempt to detect charset from byte patterns
	b := []byte(s)

	enc, _, _ := charset.DetermineEncoding(b, "")
	decoded, _ := enc.NewDecoder().Bytes(b)

	return string(decoded)
}

func HtmlToText(html string) string {
	p := bluemonday.NewPolicy()
	p.AllowStandardURLs()

	// Remove all tags to leave only text
	clean := p.Sanitize(html)
	clean = strings.ReplaceAll(clean, "\n", "")
	clean = strings.ReplaceAll(clean, "\t", " ")
	clean = strings.ReplaceAll(clean, "  ", " ")
	clean = strings.TrimSpace(clean)
	words := strings.Fields(clean)
	clean = strings.Join(words, " ")
	return clean
}

// GenerateMessageID generates and returns a string suitable for an RFC 2822
// compliant Message-ID, e.g.:
// <1444789264909237300.3464.1819418242800517193@DESKTOP01>
//
// The following parameters are used to generate a Message-ID:
// - The nanoseconds since Epoch
// - The calling PID
// - A cryptographically random int64
// - The sending hostname
func GenerateRFC2822MessageID(hostname string) (string, error) {
	t := time.Now().UnixNano()
	pid := os.Getpid()
	rint, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return "", ErrInvalidMessageID
	}
	if hostname == "" {
		return "", ErrInvalidHostname
	}
	msgid := fmt.Sprintf("<%d.%d.%d@%s>", t, pid, rint, hostname)
	return msgid, nil
}

// converts a message to a mime message. Required rfc2822 compliant message id
func ToMime(msg *abi.Mail, rfc2822MessageID string) ([]byte, error) {

	if rfc2822MessageID == "" {
		return nil, ErrInvalidRFC2822MessageID
	}

	// simple message id validation
	if !strings.HasPrefix(rfc2822MessageID, "<") || !strings.HasSuffix(rfc2822MessageID, ">") || !strings.Contains(rfc2822MessageID, "@") {
		return nil, ErrInvalidRFC2822MessageID
	}

	// convert html to text (remove unwanted tags)
	text := msg.BodyText
	if msg.BodyText == "" {
		text = HtmlToText(msg.BodyHTML)
	}

	cleanHtml := msg.BodyHTML
	if msg.BodyHTML != "" {
		cleanHtml = cleanupUGCHtml(msg.BodyHTML)
	}

	// convert replyTo to no pointer
	var replyToNoPtr []mail.Address
	if len(msg.ReplyTo) > 0 {
		rtNoPtr := make([]mail.Address, 0)
		for _, address := range msg.ReplyTo {
			rtNoPtr = append(rtNoPtr, *address)
		}
		replyToNoPtr = rtNoPtr
	}

	// construct basic message
	outgoingMime := enmime.Builder().
		From(msg.From.Name, msg.From.Address).
		Subject(msg.Subject).
		ToAddrs(msg.To).
		ReplyToAddrs(replyToNoPtr).
		Text([]byte(text)).
		Date(time.UnixMilli(msg.Timestamp)).
		HTML([]byte(cleanHtml))

	// add sender address if present
	if msg.Cc != nil {
		var noPtrCc []mail.Address
		for _, address := range msg.Cc {
			noPtrCc = append(noPtrCc, *address)
		}
		outgoingMime = outgoingMime.CCAddrs(noPtrCc)
	}
	// Bcc recipients should not be included in the message headers
	// if msg.Bcc != nil {
	// 	var noPtrBcc []mail.Address
	// 	for _, address := range msg.Bcc {
	// 		noPtrBcc = append(noPtrBcc, *address)
	// 	}
	// 	outgoingMime = outgoingMime.BCCAddrs(noPtrBcc)
	// }

	// add headers
	outgoingMime = outgoingMime.Header("X-Mailer", "Mailio")
	outgoingMime = outgoingMime.Header("X-Mailio-Message-Id", msg.MessageId)

	// add attachments
	if msg.Attachments != nil {
		for _, attachment := range msg.Attachments {
			outgoingMime = outgoingMime.AddAttachment(attachment.Content, attachment.ContentType, attachment.Filename)
		}

	}

	outgoingMime = outgoingMime.Header("Message-Id", rfc2822MessageID)

	// build and encode the message
	ep, err := outgoingMime.Build()
	if err != nil {
		return nil, ErrInvalidMessage
	}
	var buf bytes.Buffer
	err = ep.Encode(&buf)
	if err != nil {
		return nil, ErrInvalidMessage
	}

	return buf.Bytes(), nil
}

/*
Recommeneded to handle the following bounce reasons:
Mailbox Does Not Exist — SMTP Reply Code = 550, SMTP Status Code = 5.1.1
Message Too Large — SMTP Reply Code = 552, SMTP Status Code = 5.3.4
Mailbox Full — SMTP Reply Code = 552, SMTP Status Code = 5.2.2
Message Content Rejected — SMTP Reply Code = 500, SMTP Status Code = 5.6.1
Unknown Failure — SMTP Reply Code = 554, SMTP Status Code = 5.0.0
Temporary Failure — SMTP Reply Code = 450, SMTP Status Code = 4.0.0

where 4.x.x codes are soft bounces, and 5.x..x codes are hard bounces
*/
func ToBounce(recipient mail.Address, msg abi.Mail, bounceCode string, bounceReason string, mailhost string) ([]byte, error) {
	// Create the bounce message builder
	host := "localhost"
	if mailhost != "" {
		host = mailhost
	}

	from := mail.Address{Name: "Mailer-Daemon", Address: fmt.Sprintf("MAILER-DAEMON@%s", host)}

	// buffer to hold the headers temporarily
	var headerBuf bytes.Buffer

	// buffer to hold MIME message
	var buf bytes.Buffer

	// Create a multipart writer for the buffer, set to multipart/mixed
	writer := multipart.NewWriter(&buf)
	defer writer.Close()

	// Create the top-level header of the message
	header := make(textproto.MIMEHeader)
	header.Set("From", from.String())
	header.Set("To", recipient.String())
	header.Set("Subject", "Delivery Status Notification (Failure)")
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	header.Set("MIME-Version", "1.0")
	header.Set("Message-ID", msg.MessageId)
	header.Set("Content-Type", fmt.Sprintf("multipart/report; report-type=delivery-status; boundary=\"%s\"", writer.Boundary()))

	// Write the top-level headers to the temporary buffer
	for k, v := range header {
		fmt.Fprintf(&headerBuf, "%s: %s\r\n", k, strings.Join(v, ","))
	}

	// First part: Human-readable explanation of the bounce
	textPartHeader := make(textproto.MIMEHeader)
	textPartHeader.Set("Content-Type", "text/plain; charset=\"utf-8\"")
	textPart, _ := writer.CreatePart(textPartHeader)
	fmt.Fprintln(textPart, fmt.Sprintf("The following message to %s was undeliverable.\n\n"+
		"The reason for the problem:\n"+
		"%s - %s\n", recipient.String(), bounceCode, bounceReason))

	// Second part: Machine-readable delivery status
	dsnPartHeader := make(textproto.MIMEHeader)
	dsnPartHeader.Set("Content-Type", "message/delivery-status")
	dsnPart, _ := writer.CreatePart(dsnPartHeader)
	fmt.Fprintln(dsnPart, fmt.Sprintf("Reporting-MTA: dns; %s"+
		"\nArrival-Date: "+time.Now().UTC().Format(time.RFC1123Z)+"\n\n"+
		"Final-Recipient: rfc822; %s"+
		"\nAction: failed"+
		"\nStatus:%s"+
		"\nRemote-MTA: dns; %s"+
		"\nDiagnostic-Code: smtp; %s - %s", host, recipient.String(), bounceCode, host, bounceCode, bounceReason))

	// add original message
	// Third part: Original message headers and body
	originalPartHeader := make(textproto.MIMEHeader)
	originalPartHeader.Set("Content-Type", "message/rfc822")
	originalPart, _ := writer.CreatePart(originalPartHeader)
	fmt.Fprintf(originalPart, "From: %s\nTo: %s\nSubject: %s\nDate: %s\n\n%s", msg.From.String(), recipient.String(), msg.Subject, time.Now().UTC().Format(time.RFC1123Z), "The original message was not included in this report.")

	// Close the multipart writer to finalize the boundary
	if err := writer.Close(); err != nil {
		return nil, ErrInvalidMessage
	}

	// Combine headers and body
	var finalBuf bytes.Buffer
	finalBuf.Write(headerBuf.Bytes())
	finalBuf.WriteString("\r\n") // Important: Separate headers from body with an empty line
	finalBuf.Write(buf.Bytes())

	return finalBuf.Bytes(), nil
}

// ToComplaint creates a complaint message
/*
Complaints are generated when a recipient reports an email as spam or junk.
The recipient's email provider sends a complaint to the custom ESP.
The complaint includes the original email that was reported as spam or junk.
The complaint also includes information about the recipient who reported the email as spam or junk.

https://en.wikipedia.org/wiki/Abuse_Reporting_Format
https://datatracker.ietf.org/doc/html/rfc5965
*/
func ToComplaint(recipient mail.Address, reporter mail.Address, msg abi.Mail, complaintReason string, mailhost string) ([]byte, error) {
	// Set host dynamically or use "localhost" as default
	host := "localhost"
	if mailhost != "" {
		host = mailhost
	}

	// Convert the original message to MIME
	originalMsgMime, err := ToMime(&msg, msg.MessageId)
	if err != nil {
		return nil, ErrInvalidMessage
	}

	// Buffers for headers and MIME message
	var headerBuf bytes.Buffer
	var buf bytes.Buffer

	// Create a multipart writer for the MIME message buffer
	writer := multipart.NewWriter(&buf)
	defer writer.Close()

	// Set the top-level headers for the message
	header := make(textproto.MIMEHeader)
	header.Set("From", reporter.String())
	header.Set("To", recipient.String())
	header.Set("Subject", "Complaint Notification")
	header.Set("Date", time.Now().Format(time.RFC1123Z))
	header.Set("MIME-Version", "1.0")
	header.Set("Content-Type", fmt.Sprintf("multipart/report; report-type=complaint-feedback-report; boundary=\"%s\"", writer.Boundary()))

	// Write the top-level headers to the temporary buffer
	for k, v := range header {
		fmt.Fprintf(&headerBuf, "%s: %s\r\n", k, strings.Join(v, ","))
	}

	allTos := ""
	for i, to := range msg.To {
		allTos += to.String()
		if i < len(msg.To)-1 {
			allTos += ", "
		}
	}
	for i, cc := range msg.Cc {
		allTos += cc.String()
		if i < len(msg.Cc)-1 {
			allTos += ", "
		}
	}
	for i, bcc := range msg.Bcc {
		allTos += bcc.String()
		if i < len(msg.Bcc)-1 {
			allTos += ", "
		}

	}
	// First part: Human-readable explanation of the complaint
	textPartHeader := make(textproto.MIMEHeader)
	textPartHeader.Set("Content-Type", "text/plain; charset=\"utf-8\"")
	textPart, _ := writer.CreatePart(textPartHeader)
	fmt.Fprintln(textPart, fmt.Sprintf("This message is to inform you that a complaint was received for an email sent to %s.\n\n"+
		"Reason for complaint:\n"+
		"%s\n", allTos, complaintReason))

	// Second part: Machine-readable complaint feedback report
	feedbackPartHeader := make(textproto.MIMEHeader)
	feedbackPartHeader.Set("Content-Type", "message/feedback-report")
	feedbackPart, _ := writer.CreatePart(feedbackPartHeader)
	originalRecipients := ""
	for _, to := range msg.To {
		originalRecipients += "Original-Rcpt-To: " + to.String() + "\n"
	}
	reportedDomain := strings.Split(msg.From.Address, "@")[1]
	machineReadyReport := fmt.Sprintf(
		"Feedback-Type: %s\n"+
			"User-Agent: %s\n"+
			"Version: 1\n"+
			"Original-Mail-From: %s\n"+
			"%s"+
			"Arrival-Date: %s\n"+
			"Reported-Domain: %s\n",
		complaintReason,
		host,
		msg.From.String(),
		originalRecipients,
		time.UnixMilli(msg.Timestamp).Format(time.RFC1123Z),
		reportedDomain)
	fmt.Fprintln(feedbackPart, machineReadyReport)

	// add original message
	originalPartHeader := make(textproto.MIMEHeader)
	originalPartHeader.Set("Content-Type", "message/rfc822")
	originalPart, _ := writer.CreatePart(originalPartHeader)
	fmt.Fprintf(originalPart, "%s", originalMsgMime)

	// Close the multipart writer to finalize the boundary
	if err := writer.Close(); err != nil {
		return nil, ErrInvalidMessage
	}

	// Combine headers and body
	var finalBuf bytes.Buffer
	finalBuf.Write(headerBuf.Bytes())
	finalBuf.WriteString("\r\n") // Separate headers from body with an empty line
	finalBuf.Write(buf.Bytes())

	return finalBuf.Bytes(), nil
}

// Parsing raw mime message into a Mailio structure
func ParseMime(mimeBytes []byte) (*abi.Mail, error) {
	msg, err := enmime.ReadEnvelope(bytes.NewReader(mimeBytes))
	if err != nil {
		return nil, ErrFailedParsingMime
	}

	email := &abi.Mail{}
	// raw mime is the original mime message
	email.RawMime = mimeBytes

	// get the headers
	headers := msg.Root.Header
	email.MessageId = msg.GetHeader("Message-ID")
	fromHeader := headers.Get("From")

	from, fromErr := parseSingleAddressHeader(fromHeader) // ignore parsing error
	if fromErr != nil {
		return nil, ErrInvalidFromHeader
	}
	if from != nil {
		email.From = *from
	}
	to, toErr := parseAddressListHeader([]string{headers.Get("To")}) // ignore parsing error
	if toErr != nil {
		return nil, ErrInvalidRecipientHeaders
	}
	// var rErr error
	var replyTo []*mail.Address
	if headers.Get("Reply-To") != "" {
		rt, rtErr := parseAddressListHeader([]string{headers.Get("Reply-To")}) // ignore parsing error
		if rtErr != nil {
			return nil, ErrInvalidReplyToHeader
		}
		if len(rt) > 0 {
			replyTo = rt
		}
	}

	if headers.Get("Cc") != "" {
		cc, ccErr := parseAddressListHeader([]string{headers.Get("Cc")}) // ignore parsing error
		if ccErr != nil {
			return nil, ErrInvalidRecipientHeaders
		}
		if len(cc) > 0 {
			email.Cc = cc
		}
	}
	if headers.Get("Bcc") != "" {
		bcc, bccErr := parseAddressListHeader([]string{headers.Get("Bcc")}) // ignore parsing error
		if bccErr != nil {
			return nil, ErrInvalidRecipientHeaders
		}
		if len(bcc) > 0 {
			email.Bcc = bcc
		}
	}

	if len(to) > 0 {
		email.To = make([]mail.Address, len(to))
		for i, addrPtr := range to {
			email.To[i] = *addrPtr // Dereference the pointer to get the value
		}
	}
	if len(replyTo) > 0 {
		email.ReplyTo = replyTo
	}

	email.Headers = make(map[string][]string, 0)
	for key, value := range headers {
		vals := []string{}
		for _, v := range value {
			v = strings.ReplaceAll(v, "\n", "")
			v = strings.Trim(v, " ")
			switch strings.ToLower(key) {
			case "subject", "from", "to", "cc", "bcc", "reply-to":
				v = decodeHeader(v)
			}
			vals = append(vals, v)
		}
		email.Headers[key] = vals
	}

	// get the body
	rawSubject := msg.GetHeader("Subject")
	email.Subject = decodeHeader(rawSubject)
	dt, dateErr := msg.Date()
	if dateErr != nil {
		email.Timestamp = time.Now().UTC().UnixMilli()
	} else {
		email.Timestamp = dt.UnixMilli()
	}

	// mime.Attachments contains the non-inline attachments. (standard email attachments)
	totalAttachmentsSize := int64(0)
	var attachments []*abi.SmtpAttachment
	if len(msg.Attachments) > 0 {
		for _, attachment := range msg.Attachments {
			totalAttachmentsSize += int64(len(attachment.Content))
			attachments = append(attachments, &abi.SmtpAttachment{
				ContentType: attachment.ContentType,
				Filename:    attachment.FileName,
				Content:     attachment.Content,
				ContentID:   attachment.ContentID,
			})
		}
	}
	if len(attachments) > 0 {
		email.Attachments = attachments
	}

	// body (plain, html, html cleaned)
	email.BodyHTML = cleanupUGCHtml(msg.HTML)
	email.BodyText = msg.Text

	email.BodyHTML = normalizeUTF8(email.BodyHTML)
	email.BodyText = normalizeUTF8(email.BodyText)

	// mime.Inlines is a slice of inlined attacments. These are typically images that are embedded in the HTML body
	totalInlineSize := int64(0)
	for _, inline := range msg.Inlines {
		totalInlineSize += int64(len(inline.Content))
		email.BodyInlinePart = append(email.BodyInlinePart, &abi.MailBodyRaw{
			ContentType:        inline.ContentType,
			Content:            inline.Content,
			ContentDisposition: inline.Disposition,
			ContentID:          inline.ContentID,
		})
	}
	email.SizeBytes = int64(len(mimeBytes))
	email.SizeHtmlBodyBytes = int64(len([]byte(email.BodyHTML)))
	email.SizeInlineBytes = totalInlineSize
	email.SizeAttachmentsBytes = totalAttachmentsSize

	spf, dkim, dmarc := parseAuthResults(email.Headers)
	email.SpfVerdict = &abi.VerdictStatus{Status: spf}
	email.DkimVerdict = &abi.VerdictStatus{Status: dkim}
	email.DmarcVerdict = &abi.VerdictStatus{Status: dmarc}

	return email, nil
}

// parsing Authentication-Results header to get the SPF, DKIM, and DMARC results
func parseAuthResults(emailHeaders map[string][]string) (string, string, string) {
	spf := abi.VerdictStatusNotAvailable
	dkim := abi.VerdictStatusNotAvailable
	dmarc := abi.VerdictStatusNotAvailable

	if _, ok := emailHeaders["Authentication-Results"]; ok {
		for _, authResult := range emailHeaders["Authentication-Results"] {
			reSPF := regexp.MustCompile(`spf=(pass|fail|neutral|softfail|permerror|temperror)`)
			reDKIM := regexp.MustCompile(`dkim=(pass|fail|neutral|policy|neutral|temperror|permerror)`)
			reDMARC := regexp.MustCompile(`dmarc=(pass|fail|none|quarantine|reject)`)

			// Extract and assign SPF result.
			matches := reSPF.FindStringSubmatch(authResult)
			if len(matches) > 0 {
				vspf := strings.Split(matches[0], "=")
				if len(vspf) > 1 {
					verdictSpf := vspf[1]
					if spf != abi.VerdictStatusFail && verdictSpf == "pass" {
						spf = abi.VerdictStatusPass
					} else {
						spf = abi.VerdictStatusFail
					}
				}
			}
			// Extract and assign DKIM result.
			matches = reDKIM.FindStringSubmatch(authResult)
			if len(matches) > 0 {
				v := strings.Split(matches[0], "=")
				if len(v) > 1 {
					verdictDkim := v[1]
					if dkim != abi.VerdictStatusFail && verdictDkim == "pass" {
						dkim = abi.VerdictStatusPass
					} else {
						dkim = abi.VerdictStatusFail
					}
				}
			}

			// Extract and assign DMARC result.
			matches = reDMARC.FindStringSubmatch(authResult)
			if len(matches) > 0 {
				v := strings.Split(matches[0], "=")
				if len(v) > 1 {
					verdictDmarc := v[1]
					if dmarc != abi.VerdictStatusFail && verdictDmarc == "pass" {
						dmarc = abi.VerdictStatusPass
					} else {
						dmarc = abi.VerdictStatusFail
					}
				}
			}
		}
	}

	return spf, dkim, dmarc
}

// cleaning up user generated content html
func cleanupUGCHtml(html string) string {
	sanitizer := bluemonday.UGCPolicy()
	sanitizer.AllowURLSchemes("cid", "http", "https", "data") // mid not supported
	// sanitizer.AllowAttrs("href").OnElements("a")
	// sanitizer.AllowAttrs("src").OnElements("img")
	sanitizer.AllowAttrs("style").Globally()
	sanitizer.AllowStandardAttributes()
	sanitizer.AllowImages()
	sanitizer.AllowRelativeURLs(true)
	sanitizer.AllowStyling()

	// Allow only a subset of HTML elements
	allowedElements := []string{"a", "abbr", "acronym", "address", "area", "b", "bdo", "big", "blockquote", "br", "button", "caption", "center", "cite", "code", "col", "colgroup", "dd", "del", "dfn", "dir", "div", "dl", "dt", "em", "fieldset", "font", "form", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "input", "ins", "kbd", "label", "legend", "li", "map", "menu", "ol", "optgroup", "option", "p", "pre", "q", "s", "samp", "select", "small", "span", "strike", "strong", "sub", "sup", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "u", "tr", "tt", "u", "ul", "var"}
	sanitizer.AllowElements(allowedElements...)

	allowedStyles := []string{"azimuth", "background", "background-blend-mode", "background-clip", "background-color", "background-image", "background-origin", "background-position", "background-repeat", "background-size", "border", "border-bottom", "border-bottom-color", "border-bottom-left-radius", "border-bottom-right-radius", "border-bottom-style", "border-bottom-width", "border-collapse", "border-color", "border-left", "border-left-color", "border-left-style", "border-left-width", "border-radius", "border-right", "border-right-color", "border-right-style", "border-right-width", "border-spacing", "border-style", "border-top", "border-top-color", "border-top-left-radius", "border-top-right-radius", "border-top-style", "border-top-width", "border-width", "box-sizing", "break-after", "break-before", "break-inside", "caption-side", "clear", "color", "column-count", "column-fill", "column-gap", "column-rule", "column-rule-color", "column-rule-style", "column-rule-width", "column-span", "column-width", "columns", "direction", "display", "elevation", "empty-cells", "float", "font", "font-family", "font-feature-settings", "font-kerning", "font-size", "font-size-adjust", "font-stretch", "font-style", "font-synthesis", "font-variant", "font-variant-alternates", "font-variant-caps", "font-variant-east-asian", "font-variant-ligatures", "font-variant-numeric", "font-weight", "height", "image-orientation", "image-resolution", "isolation", "letter-spacing", "line-height", "list-style", "list-style-position", "list-style-type", "margin", "margin-bottom", "margin-left", "margin-right", "margin-top", "max-height", "max-width", "min-height", "min-width", "mix-blend-mode", "object-fit", "object-position", "opacity", "outline", "outline-color", "outline-style", "outline-width", "overflow", "padding", "padding-bottom", "padding-left", "padding-right", "padding-top", "pause", "pause-after", "pause-before", "pitch", "pitch-range", "quotes", "richness", "speak", "speak-header", "speak-numeral", "speak-punctuation", "speech-rate", "stress", "table-layout", "text-align", "text-combine-upright", "text-decoration", "text-decoration-color", "text-decoration-line", "text-decoration-skip", "text-decoration-style", "text-emphasis", "text-emphasis-color", "text-emphasis-style", "text-indent", "text-orientation", "text-overflow", "text-transform", "text-underline-position", "unicode-bidi", "vertical-align", "voice-family", "width", "word-spacing", "writing-mode"}
	sanitizer.AllowStyles(allowedStyles...)

	cleanHtml := sanitizer.Sanitize(html)

	return cleanHtml
}
