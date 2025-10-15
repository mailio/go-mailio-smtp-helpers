# Mailio Smtp helper functions. 

## Helper functions

```go
// converting html/text into plain/text
htmlToText(myHtml)
```

```go
// generates RFC2822 compliant Message-ID
generateRFC2822MessageID()
```

```go
// ToMime converts a Mailio specific struct to email Mime message
ToMime(msg *types.Mail) ([]byte, error)

// ToBounce converts a Mailio specific struct to a RFC compliant bounce message
ToBounce(recipient mail.Address, msg types.Mail, bounceCode string, bounceReason string) ([]byte, error)

// ToComplaint converts a Mailio specific struct to a RFC compliant complaint message
ToComplaint(recipient mail.Address, reporter mail.Address, msg types.Mail, complaintReason string) ([]byte, error)

// ParseMime parses an email message and returns a Mailio specific struct
ParseMime(mime []byte) (*types.Mail, error)
```