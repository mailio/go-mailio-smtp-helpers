package mailiosmtphelpers

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseForward(t *testing.T) {
	emailBytes, err := os.ReadFile("test_data/forward.eml")
	if err != nil {
		t.Fatalf("Failed to read email: %v", err)
	}
	email, err := ParseMime(emailBytes)
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}
	assert.Equal(t, "example@gmail.com", email.ForwardInfo.OriginalRecipient.Address)
}

func TestParseText(t *testing.T) {
	emailBytes, err := os.ReadFile("test_data/text.eml")
	if err != nil {
		t.Fatalf("Failed to read email: %v", err)
	}
	email, err := ParseMime(emailBytes)
	if err != nil {
		t.Fatalf("Failed to parse email: %v", err)
	}
	assert.NotEmpty(t, email.BodyText)
}
