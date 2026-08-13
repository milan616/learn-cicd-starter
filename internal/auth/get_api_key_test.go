package auth

import (
	"errors"
	"net/http"
	"testing"
)

// Dummy definition if ErrNoAuthHeaderIncluded is defined in your package
// var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedErr   error
		errMsgContains string
	}{
		{
			name: "Valid ApiKey Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret-token-12345"},
			},
			expectedKey: "secret-token-12345",
			expectedErr: nil,
		},
		{
			name:        "Missing Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Empty Authorization Header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Header - Wrong Scheme (Bearer)",
			headers: http.Header{
				"Authorization": []string{"Bearer secret-token-12345"},
			},
			expectedKey:    "",
			errMsgContains: "malformed authorization header",
		},
		{
			name: "Malformed Header - Missing Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:    "",
			errMsgContains: "malformed authorization header",
		},
		{
			name: "Malformed Header - Incorrect Case (apikey)",
			headers: http.Header{
				"Authorization": []string{"apikey secret-token-12345"},
			},
			expectedKey:    "",
			errMsgContains: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			// Check returned API key
			if gotKey != tt.expectedKey {
				t.Errorf("GetAPIKey() gotKey = %v, want %v", gotKey, tt.expectedKey)
			}

			// Check exact error match (e.g., ErrNoAuthHeaderIncluded)
			if tt.expectedErr != nil {
				if !errors.Is(err, tt.expectedErr) {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.expectedErr)
				}
				return
			}

			// Check error message substring for dynamically generated errors
			if tt.errMsgContains != "" {
				if err == nil || err.Error() != tt.errMsgContains {
					t.Errorf("GetAPIKey() error = %v, want error containing %q", err, tt.errMsgContains)
				}
				return
			}

			// Expecting no error
			if err != nil {
				t.Errorf("GetAPIKey() unexpected error = %v", err)
			}
		})
	}
}
