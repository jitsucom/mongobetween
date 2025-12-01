package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// AuthConfig holds proxy-level authentication configuration.
type AuthConfig struct {
	// Users maps username to user credentials
	Users map[string]*UserCredentials
	// Enabled indicates if proxy authentication is required
	Enabled bool
}

// UserCredentials holds the stored credentials for a user.
type UserCredentials struct {
	Username   string
	SaltedPass []byte // Pre-computed salted password
	Salt       []byte
	Iterations int
}

// NewAuthConfig creates a new AuthConfig.
func NewAuthConfig() *AuthConfig {
	return &AuthConfig{
		Users:   make(map[string]*UserCredentials),
		Enabled: false,
	}
}

// AddUser adds a user with the given password.
// The password is stored as a salted hash, never in plaintext.
func (a *AuthConfig) AddUser(username, password string) error {
	salt := make([]byte, 24)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	iterations := 15000 // SCRAM-SHA-256 default

	// Compute salted password using PBKDF2
	saltedPass := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	a.Users[username] = &UserCredentials{
		Username:   username,
		SaltedPass: saltedPass,
		Salt:       salt,
		Iterations: iterations,
	}
	a.Enabled = true

	return nil
}

// GetUser returns user credentials if found.
func (a *AuthConfig) GetUser(username string) (*UserCredentials, bool) {
	if a == nil || !a.Enabled {
		return nil, false
	}
	user, ok := a.Users[username]
	return user, ok
}

// AuthState tracks authentication state for a connection.
type AuthState struct {
	Authenticated  bool
	Username       string
	ConversationID int32
	ClientNonce    string
	ServerNonce    string
	AuthMessage    string
	Step           int // 0=not started, 1=saslStart received, 2=complete
	StoredKey      []byte
	ServerKey      []byte
}

// NewAuthState creates a new authentication state.
func NewAuthState() *AuthState {
	return &AuthState{
		Authenticated: false,
		Step:          0,
	}
}

// SCRAMServer handles server-side SCRAM-SHA-256 authentication.
type SCRAMServer struct {
	creds *UserCredentials
	state *AuthState
}

// NewSCRAMServer creates a new SCRAM server for the given user.
func NewSCRAMServer(creds *UserCredentials, state *AuthState) *SCRAMServer {
	return &SCRAMServer{
		creds: creds,
		state: state,
	}
}

// ProcessClientFirst processes the client-first message from saslStart.
// Returns the server-first message.
func (s *SCRAMServer) ProcessClientFirst(payload []byte) ([]byte, error) {
	// Client first message format: "n,,n=<username>,r=<nonce>"
	msg := string(payload)

	// Parse GS2 header (n,,) and client-first-message-bare
	if !strings.HasPrefix(msg, "n,,") {
		return nil, fmt.Errorf("invalid client-first message: missing GS2 header")
	}

	clientFirstBare := msg[3:] // Remove "n,,"
	parts := strings.Split(clientFirstBare, ",")

	var username, clientNonce string
	for _, part := range parts {
		if strings.HasPrefix(part, "n=") {
			username = part[2:]
		} else if strings.HasPrefix(part, "r=") {
			clientNonce = part[2:]
		}
	}

	if username == "" || clientNonce == "" {
		return nil, fmt.Errorf("invalid client-first message: missing username or nonce")
	}

	if username != s.creds.Username {
		return nil, fmt.Errorf("username mismatch")
	}

	// Generate server nonce (client nonce + server random)
	serverNonceBytes := make([]byte, 24)
	if _, err := rand.Read(serverNonceBytes); err != nil {
		return nil, fmt.Errorf("failed to generate server nonce: %w", err)
	}
	serverNonce := clientNonce + base64.StdEncoding.EncodeToString(serverNonceBytes)

	// Store state for later verification
	s.state.ClientNonce = clientNonce
	s.state.ServerNonce = serverNonce
	s.state.Username = username
	s.state.Step = 1

	// Compute stored key and server key
	clientKey := hmacSHA256(s.creds.SaltedPass, []byte("Client Key"))
	s.state.StoredKey = sha256Sum(clientKey)
	s.state.ServerKey = hmacSHA256(s.creds.SaltedPass, []byte("Server Key"))

	// Build server-first message
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d",
		serverNonce,
		base64.StdEncoding.EncodeToString(s.creds.Salt),
		s.creds.Iterations,
	)

	// Store auth message components for proof verification
	s.state.AuthMessage = clientFirstBare + "," + serverFirst

	return []byte(serverFirst), nil
}

// ProcessClientFinal processes the client-final message from saslContinue.
// Returns the server-final message if successful.
func (s *SCRAMServer) ProcessClientFinal(payload []byte) ([]byte, error) {
	if s.state.Step != 1 {
		return nil, fmt.Errorf("unexpected client-final message")
	}

	// Client final message format: "c=<channel-binding>,r=<nonce>,p=<proof>"
	msg := string(payload)
	parts := strings.Split(msg, ",")

	var channelBinding, nonce, proofB64 string
	for _, part := range parts {
		if strings.HasPrefix(part, "c=") {
			channelBinding = part[2:]
		} else if strings.HasPrefix(part, "r=") {
			nonce = part[2:]
		} else if strings.HasPrefix(part, "p=") {
			proofB64 = part[2:]
		}
	}

	// Verify nonce matches
	if nonce != s.state.ServerNonce {
		return nil, fmt.Errorf("nonce mismatch")
	}

	// Verify channel binding (should be "biws" for no channel binding)
	if channelBinding != "biws" {
		return nil, fmt.Errorf("unsupported channel binding")
	}

	// Decode client proof
	clientProof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return nil, fmt.Errorf("invalid client proof encoding: %w", err)
	}

	// Build client-final-message-without-proof
	clientFinalWithoutProof := fmt.Sprintf("c=%s,r=%s", channelBinding, nonce)

	// Complete auth message
	authMessage := s.state.AuthMessage + "," + clientFinalWithoutProof

	// Compute expected client signature
	clientSignature := hmacSHA256(s.state.StoredKey, []byte(authMessage))

	// Recover client key: ClientKey = ClientProof XOR ClientSignature
	recoveredClientKey := xorBytes(clientProof, clientSignature)

	// Verify: H(ClientKey) should equal StoredKey
	recoveredStoredKey := sha256Sum(recoveredClientKey)
	if !hmac.Equal(recoveredStoredKey, s.state.StoredKey) {
		return nil, fmt.Errorf("authentication failed: invalid proof")
	}

	// Compute server signature for server-final message
	serverSignature := hmacSHA256(s.state.ServerKey, []byte(authMessage))
	serverFinal := fmt.Sprintf("v=%s", base64.StdEncoding.EncodeToString(serverSignature))

	s.state.Step = 2
	s.state.Authenticated = true

	return []byte(serverFinal), nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// ParseSASLPayload extracts the mechanism and username from a saslStart command.
func ParseSASLPayload(payload []byte) (username string, err error) {
	msg := string(payload)
	if !strings.HasPrefix(msg, "n,,") {
		return "", fmt.Errorf("invalid SCRAM message format")
	}

	parts := strings.Split(msg[3:], ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "n=") {
			return part[2:], nil
		}
	}

	return "", fmt.Errorf("username not found in payload")
}

// ParseConversationID extracts conversationId from an integer value.
func ParseConversationID(val interface{}) (int32, error) {
	switch v := val.(type) {
	case int32:
		return v, nil
	case int64:
		return int32(v), nil
	case int:
		return int32(v), nil
	case float64:
		return int32(v), nil
	case string:
		i, err := strconv.ParseInt(v, 10, 32)
		return int32(i), err
	default:
		return 0, fmt.Errorf("cannot parse conversationId: %T", val)
	}
}
