package proxy

import (
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
	"go.uber.org/zap"

	"github.com/coinbase/mongobetween/mongo"
)

type connection struct {
	log    *zap.Logger
	statsd *statsd.Client

	address string
	conn    net.Conn
	kill    chan interface{}
	buffer  []byte

	mongoLookup MongoLookup
	dynamic     *Dynamic
	filter      *Filter
	auth        *AuthConfig
	authState   *AuthState
}

func handleConnection(log *zap.Logger, sd *statsd.Client, address string, conn net.Conn, mongoLookup MongoLookup, dynamic *Dynamic, filter *Filter, auth *AuthConfig, kill chan interface{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("Connection crashed", zap.String("panic", fmt.Sprintf("%v", r)), zap.String("stack", string(debug.Stack())))
		}
	}()

	c := connection{
		log:    log,
		statsd: sd,

		address: address,
		conn:    conn,
		kill:    kill,

		mongoLookup: mongoLookup,
		dynamic:     dynamic,
		filter:      filter,
		auth:        auth,
		authState:   NewAuthState(),
	}
	c.processMessages()
}

func (c *connection) processMessages() {
	for {
		err := c.handleMessage()
		if err != nil {
			if err != io.EOF {
				select {
				case <-c.kill:
					// ignore errors from force shutdown
				default:
					c.log.Error("Error handling message", zap.Error(err))
				}
			}
			return
		}
	}
}

func (c *connection) handleMessage() (err error) {
	var tags []string

	defer func(start time.Time) {
		tags := append(tags, fmt.Sprintf("success:%v", err == nil))
		_ = c.statsd.Timing("handle_message", time.Since(start), tags, 1)
	}(time.Now())

	var wm []byte
	if wm, err = c.readWireMessage(); err != nil {
		return
	}

	var op mongo.Operation
	if op, err = mongo.Decode(wm); err != nil {
		return
	}
	isMaster := op.IsIsMaster()
	command, collection := op.CommandAndCollection()
	unacknowledged := op.Unacknowledged()
	tags = append(
		tags,
		fmt.Sprintf("request_op_code:%v", op.OpCode()),
		fmt.Sprintf("is_master:%v", isMaster),
		fmt.Sprintf("command:%s", string(command)),
		fmt.Sprintf("collection:%s", collection),
		fmt.Sprintf("unacknowledged:%v", unacknowledged),
	)
	c.log.Debug(
		"Request",
		zap.Int32("op_code", int32(op.OpCode())),
		zap.Bool("is_master", isMaster),
		zap.String("command", string(command)),
		zap.String("collection", collection),
		zap.Int("request_size", len(wm)),
	)

	// Check if this is an authentication command
	if c.auth != nil && c.auth.Enabled {
		if res, handled, authErr := c.handleAuth(op, command); handled {
			if authErr != nil {
				c.log.Warn("Authentication failed", zap.Error(authErr))
				// Send error response to client
				errRes, _ := c.buildAuthErrorResponse(op.RequestID(), authErr.Error())
				if errRes != nil {
					_, err = c.conn.Write(errRes)
				}
				return authErr
			}
			if res != nil {
				_, err = c.conn.Write(res.Wm)
			}
			return
		}

		// If auth is required but not authenticated, reject the request
		if !c.authState.Authenticated && !isMaster {
			c.log.Warn("Unauthenticated request rejected", zap.String("command", string(command)))
			errRes, _ := c.buildAuthErrorResponse(op.RequestID(), "authentication required")
			if errRes != nil {
				_, err = c.conn.Write(errRes)
			}
			return fmt.Errorf("authentication required")
		}
	}

	// Apply operation/database/collection filters early, before routing
	// Use CommandsAndCollections to handle multi-collection operations (e.g., aggregate with $lookup)
	if c.filter != nil && !isMaster {
		cmdColls := op.CommandsAndCollections()
		if filterErr := c.filter.CheckAll(cmdColls); filterErr != nil {
			c.log.Warn("Operation filtered", zap.Error(filterErr), zap.String("command", string(command)), zap.String("collection", collection))
			errRes, buildErr := c.buildFilterErrorResponse(op.RequestID(), filterErr.Error())
			if buildErr != nil {
				err = fmt.Errorf("filter denied: %w (failed to build error response: %v)", filterErr, buildErr)
				return
			}
			_, err = c.conn.Write(errRes)
			return
		}
	}

	req := &mongo.Message{
		Wm: wm,
		Op: op,
	}
	var res *mongo.Message
	if res, err = c.roundTrip(req, isMaster, command, tags); err != nil {
		return
	}

	if unacknowledged {
		c.log.Debug("Unacknowledged request")
		return
	}

	tags = append(
		tags,
		fmt.Sprintf("response_op_code:%v", res.Op.OpCode()),
	)

	if _, err = c.conn.Write(res.Wm); err != nil {
		return
	}

	c.log.Debug(
		"Response",
		zap.Int32("op_code", int32(res.Op.OpCode())),
		zap.Int("response_size", len(res.Wm)),
	)
	return
}

// handleAuth processes authentication commands (saslStart, saslContinue).
// Returns (response, handled, error). If handled is true, the caller should not process the message further.
func (c *connection) handleAuth(op mongo.Operation, command mongo.Command) (*mongo.Message, bool, error) {
	// Only handle saslStart and saslContinue commands
	if command != mongo.SaslStart && command != mongo.SaslContinue {
		return nil, false, nil
	}

	// Extract the document from the operation
	doc, ok := c.extractDocument(op)
	if !ok {
		return nil, false, fmt.Errorf("failed to extract document from operation")
	}

	if command == mongo.SaslStart {
		return c.handleSaslStart(op.RequestID(), doc)
	}

	return c.handleSaslContinue(op.RequestID(), doc)
}

func (c *connection) handleSaslStart(requestID int32, doc bsoncore.Document) (*mongo.Message, bool, error) {
	// Extract mechanism
	mechanism, _ := doc.Lookup("mechanism").StringValueOK()
	if mechanism != "SCRAM-SHA-256" {
		return nil, true, fmt.Errorf("unsupported authentication mechanism: %s (only SCRAM-SHA-256 supported)", mechanism)
	}

	// Extract payload
	_, payload, ok := doc.Lookup("payload").BinaryOK()
	if !ok {
		return nil, true, fmt.Errorf("missing payload in saslStart")
	}

	// Parse username from payload
	username, err := ParseSASLPayload(payload)
	if err != nil {
		return nil, true, fmt.Errorf("failed to parse SASL payload: %w", err)
	}

	// Look up user credentials
	creds, ok := c.auth.GetUser(username)
	if !ok {
		c.log.Warn("Unknown user attempted authentication", zap.String("username", username))
		return nil, true, fmt.Errorf("authentication failed")
	}

	// Create SCRAM server and process client-first message
	scramServer := NewSCRAMServer(creds, c.authState)
	serverFirst, err := scramServer.ProcessClientFirst(payload)
	if err != nil {
		return nil, true, fmt.Errorf("SCRAM authentication failed: %w", err)
	}

	// Generate a conversation ID
	c.authState.ConversationID = requestID

	// Build saslStart response
	res, err := c.buildSaslResponse(requestID, c.authState.ConversationID, serverFirst, false)
	if err != nil {
		return nil, true, err
	}

	c.log.Debug("saslStart processed", zap.String("username", username))
	return res, true, nil
}

func (c *connection) handleSaslContinue(requestID int32, doc bsoncore.Document) (*mongo.Message, bool, error) {
	// Extract conversationId
	convID, _ := doc.Lookup("conversationId").Int32OK()
	if convID != c.authState.ConversationID {
		return nil, true, fmt.Errorf("invalid conversationId")
	}

	// Extract payload
	_, payload, ok := doc.Lookup("payload").BinaryOK()
	if !ok {
		return nil, true, fmt.Errorf("missing payload in saslContinue")
	}

	// If this is the final empty message after authentication
	if len(payload) == 0 && c.authState.Step == 2 {
		res, err := c.buildSaslResponse(requestID, c.authState.ConversationID, nil, true)
		if err != nil {
			return nil, true, err
		}
		c.log.Info("Authentication successful", zap.String("username", c.authState.Username))
		return res, true, nil
	}

	// Look up user credentials
	creds, ok := c.auth.GetUser(c.authState.Username)
	if !ok {
		return nil, true, fmt.Errorf("authentication failed: unknown user")
	}

	// Process client-final message
	scramServer := NewSCRAMServer(creds, c.authState)
	serverFinal, err := scramServer.ProcessClientFinal(payload)
	if err != nil {
		return nil, true, fmt.Errorf("SCRAM authentication failed: %w", err)
	}

	// Build saslContinue response
	res, err := c.buildSaslResponse(requestID, c.authState.ConversationID, serverFinal, false)
	if err != nil {
		return nil, true, err
	}

	c.log.Debug("saslContinue processed", zap.String("username", c.authState.Username))
	return res, true, nil
}

func (c *connection) extractDocument(op mongo.Operation) (bsoncore.Document, bool) {
	// For OpMsg, extract the document from the first section
	if opMsg, ok := op.(*mongo.OpMsg); ok {
		return opMsg.Document()
	}
	return nil, false
}

func (c *connection) buildSaslResponse(requestID, conversationID int32, payload []byte, done bool) (*mongo.Message, error) {
	// Build response document
	idx, doc := bsoncore.AppendDocumentStart(nil)
	doc = bsoncore.AppendInt32Element(doc, "conversationId", conversationID)
	doc = bsoncore.AppendBooleanElement(doc, "done", done)
	if payload != nil {
		doc = bsoncore.AppendBinaryElement(doc, "payload", 0x00, payload)
	} else {
		doc = bsoncore.AppendBinaryElement(doc, "payload", 0x00, []byte{})
	}
	doc = bsoncore.AppendDoubleElement(doc, "ok", 1.0)
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)

	return mongo.BuildOpMsgResponse(requestID, doc)
}

func (c *connection) buildAuthErrorResponse(requestID int32, errMsg string) ([]byte, error) {
	// Build error response document
	idx, doc := bsoncore.AppendDocumentStart(nil)
	doc = bsoncore.AppendDoubleElement(doc, "ok", 0)
	doc = bsoncore.AppendStringElement(doc, "errmsg", errMsg)
	doc = bsoncore.AppendInt32Element(doc, "code", 18) // AuthenticationFailed
	doc = bsoncore.AppendStringElement(doc, "codeName", "AuthenticationFailed")
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)

	res, err := mongo.BuildOpMsgResponse(requestID, doc)
	if err != nil {
		return nil, err
	}
	return res.Wm, nil
}

func (c *connection) buildFilterErrorResponse(requestID int32, errMsg string) ([]byte, error) {
	// Build error response document using Unauthorized error code
	// This is similar to how MongoDB responds when access is denied
	idx, doc := bsoncore.AppendDocumentStart(nil)
	doc = bsoncore.AppendDoubleElement(doc, "ok", 0)
	doc = bsoncore.AppendStringElement(doc, "errmsg", errMsg)
	doc = bsoncore.AppendInt32Element(doc, "code", 13) // Unauthorized
	doc = bsoncore.AppendStringElement(doc, "codeName", "Unauthorized")
	doc, _ = bsoncore.AppendDocumentEnd(doc, idx)

	res, err := mongo.BuildOpMsgResponse(requestID, doc)
	if err != nil {
		return nil, err
	}
	return res.Wm, nil
}

func (c *connection) readWireMessage() ([]byte, error) {
	var sizeBuf [4]byte

	_, err := io.ReadFull(c.conn, sizeBuf[:])
	if err != nil {
		return nil, err
	}

	// read the length as an int32
	size := (int32(sizeBuf[0])) | (int32(sizeBuf[1]) << 8) | (int32(sizeBuf[2]) << 16) | (int32(sizeBuf[3]) << 24)
	if int(size) > cap(c.buffer) {
		c.buffer = make([]byte, 0, size)
	}

	buffer := c.buffer[:size]
	copy(buffer, sizeBuf[:])

	_, err = io.ReadFull(c.conn, buffer[4:])
	if err != nil {
		return nil, err
	}

	return buffer, nil
}

func (c *connection) roundTrip(msg *mongo.Message, isMaster bool, command mongo.Command, tags []string) (*mongo.Message, error) {
	dynamic := c.dynamic.ForAddress(c.address)
	if dynamic.DisableWrites {
		if mongo.IsWrite(command) {
			return nil, fmt.Errorf("writes are disabled for address: %s", c.address)
		}
	}

	redirectTo := dynamic.RedirectTo
	if redirectTo == "" {
		redirectTo = c.address
	}
	client := c.mongoLookup(redirectTo)
	if client == nil {
		return nil, fmt.Errorf("mongo client not found for address: %s", c.address)
	}

	if isMaster {
		requestID := msg.Op.RequestID()
		c.log.Debug("Non-proxied ismaster response", zap.Int32("request_id", requestID))
		return mongo.IsMasterResponse(requestID, client.Description().Kind)
	}

	return client.RoundTrip(msg, tags)
}
