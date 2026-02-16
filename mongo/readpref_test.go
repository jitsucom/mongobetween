package mongo

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
)

func TestExtractReadPref_Primary(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "test"},
		{Key: "$db", Value: "testdb"},
		{Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "primary"}}},
	})
	assert.NoError(t, err)

	rp, ok := extractReadPref(doc)
	assert.True(t, ok, "Should successfully extract read preference")
	assert.NotNil(t, rp)
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())
}

func TestExtractReadPref_Secondary(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "test"},
		{Key: "$db", Value: "testdb"},
		{Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "secondary"}}},
	})
	assert.NoError(t, err)

	rp, ok := extractReadPref(doc)
	assert.True(t, ok, "Should successfully extract read preference")
	assert.NotNil(t, rp)
	assert.Equal(t, readpref.SecondaryMode, rp.Mode())
}

func TestExtractReadPref_SecondaryPreferred(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "test"},
		{Key: "$db", Value: "testdb"},
		{Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "secondaryPreferred"}}},
	})
	assert.NoError(t, err)

	rp, ok := extractReadPref(doc)
	assert.True(t, ok, "Should successfully extract read preference")
	assert.NotNil(t, rp)
	assert.Equal(t, readpref.SecondaryPreferredMode, rp.Mode())
}

func TestExtractReadPref_PrimaryPreferred(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "test"},
		{Key: "$db", Value: "testdb"},
		{Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "primaryPreferred"}}},
	})
	assert.NoError(t, err)

	rp, ok := extractReadPref(doc)
	assert.True(t, ok, "Should successfully extract read preference")
	assert.NotNil(t, rp)
	assert.Equal(t, readpref.PrimaryPreferredMode, rp.Mode())
}

func TestExtractReadPref_Nearest(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "test"},
		{Key: "$db", Value: "testdb"},
		{Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "nearest"}}},
	})
	assert.NoError(t, err)

	rp, ok := extractReadPref(doc)
	assert.True(t, ok, "Should successfully extract read preference")
	assert.NotNil(t, rp)
	assert.Equal(t, readpref.NearestMode, rp.Mode())
}

func TestExtractReadPref_NoReadPreference(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "test"},
		{Key: "$db", Value: "testdb"},
	})
	assert.NoError(t, err)

	rp, ok := extractReadPref(doc)
	assert.False(t, ok, "Should return false when no read preference is specified")
	assert.NotNil(t, rp)
	// Should default to primary
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())
}

func TestExtractReadPref_InvalidMode(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "test"},
		{Key: "$db", Value: "testdb"},
		{Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "invalidMode"}}},
	})
	assert.NoError(t, err)

	rp, ok := extractReadPref(doc)
	assert.False(t, ok, "Should return false for invalid read preference mode")
	assert.NotNil(t, rp)
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())
}

func TestExtractReadPref_MalformedDocument(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "test"},
		{Key: "$db", Value: "testdb"},
		{Key: "$readPreference", Value: "notADocument"},
	})
	assert.NoError(t, err)

	rp, ok := extractReadPref(doc)
	assert.False(t, ok, "Should return false for malformed read preference")
	assert.NotNil(t, rp)
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())
}

func TestOpMsg_ReadPref_Primary(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "trainers"},
		{Key: "$db", Value: "test"},
		{Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "primary"}}},
	})
	assert.NoError(t, err)

	op := NewOpMsg(doc, []bsoncore.Document{})
	
	rp, ok := op.Op.ReadPref()
	assert.True(t, ok)
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())
}

func TestOpMsg_ReadPref_Secondary(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "trainers"},
		{Key: "$db", Value: "test"},
		{Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "secondary"}}},
	})
	assert.NoError(t, err)

	op := NewOpMsg(doc, []bsoncore.Document{})
	
	rp, ok := op.Op.ReadPref()
	assert.True(t, ok)
	assert.Equal(t, readpref.SecondaryMode, rp.Mode())
}

func TestOpMsg_ReadPref_NoPreference(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "find", Value: "trainers"},
		{Key: "$db", Value: "test"},
	})
	assert.NoError(t, err)

	op := NewOpMsg(doc, []bsoncore.Document{})
	
	rp, ok := op.Op.ReadPref()
	assert.False(t, ok)
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())
}

func TestOpQuery_ReadPref(t *testing.T) {
	doc, err := bson.Marshal(bson.D{
		{Key: "$query", Value: bson.D{{Key: "name", Value: "test"}}},
		{Key: "$readPreference", Value: bson.D{{Key: "mode", Value: "secondary"}}},
	})
	assert.NoError(t, err)

	op := &opQuery{
		fullCollectionName: "test.trainers",
		query:              doc,
	}

	rp, ok := op.ReadPref()
	assert.True(t, ok)
	assert.Equal(t, readpref.SecondaryMode, rp.Mode())
}

func TestWriteOperations_AlwaysReturnPrimary(t *testing.T) {
	// Test Update
	updateOp := &opUpdate{}
	rp, ok := updateOp.ReadPref()
	assert.False(t, ok)
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())

	// Test Insert
	insertOp := &opInsert{}
	rp, ok = insertOp.ReadPref()
	assert.False(t, ok)
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())

	// Test Delete
	deleteOp := &opDelete{}
	rp, ok = deleteOp.ReadPref()
	assert.False(t, ok)
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())
}

// TestGetMoreOperation_CursorPinning verifies that getMore operations
// don't specify read preferences directly, as they inherit the server
// from the cursor cache. This is the correct behavior since cursors
// must remain pinned to the server where they were created.
func TestGetMoreOperation_CursorPinning(t *testing.T) {
	getMoreOp := &opGetMore{
		cursorID:           12345,
		fullCollectionName: "test.collection",
	}
	
	// GetMore should not have a read preference since it uses cursor pinning
	rp, ok := getMoreOp.ReadPref()
	assert.False(t, ok, "GetMore should not specify read preference")
	assert.Equal(t, readpref.PrimaryMode, rp.Mode())
	
	// Verify cursor ID is accessible
	cursorID, cursorOK := getMoreOp.CursorID()
	assert.True(t, cursorOK)
	assert.Equal(t, int64(12345), cursorID)
}
