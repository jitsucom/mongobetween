package proxy

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/mongodb"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/writeconcern"
	"go.uber.org/zap"

	mongob "github.com/coinbase/mongobetween/mongo"
)

var (
	ctx       = context.Background()
	proxyPort = 27020
)

type Trainer struct {
	Name string
	Age  int
	City string
}

// mongoContainer holds the container and its URI
type mongoContainer struct {
	container *mongodb.MongoDBContainer
	uri       string
}

// setupMongoContainer starts a MongoDB container and returns the container info
func setupMongoContainer(t *testing.T, ctx context.Context) *mongoContainer {
	t.Helper()

	mongoC, err := mongodb.Run(ctx, "mongo:8")
	require.NoError(t, err, "failed to start MongoDB container")

	uri, err := mongoC.ConnectionString(ctx)
	require.NoError(t, err, "failed to get MongoDB connection string")

	return &mongoContainer{
		container: mongoC,
		uri:       uri,
	}
}

// setupMongoContainers starts multiple MongoDB containers
func setupMongoContainers(t *testing.T, ctx context.Context, count int) []*mongoContainer {
	t.Helper()

	containers := make([]*mongoContainer, count)
	for i := 0; i < count; i++ {
		containers[i] = setupMongoContainer(t, ctx)
	}
	return containers
}

// cleanupContainers terminates all containers
func cleanupContainers(t *testing.T, ctx context.Context, containers []*mongoContainer) {
	for _, c := range containers {
		if c != nil && c.container != nil {
			if err := c.container.Terminate(ctx); err != nil {
				t.Logf("failed to terminate MongoDB container: %v", err)
			}
		}
	}
}

func TestProxy(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		if err := mc.container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}()

	proxy := setupProxyWithURI(t, mc.uri)

	go func() {
		err := proxy.Run()
		assert.Nil(t, err)
	}()

	client := setupClient(t, "localhost", proxyPort)
	collection := client.Database("test").Collection("test_proxy")
	_, err := collection.DeleteMany(ctx, bson.D{{}})
	assert.Nil(t, err)

	ash := Trainer{"Ash", 10, "Pallet Town"}
	misty := Trainer{"Misty", 10, "Cerulean City"}
	brock := Trainer{"Brock", 15, "Pewter City"}

	_, err = collection.InsertOne(ctx, ash)
	assert.Nil(t, err)

	_, err = collection.InsertMany(ctx, []interface{}{misty, brock})
	assert.Nil(t, err)

	filter := bson.D{{Key: "name", Value: "Ash"}}
	update := bson.D{
		{Key: "$inc", Value: bson.D{
			{Key: "age", Value: 1},
		}},
	}
	updateResult, err := collection.UpdateOne(ctx, filter, update)
	assert.Nil(t, err)
	assert.Equal(t, int64(1), updateResult.MatchedCount)
	assert.Equal(t, int64(1), updateResult.ModifiedCount)

	var result Trainer
	err = collection.FindOne(ctx, filter).Decode(&result)
	assert.Nil(t, err)
	assert.Equal(t, "Pallet Town", result.City)

	var results []Trainer
	cur, err := collection.Find(ctx, bson.D{}, options.Find().SetLimit(2).SetBatchSize(1))
	assert.Nil(t, err)
	err = cur.All(ctx, &results)
	assert.Nil(t, err)
	assert.Equal(t, "Pallet Town", results[0].City)
	assert.Equal(t, "Cerulean City", results[1].City)

	deleteResult, err := collection.DeleteMany(ctx, bson.D{{}})
	assert.Nil(t, err)
	assert.Equal(t, int64(3), deleteResult.DeletedCount)

	err = client.Disconnect(ctx)
	assert.Nil(t, err)

	proxy.Shutdown()
}

func TestProxyUnacknowledgedWrites(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		if err := mc.container.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %v", err)
		}
	}()

	proxy := setupProxyWithURI(t, mc.uri)
	defer proxy.Shutdown()

	go func() {
		err := proxy.Run()
		assert.Nil(t, err)
	}()

	// Create a client with retryable writes disabled so the test will fail if the proxy crashes while processing the
	// unacknowledged write. If the proxy were to crash, it would close all connections and the next write would error
	// if retryable writes are disabled.
	clientOpts := options.Client().SetRetryWrites(false)
	client := setupClient(t, "localhost", proxyPort, clientOpts)
	defer func() {
		err := client.Disconnect(ctx)
		assert.Nil(t, err)
	}()

	// Create two *Collection instances: one for setup and basic operations and and one configured with an
	// unacknowledged write concern for testing.
	wc := writeconcern.Unacknowledged()
	setupCollection := client.Database("test").Collection("test_proxy_unacknowledged_writes")
	unackCollection, err := setupCollection.Clone(options.Collection().SetWriteConcern(wc))
	assert.Nil(t, err)

	// Setup by deleting all documents.
	_, err = setupCollection.DeleteMany(ctx, bson.D{})
	assert.Nil(t, err)

	ash := Trainer{"Ash", 10, "Pallet Town"}
	_, err = unackCollection.InsertOne(ctx, ash)
	assert.Equal(t, mongo.ErrUnacknowledgedWrite, err) // driver returns a special error value for w=0 writes

	// Insert a document using the setup collection and ensure document count is 2. Doing this ensures that the proxy
	// did not crash while processing the unacknowledged write.
	_, err = setupCollection.InsertOne(ctx, ash)
	assert.Nil(t, err)

	count, err := setupCollection.CountDocuments(ctx, bson.D{})
	assert.Nil(t, err)
	assert.Equal(t, int64(2), count)
}

func TestProxyWithDynamicConfig(t *testing.T) {
	// Start 3 MongoDB containers
	containers := setupMongoContainers(t, ctx, 3)
	defer cleanupContainers(t, ctx, containers)

	collection := "test_proxy_with_dynamic_config"

	json := fmt.Sprintf(`{
	  "Clusters": {
		":%d": {
		  "DisableWrites": true,
		  "RedirectTo": ""
		},
		":%d": {
		  "DisableWrites": false,
		  "RedirectTo": ":%d"
		},
		":%d": {
		  "DisableWrites": false,
		  "RedirectTo": ""
		}
	  }
	}`, proxyPort, proxyPort+1, proxyPort+2, proxyPort+2)
	f, err := os.CreateTemp("", "*.json")
	assert.Nil(t, err)
	defer func() {
		_ = os.Remove(f.Name())
	}()
	_, err = f.Write([]byte(json))
	assert.Nil(t, err)
	err = f.Close()
	assert.Nil(t, err)

	d, err := NewDynamic(f.Name(), zap.L())
	assert.Nil(t, err)

	// Create proxies with the containers
	proxies := setupProxiesWithContainers(t, d, proxyPort, containers)
	defer func() {
		for _, p := range proxies {
			p.Shutdown()
		}
	}()
	for _, p := range proxies {
		proxy := p
		go func() {
			err := proxy.Run()
			assert.Nil(t, err)
		}()
	}

	clients := []*mongo.Client{setupClient(t, "localhost", proxyPort), setupClient(t, "localhost", proxyPort+1), setupClient(t, "localhost", proxyPort+2)}
	defer func() {
		for _, client := range clients {
			err := client.Disconnect(ctx)
			assert.Nil(t, err)
		}
	}()

	// Connect directly to the upstream containers
	var upstreamClients []*mongo.Client
	for _, c := range containers {
		client, err := mongo.Connect(ctx, options.Client().ApplyURI(c.uri))
		assert.Nil(t, err)
		upstreamClients = append(upstreamClients, client)
	}
	defer func() {
		for _, client := range upstreamClients {
			err := client.Disconnect(ctx)
			assert.Nil(t, err)
		}
	}()

	for _, client := range upstreamClients {
		coll := client.Database("test").Collection(collection)
		_, err := coll.DeleteMany(ctx, bson.D{{}})
		assert.Nil(t, err)
	}

	ash := Trainer{"Ash", 10, "Pallet Town"}
	misty := Trainer{"Misty", 10, "Cerulean City"}
	brock := Trainer{"Brock", 15, "Pewter City"}

	// expect write error
	_, err = clients[0].Database("test").Collection(collection).InsertOne(ctx, ash)
	assert.Error(t, err, "socket was unexpectedly closed")

	_, err = clients[1].Database("test").Collection(collection).InsertMany(ctx, []interface{}{misty, brock})
	assert.Nil(t, err)

	count, err := clients[0].Database("test").Collection(collection).CountDocuments(ctx, bson.D{})
	assert.Nil(t, err)
	assert.Equal(t, int64(0), count)

	count, err = clients[1].Database("test").Collection(collection).CountDocuments(ctx, bson.D{})
	assert.Nil(t, err)
	assert.Equal(t, int64(2), count)

	count, err = clients[2].Database("test").Collection(collection).CountDocuments(ctx, bson.D{})
	assert.Nil(t, err)
	assert.Equal(t, int64(2), count)

	// check upstreams for expected counts
	count, err = upstreamClients[0].Database("test").Collection(collection).CountDocuments(ctx, bson.D{})
	assert.Nil(t, err)
	assert.Equal(t, int64(0), count)

	count, err = upstreamClients[1].Database("test").Collection(collection).CountDocuments(ctx, bson.D{})
	assert.Nil(t, err)
	assert.Equal(t, int64(0), count)

	count, err = upstreamClients[2].Database("test").Collection(collection).CountDocuments(ctx, bson.D{})
	assert.Nil(t, err)
	assert.Equal(t, int64(2), count)
}

func setupProxyWithURI(t *testing.T, uri string) *Proxy {
	t.Helper()

	sd, err := statsd.New("localhost:8125")
	assert.Nil(t, err)

	dynamic, err := NewDynamic("", zap.L())
	assert.Nil(t, err)

	address := fmt.Sprintf(":%d", proxyPort)

	upstream, err := mongob.Connect(zap.L(), sd, options.Client().ApplyURI(uri), false)
	assert.Nil(t, err)

	lookup := func(addr string) *mongob.Mongo {
		return upstream
	}

	proxy, err := NewProxy(zap.L(), sd, "label", "tcp4", address, false, lookup, dynamic, nil, nil)
	assert.Nil(t, err)

	return proxy
}

func setupProxiesWithContainers(t *testing.T, d *Dynamic, startPort int, containers []*mongoContainer) []*Proxy {
	t.Helper()

	sd, err := statsd.New("localhost:8125")
	assert.Nil(t, err)

	upstreams := make(map[string]*mongob.Mongo)
	lookup := func(address string) *mongob.Mongo {
		return upstreams[address]
	}

	var proxies []*Proxy
	for i, c := range containers {
		port := startPort + i
		address := fmt.Sprintf(":%d", port)

		upstream, err := mongob.Connect(zap.L(), sd, options.Client().ApplyURI(c.uri), false)
		assert.Nil(t, err)
		upstreams[address] = upstream

		proxy, err := NewProxy(zap.L(), sd, "label", "tcp4", address, false, lookup, d, nil, nil)
		assert.Nil(t, err)

		proxies = append(proxies, proxy)
	}

	return proxies
}

func setupClient(t *testing.T, host string, port int, clientOpts ...*options.ClientOptions) *mongo.Client {
	t.Helper()

	// Base options should only use ApplyURI. The full set should have the user-supplied options after uriOpts so they
	// will win out in the case of conflicts.
	proxyURI := fmt.Sprintf("mongodb://%s:%d/test", host, port)
	uriOpts := options.Client().ApplyURI(proxyURI)
	allClientOpts := append([]*options.ClientOptions{uriOpts}, clientOpts...)

	client, err := mongo.Connect(ctx, allClientOpts...)
	assert.Nil(t, err)

	// Call Ping with a low timeout to ensure the cluster is running and fail-fast if not.
	pingCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	err = client.Ping(pingCtx, nil)
	if err != nil {
		// Clean up in failure cases.
		_ = client.Disconnect(ctx)

		// Use t.Fatalf instead of assert because we want to fail fast if the cluster is down.
		t.Fatalf("error pinging cluster: %v", err)
	}

	return client
}

// setupClientWithAuth creates a MongoDB client with authentication credentials
func setupClientWithAuth(t *testing.T, host string, port int, username, password string) *mongo.Client {
	t.Helper()

	proxyURI := fmt.Sprintf("mongodb://%s:%s@%s:%d/test?authMechanism=SCRAM-SHA-256", username, password, host, port)
	clientOpts := options.Client().ApplyURI(proxyURI)

	client, err := mongo.Connect(ctx, clientOpts)
	require.NoError(t, err)

	return client
}

// setupProxyWithFilter creates a proxy with the given filter configuration
func setupProxyWithFilter(t *testing.T, uri string, port int, filter *Filter) *Proxy {
	t.Helper()

	sd, err := statsd.New("localhost:8125")
	require.NoError(t, err)

	dynamic, err := NewDynamic("", zap.L())
	require.NoError(t, err)

	address := fmt.Sprintf(":%d", port)

	upstream, err := mongob.Connect(zap.L(), sd, options.Client().ApplyURI(uri), false)
	require.NoError(t, err)

	lookup := func(addr string) *mongob.Mongo {
		return upstream
	}

	proxy, err := NewProxy(zap.L(), sd, "label", "tcp4", address, false, lookup, dynamic, filter, nil)
	require.NoError(t, err)

	return proxy
}

// setupProxyWithAuth creates a proxy with the given auth configuration
func setupProxyWithAuth(t *testing.T, uri string, port int, auth *AuthConfig) *Proxy {
	t.Helper()

	sd, err := statsd.New("localhost:8125")
	require.NoError(t, err)

	dynamic, err := NewDynamic("", zap.L())
	require.NoError(t, err)

	address := fmt.Sprintf(":%d", port)

	upstream, err := mongob.Connect(zap.L(), sd, options.Client().ApplyURI(uri), false)
	require.NoError(t, err)

	lookup := func(addr string) *mongob.Mongo {
		return upstream
	}

	proxy, err := NewProxy(zap.L(), sd, "label", "tcp4", address, false, lookup, dynamic, nil, auth)
	require.NoError(t, err)

	return proxy
}

// ============================================================================
// Filter Tests
// ============================================================================

func TestProxyWithFilterAllowedOperations(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create a filter that only allows find and insert operations
	filter := NewFilter(
		[]string{"find", "insert"}, // allowed operations
		nil,                        // denied operations
		nil,                        // allowed databases
		nil,                        // denied databases
		nil,                        // allowed collections
		nil,                        // denied collections
	)

	proxy := setupProxyWithFilter(t, mc.uri, proxyPort, filter)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	// Give proxy time to start
	time.Sleep(100 * time.Millisecond)

	client := setupClient(t, "localhost", proxyPort)
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	collection := client.Database("test").Collection("test_filter_ops")

	// Insert should work (allowed)
	_, err := collection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.NoError(t, err, "insert should be allowed")

	// Find should work (allowed)
	var result bson.M
	err = collection.FindOne(ctx, bson.D{{Key: "name", Value: "test"}}).Decode(&result)
	assert.NoError(t, err, "find should be allowed")

	// Delete should fail (not allowed)
	_, err = collection.DeleteOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.Error(t, err, "delete should be denied")
	assert.Contains(t, err.Error(), "not in the allowed operations list")

	// Update should fail (not allowed)
	_, err = collection.UpdateOne(ctx, bson.D{{Key: "name", Value: "test"}}, bson.D{{Key: "$set", Value: bson.D{{Key: "age", Value: 10}}}})
	assert.Error(t, err, "update should be denied")
	assert.Contains(t, err.Error(), "not in the allowed operations list")
}

func TestProxyWithFilterDeniedOperations(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create a filter that denies drop and dropDatabase operations
	filter := NewFilter(
		nil,                              // allowed operations
		[]string{"drop", "dropDatabase"}, // denied operations
		nil,                              // allowed databases
		nil,                              // denied databases
		nil,                              // allowed collections
		nil,                              // denied collections
	)

	proxy := setupProxyWithFilter(t, mc.uri, proxyPort, filter)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	client := setupClient(t, "localhost", proxyPort)
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	collection := client.Database("test").Collection("test_filter_denied")

	// Insert should work
	_, err := collection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.NoError(t, err, "insert should be allowed")

	// Drop should fail
	err = collection.Drop(ctx)
	assert.Error(t, err, "drop should be denied")
	assert.Contains(t, err.Error(), "denied")
}

func TestProxyWithFilterAllowedDatabases(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create a filter that only allows "app_db" database
	filter := NewFilter(
		nil,              // allowed operations
		nil,              // denied operations
		[]string{"test"}, // allowed databases
		nil,              // denied databases
		nil,              // allowed collections
		nil,              // denied collections
	)

	proxy := setupProxyWithFilter(t, mc.uri, proxyPort, filter)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	client := setupClient(t, "localhost", proxyPort)
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	// Operations on "test" database should work
	testCollection := client.Database("test").Collection("test_db_filter")
	_, err := testCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.NoError(t, err, "insert to allowed database should work")

	// Operations on "other" database should fail
	otherCollection := client.Database("other").Collection("test_db_filter")
	_, err = otherCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.Error(t, err, "insert to non-allowed database should fail")
	assert.Contains(t, err.Error(), "not in the allowed databases list")
}

func TestProxyWithFilterDeniedDatabases(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create a filter that denies "admin" and "config" databases
	filter := NewFilter(
		nil,                         // allowed operations
		nil,                         // denied operations
		nil,                         // allowed databases
		[]string{"admin", "config"}, // denied databases
		nil,                         // allowed collections
		nil,                         // denied collections
	)

	proxy := setupProxyWithFilter(t, mc.uri, proxyPort, filter)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	client := setupClient(t, "localhost", proxyPort)
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	// Operations on "test" database should work
	testCollection := client.Database("test").Collection("test_denied_db")
	_, err := testCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.NoError(t, err, "insert to non-denied database should work")

	// Operations on "admin" database should fail
	adminCollection := client.Database("admin").Collection("test_denied_db")
	_, err = adminCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.Error(t, err, "insert to denied database should fail")
	assert.Contains(t, err.Error(), "denied")
}

func TestProxyWithFilterAllowedCollections(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create a filter that only allows specific collections
	filter := NewFilter(
		nil,                                   // allowed operations
		nil,                                   // denied operations
		nil,                                   // allowed databases
		nil,                                   // denied databases
		[]string{"test.users", "test.orders"}, // allowed collections
		nil,                                   // denied collections
	)

	proxy := setupProxyWithFilter(t, mc.uri, proxyPort, filter)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	client := setupClient(t, "localhost", proxyPort)
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	// Operations on "test.users" should work
	usersCollection := client.Database("test").Collection("users")
	_, err := usersCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.NoError(t, err, "insert to allowed collection should work")

	// Operations on "test.secrets" should fail
	secretsCollection := client.Database("test").Collection("secrets")
	_, err = secretsCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.Error(t, err, "insert to non-allowed collection should fail")
	assert.Contains(t, err.Error(), "not in the allowed collections list")
}

func TestProxyWithFilterWildcardCollections(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create a filter that allows collections matching a wildcard pattern
	filter := NewFilter(
		nil,                                     // allowed operations
		nil,                                     // denied operations
		nil,                                     // allowed databases
		nil,                                     // denied databases
		[]string{"test.users_*", "test.public"}, // allowed collections with wildcard
		nil,                                     // denied collections
	)

	proxy := setupProxyWithFilter(t, mc.uri, proxyPort, filter)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	client := setupClient(t, "localhost", proxyPort)
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	// Operations on "test.users_archive" should work (matches wildcard)
	archiveCollection := client.Database("test").Collection("users_archive")
	_, err := archiveCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.NoError(t, err, "insert to wildcard-matched collection should work")

	// Operations on "test.users_backup" should work (matches wildcard)
	backupCollection := client.Database("test").Collection("users_backup")
	_, err = backupCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.NoError(t, err, "insert to another wildcard-matched collection should work")

	// Operations on "test.public" should work (exact match)
	publicCollection := client.Database("test").Collection("public")
	_, err = publicCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.NoError(t, err, "insert to exact-matched collection should work")

	// Operations on "test.secrets" should fail (no match)
	secretsCollection := client.Database("test").Collection("secrets")
	_, err = secretsCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.Error(t, err, "insert to non-matched collection should fail")
	assert.Contains(t, err.Error(), "not in the allowed collections list")
}

func TestProxyWithFilterDeniedCollectionsWildcard(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create a filter that denies collections matching a wildcard pattern
	filter := NewFilter(
		nil,                                      // allowed operations
		nil,                                      // denied operations
		nil,                                      // allowed databases
		nil,                                      // denied databases
		nil,                                      // allowed collections
		[]string{"test.temp_*", "test.internal"}, // denied collections with wildcard
	)

	proxy := setupProxyWithFilter(t, mc.uri, proxyPort, filter)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	client := setupClient(t, "localhost", proxyPort)
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	// Operations on "test.users" should work (not denied)
	usersCollection := client.Database("test").Collection("users")
	_, err := usersCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.NoError(t, err, "insert to non-denied collection should work")

	// Operations on "test.temp_data" should fail (matches wildcard)
	tempCollection := client.Database("test").Collection("temp_data")
	_, err = tempCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.Error(t, err, "insert to wildcard-denied collection should fail")
	assert.Contains(t, err.Error(), "denied")

	// Operations on "test.internal" should fail (exact match)
	internalCollection := client.Database("test").Collection("internal")
	_, err = internalCollection.InsertOne(ctx, bson.D{{Key: "name", Value: "test"}})
	assert.Error(t, err, "insert to exact-denied collection should fail")
	assert.Contains(t, err.Error(), "denied")
}

// ============================================================================
// Authentication Tests
// ============================================================================

func TestProxyWithAuthSuccess(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create auth config with a test user
	auth := NewAuthConfig()
	err := auth.AddUser("testuser", "testpass")
	require.NoError(t, err)

	proxy := setupProxyWithAuth(t, mc.uri, proxyPort, auth)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	// Connect with correct credentials
	client := setupClientWithAuth(t, "localhost", proxyPort, "testuser", "testpass")
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	// Should be able to perform operations after authentication
	collection := client.Database("test").Collection("test_auth")
	_, err = collection.InsertOne(ctx, bson.D{{Key: "name", Value: "authenticated"}})
	assert.NoError(t, err, "authenticated user should be able to insert")

	var result bson.M
	err = collection.FindOne(ctx, bson.D{{Key: "name", Value: "authenticated"}}).Decode(&result)
	assert.NoError(t, err, "authenticated user should be able to find")
	assert.Equal(t, "authenticated", result["name"])
}

func TestProxyWithAuthFailureWrongPassword(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create auth config with a test user
	auth := NewAuthConfig()
	err := auth.AddUser("testuser", "testpass")
	require.NoError(t, err)

	proxy := setupProxyWithAuth(t, mc.uri, proxyPort, auth)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	// Try to connect with wrong password
	proxyURI := fmt.Sprintf("mongodb://testuser:wrongpass@localhost:%d/test", proxyPort)
	clientOpts := options.Client().ApplyURI(proxyURI)
	client, err := mongo.Connect(ctx, clientOpts)
	require.NoError(t, err)
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	// Ping should fail due to authentication error
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err = client.Ping(pingCtx, nil)
	assert.Error(t, err, "ping with wrong password should fail")
}

func TestProxyWithAuthFailureUnknownUser(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create auth config with a test user
	auth := NewAuthConfig()
	err := auth.AddUser("testuser", "testpass")
	require.NoError(t, err)

	proxy := setupProxyWithAuth(t, mc.uri, proxyPort, auth)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	// Try to connect with unknown user
	proxyURI := fmt.Sprintf("mongodb://unknownuser:testpass@localhost:%d/test", proxyPort)
	clientOpts := options.Client().ApplyURI(proxyURI)
	client, err := mongo.Connect(ctx, clientOpts)
	require.NoError(t, err)
	defer func() {
		_ = client.Disconnect(ctx)
	}()

	// Ping should fail due to authentication error
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err = client.Ping(pingCtx, nil)
	assert.Error(t, err, "ping with unknown user should fail")
}

func TestProxyWithAuthMultipleUsers(t *testing.T) {
	mc := setupMongoContainer(t, ctx)
	defer func() {
		_ = mc.container.Terminate(ctx)
	}()

	// Create auth config with multiple users
	auth := NewAuthConfig()
	err := auth.AddUser("user1", "pass1")
	require.NoError(t, err)
	err = auth.AddUser("user2", "pass2")
	require.NoError(t, err)

	proxy := setupProxyWithAuth(t, mc.uri, proxyPort, auth)
	defer proxy.Shutdown()

	go func() {
		_ = proxy.Run()
	}()

	time.Sleep(100 * time.Millisecond)

	// User1 should authenticate successfully
	client1 := setupClientWithAuth(t, "localhost", proxyPort, "user1", "pass1")
	defer func() {
		_ = client1.Disconnect(ctx)
	}()

	collection1 := client1.Database("test").Collection("test_multi_auth")
	_, err = collection1.InsertOne(ctx, bson.D{{Key: "user", Value: "user1"}})
	assert.NoError(t, err, "user1 should be able to insert")

	// User2 should authenticate successfully
	client2 := setupClientWithAuth(t, "localhost", proxyPort, "user2", "pass2")
	defer func() {
		_ = client2.Disconnect(ctx)
	}()

	collection2 := client2.Database("test").Collection("test_multi_auth")
	_, err = collection2.InsertOne(ctx, bson.D{{Key: "user", Value: "user2"}})
	assert.NoError(t, err, "user2 should be able to insert")

	// Verify both documents exist
	count, err := collection1.CountDocuments(ctx, bson.D{})
	assert.NoError(t, err)
	assert.Equal(t, int64(2), count)
}
