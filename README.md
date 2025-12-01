# mongobetween
`mongobetween` is a lightweight MongoDB connection pooler written in Golang. It's primary function is to handle a large number of incoming connections, and multiplex them across a smaller connection pool to one or more MongoDB clusters.

`mongobetween` is used in production at Coinbase. It is currently deployed as a Docker sidecar alongside a Rails application using the [Ruby Mongo driver](https://github.com/mongodb/mongo-ruby-driver), connecting to a number of sharded MongoDB clusters. It was designed to connect to `mongos` routers who are responsible for server selection for read/write preferences (connecting directly to a replica set's `mongod` instances hasn't been battle tested).

### How it works
`mongobetween` listens for incoming connections from an application, and proxies any queries to the [MongoDB Go driver](https://github.com/mongodb/mongo-go-driver) which is connected to a MongoDB cluster. It also intercepts any `ismaster` commands from the application, and responds with `"I'm a shard router (mongos)"`, without proxying. This means `mongobetween` appears to the application as an always-available MongoDB shard router, and any MongoDB connection issues or failovers are handled internally by the Go driver.

### Installation
```
go install github.com/coinbase/mongobetween
```

### Usage
```
Usage: mongobetween [OPTIONS] address1=uri1 [address2=uri2] ...
  -loglevel string
    	One of: debug, info, warn, error, dpanic, panic, fatal (default "info")
  -network string
    	One of: tcp, tcp4, tcp6, unix or unixpacket (default "tcp4")
  -password string
    	MongoDB password
  -ping
    	Ping downstream MongoDB before listening
  -pretty
    	Pretty print logging
  -statsd string
    	Statsd address (default "localhost:8125")
  -unlink
    	Unlink existing unix sockets before listening
  -username string
    	MongoDB username
  -dynamic string
    	File or URL to query for dynamic configuration
  -enable-sdam-metrics
        Enable SDAM(Server Discovery And Monitoring) metrics
  -enable-sdam-logging
        Enable SDAM(Server Discovery And Monitoring) logging
  -allowed-operations string
    	Comma-separated list of allowed MongoDB operations (e.g., find,insert,update)
  -denied-operations string
    	Comma-separated list of denied MongoDB operations (e.g., drop,dropDatabase)
  -allowed-databases string
    	Comma-separated list of allowed database names
  -denied-databases string
    	Comma-separated list of denied database names
  -allowed-collections string
    	Comma-separated list of allowed collections (format: db.collection, supports wildcard prefix: db.prefix*)
  -denied-collections string
    	Comma-separated list of denied collections (format: db.collection, supports wildcard prefix: db.prefix*)
  -proxy-auth string
    	Comma-separated list of proxy authentication credentials (format: user:pass,user2:pass2)
```

TCP socket example:
```
mongobetween ":27016=mongodb+srv://username:password@cluster.mongodb.net/database?maxpoolsize=10&label=cluster0"
```

Unix socket example:
```
mongobetween -network unix "/tmp/mongo.sock=mongodb+srv://username:password@cluster.mongodb.net/database?maxpoolsize=10&label=cluster0"
```

Proxying multiple clusters:
```
mongobetween -network unix \
  "/tmp/mongo1.sock=mongodb+srv://username:password@cluster1.mongodb.net/database?maxpoolsize=10&label=cluster1" \
  "/tmp/mongo2.sock=mongodb+srv://username:password@cluster2.mongodb.net/database?maxpoolsize=10&label=cluster2"
```

The `label` query parameter in the connection URI is used to any tag statsd metrics or logs for that connection.

### Dynamic configuration

Passing a file or URL as the `-dynamic` argument will allow somewhat dynamic configuration of `mongobetween`. Example supported file format:
```json
{
  "Clusters": {
    ":12345": {
      "DisableWrites": true,
      "RedirectTo": ""
    },
    "/var/tmp/cluster1.sock": {
      "DisableWrites": false,
      "RedirectTo": "/var/tmp/cluster2.sock"
    }
  }
}
```

This will disable writes to the proxy served from address `:12345`, and redirect any traffic sent to `/var/tmp/cluster1.sock` to the proxy running on `/var/tmp/cluster2.sock`. This is useful for minimal-downtime migrations between clusters.

### Operation and Collection Filtering

`mongobetween` supports filtering MongoDB operations at the proxy level. This allows you to restrict which operations, databases, and collections can be accessed through the proxy.

#### Filtering Operations

You can allow or deny specific MongoDB operations:

```bash
# Only allow read operations
mongobetween -allowed-operations "find,aggregate,count" \
  ":27016=mongodb://localhost:27017/database"

# Block destructive operations
mongobetween -denied-operations "drop,dropDatabase,delete" \
  ":27016=mongodb://localhost:27017/database"
```

Supported operations include: `find`, `insert`, `update`, `delete`, `aggregate`, `count`, `distinct`, `findAndModify`, `mapReduce`, `createIndexes`, `dropIndexes`, `drop`, `dropDatabase`, `listCollections`, `listIndexes`, `listDatabases`, `getMore`, and more.

#### Filtering Databases

Restrict access to specific databases:

```bash
# Only allow access to specific databases
mongobetween -allowed-databases "app_db,analytics" \
  ":27016=mongodb://localhost:27017/database"

# Block access to admin databases
mongobetween -denied-databases "admin,config,local" \
  ":27016=mongodb://localhost:27017/database"
```

#### Filtering Collections

Restrict access to specific collections. Collections are specified in `database.collection` format:

```bash
# Only allow access to specific collections
mongobetween -allowed-collections "app_db.users,app_db.orders" \
  ":27016=mongodb://localhost:27017/database"

# Block access to sensitive collections
mongobetween -denied-collections "app_db.credentials,app_db.secrets" \
  ":27016=mongodb://localhost:27017/database"
```

#### Wildcard Collection Patterns

Collection filters support wildcard prefix matching using `*` at the end:

```bash
# Allow all collections starting with "public_"
mongobetween -allowed-collections "app_db.public_*" \
  ":27016=mongodb://localhost:27017/database"

# Block all temporary collections
mongobetween -denied-collections "app_db.temp_*,app_db.cache_*" \
  ":27016=mongodb://localhost:27017/database"

# Allow all collections in a database
mongobetween -allowed-collections "app_db.*" \
  ":27016=mongodb://localhost:27017/database"
```

#### Combining Filters

Multiple filter types can be combined:

```bash
# Read-only access to specific collections
mongobetween \
  -allowed-operations "find,aggregate,count" \
  -allowed-databases "app_db" \
  -denied-collections "app_db.internal_*" \
  ":27016=mongodb://localhost:27017/database"
```

When an operation is filtered, the proxy returns a proper MongoDB error response with code `13` (Unauthorized), allowing clients to handle the error gracefully.

### Proxy Authentication

`mongobetween` can require clients to authenticate to the proxy itself before accessing the upstream MongoDB cluster. This is separate from MongoDB's native authentication and provides an additional layer of access control.

#### Configuring Proxy Authentication

Enable proxy authentication by providing user credentials:

```bash
# Single user
mongobetween -proxy-auth "appuser:secretpassword" \
  ":27016=mongodb://localhost:27017/database"

# Multiple users
mongobetween -proxy-auth "user1:pass1,user2:pass2,readonly:readonlypass" \
  ":27016=mongodb://localhost:27017/database"
```

#### Connecting with Authentication

Clients must authenticate using SCRAM-SHA-256. Most MongoDB drivers support this automatically when credentials are provided in the connection URI:

```
mongodb://appuser:secretpassword@localhost:27016/database
```

Or with explicit mechanism specification:

```
mongodb://appuser:secretpassword@localhost:27016/database?authMechanism=SCRAM-SHA-256
```

#### How It Works

1. When proxy authentication is enabled, the proxy intercepts `saslStart` and `saslContinue` commands
2. The proxy performs SCRAM-SHA-256 authentication using the configured credentials
3. Once authenticated, the connection is marked as authenticated and subsequent commands are proxied to MongoDB
4. Unauthenticated connections can only send `isMaster`/`hello` commands; all other commands are rejected

#### Security Notes

- Passwords are never stored in plaintext; they are stored as salted PBKDF2-derived keys
- Each user has a unique salt generated with cryptographically secure random bytes
- The SCRAM-SHA-256 protocol ensures passwords are never sent over the wire in plaintext
- Proxy authentication is independent of MongoDB authentication - you may use both for defense in depth

### TODO

Current known missing features:
 - [X] Transaction server pinning
 - [X] Different cursors on separate servers with the same cursor ID value


### Statsd
`mongobetween` supports reporting health metrics to a local statsd sidecar, using the [Datadog Go library](github.com/DataDog/datadog-go). By default it reports to `localhost:8125`. The following metrics are reported:
 - `mongobetween.handle_message` (Timing) - end-to-end time handling an incoming message from the application
 - `mongobetween.round_trip` (Timing) - round trip time sending a request and receiving a response from MongoDB
 - `mongobetween.request_size` (Distribution) - request size to MongoDB
 - `mongobetween.response_size` (Distribution) - response size from MongoDB
 - `mongobetween.open_connections` (Gauge) - number of open connections between the proxy and the application
 - `mongobetween.connection_opened` (Counter) - connection opened with the application
 - `mongobetween.connection_closed` (Counter) - connection closed with the application
 - `mongobetween.cursors` (Gauge) - number of open cursors being tracked (for cursor -> server mapping)
 - `mongobetween.transactions` (Gauge) - number of transactions being tracked (for client sessions -> server mapping)****
 - `mongobetween.server_selection` (Timing) - Go driver server selection timing
 - `mongobetween.checkout_connection` (Timing) - Go driver connection checkout timing
 - `mongobetween.pool.checked_out_connections` (Gauge) - number of connections checked out from the Go driver connection pool
 - `mongobetween.pool.open_connections` (Gauge) - number of open connections from the Go driver to MongoDB
 - `mongobetween.pool_event.connection_closed` (Counter) - Go driver connection closed
 - `mongobetween.pool_event.connection_pool_created` (Counter) - Go driver connection pool created
 - `mongobetween.pool_event.connection_created` (Counter) - Go driver connection created
 - `mongobetween.pool_event.connection_check_out_failed` (Counter) - Go driver connection check out failed
 - `mongobetween.pool_event.connection_checked_out` (Counter) - Go driver connection checked out
 - `mongobetween.pool_event.connection_checked_in` (Counter) - Go driver connection checked in
 - `mongobetween.pool_event.connection_pool_cleared` (Counter) - Go driver connection pool cleared
 - `mongobetween.pool_event.connection_pool_closed` (Counter) - Go driver connection pool closed

### Background
`mongobetween` was built to address a connection storm issue between a high scale Rails app and MongoDB (see [blog post](https://blog.coinbase.com/scaling-connections-with-ruby-and-mongodb-99204dbf8857)). Due to Ruby MRI's global interpreter lock, multi-threaded web applications don't utilize multiple CPU cores. To achieve better CPU utilization, Puma is run with multiple workers (processes), each of which need a separate MongoDB connection pool. This leads to a large number of connections to MongoDB, sometimes exceeding MongoDB's upstream connection limit of 128k connections.

`mongobetween` has reduced connection counts by an order of magnitude, spikes of up to 30k connections are now reduced to around 2k. It has also significantly reduced `ismaster` commands on the cluster, as there's only a single monitor goroutine per `mongobetween` process, instead of a monitor thread for each Ruby process.
