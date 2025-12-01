package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/coinbase/mongobetween/mongo"
)

func TestFilterIsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		filter   *Filter
		expected bool
	}{
		{
			name:     "nil filter",
			filter:   nil,
			expected: true,
		},
		{
			name:     "empty filter",
			filter:   NewFilter(nil, nil, nil, nil, nil, nil),
			expected: true,
		},
		{
			name:     "filter with allowed operations",
			filter:   NewFilter([]string{"find"}, nil, nil, nil, nil, nil),
			expected: false,
		},
		{
			name:     "filter with denied operations",
			filter:   NewFilter(nil, []string{"drop"}, nil, nil, nil, nil),
			expected: false,
		},
		{
			name:     "filter with allowed databases",
			filter:   NewFilter(nil, nil, []string{"app_db"}, nil, nil, nil),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.filter.IsEmpty())
		})
	}
}

func TestFilterCheckOperation(t *testing.T) {
	tests := []struct {
		name       string
		filter     *Filter
		command    mongo.Command
		collection string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "empty filter allows all",
			filter:     NewFilter(nil, nil, nil, nil, nil, nil),
			command:    mongo.Find,
			collection: "test.users",
			wantErr:    false,
		},
		{
			name:       "allowed operations - operation in list",
			filter:     NewFilter([]string{"find", "insert"}, nil, nil, nil, nil, nil),
			command:    mongo.Find,
			collection: "test.users",
			wantErr:    false,
		},
		{
			name:       "allowed operations - operation not in list",
			filter:     NewFilter([]string{"find", "insert"}, nil, nil, nil, nil, nil),
			command:    mongo.Drop,
			collection: "test.users",
			wantErr:    true,
			errMsg:     "operation 'drop' is not in the allowed operations list",
		},
		{
			name:       "denied operations - operation in list",
			filter:     NewFilter(nil, []string{"drop", "dropDatabase"}, nil, nil, nil, nil),
			command:    mongo.Drop,
			collection: "test.users",
			wantErr:    true,
			errMsg:     "operation 'drop' is denied",
		},
		{
			name:       "denied operations - operation not in list",
			filter:     NewFilter(nil, []string{"drop", "dropDatabase"}, nil, nil, nil, nil),
			command:    mongo.Find,
			collection: "test.users",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.filter.Check(tt.command, tt.collection)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilterCheckDatabase(t *testing.T) {
	tests := []struct {
		name       string
		filter     *Filter
		command    mongo.Command
		collection string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "allowed databases - database in list",
			filter:     NewFilter(nil, nil, []string{"app_db", "logs"}, nil, nil, nil),
			command:    mongo.Find,
			collection: "app_db.users",
			wantErr:    false,
		},
		{
			name:       "allowed databases - database not in list",
			filter:     NewFilter(nil, nil, []string{"app_db", "logs"}, nil, nil, nil),
			command:    mongo.Find,
			collection: "admin.users",
			wantErr:    true,
			errMsg:     "database 'admin' is not in the allowed databases list",
		},
		{
			name:       "denied databases - database in list",
			filter:     NewFilter(nil, nil, nil, []string{"admin", "config"}, nil, nil),
			command:    mongo.Find,
			collection: "admin.users",
			wantErr:    true,
			errMsg:     "database 'admin' is denied",
		},
		{
			name:       "denied databases - database not in list",
			filter:     NewFilter(nil, nil, nil, []string{"admin", "config"}, nil, nil),
			command:    mongo.Find,
			collection: "app_db.users",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.filter.Check(tt.command, tt.collection)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilterCheckCollection(t *testing.T) {
	tests := []struct {
		name       string
		filter     *Filter
		command    mongo.Command
		collection string
		wantErr    bool
		errMsg     string
	}{
		{
			name:       "allowed collections - collection in list",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.users", "app_db.orders"}, nil),
			command:    mongo.Find,
			collection: "app_db.users",
			wantErr:    false,
		},
		{
			name:       "allowed collections - collection not in list",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.users", "app_db.orders"}, nil),
			command:    mongo.Find,
			collection: "app_db.secrets",
			wantErr:    true,
			errMsg:     "collection 'app_db.secrets' is not in the allowed collections list",
		},
		{
			name:       "denied collections - collection in list",
			filter:     NewFilter(nil, nil, nil, nil, nil, []string{"app_db.secrets", "app_db.credentials"}),
			command:    mongo.Find,
			collection: "app_db.secrets",
			wantErr:    true,
			errMsg:     "collection 'app_db.secrets' is denied",
		},
		{
			name:       "denied collections - collection not in list",
			filter:     NewFilter(nil, nil, nil, nil, nil, []string{"app_db.secrets", "app_db.credentials"}),
			command:    mongo.Find,
			collection: "app_db.users",
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.filter.Check(tt.command, tt.collection)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilterCombinedFilters(t *testing.T) {
	// Filter that only allows find/insert on app_db.users and app_db.orders
	filter := NewFilter(
		[]string{"find", "insert", "update"},
		[]string{"drop", "dropDatabase"},
		[]string{"app_db"},
		[]string{"admin"},
		[]string{"app_db.users", "app_db.orders"},
		nil,
	)

	tests := []struct {
		name       string
		command    mongo.Command
		collection string
		wantErr    bool
	}{
		{
			name:       "allowed operation on allowed collection",
			command:    mongo.Find,
			collection: "app_db.users",
			wantErr:    false,
		},
		{
			name:       "denied operation on allowed collection",
			command:    mongo.Drop,
			collection: "app_db.users",
			wantErr:    true,
		},
		{
			name:       "allowed operation on denied database",
			command:    mongo.Find,
			collection: "admin.users",
			wantErr:    true,
		},
		{
			name:       "allowed operation on unlisted collection",
			command:    mongo.Find,
			collection: "app_db.secrets",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := filter.Check(tt.command, tt.collection)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSplitCollection(t *testing.T) {
	tests := []struct {
		input    string
		database string
		collName string
	}{
		{"", "", ""},
		{"mydb", "mydb", ""},
		{"mydb.mycoll", "mydb", "mycoll"},
		{"mydb.nested.coll", "mydb", "nested.coll"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			db, coll := splitCollection(tt.input)
			assert.Equal(t, tt.database, db)
			assert.Equal(t, tt.collName, coll)
		})
	}
}

func TestFilterCollectionWildcardPrefix(t *testing.T) {
	tests := []struct {
		name       string
		filter     *Filter
		command    mongo.Command
		collection string
		wantErr    bool
		errMsg     string
	}{
		// Allowed collections with prefix wildcards
		{
			name:       "allowed prefix wildcard - matches",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.users_*"}, nil),
			command:    mongo.Find,
			collection: "app_db.users_archive",
			wantErr:    false,
		},
		{
			name:       "allowed prefix wildcard - matches another",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.users_*"}, nil),
			command:    mongo.Find,
			collection: "app_db.users_backup",
			wantErr:    false,
		},
		{
			name:       "allowed prefix wildcard - does not match",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.users_*"}, nil),
			command:    mongo.Find,
			collection: "app_db.orders",
			wantErr:    true,
			errMsg:     "collection 'app_db.orders' is not in the allowed collections list",
		},
		{
			name:       "allowed prefix wildcard - exact match without wildcard suffix",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.users_*"}, nil),
			command:    mongo.Find,
			collection: "app_db.users_",
			wantErr:    false,
		},
		{
			name:       "allowed mixed exact and prefix - exact match",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.users", "app_db.logs_*"}, nil),
			command:    mongo.Find,
			collection: "app_db.users",
			wantErr:    false,
		},
		{
			name:       "allowed mixed exact and prefix - prefix match",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.users", "app_db.logs_*"}, nil),
			command:    mongo.Find,
			collection: "app_db.logs_2024",
			wantErr:    false,
		},
		{
			name:       "allowed mixed exact and prefix - no match",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.users", "app_db.logs_*"}, nil),
			command:    mongo.Find,
			collection: "app_db.orders",
			wantErr:    true,
			errMsg:     "collection 'app_db.orders' is not in the allowed collections list",
		},
		// Denied collections with prefix wildcards
		{
			name:       "denied prefix wildcard - matches",
			filter:     NewFilter(nil, nil, nil, nil, nil, []string{"app_db.temp_*"}),
			command:    mongo.Find,
			collection: "app_db.temp_data",
			wantErr:    true,
			errMsg:     "collection 'app_db.temp_data' is denied",
		},
		{
			name:       "denied prefix wildcard - does not match",
			filter:     NewFilter(nil, nil, nil, nil, nil, []string{"app_db.temp_*"}),
			command:    mongo.Find,
			collection: "app_db.users",
			wantErr:    false,
		},
		{
			name:       "denied mixed exact and prefix - exact match",
			filter:     NewFilter(nil, nil, nil, nil, nil, []string{"app_db.secrets", "app_db.temp_*"}),
			command:    mongo.Find,
			collection: "app_db.secrets",
			wantErr:    true,
			errMsg:     "collection 'app_db.secrets' is denied",
		},
		{
			name:       "denied mixed exact and prefix - prefix match",
			filter:     NewFilter(nil, nil, nil, nil, nil, []string{"app_db.secrets", "app_db.temp_*"}),
			command:    mongo.Find,
			collection: "app_db.temp_cache",
			wantErr:    true,
			errMsg:     "collection 'app_db.temp_cache' is denied",
		},
		// Edge cases
		{
			name:       "wildcard only prefix - matches everything",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.*"}, nil),
			command:    mongo.Find,
			collection: "app_db.anything",
			wantErr:    false,
		},
		{
			name:       "wildcard only prefix - different db does not match",
			filter:     NewFilter(nil, nil, nil, nil, []string{"app_db.*"}, nil),
			command:    mongo.Find,
			collection: "other_db.anything",
			wantErr:    true,
			errMsg:     "collection 'other_db.anything' is not in the allowed collections list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.filter.Check(tt.command, tt.collection)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilterCheckAllWithWildcards(t *testing.T) {
	tests := []struct {
		name    string
		filter  *Filter
		cmds    []mongo.CommandCollection
		wantErr bool
		errMsg  string
	}{
		{
			name:   "aggregate with $lookup - both match prefix pattern",
			filter: NewFilter(nil, nil, nil, nil, []string{"app_db.data_*"}, nil),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Aggregate, Database: "app_db", Collection: "data_orders"},
				{Command: mongo.Aggregate, Database: "app_db", Collection: "data_products"},
			},
			wantErr: false,
		},
		{
			name:   "aggregate with $lookup - one does not match prefix",
			filter: NewFilter(nil, nil, nil, nil, []string{"app_db.data_*"}, nil),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Aggregate, Database: "app_db", Collection: "data_orders"},
				{Command: mongo.Aggregate, Database: "app_db", Collection: "users"},
			},
			wantErr: true,
			errMsg:  "collection 'app_db.users' is not in the allowed collections list",
		},
		{
			name:   "denied prefix blocks lookup collection",
			filter: NewFilter(nil, nil, nil, nil, nil, []string{"secret_db.*"}),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Aggregate, Database: "app_db", Collection: "orders"},
				{Command: mongo.Aggregate, Database: "secret_db", Collection: "sensitive"},
			},
			wantErr: true,
			errMsg:  "collection 'secret_db.sensitive' is denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.filter.CheckAll(tt.cmds)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFilterCheckAll(t *testing.T) {
	tests := []struct {
		name    string
		filter  *Filter
		cmds    []mongo.CommandCollection
		wantErr bool
		errMsg  string
	}{
		{
			name:   "empty filter allows all",
			filter: NewFilter(nil, nil, nil, nil, nil, nil),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Find, Database: "test", Collection: "users"},
			},
			wantErr: false,
		},
		{
			name:   "single collection allowed",
			filter: NewFilter(nil, nil, []string{"app_db"}, nil, nil, nil),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Aggregate, Database: "app_db", Collection: "orders"},
			},
			wantErr: false,
		},
		{
			name:   "multiple collections all allowed",
			filter: NewFilter(nil, nil, []string{"app_db"}, nil, nil, nil),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Aggregate, Database: "app_db", Collection: "orders"},
				{Command: mongo.Aggregate, Database: "app_db", Collection: "products"},
			},
			wantErr: false,
		},
		{
			name:   "multiple collections one denied database",
			filter: NewFilter(nil, nil, []string{"app_db"}, nil, nil, nil),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Aggregate, Database: "app_db", Collection: "orders"},
				{Command: mongo.Aggregate, Database: "other_db", Collection: "products"},
			},
			wantErr: true,
			errMsg:  "database 'other_db' is not in the allowed databases list",
		},
		{
			name:   "aggregate with $lookup - lookup collection denied",
			filter: NewFilter(nil, nil, nil, []string{"secret_db"}, nil, nil),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Aggregate, Database: "app_db", Collection: "orders"},
				{Command: mongo.Aggregate, Database: "secret_db", Collection: "sensitive"},
			},
			wantErr: true,
			errMsg:  "database 'secret_db' is denied",
		},
		{
			name:   "collection filter with multiple collections",
			filter: NewFilter(nil, nil, nil, nil, []string{"app_db.orders", "app_db.products"}, nil),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Aggregate, Database: "app_db", Collection: "orders"},
				{Command: mongo.Aggregate, Database: "app_db", Collection: "products"},
			},
			wantErr: false,
		},
		{
			name:   "collection filter denies one of multiple collections",
			filter: NewFilter(nil, nil, nil, nil, []string{"app_db.orders"}, nil),
			cmds: []mongo.CommandCollection{
				{Command: mongo.Aggregate, Database: "app_db", Collection: "orders"},
				{Command: mongo.Aggregate, Database: "app_db", Collection: "products"},
			},
			wantErr: true,
			errMsg:  "collection 'app_db.products' is not in the allowed collections list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.filter.CheckAll(tt.cmds)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
