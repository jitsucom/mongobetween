package proxy

import (
	"fmt"
	"strings"

	"github.com/coinbase/mongobetween/mongo"
)

// Filter holds configuration for filtering MongoDB operations, databases, and collections.
type Filter struct {
	AllowedOperations  []string
	DeniedOperations   []string
	AllowedDatabases   []string
	DeniedDatabases    []string
	AllowedCollections []string
	DeniedCollections  []string

	// Pre-computed maps for O(1) lookup
	allowedOpsMap   map[string]bool
	deniedOpsMap    map[string]bool
	allowedDbsMap   map[string]bool
	deniedDbsMap    map[string]bool
	allowedCollsMap map[string]bool
	deniedCollsMap  map[string]bool

	// Prefix patterns for collections (entries ending with *)
	allowedCollsPrefixes []string
	deniedCollsPrefixes  []string
}

// NewFilter creates a new Filter with the given allow/deny lists.
func NewFilter(allowedOps, deniedOps, allowedDbs, deniedDbs, allowedColls, deniedColls []string) *Filter {
	f := &Filter{
		AllowedOperations:  allowedOps,
		DeniedOperations:   deniedOps,
		AllowedDatabases:   allowedDbs,
		DeniedDatabases:    deniedDbs,
		AllowedCollections: allowedColls,
		DeniedCollections:  deniedColls,
	}
	f.buildMaps()
	return f
}

func (f *Filter) buildMaps() {
	f.allowedOpsMap = sliceToMap(f.AllowedOperations)
	f.deniedOpsMap = sliceToMap(f.DeniedOperations)
	f.allowedDbsMap = sliceToMap(f.AllowedDatabases)
	f.deniedDbsMap = sliceToMap(f.DeniedDatabases)

	// Separate exact matches from prefix patterns for collections
	f.allowedCollsMap, f.allowedCollsPrefixes = sliceToMapAndPrefixes(f.AllowedCollections)
	f.deniedCollsMap, f.deniedCollsPrefixes = sliceToMapAndPrefixes(f.DeniedCollections)
}

func sliceToMap(slice []string) map[string]bool {
	if len(slice) == 0 {
		return nil
	}
	m := make(map[string]bool, len(slice))
	for _, s := range slice {
		m[s] = true
	}
	return m
}

// sliceToMapAndPrefixes separates exact matches from wildcard prefix patterns.
// Entries ending with "*" are treated as prefix patterns (the * is stripped).
// Returns a map for exact matches and a slice of prefixes.
func sliceToMapAndPrefixes(slice []string) (map[string]bool, []string) {
	if len(slice) == 0 {
		return nil, nil
	}
	m := make(map[string]bool)
	var prefixes []string
	for _, s := range slice {
		if strings.HasSuffix(s, "*") {
			// Strip the * and add as prefix pattern
			prefixes = append(prefixes, strings.TrimSuffix(s, "*"))
		} else {
			m[s] = true
		}
	}
	if len(m) == 0 {
		m = nil
	}
	return m, prefixes
}

// IsEmpty returns true if no filters are configured.
func (f *Filter) IsEmpty() bool {
	return f == nil ||
		(len(f.AllowedOperations) == 0 &&
			len(f.DeniedOperations) == 0 &&
			len(f.AllowedDatabases) == 0 &&
			len(f.DeniedDatabases) == 0 &&
			len(f.AllowedCollections) == 0 &&
			len(f.DeniedCollections) == 0)
}

// Check validates if the given operation on the specified collection is allowed.
// Returns nil if allowed, or an error describing why the operation was denied.
// Deprecated: Use CheckAll for better support of multi-collection operations.
func (f *Filter) Check(command mongo.Command, collection string) error {
	if f.IsEmpty() {
		return nil
	}

	cmdStr := string(command)

	// Check operation filters
	if err := f.checkOperation(cmdStr); err != nil {
		return err
	}

	// Extract database from collection (format: "database.collection" or just "database")
	database, collName := splitCollection(collection)

	// Check database filters
	if err := f.checkDatabase(database); err != nil {
		return err
	}

	// Check collection filters (only if collection is specified)
	if collection != "" {
		if err := f.checkCollection(collection, database, collName); err != nil {
			return err
		}
	}

	return nil
}

// CheckAll validates all command/collection pairs from an operation.
// This properly handles commands that reference multiple collections (like aggregate with $lookup).
// Returns nil if all are allowed, or an error describing why the operation was denied.
func (f *Filter) CheckAll(cmdColls []mongo.CommandCollection) error {
	if f.IsEmpty() {
		return nil
	}

	for _, cc := range cmdColls {
		cmdStr := string(cc.Command)

		// Check operation filters
		if err := f.checkOperation(cmdStr); err != nil {
			return err
		}

		// Check database filters
		if err := f.checkDatabase(cc.Database); err != nil {
			return err
		}

		// Check collection filters (only if collection is specified)
		if cc.Collection != "" {
			fullCollection := cc.Collection
			if cc.Database != "" {
				fullCollection = cc.Database + "." + cc.Collection
			}
			if err := f.checkCollection(fullCollection, cc.Database, cc.Collection); err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *Filter) checkOperation(cmd string) error {
	// If allowed list is set, command must be in it
	if len(f.allowedOpsMap) > 0 {
		if !f.allowedOpsMap[cmd] {
			return fmt.Errorf("operation '%s' is not in the allowed operations list", cmd)
		}
	}

	// If denied list is set, command must not be in it
	if len(f.deniedOpsMap) > 0 {
		if f.deniedOpsMap[cmd] {
			return fmt.Errorf("operation '%s' is denied", cmd)
		}
	}

	return nil
}

func (f *Filter) checkDatabase(database string) error {
	if database == "" {
		return nil
	}

	// If allowed list is set, database must be in it
	if len(f.allowedDbsMap) > 0 {
		if !f.allowedDbsMap[database] {
			return fmt.Errorf("database '%s' is not in the allowed databases list", database)
		}
	}

	// If denied list is set, database must not be in it
	if len(f.deniedDbsMap) > 0 {
		if f.deniedDbsMap[database] {
			return fmt.Errorf("database '%s' is denied", database)
		}
	}

	return nil
}

func (f *Filter) checkCollection(fullCollection, database, collName string) error {
	// If allowed list is set, collection must match (exact or prefix)
	if len(f.allowedCollsMap) > 0 || len(f.allowedCollsPrefixes) > 0 {
		if !f.matchesAllowedCollection(fullCollection) {
			return fmt.Errorf("collection '%s' is not in the allowed collections list", fullCollection)
		}
	}

	// If denied list is set, collection must not match (exact or prefix)
	if len(f.deniedCollsMap) > 0 || len(f.deniedCollsPrefixes) > 0 {
		if f.matchesDeniedCollection(fullCollection) {
			return fmt.Errorf("collection '%s' is denied", fullCollection)
		}
	}

	return nil
}

// matchesAllowedCollection checks if the collection matches any allowed pattern (exact or prefix).
func (f *Filter) matchesAllowedCollection(collection string) bool {
	// Check exact match first
	if f.allowedCollsMap[collection] {
		return true
	}
	// Check prefix patterns
	for _, prefix := range f.allowedCollsPrefixes {
		if strings.HasPrefix(collection, prefix) {
			return true
		}
	}
	return false
}

// matchesDeniedCollection checks if the collection matches any denied pattern (exact or prefix).
func (f *Filter) matchesDeniedCollection(collection string) bool {
	// Check exact match first
	if f.deniedCollsMap[collection] {
		return true
	}
	// Check prefix patterns
	for _, prefix := range f.deniedCollsPrefixes {
		if strings.HasPrefix(collection, prefix) {
			return true
		}
	}
	return false
}

// splitCollection splits a "database.collection" string into database and collection parts.
// If there's no dot, returns the input as database with empty collection.
func splitCollection(collection string) (database, collName string) {
	if collection == "" {
		return "", ""
	}
	idx := strings.Index(collection, ".")
	if idx == -1 {
		return collection, ""
	}
	return collection[:idx], collection[idx+1:]
}
