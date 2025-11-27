package mongo

import (
	"go.mongodb.org/mongo-driver/x/bsonx/bsoncore"
)

// CommandCollection represents a command and its target collection.
type CommandCollection struct {
	Command    Command
	Database   string
	Collection string
}

type Command string

const (
	Unknown           Command = "unknown"
	AbortTransaction  Command = "abortTransaction"
	Aggregate         Command = "aggregate"
	CommitTransaction Command = "commitTransaction"
	Count             Command = "count"
	CreateIndexes     Command = "createIndexes"
	Delete            Command = "delete"
	Distinct          Command = "distinct"
	Drop              Command = "drop"
	DropDatabase      Command = "dropDatabase"
	DropIndexes       Command = "dropIndexes"
	EndSessions       Command = "endSessions"
	Find              Command = "find"
	FindAndModify     Command = "findAndModify"
	GetMore           Command = "getMore"
	Insert            Command = "insert"
	IsMaster          Command = "isMaster"
	Ismaster          Command = "ismaster"
	GetLastError      Command = "getlasterror"
	ListCollections   Command = "listCollections"
	ListIndexes       Command = "listIndexes"
	ListDatabases     Command = "listDatabases"
	MapReduce         Command = "mapReduce"
	Update            Command = "update"
	SaslStart         Command = "saslStart"
	SaslContinue      Command = "saslContinue"
)

var collectionCommands = []Command{Aggregate, Count, CreateIndexes, Delete, Distinct, Drop, DropIndexes, Find, FindAndModify, Insert, ListIndexes, MapReduce, Update, GetLastError, SaslStart, SaslContinue}
var int32Commands = []Command{AbortTransaction, Aggregate, CommitTransaction, DropDatabase, IsMaster, Ismaster, ListCollections, ListDatabases}
var int64Commands = []Command{GetMore}
var arrayCommands = []Command{EndSessions}

func IsWrite(command Command) bool {
	switch command {
	case CommitTransaction, CreateIndexes, Delete, Drop, DropIndexes, DropDatabase, FindAndModify, Insert, Update:
		return true
	}
	return false
}

func CommandAndCollection(msg bsoncore.Document) (Command, string) {
	for _, s := range collectionCommands {
		value := msg.Lookup(string(s))
		if col, ok := value.StringValueOK(); ok {
			return s, col
		} else if _, ok = value.Int32OK(); ok {
			return s, ""
		}
	}
	for _, s := range int32Commands {
		value := msg.Lookup(string(s))
		if value.Data != nil {
			return s, ""
		}
	}
	for _, s := range int64Commands {
		value := msg.Lookup(string(s))
		if value.Data != nil {
			if coll, ok := msg.Lookup("collection").StringValueOK(); ok {
				return s, coll
			}
			return s, ""
		}
	}
	for _, s := range arrayCommands {
		value := msg.Lookup(string(s))
		if value.Data != nil {
			return s, ""
		}
	}
	return Unknown, ""
}

func IsIsMasterDoc(doc bsoncore.Document) bool {
	isMaster := doc.Lookup(string(IsMaster))
	ismaster := doc.Lookup(string(Ismaster))
	getLastError := doc.Lookup(string(GetLastError))
	return IsIsMasterValueTruthy(isMaster) || IsIsMasterValueTruthy(ismaster) || IsIsMasterValueTruthy(getLastError)
}

func IsIsMasterValueTruthy(val bsoncore.Value) bool {
	if intValue, isInt := val.Int32OK(); intValue > 0 {
		return true
	} else if !isInt {
		boolValue, isBool := val.BooleanOK()
		return boolValue && isBool
	}
	return false
}

// CommandsAndCollections extracts all command/collection pairs from a BSON document.
// This handles commands that may reference multiple collections like aggregate with
// $lookup, $merge, $out, $unionWith stages.
func CommandsAndCollections(msg bsoncore.Document) []CommandCollection {
	command, collection := CommandAndCollection(msg)
	if command == Unknown {
		return nil
	}

	// Get the database from $db field
	database, _ := msg.Lookup("$db").StringValueOK()

	result := []CommandCollection{{
		Command:    command,
		Database:   database,
		Collection: collection,
	}}

	// For aggregate commands, parse the pipeline for additional collections
	if command == Aggregate {
		result = append(result, extractAggregateCollections(msg, database)...)
	}

	// For mapReduce, check the out option
	if command == MapReduce {
		result = append(result, extractMapReduceOut(msg, database)...)
	}

	return result
}

// extractAggregateCollections parses aggregate pipeline stages that reference other collections.
func extractAggregateCollections(msg bsoncore.Document, defaultDB string) []CommandCollection {
	var result []CommandCollection

	pipeline, ok := msg.Lookup("pipeline").ArrayOK()
	if !ok {
		return result
	}

	values, err := pipeline.Values()
	if err != nil {
		return result
	}

	for _, val := range values {
		stage, ok := val.DocumentOK()
		if !ok {
			continue
		}

		// $lookup stage
		if lookup := stage.Lookup("$lookup"); lookup.Data != nil {
			if lookupDoc, ok := lookup.DocumentOK(); ok {
				if from, ok := lookupDoc.Lookup("from").StringValueOK(); ok {
					db := defaultDB
					// Check if there's a db field in lookup (MongoDB 5.1+)
					if lookupDB, ok := lookupDoc.Lookup("db").StringValueOK(); ok {
						db = lookupDB
					}
					result = append(result, CommandCollection{
						Command:    Aggregate,
						Database:   db,
						Collection: from,
					})
				}
			}
		}

		// $unionWith stage
		if unionWith := stage.Lookup("$unionWith"); unionWith.Data != nil {
			// Can be a string (collection name) or document with coll field
			if coll, ok := unionWith.StringValueOK(); ok {
				result = append(result, CommandCollection{
					Command:    Aggregate,
					Database:   defaultDB,
					Collection: coll,
				})
			} else if unionDoc, ok := unionWith.DocumentOK(); ok {
				if coll, ok := unionDoc.Lookup("coll").StringValueOK(); ok {
					db := defaultDB
					if unionDB, ok := unionDoc.Lookup("db").StringValueOK(); ok {
						db = unionDB
					}
					result = append(result, CommandCollection{
						Command:    Aggregate,
						Database:   db,
						Collection: coll,
					})
				}
			}
		}

		// $merge stage
		if merge := stage.Lookup("$merge"); merge.Data != nil {
			// Can be a string (collection name) or document with into field
			if coll, ok := merge.StringValueOK(); ok {
				result = append(result, CommandCollection{
					Command:    Aggregate,
					Database:   defaultDB,
					Collection: coll,
				})
			} else if mergeDoc, ok := merge.DocumentOK(); ok {
				if into := mergeDoc.Lookup("into"); into.Data != nil {
					if coll, ok := into.StringValueOK(); ok {
						db := defaultDB
						if mergeDB, ok := mergeDoc.Lookup("db").StringValueOK(); ok {
							db = mergeDB
						}
						result = append(result, CommandCollection{
							Command:    Aggregate,
							Database:   db,
							Collection: coll,
						})
					} else if intoDoc, ok := into.DocumentOK(); ok {
						if coll, ok := intoDoc.Lookup("coll").StringValueOK(); ok {
							db := defaultDB
							if intoDB, ok := intoDoc.Lookup("db").StringValueOK(); ok {
								db = intoDB
							}
							result = append(result, CommandCollection{
								Command:    Aggregate,
								Database:   db,
								Collection: coll,
							})
						}
					}
				}
			}
		}

		// $out stage
		if out := stage.Lookup("$out"); out.Data != nil {
			// Can be a string (collection name) or document with db and coll fields
			if coll, ok := out.StringValueOK(); ok {
				result = append(result, CommandCollection{
					Command:    Aggregate,
					Database:   defaultDB,
					Collection: coll,
				})
			} else if outDoc, ok := out.DocumentOK(); ok {
				if coll, ok := outDoc.Lookup("coll").StringValueOK(); ok {
					db := defaultDB
					if outDB, ok := outDoc.Lookup("db").StringValueOK(); ok {
						db = outDB
					}
					result = append(result, CommandCollection{
						Command:    Aggregate,
						Database:   db,
						Collection: coll,
					})
				}
			}
		}

		// $graphLookup stage
		if graphLookup := stage.Lookup("$graphLookup"); graphLookup.Data != nil {
			if graphDoc, ok := graphLookup.DocumentOK(); ok {
				if from, ok := graphDoc.Lookup("from").StringValueOK(); ok {
					result = append(result, CommandCollection{
						Command:    Aggregate,
						Database:   defaultDB,
						Collection: from,
					})
				}
			}
		}
	}

	return result
}

// extractMapReduceOut parses the out option from a mapReduce command.
func extractMapReduceOut(msg bsoncore.Document, defaultDB string) []CommandCollection {
	var result []CommandCollection

	out := msg.Lookup("out")
	if out.Data == nil {
		return result
	}

	// out can be a string (collection name) or document
	if coll, ok := out.StringValueOK(); ok {
		result = append(result, CommandCollection{
			Command:    MapReduce,
			Database:   defaultDB,
			Collection: coll,
		})
	} else if outDoc, ok := out.DocumentOK(); ok {
		// Check for replace, merge, or reduce actions
		for _, action := range []string{"replace", "merge", "reduce"} {
			if coll, ok := outDoc.Lookup(action).StringValueOK(); ok {
				db := defaultDB
				if outDB, ok := outDoc.Lookup("db").StringValueOK(); ok {
					db = outDB
				}
				result = append(result, CommandCollection{
					Command:    MapReduce,
					Database:   db,
					Collection: coll,
				})
				break
			}
		}
	}

	return result
}
