package mongo_store

import (
	"context"
	"errors"
	"log"
	"net"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	// success
	CodeSuccess = "20000"

	// client
	CodeNotFound     = "40004"
	CodeInvalidInput = "40000"

	// auth
	CodeUnauthorized = "40001"

	// server
	CodeTimeout       = "50001"
	CodeNetworkError  = "50002"
	CodeDBError       = "50003"
	CodeInternalError = "50000"
)

func NewMongoClient(uri string) (*mongo.Client, error) {
	// context Timeout in v2 works without ctx directly on ping/connect mostly, but we define timeout
	clientOptions := options.Client().ApplyURI(uri)
	client, err := mongo.Connect(clientOptions)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}

	log.Println("Connected to MongoDB successfully!")
	return client, nil
}
func ToMongoQueryString(filter bson.M) string {
	data, err := bson.MarshalExtJSON(filter, true, false)
	if err != nil {
		return ""
	}
	return string(data)
}
func BuildMongoFilter(input map[string]any) bson.M {
	filter := bson.M{}

	for k, v := range input {
		switch val := v.(type) {

		// 🔥 case: slice → ใช้ $in
		case []any:
			if len(val) > 0 {
				filter[k] = bson.M{"$in": val}
			}

		// รองรับ []string
		case []string:
			if len(val) > 0 {
				arr := make([]any, len(val))
				for i, s := range val {
					arr[i] = s
				}
				filter[k] = bson.M{"$in": arr}
			}

		// รองรับ []int
		case []int:
			if len(val) > 0 {
				arr := make([]any, len(val))
				for i, n := range val {
					arr[i] = n
				}
				filter[k] = bson.M{"$in": arr}
			}

		// ✅ default: value ปกติ
		default:
			filter[k] = val
		}
	}

	return filter
}

func classifyMongoError(err error) (resultCode string, errMsg string) {
	if err == nil {
		return CodeSuccess, "OK"
	}

	// ⏳ timeout
	if errors.Is(err, context.DeadlineExceeded) {
		return CodeTimeout, "request_timeout"
	}

	if errors.Is(err, context.Canceled) {
		return CodeTimeout, "request_canceled"
	}

	// 🔍 not found
	if errors.Is(err, mongo.ErrNoDocuments) {
		return CodeNotFound, "resource_not_found"
	}

	// 🌐 network error
	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return CodeTimeout, "network_timeout"
		}
		return CodeNetworkError, "network_error"
	}

	// 🧠 mongo command error
	var cmdErr mongo.CommandError
	if errors.As(err, &cmdErr) {
		return CodeDBError, cmdErr.Message
	}

	// 🔐 duplicate key (สำคัญมาก)
	var writeErr mongo.WriteException
	if errors.As(err, &writeErr) {
		for _, e := range writeErr.WriteErrors {
			if e.Code == 11000 {
				return CodeInvalidInput, "duplicate_key"
			}
		}
		return CodeDBError, "database_write_error"
	}

	// fallback
	return CodeInternalError, err.Error()
}

func EnsureIndexes(client *mongo.Client, dbName string) error {
	db := client.Database(dbName)

	// 1. Clients Index
	_, err := db.Collection("clients").Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys:    bson.D{{Key: "_id", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		log.Printf("failed to create clients index: %v", err)
	}

	log.Println("Database indexes ensured successfully.")
	return nil
}
