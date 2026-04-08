package mongo_store

import (
	"context"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
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
