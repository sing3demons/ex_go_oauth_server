package models

import "time"

type AuditLog struct {
	ID         string    `bson:"_id,omitempty" json:"id"`
	UserID     string    `bson:"user_id" json:"user_id"`
	Event      string    `bson:"event" json:"event"` // login_success, login_failed, logout
	IPAddress  string    `bson:"ip_address" json:"ip_address"`
	UserAgent  string    `bson:"user_agent" json:"user_agent"`
	DeviceInfo string    `bson:"device_info" json:"device_info"`
	Reason     string    `bson:"reason,omitempty" json:"reason,omitempty"`
	CreatedAt  time.Time `bson:"created_at" json:"created_at"`
}
