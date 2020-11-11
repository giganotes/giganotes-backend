package giganotes

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
)

var db *gorm.DB

// DBConnect function connects to postgres database
func DBConnect(address string) {
	var err error
	db, err = gorm.Open("postgres", address)
	if err != nil {
		panic(err)
	}

	db.AutoMigrate(&User{})
	db.AutoMigrate(&Folder{})
	db.AutoMigrate(&Note{})
	db.AutoMigrate(&Event{})
	db.AutoMigrate(&Feedback{})
	db.AutoMigrate(&UserNoteFavorite{})

	// Optional. Switch the session to a monotonic behavior.

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			log.Println("%v captured - Closing database connection", sig)
			db.Close()
			os.Exit(1)
		}
	}()

}

// User struct stores various user information
type User struct {
	ID                  int64 `gorm:"primary_key"`
	CreatedAt           time.Time
	UpdatedAt           time.Time
	Email               string
	PasswordHash        string
	AccountType         int
	SubscriptionExpires *time.Time
	PasswordRestoreCode string
	EncryptedData       bool `gorm:"default:'false'"`
}

// Note struct is used to store note information
type Note struct {
	ID                 string     `gorm:"primary_key" json:"id"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
	DeletedAt          *time.Time `json:"deletedAt"`
	Title              string     `json:"title"`
	Text               string     `json:"text"`
	FolderID           string     `json:"folderId"`
	UserID             int64      `json:"userId"`
	Level              int64      `json:"level"`
	Encrypted          bool       `gorm:"default:'false'" json:"encrypted"`
	EncryptionCodeHash bool       `gorm:"default:'false'" json:"encryptionCodeHash"`
}

// Folder struct is used to represent folder which contains notes and subfolders
type Folder struct {
	ID        string     `gorm:"primary_key" json:"id"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"deletedAt"`
	Title     string     `json:"title"`
	ParentID  *string    `json:"parentId"`
	UserID    int64      `json:"userId"`
	Level     int64      `json:"level"`
	Children  []Folder   `json:"children"`
	Notes     []Note     `json:"notes"`
}

// SyncShortInfo is intended to return the base information to provide sync
type SyncShortInfo struct {
	ID        string     `json:"id"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"deletedAt"`
	FolderID  string     `json:"folderId"`
}

type Event struct {
	ID         int64     `gorm:"primary_key" json:"id"`
	CreatedAt  time.Time `json:"createdAt"`
	UserID     int64     `json:"userId"`
	Type       int       `json:"type"`
	ClientType int       `json:"clientType"`
	ClientID   string    `json:"clientId"`
}

type Feedback struct {
	ID        int64     `gorm:"primary_key" json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	Message   string    `json:"message"`
}

type UserNoteFavorite struct {
	ID     int64  `gorm:"primary_key" json:"id"`
	UserID int64  `json:"userId"`
	NoteID string `json:"noteId"`
}

//Web socket event

type EventWS struct {
	ClientType int
}
