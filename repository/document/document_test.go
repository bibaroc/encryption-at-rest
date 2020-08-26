package document_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"io"
	"testing"

	"github.com/bibaroc/encryption-at-rest/pkg/db"
	"github.com/bibaroc/encryption-at-rest/repository/document"
	"github.com/bibaroc/encryption-at-rest/repository/user"
)

func TestDocumentsShouldBeEncryptedAtRest(t *testing.T) {
	documentContents := []byte("here are some secret contents that should be encrypted at rest")

	db := GetDB(t)
	username := randString(5)
	password := randString(5)

	userRepository := GetUserRepository(t, db)
	if _, _, err := userRepository.CreateUser(context.Background(), username, password); err != nil {
		t.Fatal(err)
	}
	documentRepository := GetDocumentRepository(t, db)
	documentID, err := documentRepository.New(context.Background(), documentContents)
	if err != nil {
		t.Fatal(err)
	}
	if documentID <= 0 {
		t.Fatalf("Expected positive document id, got %d\n", documentID)
	}
	var savedContents []byte
	err = db.QueryRowContext(context.Background(), "select contents from documents d where d.id = $1;", documentID).
		Scan(&savedContents)
	if err != nil {
		t.Fatal(err)
	}
	if string(documentContents) == string(savedContents) {
		t.Fatalf("Expected saved document contents to be different from the actual ones.\n")
	}
}

func TestReadEncryptedDocumentAsLogedInUser(t *testing.T) {
	documentContents := []byte("here are some secret contents that should be encrypted at rest")

	db := GetDB(t)
	username := randString(5)
	password := randString(5)

	userRepository := GetUserRepository(t, db)
	documentRepository := GetDocumentRepository(t, db)

	if _, _, err := userRepository.CreateUser(context.Background(), username, password); err != nil {
		t.Fatal(err)
	}

	documentID, err := documentRepository.New(context.Background(), documentContents)
	if err != nil {
		t.Fatal(err)
	}
	if documentID <= 0 {
		t.Fatalf("Expected positive document id, got %d\n", documentID)
	}

	userInfo, err := userRepository.Login(context.Background(), username, password)
	if err != nil {
		t.Fatal(err)
	}

	fetchedDocumentContents, err := documentRepository.Get(context.Background(), userInfo, documentID)
	if err != nil {
		t.Fatal(err)
	}
	if string(fetchedDocumentContents) != string(documentContents) {
		t.Fatalf("Expected fetched document contents to be the same as the original one. Expected:\n%s\nGot:\n%s\n",
			documentContents, fetchedDocumentContents)
	}
}

func GetDB(t *testing.T) *sql.DB {
	sqlDB, err := db.PGConnect(db.DBConfigurationFromEnv())
	if err != nil {
		t.Fatal(err)
	}
	return sqlDB
}
func GetDocumentRepository(t *testing.T, db *sql.DB) *document.Repository {
	return document.NewRepository(db)
}

func GetUserRepository(t *testing.T, db *sql.DB) *user.Repository {
	return user.NewRepository(db)
}

// randString works best with EVEN numbers
// odd values will be subtraced 1 due to hex encoding internals
func randString(ln int) string {
	s := make([]byte, hex.DecodedLen(ln))
	_, err := io.ReadFull(rand.Reader, s)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(s)
}
