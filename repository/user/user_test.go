package user_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"io"
	"testing"

	"github.com/bibaroc/encryption-at-rest/pkg/db"
	"github.com/bibaroc/encryption-at-rest/repository/user"
)

func TestAddUserAndLogin(t *testing.T) {
	userRepository := GetUserRepository(t)
	username := randString(6)
	password := randString(6)

	userID, recoveryCode, err := userRepository.CreateUser(context.Background(), username, password)
	if err != nil {
		t.Fatal(err)
	}
	if recoveryCode == "" {
		t.Fatalf("Expected non empty recovery code, got %s\n", recoveryCode)
	}
	if userID <= 0 {
		t.Fatalf("Expected positive userid, got %d\n", userID)
	}

	usersCrypto, err := userRepository.Login(context.Background(), username, password)
	if err != nil {
		t.Fatal(err)
	}
	if usersCrypto.PrivateKey == nil {
		t.Fatalf("Expected non nil private key\n")
	}
	if usersCrypto.PublicKey == nil {
		t.Fatalf("Expected non nil public key\n")
	}
}

func TestPublicKeyMarshalUnmarshal(t *testing.T) {
	pkey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	keyData := x509.MarshalPKCS1PublicKey(&pkey.PublicKey)
	if keyData == nil {
		t.Fatalf("Expected non nil public key data\n")
	}
	publicKey, err := x509.ParsePKCS1PublicKey(keyData)
	if err != nil {
		t.Fatal(err)
	}
	if publicKey == nil {
		t.Fatalf("Expected non nil public key\n")
	}
}

func GetUserRepository(t *testing.T) *user.Repository {
	sqlDB, err := db.PGConnect(db.DBConfigurationFromEnv())
	if err != nil {
		t.Fatal(err)
	}
	return user.NewRepository(sqlDB)
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
