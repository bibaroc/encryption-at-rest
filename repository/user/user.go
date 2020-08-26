package user

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/bibaroc/encryption-at-rest/pkg/cryptoutils"

	"golang.org/x/crypto/bcrypt"
)

type Repository struct {
	db *sql.DB
}

// CreateUser returns a new UID, recovery code and an error.
//
// The second value is a recovery code that can be used to decrypt the user's private key,
// allowing for password reset even when the user forgets his old credentials.
func (r *Repository) CreateUser(ctx context.Context, username, password string) (int64, string, error) {
	// this hashed value will be used for authentication
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, "", fmt.Errorf("Couldn't hash user's password, %w", err)
	}

	// two copies of this will be saved, one encrypted via KEK one via recovery code
	pkey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return 0, "", fmt.Errorf("Couldn't generate private key, %w", err)
	}

	encodedPublicKey := x509.MarshalPKCS1PublicKey(&pkey.PublicKey)
	encodedPrivateKey := x509.MarshalPKCS1PrivateKey(pkey)

	// private key is encrypted using an ephimeral key generated from user's password
	kekBlock, err := BlockForString(password)
	if err != nil {
		return 0, "", err
	}
	kekEncryptedPrivateKey, err := cryptoutils.EncryptWithBlock(kekBlock, encodedPrivateKey)
	if err != nil {
		return 0, "", fmt.Errorf("Couldn't encrypt user's private key, %w", err)
	}
	// private key is also encrypted using a random recovery code.
	// this recovery code could potentialy be generated from a set of user questions like
	//
	// - What was you nickname as a child?
	recoveryCode, recoveryCodeBlock, err := cryptoutils.RandomKey()
	if err != nil {
		return 0, "", err
	}
	recoveryCodeEncryptedPrivateKey, err := cryptoutils.EncryptWithBlock(recoveryCodeBlock, encodedPrivateKey)
	if err != nil {
		return 0, "", fmt.Errorf("Couldn't encrypt user's private key recovery, %w", err)
	}

	const q = `insert into users (name, "password", public_key, private_key, private_key_recovery) 
		values ($1, $2, $3, $4, $5) returning id;`
	var userID int64
	err = r.db.QueryRowContext(ctx, q,
		username,
		hashedPassword,
		encodedPublicKey,
		kekEncryptedPrivateKey,
		recoveryCodeEncryptedPrivateKey,
	).Scan(&userID)
	if err != nil {
		return 0, "", fmt.Errorf("Couldn't insert users data, %w", err)
	}
	return userID, hex.EncodeToString(recoveryCode), nil
}

// Login returns desired user's crypto details.
// Returns err != nil when authentication has failed.
// Returned CryptoSuite is UNENCRYPTED.recoveryCode
func (r *Repository) Login(ctx context.Context, username, password string) (CryptoSuite, error) {
	var hashedPassword string
	var plainPublicKey, encryptedPrivateKey []byte
	const q = `select u."password", u.public_key, u.private_key from users u where u."name" = $1;`
	err := r.db.QueryRowContext(ctx, q, username).Scan(
		&hashedPassword,
		&plainPublicKey,
		&encryptedPrivateKey,
	)
	if err == sql.ErrNoRows {
		log.Printf("Login attempt for non registered user %s\n", username)
		return CryptoSuite{}, fmt.Errorf("Login attempt failed")
	}
	if bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) != nil {
		log.Printf("Login attempt for registered user %s failed\n", username)
		return CryptoSuite{}, fmt.Errorf("Login attempt failed")
	}
	// at this point the user IS authenticated and we must decrypt his private key
	kekBlock, err := BlockForString(password)
	if err != nil {
		return CryptoSuite{}, err
	}

	publicKey, err := x509.ParsePKCS1PublicKey(plainPublicKey)
	if err != nil {
		return CryptoSuite{}, fmt.Errorf("Coudn't parse public key, %w", err)
	}

	plainPrivateKey, err := cryptoutils.DecryptWithBlock(kekBlock, encryptedPrivateKey)
	if err != nil {
		return CryptoSuite{}, fmt.Errorf("Coudn't decrypt user's private key, %w", err)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(plainPrivateKey)
	if err != nil {
		return CryptoSuite{}, fmt.Errorf("Coudn't parse private key, %w", err)
	}
	return CryptoSuite{PublicKey: publicKey, PrivateKey: privateKey}, nil
}

// BlockForString computes a sha256 on a password, and
// generates an AES-256 cipher block from that hash
func BlockForString(password string) (cipher.Block, error) {
	hash := sha256.New()
	hash.Write([]byte(password))

	hashedPassword := hash.Sum(nil)
	// sha256 produces a 32byte value, which translates to AES-256
	block, err := aes.NewCipher(hashedPassword)
	if err != nil {
		return nil, fmt.Errorf("Error generating key encryption key cipher from password, %w", err)
	}
	return block, err
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		db: db,
	}
}
