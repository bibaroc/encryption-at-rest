package document

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"fmt"
	"strings"

	"github.com/bibaroc/encryption-at-rest/pkg/cryptoutils"
	"github.com/bibaroc/encryption-at-rest/repository/user"
)

type Repository struct {
	db *sql.DB
}

// New will insert the specified document, and allow each user to view it's contents
// Contents are encrypted at rest.
//
// Each document inserted this way are AES encrypted by a file-key.
// A copy of this file-key is encrypted using the public key of each currently registered user.
func (r *Repository) New(ctx context.Context, contents []byte) (int64, error) {
	// documentKey will be used to encrypt document's contents.
	documentKey, documentBlock, err := cryptoutils.RandomKey()
	if err != nil {
		return 0, fmt.Errorf("Couldn't generate document key, %w", err)
	}
	encryptedContent, err := cryptoutils.EncryptWithBlock(documentBlock, contents)
	if err != nil {
		return 0, fmt.Errorf("Couldn't encrypt document's content, %w", err)
	}

	// will fetch all of the public keys.
	// there is no need to use `distinct` here as public_key is UNIQUE.
	const usersQuery = `select u.public_key from users u;`
	publicKeys, err := r.db.QueryContext(ctx, usersQuery)
	if err != nil {
		return 0, fmt.Errorf("Couldn't fetch public keys, %w", err)
	}
	defer publicKeys.Close()

	// please note that the first parameter is populated, later on this will be the documentID.
	//
	// elements of this array will look like
	// documentID, public_key1, file-key encrypted using public_key1,
	//             public_key2, file-key encrypted using public_key2,
	//             public_key3, file-key encrypted using public_key3,
	insertQueryArgs := make([]interface{}, 1, 30)
	// manualy building a query here, this does allocate. There are better solutions available,
	// however this is the easiest to understand.
	//
	// elements of this array will look like
	// "(%1, $2, $3)",
	// "(%1, $4, $5)",
	// "(%1, $6, $7)",
	valueParts := make([]string, 0, 15)

	for cnt := 2; publicKeys.Next(); cnt += 2 {
		// for each user, we are encrypting the documentKey using that user's public key
		// in order to allow him to later decrypt it using his private key.
		var userPublicKey []byte
		if err = publicKeys.Scan(&userPublicKey); err != nil {
			return 0, fmt.Errorf("Couldn't scan users public key, %w", err)
		}
		publicKey, err := x509.ParsePKCS1PublicKey(userPublicKey)
		if err != nil {
			return 0, fmt.Errorf("Invalid public key detected, %w", err)
		}
		encryptedDocumentKey, err := rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			publicKey,
			documentKey,
			nil)
		if err != nil {
			return 0, fmt.Errorf("Error encrypting document key using users public key, %w", err)
		}
		insertQueryArgs = append(insertQueryArgs, userPublicKey, encryptedDocumentKey)
		valueParts = append(valueParts, fmt.Sprintf("($1, $%d, $%d)", cnt, cnt+1))

	}

	insertQueryBuilder := strings.Builder{}
	// this procedure is safe as all of the parts composing it are internal only.
	insertQueryBuilder.WriteString("insert into users_documents(document_id, public_key, document_key) values ")
	insertQueryBuilder.WriteString(strings.Join(valueParts, ","))
	insertQueryBuilder.WriteString(";")

	insertQuery := insertQueryBuilder.String()

	// a case can be made here for not starting a transaction
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil
	}
	const q = `insert into documents(contents) values($1) returning id;`
	var documentID int64
	err = tx.QueryRowContext(ctx, q, encryptedContent).Scan(&documentID)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("Couldn't save encrypted document's content, %w", err)
	}

	insertQueryArgs[0] = documentID
	_, err = tx.ExecContext(ctx, insertQuery, insertQueryArgs...)
	if err != nil {
		tx.Rollback()
		return 0, err
	}

	if err = tx.Commit(); err != nil {
		tx.Rollback()
		return 0, err
	}
	return documentID, nil
}

// Get will retrieve and decrypt the content's of a specified document.
//
// To achieve this first we first check if that document has a file-key encrypted using provided publicKey.
// We can later decrypt that file-key by using the provided private key.
// Finaly that plain file-key can be used to decrypt selected document's contents.
func (r *Repository) Get(ctx context.Context, userCrypto user.CryptoSuite, documentID int64) ([]byte, error) {
	var encryptedDocumentKey, encryptedDocument []byte
	const q = `select ud.document_key, d.contents 
		from users_documents ud 
		left outer join documents d on ud.document_id = d.id 
		where ud.public_key = $1
		and d.id = $2;`

	// fetching both file-key and document's contents here.
	err := r.db.QueryRowContext(ctx, q, x509.MarshalPKCS1PublicKey(userCrypto.PublicKey), documentID).
		Scan(
			&encryptedDocumentKey,
			&encryptedDocument,
		)
	if err != nil {
		return nil, fmt.Errorf("Couldn't query document contents, %w", err)
	}
	// we should now have a plain file-key
	documentKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, userCrypto.PrivateKey, encryptedDocumentKey, nil)
	if err != nil {
		return nil, fmt.Errorf("Couldn't decrypt document key, %w", err)
	}
	// file key is used to decrypt document's content
	documentContents, err := cryptoutils.AESDecrypt(documentKey, encryptedDocument)
	if err != nil {
		return nil, fmt.Errorf("Couldn't decrypt document, %w", err)
	}
	return documentContents, nil
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{
		db: db,
	}
}
