CREATE TABLE users (
	id bigserial NOT NULL,
	name varchar NOT NULL,
	"password" varchar NOT NULL,
	public_key bytea NOT NULL,
	private_key bytea NOT NULL,
	private_key_recovery bytea NOT NULL,
	CONSTRAINT users_pk PRIMARY KEY (id),
	CONSTRAINT users_un_pub UNIQUE (public_key)
);

CREATE TABLE documents (
	id bigserial NOT NULL,
	contents bytea NOT NULL,
	CONSTRAINT documents_pk PRIMARY KEY (id)
);

CREATE TABLE users_documents (
	id bigserial NOT NULL,
	document_id bigint NOT NULL,
	public_key bytea NOT NULL,
	document_key bytea NOT NULL,
	CONSTRAINT users_documents_pk PRIMARY KEY (id),
	CONSTRAINT users_documents_fk_users FOREIGN KEY (public_key) REFERENCES users(public_key),
	CONSTRAINT users_documents_fk_documents FOREIGN KEY (document_id) REFERENCES documents(id)
);

