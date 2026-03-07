package auth

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPGDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("OPERATOR_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OPERATOR_TEST_PG_DSN not set — skipping PostgreSQL integration test")
	}

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)

	db.Exec("DROP TABLE IF EXISTS credentials CASCADE")

	t.Cleanup(func() {
		db.Exec("DROP TABLE IF EXISTS credentials CASCADE")
		db.Close()
	})

	return db
}

func TestPGCredentialStoreNilDB(t *testing.T) {
	_, err := NewPGCredentialStore(nil, "key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db is nil")
}

func TestPGCredentialStoreInterfaceCompliance(t *testing.T) {
	var _ CredentialStore = (*PGCredentialStore)(nil)
}

func TestPGCredentialStoreSetGet(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGCredentialStore(db, "test-key-32-chars-long-enough!!")
	require.NoError(t, err)

	cred := &AuthCredential{
		AccessToken:  "at-123",
		RefreshToken: "rt-456",
		Provider:     "github",
	}

	err = store.Set("github", cred)
	require.NoError(t, err)

	got, err := store.Get("github")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "at-123", got.AccessToken)
	assert.Equal(t, "rt-456", got.RefreshToken)
}

func TestPGCredentialStoreGetNotFound(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGCredentialStore(db, "test-key-32-chars-long-enough!!")
	require.NoError(t, err)

	got, err := store.Get("nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestPGCredentialStoreUpsert(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGCredentialStore(db, "test-key-32-chars-long-enough!!")
	require.NoError(t, err)

	cred1 := &AuthCredential{AccessToken: "old"}
	err = store.Set("provider", cred1)
	require.NoError(t, err)

	cred2 := &AuthCredential{AccessToken: "new"}
	err = store.Set("provider", cred2)
	require.NoError(t, err)

	got, err := store.Get("provider")
	require.NoError(t, err)
	assert.Equal(t, "new", got.AccessToken)
}

func TestPGCredentialStoreDelete(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGCredentialStore(db, "test-key-32-chars-long-enough!!")
	require.NoError(t, err)

	err = store.Set("del", &AuthCredential{AccessToken: "x"})
	require.NoError(t, err)

	err = store.Delete("del")
	require.NoError(t, err)

	got, err := store.Get("del")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestPGCredentialStoreDeleteAll(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGCredentialStore(db, "test-key-32-chars-long-enough!!")
	require.NoError(t, err)

	err = store.Set("a", &AuthCredential{AccessToken: "1"})
	require.NoError(t, err)
	err = store.Set("b", &AuthCredential{AccessToken: "2"})
	require.NoError(t, err)

	err = store.DeleteAll()
	require.NoError(t, err)

	list, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestPGCredentialStoreList(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGCredentialStore(db, "test-key-32-chars-long-enough!!")
	require.NoError(t, err)

	err = store.Set("x", &AuthCredential{AccessToken: "ax"})
	require.NoError(t, err)
	err = store.Set("y", &AuthCredential{AccessToken: "ay"})
	require.NoError(t, err)

	list, err := store.List()
	require.NoError(t, err)
	assert.Len(t, list, 2)
	assert.Equal(t, "ax", list["x"].AccessToken)
	assert.Equal(t, "ay", list["y"].AccessToken)
}

func TestPGCredentialStoreUnencrypted(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGCredentialStore(db, "")
	require.NoError(t, err)

	cred := &AuthCredential{AccessToken: "plain-token"}
	err = store.Set("p", cred)
	require.NoError(t, err)

	got, err := store.Get("p")
	require.NoError(t, err)
	assert.Equal(t, "plain-token", got.AccessToken)
}

func TestPGCredentialStoreClose(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGCredentialStore(db, "key")
	require.NoError(t, err)

	// Close is a no-op.
	err = store.Close()
	assert.NoError(t, err)
}
