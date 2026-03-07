package billing

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

func openUsageDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNewSQLiteUsageStore_NilDB(t *testing.T) {
	_, err := NewSQLiteUsageStore(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db is nil")
}

func TestNewSQLiteUsageStore_OK(t *testing.T) {
	db := openUsageDB(t)
	store, err := NewSQLiteUsageStore(db)
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestUsageStore_Record(t *testing.T) {
	db := openUsageDB(t)
	store, err := NewSQLiteUsageStore(db)
	require.NoError(t, err)

	ev := &UsageEvent{
		ID:           "evt-1",
		UserID:       "user-1",
		Model:        "gpt-4o",
		Provider:     "openai",
		InputTokens:  100,
		OutputTokens: 50,
		SessionKey:   "sess-1",
		AgentID:      "agent-1",
		DurationMs:   1500,
		EstimatedCost: 0.0045,
	}

	err = store.Record(ev)
	require.NoError(t, err)

	// TotalTokens auto-computed.
	assert.Equal(t, int64(150), ev.TotalTokens)
	assert.False(t, ev.CreatedAt.IsZero())
}

func TestUsageStore_Record_NilEvent(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)
	assert.Error(t, store.Record(nil))
}

func TestUsageStore_Record_EmptyID(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)
	err := store.Record(&UsageEvent{UserID: "u", Model: "m"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ID is empty")
}

func TestUsageStore_Record_EmptyUserID(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)
	err := store.Record(&UsageEvent{ID: "e", Model: "m"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user_id is empty")
}

func TestUsageStore_Record_EmptyModel(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)
	err := store.Record(&UsageEvent{ID: "e", UserID: "u"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "model is empty")
}

func TestUsageStore_Record_DuplicateID(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	ev := &UsageEvent{ID: "dup", UserID: "u", Model: "m", InputTokens: 10}
	require.NoError(t, store.Record(ev))

	ev2 := &UsageEvent{ID: "dup", UserID: "u", Model: "m", InputTokens: 20}
	err := store.Record(ev2)
	assert.ErrorIs(t, err, ErrDuplicateID)
}

func TestUsageStore_Record_TotalPreserved(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	ev := &UsageEvent{
		ID:           "e1",
		UserID:       "u",
		Model:        "m",
		InputTokens:  100,
		OutputTokens: 50,
		TotalTokens:  200, // explicitly set (e.g., including reasoning tokens)
	}
	require.NoError(t, store.Record(ev))
	assert.Equal(t, int64(200), ev.TotalTokens) // not overwritten
}

func TestUsageStore_GetSummary(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	now := time.Now().UTC()
	base := now.Add(-time.Hour)

	// Record 3 events.
	for i := 0; i < 3; i++ {
		require.NoError(t, store.Record(&UsageEvent{
			ID:            fmt.Sprintf("e%d", i),
			UserID:        "user-1",
			Model:         "gpt-4o",
			Provider:      "openai",
			InputTokens:   100,
			OutputTokens:  50,
			EstimatedCost: 0.01,
			CreatedAt:     base.Add(time.Duration(i) * time.Minute),
		}))
	}

	summary, err := store.GetSummary("user-1", base.Add(-time.Minute), now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, "user-1", summary.UserID)
	assert.Equal(t, int64(300), summary.TotalInput)
	assert.Equal(t, int64(150), summary.TotalOutput)
	assert.Equal(t, int64(450), summary.TotalTokens)
	assert.Equal(t, int64(3), summary.TotalRequests)
	assert.InDelta(t, 0.03, summary.TotalCost, 0.001)
}

func TestUsageStore_GetSummary_Empty(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	now := time.Now().UTC()
	summary, err := store.GetSummary("nobody", now.Add(-time.Hour), now)
	require.NoError(t, err)
	assert.Equal(t, int64(0), summary.TotalTokens)
	assert.Equal(t, int64(0), summary.TotalRequests)
}

func TestUsageStore_GetSummary_TimeRange(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	// Event inside range.
	require.NoError(t, store.Record(&UsageEvent{
		ID: "in", UserID: "u", Model: "m", InputTokens: 100,
		CreatedAt: base.Add(12 * time.Hour),
	}))
	// Event outside range.
	require.NoError(t, store.Record(&UsageEvent{
		ID: "out", UserID: "u", Model: "m", InputTokens: 999,
		CreatedAt: base.Add(-24 * time.Hour),
	}))

	summary, err := store.GetSummary("u", base, base.Add(24*time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(100), summary.TotalInput)
	assert.Equal(t, int64(1), summary.TotalRequests)
}

func TestUsageStore_GetByModel(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	now := time.Now().UTC()
	base := now.Add(-time.Hour)

	require.NoError(t, store.Record(&UsageEvent{
		ID: "e1", UserID: "u", Model: "gpt-4o", Provider: "openai",
		InputTokens: 100, OutputTokens: 50, CreatedAt: base,
	}))
	require.NoError(t, store.Record(&UsageEvent{
		ID: "e2", UserID: "u", Model: "gpt-4o", Provider: "openai",
		InputTokens: 200, OutputTokens: 100, CreatedAt: base.Add(time.Minute),
	}))
	require.NoError(t, store.Record(&UsageEvent{
		ID: "e3", UserID: "u", Model: "claude-sonnet", Provider: "anthropic",
		InputTokens: 50, OutputTokens: 25, CreatedAt: base.Add(2 * time.Minute),
	}))

	models, err := store.GetByModel("u", base.Add(-time.Minute), now.Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, models, 2)

	// Sorted by total tokens DESC: gpt-4o (450) > claude-sonnet (75).
	assert.Equal(t, "gpt-4o", models[0].Model)
	assert.Equal(t, "openai", models[0].Provider)
	assert.Equal(t, int64(300), models[0].InputTokens)
	assert.Equal(t, int64(150), models[0].OutputTokens)
	assert.Equal(t, int64(2), models[0].RequestCount)

	assert.Equal(t, "claude-sonnet", models[1].Model)
	assert.Equal(t, "anthropic", models[1].Provider)
	assert.Equal(t, int64(1), models[1].RequestCount)
}

func TestUsageStore_GetByModel_Empty(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	models, err := store.GetByModel("nobody", time.Now().Add(-time.Hour), time.Now())
	require.NoError(t, err)
	assert.Empty(t, models)
}

func TestUsageStore_GetDaily(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	day1 := time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 3, 2, 14, 0, 0, 0, time.UTC)

	require.NoError(t, store.Record(&UsageEvent{
		ID: "d1a", UserID: "u", Model: "m", InputTokens: 100, CreatedAt: day1,
	}))
	require.NoError(t, store.Record(&UsageEvent{
		ID: "d1b", UserID: "u", Model: "m", InputTokens: 200, CreatedAt: day1.Add(2 * time.Hour),
	}))
	require.NoError(t, store.Record(&UsageEvent{
		ID: "d2a", UserID: "u", Model: "m", InputTokens: 500, CreatedAt: day2,
	}))

	daily, err := store.GetDaily("u", day1.Add(-time.Hour), day2.Add(time.Hour))
	require.NoError(t, err)
	require.Len(t, daily, 2)

	assert.Equal(t, "2026-03-01", daily[0].Date)
	assert.Equal(t, int64(300), daily[0].InputTokens)
	assert.Equal(t, int64(2), daily[0].RequestCount)

	assert.Equal(t, "2026-03-02", daily[1].Date)
	assert.Equal(t, int64(500), daily[1].InputTokens)
	assert.Equal(t, int64(1), daily[1].RequestCount)
}

func TestUsageStore_GetDaily_Empty(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	daily, err := store.GetDaily("nobody", time.Now().Add(-time.Hour), time.Now())
	require.NoError(t, err)
	assert.Empty(t, daily)
}

func TestUsageStore_GetCurrentPeriodUsage(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	periodStart := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	// In period.
	require.NoError(t, store.Record(&UsageEvent{
		ID: "p1", UserID: "u", Model: "m", InputTokens: 100, OutputTokens: 50,
		CreatedAt: periodStart.Add(time.Hour),
	}))
	require.NoError(t, store.Record(&UsageEvent{
		ID: "p2", UserID: "u", Model: "m", InputTokens: 200, OutputTokens: 100,
		CreatedAt: periodStart.Add(2 * time.Hour),
	}))
	// Before period.
	require.NoError(t, store.Record(&UsageEvent{
		ID: "old", UserID: "u", Model: "m", InputTokens: 999,
		CreatedAt: periodStart.Add(-24 * time.Hour),
	}))

	total, err := store.GetCurrentPeriodUsage("u", periodStart)
	require.NoError(t, err)
	assert.Equal(t, int64(450), total) // 150 + 300
}

func TestUsageStore_GetCurrentPeriodMessages(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	periodStart := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, store.Record(&UsageEvent{
		ID: "m1", UserID: "u", Model: "m", InputTokens: 100,
		CreatedAt: periodStart.Add(time.Hour),
	}))
	require.NoError(t, store.Record(&UsageEvent{
		ID: "m2", UserID: "u", Model: "m", InputTokens: 200,
		CreatedAt: periodStart.Add(2 * time.Hour),
	}))
	// Before period.
	require.NoError(t, store.Record(&UsageEvent{
		ID: "old", UserID: "u", Model: "m", InputTokens: 999,
		CreatedAt: periodStart.Add(-24 * time.Hour),
	}))

	count, err := store.GetCurrentPeriodMessages("u", periodStart)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestUsageStore_ListEvents(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 5; i++ {
		model := "gpt-4o"
		if i%2 == 0 {
			model = "claude-sonnet"
		}
		require.NoError(t, store.Record(&UsageEvent{
			ID:          fmt.Sprintf("e%d", i),
			UserID:      "u",
			Model:       model,
			InputTokens: int64(100 * (i + 1)),
			CreatedAt:   base.Add(time.Duration(i) * time.Hour),
		}))
	}

	// List all for user.
	events, err := store.ListEvents(UsageQuery{UserID: "u"})
	require.NoError(t, err)
	assert.Len(t, events, 5)
	// Ordered DESC by created_at.
	assert.Equal(t, "e4", events[0].ID)
	assert.Equal(t, "e0", events[4].ID)

	// Filter by model.
	events, err = store.ListEvents(UsageQuery{UserID: "u", Model: "gpt-4o"})
	require.NoError(t, err)
	assert.Len(t, events, 2)

	// Pagination.
	events, err = store.ListEvents(UsageQuery{UserID: "u", Limit: 2, Offset: 1})
	require.NoError(t, err)
	assert.Len(t, events, 2)
	assert.Equal(t, "e3", events[0].ID)
}

func TestUsageStore_ListEvents_DefaultLimit(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	// Default limit is 100, max is 1000.
	events, err := store.ListEvents(UsageQuery{})
	require.NoError(t, err)
	assert.Empty(t, events) // no data
}

func TestUsageStore_ListEvents_TimeRange(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, store.Record(&UsageEvent{
		ID: "e1", UserID: "u", Model: "m", InputTokens: 100,
		CreatedAt: base.Add(12 * time.Hour),
	}))
	require.NoError(t, store.Record(&UsageEvent{
		ID: "e2", UserID: "u", Model: "m", InputTokens: 200,
		CreatedAt: base.Add(36 * time.Hour),
	}))

	events, err := store.ListEvents(UsageQuery{
		UserID: "u",
		Since:  base,
		Until:  base.Add(24 * time.Hour),
	})
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "e1", events[0].ID)
}

func TestUsageStore_DeleteBefore(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, store.Record(&UsageEvent{
		ID: "old", UserID: "u", Model: "m", InputTokens: 100,
		CreatedAt: base,
	}))
	require.NoError(t, store.Record(&UsageEvent{
		ID: "new", UserID: "u", Model: "m", InputTokens: 200,
		CreatedAt: base.Add(48 * time.Hour),
	}))

	deleted, err := store.DeleteBefore(base.Add(24 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	// Only "new" remains.
	events, err := store.ListEvents(UsageQuery{UserID: "u"})
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "new", events[0].ID)
}

func TestUsageStore_DeleteBefore_None(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	deleted, err := store.DeleteBefore(time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(0), deleted)
}

func TestUsageStore_MultiUser_Isolation(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	now := time.Now().UTC()

	require.NoError(t, store.Record(&UsageEvent{
		ID: "u1e", UserID: "user-1", Model: "m", InputTokens: 100, CreatedAt: now,
	}))
	require.NoError(t, store.Record(&UsageEvent{
		ID: "u2e", UserID: "user-2", Model: "m", InputTokens: 200, CreatedAt: now,
	}))

	s1, err := store.GetSummary("user-1", now.Add(-time.Hour), now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(100), s1.TotalInput)

	s2, err := store.GetSummary("user-2", now.Add(-time.Hour), now.Add(time.Hour))
	require.NoError(t, err)
	assert.Equal(t, int64(200), s2.TotalInput)
}

func TestUsageStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/usage.db"

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	store, err := NewSQLiteUsageStore(db)
	require.NoError(t, err)

	require.NoError(t, store.Record(&UsageEvent{
		ID: "e1", UserID: "u", Model: "gpt-4o", Provider: "openai",
		InputTokens: 100, OutputTokens: 50, SessionKey: "sess",
		AgentID: "agent", DurationMs: 1500, EstimatedCost: 0.01,
	}))
	require.NoError(t, db.Close())

	// Reopen.
	db2, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	defer db2.Close()

	store2, err := NewSQLiteUsageStore(db2)
	require.NoError(t, err)

	events, err := store2.ListEvents(UsageQuery{UserID: "u"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "e1", events[0].ID)
	assert.Equal(t, "gpt-4o", events[0].Model)
	assert.Equal(t, "openai", events[0].Provider)
	assert.Equal(t, int64(100), events[0].InputTokens)
	assert.Equal(t, int64(50), events[0].OutputTokens)
	assert.Equal(t, int64(150), events[0].TotalTokens)
	assert.Equal(t, "sess", events[0].SessionKey)
	assert.Equal(t, "agent", events[0].AgentID)
	assert.Equal(t, int64(1500), events[0].DurationMs)
	assert.InDelta(t, 0.01, events[0].EstimatedCost, 0.001)
}

func TestUsageStore_Close(t *testing.T) {
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)
	assert.NoError(t, store.Close())
}

func TestUsageStore_LimitEnforcement(t *testing.T) {
	// Integration test: check usage against plan limits.
	db := openUsageDB(t)
	store, _ := NewSQLiteUsageStore(db)

	periodStart := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	// Free plan: 500K tokens/month, 500 messages/month.
	plans := DefaultPlans()
	freePlan := plans[PlanFree]

	// Record usage near limit.
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Record(&UsageEvent{
			ID:          fmt.Sprintf("e%d", i),
			UserID:      "u",
			Model:       "gpt-4o-mini",
			InputTokens: 90_000,
			CreatedAt:   periodStart.Add(time.Duration(i) * time.Hour),
		}))
	}

	totalTokens, err := store.GetCurrentPeriodUsage("u", periodStart)
	require.NoError(t, err)
	assert.Equal(t, int64(450_000), totalTokens) // 5 × 90K

	// Check against plan limit.
	err = CheckLimit("tokens", totalTokens, freePlan.Limits.MaxTokensPerMonth)
	assert.NoError(t, err) // 450K < 500K — OK.

	// Add one more to exceed.
	require.NoError(t, store.Record(&UsageEvent{
		ID:          "e-over",
		UserID:      "u",
		Model:       "gpt-4o-mini",
		InputTokens: 60_000,
		CreatedAt:   periodStart.Add(6 * time.Hour),
	}))

	totalTokens, err = store.GetCurrentPeriodUsage("u", periodStart)
	require.NoError(t, err)
	assert.Equal(t, int64(510_000), totalTokens)

	err = CheckLimit("tokens", totalTokens, freePlan.Limits.MaxTokensPerMonth)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "tokens limit reached")
}
