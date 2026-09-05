package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/akozadaev/guardian/internal/config"
	"github.com/akozadaev/guardian/internal/models"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store объединяет пулы основной БД и необязательной реплики для чтения.
type Store struct {
	Primary *pgxpool.Pool
	Replica *pgxpool.Pool
}

func NewStore(ctx context.Context, cfg config.PostgresConfig) (*Store, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns > 0 {
		poolCfg.MinConns = cfg.MinConns
	}
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime

	primary, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("connect primary: %w", err)
	}
	if err := primary.Ping(ctx); err != nil {
		primary.Close()
		return nil, fmt.Errorf("ping primary: %w", err)
	}

	s := &Store{Primary: primary, Replica: primary}
	if cfg.ReadReplicaDSN != "" {
		rep, err := pgxpool.New(ctx, cfg.ReadReplicaDSN)
		if err != nil {
			primary.Close()
			return nil, fmt.Errorf("connect replica: %w", err)
		}
		s.Replica = rep
	}
	return s, nil
}

func (s *Store) Close() {
	if s.Replica != nil && s.Replica != s.Primary {
		s.Replica.Close()
	}
	if s.Primary != nil {
		s.Primary.Close()
	}
}

func (s *Store) reader() *pgxpool.Pool {
	if s.Replica != nil {
		return s.Replica
	}
	return s.Primary
}

// --- Пользователи ---

func (s *Store) CreateUser(ctx context.Context, u *models.User) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	now := time.Now().UTC()
	u.CreatedAt, u.UpdatedAt = now, now
	_, err := s.Primary.Exec(ctx, `
		INSERT INTO users (id, email, role, active, quota_rps, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		u.ID, u.Email, u.Role, u.Active, u.QuotaRPS, u.CreatedAt, u.UpdatedAt)
	return err
}

func (s *Store) GetUser(ctx context.Context, id uuid.UUID) (*models.User, error) {
	row := s.reader().QueryRow(ctx, `
		SELECT id, email, role, active, COALESCE(quota_rps,1000), created_at, COALESCE(updated_at, created_at)
		FROM users WHERE id=$1`, id)
	return scanUser(row)
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	row := s.reader().QueryRow(ctx, `
		SELECT id, email, role, active, COALESCE(quota_rps,1000), created_at, COALESCE(updated_at, created_at)
		FROM users WHERE email=$1`, email)
	return scanUser(row)
}

func (s *Store) UpdateUser(ctx context.Context, u *models.User) error {
	u.UpdatedAt = time.Now().UTC()
	ct, err := s.Primary.Exec(ctx, `
		UPDATE users SET email=$2, role=$3, active=$4, quota_rps=$5, updated_at=$6 WHERE id=$1`,
		u.ID, u.Email, u.Role, u.Active, u.QuotaRPS, u.UpdatedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	ct, err := s.Primary.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) ListUsers(ctx context.Context, p models.PageParams) (*models.PageResult[models.User], error) {
	if p.Page < 1 {
		p.Page = 1
	}
	if p.Limit < 1 {
		p.Limit = 20
	}
	var total int64
	if err := s.reader().QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.reader().Query(ctx, `
		SELECT id, email, role, active, COALESCE(quota_rps,1000), created_at, COALESCE(updated_at, created_at)
		FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`, p.Limit, p.Offset())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]models.User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *u)
	}
	pages := int(total) / p.Limit
	if int(total)%p.Limit != 0 {
		pages++
	}
	return &models.PageResult[models.User]{Items: items, Total: total, Page: p.Page, Limit: p.Limit, TotalPages: pages}, nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanUser(row scannable) (*models.User, error) {
	var u models.User
	err := row.Scan(&u.ID, &u.Email, &u.Role, &u.Active, &u.QuotaRPS, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// --- Правила ---

func (s *Store) CreateRule(ctx context.Context, r *models.Rule) error {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	now := time.Now().UTC()
	r.CreatedAt, r.UpdatedAt = now, now
	cond, err := json.Marshal(r.Conditions)
	if err != nil {
		return err
	}
	resp, err := json.Marshal(r.Response)
	if err != nil {
		return err
	}
	mod, err := json.Marshal(r.Modify)
	if err != nil {
		return err
	}
	_, err = s.Primary.Exec(ctx, `
		INSERT INTO rules (id, name, priority, enabled, conditions, action, response, modify, created_by, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		r.ID, r.Name, r.Priority, r.Enabled, cond, r.Action, resp, mod, r.CreatedBy, r.CreatedAt, r.UpdatedAt)
	return err
}

func (s *Store) GetRule(ctx context.Context, id uuid.UUID) (*models.Rule, error) {
	row := s.reader().QueryRow(ctx, `
		SELECT id, name, priority, enabled, conditions, action, response, modify, created_by, created_at, COALESCE(updated_at, created_at)
		FROM rules WHERE id=$1`, id)
	return scanRule(row)
}

func (s *Store) UpdateRule(ctx context.Context, r *models.Rule) error {
	r.UpdatedAt = time.Now().UTC()
	cond, err := json.Marshal(r.Conditions)
	if err != nil {
		return err
	}
	resp, err := json.Marshal(r.Response)
	if err != nil {
		return err
	}
	mod, err := json.Marshal(r.Modify)
	if err != nil {
		return err
	}
	ct, err := s.Primary.Exec(ctx, `
		UPDATE rules SET name=$2, priority=$3, enabled=$4, conditions=$5, action=$6, response=$7, modify=$8, updated_at=$9
		WHERE id=$1`, r.ID, r.Name, r.Priority, r.Enabled, cond, r.Action, resp, mod, r.UpdatedAt)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteRule(ctx context.Context, id uuid.UUID) error {
	ct, err := s.Primary.Exec(ctx, `DELETE FROM rules WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) ListRules(ctx context.Context, p models.PageParams) (*models.PageResult[models.Rule], error) {
	if p.Page < 1 {
		p.Page = 1
	}
	if p.Limit < 1 {
		p.Limit = 20
	}
	var total int64
	if err := s.reader().QueryRow(ctx, `SELECT COUNT(*) FROM rules`).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := s.reader().Query(ctx, `
		SELECT id, name, priority, enabled, conditions, action, response, modify, created_by, created_at, COALESCE(updated_at, created_at)
		FROM rules ORDER BY priority DESC, created_at DESC LIMIT $1 OFFSET $2`, p.Limit, p.Offset())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]models.Rule, 0)
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *r)
	}
	pages := int(total) / p.Limit
	if int(total)%p.Limit != 0 {
		pages++
	}
	return &models.PageResult[models.Rule]{Items: items, Total: total, Page: p.Page, Limit: p.Limit, TotalPages: pages}, nil
}

func (s *Store) ListEnabledRules(ctx context.Context) ([]models.Rule, error) {
	rows, err := s.reader().Query(ctx, `
		SELECT id, name, priority, enabled, conditions, action, response, modify, created_by, created_at, COALESCE(updated_at, created_at)
		FROM rules WHERE enabled=true ORDER BY priority DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]models.Rule, 0)
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *r)
	}
	return items, rows.Err()
}

func scanRule(row scannable) (*models.Rule, error) {
	var (
		r               models.Rule
		cond, resp, mod []byte
		createdBy       *uuid.UUID
	)
	err := row.Scan(&r.ID, &r.Name, &r.Priority, &r.Enabled, &cond, &r.Action, &resp, &mod, &createdBy, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, err
	}
	r.CreatedBy = createdBy
	if err := json.Unmarshal(cond, &r.Conditions); err != nil {
		return nil, err
	}
	if len(resp) > 0 && string(resp) != "null" {
		var rr models.RuleResponse
		if err := json.Unmarshal(resp, &rr); err == nil {
			r.Response = &rr
		}
	}
	if len(mod) > 0 && string(mod) != "null" {
		var m models.ModifySpec
		if err := json.Unmarshal(mod, &m); err == nil {
			r.Modify = &m
		}
	}
	return &r, nil
}

// --- Журналы аудита и запросов ---

func (s *Store) InsertAudit(ctx context.Context, a *models.AuditLog) error {
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	_, err := s.Primary.Exec(ctx, `
		INSERT INTO audit_logs (id, user_id, action, resource, details, ip, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		a.ID, a.UserID, a.Action, a.Resource, a.Details, a.IP, a.CreatedAt)
	return err
}

func (s *Store) InsertRequestLog(ctx context.Context, l *models.RequestLog) error {
	if l.ID == uuid.Nil {
		l.ID = uuid.New()
	}
	if l.CreatedAt.IsZero() {
		l.CreatedAt = time.Now().UTC()
	}
	_, err := s.Primary.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, method, url, status_code, response_time_ms, user_id, rule_id, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		l.ID, l.RequestID, l.Method, l.URL, l.StatusCode, l.ResponseTimeMs, l.UserID, l.RuleID, l.CreatedAt)
	return err
}

func (s *Store) RuleStats(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.reader().Query(ctx, `
		SELECT COALESCE(rule_id::text,''), COUNT(*), AVG(response_time_ms)
		FROM request_logs WHERE rule_id IS NOT NULL
		GROUP BY rule_id ORDER BY COUNT(*) DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id string
		var cnt int64
		var avg float64
		if err := rows.Scan(&id, &cnt, &avg); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"rule_id": id, "hits": cnt, "avg_ms": avg})
	}
	return out, nil
}

func (s *Store) UserStats(ctx context.Context) ([]map[string]any, error) {
	rows, err := s.reader().Query(ctx, `
		SELECT COALESCE(user_id::text,''), COUNT(*), AVG(response_time_ms)
		FROM request_logs WHERE user_id IS NOT NULL
		GROUP BY user_id ORDER BY COUNT(*) DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]map[string]any, 0)
	for rows.Next() {
		var id string
		var cnt int64
		var avg float64
		if err := rows.Scan(&id, &cnt, &avg); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"user_id": id, "requests": cnt, "avg_ms": avg})
	}
	return out, nil
}
