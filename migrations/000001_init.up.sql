CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    active BOOLEAN DEFAULT true,
    quota_rps INT DEFAULT 1000,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    priority INT DEFAULT 0,
    enabled BOOLEAN DEFAULT true,
    conditions JSONB NOT NULL,
    action VARCHAR(50) NOT NULL,
    response JSONB,
    modify JSONB,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255),
    details JSONB,
    ip VARCHAR(45),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS request_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id UUID NOT NULL,
    method VARCHAR(10),
    url TEXT,
    status_code INT,
    response_time_ms INT,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    rule_id UUID REFERENCES rules(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rules_enabled_priority ON rules(enabled, priority DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_request_logs_created_at ON request_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_request_logs_user_id ON request_logs(user_id);

-- Добавляем администратора по умолчанию
INSERT INTO users (id, email, role, active, quota_rps)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin@guardian.local', 'admin', true, 10000)
ON CONFLICT (email) DO NOTHING;
