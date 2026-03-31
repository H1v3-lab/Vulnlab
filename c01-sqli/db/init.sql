-- ─────────────────────────────────────────────
-- VulnLab C01 — SQL Injection
-- Base de données : vulnlab
-- ─────────────────────────────────────────────

CREATE DATABASE IF NOT EXISTS vulnlab;
USE vulnlab;

-- Table des utilisateurs (login vulnérable)
CREATE TABLE IF NOT EXISTS users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(64)  NOT NULL,
    password VARCHAR(255) NOT NULL,
    role     VARCHAR(16)  NOT NULL DEFAULT 'user',
    email    VARCHAR(128)
);

-- Utilisateurs normaux (mots de passe en clair — volontaire !)
INSERT INTO users (username, password, role, email) VALUES
  ('alice',  'Alice2024!',   'user',  'alice@corp.local'),
  ('bob',    'b0bIsC00l',    'user',  'bob@corp.local'),
  ('charlie','password123',  'user',  'charlie@corp.local'),
  ('admin',  'Sup3rS3cr3t!', 'admin', 'admin@corp.local');

-- Table des secrets — accessible uniquement si on bypass l'auth
CREATE TABLE IF NOT EXISTS secrets (
    id      INT AUTO_INCREMENT PRIMARY KEY,
    name    VARCHAR(64),
    value   TEXT
);

INSERT INTO secrets (name, value) VALUES
  ('flag',         'FLAG{sql1_1nj3ct10n_byp4ss_succ3ss}'),
  ('internal_key', 'sk-internal-a3f9b2c1d4e5'),
  ('db_backup_url','ftp://backup.corp.local/dump_2024.sql');

-- Table des commandes (pour UNION-based injection)
CREATE TABLE IF NOT EXISTS orders (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT,
    product    VARCHAR(128),
    amount     DECIMAL(10,2),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO orders (user_id, product, amount) VALUES
  (1, 'Laptop Pro X', 1299.99),
  (2, 'Mechanical Keyboard', 149.00),
  (3, 'USB-C Hub',     39.99),
  (4, 'Server Rack',  4500.00);
