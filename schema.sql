-- Import in phpMyAdmin: Import tab > choose this file > Go
CREATE DATABASE IF NOT EXISTS xss_demo
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE xss_demo;

CREATE TABLE IF NOT EXISTS users (
    id       INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL       -- password_hash() value, never plain text
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS activity (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    username   TEXT NOT NULL,
    action     VARCHAR(100) NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
