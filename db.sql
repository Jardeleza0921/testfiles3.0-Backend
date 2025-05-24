-- db.sql
-- SQL commands to create the database and tables

-- Create the database if it doesn't exist
CREATE DATABASE IF NOT EXISTS baghaven_db;

-- Use the newly created database
USE baghaven_db;

-- Create the users table
-- This table will store both regular users and admin users.
-- The 'role' column will differentiate between them.
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- Hashed password
    role ENUM('user', 'admin') NOT NULL DEFAULT 'user', -- 'user' or 'admin'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Optional: Add some initial data for testing
-- Insert a regular user
INSERT INTO users (username, password, role) VALUES ('user', '$2a$10$w0X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X', 'user');

-- Insert an admin user
INSERT INTO users (username, password, role) VALUES ('admin', '$2a$10$w0X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X/y.X', 'admin');