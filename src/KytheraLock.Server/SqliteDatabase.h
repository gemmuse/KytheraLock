/*
This source file is part of Kythera Lock
For the latest info, see https://github.com/gemmuse/KytheraLock

Copyright 2026 Kythera Lock Development Team

This program is free software : you can redistribute it and /or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see < https://www.gnu.org/licenses/>.
*/
#ifndef SQLITEDATABASE_H_
#define SQLITEDATABASE_H_
#include <string>
#include "sqlite/sqlite3.h"

namespace kythera::server {

/**
 * @brief RAII wrapper around a SQLite database connection.
 *
 * This class owns a sqlite3* handle and ensures:
 *  - The database connection is opened in the constructor
 *  - The connection is automatically closed in the destructor
 *  - Errors are converted into C++ exceptions
 *
 * It is intentionally minimal and does not implement higher-level
 * abstractions such as transactions or repositories.
 */
class SqliteDatabase {
 public:
    /**
     * @brief Opens a SQLite database file.
     *
     * If the file does not exist, SQLite will create it.
     * Throws std::runtime_error if opening fails.
     *
     * @param path Path to the SQLite database file.
     */
    explicit SqliteDatabase(const std::string& path);

    /**
     * @brief Closes the SQLite connection.
     */
    ~SqliteDatabase();

    SqliteDatabase(const SqliteDatabase&) = delete;
    SqliteDatabase& operator=(const SqliteDatabase&) = delete;

    /**
     * @brief Returns the raw sqlite3* handle.
     *
     * Used internally when creating prepared statements.
     */
    sqlite3* Handle() const { return db_; }

    /**
     * @brief Executes a SQL statement that does not return rows.
     *
     * Intended for:
     *  - CREATE TABLE
     *  - PRAGMA
     *  - INSERT (without needing bound parameters)
     *
     * Throws std::runtime_error on failure.
     */
    void Exec(const std::string& sql);

 private:
    sqlite3* db_{ nullptr };
};

}   // namespace kythera::server

#endif  // SQLITEDATABASE_H_
