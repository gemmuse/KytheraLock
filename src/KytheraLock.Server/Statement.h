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
#ifndef STATEMENT_H_
#define STATEMENT_H_
#include <string>
#include "sqlite/sqlite3.h"

/**
 * @brief RAII wrapper for a prepared SQLite statement.
 *
 * A Statement represents a compiled SQL query that may contain
 * parameter placeholders ("?").
 *
 * Responsibilities:
 *  - Preparing SQL
 *  - Binding parameters
 *  - Executing (step)
 *  - Reading result columns
 *  - Automatically finalizing on destruction
 *
 * This prevents:
 *  - SQL injection
 *  - Memory leaks
 *  - Manual lifecycle errors
 */
class Statement {
 public:
    /**
     * @brief Prepares a SQL statement.
     *
     * The SQL string may contain '?' placeholders.
     * Throws std::runtime_error if preparation fails.
     *
     * @param db   Open sqlite3 connection.
     * @param sql  SQL query to prepare.
     */
    Statement(sqlite3* db, const std::string& sql);

    /**
     * @brief Finalizes the prepared statement.
     *
     * Automatically called when the object goes out of scope.
     */
    ~Statement();

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    /**
     * @brief Bind an integer parameter to a '?' placeholder.
     *
     * Parameter indices start at 1 (not 0).
     *
     * Example:
     *   SELECT * FROM table WHERE id = ?
     *   bind_int(1, 42);
     */
    void BindInt(int index, int value);

    /**
     * @brief Bind a string parameter to a '?' placeholder.
     *
     * Parameter indices start at 1 (not 0).
     */
    void BindText(int index, const std::string& value);

    /**
     * @brief Executes one step of the statement.
     *
     * For SELECT queries:
     *   - Returns true if a row is available.
     *   - Returns false when no more rows exist.
     *
     * For INSERT/UPDATE/DELETE:
     *   - Executes once.
     *   - Returns false (no rows).
     *
     * Throws std::runtime_error on error.
     */
    bool Step();

    /**
     * @brief Returns a text column from the current row.
     *
     * Column indices start at 0.
     */
    std::string ColumnText(int index) const;

    /**
     * @brief Returns an integer column from the current row.
     *
     * Column indices start at 0.
     */
    int ColumnInt(int index) const;

 private:
    sqlite3* db_;
    sqlite3_stmt* stmt_{ nullptr };
};

#endif  // STATEMENT_H_
