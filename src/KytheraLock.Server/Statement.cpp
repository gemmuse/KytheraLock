/*
This source file is part of Kythera Lock
For the latest info, see https ://github.com/SwatKat1977/KytheraLock

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
#include <stdexcept>
#include <string>
#include "Statement.h"

Statement::Statement(sqlite3* db, const std::string& sql) : db_(db) {
    if (sqlite3_prepare_v2(db_,
                           sql.c_str(),
                           -1,
                           &stmt_,
                           nullptr) != SQLITE_OK) {
        throw std::runtime_error("SQLite prepare failed: " +
            std::string(sqlite3_errmsg(db_)));
    }
}

Statement::~Statement() {
    if (stmt_) {
        sqlite3_finalize(stmt_);
    }
}

void Statement::BindInt(int index, int value) {
    sqlite3_bind_int(stmt_, index, value);
}

void Statement::BindText(int index, const std::string& value) {
    sqlite3_bind_text(stmt_, index, value.c_str(), -1, SQLITE_TRANSIENT);
}

bool Statement::Step() {
    int rc = sqlite3_step(stmt_);
    if (rc == SQLITE_ROW)
        return true;
    if (rc == SQLITE_DONE)
        return false;

    std::string msg = std::string(sqlite3_errmsg(db_));
    throw std::runtime_error("SQLite step failed: " + msg);
}

std::string Statement::ColumnText(int index) const {
    const unsigned char* txt = sqlite3_column_text(stmt_, index);
    return txt ? reinterpret_cast<const char*>(txt) : "";
}

int Statement::ColumnInt(int index) const {
    return sqlite3_column_int(stmt_, index);
}
