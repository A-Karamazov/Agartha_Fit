import { Database } from "bun:sqlite";

const db = new Database("database.sqlite");

db.exec(`
    CREATE TABLE IF NOT EXISTS user_secure (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        username        TEXT NOT NULL UNIQUE,
        password_hash   TEXT NOT NULL
    );
`);

export { db }
export default db