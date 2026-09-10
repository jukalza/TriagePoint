import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

const useSsl = process.env.DB_HOST === "cloud.layerbase.dev";

const database = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: Number(process.env.DB_PORT),

    ssl: useSsl
        ? {
            rejectUnauthorized: true
        }
        : undefined
});

export default database;