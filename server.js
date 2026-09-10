import express from "express";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";
import nvdRoutes from "./routes/nvdRoutes.js";
import database from "./services/databaseService.js";

dotenv.config();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename)

// test database connection
try {
    const connection = await database.getConnection();

    console.log("Connected to MySQL");

    connection.release();

} catch (error) {
    console.log("MySQL connection failed");
    console.log(error.message);
}

const app = express();
const PORT = process.env.PORT || 3000;

// middleware
app.use(express.json());
app.use(express.static("public"));

app.get("/", function(req, res) {
    res.sendFile(
        path.join(
            __dirname,
            "public",
            "index.html"
        )
    );
});

// NVD routes
app.use("/api/nvd", nvdRoutes);

// 404 handler

app.use((req, res) => {
    res.status(404).json({
        error: "Route not found"
    });
});

// start server
app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});

export default app;