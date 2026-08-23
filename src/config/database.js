import mongoose from "mongoose";
import config from "./config.js";

async function connectDB() {
    await mongoose.connect(config.MONGO_URI)
    console.log("Connected to DB")

    try {
        const db = mongoose.connection.db;
        const collections = await db.listCollections({ name: "users" }).toArray();
        if (collections.length > 0) {
            const indexes = await db.collection("users").indexes();
            if (indexes.some(index => index.name === "password_1")) {
                await db.collection("users").dropIndex("password_1");
                console.log("Dropped unique password index 'password_1' successfully.");
            }
        }
    } catch (error) {
        console.error("Failed to check or drop unique password index:", error.message);
    }
}

export default connectDB;