import mongoose from "mongoose";

export async function connectToDB() {
  try {
    await mongoose.connect(process.env.MONGO_URI!);
    console.log("MongoDB connected successfully");
  } catch (err) {
    console.error("MongoDB connection failed");
    process.exit(1);
  }
}
