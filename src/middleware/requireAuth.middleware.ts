import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { User } from "../models/user.model";

async function requireAuth(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ message: "Access token is missing" });
    }

    const token = authHeader.split(" ")[1];

    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      _id: string;
      role: "user" | "admin";
      tokenVersion: number;
    };

    const user = await User.findById(payload._id);

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    if (user.tokenVersion !== payload.tokenVersion) {
      return res.status(401).json({ message: "Invalid Token" });
    }

    (req as any).user = {
      _id: user._id,
      name: user.name,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
    };

    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired access token" });
  }
}

export default requireAuth;
