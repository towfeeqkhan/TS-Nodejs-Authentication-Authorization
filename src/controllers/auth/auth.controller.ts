import { Request, Response } from "express";
import { registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { sendEmail } from "../../lib/email";

export async function registerHandler(req: Request, res: Response) {
  try {
    const validation = registerSchema.safeParse(req.body);

    if (!validation.success) {
      return res.status(400).json({
        message: "Invalid data",
        errors: validation.error.flatten(),
      });
    }

    const { name, email, password } = validation.data;

    const existingUser = await User.findOne({ email: email });

    if (existingUser) {
      return res.status(409).json({
        message:
          "Email Id already exist, please try again with a different email id",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const newUser = await User.create({
      email,
      passwordHash,
      role: "user",
    });

    // email verification

    const verifyToken = jwt.sign(
      { _id: newUser._id },
      process.env.JWT_ACCESS_SECRET!,
      { expiresIn: "1d" },
    );

    const verifyUrl = `${process.env.APP_URL}/auth/verify-email?token=${verifyToken}`;

    await sendEmail(
      newUser.email,
      "Verify your email",
      `
      <p>Please verify your email by clicking the link below</p>
      <a href=${verifyUrl}>${verifyUrl}</a>
      `,
    );

    res.status(201).json({
      message: "User registered",
      user: {
        _id: newUser._id,
        email: newUser.email,
        role: newUser.role,
        isEmailVerified: newUser.isEmailVerified,
      },
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal server error" });
  }
}

export async function verifyEmailHandler(req: Request, res: Response) {
  const token = req.query.token as string;

  if (!token) {
    return res.status(400).json({
      message: "Verification token is missing",
    });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
      _id: string;
    };

    const user = await User.findById(payload._id);

    if (!user) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    if (user.isEmailVerified) {
      return res.json({ message: "Email is already verified" });
    }

    user.isEmailVerified = true;
    await user.save();

    res.json({ message: "Email is now verified, You can login" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal server error" });
  }
}
